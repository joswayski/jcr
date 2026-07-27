use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{any, get},
};
use tower_cookies::CookieManagerLayer;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{auth, registry, state::AppState, web};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v2/", get(auth::v2_check))
        .route("/auth/token", get(auth::token))
        .route("/v2/{*path}", any(registry::dispatch))
        .merge(web::router())
        // Upload limits are enforced while each OCI request body is read. The
        // default Axum limit would otherwise reject valid 64 MiB JCR chunks.
        .layer(DefaultBodyLimit::disable())
        .layer(CookieManagerLayer::new())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        net::SocketAddr,
        path::Path,
        process::{Command, Stdio},
        sync::Arc,
        time::Duration,
    };

    use anyhow::{Context, Result, bail};
    use axum::{
        body::{Body, Bytes, to_bytes},
        extract::{OriginalUri, State},
        http::{
            HeaderMap, Method, Request, StatusCode,
            header::{
                AUTHORIZATION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HOST, LOCATION, RANGE,
                WWW_AUTHENTICATE,
            },
        },
        response::IntoResponse,
        routing::any,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use jcr::{
        credentials::DockerCredentials,
        image::{BlobFile, ManifestObject, PreparedImage},
        registry::RegistryClient,
        resume::ResumeStore,
    };
    use jcr_core::{Digest, manifest::OCI_IMAGE_MANIFEST};
    use serde_json::Value;
    use sha2::{Digest as _, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::{
        config::{Config, RegistrationMode, StorageConfig},
        db::{self, VerifiedLogin},
        state::AppState,
        storage::FilesystemBlobStore,
    };

    #[tokio::test]
    async fn postgres_registry_flow_when_database_is_configured() {
        let Some(database_url) = std::env::var("JCR_DATABASE_URL").ok() else {
            eprintln!("skipping PostgreSQL registry flow; JCR_DATABASE_URL is unset");
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend_listener.local_addr().unwrap();
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy_listener.local_addr().unwrap();
        let config = Config {
            listen_address: backend_address,
            public_url: format!("http://{address}/").parse().unwrap(),
            database_url,
            jwt_secret: "integration-test-secret-with-at-least-32-bytes".to_owned(),
            registration_mode: RegistrationMode::Allowlist,
            bootstrap_email: Some("jose@example.com".to_owned()),
            bootstrap_username: "jose".to_owned(),
            bootstrap_namespace: "jose".to_owned(),
            google: None,
            upload_chunk_limit: 80 * 1024 * 1024,
            upload_session_hours: 24,
            gc_grace_days: 7,
            storage: StorageConfig::Filesystem {
                root: directory.path().join("objects"),
            },
        };
        let pool = db::connect_and_migrate(&config).await.unwrap();
        let jose = db::register_verified_identity(
            &pool,
            VerifiedLogin {
                provider: "google".to_owned(),
                subject: "jcr-integration-jose".to_owned(),
                email: "jose@example.com".to_owned(),
                email_verified: true,
                display_name: Some("Jose Valerio".to_owned()),
            },
        )
        .await
        .unwrap();
        assert_eq!(jose.username, "jose");
        assert!(jose.is_instance_admin());
        let role: String = sqlx::query_scalar(
            "SELECT m.role::text
             FROM namespace_memberships m
             JOIN namespaces n ON n.id = m.namespace_id
             WHERE n.name = 'jose' AND m.user_id = $1",
        )
        .bind(jose.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(role, "admin");

        let denied_email = format!("denied-{}@example.com", Uuid::new_v4());
        let denied = db::register_verified_identity(
            &pool,
            VerifiedLogin {
                provider: "google".to_owned(),
                subject: Uuid::new_v4().to_string(),
                email: denied_email.clone(),
                email_verified: true,
                display_name: None,
            },
        )
        .await;
        assert!(denied.is_err());
        let denied_records: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE primary_email = $1")
                .bind(&denied_email)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(denied_records, 0);

        let invite_suffix = Uuid::new_v4().simple().to_string();
        let invite_email = format!("invite-{invite_suffix}@example.com");
        let invite_username = format!("invite-{}", &invite_suffix[..12]);
        sqlx::query(
            "INSERT INTO registration_entries (
                 id, email, reserved_username, reserved_namespace,
                 instance_role, namespace_role, status
             ) VALUES ($1, $2, $3, $3, 'user', 'admin', 'pending')",
        )
        .bind(Uuid::new_v4())
        .bind(&invite_email)
        .bind(&invite_username)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE instance_settings
             SET registration_mode = 'invite'
             WHERE singleton = TRUE",
        )
        .execute(&pool)
        .await
        .unwrap();
        let invited = db::register_verified_identity(
            &pool,
            VerifiedLogin {
                provider: "google".to_owned(),
                subject: Uuid::new_v4().to_string(),
                email: invite_email,
                email_verified: true,
                display_name: None,
            },
        )
        .await;
        sqlx::query(
            "UPDATE instance_settings
             SET registration_mode = 'allowlist'
             WHERE singleton = TRUE",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(invited.unwrap().username, invite_username);

        let issued = db::create_pat(&pool, jose.id, "integration", None)
            .await
            .unwrap();
        let storage = FilesystemBlobStore::new(directory.path().join("blobs"))
            .await
            .unwrap();
        let state = AppState::new(config, pool.clone(), Arc::new(storage));
        let application = router(state.clone());
        let network_application = application.clone();
        let server = tokio::spawn(async move {
            axum::serve(backend_listener, network_application.into_make_service())
                .await
                .unwrap();
        });
        let proxy = Router::new()
            .fallback(any(capped_proxy))
            .layer(DefaultBodyLimit::disable())
            .with_state(ProxyState {
                backend: format!("http://{backend_address}"),
                http: reqwest::Client::new(),
            });
        let proxy_server = tokio::spawn(async move {
            axum::serve(proxy_listener, proxy.into_make_service())
                .await
                .unwrap();
        });
        let basic = format!(
            "Basic {}",
            STANDARD.encode(format!("jose:{}", issued.token))
        );

        let first_name = format!("jose/smoke-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let second_name = format!("jose/shared-{}", &Uuid::new_v4().simple().to_string()[..8]);
        db::ensure_repository_for_push(&pool, &first_name, &jose)
            .await
            .unwrap();
        db::ensure_repository_for_push(&pool, &second_name, &jose)
            .await
            .unwrap();
        let first_token = bearer_token(
            &application,
            &basic,
            &format!("repository:{first_name}:pull,push,delete"),
        )
        .await;
        let second_token = bearer_token(
            &application,
            &basic,
            &format!("repository:{second_name}:pull,push,delete"),
        )
        .await;

        let private = request(
            &application,
            Request::get(format!("/v2/{first_name}/manifests/latest"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(private.status(), StatusCode::UNAUTHORIZED);
        let anonymous_push = request(
            &application,
            Request::post(format!("/v2/{first_name}/blobs/uploads/"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(anonymous_push.status(), StatusCode::UNAUTHORIZED);

        let config_bytes = Bytes::from_static(br#"{"architecture":"amd64","os":"linux"}"#);
        let config_digest = Digest::sha256(&config_bytes);
        let start = authorized_request(
            &application,
            Request::post(format!("/v2/{first_name}/blobs/uploads/")),
            &first_token,
            Body::empty(),
        )
        .await;
        assert_eq!(start.status(), StatusCode::ACCEPTED);
        let upload = start
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let out_of_order = authorized_request(
            &application,
            Request::patch(&upload).header(CONTENT_RANGE, "5-7"),
            &first_token,
            Body::from("bad"),
        )
        .await;
        assert_eq!(out_of_order.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        let status = authorized_request(
            &application,
            Request::get(&upload),
            &first_token,
            Body::empty(),
        )
        .await;
        assert_eq!(status.status(), StatusCode::NO_CONTENT);
        assert!(status.headers().get(RANGE).is_none());

        let expired_start = authorized_request(
            &application,
            Request::post(format!("/v2/{first_name}/blobs/uploads/")),
            &first_token,
            Body::empty(),
        )
        .await;
        let expired_location = expired_start
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let expired_id = Uuid::parse_str(expired_location.rsplit('/').next().unwrap()).unwrap();
        sqlx::query(
            "UPDATE upload_sessions
             SET expires_at = NOW() - INTERVAL '1 second'
             WHERE id = $1",
        )
        .bind(expired_id)
        .execute(&pool)
        .await
        .unwrap();
        let expired = authorized_request(
            &application,
            Request::get(&expired_location),
            &first_token,
            Body::empty(),
        )
        .await;
        assert_eq!(expired.status(), StatusCode::NOT_FOUND);

        let patch = authorized_request(
            &application,
            Request::patch(&upload).header(CONTENT_RANGE, format!("0-{}", config_bytes.len() - 1)),
            &first_token,
            Body::from(config_bytes.clone()),
        )
        .await;
        assert_eq!(patch.status(), StatusCode::ACCEPTED);

        // Rebuild the application around the same PostgreSQL and blob-store
        // state to model a jcrd process restart between chunks.
        let restarted_application = router(state.clone());
        let resumed = authorized_request(
            &restarted_application,
            Request::get(&upload),
            &first_token,
            Body::empty(),
        )
        .await;
        assert_eq!(resumed.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resumed.headers().get(RANGE).unwrap().to_str().unwrap(),
            format!("0-{}", config_bytes.len() - 1)
        );
        let complete = authorized_request(
            &restarted_application,
            Request::put(format!("{upload}?digest={config_digest}")),
            &first_token,
            Body::empty(),
        )
        .await;
        assert_eq!(complete.status(), StatusCode::CREATED);

        let incorrect_start = authorized_request(
            &application,
            Request::post(format!("/v2/{first_name}/blobs/uploads/")),
            &first_token,
            Body::empty(),
        )
        .await;
        let incorrect_location = incorrect_start
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let incorrect_patch = authorized_request(
            &application,
            Request::patch(&incorrect_location)
                .header(CONTENT_RANGE, format!("0-{}", config_bytes.len() - 1)),
            &first_token,
            Body::from(config_bytes.clone()),
        )
        .await;
        assert_eq!(incorrect_patch.status(), StatusCode::ACCEPTED);
        let incorrect = authorized_request(
            &application,
            Request::put(format!(
                "{incorrect_location}?digest={}",
                Digest::sha256(b"not the uploaded bytes")
            )),
            &first_token,
            Body::empty(),
        )
        .await;
        assert_eq!(incorrect.status(), StatusCode::BAD_REQUEST);

        let mount = authorized_request(
            &application,
            Request::post(format!(
                "/v2/{second_name}/blobs/uploads/?mount={config_digest}&from={first_name}"
            )),
            &second_token,
            Body::empty(),
        )
        .await;
        assert_eq!(mount.status(), StatusCode::CREATED);

        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config_bytes.len()
            },
            "layers": []
        }))
        .unwrap();
        let manifest_digest = Digest::sha256(&manifest_bytes);
        for (repository, token) in [(&first_name, &first_token), (&second_name, &second_token)] {
            let response = authorized_request(
                &application,
                Request::put(format!("/v2/{repository}/manifests/latest"))
                    .header(CONTENT_TYPE, OCI_IMAGE_MANIFEST),
                token,
                Body::from(manifest_bytes.clone()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let wrong_scope = authorized_request(
            &application,
            Request::get(format!("/v2/{second_name}/manifests/latest")),
            &first_token,
            Body::empty(),
        )
        .await;
        assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

        sqlx::query(
            "UPDATE repositories
             SET visibility = 'public'
             WHERE id = (
                 SELECT r.id FROM repositories r
                 JOIN namespaces n ON n.id = r.namespace_id
                 WHERE n.name || '/' || r.name = $1
             )",
        )
        .bind(&second_name)
        .execute(&pool)
        .await
        .unwrap();
        let public = request(
            &application,
            Request::get(format!("/v2/{second_name}/manifests/latest"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(public.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(public.into_body(), 1024 * 1024).await.unwrap(),
            manifest_bytes
        );

        let delete = authorized_request(
            &application,
            Request::delete(format!("/v2/{first_name}/manifests/{manifest_digest}")),
            &first_token,
            Body::empty(),
        )
        .await;
        assert_eq!(delete.status(), StatusCode::ACCEPTED);
        let shared_blob = authorized_request(
            &application,
            Request::head(format!("/v2/{second_name}/blobs/{config_digest}")),
            &second_token,
            Body::empty(),
        )
        .await;
        assert_eq!(shared_blob.status(), StatusCode::OK);

        let malformed = authorized_request(
            &application,
            Request::put(format!("/v2/{second_name}/manifests/bad"))
                .header(CONTENT_TYPE, OCI_IMAGE_MANIFEST),
            &second_token,
            Body::from("{}"),
        )
        .await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

        // Exercise the real first-party HTTP client against a live jcrd
        // listener. A 65 MiB layer must become one 64 MiB PATCH plus a small
        // final PUT, keeping every request below the configured 80 MiB cap.
        let chunk_repository = format!("jose/chunks-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let client_workspace = tempfile::tempdir().unwrap();
        let client_config = Bytes::from_static(br#"{"architecture":"amd64","os":"linux"}"#);
        let client_config_digest = Digest::sha256(&client_config);
        let client_config_path = client_workspace.path().join("config.json");
        std::fs::write(&client_config_path, &client_config).unwrap();
        let layer_mebibytes = std::env::var("JCR_LARGE_TEST_MIB")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(65);
        assert!(layer_mebibytes >= 65);
        let layer_size = layer_mebibytes * 1024 * 1024;
        let layer_path = client_workspace.path().join("layer.bin");
        let mut layer_file = std::fs::File::create(&layer_path).unwrap();
        let mut layer_hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut state_word = 0x9e37_79b9_u32;
        let mut remaining = layer_size;
        while remaining > 0 {
            let length = remaining.min(buffer.len());
            for chunk in buffer[..length].chunks_mut(4) {
                state_word ^= state_word << 13;
                state_word ^= state_word >> 17;
                state_word ^= state_word << 5;
                chunk.copy_from_slice(&state_word.to_le_bytes()[..chunk.len()]);
            }
            layer_file.write_all(&buffer[..length]).unwrap();
            layer_hasher.update(&buffer[..length]);
            remaining -= length;
        }
        layer_file.sync_all().unwrap();
        drop(layer_file);
        let layer_digest = format!("sha256:{}", hex::encode(layer_hasher.finalize()))
            .parse()
            .unwrap();
        let client_manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": client_config_digest,
                "size": client_config.len()
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": layer_size
            }]
        }))
        .unwrap();
        let client_manifest_digest = Digest::sha256(&client_manifest);
        let prepared = PreparedImage::from_parts(
            vec![
                BlobFile {
                    digest: client_config_digest,
                    size: client_config.len() as u64,
                    path: client_config_path,
                },
                BlobFile {
                    digest: layer_digest,
                    size: layer_size as u64,
                    path: layer_path,
                },
            ],
            vec![ManifestObject {
                digest: client_manifest_digest.clone(),
                media_type: OCI_IMAGE_MANIFEST.to_owned(),
                bytes: client_manifest.clone(),
            }],
            client_manifest_digest,
            client_workspace,
        );
        let remote = format!("{address}/{chunk_repository}:latest")
            .parse()
            .unwrap();
        let network_client = RegistryClient::for_push(&remote, "jose", &issued.token)
            .await
            .unwrap();
        let resume = ResumeStore::at(directory.path().join("resume/uploads.json"))
            .await
            .unwrap();
        network_client
            .push(prepared, &remote, 2, resume)
            .await
            .unwrap();
        let part_sizes: Vec<i64> = sqlx::query_scalar(
            "SELECT p.size
             FROM upload_parts p
             JOIN upload_sessions u ON u.id = p.upload_id
             JOIN repositories r ON r.id = u.repository_id
             JOIN namespaces n ON n.id = r.namespace_id
             WHERE n.name || '/' || r.name = $1
             ORDER BY p.size DESC",
        )
        .bind(&chunk_repository)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(part_sizes.contains(&(64 * 1024 * 1024)));
        assert!(part_sizes.iter().all(|size| *size <= 64 * 1024 * 1024));
        let chunk_token = bearer_token(
            &application,
            &basic,
            &format!("repository:{chunk_repository}:pull"),
        )
        .await;
        let pulled = reqwest::Client::new()
            .get(format!(
                "http://{address}/v2/{chunk_repository}/manifests/latest"
            ))
            .bearer_auth(chunk_token)
            .send()
            .await
            .unwrap();
        assert_eq!(pulled.status(), StatusCode::OK);
        assert_eq!(pulled.bytes().await.unwrap(), client_manifest);

        if let Some(binary) = std::env::var_os("JCR_TEST_CONFORMANCE_BINARY") {
            let suffix = &Uuid::new_v4().simple().to_string()[..8];
            let namespace = format!("jose/conformance-{suffix}");
            let cross_namespace = format!("jose/conformance-cross-{suffix}");
            let password = issued.token.clone();
            let output = tokio::task::spawn_blocking(move || {
                Command::new(binary)
                    .env("OCI_ROOT_URL", format!("http://{address}"))
                    .env("OCI_NAMESPACE", namespace)
                    .env("OCI_CROSSMOUNT_NAMESPACE", cross_namespace)
                    .env("OCI_USERNAME", "jose")
                    .env("OCI_PASSWORD", password)
                    .env("OCI_TEST_PULL", "1")
                    .env("OCI_TEST_PUSH", "1")
                    .env("OCI_HIDE_SKIPPED_WORKFLOWS", "1")
                    .env("OCI_DELETE_MANIFEST_BEFORE_BLOBS", "1")
                    .env("OCI_REPORT_DIR", "none")
                    .output()
            })
            .await
            .unwrap()
            .unwrap();
            assert!(
                output.status.success(),
                "OCI conformance failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        if std::env::var("JCR_TEST_DOCKER_CLIENT").as_deref() == Ok("1") {
            let password = issued.token.clone();
            let docker_registry = std::env::var("JCR_TEST_DOCKER_REGISTRY").ok();
            tokio::task::spawn_blocking(move || {
                docker_compatibility(address, docker_registry.as_deref(), &password)
            })
            .await
            .unwrap()
            .unwrap();
        }

        db::revoke_pat(&pool, jose.id, issued.id).await.unwrap();
        let revoked = request(
            &application,
            Request::get("/auth/token?service=jcr")
                .header(AUTHORIZATION, basic)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
        proxy_server.abort();
        server.abort();
    }

    async fn bearer_token(application: &Router, basic: &str, scope: &str) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("service", "jcr")
            .append_pair("scope", scope)
            .finish();
        let response = request(
            application,
            Request::get(format!("/auth/token?{query}"))
                .header(AUTHORIZATION, basic)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        value["token"].as_str().unwrap().to_owned()
    }

    async fn authorized_request(
        application: &Router,
        builder: axum::http::request::Builder,
        token: &str,
        body: Body,
    ) -> axum::response::Response {
        request(
            application,
            builder
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(body)
                .unwrap(),
        )
        .await
    }

    async fn request(application: &Router, request: Request<Body>) -> axum::response::Response {
        application.clone().oneshot(request).await.unwrap()
    }

    #[derive(Clone)]
    struct ProxyState {
        backend: String,
        http: reqwest::Client,
    }

    async fn capped_proxy(
        State(proxy): State<ProxyState>,
        OriginalUri(uri): OriginalUri,
        method: Method,
        mut headers: HeaderMap,
        body: Body,
    ) -> axum::response::Response {
        let Ok(bytes) = to_bytes(body, 100 * 1024 * 1024).await else {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        };
        let request_host = headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        headers.remove(HOST);
        headers.remove(CONTENT_LENGTH);
        let response = proxy
            .http
            .request(method, format!("{}{}", proxy.backend, uri))
            .headers(headers)
            .body(bytes)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let mut headers = response.headers().clone();
        if let (Some(host), Some(challenge)) = (
            request_host,
            headers
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
        ) && let Some(rewritten) = rewrite_auth_realm(challenge, &host)
        {
            headers.insert(
                WWW_AUTHENTICATE,
                rewritten.parse().expect("rewritten challenge is valid"),
            );
        }
        let body = response.bytes().await.unwrap();
        let mut forwarded = Body::from(body).into_response();
        *forwarded.status_mut() = status;
        *forwarded.headers_mut() = headers;
        forwarded
    }

    fn rewrite_auth_realm(challenge: &str, host: &str) -> Option<String> {
        let marker = "realm=\"";
        let start = challenge.find(marker)? + marker.len();
        let end = start + challenge[start..].find('"')?;
        let mut rewritten = challenge.to_owned();
        rewritten.replace_range(start..end, &format!("http://{host}/auth/token"));
        Some(rewritten)
    }

    fn docker_compatibility(
        proxy_address: SocketAddr,
        registry_override: Option<&str>,
        password: &str,
    ) -> Result<()> {
        if registry_override.is_none() && cfg!(target_os = "macos") {
            return docker_compatibility_in_dind(proxy_address.port(), password);
        }
        let registry = registry_override
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| proxy_address.to_string());
        docker_compatibility_on_host(&registry, password)
    }

    fn docker_compatibility_on_host(registry: &str, password: &str) -> Result<()> {
        let docker_config = tempfile::tempdir()?;
        let config_file = docker_config.path().join("config.json");
        let context = tempfile::tempdir()?;
        std::fs::write(
            context.path().join("Dockerfile"),
            "FROM scratch\nCOPY hello.txt /hello.txt\n",
        )?;
        std::fs::write(context.path().join("hello.txt"), "hello from JCR\n")?;
        let reference = format!(
            "{registry}/jose/docker-{}:latest",
            &Uuid::new_v4().simple().to_string()[..8]
        );

        let mut login = docker_command(docker_config.path());
        login
            .args(["login", registry, "--username", "jose"])
            .arg("--password-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = login.spawn().context("failed to start docker login")?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{password}\n").as_bytes())?;
        let output = child.wait_with_output()?;
        ensure_docker_success(&output, "docker login")?;

        let stored = DockerCredentials::get_from_path(&config_file, registry)?
            .context("JCR could not read credentials written by Docker")?;
        if stored.username != "jose" || stored.secret != password {
            bail!("JCR read different credentials than Docker stored");
        }
        run_docker(docker_config.path(), ["logout", registry], "docker logout")?;
        DockerCredentials::store_at(&config_file, registry, "jose", password)?;

        let mut build = docker_command(docker_config.path());
        build
            .args(["build", "--tag", &reference])
            .arg(context.path());
        let output = build.output()?;
        ensure_docker_success(&output, "docker build")?;
        run_docker(docker_config.path(), ["push", &reference], "docker push")?;
        run_docker(
            docker_config.path(),
            ["image", "rm", "--force", &reference],
            "docker image rm before pull",
        )?;
        run_docker(docker_config.path(), ["pull", &reference], "docker pull")?;
        run_docker(
            docker_config.path(),
            ["image", "rm", "--force", &reference],
            "docker image cleanup",
        )?;
        run_docker(
            docker_config.path(),
            ["logout", registry],
            "docker logout cleanup",
        )?;
        Ok(())
    }

    struct DockerDind {
        network: String,
        relay: String,
        daemon: String,
        registry: String,
    }

    impl DockerDind {
        fn start(proxy_port: u16) -> Result<Self> {
            let suffix = &Uuid::new_v4().simple().to_string()[..8];
            let harness = Self {
                network: format!("jcr-test-{suffix}"),
                relay: format!("jcr-registry-{suffix}"),
                daemon: format!("jcr-dind-{suffix}"),
                registry: format!("jcr-registry-{suffix}:5000"),
            };

            let output = Command::new("docker")
                .args(["network", "create", &harness.network])
                .output()
                .context("failed to create the Docker compatibility network")?;
            ensure_docker_success(&output, "docker network create")?;

            let destination = format!("TCP:host.docker.internal:{proxy_port}");
            let output = Command::new("docker")
                .args([
                    "run",
                    "--detach",
                    "--rm",
                    "--network",
                    &harness.network,
                    "--name",
                    &harness.relay,
                    "alpine/socat",
                    "-dd",
                    "TCP-LISTEN:5000,fork,reuseaddr",
                    &destination,
                ])
                .output()
                .context("failed to start the Docker registry relay")?;
            ensure_docker_success(&output, "docker registry relay")?;

            let insecure_registry = format!("--insecure-registry={}", harness.registry);
            let output = Command::new("docker")
                .args([
                    "run",
                    "--detach",
                    "--rm",
                    "--privileged",
                    "--network",
                    &harness.network,
                    "--name",
                    &harness.daemon,
                    "docker:28-dind",
                    &insecure_registry,
                ])
                .output()
                .context("failed to start Docker-in-Docker")?;
            ensure_docker_success(&output, "docker-in-docker start")?;

            for _ in 0..120 {
                let output = Command::new("docker")
                    .args(["exec", &harness.daemon, "docker", "info"])
                    .output()?;
                if output.status.success() {
                    return Ok(harness);
                }
                std::thread::sleep(Duration::from_millis(250));
            }

            let logs = Command::new("docker")
                .args(["logs", &harness.daemon])
                .output()?;
            bail!(
                "Docker-in-Docker did not become ready\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&logs.stdout),
                String::from_utf8_lossy(&logs.stderr)
            );
        }

        fn command(&self, config: &str) -> Command {
            let mut command = Command::new("docker");
            command
                .args(["exec", "-i", &self.daemon, "docker", "--config"])
                .arg(config);
            command
        }

        fn run<const N: usize>(
            &self,
            config: &str,
            arguments: [&str; N],
            operation: &str,
        ) -> Result<()> {
            let mut command = self.command(config);
            command.args(arguments);
            let output = command.output()?;
            ensure_docker_success(&output, operation)
        }

        fn read_file(&self, path: &str) -> Result<Vec<u8>> {
            let output = Command::new("docker")
                .args(["exec", &self.daemon, "cat", path])
                .output()?;
            ensure_docker_success(&output, "read Docker compatibility file")?;
            Ok(output.stdout)
        }

        fn write_file(&self, path: &str, contents: &[u8]) -> Result<()> {
            let mut command = Command::new("docker");
            command
                .args(["exec", "-i", &self.daemon, "tee", path])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            let mut child = command.spawn()?;
            child.stdin.take().unwrap().write_all(contents)?;
            let output = child.wait_with_output()?;
            ensure_docker_success(&output, "write Docker compatibility file")
        }
    }

    impl Drop for DockerDind {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["container", "rm", "--force", &self.daemon])
                .output();
            let _ = Command::new("docker")
                .args(["container", "rm", "--force", &self.relay])
                .output();
            let _ = Command::new("docker")
                .args(["network", "rm", &self.network])
                .output();
        }
    }

    fn docker_compatibility_in_dind(proxy_port: u16, password: &str) -> Result<()> {
        let harness = DockerDind::start(proxy_port)?;
        let docker_config = "/tmp/jcr-docker";
        let docker_config_file = format!("{docker_config}/config.json");
        let local_config_directory = tempfile::tempdir()?;
        let local_config = local_config_directory.path().join("config.json");
        let reference = format!(
            "{}/jose/docker-{}:latest",
            harness.registry,
            &Uuid::new_v4().simple().to_string()[..8]
        );

        let output = Command::new("docker")
            .args(["exec", &harness.daemon, "mkdir", "-p", docker_config])
            .output()?;
        ensure_docker_success(&output, "prepare Docker compatibility directories")?;

        let mut login = harness.command(docker_config);
        login
            .args(["login", &harness.registry, "--username", "jose"])
            .arg("--password-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = login.spawn().context("failed to start docker login")?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{password}\n").as_bytes())?;
        let output = child.wait_with_output()?;
        ensure_docker_success(&output, "docker login")?;

        std::fs::write(&local_config, harness.read_file(&docker_config_file)?)?;
        let stored = DockerCredentials::get_from_path(&local_config, &harness.registry)?
            .context("JCR could not read credentials written by Docker")?;
        if stored.username != "jose" || stored.secret != password {
            bail!("JCR read different credentials than Docker stored");
        }
        harness.run(
            docker_config,
            ["logout", &harness.registry],
            "docker logout",
        )?;
        DockerCredentials::store_at(&local_config, &harness.registry, "jose", password)?;
        harness.write_file(&docker_config_file, &std::fs::read(&local_config)?)?;

        let import_script = format!(
            "mkdir -p /tmp/jcr-rootfs && \
             printf 'hello from JCR\\n' > /tmp/jcr-rootfs/hello.txt && \
             tar -C /tmp/jcr-rootfs -cf - . | docker image import - {reference}"
        );
        let output = Command::new("docker")
            .args(["exec", &harness.daemon, "sh", "-c", &import_script])
            .output()?;
        ensure_docker_success(&output, "docker image import")?;
        harness.run(docker_config, ["push", &reference], "docker push")?;
        harness.run(
            docker_config,
            ["image", "rm", "--force", &reference],
            "docker image rm before pull",
        )?;
        harness.run(docker_config, ["pull", &reference], "docker pull")?;
        harness.run(
            docker_config,
            ["image", "rm", "--force", &reference],
            "docker image cleanup",
        )?;
        harness.run(
            docker_config,
            ["logout", &harness.registry],
            "docker logout cleanup",
        )?;
        Ok(())
    }

    fn docker_command(config: &Path) -> Command {
        let mut command = Command::new("docker");
        command.arg("--config").arg(config);
        command
    }

    fn run_docker<const N: usize>(
        config: &Path,
        arguments: [&str; N],
        operation: &str,
    ) -> Result<()> {
        let mut command = docker_command(config);
        command.args(arguments);
        let output = command.output()?;
        ensure_docker_success(&output, operation)
    }

    fn ensure_docker_success(output: &std::process::Output, operation: &str) -> Result<()> {
        if output.status.success() {
            return Ok(());
        }
        bail!(
            "{operation} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}
