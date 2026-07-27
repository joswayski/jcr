use std::{collections::HashMap, str::FromStr};

use axum::{
    body::{Body, Bytes, to_bytes},
    extract::{Path, RawQuery, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{self, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE},
    },
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use futures::StreamExt;
use jcr_core::{
    AccessAction, CompletedPart, DescriptorRelationship, Digest, ManifestDocument, RepositoryScope,
    StorageUpload,
};
use regex::Regex;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    auth,
    db::{self, Repository, User},
    error::AppError,
    state::AppState,
};

const MANIFEST_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug)]
enum Endpoint {
    Blob {
        repository: String,
        digest: String,
    },
    UploadStart {
        repository: String,
    },
    Upload {
        repository: String,
        id: String,
    },
    Manifest {
        repository: String,
        reference: String,
    },
    Tags {
        repository: String,
    },
}

impl Endpoint {
    fn repository(&self) -> &str {
        match self {
            Self::Blob { repository, .. }
            | Self::UploadStart { repository }
            | Self::Upload { repository, .. }
            | Self::Manifest { repository, .. }
            | Self::Tags { repository } => repository,
        }
    }

    fn action(&self, method: &Method) -> Option<AccessAction> {
        match (self, method) {
            (
                Self::Blob { .. } | Self::Manifest { .. } | Self::Tags { .. },
                &Method::GET | &Method::HEAD,
            ) => Some(AccessAction::Pull),
            (
                Self::UploadStart { .. } | Self::Upload { .. },
                &Method::POST | &Method::PATCH | &Method::PUT | &Method::GET | &Method::DELETE,
            ) => Some(AccessAction::Push),
            (Self::Manifest { .. }, &Method::PUT) => Some(AccessAction::Push),
            (Self::Manifest { .. }, &Method::DELETE) => Some(AccessAction::Delete),
            _ => None,
        }
    }
}

struct Authorized {
    repository: Option<Repository>,
    user: Option<User>,
}

#[derive(FromRow)]
struct BlobRecord {
    digest: String,
    size: i64,
    object_key: String,
}

#[derive(FromRow)]
struct UploadRecord {
    id: Uuid,
    object_key: String,
    storage_upload_id: String,
    accepted_offset: i64,
    next_part_number: i32,
    uniform_part_size: Option<i64>,
    last_part_size: Option<i64>,
    status: String,
    expires_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ManifestRecord {
    digest: String,
    media_type: String,
    payload: Vec<u8>,
}

pub async fn dispatch(
    State(state): State<AppState>,
    Path(path): Path<String>,
    method: Method,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    body: Body,
) -> Response {
    match dispatch_inner(state, path, method, headers, raw_query, body).await {
        Ok(response) => response,
        Err(error) => error.into_oci_response(),
    }
}

async fn dispatch_inner(
    state: AppState,
    path: String,
    method: Method,
    headers: HeaderMap,
    raw_query: Option<String>,
    body: Body,
) -> Result<Response, AppError> {
    let endpoint = parse_endpoint(&path)?;
    let Some(action) = endpoint.action(&method) else {
        return Ok(registry_response(StatusCode::METHOD_NOT_ALLOWED));
    };

    let authorized = match authorize(&state, &headers, endpoint.repository(), action).await {
        Ok(authorized) => authorized,
        Err(response) => return Ok(response),
    };
    let query = parse_query(raw_query.as_deref());

    match (endpoint, method) {
        (Endpoint::Blob { digest, .. }, Method::GET) => {
            get_blob(&state, authorized, &digest, false).await
        }
        (Endpoint::Blob { digest, .. }, Method::HEAD) => {
            get_blob(&state, authorized, &digest, true).await
        }
        (Endpoint::UploadStart { repository }, Method::POST) => {
            start_upload(&state, authorized, &repository, &headers, &query, body).await
        }
        (Endpoint::Upload { id, .. }, Method::PATCH) => {
            patch_upload(&state, authorized, &id, &headers, body).await
        }
        (Endpoint::Upload { id, .. }, Method::GET) => upload_status(&state, authorized, &id).await,
        (Endpoint::Upload { id, .. }, Method::PUT) => {
            complete_upload(&state, authorized, &id, &headers, &query, body).await
        }
        (Endpoint::Upload { id, .. }, Method::DELETE) => {
            cancel_upload(&state, authorized, &id).await
        }
        (Endpoint::Manifest { reference, .. }, Method::PUT) => {
            put_manifest(&state, authorized, &reference, &headers, body).await
        }
        (Endpoint::Manifest { reference, .. }, Method::GET) => {
            get_manifest(&state, authorized, &reference, false).await
        }
        (Endpoint::Manifest { reference, .. }, Method::HEAD) => {
            get_manifest(&state, authorized, &reference, true).await
        }
        (Endpoint::Manifest { reference, .. }, Method::DELETE) => {
            delete_manifest(&state, authorized, &reference).await
        }
        (Endpoint::Tags { repository }, Method::GET) => {
            list_tags(&state, authorized, repository, &query).await
        }
        _ => Ok(registry_response(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

fn parse_endpoint(path: &str) -> Result<Endpoint, AppError> {
    if let Some((repository, suffix)) = path.split_once("/blobs/uploads/") {
        validate_repository(repository)?;
        return if suffix.is_empty() {
            Ok(Endpoint::UploadStart {
                repository: repository.to_owned(),
            })
        } else if !suffix.contains('/') {
            Ok(Endpoint::Upload {
                repository: repository.to_owned(),
                id: suffix.to_owned(),
            })
        } else {
            Err(oci(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "upload route was not found",
            ))
        };
    }

    if let Some(repository) = path.strip_suffix("/blobs/uploads") {
        validate_repository(repository)?;
        return Ok(Endpoint::UploadStart {
            repository: repository.to_owned(),
        });
    }

    if let Some((repository, digest)) = path.split_once("/blobs/") {
        validate_repository(repository)?;
        return Ok(Endpoint::Blob {
            repository: repository.to_owned(),
            digest: digest.to_owned(),
        });
    }

    if let Some((repository, reference)) = path.split_once("/manifests/") {
        validate_repository(repository)?;
        if reference.is_empty() || reference.contains('/') {
            return Err(oci(
                StatusCode::BAD_REQUEST,
                "MANIFEST_INVALID",
                "manifest reference is invalid",
            ));
        }
        return Ok(Endpoint::Manifest {
            repository: repository.to_owned(),
            reference: reference.to_owned(),
        });
    }

    if let Some(repository) = path.strip_suffix("/tags/list") {
        validate_repository(repository)?;
        return Ok(Endpoint::Tags {
            repository: repository.to_owned(),
        });
    }

    Err(oci(
        StatusCode::NOT_FOUND,
        "NAME_UNKNOWN",
        "registry route was not found",
    ))
}

fn validate_repository(repository: &str) -> Result<(), AppError> {
    let valid = repository.contains('/')
        && repository.split('/').all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        });
    if valid {
        Ok(())
    } else {
        Err(oci(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            "repository names must use namespace/name",
        ))
    }
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    repository_name: &str,
    action: AccessAction,
) -> Result<Authorized, Response> {
    let repository = match db::find_repository(&state.pool, repository_name).await {
        Ok(repository) => repository,
        Err(error) => return Err(error.into_oci_response()),
    };
    let principal = match auth::authenticate(state, headers).await {
        Ok(principal) => principal,
        Err(_) => {
            return Err(auth::challenge_response(
                state,
                Some(&RepositoryScope::new(repository_name, [action])),
                StatusCode::UNAUTHORIZED,
            ));
        }
    };

    if action == AccessAction::Pull
        && repository.as_ref().is_some_and(Repository::is_public)
        && principal.is_none()
    {
        return Ok(Authorized {
            repository,
            user: None,
        });
    }

    let Some(principal) = principal else {
        return Err(auth::challenge_response(
            state,
            Some(&RepositoryScope::new(repository_name, [action])),
            StatusCode::UNAUTHORIZED,
        ));
    };

    let database_allowed = match &repository {
        Some(repository) => {
            db::authorize_repository(&state.pool, principal.user.as_ref(), repository, action).await
        }
        None => {
            db::authorize_repository_name(
                &state.pool,
                principal.user.as_ref(),
                repository_name,
                action,
            )
            .await
        }
    };
    let database_allowed = match database_allowed {
        Ok(allowed) => allowed,
        Err(error) => return Err(error.into_oci_response()),
    };
    let token_allowed = !principal.bearer || principal.permits(repository_name, action);

    if !database_allowed || !token_allowed {
        return Err(oci(
            StatusCode::FORBIDDEN,
            "DENIED",
            "requested repository access is denied",
        )
        .into_oci_response());
    }

    Ok(Authorized {
        repository,
        user: principal.user,
    })
}

async fn get_blob(
    state: &AppState,
    authorized: Authorized,
    digest: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    let digest = Digest::from_str(digest)
        .map_err(|error| oci(StatusCode::BAD_REQUEST, "DIGEST_INVALID", error.to_string()))?;
    let repository = require_repository(authorized.repository)?;
    let blob = sqlx::query_as::<_, BlobRecord>(
        "SELECT b.digest, b.size, b.object_key
         FROM blobs b
         JOIN repository_blobs rb ON rb.digest = b.digest
         WHERE rb.repository_id = $1
           AND b.digest = $2
           AND b.status = 'committed'",
    )
    .bind(repository.id)
    .bind(digest.to_string())
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        oci(
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
            "blob was not found in this repository",
        )
    })?;

    let mut response = if head_only {
        registry_response(StatusCode::OK)
    } else if let Some(url) = state
        .blob_store
        .signed_get_url(&blob.object_key, 300)
        .await?
    {
        let mut response = registry_response(StatusCode::TEMPORARY_REDIRECT);
        insert_header(&mut response, LOCATION, &url)?;
        response
    } else {
        let stream = state.blob_store.stream(&blob.object_key).await?;
        let mut response = Body::from_stream(stream).into_response();
        *response.status_mut() = StatusCode::OK;
        add_registry_version(&mut response);
        response
    };
    // Content-Length describes the redirect response body, not the object at
    // its signed destination. Sending the blob size on an empty 307 response
    // makes strict HTTP clients wait for bytes that will never arrive.
    if response.status() != StatusCode::TEMPORARY_REDIRECT {
        insert_header(
            &mut response,
            header::CONTENT_LENGTH,
            &blob.size.to_string(),
        )?;
    }
    insert_header(
        &mut response,
        HeaderName::from_static("docker-content-digest"),
        &blob.digest,
    )?;
    insert_header(&mut response, CONTENT_TYPE, "application/octet-stream")?;
    Ok(response)
}

async fn start_upload(
    state: &AppState,
    authorized: Authorized,
    repository_name: &str,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
    body: Body,
) -> Result<Response, AppError> {
    let actor = authorized
        .user
        .ok_or_else(|| AppError::Denied("push requires a user".to_owned()))?;
    let repository = match authorized.repository {
        Some(repository) => repository,
        None => db::ensure_repository_for_push(&state.pool, repository_name, &actor).await?,
    };

    if let (Some(mount), Some(from)) = (query.get("mount"), query.get("from"))
        && let Ok(digest) = Digest::from_str(mount)
        && mount_blob(state, &actor, &repository, from, &digest).await?
    {
        let location = format!("/v2/{repository_name}/blobs/{digest}");
        let mut response = registry_response(StatusCode::CREATED);
        insert_header(&mut response, LOCATION, &location)?;
        insert_header(
            &mut response,
            HeaderName::from_static("docker-content-digest"),
            &digest.to_string(),
        )?;
        return Ok(response);
    }

    let id = Uuid::new_v4();
    let object_key = format!("uploads/{id}");
    let storage = state.blob_store.initiate_upload(&object_key).await?;
    let expires_at = Utc::now() + Duration::hours(state.config.upload_session_hours);
    if let Err(error) = sqlx::query(
        "INSERT INTO upload_sessions (
             id, repository_id, actor_user_id, object_key, storage_upload_id,
             expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(repository.id)
    .bind(actor.id)
    .bind(&object_key)
    .bind(&storage.upload_id)
    .bind(expires_at)
    .execute(&state.pool)
    .await
    {
        let _ = state.blob_store.abort_upload(&storage).await;
        return Err(error.into());
    }

    if query.contains_key("digest") {
        return complete_upload(
            state,
            Authorized {
                repository: Some(repository),
                user: Some(actor),
            },
            &id.to_string(),
            headers,
            query,
            body,
        )
        .await;
    }

    let mut response = registry_response(StatusCode::ACCEPTED);
    set_upload_headers(&mut response, repository_name, id, 0)?;
    Ok(response)
}

async fn mount_blob(
    state: &AppState,
    actor: &User,
    target: &Repository,
    source_name: &str,
    digest: &Digest,
) -> Result<bool, AppError> {
    let Some(source) = db::find_repository(&state.pool, source_name).await? else {
        return Ok(false);
    };
    if !db::authorize_repository(&state.pool, Some(actor), &source, AccessAction::Pull).await? {
        return Ok(false);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM repository_blobs rb
             JOIN blobs b ON b.digest = rb.digest
             WHERE rb.repository_id = $1 AND rb.digest = $2
               AND b.status = 'committed'
         )",
    )
    .bind(source.id)
    .bind(digest.to_string())
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO repository_blobs (repository_id, digest)
         VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(target.id)
    .bind(digest.to_string())
    .execute(&state.pool)
    .await?;
    Ok(true)
}

async fn patch_upload(
    state: &AppState,
    authorized: Authorized,
    id: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, AppError> {
    let repository = require_repository(authorized.repository)?;
    let id = parse_upload_id(id)?;
    let bytes = read_body(body, headers, state.config.upload_chunk_limit).await?;
    if bytes.is_empty() {
        return Err(oci(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            "PATCH chunks cannot be empty",
        ));
    }

    let mut transaction = state.pool.begin().await?;
    let upload = lock_upload(&mut transaction, repository.id, id).await?;
    validate_upload(&upload)?;
    validate_content_range(headers, upload.accepted_offset, bytes.len())?;
    if let Some(size) = upload.uniform_part_size {
        if upload.last_part_size.is_some_and(|last| last < size) {
            return Err(oci(
                StatusCode::BAD_REQUEST,
                "BLOB_UPLOAD_INVALID",
                "a short final PATCH was already accepted; complete the upload with an empty PUT",
            ));
        }
        if bytes.len() as i64 > size {
            return Err(oci(
                StatusCode::BAD_REQUEST,
                "BLOB_UPLOAD_INVALID",
                "PATCH chunks cannot exceed the first chunk size",
            ));
        }
    }

    let storage = storage_upload(&upload);
    let completed = state
        .blob_store
        .upload_part(&storage, upload.next_part_number, bytes)
        .await?;
    persist_part(&mut transaction, &upload, &completed, true).await?;
    transaction.commit().await?;

    let new_offset = upload.accepted_offset + completed.size as i64;
    let mut response = registry_response(StatusCode::ACCEPTED);
    set_upload_headers(&mut response, &repository.full_name(), id, new_offset)?;
    Ok(response)
}

async fn upload_status(
    state: &AppState,
    authorized: Authorized,
    id: &str,
) -> Result<Response, AppError> {
    let repository = require_repository(authorized.repository)?;
    let id = parse_upload_id(id)?;
    let upload = fetch_upload(&state.pool, repository.id, id).await?;
    validate_upload(&upload)?;
    let mut response = registry_response(StatusCode::NO_CONTENT);
    set_upload_headers(
        &mut response,
        &repository.full_name(),
        id,
        upload.accepted_offset,
    )?;
    Ok(response)
}

async fn complete_upload(
    state: &AppState,
    authorized: Authorized,
    id: &str,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
    body: Body,
) -> Result<Response, AppError> {
    let repository = require_repository(authorized.repository)?;
    let actor = authorized.user;
    let id = parse_upload_id(id)?;
    let expected = query
        .get("digest")
        .ok_or_else(|| {
            oci(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "completion requires a digest query parameter",
            )
        })?
        .parse::<Digest>()
        .map_err(|error| oci(StatusCode::BAD_REQUEST, "DIGEST_INVALID", error.to_string()))?;
    let final_bytes = read_body(body, headers, state.config.upload_chunk_limit).await?;

    let mut transaction = state.pool.begin().await?;
    let upload = lock_upload(&mut transaction, repository.id, id).await?;
    validate_upload(&upload)?;
    validate_content_range(headers, upload.accepted_offset, final_bytes.len())?;
    let storage = storage_upload(&upload);

    if !final_bytes.is_empty() {
        if upload
            .uniform_part_size
            .zip(upload.last_part_size)
            .is_some_and(|(uniform, last)| last < uniform)
        {
            return Err(oci(
                StatusCode::BAD_REQUEST,
                "BLOB_UPLOAD_INVALID",
                "a short final PATCH was already accepted; finish with an empty PUT",
            ));
        }
        if let Some(uniform) = upload.uniform_part_size
            && final_bytes.len() as i64 > uniform
        {
            return Err(oci(
                StatusCode::BAD_REQUEST,
                "BLOB_UPLOAD_INVALID",
                "the final PUT chunk cannot exceed the PATCH chunk size",
            ));
        }
        let completed = state
            .blob_store
            .upload_part(&storage, upload.next_part_number, final_bytes)
            .await?;
        persist_part(&mut transaction, &upload, &completed, false).await?;
    }
    sqlx::query(
        "UPDATE upload_sessions
         SET status = 'finalizing', updated_at = NOW()
         WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let parts = upload_parts(&state.pool, id).await?;
    if parts.is_empty() {
        state.blob_store.abort_upload(&storage).await?;
        state
            .blob_store
            .put(&upload.object_key, Bytes::new())
            .await?;
    } else {
        state.blob_store.complete_upload(&storage, &parts).await?;
    }

    let (actual, size) = hash_stored_blob(state, &upload.object_key).await?;
    if actual != expected {
        state.blob_store.delete(&upload.object_key).await?;
        mark_upload_failed(
            &state.pool,
            id,
            &format!("expected {expected}, received {actual}"),
        )
        .await?;
        return Err(oci(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            format!("expected {expected}, received {actual}"),
        ));
    }

    repair_missing_blob_metadata(state, &expected).await?;
    let duplicate_key = commit_blob(
        &state.pool,
        &repository,
        id,
        &upload.object_key,
        &expected,
        size,
    )
    .await?;
    if duplicate_key {
        state.blob_store.delete(&upload.object_key).await?;
    }
    db::insert_audit(
        &state.pool,
        actor.as_ref().map(|user| user.id),
        "blob.uploaded",
        Some(repository.id),
        Some("blob"),
        Some(&expected.to_string()),
        serde_json::json!({"size": size}),
    )
    .await?;

    let location = format!("/v2/{}/blobs/{expected}", repository.full_name());
    let mut response = registry_response(StatusCode::CREATED);
    insert_header(&mut response, LOCATION, &location)?;
    insert_header(
        &mut response,
        HeaderName::from_static("docker-content-digest"),
        &expected.to_string(),
    )?;
    Ok(response)
}

async fn cancel_upload(
    state: &AppState,
    authorized: Authorized,
    id: &str,
) -> Result<Response, AppError> {
    let repository = require_repository(authorized.repository)?;
    let id = parse_upload_id(id)?;
    let upload = fetch_upload(&state.pool, repository.id, id).await?;
    validate_upload(&upload)?;
    state
        .blob_store
        .abort_upload(&storage_upload(&upload))
        .await?;
    sqlx::query(
        "UPDATE upload_sessions
         SET status = 'cancelled', updated_at = NOW()
         WHERE id = $1 AND status = 'uploading'",
    )
    .bind(id)
    .execute(&state.pool)
    .await?;
    Ok(registry_response(StatusCode::NO_CONTENT))
}

async fn put_manifest(
    state: &AppState,
    authorized: Authorized,
    reference: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, AppError> {
    let repository = require_repository(authorized.repository)?;
    let actor = authorized
        .user
        .ok_or_else(|| AppError::Denied("manifest push requires a user".to_owned()))?;
    let bytes = read_body(body, headers, MANIFEST_LIMIT).await?;
    let supplied_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let manifest = ManifestDocument::parse(bytes.to_vec(), supplied_type).map_err(|error| {
        oci(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            error.to_string(),
        )
    })?;

    if let Ok(reference_digest) = reference.parse::<Digest>()
        && reference_digest != *manifest.digest()
    {
        return Err(oci(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "manifest bytes do not match the digest reference",
        ));
    }

    validate_manifest_dependencies(&state.pool, &repository, &manifest).await?;
    persist_manifest(&state.pool, &repository, &actor, reference, &manifest).await?;

    let location = format!(
        "/v2/{}/manifests/{}",
        repository.full_name(),
        manifest.digest()
    );
    let mut response = registry_response(StatusCode::CREATED);
    insert_header(&mut response, LOCATION, &location)?;
    insert_header(
        &mut response,
        HeaderName::from_static("docker-content-digest"),
        &manifest.digest().to_string(),
    )?;
    Ok(response)
}

async fn get_manifest(
    state: &AppState,
    authorized: Authorized,
    reference: &str,
    head_only: bool,
) -> Result<Response, AppError> {
    let repository = require_repository(authorized.repository)?;
    let manifest = if reference.parse::<Digest>().is_ok() {
        sqlx::query_as::<_, ManifestRecord>(
            "SELECT m.digest, m.media_type, m.payload
             FROM manifests m
             JOIN repository_manifests rm ON rm.digest = m.digest
             WHERE rm.repository_id = $1
               AND rm.digest = $2
               AND rm.deleted_at IS NULL",
        )
        .bind(repository.id)
        .bind(reference)
        .fetch_optional(&state.pool)
        .await?
    } else {
        sqlx::query_as::<_, ManifestRecord>(
            "SELECT m.digest, m.media_type, m.payload
             FROM tags t
             JOIN manifests m ON m.digest = t.manifest_digest
             JOIN repository_manifests rm
               ON rm.repository_id = t.repository_id
              AND rm.digest = m.digest
              AND rm.deleted_at IS NULL
             WHERE t.repository_id = $1 AND t.name = $2",
        )
        .bind(repository.id)
        .bind(reference)
        .fetch_optional(&state.pool)
        .await?
    }
    .ok_or_else(|| {
        oci(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            "manifest was not found",
        )
    })?;

    let mut response = if head_only {
        registry_response(StatusCode::OK)
    } else {
        let mut response = Body::from(manifest.payload.clone()).into_response();
        *response.status_mut() = StatusCode::OK;
        add_registry_version(&mut response);
        response
    };
    insert_header(&mut response, CONTENT_TYPE, &manifest.media_type)?;
    insert_header(
        &mut response,
        CONTENT_LENGTH,
        &manifest.payload.len().to_string(),
    )?;
    insert_header(
        &mut response,
        HeaderName::from_static("docker-content-digest"),
        &manifest.digest,
    )?;
    Ok(response)
}

async fn delete_manifest(
    state: &AppState,
    authorized: Authorized,
    reference: &str,
) -> Result<Response, AppError> {
    let repository = require_repository(authorized.repository)?;
    let actor = authorized
        .user
        .ok_or_else(|| AppError::Denied("manifest deletion requires a user".to_owned()))?;
    let digest = reference.parse::<Digest>().map_err(|_| {
        oci(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "manifests must be deleted by digest",
        )
    })?;
    let mut transaction = state.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE repository_manifests
         SET deleted_at = NOW()
         WHERE repository_id = $1 AND digest = $2 AND deleted_at IS NULL",
    )
    .bind(repository.id)
    .bind(digest.to_string())
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(oci(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            "manifest was not found",
        ));
    }
    let tags: Vec<String> = sqlx::query_scalar(
        "DELETE FROM tags
         WHERE repository_id = $1 AND manifest_digest = $2
         RETURNING name",
    )
    .bind(repository.id)
    .bind(digest.to_string())
    .fetch_all(&mut *transaction)
    .await?;
    for tag in tags {
        sqlx::query(
            "INSERT INTO tag_events (
                 id, repository_id, tag_name, previous_digest,
                 new_digest, actor_user_id
             ) VALUES ($1, $2, $3, $4, NULL, $5)",
        )
        .bind(Uuid::new_v4())
        .bind(repository.id)
        .bind(tag)
        .bind(digest.to_string())
        .bind(actor.id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    db::insert_audit(
        &state.pool,
        Some(actor.id),
        "manifest.deleted",
        Some(repository.id),
        Some("manifest"),
        Some(&digest.to_string()),
        serde_json::json!({}),
    )
    .await?;
    Ok(registry_response(StatusCode::ACCEPTED))
}

async fn list_tags(
    state: &AppState,
    authorized: Authorized,
    repository_name: String,
    query: &HashMap<String, String>,
) -> Result<Response, AppError> {
    let repository = require_repository(authorized.repository)?;
    let limit = query
        .get("n")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let last = query.get("last").map(String::as_str).unwrap_or("");
    let mut tags: Vec<String> = sqlx::query_scalar(
        "SELECT name
         FROM tags
         WHERE repository_id = $1 AND name > $2
         ORDER BY name
         LIMIT $3",
    )
    .bind(repository.id)
    .bind(last)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;

    #[derive(Serialize)]
    struct TagList {
        name: String,
        tags: Vec<String>,
    }
    let has_more = tags.len() as i64 > limit;
    if has_more {
        tags.truncate(limit as usize);
    }
    let next = tags.last().cloned();
    let mut response = axum::Json(TagList {
        name: repository_name,
        tags,
    })
    .into_response();
    add_registry_version(&mut response);
    if has_more && let Some(next) = next {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("n", &limit.to_string())
            .append_pair("last", &next)
            .finish();
        insert_header(
            &mut response,
            HeaderName::from_static("link"),
            &format!(
                "</v2/{}/tags/list?{}>; rel=\"next\"",
                repository.full_name(),
                query
            ),
        )?;
    }
    Ok(response)
}

async fn validate_manifest_dependencies(
    pool: &sqlx::PgPool,
    repository: &Repository,
    manifest: &ManifestDocument,
) -> Result<(), AppError> {
    for (relationship, _, descriptor) in manifest.descriptors() {
        if descriptor.size < 0 {
            return Err(oci(
                StatusCode::BAD_REQUEST,
                "MANIFEST_INVALID",
                "descriptor sizes cannot be negative",
            ));
        }
        let exists: bool = match relationship {
            DescriptorRelationship::Config | DescriptorRelationship::Layer => {
                sqlx::query_scalar(
                    "SELECT EXISTS(
                         SELECT 1 FROM repository_blobs rb
                         JOIN blobs b ON b.digest = rb.digest
                         WHERE rb.repository_id = $1 AND rb.digest = $2
                           AND b.status = 'committed' AND b.size = $3
                     )",
                )
                .bind(repository.id)
                .bind(descriptor.digest.to_string())
                .bind(descriptor.size)
                .fetch_one(pool)
                .await?
            }
            DescriptorRelationship::Manifest => {
                sqlx::query_scalar(
                    "SELECT EXISTS(
                         SELECT 1 FROM repository_manifests
                         WHERE repository_id = $1 AND digest = $2
                           AND deleted_at IS NULL
                     )",
                )
                .bind(repository.id)
                .bind(descriptor.digest.to_string())
                .fetch_one(pool)
                .await?
            }
            // A subject may arrive after its referring artifact. Keeping the
            // generic relationship is what makes future referrers possible.
            DescriptorRelationship::Subject => true,
        };
        if !exists {
            return Err(oci(
                StatusCode::BAD_REQUEST,
                "MANIFEST_BLOB_UNKNOWN",
                format!(
                    "{} descriptor {} is unavailable in this repository",
                    relationship.as_str(),
                    descriptor.digest
                ),
            ));
        }
    }
    Ok(())
}

async fn persist_manifest(
    pool: &sqlx::PgPool,
    repository: &Repository,
    actor: &User,
    reference: &str,
    manifest: &ManifestDocument,
) -> Result<(), AppError> {
    let digest = manifest.digest().to_string();
    let subject = manifest.subject().map(|value| value.digest.to_string());
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO manifests (
             digest, media_type, artifact_type, subject_digest, size, payload
         ) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (digest) DO NOTHING",
    )
    .bind(&digest)
    .bind(manifest.media_type())
    .bind(manifest.artifact_type())
    .bind(subject)
    .bind(manifest.raw().len() as i64)
    .bind(manifest.raw())
    .execute(&mut *transaction)
    .await?;

    for (relationship, position, descriptor) in manifest.descriptors() {
        sqlx::query(
            "INSERT INTO descriptor_edges (
                 parent_digest, child_digest, relationship, position,
                 media_type, size, platform, annotations
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT DO NOTHING",
        )
        .bind(&digest)
        .bind(descriptor.digest.to_string())
        .bind(relationship.as_str())
        .bind(position as i32)
        .bind(&descriptor.media_type)
        .bind(descriptor.size)
        .bind(&descriptor.platform)
        .bind(
            descriptor
                .annotations
                .as_ref()
                .map(|annotations| serde_json::Value::Object(annotations.clone())),
        )
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "INSERT INTO repository_manifests (repository_id, digest)
         VALUES ($1, $2)
         ON CONFLICT (repository_id, digest)
         DO UPDATE SET deleted_at = NULL, linked_at = NOW()",
    )
    .bind(repository.id)
    .bind(&digest)
    .execute(&mut *transaction)
    .await?;

    if reference.parse::<Digest>().is_err() {
        validate_tag(reference)?;
        let previous: Option<String> = sqlx::query_scalar(
            "SELECT manifest_digest FROM tags
             WHERE repository_id = $1 AND name = $2
             FOR UPDATE",
        )
        .bind(repository.id)
        .bind(reference)
        .fetch_optional(&mut *transaction)
        .await?;
        if previous.as_deref().is_some_and(|value| value != digest)
            && let Some(pattern) = &repository.immutable_tag_pattern
        {
            let pattern = Regex::new(pattern).map_err(|error| {
                AppError::Internal(anyhow::anyhow!("invalid immutable tag pattern: {error}"))
            })?;
            if pattern.is_match(reference) {
                return Err(oci(
                    StatusCode::CONFLICT,
                    "TAG_INVALID",
                    "this release tag is immutable",
                ));
            }
        }
        sqlx::query(
            "INSERT INTO tags (repository_id, name, manifest_digest)
             VALUES ($1, $2, $3)
             ON CONFLICT (repository_id, name)
             DO UPDATE SET manifest_digest = EXCLUDED.manifest_digest,
                           updated_at = NOW()",
        )
        .bind(repository.id)
        .bind(reference)
        .bind(&digest)
        .execute(&mut *transaction)
        .await?;
        if previous.as_deref() != Some(&digest) {
            sqlx::query(
                "INSERT INTO tag_events (
                     id, repository_id, tag_name, previous_digest,
                     new_digest, actor_user_id
                 ) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(Uuid::new_v4())
            .bind(repository.id)
            .bind(reference)
            .bind(previous)
            .bind(&digest)
            .bind(actor.id)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;
    db::insert_audit(
        pool,
        Some(actor.id),
        "manifest.pushed",
        Some(repository.id),
        Some("manifest"),
        Some(&digest),
        serde_json::json!({"reference": reference}),
    )
    .await?;
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), AppError> {
    let valid = !tag.is_empty()
        && tag.len() <= 128
        && tag.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-') && index > 0
        });
    if valid {
        Ok(())
    } else {
        Err(oci(
            StatusCode::BAD_REQUEST,
            "TAG_INVALID",
            "tag is invalid",
        ))
    }
}

async fn lock_upload(
    transaction: &mut Transaction<'_, Postgres>,
    repository_id: Uuid,
    id: Uuid,
) -> Result<UploadRecord, AppError> {
    sqlx::query_as::<_, UploadRecord>(
        "SELECT u.id, u.object_key, u.storage_upload_id,
                accepted_offset, next_part_number, uniform_part_size,
                (
                    SELECT p.size FROM upload_parts p
                    WHERE p.upload_id = u.id
                    ORDER BY p.part_number DESC LIMIT 1
                ) AS last_part_size,
                u.status::text AS status, u.expires_at
         FROM upload_sessions u
         WHERE u.id = $1 AND u.repository_id = $2
         FOR UPDATE",
    )
    .bind(id)
    .bind(repository_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| {
        oci(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "upload session was not found",
        )
    })
}

async fn fetch_upload(
    pool: &sqlx::PgPool,
    repository_id: Uuid,
    id: Uuid,
) -> Result<UploadRecord, AppError> {
    sqlx::query_as::<_, UploadRecord>(
        "SELECT u.id, u.object_key, u.storage_upload_id,
                accepted_offset, next_part_number, uniform_part_size,
                (
                    SELECT p.size FROM upload_parts p
                    WHERE p.upload_id = u.id
                    ORDER BY p.part_number DESC LIMIT 1
                ) AS last_part_size,
                u.status::text AS status, u.expires_at
         FROM upload_sessions u
         WHERE u.id = $1 AND u.repository_id = $2",
    )
    .bind(id)
    .bind(repository_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| {
        oci(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "upload session was not found",
        )
    })
}

fn validate_upload(upload: &UploadRecord) -> Result<(), AppError> {
    if upload.status != "uploading" || upload.expires_at <= Utc::now() {
        return Err(oci(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "upload session is unavailable or expired",
        ));
    }
    Ok(())
}

async fn persist_part(
    transaction: &mut Transaction<'_, Postgres>,
    upload: &UploadRecord,
    part: &CompletedPart,
    establish_uniform_size: bool,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO upload_parts (upload_id, part_number, etag, size)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(upload.id)
    .bind(part.part_number)
    .bind(&part.etag)
    .bind(part.size as i64)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE upload_sessions
         SET accepted_offset = accepted_offset + $2,
             next_part_number = next_part_number + 1,
             uniform_part_size = CASE
                 WHEN $3 AND uniform_part_size IS NULL THEN $2
                 ELSE uniform_part_size
             END,
             updated_at = NOW()
         WHERE id = $1",
    )
    .bind(upload.id)
    .bind(part.size as i64)
    .bind(establish_uniform_size)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn upload_parts(
    pool: &sqlx::PgPool,
    upload_id: Uuid,
) -> Result<Vec<CompletedPart>, AppError> {
    #[derive(FromRow)]
    struct Part {
        part_number: i32,
        etag: String,
        size: i64,
    }
    let parts = sqlx::query_as::<_, Part>(
        "SELECT part_number, etag, size
         FROM upload_parts
         WHERE upload_id = $1
         ORDER BY part_number",
    )
    .bind(upload_id)
    .fetch_all(pool)
    .await?;
    Ok(parts
        .into_iter()
        .map(|part| CompletedPart {
            part_number: part.part_number,
            etag: part.etag,
            size: part.size as u64,
        })
        .collect())
}

async fn hash_stored_blob(state: &AppState, key: &str) -> Result<(Digest, i64), AppError> {
    let mut stream = state.blob_store.stream(key).await?;
    let mut hasher = Sha256::new();
    let mut size = 0_i64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        size = size
            .checked_add(chunk.len() as i64)
            .ok_or_else(|| AppError::PayloadTooLarge("blob is too large".to_owned()))?;
        hasher.update(&chunk);
    }
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()))
        .parse()
        .expect("SHA-256 output is always a valid OCI digest");
    Ok((digest, size))
}

async fn repair_missing_blob_metadata(state: &AppState, digest: &Digest) -> Result<(), AppError> {
    let object_key: Option<String> = sqlx::query_scalar(
        "SELECT object_key
         FROM blobs
         WHERE digest = $1 AND status = 'committed'",
    )
    .bind(digest.to_string())
    .fetch_optional(&state.pool)
    .await?;
    let Some(object_key) = object_key else {
        return Ok(());
    };
    if state.blob_store.exists(&object_key).await? {
        return Ok(());
    }
    sqlx::query(
        "UPDATE blobs
         SET status = 'tombstoned', tombstoned_at = NOW()
         WHERE digest = $1 AND object_key = $2 AND status = 'committed'",
    )
    .bind(digest.to_string())
    .bind(object_key)
    .execute(&state.pool)
    .await?;
    Ok(())
}

async fn commit_blob(
    pool: &sqlx::PgPool,
    repository: &Repository,
    upload_id: Uuid,
    object_key: &str,
    digest: &Digest,
    size: i64,
) -> Result<bool, AppError> {
    let digest = digest.to_string();
    let mut transaction = pool.begin().await?;
    #[derive(FromRow)]
    struct ExistingBlob {
        object_key: String,
        status: String,
    }
    let existing = sqlx::query_as::<_, ExistingBlob>(
        "SELECT object_key, status::text AS status
         FROM blobs WHERE digest = $1 FOR UPDATE",
    )
    .bind(&digest)
    .fetch_optional(&mut *transaction)
    .await?;
    let duplicate = existing
        .as_ref()
        .is_some_and(|blob| blob.status == "committed" && blob.object_key != object_key);
    sqlx::query(
        "INSERT INTO blobs (digest, size, object_key, status)
         VALUES ($1, $2, $3, 'committed')
         ON CONFLICT (digest)
         DO UPDATE SET
             size = CASE WHEN blobs.status = 'tombstoned'
                         THEN EXCLUDED.size ELSE blobs.size END,
             object_key = CASE WHEN blobs.status = 'tombstoned'
                               THEN EXCLUDED.object_key ELSE blobs.object_key END,
             status = 'committed',
             tombstoned_at = NULL",
    )
    .bind(&digest)
    .bind(size)
    .bind(object_key)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO repository_blobs (repository_id, digest)
         VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(repository.id)
    .bind(&digest)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE upload_sessions
         SET status = 'committed', accepted_offset = $2, updated_at = NOW()
         WHERE id = $1",
    )
    .bind(upload_id)
    .bind(size)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(duplicate)
}

async fn mark_upload_failed(pool: &sqlx::PgPool, id: Uuid, message: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE upload_sessions
         SET status = 'failed', error_message = $2, updated_at = NOW()
         WHERE id = $1",
    )
    .bind(id)
    .bind(message)
    .execute(pool)
    .await?;
    Ok(())
}

fn validate_content_range(
    headers: &HeaderMap,
    expected_offset: i64,
    body_len: usize,
) -> Result<(), AppError> {
    let Some(value) = headers.get(CONTENT_RANGE) else {
        return Ok(());
    };
    let value = value.to_str().map_err(|_| {
        oci(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            "Content-Range is invalid",
        )
    })?;
    let value = value
        .strip_prefix("bytes ")
        .unwrap_or(value)
        .split('/')
        .next()
        .unwrap_or(value);
    let (start, end) = value.split_once('-').ok_or_else(|| {
        oci(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            "Content-Range must be start-end",
        )
    })?;
    let start = start.parse::<i64>().map_err(|_| {
        oci(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            "Content-Range start is invalid",
        )
    })?;
    let end = end.parse::<i64>().map_err(|_| {
        oci(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            "Content-Range end is invalid",
        )
    })?;
    if start != expected_offset
        || body_len > 0 && end != start + body_len as i64 - 1
        || body_len == 0 && end >= start
    {
        return Err(oci(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "BLOB_UPLOAD_INVALID",
            format!("expected the next byte at offset {expected_offset}"),
        ));
    }
    Ok(())
}

async fn read_body(body: Body, headers: &HeaderMap, limit: usize) -> Result<Bytes, AppError> {
    if let Some(length) = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        && length > limit
    {
        return Err(oci(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SIZE_INVALID",
            format!("request bodies are limited to {limit} bytes"),
        ));
    }
    to_bytes(body, limit).await.map_err(|_| {
        oci(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SIZE_INVALID",
            format!("request bodies are limited to {limit} bytes"),
        )
    })
}

fn parse_query(raw: Option<&str>) -> HashMap<String, String> {
    raw.map(|raw| {
        url::form_urlencoded::parse(raw.as_bytes())
            .into_owned()
            .collect()
    })
    .unwrap_or_default()
}

fn parse_upload_id(value: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(value).map_err(|_| {
        oci(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "upload session id is invalid",
        )
    })
}

fn require_repository(repository: Option<Repository>) -> Result<Repository, AppError> {
    repository.ok_or_else(|| {
        oci(
            StatusCode::NOT_FOUND,
            "NAME_UNKNOWN",
            "repository was not found",
        )
    })
}

fn storage_upload(upload: &UploadRecord) -> StorageUpload {
    StorageUpload {
        key: upload.object_key.clone(),
        upload_id: upload.storage_upload_id.clone(),
    }
}

fn set_upload_headers(
    response: &mut Response,
    repository: &str,
    id: Uuid,
    offset: i64,
) -> Result<(), AppError> {
    insert_header(
        response,
        LOCATION,
        &format!("/v2/{repository}/blobs/uploads/{id}"),
    )?;
    insert_header(
        response,
        HeaderName::from_static("docker-upload-uuid"),
        &id.to_string(),
    )?;
    if offset > 0 {
        insert_header(response, RANGE, &format!("0-{}", offset - 1))?;
    }
    Ok(())
}

fn registry_response(status: StatusCode) -> Response {
    auth::registry_api_response(status)
}

fn add_registry_version(response: &mut Response) {
    response.headers_mut().insert(
        HeaderName::from_static("docker-distribution-api-version"),
        HeaderValue::from_static("registry/2.0"),
    );
}

fn insert_header(response: &mut Response, name: HeaderName, value: &str) -> Result<(), AppError> {
    let value = HeaderValue::from_str(value).map_err(|error| AppError::Internal(error.into()))?;
    response.headers_mut().insert(name, value);
    Ok(())
}

fn oci(status: StatusCode, code: &'static str, message: impl Into<String>) -> AppError {
    AppError::Oci {
        status,
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_repository_routes() {
        let endpoint = parse_endpoint("jose/tools/app/blobs/uploads/123").unwrap();
        assert!(matches!(
            endpoint,
            Endpoint::Upload { repository, id }
                if repository == "jose/tools/app" && id == "123"
        ));
    }

    #[test]
    fn validates_chunk_ranges() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_RANGE, HeaderValue::from_static("64-127"));
        assert!(validate_content_range(&headers, 64, 64).is_ok());
        assert!(validate_content_range(&headers, 0, 64).is_err());
    }

    #[test]
    fn validates_tags() {
        assert!(validate_tag("v1.2.3").is_ok());
        assert!(validate_tag("-release").is_err());
        assert!(validate_tag("bad/tag").is_err());
    }
}
