use axum::{
    Form, Router,
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;
use sqlx::FromRow;
use tower_cookies::{Cookie, Cookies, cookie::SameSite};
use uuid::Uuid;

use crate::{
    db::{self, BrowserSession, User, VerifiedLogin},
    error::AppError,
    state::AppState,
};

const SESSION_COOKIE: &str = "jcr_session";

#[derive(FromRow)]
struct RepositoryView {
    id: Uuid,
    full_name: String,
    visibility: String,
    immutable_tag_pattern: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct PatView {
    id: Uuid,
    name: String,
    token_prefix: String,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct TagView {
    repository: String,
    name: String,
    manifest_digest: String,
    updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct TagEventView {
    repository: String,
    tag_name: String,
    previous_digest: Option<String>,
    new_digest: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct UploadView {
    repository: String,
    id: Uuid,
    status: String,
    accepted_offset: i64,
    error_message: Option<String>,
    updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct AuditView {
    action: String,
    resource_type: Option<String>,
    resource_id: Option<String>,
    created_at: DateTime<Utc>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/registry", get(index))
        .route("/registry/", get(index))
        .route("/registry/login", get(login))
        .route("/registry/auth/callback", get(callback))
        .route("/registry/logout", post(logout))
        .route("/registry/tokens", post(create_pat))
        .route("/registry/tokens/{id}/revoke", post(revoke_pat))
        .route("/registry/repositories", post(create_repository))
        .route(
            "/registry/repositories/{id}/visibility",
            post(update_visibility),
        )
        .route(
            "/registry/repositories/{id}/manifests/delete",
            post(delete_manifest),
        )
}

async fn index(State(state): State<AppState>, cookies: Cookies) -> Result<Html<String>, AppError> {
    let Some((session, user)) = current_session(&state, &cookies).await? else {
        return Ok(render("JCR", public_page(state.config.google.is_some())));
    };

    let repositories = sqlx::query_as::<_, RepositoryView>(
        "SELECT r.id,
                n.name || '/' || r.name AS full_name,
                r.visibility::text AS visibility,
                r.immutable_tag_pattern, r.created_at
         FROM repositories r
         JOIN namespaces n ON n.id = r.namespace_id
         LEFT JOIN namespace_memberships nm
           ON nm.namespace_id = n.id AND nm.user_id = $1
         WHERE r.deleted_at IS NULL
           AND ($2 OR nm.user_id IS NOT NULL)
         ORDER BY full_name",
    )
    .bind(user.id)
    .bind(user.is_instance_admin())
    .fetch_all(&state.pool)
    .await?;
    let pats = sqlx::query_as::<_, PatView>(
        "SELECT id, name, token_prefix, expires_at, last_used_at, created_at
         FROM personal_access_tokens
         WHERE user_id = $1 AND revoked_at IS NULL
         ORDER BY created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    let tags = sqlx::query_as::<_, TagView>(
        "SELECT n.name || '/' || r.name AS repository,
                t.name, t.manifest_digest, t.updated_at
         FROM tags t
         JOIN repositories r ON r.id = t.repository_id
         JOIN namespaces n ON n.id = r.namespace_id
         LEFT JOIN namespace_memberships nm
           ON nm.namespace_id = n.id AND nm.user_id = $1
         WHERE $2 OR nm.user_id IS NOT NULL
         ORDER BY t.updated_at DESC
         LIMIT 100",
    )
    .bind(user.id)
    .bind(user.is_instance_admin())
    .fetch_all(&state.pool)
    .await?;
    let history = sqlx::query_as::<_, TagEventView>(
        "SELECT n.name || '/' || r.name AS repository,
                e.tag_name, e.previous_digest, e.new_digest, e.created_at
         FROM tag_events e
         JOIN repositories r ON r.id = e.repository_id
         JOIN namespaces n ON n.id = r.namespace_id
         LEFT JOIN namespace_memberships nm
           ON nm.namespace_id = n.id AND nm.user_id = $1
         WHERE $2 OR nm.user_id IS NOT NULL
         ORDER BY e.created_at DESC
         LIMIT 100",
    )
    .bind(user.id)
    .bind(user.is_instance_admin())
    .fetch_all(&state.pool)
    .await?;
    let uploads = sqlx::query_as::<_, UploadView>(
        "SELECT n.name || '/' || r.name AS repository,
                u.id, u.status::text AS status, u.accepted_offset,
                u.error_message, u.updated_at
         FROM upload_sessions u
         JOIN repositories r ON r.id = u.repository_id
         JOIN namespaces n ON n.id = r.namespace_id
         WHERE u.actor_user_id = $1 OR $2
         ORDER BY u.updated_at DESC
         LIMIT 50",
    )
    .bind(user.id)
    .bind(user.is_instance_admin())
    .fetch_all(&state.pool)
    .await?;
    let audits = sqlx::query_as::<_, AuditView>(
        "SELECT action, resource_type, resource_id, created_at
         FROM audit_events
         WHERE actor_user_id = $1 OR $2
         ORDER BY created_at DESC
         LIMIT 100",
    )
    .bind(user.id)
    .bind(user.is_instance_admin())
    .fetch_all(&state.pool)
    .await?;
    let storage_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(visible.size), 0)::BIGINT
         FROM (
             SELECT DISTINCT b.digest, b.size
             FROM blobs b
             JOIN repository_blobs rb ON rb.digest = b.digest
             JOIN repositories r ON r.id = rb.repository_id
             LEFT JOIN namespace_memberships nm
               ON nm.namespace_id = r.namespace_id AND nm.user_id = $1
             WHERE b.status = 'committed' AND ($2 OR nm.user_id IS NOT NULL)
         ) visible",
    )
    .bind(user.id)
    .bind(user.is_instance_admin())
    .fetch_one(&state.pool)
    .await?;

    Ok(render(
        "JCR registry",
        dashboard(
            &user,
            &session,
            repositories,
            pats,
            tags,
            history,
            uploads,
            audits,
            storage_bytes,
        ),
    ))
}

async fn login(State(state): State<AppState>) -> Result<Redirect, AppError> {
    let google = state
        .config
        .google
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Google login is not configured".to_owned()))?;
    let raw_state = db::random_url_token(32);
    sqlx::query(
        "INSERT INTO oauth_states (state_hash, return_to, expires_at)
         VALUES ($1, '/registry', $2)",
    )
    .bind(db::token_hash(&raw_state))
    .bind(Utc::now() + Duration::minutes(10))
    .execute(&state.pool)
    .await?;

    let mut url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
        .expect("Google OAuth URL is valid");
    url.query_pairs_mut()
        .append_pair("client_id", &google.client_id)
        .append_pair("redirect_uri", google.redirect_url.as_str())
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email profile")
        .append_pair("state", &raw_state)
        .append_pair("prompt", "select_account");
    Ok(Redirect::temporary(url.as_str()))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleToken {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUser {
    sub: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
}

async fn callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    if let Some(error) = query.error {
        return Err(AppError::Denied(format!(
            "Google login was not completed: {error}"
        )));
    }
    let code = query
        .code
        .ok_or_else(|| AppError::BadRequest("OAuth code is missing".to_owned()))?;
    let raw_state = query
        .state
        .ok_or_else(|| AppError::BadRequest("OAuth state is missing".to_owned()))?;
    let return_to: Option<String> = sqlx::query_scalar(
        "DELETE FROM oauth_states
         WHERE state_hash = $1 AND expires_at > NOW()
         RETURNING return_to",
    )
    .bind(db::token_hash(&raw_state))
    .fetch_optional(&state.pool)
    .await?;
    let return_to = return_to
        .ok_or_else(|| AppError::Denied("OAuth state is invalid or expired".to_owned()))?;
    let google = state
        .config
        .google
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Google login is not configured".to_owned()))?;
    let token = state
        .http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", google.client_id.as_str()),
            ("client_secret", google.client_secret.as_str()),
            ("code", code.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", google.redirect_url.as_str()),
        ])
        .send()
        .await
        .map_err(|error| AppError::Internal(error.into()))?
        .error_for_status()
        .map_err(|error| AppError::Denied(format!("Google rejected the login: {error}")))?
        .json::<GoogleToken>()
        .await
        .map_err(|error| AppError::Internal(error.into()))?;
    let profile = state
        .http
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(token.access_token)
        .send()
        .await
        .map_err(|error| AppError::Internal(error.into()))?
        .error_for_status()
        .map_err(|error| AppError::Denied(format!("Google user lookup failed: {error}")))?
        .json::<GoogleUser>()
        .await
        .map_err(|error| AppError::Internal(error.into()))?;

    let user = db::register_verified_identity(
        &state.pool,
        VerifiedLogin {
            provider: "google".to_owned(),
            subject: profile.sub,
            email: profile.email,
            email_verified: profile.email_verified,
            display_name: profile.name,
        },
    )
    .await?;
    let (raw_session, _) = db::create_browser_session(&state.pool, user.id).await?;
    set_session_cookie(&state, &cookies, raw_session);
    Ok(Redirect::to(&return_to).into_response())
}

async fn logout(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect, AppError> {
    let (session, _) = require_session(&state, &cookies).await?;
    verify_csrf(&session, &form.csrf)?;
    if let Some(cookie) = cookies.get(SESSION_COOKIE) {
        db::delete_browser_session(&state.pool, cookie.value()).await?;
    }
    remove_session_cookie(&cookies);
    Ok(Redirect::to("/registry"))
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

#[derive(Deserialize)]
struct CreatePatForm {
    csrf: String,
    name: String,
    expires_days: Option<i64>,
}

async fn create_pat(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CreatePatForm>,
) -> Result<Html<String>, AppError> {
    let (session, user) = require_session(&state, &cookies).await?;
    verify_csrf(&session, &form.csrf)?;
    let name = form.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::BadRequest(
            "token name must contain 1 to 100 characters".to_owned(),
        ));
    }
    let expires_at = form
        .expires_days
        .filter(|days| *days > 0)
        .map(|days| Utc::now() + Duration::days(days.min(3650)));
    let issued = db::create_pat(&state.pool, user.id, name, expires_at).await?;
    Ok(render(
        "Personal access token",
        html! {
            section class="hero" {
                p class="eyebrow" { "Personal access token" }
                h1 { "Copy this token now" }
                p { "JCR stores only its Argon2id hash. This secret will not be shown again." }
                pre class="secret" { (issued.token) }
                p class="muted" {
                    (issued.name) " · prefix " code { (issued.prefix) }
                    @if let Some(expiry) = issued.expires_at {
                        " · expires " (short_time(expiry))
                    }
                    " · id " code { (issued.id) }
                }
                p { "Use it as the password with username " code { (user.username) } "." }
                a class="button" href="/registry" { "Return to registry" }
            }
        },
    ))
}

async fn revoke_pat(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Result<Redirect, AppError> {
    let (session, user) = require_session(&state, &cookies).await?;
    verify_csrf(&session, &form.csrf)?;
    db::revoke_pat(&state.pool, user.id, id).await?;
    Ok(Redirect::to("/registry"))
}

#[derive(Deserialize)]
struct RepositoryForm {
    csrf: String,
    namespace: String,
    name: String,
    visibility: String,
    immutable_tag_pattern: Option<String>,
}

async fn create_repository(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<RepositoryForm>,
) -> Result<Redirect, AppError> {
    let (session, user) = require_session(&state, &cookies).await?;
    verify_csrf(&session, &form.csrf)?;
    validate_visibility(&form.visibility)?;
    let full_name = format!("{}/{}", form.namespace.trim(), form.name.trim());
    let repository = db::ensure_repository_for_push(&state.pool, &full_name, &user).await?;
    if !db::authorize_repository(
        &state.pool,
        Some(&user),
        &repository,
        jcr_core::AccessAction::Admin,
    )
    .await?
    {
        return Err(AppError::Denied(
            "repository administration is denied".to_owned(),
        ));
    }
    let pattern = form
        .immutable_tag_pattern
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if let Some(pattern) = &pattern {
        regex::Regex::new(pattern).map_err(|error| {
            AppError::BadRequest(format!("immutable tag pattern is invalid: {error}"))
        })?;
    }
    sqlx::query(
        "UPDATE repositories
         SET visibility = $2::repository_visibility,
             immutable_tag_pattern = $3, updated_at = NOW()
         WHERE id = $1",
    )
    .bind(repository.id)
    .bind(form.visibility)
    .bind(pattern)
    .execute(&state.pool)
    .await?;
    Ok(Redirect::to("/registry"))
}

#[derive(Deserialize)]
struct VisibilityForm {
    csrf: String,
    visibility: String,
}

async fn update_visibility(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<VisibilityForm>,
) -> Result<Redirect, AppError> {
    let (session, user) = require_session(&state, &cookies).await?;
    verify_csrf(&session, &form.csrf)?;
    validate_visibility(&form.visibility)?;
    authorize_repository_id(&state, &user, id).await?;
    sqlx::query(
        "UPDATE repositories
         SET visibility = $2::repository_visibility, updated_at = NOW()
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(&form.visibility)
    .execute(&state.pool)
    .await?;
    db::insert_audit(
        &state.pool,
        Some(user.id),
        "repository.visibility_changed",
        Some(id),
        Some("repository"),
        Some(&id.to_string()),
        serde_json::json!({"visibility": form.visibility}),
    )
    .await?;
    Ok(Redirect::to("/registry"))
}

#[derive(Deserialize)]
struct DeleteManifestForm {
    csrf: String,
    digest: String,
}

async fn delete_manifest(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<Uuid>,
    Form(form): Form<DeleteManifestForm>,
) -> Result<Redirect, AppError> {
    let (session, user) = require_session(&state, &cookies).await?;
    verify_csrf(&session, &form.csrf)?;
    authorize_repository_id(&state, &user, id).await?;
    form.digest
        .parse::<jcr_core::Digest>()
        .map_err(|error| AppError::BadRequest(format!("manifest digest is invalid: {error}")))?;
    let mut transaction = state.pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE repository_manifests
         SET deleted_at = NOW()
         WHERE repository_id = $1 AND digest = $2 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(&form.digest)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::NotFound("manifest was not found".to_owned()));
    }
    let tags: Vec<String> = sqlx::query_scalar(
        "DELETE FROM tags
         WHERE repository_id = $1 AND manifest_digest = $2
         RETURNING name",
    )
    .bind(id)
    .bind(&form.digest)
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
        .bind(id)
        .bind(tag)
        .bind(&form.digest)
        .bind(user.id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    db::insert_audit(
        &state.pool,
        Some(user.id),
        "manifest.deleted",
        Some(id),
        Some("manifest"),
        Some(&form.digest),
        serde_json::json!({"source": "web"}),
    )
    .await?;
    Ok(Redirect::to("/registry"))
}

async fn authorize_repository_id(state: &AppState, user: &User, id: Uuid) -> Result<(), AppError> {
    let full_name: Option<String> = sqlx::query_scalar(
        "SELECT n.name || '/' || r.name
         FROM repositories r
         JOIN namespaces n ON n.id = r.namespace_id
         WHERE r.id = $1 AND r.deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    let repository = db::find_repository(
        &state.pool,
        &full_name.ok_or_else(|| AppError::NotFound("repository was not found".to_owned()))?,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("repository was not found".to_owned()))?;
    if db::authorize_repository(
        &state.pool,
        Some(user),
        &repository,
        jcr_core::AccessAction::Admin,
    )
    .await?
    {
        Ok(())
    } else {
        Err(AppError::Denied(
            "repository administration is denied".to_owned(),
        ))
    }
}

fn validate_visibility(visibility: &str) -> Result<(), AppError> {
    if matches!(visibility, "public" | "private") {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "visibility must be public or private".to_owned(),
        ))
    }
}

async fn current_session(
    state: &AppState,
    cookies: &Cookies,
) -> Result<Option<(BrowserSession, User)>, AppError> {
    let Some(cookie) = cookies.get(SESSION_COOKIE) else {
        return Ok(None);
    };
    db::browser_session_user(&state.pool, cookie.value()).await
}

async fn require_session(
    state: &AppState,
    cookies: &Cookies,
) -> Result<(BrowserSession, User), AppError> {
    current_session(state, cookies)
        .await?
        .ok_or_else(|| AppError::Unauthorized("browser session is required".to_owned()))
}

fn verify_csrf(session: &BrowserSession, supplied: &str) -> Result<(), AppError> {
    use subtle::ConstantTimeEq;
    if session
        .csrf_token
        .as_bytes()
        .ct_eq(supplied.as_bytes())
        .into()
    {
        Ok(())
    } else {
        Err(AppError::Denied("CSRF token is invalid".to_owned()))
    }
}

fn set_session_cookie(state: &AppState, cookies: &Cookies, value: String) {
    let mut cookie = Cookie::new(SESSION_COOKIE, value);
    cookie.set_path("/registry");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(state.config.public_url.scheme() == "https");
    cookies.add(cookie);
}

fn remove_session_cookie(cookies: &Cookies) {
    let mut cookie = Cookie::new(SESSION_COOKIE, "");
    cookie.set_path("/registry");
    cookies.remove(cookie);
}

fn render(title: &str, body: Markup) -> Html<String> {
    Html(
        html! {
            (DOCTYPE)
            html lang="en" {
                head {
                    meta charset="utf-8";
                    meta name="viewport" content="width=device-width, initial-scale=1";
                    title { (title) }
                    style { (PreEscaped(STYLES)) }
                }
                body {
                    main class="shell" { (body) }
                }
            }
        }
        .into_string(),
    )
}

fn public_page(google_configured: bool) -> Markup {
    html! {
        section class="hero" {
            p class="eyebrow" { "Jose's Container Registry" }
            h1 { "A small OCI registry with a deliberately complete core." }
            p {
                "JCR stores ordinary OCI images, speaks the Docker Registry API,
                and uses bounded resumable uploads for large layers."
            }
            @if google_configured {
                a class="button" href="/registry/login" { "Continue with Google" }
            } @else {
                p class="notice" {
                    "Google login is not configured in this development environment."
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dashboard(
    user: &User,
    session: &BrowserSession,
    repositories: Vec<RepositoryView>,
    pats: Vec<PatView>,
    tags: Vec<TagView>,
    history: Vec<TagEventView>,
    uploads: Vec<UploadView>,
    audits: Vec<AuditView>,
    storage_bytes: i64,
) -> Markup {
    let csrf = &session.csrf_token;
    html! {
        header class="topbar" {
            div {
                p class="eyebrow" { "JCR" }
                h1 { "Registry control plane" }
            }
            div class="account" {
                span { (user.username) " · " (user.primary_email) }
                form method="post" action="/registry/logout" {
                    input type="hidden" name="csrf" value=(csrf);
                    button class="link" type="submit" { "Sign out" }
                }
            }
        }

        section class="stats" {
            article { strong { (repositories.len()) } span { "repositories" } }
            article { strong { (tags.len()) } span { "visible tags" } }
            article { strong { (format_bytes(storage_bytes)) } span { "stored blobs" } }
        }

        section class="grid two" {
            article class="panel" {
                h2 { "Create repository" }
                form method="post" action="/registry/repositories" class="stack" {
                    input type="hidden" name="csrf" value=(csrf);
                    label { "Namespace" input name="namespace" value=(user.username) required; }
                    label { "Repository name" input name="name" placeholder="app" required; }
                    label { "Visibility"
                        select name="visibility" {
                            option value="private" { "Private" }
                            option value="public" { "Public" }
                        }
                    }
                    label { "Immutable tag regex (optional)"
                        input name="immutable_tag_pattern" placeholder="^v\\d+\\.\\d+\\.\\d+$";
                    }
                    button type="submit" { "Create repository" }
                }
            }
            article class="panel" {
                h2 { "Create personal access token" }
                form method="post" action="/registry/tokens" class="stack" {
                    input type="hidden" name="csrf" value=(csrf);
                    label { "Name" input name="name" placeholder="MacBook CLI" required; }
                    label { "Expires after days (blank for no expiry)"
                        input type="number" min="1" max="3650" name="expires_days";
                    }
                    button type="submit" { "Create token" }
                }
            }
        }

        section class="panel" {
            h2 { "Repositories" }
            @if repositories.is_empty() {
                p class="muted" { "No repositories yet." }
            } @else {
                div class="cards" {
                    @for repository in &repositories {
                        article class="repo" {
                            div {
                                h3 { (repository.full_name) }
                                p class="muted" {
                                    (repository.visibility) " · created "
                                    (short_time(repository.created_at))
                                }
                                @if let Some(pattern) = &repository.immutable_tag_pattern {
                                    code { (pattern) }
                                }
                            }
                            form method="post"
                                action=(format!("/registry/repositories/{}/visibility", repository.id)) {
                                input type="hidden" name="csrf" value=(csrf);
                                input type="hidden" name="visibility"
                                    value=(if repository.visibility == "public" { "private" } else { "public" });
                                button class="secondary" type="submit" {
                                    (if repository.visibility == "public" { "Make private" } else { "Make public" })
                                }
                            }
                        }
                    }
                }
            }
        }

        section class="grid two" {
            article class="panel" {
                h2 { "Personal access tokens" }
                @if pats.is_empty() {
                    p class="muted" { "No active tokens." }
                } @else {
                    table {
                        thead { tr { th { "Name" } th { "Prefix" } th { "Last used" } th {} } }
                        tbody {
                            @for pat in pats {
                                tr {
                                    td {
                                        (pat.name)
                                        small {
                                            "created " (short_time(pat.created_at))
                                            @if let Some(expiry) = pat.expires_at {
                                                " · expires " (short_time(expiry))
                                            }
                                        }
                                    }
                                    td { code { (pat.token_prefix) } }
                                    td { (pat.last_used_at.map(short_time).unwrap_or_else(|| "never".to_owned())) }
                                    td {
                                        form method="post" action=(format!("/registry/tokens/{}/revoke", pat.id)) {
                                            input type="hidden" name="csrf" value=(csrf);
                                            button class="danger link" type="submit" { "Revoke" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            article class="panel" {
                h2 { "Uploads" }
                @if uploads.is_empty() {
                    p class="muted" { "No uploads yet." }
                } @else {
                    table {
                        thead { tr { th { "Repository" } th { "Status" } th { "Accepted" } } }
                        tbody {
                            @for upload in uploads {
                                tr {
                                    td {
                                        (upload.repository)
                                        small { code { (upload.id) } " · " (short_time(upload.updated_at)) }
                                    }
                                    td {
                                        (upload.status)
                                        @if let Some(error) = upload.error_message {
                                            small class="error" { (error) }
                                        }
                                    }
                                    td { (format_bytes(upload.accepted_offset)) }
                                }
                            }
                        }
                    }
                }
            }
        }

        section class="panel" {
            h2 { "Tags and manifests" }
            @if tags.is_empty() {
                p class="muted" { "No tags yet." }
            } @else {
                table {
                    thead { tr { th { "Repository" } th { "Tag" } th { "Digest" } th { "Updated" } th {} } }
                    tbody {
                        @for tag in tags {
                            @let repository_id = repositories.iter()
                                .find(|repo| repo.full_name == tag.repository)
                                .map(|repo| repo.id);
                            tr {
                                td { (tag.repository) }
                                td { code { (tag.name) } }
                                td { code class="digest" { (tag.manifest_digest) } }
                                td { (short_time(tag.updated_at)) }
                                td {
                                    @if let Some(id) = repository_id {
                                        form method="post"
                                            action=(format!("/registry/repositories/{id}/manifests/delete")) {
                                            input type="hidden" name="csrf" value=(csrf);
                                            input type="hidden" name="digest" value=(tag.manifest_digest);
                                            button class="danger link" type="submit" { "Delete" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        section class="grid two" {
            article class="panel" {
                h2 { "Tag history" }
                ul class="events" {
                    @for event in history {
                        li {
                            strong { (event.repository) ":" (event.tag_name) }
                            span {
                                (event.previous_digest.as_deref().map(short_digest).unwrap_or("new"))
                                " → "
                                (event.new_digest.as_deref().map(short_digest).unwrap_or("deleted"))
                                " · " (short_time(event.created_at))
                            }
                        }
                    }
                }
            }
            article class="panel" {
                h2 { "Audit events" }
                ul class="events" {
                    @for audit in audits {
                        li {
                            strong { (audit.action) }
                            span {
                                @if let Some(kind) = audit.resource_type { (kind) " " }
                                @if let Some(id) = audit.resource_id { (short_digest(&id)) " · " }
                                (short_time(audit.created_at))
                            }
                        }
                    }
                }
            }
        }
    }
}

fn short_time(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%d %H:%M UTC").to_string()
}

fn short_digest(value: &str) -> &str {
    value.get(..20).unwrap_or(value)
}

fn format_bytes(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes.max(0) as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

const STYLES: &str = r#"
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #080b10; color: #f5f7fb; }
* { box-sizing: border-box; }
body { margin: 0; background: radial-gradient(circle at 20% 0%, #182131 0, #080b10 36rem); }
.shell { width: min(1180px, calc(100% - 2rem)); margin: 0 auto; padding: 4rem 0 8rem; }
.hero { max-width: 720px; padding: 10vh 0; }
.hero h1, .topbar h1 { font-size: clamp(2.3rem, 7vw, 5.8rem); line-height: .96; letter-spacing: -.055em; margin: .25rem 0 1.5rem; }
.hero p { color: #aab5c6; font-size: 1.1rem; line-height: 1.7; }
.eyebrow { color: #77d7a8 !important; font-size: .76rem !important; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
.button, button { display: inline-flex; border: 0; border-radius: .65rem; padding: .72rem 1rem; background: #72e2a8; color: #07110c; font: inherit; font-weight: 750; cursor: pointer; text-decoration: none; }
button.secondary { background: #202a38; color: #dce6f5; }
button.link { padding: 0; background: transparent; color: #aab5c6; }
button.danger { color: #ff9a9a; }
.topbar { display: flex; align-items: end; justify-content: space-between; gap: 2rem; margin-bottom: 2rem; }
.topbar h1 { font-size: clamp(2.2rem, 5vw, 4.3rem); margin-bottom: 0; }
.account { display: flex; gap: 1rem; color: #aab5c6; }
.stats, .grid, .cards { display: grid; gap: 1rem; }
.stats { grid-template-columns: repeat(3, 1fr); margin: 1rem 0; }
.stats article, .panel { border: 1px solid #222c39; background: rgba(14, 19, 27, .86); border-radius: 1rem; }
.stats article { padding: 1.25rem; }
.stats strong { display: block; font-size: 1.6rem; }
.stats span, .muted, small { color: #8996a8; }
.grid.two { grid-template-columns: repeat(2, minmax(0, 1fr)); margin: 1rem 0; }
.panel { padding: 1.25rem; overflow: hidden; margin: 1rem 0; }
.panel h2 { margin: 0 0 1rem; font-size: 1rem; letter-spacing: .03em; }
.stack { display: grid; gap: .8rem; }
label { display: grid; gap: .35rem; color: #aab5c6; font-size: .86rem; }
input, select { width: 100%; border: 1px solid #303b4b; border-radius: .55rem; background: #0b1017; color: #f5f7fb; padding: .7rem .75rem; font: inherit; }
.cards { grid-template-columns: repeat(auto-fit, minmax(270px, 1fr)); }
.repo { display: flex; justify-content: space-between; gap: 1rem; padding: 1rem; border: 1px solid #273140; border-radius: .75rem; }
.repo h3 { margin: 0 0 .4rem; }
table { width: 100%; border-collapse: collapse; font-size: .86rem; }
th, td { padding: .7rem .45rem; border-bottom: 1px solid #212a37; text-align: left; vertical-align: top; }
th { color: #8996a8; font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; }
td small { display: block; margin-top: .25rem; }
code, .secret { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
.digest { display: inline-block; max-width: 25ch; overflow: hidden; text-overflow: ellipsis; }
.secret { padding: 1rem; border: 1px solid #37694e; background: #0c1711; border-radius: .7rem; white-space: pre-wrap; }
.events { display: grid; gap: .65rem; margin: 0; padding: 0; list-style: none; }
.events li { display: grid; gap: .2rem; padding-bottom: .65rem; border-bottom: 1px solid #212a37; }
.events span { color: #8996a8; font-size: .82rem; }
.error, .notice { color: #ff9a9a; }
@media (max-width: 760px) { .grid.two, .stats { grid-template-columns: 1fr; } .topbar { align-items: start; flex-direction: column; } .account { flex-wrap: wrap; } table { display: block; overflow-x: auto; } }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_storage_usage() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(64 * 1024 * 1024), "64.0 MiB");
    }
}
