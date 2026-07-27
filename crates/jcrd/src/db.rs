use std::str::FromStr;

use anyhow::Context;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use jcr_core::AccessAction;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::{
    config::{Config, RegistrationMode},
    error::AppError,
};

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub primary_email: String,
    pub instance_role: String,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn is_instance_admin(&self) -> bool {
        self.instance_role == "admin"
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedLogin {
    pub provider: String,
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Repository {
    pub id: Uuid,
    pub namespace_id: Uuid,
    pub namespace: String,
    pub name: String,
    pub visibility: String,
    pub immutable_tag_pattern: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Repository {
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }

    pub fn is_public(&self) -> bool {
        self.visibility == "public"
    }
}

#[derive(Clone, Debug)]
pub struct IssuedPat {
    pub id: Uuid,
    pub name: String,
    pub token: String,
    pub prefix: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, FromRow)]
pub struct BrowserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn connect_and_migrate(config: &Config) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .context("failed to connect to PostgreSQL")?;

    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .context("failed to apply database migrations")?;

    sqlx::query(
        "UPDATE instance_settings
         SET registration_mode = $1::registration_mode, updated_at = NOW()
         WHERE singleton = TRUE",
    )
    .bind(config.registration_mode.as_str())
    .execute(&pool)
    .await
    .context("failed to configure registration mode")?;

    if let Some(email) = &config.bootstrap_email {
        seed_bootstrap_registration(
            &pool,
            email,
            &config.bootstrap_username,
            &config.bootstrap_namespace,
        )
        .await
        .context("failed to seed bootstrap registration")?;
    }

    Ok(pool)
}

async fn seed_bootstrap_registration(
    pool: &PgPool,
    email: &str,
    username: &str,
    namespace: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO registration_entries (
             id, email, reserved_username, reserved_namespace,
             instance_role, namespace_role, status
         )
         SELECT $1, $2, $3, $4, 'admin', 'admin', 'pending'
         WHERE NOT EXISTS (
             SELECT 1 FROM users WHERE LOWER(primary_email) = LOWER($2)
         )
         ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(username)
    .bind(namespace)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn register_verified_identity(
    pool: &PgPool,
    login: VerifiedLogin,
) -> Result<User, AppError> {
    if !login.email_verified {
        return Err(AppError::Denied(
            "the identity provider did not verify this email".to_owned(),
        ));
    }

    if let Some(user) = sqlx::query_as::<_, User>(
        "SELECT u.id, u.username, u.display_name, u.primary_email,
                u.instance_role::text AS instance_role, u.created_at
         FROM verified_identities i
         JOIN users u ON u.id = i.user_id
         WHERE i.provider = $1 AND i.provider_subject = $2
           AND u.disabled_at IS NULL",
    )
    .bind(&login.provider)
    .bind(&login.subject)
    .fetch_optional(pool)
    .await?
    {
        sqlx::query(
            "UPDATE verified_identities
             SET last_login_at = NOW(), email = $3, email_verified = TRUE
             WHERE provider = $1 AND provider_subject = $2",
        )
        .bind(&login.provider)
        .bind(&login.subject)
        .bind(&login.email)
        .execute(pool)
        .await?;
        return Ok(user);
    }

    let mut transaction = pool.begin().await?;
    let mode: String = sqlx::query_scalar(
        "SELECT registration_mode::text
         FROM instance_settings
         WHERE singleton = TRUE
         FOR UPDATE",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let mode = RegistrationMode::from_str(&mode).map_err(AppError::Internal)?;

    #[derive(FromRow)]
    struct RegistrationEntry {
        id: Uuid,
        reserved_username: Option<String>,
        reserved_namespace: Option<String>,
        instance_role: String,
        namespace_role: String,
    }

    let entry = sqlx::query_as::<_, RegistrationEntry>(
        "SELECT id, reserved_username, reserved_namespace,
                instance_role::text AS instance_role,
                namespace_role::text AS namespace_role
         FROM registration_entries
         WHERE LOWER(email) = LOWER($1)
           AND status = 'pending'
           AND (expires_at IS NULL OR expires_at > NOW())
         FOR UPDATE",
    )
    .bind(login.email.trim())
    .fetch_optional(&mut *transaction)
    .await?;

    let (entry, username, namespace, instance_role, namespace_role) = match (mode, entry) {
        (RegistrationMode::Closed, _) => {
            return Err(AppError::Denied("registration is closed".to_owned()));
        }
        (RegistrationMode::Allowlist | RegistrationMode::Invite, None) => {
            return Err(AppError::Denied(
                "this verified email is not allowed to register".to_owned(),
            ));
        }
        (_, Some(entry)) => {
            let username = entry
                .reserved_username
                .clone()
                .unwrap_or_else(|| username_from_email(&login.email));
            let namespace = entry
                .reserved_namespace
                .clone()
                .unwrap_or_else(|| username.clone());
            let instance_role = entry.instance_role.clone();
            let namespace_role = entry.namespace_role.clone();
            (
                Some(entry),
                username,
                namespace,
                instance_role,
                namespace_role,
            )
        }
        (RegistrationMode::Open, None) => {
            let username = available_username(&mut transaction, &login.email).await?;
            (
                None,
                username.clone(),
                username,
                "user".to_owned(),
                "admin".to_owned(),
            )
        }
    };

    let user_id = Uuid::new_v4();
    let namespace_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (
             id, username, display_name, primary_email, instance_role
         )
         VALUES ($1, $2, $3, $4, $5::instance_role)
         RETURNING id, username, display_name, primary_email,
                   instance_role::text AS instance_role, created_at",
    )
    .bind(user_id)
    .bind(&username)
    .bind(&login.display_name)
    .bind(login.email.trim().to_ascii_lowercase())
    .bind(&instance_role)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_unique_registration_error)?;

    sqlx::query(
        "INSERT INTO verified_identities (
             id, user_id, provider, provider_subject, email, email_verified
         ) VALUES ($1, $2, $3, $4, $5, TRUE)",
    )
    .bind(identity_id)
    .bind(user_id)
    .bind(&login.provider)
    .bind(&login.subject)
    .bind(login.email.trim().to_ascii_lowercase())
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        "INSERT INTO namespaces (id, name, owner_user_id)
         VALUES ($1, $2, $3)",
    )
    .bind(namespace_id)
    .bind(&namespace)
    .bind(user_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_unique_registration_error)?;

    sqlx::query(
        "INSERT INTO namespace_memberships (namespace_id, user_id, role)
         VALUES ($1, $2, $3::namespace_role)",
    )
    .bind(namespace_id)
    .bind(user_id)
    .bind(&namespace_role)
    .execute(&mut *transaction)
    .await?;

    if let Some(entry) = entry {
        sqlx::query(
            "UPDATE registration_entries
             SET status = 'claimed', claimed_by = $2, claimed_at = NOW()
             WHERE id = $1",
        )
        .bind(entry.id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    }

    insert_audit_tx(
        &mut transaction,
        Some(user_id),
        "user.registered",
        None,
        Some("user"),
        Some(&user_id.to_string()),
        serde_json::json!({"provider": login.provider}),
    )
    .await?;

    transaction.commit().await?;
    Ok(user)
}

async fn available_username(
    transaction: &mut Transaction<'_, Postgres>,
    email: &str,
) -> Result<String, AppError> {
    let base = username_from_email(email);
    for suffix in 0..1000 {
        let candidate = if suffix == 0 {
            base.clone()
        } else {
            format!("{base}-{suffix}")
        };
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username) = LOWER($1))",
        )
        .bind(&candidate)
        .fetch_one(&mut **transaction)
        .await?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(AppError::Conflict(
        "could not allocate a unique username".to_owned(),
    ))
}

fn username_from_email(email: &str) -> String {
    let local = email
        .split('@')
        .next()
        .unwrap_or("user")
        .to_ascii_lowercase();
    let mut output = String::new();
    let mut previous_separator = false;
    for character in local.chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            output.push(character);
            previous_separator = false;
        } else if !previous_separator && !output.is_empty() {
            output.push('-');
            previous_separator = true;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    if output.is_empty() {
        "user".to_owned()
    } else {
        output
    }
}

fn map_unique_registration_error(error: sqlx::Error) -> AppError {
    if error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
    {
        AppError::Conflict("that username, email, or namespace is already in use".to_owned())
    } else {
        AppError::Database(error)
    }
}

pub async fn create_pat(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Result<IssuedPat, AppError> {
    // The token format uses an underscore as the prefix/secret delimiter, so
    // keep the lookup prefix hexadecimal rather than base64url (which can
    // itself contain underscores).
    let prefix = random_hex_token(8);
    let secret = random_url_token(32);
    let token = format!("jcr_pat_{prefix}_{secret}");
    let secret_hash = tokio::task::spawn_blocking({
        let token = token.clone();
        move || {
            Argon2::default()
                .hash_password(token.as_bytes(), &SaltString::generate(&mut OsRng))
                .map(|hash| hash.to_string())
        }
    })
    .await
    .map_err(|error| AppError::Internal(error.into()))?
    .map_err(|error| AppError::Internal(anyhow::anyhow!(error.to_string())))?;
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO personal_access_tokens (
             id, user_id, name, token_prefix, secret_hash, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(&prefix)
    .bind(secret_hash)
    .bind(expires_at)
    .execute(pool)
    .await?;

    insert_audit(
        pool,
        Some(user_id),
        "pat.created",
        None,
        Some("personal_access_token"),
        Some(&id.to_string()),
        serde_json::json!({"name": name, "prefix": prefix}),
    )
    .await?;

    Ok(IssuedPat {
        id,
        name: name.to_owned(),
        token,
        prefix,
        expires_at,
    })
}

pub async fn revoke_pat(pool: &PgPool, user_id: Uuid, token_id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE personal_access_tokens
         SET revoked_at = NOW()
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(token_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("token was not found".to_owned()));
    }
    insert_audit(
        pool,
        Some(user_id),
        "pat.revoked",
        None,
        Some("personal_access_token"),
        Some(&token_id.to_string()),
        serde_json::json!({}),
    )
    .await?;
    Ok(())
}

pub async fn validate_pat(
    pool: &PgPool,
    username: &str,
    token: &str,
) -> Result<Option<User>, AppError> {
    let Some(prefix) = pat_prefix(token) else {
        return Ok(None);
    };

    #[derive(FromRow)]
    struct TokenUser {
        token_id: Uuid,
        secret_hash: String,
        id: Uuid,
        username: String,
        display_name: Option<String>,
        primary_email: String,
        instance_role: String,
        created_at: DateTime<Utc>,
    }

    let Some(candidate) = sqlx::query_as::<_, TokenUser>(
        "SELECT t.id AS token_id, t.secret_hash,
                u.id, u.username, u.display_name, u.primary_email,
                u.instance_role::text AS instance_role, u.created_at
         FROM personal_access_tokens t
         JOIN users u ON u.id = t.user_id
         WHERE t.token_prefix = $1
           AND LOWER(u.username) = LOWER($2)
           AND t.revoked_at IS NULL
           AND (t.expires_at IS NULL OR t.expires_at > NOW())
           AND u.disabled_at IS NULL",
    )
    .bind(prefix)
    .bind(username)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    let hash = candidate.secret_hash.clone();
    let token = token.to_owned();
    let valid = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash).ok().is_some_and(|hash| {
            Argon2::default()
                .verify_password(token.as_bytes(), &hash)
                .is_ok()
        })
    })
    .await
    .map_err(|error| AppError::Internal(error.into()))?;

    if !valid {
        return Ok(None);
    }

    sqlx::query(
        "UPDATE personal_access_tokens
         SET last_used_at = NOW()
         WHERE id = $1",
    )
    .bind(candidate.token_id)
    .execute(pool)
    .await?;

    Ok(Some(User {
        id: candidate.id,
        username: candidate.username,
        display_name: candidate.display_name,
        primary_email: candidate.primary_email,
        instance_role: candidate.instance_role,
        created_at: candidate.created_at,
    }))
}

fn pat_prefix(token: &str) -> Option<&str> {
    let remainder = token.strip_prefix("jcr_pat_")?;
    let (prefix, secret) = remainder.split_once('_')?;
    if prefix.is_empty() || secret.is_empty() {
        None
    } else {
        Some(prefix)
    }
}

pub async fn create_browser_session(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(String, BrowserSession), AppError> {
    let raw_token = random_url_token(32);
    let token_hash = token_hash(&raw_token);
    let session = BrowserSession {
        id: Uuid::new_v4(),
        user_id,
        csrf_token: random_url_token(24),
        expires_at: Utc::now() + Duration::days(7),
    };

    sqlx::query(
        "INSERT INTO browser_sessions (
             id, user_id, token_hash, csrf_token, expires_at
         ) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(session.id)
    .bind(session.user_id)
    .bind(token_hash)
    .bind(&session.csrf_token)
    .bind(session.expires_at)
    .execute(pool)
    .await?;
    Ok((raw_token, session))
}

pub async fn browser_session_user(
    pool: &PgPool,
    raw_token: &str,
) -> Result<Option<(BrowserSession, User)>, AppError> {
    #[derive(FromRow)]
    struct SessionUser {
        session_id: Uuid,
        user_id: Uuid,
        csrf_token: String,
        expires_at: DateTime<Utc>,
        username: String,
        display_name: Option<String>,
        primary_email: String,
        instance_role: String,
        created_at: DateTime<Utc>,
    }

    let row = sqlx::query_as::<_, SessionUser>(
        "SELECT s.id AS session_id, s.user_id, s.csrf_token, s.expires_at,
                u.username, u.display_name, u.primary_email,
                u.instance_role::text AS instance_role, u.created_at
         FROM browser_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1
           AND s.expires_at > NOW()
           AND u.disabled_at IS NULL",
    )
    .bind(token_hash(raw_token))
    .fetch_optional(pool)
    .await?;

    if let Some(row) = &row {
        sqlx::query("UPDATE browser_sessions SET last_seen_at = NOW() WHERE id = $1")
            .bind(row.session_id)
            .execute(pool)
            .await?;
    }

    Ok(row.map(|row| {
        (
            BrowserSession {
                id: row.session_id,
                user_id: row.user_id,
                csrf_token: row.csrf_token,
                expires_at: row.expires_at,
            },
            User {
                id: row.user_id,
                username: row.username,
                display_name: row.display_name,
                primary_email: row.primary_email,
                instance_role: row.instance_role,
                created_at: row.created_at,
            },
        )
    }))
}

pub async fn delete_browser_session(pool: &PgPool, raw_token: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM browser_sessions WHERE token_hash = $1")
        .bind(token_hash(raw_token))
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn find_repository(
    pool: &PgPool,
    full_name: &str,
) -> Result<Option<Repository>, AppError> {
    let Some((namespace, name)) = full_name.split_once('/') else {
        return Err(AppError::BadRequest(
            "repository must include namespace/name".to_owned(),
        ));
    };
    Ok(sqlx::query_as::<_, Repository>(
        "SELECT r.id, r.namespace_id, n.name AS namespace, r.name,
                r.visibility::text AS visibility, r.immutable_tag_pattern,
                r.created_at
         FROM repositories r
         JOIN namespaces n ON n.id = r.namespace_id
         WHERE LOWER(n.name) = LOWER($1)
           AND r.name = $2
           AND r.deleted_at IS NULL",
    )
    .bind(namespace)
    .bind(name)
    .fetch_optional(pool)
    .await?)
}

pub async fn ensure_repository_for_push(
    pool: &PgPool,
    full_name: &str,
    actor: &User,
) -> Result<Repository, AppError> {
    if let Some(repository) = find_repository(pool, full_name).await? {
        if authorize_repository(pool, Some(actor), &repository, AccessAction::Push).await? {
            return Ok(repository);
        }
        return Err(AppError::Denied(
            "push access to this repository is denied".to_owned(),
        ));
    }

    let Some((namespace, name)) = full_name.split_once('/') else {
        return Err(AppError::BadRequest(
            "repository must include namespace/name".to_owned(),
        ));
    };
    if name.is_empty() {
        return Err(AppError::BadRequest("repository name is empty".to_owned()));
    }

    #[derive(FromRow)]
    struct NamespaceAccess {
        id: Uuid,
        role: String,
    }
    let access = sqlx::query_as::<_, NamespaceAccess>(
        "SELECT n.id, m.role::text AS role
         FROM namespaces n
         JOIN namespace_memberships m ON m.namespace_id = n.id
         WHERE LOWER(n.name) = LOWER($1) AND m.user_id = $2",
    )
    .bind(namespace)
    .bind(actor.id)
    .fetch_optional(pool)
    .await?;

    let Some(access) = access else {
        return Err(AppError::Denied(
            "push access to this namespace is denied".to_owned(),
        ));
    };
    if !actor.is_instance_admin() && !matches!(access.role.as_str(), "writer" | "admin") {
        return Err(AppError::Denied(
            "push access to this namespace is denied".to_owned(),
        ));
    }

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO repositories (id, namespace_id, name, visibility)
         VALUES ($1, $2, $3, 'private')
         ON CONFLICT (namespace_id, name) DO NOTHING",
    )
    .bind(id)
    .bind(access.id)
    .bind(name)
    .execute(pool)
    .await?;

    let repository = find_repository(pool, full_name)
        .await?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("repository creation failed")))?;
    insert_audit(
        pool,
        Some(actor.id),
        "repository.created",
        Some(repository.id),
        Some("repository"),
        Some(&repository.id.to_string()),
        serde_json::json!({"name": repository.full_name()}),
    )
    .await?;
    Ok(repository)
}

pub async fn authorize_repository_name(
    pool: &PgPool,
    user: Option<&User>,
    full_name: &str,
    action: AccessAction,
) -> Result<bool, AppError> {
    if let Some(repository) = find_repository(pool, full_name).await? {
        return authorize_repository(pool, user, &repository, action).await;
    }

    let Some(user) = user else {
        return Ok(false);
    };
    if user.is_instance_admin() {
        return Ok(true);
    }
    if !matches!(action, AccessAction::Pull | AccessAction::Push) {
        return Ok(false);
    }
    let Some((namespace, _)) = full_name.split_once('/') else {
        return Ok(false);
    };
    let role: Option<String> = sqlx::query_scalar(
        "SELECT m.role::text
         FROM namespaces n
         JOIN namespace_memberships m ON m.namespace_id = n.id
         WHERE LOWER(n.name) = LOWER($1) AND m.user_id = $2",
    )
    .bind(namespace)
    .bind(user.id)
    .fetch_optional(pool)
    .await?;
    Ok(role.is_some_and(|role| match action {
        AccessAction::Pull => matches!(role.as_str(), "reader" | "writer" | "admin"),
        AccessAction::Push => matches!(role.as_str(), "writer" | "admin"),
        AccessAction::Delete | AccessAction::Admin => false,
    }))
}

pub async fn authorize_repository(
    pool: &PgPool,
    user: Option<&User>,
    repository: &Repository,
    action: AccessAction,
) -> Result<bool, AppError> {
    if action == AccessAction::Pull && repository.is_public() {
        return Ok(true);
    }
    let Some(user) = user else {
        return Ok(false);
    };
    if user.is_instance_admin() {
        return Ok(true);
    }

    let namespace_role: Option<String> = sqlx::query_scalar(
        "SELECT role::text
         FROM namespace_memberships
         WHERE namespace_id = $1 AND user_id = $2",
    )
    .bind(repository.namespace_id)
    .bind(user.id)
    .fetch_optional(pool)
    .await?;

    let namespace_grants = namespace_role.is_some_and(|role| match action {
        AccessAction::Pull => matches!(role.as_str(), "reader" | "writer" | "admin"),
        AccessAction::Push => matches!(role.as_str(), "writer" | "admin"),
        AccessAction::Delete | AccessAction::Admin => role == "admin",
    });
    if namespace_grants {
        return Ok(true);
    }

    let action = action.to_string();
    let explicit: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM repository_permissions
             WHERE repository_id = $1
               AND user_id = $2
               AND action IN ($3::repository_action, 'admin'::repository_action)
         )",
    )
    .bind(repository.id)
    .bind(user.id)
    .bind(action)
    .fetch_one(pool)
    .await?;
    Ok(explicit)
}

pub async fn user_by_id(pool: &PgPool, user_id: Uuid) -> Result<Option<User>, AppError> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT id, username, display_name, primary_email,
                instance_role::text AS instance_role, created_at
         FROM users WHERE id = $1 AND disabled_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn insert_audit(
    pool: &PgPool,
    actor_user_id: Option<Uuid>,
    action: &str,
    repository_id: Option<Uuid>,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    detail: serde_json::Value,
) -> Result<(), AppError> {
    let mut transaction = pool.begin().await?;
    insert_audit_tx(
        &mut transaction,
        actor_user_id,
        action,
        repository_id,
        resource_type,
        resource_id,
        detail,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn insert_audit_tx(
    transaction: &mut Transaction<'_, Postgres>,
    actor_user_id: Option<Uuid>,
    action: &str,
    repository_id: Option<Uuid>,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    detail: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (
             id, actor_user_id, action, repository_id,
             resource_type, resource_id, detail
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::new_v4())
    .bind(actor_user_id)
    .bind(action)
    .bind(repository_id)
    .bind(resource_type)
    .bind(resource_id)
    .bind(detail)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn random_url_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn random_hex_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut value);
    hex::encode(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_safe_username_from_email() {
        assert_eq!(
            username_from_email("Jose.Valerio+test@example.com"),
            "jose-valerio-test"
        );
        assert_eq!(username_from_email("@example.com"), "user");
    }

    #[test]
    fn extracts_pat_prefix() {
        assert_eq!(pat_prefix("jcr_pat_abcdef_secret"), Some("abcdef"));
        assert_eq!(pat_prefix("not-a-token"), None);
    }

    #[test]
    fn generated_pat_prefixes_cannot_contain_the_delimiter() {
        for _ in 0..1_000 {
            let prefix = random_hex_token(8);
            assert_eq!(prefix.len(), 16);
            assert!(prefix.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(!prefix.contains('_'));
        }
    }
}
