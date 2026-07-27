use std::{collections::BTreeSet, str::FromStr};

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use jcr_core::{AccessAction, RepositoryScope};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::{self, User},
    error::AppError,
    state::AppState,
};

const TOKEN_LIFETIME_MINUTES: i64 = 10;

#[derive(Clone, Debug)]
pub struct Principal {
    pub user: Option<User>,
    pub scopes: Vec<RepositoryScope>,
    pub bearer: bool,
}

impl Principal {
    pub fn permits(&self, repository: &str, action: AccessAction) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope.permits(repository, action))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TokenAccess {
    #[serde(rename = "type")]
    resource_type: String,
    name: String,
    actions: Vec<AccessAction>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    nbf: usize,
    iat: usize,
    jti: String,
    user_id: Option<Uuid>,
    access: Vec<TokenAccess>,
}

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    #[serde(default = "default_service")]
    service: String,
    scope: Option<String>,
    #[serde(rename = "account")]
    _account: Option<String>,
}

fn default_service() -> String {
    "jcr".to_owned()
}

#[derive(Serialize)]
pub(crate) struct TokenResponse {
    token: String,
    access_token: String,
    expires_in: i64,
    issued_at: String,
}

pub async fn token(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
    headers: HeaderMap,
) -> Result<Json<TokenResponse>, AppError> {
    let user = if let Some((username, token)) = basic_credentials(&headers) {
        Some(
            db::validate_pat(&state.pool, &username, &token)
                .await?
                .ok_or_else(|| AppError::Unauthorized("invalid username or token".to_owned()))?,
        )
    } else {
        None
    };

    let requested = query
        .scope
        .as_deref()
        .map(RepositoryScope::from_str)
        .transpose()
        .map_err(|error| AppError::BadRequest(error.to_string()))?;

    let mut granted_scopes = Vec::new();
    if let Some(requested) = requested {
        let mut granted = BTreeSet::new();
        for action in requested.actions {
            if db::authorize_repository_name(
                &state.pool,
                user.as_ref(),
                &requested.repository,
                action,
            )
            .await?
            {
                granted.insert(action);
            }
        }
        granted_scopes.push(RepositoryScope::new(requested.repository, granted));
    }

    let now = Utc::now();
    let expires = now + Duration::minutes(TOKEN_LIFETIME_MINUTES);
    let claims = TokenClaims {
        iss: state.config.public_url.to_string(),
        sub: user
            .as_ref()
            .map(|user| user.username.clone())
            .unwrap_or_default(),
        aud: query.service,
        exp: expires.timestamp() as usize,
        nbf: (now - Duration::seconds(5)).timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: Uuid::new_v4().to_string(),
        user_id: user.as_ref().map(|user| user.id),
        access: granted_scopes
            .iter()
            .map(|scope| TokenAccess {
                resource_type: "repository".to_owned(),
                name: scope.repository.clone(),
                actions: scope.actions.iter().copied().collect(),
            })
            .collect(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|error| AppError::Internal(error.into()))?;

    Ok(Json(TokenResponse {
        token: token.clone(),
        access_token: token,
        expires_in: TOKEN_LIFETIME_MINUTES * 60,
        issued_at: now.to_rfc3339(),
    }))
}

pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Principal>, AppError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| AppError::Unauthorized("authorization header is invalid".to_owned()))?;

    if let Some(token) = value.strip_prefix("Bearer ") {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["jcr"]);
        validation.validate_nbf = true;
        let claims = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AppError::Unauthorized("bearer token is invalid or expired".to_owned()))?
        .claims;
        let user = match claims.user_id {
            Some(user_id) => db::user_by_id(&state.pool, user_id).await?,
            None => None,
        };
        let scopes = claims
            .access
            .into_iter()
            .filter(|access| access.resource_type == "repository")
            .map(|access| RepositoryScope::new(access.name, access.actions))
            .collect();
        return Ok(Some(Principal {
            user,
            scopes,
            bearer: true,
        }));
    }

    if let Some((username, token)) = decode_basic(value) {
        let user = db::validate_pat(&state.pool, &username, &token)
            .await?
            .ok_or_else(|| AppError::Unauthorized("invalid username or token".to_owned()))?;
        return Ok(Some(Principal {
            user: Some(user),
            scopes: Vec::new(),
            bearer: false,
        }));
    }

    Err(AppError::Unauthorized(
        "unsupported authorization scheme".to_owned(),
    ))
}

pub async fn v2_check(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if headers.contains_key(header::AUTHORIZATION) {
        authenticate(&state, &headers).await?;
        return Ok(registry_api_response(StatusCode::OK));
    }

    Ok(challenge_response(&state, None, StatusCode::UNAUTHORIZED))
}

pub fn challenge_response(
    state: &AppState,
    scope: Option<&RepositoryScope>,
    status: StatusCode,
) -> Response {
    let realm = state
        .config
        .public_url
        .join("auth/token")
        .expect("public URL accepts auth/token");
    let mut challenge = format!("Bearer realm=\"{realm}\",service=\"jcr\"");
    if let Some(scope) = scope {
        challenge.push_str(&format!(",scope=\"{scope}\""));
    }
    let mut response = registry_api_response(status);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).expect("challenge header is valid"),
    );
    response
}

pub fn registry_api_response(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response.headers_mut().insert(
        "Docker-Distribution-Api-Version",
        HeaderValue::from_static("registry/2.0"),
    );
    response
}

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(decode_basic)
}

fn decode_basic(value: &str) -> Option<(String, String)> {
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, token) = decoded.split_once(':')?;
    Some((username.to_owned(), token.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_basic_credentials() {
        let value = format!("Basic {}", STANDARD.encode("jose:jcr_pat_prefix_secret"));
        assert_eq!(
            decode_basic(&value),
            Some(("jose".to_owned(), "jcr_pat_prefix_secret".to_owned()))
        );
    }
}
