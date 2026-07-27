use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{message}")]
    Oci {
        status: StatusCode,
        code: &'static str,
        message: String,
    },
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    PayloadTooLarge(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("storage error: {0}")]
    Storage(#[from] jcr_core::StorageError),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Oci { status, .. } => *status,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Denied(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Database(_) | Self::Storage(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    pub fn oci_code(&self) -> &'static str {
        match self {
            Self::Oci { code, .. } => code,
            Self::BadRequest(_) => "BLOB_UPLOAD_INVALID",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Denied(_) => "DENIED",
            Self::NotFound(_) => "NAME_UNKNOWN",
            Self::Conflict(_) => "MANIFEST_INVALID",
            Self::PayloadTooLarge(_) => "SIZE_INVALID",
            Self::Database(_) | Self::Storage(_) | Self::Internal(_) => "UNKNOWN",
        }
    }

    pub fn into_oci_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            tracing::error!(error = %self, "request failed");
        }
        (
            status,
            Json(OciErrorEnvelope {
                errors: vec![OciErrorBody {
                    code: self.oci_code(),
                    message: self.to_string(),
                    detail: Value::Null,
                }],
            }),
        )
            .into_response()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            tracing::error!(error = %self, "request failed");
        }
        (
            status,
            Json(serde_json::json!({
                "error": self.to_string(),
            })),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct OciErrorEnvelope {
    errors: Vec<OciErrorBody>,
}

#[derive(Serialize)]
struct OciErrorBody {
    code: &'static str,
    message: String,
    detail: Value,
}
