use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use jcr_core::BlobStore;
use url::Url;

use crate::storage::{FilesystemBlobStore, S3BlobStore, S3Options};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationMode {
    Closed,
    Allowlist,
    Invite,
    Open,
}

impl RegistrationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Allowlist => "allowlist",
            Self::Invite => "invite",
            Self::Open => "open",
        }
    }
}

impl FromStr for RegistrationMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "closed" => Ok(Self::Closed),
            "allowlist" => Ok(Self::Allowlist),
            "invite" => Ok(Self::Invite),
            "open" => Ok(Self::Open),
            _ => bail!("JCR_REGISTRATION_MODE must be closed, allowlist, invite, or open"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: Url,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_address: SocketAddr,
    pub public_url: Url,
    pub database_url: String,
    pub jwt_secret: String,
    pub registration_mode: RegistrationMode,
    pub bootstrap_email: Option<String>,
    pub bootstrap_username: String,
    pub bootstrap_namespace: String,
    pub google: Option<GoogleOAuthConfig>,
    pub upload_chunk_limit: usize,
    pub upload_session_hours: i64,
    pub gc_grace_days: i64,
    pub storage: StorageConfig,
}

#[derive(Clone, Debug)]
pub enum StorageConfig {
    Filesystem { root: PathBuf },
    S3(S3Options),
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen_address = env_or("JCR_LISTEN_ADDRESS", "127.0.0.1:5000")
            .parse()
            .context("JCR_LISTEN_ADDRESS is not a valid socket address")?;
        let public_url = Url::parse(&env_or("JCR_PUBLIC_URL", "http://127.0.0.1:5000"))
            .context("JCR_PUBLIC_URL is not a valid URL")?;
        let database_url = required("JCR_DATABASE_URL")?;
        let jwt_secret = required("JCR_JWT_SECRET")?;
        if jwt_secret.len() < 32 {
            bail!("JCR_JWT_SECRET must contain at least 32 bytes");
        }

        let registration_mode = env_or("JCR_REGISTRATION_MODE", "allowlist").parse()?;
        let bootstrap_email = optional("JCR_BOOTSTRAP_EMAIL")
            .map(|email| email.trim().to_ascii_lowercase())
            .filter(|email| !email.is_empty());
        let bootstrap_username = env_or("JCR_BOOTSTRAP_USERNAME", "jose");
        let bootstrap_namespace = env_or("JCR_BOOTSTRAP_NAMESPACE", "jose");

        if registration_mode == RegistrationMode::Allowlist && bootstrap_email.is_none() {
            tracing::warn!(
                "registration is allowlist-only but JCR_BOOTSTRAP_EMAIL is unset; no new account can be created"
            );
        }

        let google_client_id = optional("JCR_GOOGLE_CLIENT_ID");
        let google_client_secret = optional("JCR_GOOGLE_CLIENT_SECRET");
        let google_redirect_url = optional("JCR_GOOGLE_REDIRECT_URL");
        let google = match (google_client_id, google_client_secret, google_redirect_url) {
            (None, None, None) => None,
            (Some(client_id), Some(client_secret), Some(redirect_url)) => Some(GoogleOAuthConfig {
                client_id,
                client_secret,
                redirect_url: Url::parse(&redirect_url)
                    .context("JCR_GOOGLE_REDIRECT_URL is invalid")?,
            }),
            _ => bail!(
                "Google OAuth requires JCR_GOOGLE_CLIENT_ID, JCR_GOOGLE_CLIENT_SECRET, and JCR_GOOGLE_REDIRECT_URL together"
            ),
        };

        let upload_chunk_limit = parse_u64("JCR_UPLOAD_CHUNK_LIMIT_MIB", 80)?
            .checked_mul(1024 * 1024)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| anyhow!("JCR_UPLOAD_CHUNK_LIMIT_MIB is too large"))?;

        let storage = match env_or("JCR_STORAGE_BACKEND", "filesystem").as_str() {
            "filesystem" => StorageConfig::Filesystem {
                root: PathBuf::from(env_or("JCR_FILESYSTEM_ROOT", ".data/storage")),
            },
            "s3" => StorageConfig::S3(S3Options {
                endpoint: required("JCR_S3_ENDPOINT")?,
                region: env_or("JCR_S3_REGION", "auto"),
                bucket: required("JCR_S3_BUCKET")?,
                access_key_id: required("JCR_S3_ACCESS_KEY_ID")?,
                secret_access_key: required("JCR_S3_SECRET_ACCESS_KEY")?,
                force_path_style: parse_bool("JCR_S3_FORCE_PATH_STYLE", true)?,
            }),
            backend => bail!("unsupported JCR_STORAGE_BACKEND '{backend}'"),
        };

        Ok(Self {
            listen_address,
            public_url,
            database_url,
            jwt_secret,
            registration_mode,
            bootstrap_email,
            bootstrap_username,
            bootstrap_namespace,
            google,
            upload_chunk_limit,
            upload_session_hours: parse_i64("JCR_UPLOAD_SESSION_HOURS", 24)?,
            gc_grace_days: parse_i64("JCR_GC_GRACE_DAYS", 7)?,
            storage,
        })
    }

    pub async fn create_blob_store(&self) -> Result<Arc<dyn BlobStore>> {
        match &self.storage {
            StorageConfig::Filesystem { root } => {
                Ok(Arc::new(FilesystemBlobStore::new(root).await?))
            }
            StorageConfig::S3(options) => Ok(Arc::new(S3BlobStore::new(options.clone()).await?)),
        }
    }
}

fn env_or(name: &str, default: &str) -> String {
    optional(name).unwrap_or_else(|| default.to_owned())
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required(name: &str) -> Result<String> {
    optional(name).ok_or_else(|| anyhow!("{name} is required"))
}

fn parse_u64(name: &str, default: u64) -> Result<u64> {
    optional(name)
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("{name} must be an unsigned integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn parse_i64(name: &str, default: i64) -> Result<i64> {
    optional(name)
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("{name} must be an integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn parse_bool(name: &str, default: bool) -> Result<bool> {
    optional(name)
        .map(|value| match value.as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(anyhow!("{name} must be true or false")),
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}
