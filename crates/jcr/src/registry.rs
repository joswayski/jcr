use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use jcr_core::{Digest, ImageReference};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{
    Client, Response, StatusCode,
    header::{CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE, WWW_AUTHENTICATE},
};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::RwLock,
};
use url::Url;

use crate::{
    image::{BlobFile, ManifestObject, PreparedImage},
    resume::{ResumeEntry, ResumeStore},
};

pub const CHUNK_SIZE: usize = 64 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 5;

#[derive(Clone)]
pub struct RegistryClient {
    http: Client,
    base: Url,
    repository: String,
    username: Arc<str>,
    secret: Arc<str>,
    challenge: Arc<Challenge>,
    token: Arc<RwLock<String>>,
}

#[derive(Clone, Debug)]
struct Challenge {
    realm: Url,
    service: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

struct UploadPosition {
    location: String,
    offset: u64,
}

impl RegistryClient {
    pub async fn validate_login(registry: &str, username: &str, secret: &str) -> Result<()> {
        let http = Client::builder()
            .user_agent(concat!("jcr/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let base = registry_base(registry)?;
        let challenge = discover_challenge(&http, &base).await?;
        exchange_token(&http, &challenge, username, secret, None).await?;
        Ok(())
    }

    pub async fn for_push(remote: &ImageReference, username: &str, secret: &str) -> Result<Self> {
        let http = Client::builder()
            .user_agent(concat!("jcr/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let base = registry_base(&remote.registry)?;
        let challenge = discover_challenge(&http, &base).await?;
        let scope = format!("repository:{}:pull,push", remote.repository);
        let token = exchange_token(&http, &challenge, username, secret, Some(&scope)).await?;
        Ok(Self {
            http,
            base,
            repository: remote.repository.clone(),
            username: Arc::from(username),
            secret: Arc::from(secret),
            challenge: Arc::new(challenge),
            token: Arc::new(RwLock::new(token)),
        })
    }

    pub async fn push(
        &self,
        image: PreparedImage,
        remote: &ImageReference,
        jobs: usize,
        resume: ResumeStore,
    ) -> Result<()> {
        if remote.is_digest() && remote.reference.parse::<Digest>()? != image.root_digest {
            bail!(
                "remote digest {} does not match prepared image {}",
                remote.reference,
                image.root_digest
            );
        }

        let progress = MultiProgress::new();
        let style = ProgressStyle::with_template(
            "{spinner:.green} {prefix:.bold} [{bar:32.cyan/blue}] {bytes}/{total_bytes} {bytes_per_sec}",
        )?
        .progress_chars("=>-");
        stream::iter(image.blobs.clone().into_iter().map(|blob| {
            let client = self.clone();
            let progress = progress.clone();
            let style = style.clone();
            let resume = resume.clone();
            let registry = remote.registry.clone();
            async move {
                let bar = progress.add(ProgressBar::new(blob.size));
                bar.set_style(style);
                bar.set_prefix(short_digest(&blob.digest));
                let result = client.upload_blob(&registry, &blob, &bar, &resume).await;
                match &result {
                    Ok(()) => bar.finish_with_message("uploaded"),
                    Err(_) => bar.abandon_with_message("failed"),
                }
                result
            }
        }))
        .buffer_unordered(jobs)
        .try_collect::<Vec<_>>()
        .await?;

        for manifest in &image.manifests {
            if manifest.digest == image.root_digest {
                self.put_manifest(&remote.reference, manifest).await?;
            } else {
                self.put_manifest(&manifest.digest.to_string(), manifest)
                    .await?;
            }
        }
        Ok(())
    }

    async fn upload_blob(
        &self,
        registry: &str,
        blob: &BlobFile,
        progress: &ProgressBar,
        resume: &ResumeStore,
    ) -> Result<()> {
        let key = format!("{registry}/{}@{}", self.repository, blob.digest);
        if self.blob_exists(&blob.digest).await? {
            resume.remove(&key).await?;
            progress.set_position(blob.size);
            return Ok(());
        }

        let mut position = if let Some(saved) = resume.get(&key).await {
            match self.upload_status(&saved.location).await {
                Ok(position)
                    if position.offset <= blob.size && position.offset % CHUNK_SIZE as u64 == 0 =>
                {
                    position
                }
                Ok(_) | Err(_) => {
                    resume.remove(&key).await?;
                    self.start_upload().await?
                }
            }
        } else {
            self.start_upload().await?
        };
        resume
            .set(
                key.clone(),
                ResumeEntry {
                    location: position.location.clone(),
                    offset: position.offset,
                },
            )
            .await?;
        progress.set_position(position.offset);

        let mut file = tokio::fs::File::open(&blob.path)
            .await
            .with_context(|| format!("failed to open {}", blob.path.display()))?;
        file.seek(std::io::SeekFrom::Start(position.offset)).await?;
        while blob.size - position.offset >= CHUNK_SIZE as u64 {
            let mut buffer = vec![0_u8; CHUNK_SIZE];
            file.read_exact(&mut buffer).await?;
            let expected = position.offset + CHUNK_SIZE as u64;
            position = self
                .patch_upload(&position.location, position.offset, Bytes::from(buffer))
                .await?;
            if position.offset != expected {
                bail!(
                    "registry acknowledged offset {}, expected {}",
                    position.offset,
                    expected
                );
            }
            resume
                .set(
                    key.clone(),
                    ResumeEntry {
                        location: position.location.clone(),
                        offset: position.offset,
                    },
                )
                .await?;
            progress.set_position(position.offset);
        }

        let remainder = (blob.size - position.offset) as usize;
        let final_bytes = if remainder == 0 {
            Bytes::new()
        } else {
            let mut buffer = vec![0_u8; remainder];
            file.read_exact(&mut buffer).await?;
            Bytes::from(buffer)
        };
        self.complete_upload(
            &position.location,
            position.offset,
            &blob.digest,
            final_bytes,
        )
        .await?;
        resume.remove(&key).await?;
        progress.set_position(blob.size);
        Ok(())
    }

    async fn blob_exists(&self, digest: &Digest) -> Result<bool> {
        let url = self.registry_url(&format!("blobs/{}", path_segment(&digest.to_string())))?;
        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .http
                .head(url.clone())
                .bearer_auth(self.current_token().await)
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => return Ok(true),
                Ok(response) if response.status() == StatusCode::NOT_FOUND => {
                    return Ok(false);
                }
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                    self.refresh_token().await?;
                }
                Ok(response) if transient(response.status()) => {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(response_error(response).await),
                Err(error) if error.is_timeout() || error.is_connect() => {
                    retry_delay(attempt).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        bail!("blob existence check exhausted its retries")
    }

    async fn start_upload(&self) -> Result<UploadPosition> {
        let url = self.registry_url("blobs/uploads/")?;
        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .http
                .post(url.clone())
                .bearer_auth(self.current_token().await)
                .send()
                .await;
            match response {
                Ok(response)
                    if matches!(
                        response.status(),
                        StatusCode::ACCEPTED | StatusCode::CREATED
                    ) =>
                {
                    return upload_position(response, 0);
                }
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                    self.refresh_token().await?;
                }
                Ok(response) if transient(response.status()) => {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(response_error(response).await),
                Err(error) if error.is_timeout() || error.is_connect() => {
                    retry_delay(attempt).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        bail!("upload initialization exhausted its retries")
    }

    async fn upload_status(&self, location: &str) -> Result<UploadPosition> {
        let url = self.resolve_location(location)?;
        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .http
                .get(url.clone())
                .bearer_auth(self.current_token().await)
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    let offset = response
                        .headers()
                        .get(RANGE)
                        .and_then(|value| value.to_str().ok())
                        .map(parse_range_offset)
                        .transpose()?
                        .unwrap_or(0);
                    return upload_position(response, offset);
                }
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                    self.refresh_token().await?;
                }
                Ok(response) if transient(response.status()) => {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(response_error(response).await),
                Err(error) if error.is_timeout() || error.is_connect() => {
                    retry_delay(attempt).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        bail!("upload status exhausted its retries")
    }

    async fn patch_upload(
        &self,
        location: &str,
        offset: u64,
        bytes: Bytes,
    ) -> Result<UploadPosition> {
        let url = self.resolve_location(location)?;
        let end = offset + bytes.len() as u64 - 1;
        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .http
                .patch(url.clone())
                .bearer_auth(self.current_token().await)
                .header(CONTENT_TYPE, "application/octet-stream")
                .header(CONTENT_RANGE, format!("{offset}-{end}"))
                .body(bytes.clone())
                .send()
                .await;
            match response {
                Ok(response) if response.status() == StatusCode::ACCEPTED => {
                    let acknowledged = response
                        .headers()
                        .get(RANGE)
                        .and_then(|value| value.to_str().ok())
                        .map(parse_range_offset)
                        .transpose()?
                        .ok_or_else(|| anyhow!("registry omitted Range from PATCH response"))?;
                    return upload_position(response, acknowledged);
                }
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                    self.refresh_token().await?;
                }
                Ok(response) if transient(response.status()) => {
                    if let Ok(position) = self.upload_status(location).await
                        && position.offset >= offset + bytes.len() as u64
                    {
                        return Ok(position);
                    }
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(response_error(response).await),
                Err(error) if error.is_timeout() || error.is_connect() => {
                    // The server may have accepted a body before the
                    // connection failed. Querying status prevents replay.
                    if let Ok(position) = self.upload_status(location).await
                        && position.offset >= offset + bytes.len() as u64
                    {
                        return Ok(position);
                    }
                    retry_delay(attempt).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        bail!("chunk upload exhausted its retries")
    }

    async fn complete_upload(
        &self,
        location: &str,
        offset: u64,
        digest: &Digest,
        bytes: Bytes,
    ) -> Result<()> {
        let mut url = self.resolve_location(location)?;
        url.query_pairs_mut()
            .append_pair("digest", &digest.to_string());
        for attempt in 0..MAX_ATTEMPTS {
            let mut request = self
                .http
                .put(url.clone())
                .bearer_auth(self.current_token().await)
                .header(CONTENT_TYPE, "application/octet-stream");
            if !bytes.is_empty() {
                request = request.header(
                    CONTENT_RANGE,
                    format!("{}-{}", offset, offset + bytes.len() as u64 - 1),
                );
            }
            let response = request.body(bytes.clone()).send().await;
            match response {
                Ok(response) if response.status() == StatusCode::CREATED => {
                    return Ok(());
                }
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                    self.refresh_token().await?;
                }
                Ok(response) if transient(response.status()) => {
                    if self.blob_exists(digest).await.unwrap_or(false) {
                        return Ok(());
                    }
                    retry_delay(attempt).await;
                }
                Ok(response) => {
                    // A previous completion request can finish after this
                    // retry reaches a now-finalizing upload session. Checking
                    // the immutable digest prevents reporting failure after
                    // the registry has actually committed the blob.
                    if self.blob_exists(digest).await.unwrap_or(false) {
                        return Ok(());
                    }
                    return Err(response_error(response).await);
                }
                Err(error) if error.is_timeout() || error.is_connect() => {
                    if self.blob_exists(digest).await.unwrap_or(false) {
                        return Ok(());
                    }
                    retry_delay(attempt).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        bail!("upload completion exhausted its retries")
    }

    async fn put_manifest(&self, reference: &str, manifest: &ManifestObject) -> Result<()> {
        let url = self.registry_url(&format!("manifests/{}", path_segment(reference)))?;
        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .http
                .put(url.clone())
                .bearer_auth(self.current_token().await)
                .header(CONTENT_TYPE, &manifest.media_type)
                .body(manifest.bytes.clone())
                .send()
                .await;
            match response {
                Ok(response) if response.status() == StatusCode::CREATED => {
                    return Ok(());
                }
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                    self.refresh_token().await?;
                }
                Ok(response) if transient(response.status()) => {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(response_error(response).await),
                Err(error) if error.is_timeout() || error.is_connect() => {
                    retry_delay(attempt).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        bail!("manifest upload exhausted its retries")
    }

    async fn current_token(&self) -> String {
        self.token.read().await.clone()
    }

    async fn refresh_token(&self) -> Result<()> {
        let scope = format!("repository:{}:pull,push", self.repository);
        let token = exchange_token(
            &self.http,
            &self.challenge,
            &self.username,
            &self.secret,
            Some(&scope),
        )
        .await?;
        *self.token.write().await = token;
        Ok(())
    }

    fn registry_url(&self, suffix: &str) -> Result<Url> {
        self.base
            .join(&format!("v2/{}/{suffix}", self.repository))
            .context("failed to build registry URL")
    }

    fn resolve_location(&self, location: &str) -> Result<Url> {
        Url::parse(location)
            .or_else(|_| self.base.join(location))
            .context("registry returned an invalid upload location")
    }
}

pub fn normalize_registry(value: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() {
        bail!("registry cannot be empty");
    }
    if value.contains("://") {
        let url = Url::parse(value).context("registry URL is invalid")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("registry must be an HTTP(S) origin without a path");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("registry host is missing"))?;
        return Ok(match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        });
    }
    if value.contains('/') || value.contains('?') || value.contains('#') {
        bail!("registry must be a hostname with an optional port");
    }
    Ok(value.to_owned())
}

fn registry_base(registry: &str) -> Result<Url> {
    let registry = normalize_registry(registry)?;
    let local = registry == "localhost"
        || registry.starts_with("localhost:")
        || registry.starts_with("127.0.0.1:")
        || registry.starts_with("[::1]:");
    Url::parse(&format!(
        "{}://{registry}/",
        if local { "http" } else { "https" }
    ))
    .context("registry origin is invalid")
}

async fn discover_challenge(http: &Client, base: &Url) -> Result<Challenge> {
    let response = http
        .get(base.join("v2/")?)
        .send()
        .await
        .context("failed to contact registry")?;
    if response.status() != StatusCode::UNAUTHORIZED {
        bail!(
            "registry did not return the Docker bearer challenge (status {})",
            response.status()
        );
    }
    let value = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow!("registry omitted WWW-Authenticate"))?;
    if !value.starts_with("Bearer ") {
        bail!("registry does not advertise Docker bearer authentication");
    }
    let realm = challenge_field(value, "realm")
        .ok_or_else(|| anyhow!("registry challenge omitted realm"))?;
    let service = challenge_field(value, "service").unwrap_or_else(|| "jcr".to_owned());
    Ok(Challenge {
        realm: Url::parse(&realm).context("registry token realm is invalid")?,
        service,
    })
}

async fn exchange_token(
    http: &Client,
    challenge: &Challenge,
    username: &str,
    secret: &str,
    scope: Option<&str>,
) -> Result<String> {
    let mut request = http
        .get(challenge.realm.clone())
        .basic_auth(username, Some(secret))
        .query(&[("service", challenge.service.as_str())]);
    if let Some(scope) = scope {
        request = request.query(&[("scope", scope)]);
    }
    let response = request
        .send()
        .await
        .context("failed to request registry token")?;
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    let response: TokenResponse = response
        .json()
        .await
        .context("registry returned an invalid token response")?;
    let token = response.token.or(response.access_token).unwrap_or_default();
    if token.is_empty() {
        bail!("registry returned an empty bearer token");
    }
    Ok(token)
}

fn challenge_field(challenge: &str, name: &str) -> Option<String> {
    let start = challenge.find(&format!("{name}=\""))? + name.len() + 2;
    let remainder = &challenge[start..];
    let end = remainder.find('"')?;
    Some(remainder[..end].to_owned())
}

fn upload_position(response: Response, fallback_offset: u64) -> Result<UploadPosition> {
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow!("registry omitted upload Location"))?
        .to_owned();
    Ok(UploadPosition {
        location,
        offset: fallback_offset,
    })
}

fn parse_range_offset(value: &str) -> Result<u64> {
    let (_, end) = value
        .trim()
        .split_once('-')
        .ok_or_else(|| anyhow!("registry returned an invalid Range header"))?;
    Ok(end
        .parse::<u64>()
        .context("registry returned an invalid Range offset")?
        + 1)
}

fn transient(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

async fn retry_delay(attempt: usize) {
    let milliseconds = 200_u64.saturating_mul(1_u64 << attempt.min(4));
    tokio::time::sleep(Duration::from_millis(milliseconds)).await;
}

async fn response_error(response: Response) -> anyhow::Error {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if body.is_empty() {
        anyhow!("registry request failed with {status}")
    } else {
        anyhow!("registry request failed with {status}: {body}")
    }
}

fn path_segment(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn short_digest(digest: &Digest) -> String {
    format!("{}:{}", digest.algorithm(), &digest.encoded()[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge_fields_with_comma_scopes() {
        let challenge = "Bearer realm=\"https://registry.example/auth/token\",service=\"jcr\",scope=\"repository:alice/app:pull,push\"";
        assert_eq!(
            challenge_field(challenge, "realm").as_deref(),
            Some("https://registry.example/auth/token")
        );
        assert_eq!(
            challenge_field(challenge, "service").as_deref(),
            Some("jcr")
        );
    }

    #[test]
    fn parses_registry_ranges_as_next_offsets() {
        assert_eq!(parse_range_offset("0-67108863").unwrap(), 67_108_864);
    }

    #[test]
    fn normalizes_registry_origins() {
        assert_eq!(
            normalize_registry("https://registry.example.com/").unwrap(),
            "registry.example.com"
        );
        assert!(normalize_registry("registry.example.com/path").is_err());
    }
}
