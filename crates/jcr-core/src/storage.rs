use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type BlobStream = Pin<Box<dyn Stream<Item = Result<Bytes, StorageError>> + Send + 'static>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageUpload {
    pub key: String,
    pub upload_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletedPart {
    pub part_number: i32,
    pub etag: String,
    pub size: u64,
}

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn initiate_upload(&self, key: &str) -> Result<StorageUpload, StorageError>;

    async fn upload_part(
        &self,
        upload: &StorageUpload,
        part_number: i32,
        bytes: Bytes,
    ) -> Result<CompletedPart, StorageError>;

    async fn complete_upload(
        &self,
        upload: &StorageUpload,
        parts: &[CompletedPart],
    ) -> Result<(), StorageError>;

    async fn abort_upload(&self, upload: &StorageUpload) -> Result<(), StorageError>;

    async fn put(&self, key: &str, bytes: Bytes) -> Result<(), StorageError>;

    async fn exists(&self, key: &str) -> Result<bool, StorageError>;

    async fn stream(&self, key: &str) -> Result<BlobStream, StorageError>;

    async fn signed_get_url(
        &self,
        key: &str,
        expires_in_seconds: u64,
    ) -> Result<Option<String>, StorageError>;

    async fn delete(&self, key: &str) -> Result<(), StorageError>;
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("object '{0}' was not found")]
    NotFound(String),
    #[error("storage rejected the request: {0}")]
    Provider(String),
    #[error("storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored upload state is invalid: {0}")]
    InvalidState(String),
}
