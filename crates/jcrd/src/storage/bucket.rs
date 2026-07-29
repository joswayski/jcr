use std::time::Duration;

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client,
    config::Builder as S3ConfigBuilder,
    presigning::PresigningConfig,
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart as S3CompletedPart},
};
use bytes::Bytes;
use futures::StreamExt;
use jcr_core::{BlobStore, BlobStream, CompletedPart, StorageError, StorageUpload};
use tokio_util::io::ReaderStream;

#[derive(Clone, Debug)]
pub struct BucketOptions {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub force_path_style: bool,
}

#[derive(Clone, Debug)]
pub struct BucketBlobStore {
    client: Client,
    bucket: String,
}

impl BucketBlobStore {
    pub async fn new(options: BucketOptions) -> Result<Self, StorageError> {
        let credentials = Credentials::new(
            options.access_key_id,
            options.secret_access_key,
            None,
            None,
            "jcr-config",
        );
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(options.region))
            .credentials_provider(credentials)
            .load()
            .await;
        let config = S3ConfigBuilder::from(&shared)
            .endpoint_url(options.endpoint)
            .force_path_style(options.force_path_style)
            .build();

        Ok(Self {
            client: Client::from_conf(config),
            bucket: options.bucket,
        })
    }

    fn provider(error: impl std::fmt::Display) -> StorageError {
        StorageError::Provider(error.to_string())
    }
}

#[async_trait]
impl BlobStore for BucketBlobStore {
    async fn initiate_upload(&self, key: &str) -> Result<StorageUpload, StorageError> {
        let output = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Self::provider)?;
        let upload_id = output.upload_id().ok_or_else(|| {
            StorageError::Provider("bucket provider omitted upload id".to_owned())
        })?;
        Ok(StorageUpload {
            key: key.to_owned(),
            upload_id: upload_id.to_owned(),
        })
    }

    async fn upload_part(
        &self,
        upload: &StorageUpload,
        part_number: i32,
        bytes: Bytes,
    ) -> Result<CompletedPart, StorageError> {
        let size = bytes.len() as u64;
        let output = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(&upload.key)
            .upload_id(&upload.upload_id)
            .part_number(part_number)
            .content_length(size as i64)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(Self::provider)?;
        let etag = output.e_tag().ok_or_else(|| {
            StorageError::Provider("bucket provider omitted part ETag".to_owned())
        })?;
        Ok(CompletedPart {
            part_number,
            etag: etag.to_owned(),
            size,
        })
    }

    async fn complete_upload(
        &self,
        upload: &StorageUpload,
        parts: &[CompletedPart],
    ) -> Result<(), StorageError> {
        let parts = parts
            .iter()
            .map(|part| {
                S3CompletedPart::builder()
                    .part_number(part.part_number)
                    .e_tag(&part.etag)
                    .build()
            })
            .collect::<Vec<_>>();
        let multipart = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&upload.key)
            .upload_id(&upload.upload_id)
            .multipart_upload(multipart)
            .send()
            .await
            .map_err(Self::provider)?;
        Ok(())
    }

    async fn abort_upload(&self, upload: &StorageUpload) -> Result<(), StorageError> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(&upload.key)
            .upload_id(&upload.upload_id)
            .send()
            .await
            .map_err(Self::provider)?;
        Ok(())
    }

    async fn put(&self, key: &str, bytes: Bytes) -> Result<(), StorageError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(Self::provider)?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_not_found()) =>
            {
                Ok(false)
            }
            Err(error) => Err(Self::provider(error)),
        }
    }

    async fn stream(&self, key: &str) -> Result<BlobStream, StorageError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Self::provider)?;
        let stream = ReaderStream::new(output.body.into_async_read())
            .map(|result| result.map_err(StorageError::Io));
        Ok(Box::pin(stream))
    }

    async fn signed_get_url(
        &self,
        key: &str,
        expires_in_seconds: u64,
    ) -> Result<Option<String>, StorageError> {
        let config = PresigningConfig::expires_in(Duration::from_secs(expires_in_seconds))
            .map_err(Self::provider)?;
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(config)
            .await
            .map_err(Self::provider)?;
        Ok(Some(request.uri().to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Self::provider)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn multipart_round_trip_when_bucket_test_backend_is_configured() {
        let Some(endpoint) = std::env::var("JCR_TEST_BUCKET_ENDPOINT").ok() else {
            eprintln!("skipping bucket integration; JCR_TEST_BUCKET_ENDPOINT is unset");
            return;
        };
        let options = BucketOptions {
            endpoint,
            region: std::env::var("JCR_TEST_BUCKET_REGION")
                .unwrap_or_else(|_| "us-east-1".to_owned()),
            bucket: std::env::var("JCR_TEST_BUCKET_NAME").unwrap_or_else(|_| "jcr".to_owned()),
            access_key_id: std::env::var("JCR_TEST_BUCKET_ACCESS_KEY_ID")
                .expect("JCR_TEST_BUCKET_ACCESS_KEY_ID is required"),
            secret_access_key: std::env::var("JCR_TEST_BUCKET_SECRET_ACCESS_KEY")
                .expect("JCR_TEST_BUCKET_SECRET_ACCESS_KEY is required"),
            force_path_style: std::env::var("JCR_TEST_BUCKET_FORCE_PATH_STYLE")
                .map(|value| value != "false")
                .unwrap_or(true),
        };
        let store = BucketBlobStore::new(options).await.unwrap();
        let created_bucket = std::env::var("JCR_TEST_BUCKET_CREATE").as_deref() == Ok("1");
        if created_bucket {
            store
                .client
                .create_bucket()
                .bucket(&store.bucket)
                .send()
                .await
                .unwrap();
        }
        let key = format!("integration/{}", Uuid::new_v4());
        let upload = store.initiate_upload(&key).await.unwrap();
        let first_bytes = Bytes::from(vec![0x51; 6 * 1024 * 1024]);
        let final_bytes = Bytes::from_static(b"final-part");
        let first = store
            .upload_part(&upload, 1, first_bytes.clone())
            .await
            .unwrap();
        let final_part = store
            .upload_part(&upload, 2, final_bytes.clone())
            .await
            .unwrap();
        store
            .complete_upload(&upload, &[first, final_part])
            .await
            .unwrap();
        assert!(store.exists(&key).await.unwrap());
        assert!(store.signed_get_url(&key, 60).await.unwrap().is_some());
        let received = store
            .stream(&key)
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .concat();
        let expected = [first_bytes.as_ref(), final_bytes.as_ref()].concat();
        assert_eq!(received, expected);
        store.delete(&key).await.unwrap();
        assert!(!store.exists(&key).await.unwrap());
        if created_bucket {
            store
                .client
                .delete_bucket()
                .bucket(&store.bucket)
                .send()
                .await
                .unwrap();
        }
    }
}
