use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use jcr_core::{BlobStore, BlobStream, CompletedPart, Digest, StorageError, StorageUpload};
use tokio::{
    fs::{self, File},
    io::{AsyncWriteExt, BufWriter},
};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct FilesystemBlobStore {
    uploads: PathBuf,
    objects: PathBuf,
}

impl FilesystemBlobStore {
    pub async fn new(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        let uploads = root.join(".uploads");
        let objects = root.join("objects");
        fs::create_dir_all(&uploads).await?;
        fs::create_dir_all(&objects).await?;
        Ok(Self { uploads, objects })
    }

    fn safe_object_path(&self, key: &str) -> Result<PathBuf, StorageError> {
        let relative = Path::new(key);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(StorageError::InvalidState(format!(
                "unsafe object key '{key}'"
            )));
        }
        Ok(self.objects.join(relative))
    }

    fn upload_dir(&self, upload_id: &str) -> Result<PathBuf, StorageError> {
        let id = Uuid::parse_str(upload_id)
            .map_err(|_| StorageError::InvalidState("invalid upload id".to_owned()))?;
        Ok(self.uploads.join(id.to_string()))
    }

    fn part_path(&self, upload_id: &str, part_number: i32) -> Result<PathBuf, StorageError> {
        Ok(self
            .upload_dir(upload_id)?
            .join(format!("{part_number:08}.part")))
    }
}

#[async_trait]
impl BlobStore for FilesystemBlobStore {
    async fn initiate_upload(&self, key: &str) -> Result<StorageUpload, StorageError> {
        self.safe_object_path(key)?;
        let upload_id = Uuid::new_v4().to_string();
        fs::create_dir_all(self.upload_dir(&upload_id)?).await?;
        Ok(StorageUpload {
            key: key.to_owned(),
            upload_id,
        })
    }

    async fn upload_part(
        &self,
        upload: &StorageUpload,
        part_number: i32,
        bytes: Bytes,
    ) -> Result<CompletedPart, StorageError> {
        let path = self.part_path(&upload.upload_id, part_number)?;
        fs::write(&path, &bytes).await?;
        Ok(CompletedPart {
            part_number,
            etag: Digest::sha256(&bytes).to_string(),
            size: bytes.len() as u64,
        })
    }

    async fn complete_upload(
        &self,
        upload: &StorageUpload,
        parts: &[CompletedPart],
    ) -> Result<(), StorageError> {
        let destination = self.safe_object_path(&upload.key)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).await?;
        }

        let temporary = destination.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let mut output = BufWriter::new(File::create(&temporary).await?);
        for part in parts {
            let path = self.part_path(&upload.upload_id, part.part_number)?;
            let mut input = File::open(path).await?;
            tokio::io::copy(&mut input, &mut output).await?;
        }
        output.flush().await?;
        output.get_ref().sync_all().await?;
        drop(output);
        fs::rename(temporary, destination).await?;
        let _ = fs::remove_dir_all(self.upload_dir(&upload.upload_id)?).await;
        Ok(())
    }

    async fn abort_upload(&self, upload: &StorageUpload) -> Result<(), StorageError> {
        match fs::remove_dir_all(self.upload_dir(&upload.upload_id)?).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn put(&self, key: &str, bytes: Bytes) -> Result<(), StorageError> {
        let destination = self.safe_object_path(key)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(destination, bytes).await?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        match fs::metadata(self.safe_object_path(key)?).await {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn stream(&self, key: &str) -> Result<BlobStream, StorageError> {
        let file = File::open(self.safe_object_path(key)?)
            .await
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound(key.to_owned())
                } else {
                    StorageError::Io(error)
                }
            })?;
        let stream = ReaderStream::new(file).map(|result| result.map_err(StorageError::Io));
        Ok(Box::pin(stream))
    }

    async fn signed_get_url(
        &self,
        _key: &str,
        _expires_in_seconds: u64,
    ) -> Result<Option<String>, StorageError> {
        Ok(None)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match fs::remove_file(self.safe_object_path(key)?).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;
    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn completes_and_streams_multipart_objects() {
        let directory = tempdir().unwrap();
        let store = FilesystemBlobStore::new(directory.path()).await.unwrap();
        let upload = store.initiate_upload("blobs/example").await.unwrap();
        let first = store
            .upload_part(&upload, 1, Bytes::from_static(b"hello "))
            .await
            .unwrap();
        let second = store
            .upload_part(&upload, 2, Bytes::from_static(b"world"))
            .await
            .unwrap();
        store
            .complete_upload(&upload, &[first, second])
            .await
            .unwrap();

        let bytes = store
            .stream("blobs/example")
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .concat();
        assert_eq!(bytes, b"hello world");
    }
}
