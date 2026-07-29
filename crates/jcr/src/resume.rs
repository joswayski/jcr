use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResumeEntry {
    pub location: String,
    pub offset: u64,
}

#[derive(Default, Deserialize, Serialize)]
struct ResumeData {
    uploads: HashMap<String, ResumeEntry>,
}

#[derive(Clone)]
pub struct ResumeStore {
    path: Arc<PathBuf>,
    data: Arc<Mutex<ResumeData>>,
}

impl ResumeStore {
    pub async fn load() -> Result<Self> {
        Self::at(state_path()?).await
    }

    pub async fn at(path: PathBuf) -> Result<Self> {
        let data = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse {}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ResumeData::default(),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        Ok(Self {
            path: Arc::new(path),
            data: Arc::new(Mutex::new(data)),
        })
    }

    pub async fn get(&self, key: &str) -> Option<ResumeEntry> {
        self.data.lock().await.uploads.get(key).cloned()
    }

    pub async fn set(&self, key: String, entry: ResumeEntry) -> Result<()> {
        let bytes = {
            let mut data = self.data.lock().await;
            data.uploads.insert(key, entry);
            serde_json::to_vec_pretty(&*data)?
        };
        write_atomic(&self.path, &bytes).await
    }

    pub async fn remove(&self, key: &str) -> Result<()> {
        let bytes = {
            let mut data = self.data.lock().await;
            data.uploads.remove(key);
            serde_json::to_vec_pretty(&*data)?
        };
        write_atomic(&self.path, &bytes).await
    }
}

fn state_path() -> Result<PathBuf> {
    if let Some(directory) = std::env::var_os("JCR_STATE_DIR") {
        return Ok(PathBuf::from(directory).join("uploads.json"));
    }
    if let Some(directory) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(directory).join("jcr/uploads.json"));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME is unavailable and JCR_STATE_DIR is unset"))?;
    Ok(PathBuf::from(home).join(".local/state/jcr/uploads.json"))
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("JCR state path has no parent"))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let temporary = parent.join(format!(".uploads-{}.tmp", Uuid::new_v4()));
    tokio::fs::write(&temporary, bytes)
        .await
        .context("failed to write resumable upload state")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .await
            .context("failed to secure resumable upload state")?;
    }

    tokio::fs::rename(&temporary, path)
        .await
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn persists_resume_offsets() {
        let directory = tempfile::tempdir().unwrap();
        let store = ResumeStore {
            path: Arc::new(directory.path().join("uploads.json")),
            data: Arc::new(Mutex::new(ResumeData::default())),
        };
        store
            .set(
                "registry/repo@digest".to_owned(),
                ResumeEntry {
                    location: "/upload/1".to_owned(),
                    offset: 64,
                },
            )
            .await
            .unwrap();
        assert_eq!(store.get("registry/repo@digest").await.unwrap().offset, 64);
    }
}
