use std::sync::Arc;

use jcr_core::BlobStore;
use reqwest::Client;
use sqlx::PgPool;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: PgPool,
    pub blob_store: Arc<dyn BlobStore>,
    pub http: Client,
}

impl AppState {
    pub fn new(config: Config, pool: PgPool, blob_store: Arc<dyn BlobStore>) -> Self {
        Self {
            config: Arc::new(config),
            pool,
            blob_store,
            http: Client::new(),
        }
    }
}
