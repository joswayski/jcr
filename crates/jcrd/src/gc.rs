use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use jcr_core::StorageUpload;
use sqlx::FromRow;
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

#[derive(FromRow)]
struct ExpiredUpload {
    id: Uuid,
    object_key: String,
    storage_upload_id: String,
}

#[derive(FromRow)]
struct GarbageBlob {
    digest: String,
    object_key: String,
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            if let Err(error) = run_once(&state).await {
                tracing::error!(error = %error, "garbage collection pass failed");
            }
        }
    });
}

pub async fn run_once(state: &AppState) -> Result<(), AppError> {
    clean_expired_uploads(state).await?;
    clean_unreferenced_blobs(state).await?;
    Ok(())
}

async fn clean_expired_uploads(state: &AppState) -> Result<(), AppError> {
    let uploads = sqlx::query_as::<_, ExpiredUpload>(
        "SELECT id, object_key, storage_upload_id
         FROM upload_sessions
         WHERE status IN ('uploading', 'finalizing')
           AND expires_at <= NOW()
         ORDER BY expires_at
         LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await?;

    for upload in uploads {
        let storage_upload = StorageUpload {
            key: upload.object_key,
            upload_id: upload.storage_upload_id,
        };
        if let Err(error) = state.blob_store.abort_upload(&storage_upload).await {
            tracing::warn!(
                upload_id = %upload.id,
                error = %error,
                "could not abort expired storage upload"
            );
        }
        sqlx::query(
            "UPDATE upload_sessions
             SET status = 'failed', error_message = 'upload expired',
                 updated_at = NOW()
             WHERE id = $1 AND status IN ('uploading', 'finalizing')",
        )
        .bind(upload.id)
        .execute(&state.pool)
        .await?;
    }
    Ok(())
}

async fn clean_unreferenced_blobs(state: &AppState) -> Result<(), AppError> {
    let cutoff = Utc::now() - Duration::days(state.config.gc_grace_days);
    let blobs = sqlx::query_as::<_, GarbageBlob>(
        "SELECT b.digest, b.object_key
         FROM blobs b
         WHERE b.status = 'committed'
           AND b.created_at < $1
           AND NOT EXISTS (
               SELECT 1
               FROM descriptor_edges e
               JOIN repository_manifests rm
                 ON rm.digest = e.parent_digest
                AND rm.deleted_at IS NULL
               WHERE e.child_digest = b.digest
                 AND e.relationship IN ('config', 'layer')
           )
         ORDER BY b.created_at
         LIMIT 100",
    )
    .bind(cutoff)
    .fetch_all(&state.pool)
    .await?;

    for blob in blobs {
        let mut transaction = state.pool.begin().await?;
        let claimed = sqlx::query(
            "UPDATE blobs b
             SET status = 'tombstoned', tombstoned_at = NOW()
             WHERE b.digest = $1
               AND b.status = 'committed'
               AND b.created_at < $2
               AND NOT EXISTS (
                   SELECT 1
                   FROM descriptor_edges e
                   JOIN repository_manifests rm
                     ON rm.digest = e.parent_digest
                    AND rm.deleted_at IS NULL
                   WHERE e.child_digest = b.digest
                     AND e.relationship IN ('config', 'layer')
               )",
        )
        .bind(&blob.digest)
        .bind(cutoff)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        transaction.commit().await?;
        if claimed == 0 {
            continue;
        }

        if let Err(error) = state.blob_store.delete(&blob.object_key).await {
            sqlx::query(
                "UPDATE blobs
                 SET status = 'committed', tombstoned_at = NULL
                 WHERE digest = $1 AND status = 'tombstoned'",
            )
            .bind(&blob.digest)
            .execute(&state.pool)
            .await?;
            return Err(error.into());
        }
        sqlx::query("DELETE FROM repository_blobs WHERE digest = $1")
            .bind(&blob.digest)
            .execute(&state.pool)
            .await?;
    }
    Ok(())
}
