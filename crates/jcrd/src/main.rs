mod app;
mod auth;
mod config;
mod db;
mod error;
mod gc;
mod registry;
mod state;
mod storage;
mod web;

use anyhow::Result;
use config::Config;
use state::AppState;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Local development can use the documented `.env` file. Real
    // deployments continue to provide the same settings as environment
    // variables and do not depend on this file.
    let _ = dotenvy::dotenv();
    init_tracing();

    let config = Config::from_env()?;
    let pool = db::connect_and_migrate(&config).await?;
    let blob_store = config.create_blob_store().await?;
    let state = AppState::new(config.clone(), pool, blob_store);
    gc::spawn(state.clone());
    let application = app::router(state);
    let listener = TcpListener::bind(config.listen_address).await?;

    tracing::info!(address = %config.listen_address, "jcrd listening");
    axum::serve(
        listener,
        application.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("jcrd=info,tower_http=info"));
    let format = tracing_subscriber::fmt::layer();

    tracing_subscriber::registry()
        .with(filter)
        .with(format)
        .init();
}

async fn shutdown_signal() {
    let control_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = control_c => {},
        () = terminate => {},
    }
}
