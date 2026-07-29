use std::{
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use jcr_core::ImageReference;

use jcr::{
    credentials::DockerCredentials,
    image::{prepare_docker_image, prepare_oci_archive},
    registry::{self, RegistryClient},
    resume::ResumeStore,
};

#[derive(Parser)]
#[command(
    name = "jcr",
    version,
    about = "Bounded, resumable pushes for Jose's Container Registry"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a PAT and store it using Docker's credential configuration.
    Login {
        registry: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove credentials using Docker's credential configuration.
    Logout { registry: String },
    /// Push a Docker Engine image or OCI archive in bounded chunks.
    Push {
        #[arg(long, value_name = "PATH")]
        oci_archive: Option<PathBuf>,
        #[arg(long, default_value_t = 3)]
        jobs: usize,
        #[arg(value_name = "SOURCE_OR_REMOTE", num_args = 1..=2)]
        references: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "jcr=warn".into()),
        )
        .with_target(false)
        .init();

    match Cli::parse().command {
        Command::Login {
            registry,
            username,
            password_stdin,
        } => login(&registry, username, password_stdin).await,
        Command::Logout { registry } => logout(&registry),
        Command::Push {
            oci_archive,
            jobs,
            references,
        } => push(oci_archive, jobs, references).await,
    }
}

async fn login(registry: &str, username: Option<String>, password_stdin: bool) -> Result<()> {
    let registry = registry::normalize_registry(registry)?;
    let username = match username {
        Some(username) if !username.trim().is_empty() => username,
        _ => prompt("Username: ")?,
    };
    let secret = if password_stdin {
        let mut value = String::new();
        io::stdin()
            .read_to_string(&mut value)
            .context("failed to read the token from stdin")?;
        value.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        if !io::stdin().is_terminal() {
            bail!("stdin is not a terminal; pass --password-stdin");
        }
        rpassword::prompt_password("Personal access token: ")
            .context("failed to read the personal access token")?
    };
    if secret.is_empty() {
        bail!("personal access token cannot be empty");
    }

    RegistryClient::validate_login(&registry, &username, &secret).await?;
    DockerCredentials::store(&registry, &username, &secret)?;
    println!("Login succeeded for {username} at {registry}");
    Ok(())
}

fn logout(registry: &str) -> Result<()> {
    let registry = registry::normalize_registry(registry)?;
    DockerCredentials::erase(&registry)?;
    println!("Removed credentials for {registry}");
    Ok(())
}

async fn push(oci_archive: Option<PathBuf>, jobs: usize, references: Vec<String>) -> Result<()> {
    if !(1..=16).contains(&jobs) {
        bail!("--jobs must be between 1 and 16");
    }
    let (prepared, remote) = if let Some(path) = oci_archive {
        if references.len() != 1 {
            bail!("jcr push --oci-archive PATH expects one REMOTE_REFERENCE");
        }
        (
            prepare_oci_archive(path).await?,
            references[0].parse::<ImageReference>()?,
        )
    } else {
        if references.len() != 2 {
            bail!("jcr push expects LOCAL_IMAGE REMOTE_REFERENCE");
        }
        (
            prepare_docker_image(&references[0]).await?,
            references[1].parse::<ImageReference>()?,
        )
    };

    let credentials = DockerCredentials::get(&remote.registry)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no Docker-compatible credentials found for {}; run `jcr login {}` or `docker login {}`",
            remote.registry,
            remote.registry,
            remote.registry
        )
    })?;
    let client =
        RegistryClient::for_push(&remote, &credentials.username, &credentials.secret).await?;
    let resume = ResumeStore::load().await?;
    client.push(prepared, &remote, jobs, resume).await?;
    println!("Pushed {remote}");
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush().context("failed to write prompt")?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .context("failed to read prompt")?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("value cannot be empty");
    }
    Ok(value)
}
