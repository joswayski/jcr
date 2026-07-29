use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug)]
pub struct DockerCredentials {
    pub username: String,
    pub secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HelperCredentials {
    username: String,
    secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HelperStore<'a> {
    server_url: &'a str,
    username: &'a str,
    secret: &'a str,
}

impl DockerCredentials {
    pub fn get(registry: &str) -> Result<Option<Self>> {
        let path = docker_config_path()?;
        Self::get_from_path(&path, registry)
    }

    pub fn get_from_path(path: &Path, registry: &str) -> Result<Option<Self>> {
        let config = read_config(path)?;
        let key = matching_registry_key(&config, registry).unwrap_or_else(|| registry.to_owned());
        if let Some(helper) = configured_helper(&config, &key) {
            match helper_get(&helper, &key) {
                Ok(credentials) => return Ok(Some(credentials)),
                Err(error) => {
                    tracing::debug!(
                        helper,
                        registry = key,
                        error = %error,
                        "Docker credential helper lookup failed; checking inline auth"
                    );
                }
            }
        }

        let auth = config
            .get("auths")
            .and_then(Value::as_object)
            .and_then(|auths| {
                registry_aliases(registry)
                    .into_iter()
                    .find_map(|alias| auths.get(&alias))
            })
            .and_then(|entry| entry.get("auth"))
            .and_then(Value::as_str);
        let Some(auth) = auth else {
            return Ok(None);
        };
        let decoded = STANDARD
            .decode(auth)
            .context("Docker config contains invalid base64 credentials")?;
        let decoded =
            String::from_utf8(decoded).context("Docker config credentials are not UTF-8")?;
        let (username, secret) = decoded
            .split_once(':')
            .ok_or_else(|| anyhow!("Docker config credentials are malformed"))?;
        Ok(Some(Self {
            username: username.to_owned(),
            secret: secret.to_owned(),
        }))
    }

    pub fn store(registry: &str, username: &str, secret: &str) -> Result<()> {
        let path = docker_config_path()?;
        Self::store_at(&path, registry, username, secret)
    }

    pub fn store_at(path: &Path, registry: &str, username: &str, secret: &str) -> Result<()> {
        let mut config = read_config(path)?;
        let key = matching_registry_key(&config, registry).unwrap_or_else(|| registry.to_owned());

        if let Some(helper) = configured_helper(&config, &key) {
            helper_store(&helper, &key, username, secret)?;
            ensure_auth_entry(&mut config, &key, None)?;
        } else {
            let auth = STANDARD.encode(format!("{username}:{secret}"));
            ensure_auth_entry(&mut config, &key, Some(auth))?;
            eprintln!(
                "Warning: Docker has no credential helper configured; the token is stored base64-encoded in {}",
                path.display()
            );
        }
        write_config(path, &config)
    }

    pub fn erase(registry: &str) -> Result<()> {
        let path = docker_config_path()?;
        Self::erase_at(&path, registry)
    }

    pub fn erase_at(path: &Path, registry: &str) -> Result<()> {
        let mut config = read_config(path)?;
        let key = matching_registry_key(&config, registry).unwrap_or_else(|| registry.to_owned());
        if let Some(helper) = configured_helper(&config, &key) {
            helper_erase(&helper, &key)?;
        }
        if let Some(auths) = config.get_mut("auths").and_then(Value::as_object_mut) {
            for alias in registry_aliases(registry) {
                auths.remove(&alias);
            }
        }
        write_config(path, &config)
    }
}

fn docker_config_path() -> Result<PathBuf> {
    if let Some(directory) = std::env::var_os("DOCKER_CONFIG") {
        return Ok(PathBuf::from(directory).join("config.json"));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("HOME is unavailable and DOCKER_CONFIG is unset"))?;
    Ok(PathBuf::from(home).join(".docker/config.json"))
}

fn read_config(path: &Path) -> Result<Value> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Value::Object(Map::new())),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn write_config(path: &Path, config: &Value) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Docker config path has no parent"))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .context("failed to create a temporary Docker config")?;
    temporary
        .write_all(&serde_json::to_vec_pretty(config)?)
        .context("failed to write Docker config")?;
    temporary
        .write_all(b"\n")
        .context("failed to finish Docker config")?;
    temporary
        .as_file()
        .sync_all()
        .context("failed to sync Docker config")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("failed to secure Docker config permissions")?;
    }

    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

fn configured_helper(config: &Value, registry: &str) -> Option<String> {
    config
        .get("credHelpers")
        .and_then(Value::as_object)
        .and_then(|helpers| helpers.get(registry))
        .and_then(Value::as_str)
        .or_else(|| config.get("credsStore").and_then(Value::as_str))
        .filter(|helper| !helper.is_empty())
        .map(ToOwned::to_owned)
}

fn matching_registry_key(config: &Value, registry: &str) -> Option<String> {
    let aliases = registry_aliases(registry);
    config
        .get("credHelpers")
        .and_then(Value::as_object)
        .and_then(|helpers| {
            aliases
                .iter()
                .find(|alias| helpers.contains_key(alias.as_str()))
        })
        .or_else(|| {
            config
                .get("auths")
                .and_then(Value::as_object)
                .and_then(|auths| {
                    aliases
                        .iter()
                        .find(|alias| auths.contains_key(alias.as_str()))
                })
        })
        .cloned()
}

fn registry_aliases(registry: &str) -> Vec<String> {
    let registry = registry
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    vec![
        registry.to_owned(),
        format!("https://{registry}"),
        format!("http://{registry}"),
    ]
}

fn ensure_auth_entry(config: &mut Value, registry: &str, auth: Option<String>) -> Result<()> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| anyhow!("Docker config root must be a JSON object"))?;
    let auths = root
        .entry("auths")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow!("Docker config auths must be a JSON object"))?;
    let entry = auths
        .entry(registry)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow!("Docker auth entry must be a JSON object"))?;
    if let Some(auth) = auth {
        entry.insert("auth".to_owned(), Value::String(auth));
    } else {
        entry.remove("auth");
    }
    Ok(())
}

fn helper_get(helper: &str, registry: &str) -> Result<DockerCredentials> {
    let output = helper_command(helper, "get", format!("{registry}\n").as_bytes())?;
    let credentials: HelperCredentials =
        serde_json::from_slice(&output).context("credential helper returned invalid JSON")?;
    Ok(DockerCredentials {
        username: credentials.username,
        secret: credentials.secret,
    })
}

fn helper_store(helper: &str, registry: &str, username: &str, secret: &str) -> Result<()> {
    let payload = serde_json::to_vec(&HelperStore {
        server_url: registry,
        username,
        secret,
    })?;
    helper_command(helper, "store", &payload)?;
    Ok(())
}

fn helper_erase(helper: &str, registry: &str) -> Result<()> {
    match helper_command(helper, "erase", format!("{registry}\n").as_bytes()) {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().contains("not found") => Ok(()),
        Err(error) => Err(error),
    }
}

fn helper_command(helper: &str, action: &str, input: &[u8]) -> Result<Vec<u8>> {
    let program = format!("docker-credential-{helper}");
    let mut child = Command::new(&program)
        .arg(action)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start {program}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("credential helper stdin is unavailable"))?
        .write_all(input)
        .context("failed to write to credential helper")?;
    let output = child
        .wait_with_output()
        .context("credential helper failed to exit")?;
    if !output.status.success() {
        bail!(
            "{program} {action} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_registry_aliases() {
        let config = serde_json::json!({
            "auths": {
                "https://registry.example.com": {"auth": "abc"}
            }
        });
        assert_eq!(
            matching_registry_key(&config, "registry.example.com"),
            Some("https://registry.example.com".to_owned())
        );
    }
}
