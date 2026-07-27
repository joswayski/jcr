use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use flate2::{Compression, GzBuilder, read::GzDecoder};
use jcr_core::{DescriptorRelationship, Digest, ManifestDocument, manifest::OCI_IMAGE_MANIFEST};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct BlobFile {
    pub digest: Digest,
    pub size: u64,
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ManifestObject {
    pub digest: Digest,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

pub struct PreparedImage {
    pub blobs: Vec<BlobFile>,
    pub manifests: Vec<ManifestObject>,
    pub root_digest: Digest,
    _workspace: TempDir,
}

impl PreparedImage {
    /// Constructs a prepared image from verified local objects.
    ///
    /// Integration tooling can use this when it generates OCI objects
    /// directly instead of reading a Docker or OCI archive.
    pub fn from_parts(
        blobs: Vec<BlobFile>,
        manifests: Vec<ManifestObject>,
        root_digest: Digest,
        workspace: TempDir,
    ) -> Self {
        Self {
            blobs,
            manifests,
            root_digest,
            _workspace: workspace,
        }
    }
}

pub async fn prepare_oci_archive(path: PathBuf) -> Result<PreparedImage> {
    tokio::task::spawn_blocking(move || prepare_oci_archive_sync(&path))
        .await
        .context("OCI archive preparation task failed")?
}

pub async fn prepare_docker_image(reference: &str) -> Result<PreparedImage> {
    let reference = reference.to_owned();
    tokio::task::spawn_blocking(move || prepare_docker_image_sync(&reference))
        .await
        .context("Docker image preparation task failed")?
}

fn prepare_oci_archive_sync(path: &Path) -> Result<PreparedImage> {
    let workspace = tempfile::tempdir().context("failed to create OCI workspace")?;
    let layout = workspace.path().join("layout");
    fs::create_dir_all(&layout)?;
    unpack_archive(path, &layout)?;

    let layout_marker = fs::read_to_string(layout.join("oci-layout"))
        .context("archive does not contain oci-layout")?;
    let marker: serde_json::Value =
        serde_json::from_str(&layout_marker).context("oci-layout is invalid JSON")?;
    if marker
        .get("imageLayoutVersion")
        .and_then(serde_json::Value::as_str)
        != Some("1.0.0")
    {
        bail!("OCI archive uses an unsupported image layout version");
    }

    let index_bytes =
        fs::read(layout.join("index.json")).context("archive does not contain index.json")?;
    let index = ManifestDocument::parse(
        index_bytes.clone(),
        Some("application/vnd.oci.image.index.v1+json"),
    )
    .context("OCI archive index is invalid")?;
    let roots = index
        .descriptors()
        .filter(|(relationship, _, _)| *relationship == DescriptorRelationship::Manifest)
        .map(|(_, _, descriptor)| descriptor.clone())
        .collect::<Vec<_>>();
    if roots.is_empty() {
        bail!("OCI archive index does not reference an image");
    }

    let mut context = GraphContext {
        layout: &layout,
        blobs: HashMap::new(),
        manifests: Vec::new(),
        visited_manifests: HashSet::new(),
    };
    let root = if roots.len() == 1 {
        let descriptor = &roots[0];
        let bytes = read_descriptor(&layout, &descriptor.digest, descriptor.size)?;
        visit_manifest(&mut context, bytes, Some(&descriptor.media_type))?
    } else {
        visit_manifest(
            &mut context,
            index_bytes,
            Some("application/vnd.oci.image.index.v1+json"),
        )?
    };

    Ok(PreparedImage {
        blobs: context.blobs.into_values().collect(),
        manifests: context.manifests,
        root_digest: root,
        _workspace: workspace,
    })
}

fn prepare_docker_image_sync(reference: &str) -> Result<PreparedImage> {
    let workspace = tempfile::tempdir().context("failed to create Docker workspace")?;
    let archive_path = workspace.path().join("docker-save.tar");
    let status = Command::new("docker")
        .args(["image", "save", "--output"])
        .arg(&archive_path)
        .arg(reference)
        .status()
        .context("failed to run Docker; is the Docker Engine available?")?;
    if !status.success() {
        bail!("docker image save failed for {reference}");
    }

    let extracted = workspace.path().join("docker");
    fs::create_dir_all(&extracted)?;
    unpack_archive(&archive_path, &extracted)?;
    let manifest_bytes = fs::read(extracted.join("manifest.json"))
        .context("Docker archive does not contain manifest.json")?;
    let entries: Vec<DockerSaveManifest> = serde_json::from_slice(&manifest_bytes)
        .context("Docker archive manifest.json is invalid")?;
    let entry = entries
        .iter()
        .find(|entry| {
            entry
                .repo_tags
                .as_ref()
                .is_some_and(|tags| tags.iter().any(|tag| tag == reference))
        })
        .or_else(|| entries.first())
        .ok_or_else(|| anyhow!("Docker archive contains no images"))?;

    let config_path = safe_join(&extracted, &entry.config)?;
    let (config_digest, config_size) = hash_file(&config_path)?;
    let generated = workspace.path().join("generated");
    fs::create_dir_all(&generated)?;

    let mut layers = Vec::new();
    let mut blobs = HashMap::new();
    blobs.insert(
        config_digest.clone(),
        BlobFile {
            digest: config_digest.clone(),
            size: config_size,
            path: config_path,
        },
    );
    for (index, layer) in entry.layers.iter().enumerate() {
        let source = safe_join(&extracted, layer)?;
        let destination = generated.join(format!("{index:06}.tar.gz"));
        gzip_deterministic(&source, &destination)?;
        let (digest, size) = hash_file(&destination)?;
        layers.push(serde_json::json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": digest,
            "size": size
        }));
        blobs.entry(digest.clone()).or_insert(BlobFile {
            digest,
            size,
            path: destination,
        });
    }

    let root_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_size
        },
        "layers": layers
    }))?;
    let root_digest = Digest::sha256(&root_bytes);
    Ok(PreparedImage {
        blobs: blobs.into_values().collect(),
        manifests: vec![ManifestObject {
            digest: root_digest.clone(),
            media_type: OCI_IMAGE_MANIFEST.to_owned(),
            bytes: root_bytes,
        }],
        root_digest,
        _workspace: workspace,
    })
}

struct GraphContext<'a> {
    layout: &'a Path,
    blobs: HashMap<Digest, BlobFile>,
    manifests: Vec<ManifestObject>,
    visited_manifests: HashSet<Digest>,
}

fn visit_manifest(
    context: &mut GraphContext<'_>,
    bytes: Vec<u8>,
    supplied_media_type: Option<&str>,
) -> Result<Digest> {
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("manifest exceeds the 8 MiB client limit");
    }
    let manifest =
        ManifestDocument::parse(bytes, supplied_media_type).context("OCI manifest is invalid")?;
    let digest = manifest.digest().clone();
    if context.visited_manifests.contains(&digest) {
        return Ok(digest);
    }

    for (relationship, _, descriptor) in manifest.descriptors() {
        match relationship {
            DescriptorRelationship::Config | DescriptorRelationship::Layer => {
                let path = descriptor_path(context.layout, &descriptor.digest);
                verify_file(&path, &descriptor.digest, descriptor.size)?;
                context
                    .blobs
                    .entry(descriptor.digest.clone())
                    .or_insert(BlobFile {
                        digest: descriptor.digest.clone(),
                        size: descriptor.size as u64,
                        path,
                    });
            }
            DescriptorRelationship::Manifest => {
                let child = read_descriptor(context.layout, &descriptor.digest, descriptor.size)?;
                visit_manifest(context, child, Some(&descriptor.media_type))?;
            }
            DescriptorRelationship::Subject => {
                // Subjects are references, not dependencies. If the subject is
                // already present remotely, JCR retains the relationship.
            }
        }
    }
    context.visited_manifests.insert(digest.clone());
    context.manifests.push(ManifestObject {
        digest: digest.clone(),
        media_type: manifest.media_type().to_owned(),
        bytes: manifest.raw().to_vec(),
    });
    Ok(digest)
}

fn read_descriptor(layout: &Path, digest: &Digest, size: i64) -> Result<Vec<u8>> {
    if size < 0 || size as u64 > MAX_MANIFEST_BYTES {
        bail!("manifest descriptor {digest} has an invalid size");
    }
    let path = descriptor_path(layout, digest);
    verify_file(&path, digest, size)?;
    fs::read(&path).with_context(|| format!("failed to read {}", path.display()))
}

fn descriptor_path(layout: &Path, digest: &Digest) -> PathBuf {
    layout
        .join("blobs")
        .join(digest.algorithm())
        .join(digest.encoded())
}

fn verify_file(path: &Path, expected: &Digest, expected_size: i64) -> Result<()> {
    if expected_size < 0 {
        bail!("descriptor {expected} has a negative size");
    }
    let (actual, size) = hash_file(path)?;
    if &actual != expected || size != expected_size as u64 {
        bail!(
            "{} does not match descriptor {} (expected {} bytes, found {} and {} bytes)",
            path.display(),
            expected,
            expected_size,
            actual,
            size
        );
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(Digest, u64)> {
    let mut input =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let size = std::io::copy(&mut input, &mut HashWriter(&mut hasher))
        .with_context(|| format!("failed to hash {}", path.display()))?;
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()))
        .parse()
        .expect("SHA-256 output is a valid OCI digest");
    Ok((digest, size))
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn gzip_deterministic(source: &Path, destination: &Path) -> Result<()> {
    let mut input =
        File::open(source).with_context(|| format!("failed to open {}", source.display()))?;
    let output = File::create(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(output, Compression::default());
    std::io::copy(&mut input, &mut encoder)
        .with_context(|| format!("failed to compress {}", source.display()))?;
    encoder.finish()?.sync_all()?;
    Ok(())
}

fn unpack_archive(path: &Path, destination: &Path) -> Result<()> {
    let mut input =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut magic = [0_u8; 2];
    let read = input.read(&mut magic)?;
    input.seek(SeekFrom::Start(0))?;
    let reader: Box<dyn Read> = if read == 2 && magic == [0x1f, 0x8b] {
        Box::new(GzDecoder::new(input))
    } else {
        Box::new(input)
    };
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries().context("failed to read archive")? {
        let mut entry = entry.context("failed to read archive entry")?;
        if !entry
            .unpack_in(destination)
            .context("failed to unpack archive entry")?
        {
            bail!("archive contains a path outside its root");
        }
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("archive contains an unsafe path: {}", relative.display());
    }
    Ok(root.join(relative))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerSaveManifest {
    config: String,
    repo_tags: Option<Vec<String>>,
    layers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_gzip_has_stable_digest() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("layer.tar");
        fs::write(&source, b"example layer").unwrap();
        let first = directory.path().join("first.gz");
        let second = directory.path().join("second.gz");
        gzip_deterministic(&source, &first).unwrap();
        gzip_deterministic(&source, &second).unwrap();
        assert_eq!(hash_file(&first).unwrap(), hash_file(&second).unwrap());
    }

    #[test]
    fn rejects_unsafe_archive_paths() {
        assert!(safe_join(Path::new("/tmp/root"), "../secret").is_err());
    }
}
