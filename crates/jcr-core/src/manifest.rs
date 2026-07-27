use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{Digest, DigestError};

pub const OCI_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_IMAGE_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_IMAGE_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestKind {
    Manifest,
    Index,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorRelationship {
    Config,
    Layer,
    Manifest,
    Subject,
}

impl DescriptorRelationship {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Layer => "layer",
            Self::Manifest => "manifest",
            Self::Subject => "subject",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ManifestDocument {
    raw: Vec<u8>,
    digest: Digest,
    media_type: String,
    kind: ManifestKind,
    artifact_type: Option<String>,
    subject: Option<Descriptor>,
    descriptors: Vec<(DescriptorRelationship, usize, Descriptor)>,
}

impl ManifestDocument {
    pub fn parse(
        raw: impl Into<Vec<u8>>,
        supplied_media_type: Option<&str>,
    ) -> Result<Self, ManifestError> {
        let raw = raw.into();
        let value: Value = serde_json::from_slice(&raw)?;

        if value.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
            return Err(ManifestError::UnsupportedSchema);
        }

        let media_type = value
            .get("mediaType")
            .and_then(Value::as_str)
            .or_else(|| supplied_media_type.and_then(|value| value.split(';').next()))
            .ok_or(ManifestError::MissingMediaType)?
            .trim()
            .to_owned();

        let kind = match media_type.as_str() {
            OCI_IMAGE_MANIFEST | DOCKER_IMAGE_MANIFEST => ManifestKind::Manifest,
            OCI_IMAGE_INDEX | DOCKER_MANIFEST_LIST => ManifestKind::Index,
            _ if value.get("config").is_some() || value.get("layers").is_some() => {
                ManifestKind::Manifest
            }
            _ if value.get("manifests").is_some() => ManifestKind::Index,
            _ => return Err(ManifestError::UnsupportedMediaType(media_type)),
        };

        let artifact_type = value
            .get("artifactType")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let subject: Option<Descriptor> = value
            .get("subject")
            .map(|subject| serde_json::from_value(subject.clone()))
            .transpose()?;

        let mut descriptors = Vec::new();
        match kind {
            ManifestKind::Manifest => {
                if let Some(config) = value.get("config") {
                    descriptors.push((
                        DescriptorRelationship::Config,
                        0,
                        serde_json::from_value(config.clone())?,
                    ));
                }

                for (index, layer) in value
                    .get("layers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    descriptors.push((
                        DescriptorRelationship::Layer,
                        index,
                        serde_json::from_value(layer.clone())?,
                    ));
                }
            }
            ManifestKind::Index => {
                for (index, manifest) in value
                    .get("manifests")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    descriptors.push((
                        DescriptorRelationship::Manifest,
                        index,
                        serde_json::from_value(manifest.clone())?,
                    ));
                }
            }
        }

        if let Some(subject) = &subject {
            descriptors.push((DescriptorRelationship::Subject, 0, subject.clone()));
        }

        Ok(Self {
            digest: Digest::sha256(&raw),
            raw,
            media_type,
            kind,
            artifact_type,
            subject,
            descriptors,
        })
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn kind(&self) -> ManifestKind {
        self.kind
    }

    pub fn artifact_type(&self) -> Option<&str> {
        self.artifact_type.as_deref()
    }

    pub fn subject(&self) -> Option<&Descriptor> {
        self.subject.as_ref()
    }

    pub fn descriptors(
        &self,
    ) -> impl Iterator<Item = (DescriptorRelationship, usize, &Descriptor)> {
        self.descriptors
            .iter()
            .map(|(relationship, position, descriptor)| (*relationship, *position, descriptor))
    }
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("manifest must use schemaVersion 2")]
    UnsupportedSchema,
    #[error("manifest media type is missing")]
    MissingMediaType,
    #[error("manifest media type '{0}' is unsupported")]
    UnsupportedMediaType(String),
    #[error("manifest descriptor contains an invalid digest: {0}")]
    Digest(#[from] DigestError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_manifest_relationships() {
        let config = Digest::sha256(b"config");
        let layer = Digest::sha256(b"layer");
        let raw = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config,
                "size": 6
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer,
                "size": 5
            }]
        }))
        .unwrap();

        let manifest = ManifestDocument::parse(raw, None).unwrap();
        assert_eq!(manifest.kind(), ManifestKind::Manifest);
        assert_eq!(manifest.descriptors().count(), 2);
    }

    #[test]
    fn keeps_subject_as_a_generic_relationship() {
        let subject = Digest::sha256(b"subject");
        let raw = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST,
            "artifactType": "application/example",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": Digest::sha256(b"{}"),
                "size": 2
            },
            "layers": [],
            "subject": {
                "mediaType": OCI_IMAGE_MANIFEST,
                "digest": subject,
                "size": 100
            }
        }))
        .unwrap();

        let manifest = ManifestDocument::parse(raw, None).unwrap();
        assert_eq!(
            manifest
                .descriptors()
                .filter(|(relationship, _, _)| { *relationship == DescriptorRelationship::Subject })
                .count(),
            1
        );
    }
}
