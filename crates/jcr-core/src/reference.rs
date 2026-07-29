use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Digest;

/// A fully-qualified OCI image reference (`registry/namespace/name:tag`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub reference: String,
}

impl ImageReference {
    pub fn scope_name(&self) -> &str {
        &self.repository
    }

    pub fn is_digest(&self) -> bool {
        self.reference.parse::<Digest>().is_ok()
    }

    pub fn scheme(&self) -> &'static str {
        if self.registry == "localhost"
            || self.registry.starts_with("localhost:")
            || self.registry.starts_with("127.0.0.1:")
            || self.registry.starts_with("[::1]:")
        {
            "http"
        } else {
            "https"
        }
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_digest() {
            write!(
                formatter,
                "{}/{}@{}",
                self.registry, self.repository, self.reference
            )
        } else {
            write!(
                formatter,
                "{}/{}:{}",
                self.registry, self.repository, self.reference
            )
        }
    }
}

impl FromStr for ImageReference {
    type Err = ReferenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (registry, remainder) = value
            .split_once('/')
            .ok_or(ReferenceError::MissingRegistry)?;

        if registry.is_empty() || !registry.contains(['.', ':']) && registry != "localhost" {
            return Err(ReferenceError::InvalidRegistry);
        }

        let (repository, reference) = if let Some((repository, digest)) = remainder.rsplit_once('@')
        {
            digest
                .parse::<Digest>()
                .map_err(|_| ReferenceError::InvalidDigest)?;
            (repository, digest)
        } else {
            let final_slash = remainder.rfind('/').map_or(0, |index| index + 1);
            let tail = &remainder[final_slash..];
            if let Some(colon) = tail.rfind(':') {
                let split = final_slash + colon;
                (&remainder[..split], &remainder[split + 1..])
            } else {
                (remainder, "latest")
            }
        };

        if repository.is_empty()
            || repository.starts_with('/')
            || repository.ends_with('/')
            || repository.split('/').any(|piece| {
                piece.is_empty()
                    || !piece.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(ReferenceError::InvalidRepository);
        }

        if reference.is_empty() {
            return Err(ReferenceError::InvalidReference);
        }

        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            reference: reference.to_owned(),
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReferenceError {
    #[error("reference must include a registry hostname")]
    MissingRegistry,
    #[error("registry hostname is invalid")]
    InvalidRegistry,
    #[error("repository name is invalid")]
    InvalidRepository,
    #[error("tag or digest is invalid")]
    InvalidReference,
    #[error("digest reference is invalid")]
    InvalidDigest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tag_and_default_tag() {
        let tagged: ImageReference = "registry.example.com/alice/app:v1".parse().unwrap();
        assert_eq!(tagged.repository, "alice/app");
        assert_eq!(tagged.reference, "v1");

        let latest: ImageReference = "localhost:5000/alice/app".parse().unwrap();
        assert_eq!(latest.reference, "latest");
        assert_eq!(latest.scheme(), "http");
    }

    #[test]
    fn parses_digest_reference() {
        let value = format!(
            "registry.example.com/alice/app@{}",
            Digest::sha256(b"manifest")
        );
        let reference: ImageReference = value.parse().unwrap();
        assert!(reference.is_digest());
    }
}
