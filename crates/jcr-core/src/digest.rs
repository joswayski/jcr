use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// An OCI content digest.
///
/// JCR v1 deliberately supports SHA-256 only. The type retains the algorithm
/// component so another algorithm can be introduced without changing database
/// keys or public interfaces.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest {
    algorithm: String,
    encoded: String,
}

impl Digest {
    pub const SHA256: &'static str = "sha256";

    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        let encoded = hex::encode(Sha256::digest(bytes.as_ref()));
        Self {
            algorithm: Self::SHA256.to_owned(),
            encoded,
        }
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    pub fn object_fragment(&self) -> String {
        format!("{}/{}/{}", self.algorithm, &self.encoded[..2], self.encoded)
    }

    pub fn verify(&self, bytes: impl AsRef<[u8]>) -> bool {
        self == &Self::sha256(bytes)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.algorithm, self.encoded)
    }
}

impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for Digest {
    type Error = DigestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl FromStr for Digest {
    type Err = DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (algorithm, encoded) = value.split_once(':').ok_or(DigestError::MissingSeparator)?;

        if algorithm != Self::SHA256 {
            return Err(DigestError::UnsupportedAlgorithm(algorithm.to_owned()));
        }

        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DigestError::InvalidSha256);
        }

        Ok(Self {
            algorithm: algorithm.to_owned(),
            encoded: encoded.to_owned(),
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DigestError {
    #[error("digest must contain an algorithm and encoded value separated by ':'")]
    MissingSeparator,
    #[error("unsupported digest algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    #[error("SHA-256 digest must contain exactly 64 lowercase hexadecimal characters")]
    InvalidSha256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_and_round_trips_sha256() {
        let digest = Digest::sha256(b"hello");
        assert_eq!(
            digest.to_string(),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(digest.to_string().parse::<Digest>().unwrap(), digest);
    }

    #[test]
    fn rejects_uppercase_and_unknown_algorithms() {
        assert!(matches!(
            "sha512:abcd".parse::<Digest>(),
            Err(DigestError::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .parse::<Digest>(),
            Err(DigestError::InvalidSha256)
        ));
    }
}
