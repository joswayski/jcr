//! Protocol and domain primitives shared by the JCR server and client.

pub mod auth;
pub mod digest;
pub mod manifest;
pub mod reference;
pub mod storage;

pub use auth::{AccessAction, RepositoryScope};
pub use digest::{Digest, DigestError};
pub use manifest::{
    Descriptor, DescriptorRelationship, ManifestDocument, ManifestError, ManifestKind,
};
pub use reference::{ImageReference, ReferenceError};
pub use storage::{BlobStore, BlobStream, CompletedPart, StorageError, StorageUpload};
