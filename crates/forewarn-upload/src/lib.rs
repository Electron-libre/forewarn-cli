//! The upload adapter of `forewarn` (ADR 0018, `specs/sbom-upload.md`).

mod endpoint;
mod token;

pub use endpoint::{Endpoint, EndpointProblem, InvalidEndpoint};
pub use token::{InvalidToken, Token};
mod send;
pub use send::{MAX_SBOM_BYTES, Stored, UploadError, upload};
