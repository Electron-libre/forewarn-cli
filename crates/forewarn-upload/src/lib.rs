//! The upload adapter of `forewarn` (ADR 0018, `specs/sbom-upload.md`).

mod endpoint;
mod token;

pub use endpoint::{Endpoint, EndpointProblem, InvalidEndpoint};
pub use token::{InvalidToken, Token};
mod send;
pub use forewarn_api::MAX_SBOM_BYTES;
pub use send::{Stored, UploadError, check_upload, upload};
