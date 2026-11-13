//! The domain of `forewarn`: SBOM components, completeness rules, vulnerability matching and CRA reporting
//! deadlines. It performs no I/O and depends on no adapter.

pub mod completeness;
pub mod matching;
mod purl;
pub mod sbom;
mod version;
pub mod vulnerability;
