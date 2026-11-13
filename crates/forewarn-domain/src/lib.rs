//! The domain of `forewarn`: SBOM components, completeness rules, vulnerability matching, the flagging of actively
//! exploited vulnerabilities and CRA reporting deadlines. It performs no I/O and depends on no adapter.

pub mod completeness;
mod cve;
pub mod date;
pub mod exploited;
pub mod matching;
mod purl;
pub mod sbom;
mod version;
pub mod vulnerability;
