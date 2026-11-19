//! The domain of `forewarn`: SBOM components, completeness rules, vulnerability matching, the flagging of actively
//! exploited vulnerabilities, the VEX verdicts of the vendor, CRA reporting deadlines and the draft of the early warning. It performs no I/O and
//! depends on no adapter.

pub mod completeness;
mod cve;
pub mod date;
pub mod deadlines;
mod debian;
pub mod early_warning;
pub mod exploited;
pub mod matching;
pub mod purl;
pub mod sbom;
mod version;
pub mod vex;
pub mod vulnerability;

pub use cve::is_cve;
