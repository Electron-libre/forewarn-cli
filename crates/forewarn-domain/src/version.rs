//! The version orderings a range is compared by (`specs/vulnerability-matching.md`, VMT-9, VMT-23).

use std::cmp::Ordering;

use crate::vulnerability::RangeKind;

/// How the versions of a range are read and ordered.
pub(crate) trait VersionOrder {
    /// A version read in this ordering.
    type Key;

    /// The version read in this ordering, or `None` when it does not follow it.
    fn parse(version: &str) -> Option<Self::Key>;

    /// The order of two versions read in this ordering.
    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering;
}

/// The orderings matching knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    /// Semantic Versioning 2.0, a leading `v` ignored.
    Semver,
}

impl Scheme {
    /// The ordering a range of this kind naming a package of this ecosystem is compared by, or `None` when matching
    /// does not compare it (VMT-9, VMT-23).
    pub(crate) fn of(kind: RangeKind, ecosystem: &str) -> Option<Self> {
        match (kind, ecosystem) {
            (RangeKind::Semver, _) | (RangeKind::Ecosystem, "crates.io" | "npm" | "Go") => {
                Some(Self::Semver)
            }
            _ => None,
        }
    }
}

/// Semantic Versioning 2.0, build metadata ignored, a leading `v` ignored.
pub(crate) struct Semver;

impl VersionOrder for Semver {
    type Key = semver::Version;

    fn parse(version: &str) -> Option<Self::Key> {
        let version = version.trim();
        let version = version.strip_prefix('v').unwrap_or(version);
        semver::Version::parse(version).ok()
    }

    fn compare(a: &Self::Key, b: &Self::Key) -> Ordering {
        a.cmp_precedence(b)
    }
}
