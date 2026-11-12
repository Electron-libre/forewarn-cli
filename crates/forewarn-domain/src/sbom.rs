//! An SBOM as the domain sees it: its spec version and the flat list of its components (`specs/sbom-reading.md`).

use std::fmt;

/// An SBOM read by an adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sbom {
    /// The version of the SBOM specification the document follows.
    pub spec_version: SpecVersion,
    /// Every component of the document, the nested ones included, in document order.
    pub components: Vec<Component>,
}

/// The version of a CycloneDX specification, `major.minor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpecVersion {
    major: u8,
    minor: u8,
}

impl SpecVersion {
    /// The minimum CycloneDX version BSI TR-03183-2 accepts.
    pub const BSI_MINIMUM: Self = Self::new(1, 6);

    /// The version `major.minor`.
    #[must_use]
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Whether the version is older than [`Self::BSI_MINIMUM`]: the SBOM is read, but flagged.
    #[must_use]
    pub fn is_below_bsi_minimum(self) -> bool {
        self < Self::BSI_MINIMUM
    }
}

impl fmt::Display for SpecVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A component of an SBOM, with the fields the CRA checks and the matching need. An absent field is `None` or empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    /// The package URL, as written in the SBOM.
    pub purl: Option<String>,
    /// The supplier organisation: its name, else a contact email or a URL.
    pub supplier: Option<String>,
    /// The manufacturer organisation (CycloneDX 1.6): its name, else a contact email or a URL.
    pub manufacturer: Option<String>,
    /// The authors: the legacy single `author` text, then the name, else the email, of each author of
    /// CycloneDX 1.6.
    pub authors: Vec<String>,
    pub publisher: Option<String>,
    /// Each license: an SPDX identifier, a license name, or an SPDX expression.
    pub licenses: Vec<String>,
    pub hashes: Vec<Hash>,
}

/// A hash of a component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hash {
    /// The algorithm, as written in the SBOM (`SHA-256`, or a value the specification does not list).
    pub algorithm: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::SpecVersion;

    #[test]
    fn displays_and_orders_versions() {
        assert_eq!(SpecVersion::new(1, 7).to_string(), "1.7");
        assert!(SpecVersion::new(1, 5) < SpecVersion::new(1, 6));
        assert!(SpecVersion::new(1, 10) > SpecVersion::new(1, 9));
    }
}
