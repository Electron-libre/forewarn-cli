//! The completeness check: which of the fields the CRA expects each component of an SBOM lacks
//! (`specs/sbom-completeness.md`).

use crate::sbom::{Component, Hash};

/// A field of a component the completeness check looks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Field {
    /// The organisation that supplies the component: its supplier, manufacturer, an author or its publisher.
    Supplier,
    /// A license, other than `NOASSERTION` in any case.
    License,
    /// A hash with a value and an algorithm of the CycloneDX enumeration.
    Hash,
}

/// The fields the check looks for, in the order a report lists them. BSI TR-03183-2 requires more: the list grows
/// with the spec.
pub const CHECKED_FIELDS: [Field; 3] = [Field::Supplier, Field::License, Field::Hash];

/// The hash algorithms of the CycloneDX 1.7 enumeration, compared without regard to case.
const HASH_ALGORITHMS: [&str; 14] = [
    "MD5",
    "SHA-1",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "BLAKE2b-256",
    "BLAKE2b-384",
    "BLAKE2b-512",
    "BLAKE3",
    "Streebog-256",
    "Streebog-512",
];

impl Field {
    /// Whether the component has this field.
    #[must_use]
    pub fn is_present_in(self, component: &Component) -> bool {
        match self {
            Self::Supplier => [
                &component.supplier,
                &component.manufacturer,
                &component.publisher,
            ]
            .into_iter()
            .flatten()
            .chain(&component.authors)
            .any(|value| is_filled(value)),
            Self::License => component.licenses.iter().any(|license| {
                is_filled(license) && !license.trim().eq_ignore_ascii_case("NOASSERTION")
            }),
            Self::Hash => component.hashes.iter().any(is_usable_hash),
        }
    }
}

fn is_filled(value: &str) -> bool {
    !value.trim().is_empty()
}

fn is_usable_hash(hash: &Hash) -> bool {
    let algorithm = hash.algorithm.trim();
    is_filled(&hash.value)
        && HASH_ALGORITHMS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(algorithm))
}

/// A component that lacks at least one checked field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompleteComponent {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    /// The checked fields it lacks, in the order of [`CHECKED_FIELDS`].
    pub missing: Vec<Field>,
}

/// A component the check leaves out: a file (SBR-15), such as a manifest a tool read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotCheckedComponent {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
}

/// The result of the check: the incomplete components and those not checked, in the order of the SBOM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompletenessReport {
    checked: usize,
    incomplete: Vec<IncompleteComponent>,
    not_checked: Vec<NotCheckedComponent>,
}

impl CompletenessReport {
    /// How many components were checked, those not checked left out.
    #[must_use]
    pub fn checked(&self) -> usize {
        self.checked
    }

    /// The components that lack at least one checked field, in the order of the SBOM.
    #[must_use]
    pub fn incomplete(&self) -> &[IncompleteComponent] {
        &self.incomplete
    }

    /// The components left out of the check, the files, in the order of the SBOM.
    #[must_use]
    pub fn not_checked(&self) -> &[NotCheckedComponent] {
        &self.not_checked
    }

    /// Whether no checked component lacks a checked field (an SBOM with no component is complete).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty()
    }
}

/// Checks each component but the files for the fields of [`CHECKED_FIELDS`], and returns the files apart
/// (`specs/sbom-completeness.md`, SBC-8).
#[must_use]
pub fn check(components: &[Component]) -> CompletenessReport {
    let mut report = CompletenessReport::default();
    for component in components {
        if component.file {
            report.not_checked.push(NotCheckedComponent {
                name: component.name.clone(),
                version: component.version.clone(),
                purl: component.purl.clone(),
            });
            continue;
        }
        report.checked += 1;
        let missing: Vec<Field> = CHECKED_FIELDS
            .into_iter()
            .filter(|field| !field.is_present_in(component))
            .collect();
        if !missing.is_empty() {
            report.incomplete.push(IncompleteComponent {
                name: component.name.clone(),
                version: component.version.clone(),
                purl: component.purl.clone(),
                missing,
            });
        }
    }
    report
}
