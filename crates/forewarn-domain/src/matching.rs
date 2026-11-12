//! The matching of the components of an SBOM against known vulnerabilities (`specs/vulnerability-matching.md`).

use crate::purl::PackageUrl;
use crate::sbom::Component;

/// How a package URL type maps to an OSV ecosystem and how its name is built (VMT-4).
#[derive(Clone, Copy)]
enum NameForm {
    /// The name alone, any namespace left out.
    Name,
    /// `namespace/name`, or the name without a namespace.
    Slash,
    /// `namespace:name`, or the name without a namespace.
    Colon,
}

/// The package URL types matching knows: type, OSV ecosystem, name form.
const ECOSYSTEMS: [(&str, &str, NameForm); 8] = [
    ("cargo", "crates.io", NameForm::Name),
    ("npm", "npm", NameForm::Slash),
    ("pypi", "PyPI", NameForm::Name),
    ("maven", "Maven", NameForm::Colon),
    ("golang", "Go", NameForm::Slash),
    ("nuget", "NuGet", NameForm::Name),
    ("gem", "RubyGems", NameForm::Name),
    ("composer", "Packagist", NameForm::Slash),
];

/// Why a component cannot be matched at all (VMT-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentReason {
    /// The component has no package URL.
    NoPackageUrl,
    /// The package URL does not follow the specification.
    InvalidPackageUrl,
    /// The package URL type maps to no OSV ecosystem matching knows.
    UnknownEcosystem,
    /// Neither the component nor its package URL has a version.
    NoVersion,
}

/// The package a component is matched under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentPackage {
    /// The OSV ecosystem.
    pub ecosystem: &'static str,
    /// The name in that ecosystem.
    pub name: String,
    /// The component's version, else the version of its package URL.
    pub version: String,
}

impl ComponentPackage {
    /// The package of a component, or why it cannot be matched.
    ///
    /// # Errors
    ///
    /// The [`ComponentReason`] that keeps the component from being matched.
    pub fn of(component: &Component) -> Result<Self, ComponentReason> {
        let purl = component
            .purl
            .as_deref()
            .filter(|purl| !purl.trim().is_empty())
            .ok_or(ComponentReason::NoPackageUrl)?;
        let purl =
            PackageUrl::parse(purl.trim()).map_err(|_| ComponentReason::InvalidPackageUrl)?;
        let (_, ecosystem, form) = ECOSYSTEMS
            .iter()
            .find(|(purl_type, _, _)| *purl_type == purl.purl_type)
            .ok_or(ComponentReason::UnknownEcosystem)?;
        let version = [component.version.as_deref(), purl.version.as_deref()]
            .into_iter()
            .flatten()
            .map(str::trim)
            .find(|version| !version.is_empty())
            .ok_or(ComponentReason::NoVersion)?
            .to_owned();
        let name = match (form, purl.namespace.is_empty()) {
            (NameForm::Name, _) | (_, true) => purl.name,
            (NameForm::Slash, false) => format!("{}/{}", purl.namespace, purl.name),
            (NameForm::Colon, false) => format!("{}:{}", purl.namespace, purl.name),
        };
        Ok(Self {
            ecosystem,
            name,
            version,
        })
    }
}

/// Whether two package names of an ecosystem are the same: exactly equal, or equal once normalized under `PyPI`
/// (VMT-6).
#[must_use]
pub fn same_name(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem == "PyPI" {
        normalize_pypi(a) == normalize_pypi(b)
    } else {
        a == b
    }
}

/// Lower case, each run of `-`, `_`, `.` as one `-` (PEP 503).
fn normalize_pypi(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut in_separator = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_separator {
                normalized.push('-');
            }
            in_separator = true;
        } else {
            normalized.extend(c.to_lowercase());
            in_separator = false;
        }
    }
    normalized
}
