//! The CycloneDX adapter of `rollcall`: reads an SBOM produced by an existing tool into the types of the domain.

use std::fmt;
use std::io::Read;

use cyclonedx_bom::models::bom::{Bom, SpecVersion as CdxSpecVersion};
use cyclonedx_bom::models::component::Component as CdxComponent;
use cyclonedx_bom::models::license::{LicenseChoice, LicenseIdentifier};
use rollcall_domain::sbom::{Component, Hash, Sbom, SpecVersion};
use serde_json::Value;

/// Why an input is not a readable CycloneDX JSON SBOM (`specs/sbom-reading.md`, SBR-7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The input is not JSON; the parser's reason.
    NotJson(String),
    /// `bomFormat` is absent, or holds this other value (as JSON).
    NotCycloneDx(Option<String>),
    /// `specVersion` is absent or is not a string.
    MissingSpecVersion,
    /// `specVersion` names a version this reader does not parse.
    UnsupportedSpecVersion(String),
    /// The document does not match its spec version; the parser's reason.
    Invalid(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson(reason) => write!(f, "not JSON: {reason}"),
            Self::NotCycloneDx(None) => write!(f, "not a CycloneDX SBOM: no `bomFormat`"),
            Self::NotCycloneDx(Some(format)) => {
                write!(f, "not a CycloneDX SBOM: `bomFormat` is {format}")
            }
            Self::MissingSpecVersion => write!(f, "missing spec version"),
            Self::UnsupportedSpecVersion(version) => {
                write!(
                    f,
                    "unsupported spec version {version:?}: 1.3 to 1.7 are read"
                )
            }
            Self::Invalid(reason) => write!(f, "invalid SBOM: {reason}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Reads a CycloneDX JSON SBOM: its spec version and its components, the nested ones flattened in document order.
///
/// # Errors
///
/// A [`ReadError`] naming why the input is not a readable CycloneDX JSON SBOM, the first that applies in the order
/// of its variants.
pub fn read_json(reader: impl Read) -> Result<Sbom, ReadError> {
    let document: Value =
        serde_json::from_reader(reader).map_err(|e| ReadError::NotJson(e.to_string()))?;
    match document.get("bomFormat") {
        Some(Value::String(format)) if format == "CycloneDX" => {}
        other => return Err(ReadError::NotCycloneDx(other.map(Value::to_string))),
    }
    let text = document
        .get("specVersion")
        .and_then(Value::as_str)
        .ok_or(ReadError::MissingSpecVersion)?;
    let (cdx_version, spec_version) = spec_version(text)?;
    let bom = Bom::parse_json_value_with_version(document, cdx_version)
        .map_err(|e| ReadError::Invalid(e.to_string()))?;
    let mut components = Vec::new();
    if let Some(top) = &bom.components {
        flatten(&top.0, &mut components);
    }
    Ok(Sbom {
        spec_version,
        components,
    })
}

/// The versions this reader parses: those of `cyclonedx-bom`, named here so that a new one is a decision.
fn spec_version(text: &str) -> Result<(CdxSpecVersion, SpecVersion), ReadError> {
    let (cdx, minor) = match text {
        "1.3" => (CdxSpecVersion::V1_3, 3),
        "1.4" => (CdxSpecVersion::V1_4, 4),
        "1.5" => (CdxSpecVersion::V1_5, 5),
        "1.6" => (CdxSpecVersion::V1_6, 6),
        "1.7" => (CdxSpecVersion::V1_7, 7),
        _ => return Err(ReadError::UnsupportedSpecVersion(text.to_owned())),
    };
    Ok((cdx, SpecVersion::new(1, minor)))
}

/// Pushes each component, then its nested ones, depth first.
fn flatten(components: &[CdxComponent], into: &mut Vec<Component>) {
    for component in components {
        into.push(to_domain(component));
        if let Some(nested) = &component.components {
            flatten(&nested.0, into);
        }
    }
}

fn to_domain(component: &CdxComponent) -> Component {
    Component {
        name: component.name.to_string(),
        version: component.version.as_ref().map(ToString::to_string),
        purl: component.purl.as_ref().map(ToString::to_string),
        supplier: component
            .supplier
            .as_ref()
            .and_then(|s| s.name.as_ref())
            .map(ToString::to_string),
        manufacturer: component
            .manufacturer
            .as_ref()
            .and_then(|m| m.name.as_ref())
            .map(ToString::to_string),
        authors: component
            .author
            .iter()
            .chain(
                component
                    .authors
                    .iter()
                    .flatten()
                    .filter_map(|contact| contact.name.as_ref()),
            )
            .map(ToString::to_string)
            .collect(),
        publisher: component.publisher.as_ref().map(ToString::to_string),
        licenses: component
            .licenses
            .iter()
            .flat_map(|l| &l.0)
            .map(|choice| match choice {
                LicenseChoice::License(license) => match &license.license_identifier {
                    LicenseIdentifier::SpdxId(id) => id.to_string(),
                    LicenseIdentifier::Name(name) => name.to_string(),
                },
                LicenseChoice::Expression(expression) => expression.to_string(),
            })
            .collect(),
        hashes: component
            .hashes
            .iter()
            .flat_map(|h| &h.0)
            .map(|hash| Hash {
                algorithm: hash.alg.to_string(),
                value: hash.content.0.clone(),
            })
            .collect(),
    }
}
