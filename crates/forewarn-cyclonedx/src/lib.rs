//! The CycloneDX adapter of `forewarn`: reads an SBOM produced by an existing tool into the types of the domain.

use std::collections::HashSet;
use std::fmt;
use std::io::Read;

use cyclonedx_bom::models::bom::{Bom, SpecVersion as CdxSpecVersion};
use cyclonedx_bom::models::component::Component as CdxComponent;
use cyclonedx_bom::models::license::{LicenseChoice, LicenseIdentifier};
use cyclonedx_bom::models::metadata::Metadata;
use cyclonedx_bom::models::organization::{OrganizationalContact, OrganizationalEntity};
use forewarn_domain::sbom::{Component, Hash, Product, Sbom, SpecVersion};
use serde_json::Value;

/// Why an input is not a readable CycloneDX JSON SBOM (`specs/sbom-reading.md`, SBR-7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The input cannot be read; the system's reason.
    Io(String),
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
            Self::Io(reason) => write!(f, "cannot read the input: {reason}"),
            Self::NotJson(reason) => write!(f, "not JSON: {reason}"),
            Self::NotCycloneDx(None) => write!(f, "not a CycloneDX SBOM: no `bomFormat`"),
            Self::NotCycloneDx(Some(format)) => {
                write!(f, "not a CycloneDX SBOM: `bomFormat` is {format}")
            }
            Self::MissingSpecVersion => write!(f, "missing spec version"),
            Self::UnsupportedSpecVersion(version) => {
                let (first, last) = (READ_VERSIONS[0].1, READ_VERSIONS[READ_VERSIONS.len() - 1].1);
                write!(
                    f,
                    "unsupported spec version {version:?}: {first} to {last} are read"
                )
            }
            Self::Invalid(reason) => write!(f, "invalid SBOM: {reason}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Reads a CycloneDX JSON SBOM: its spec version, the product it describes and its components, the nested ones
/// flattened in document order, then those nested in the product, a `bom-ref` already read and a target of the
/// product skipped.
///
/// # Errors
///
/// A [`ReadError`] naming why the input is not a readable CycloneDX JSON SBOM, the first that applies in the order
/// of its variants.
pub fn read_json(mut reader: impl Read) -> Result<Sbom, ReadError> {
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| ReadError::Io(e.to_string()))?;
    let json = bytes.strip_prefix(UTF8_BOM).unwrap_or(&bytes);
    let document: Value =
        serde_json::from_slice(json).map_err(|e| ReadError::NotJson(e.to_string()))?;
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
    let mut read_refs = HashSet::new();
    if let Some(top) = &bom.components {
        flatten(&top.0, &mut components, &mut read_refs, Keep::All);
    }
    let in_product = bom.metadata.as_ref().and_then(|m| m.component.as_ref());
    if let Some(nested) = in_product.and_then(|product| product.components.as_ref()) {
        let product_purl = in_product
            .and_then(|product| product.purl.as_ref())
            .map(ToString::to_string);
        let keep = Keep::NewAndNotTargetOf(product_purl.as_deref().map(purl_base));
        flatten(&nested.0, &mut components, &mut read_refs, keep);
    }
    Ok(Sbom {
        spec_version,
        product: bom.metadata.as_ref().and_then(product),
        components,
    })
}

/// The byte-order mark some Windows tools write before UTF-8 JSON.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// The versions this reader parses, oldest first: those of `cyclonedx-bom`, listed here so that a new one is a
/// decision.
const READ_VERSIONS: [(CdxSpecVersion, SpecVersion); 5] = [
    (CdxSpecVersion::V1_3, SpecVersion::new(1, 3)),
    (CdxSpecVersion::V1_4, SpecVersion::new(1, 4)),
    (CdxSpecVersion::V1_5, SpecVersion::new(1, 5)),
    (CdxSpecVersion::V1_6, SpecVersion::new(1, 6)),
    (CdxSpecVersion::V1_7, SpecVersion::new(1, 7)),
];

fn spec_version(text: &str) -> Result<(CdxSpecVersion, SpecVersion), ReadError> {
    READ_VERSIONS
        .into_iter()
        .find(|(cdx, _)| cdx.to_string() == text)
        .ok_or_else(|| ReadError::UnsupportedSpecVersion(text.to_owned()))
}

/// The product of `metadata.component` (SBR-12): its own manufacturer, else the deprecated `metadata.manufacture`
/// (`metadata.manufacturer` made the SBOM, not the product); the supplier of the metadata before that of the component;
/// each by its name only, a contact email or a URL not being a name.
fn product(metadata: &Metadata) -> Option<Product> {
    let component = metadata.component.as_ref()?;
    let Component {
        name,
        version,
        purl,
        ..
    } = to_domain(component);
    Some(Product {
        name,
        version,
        purl,
        manufacturer: first_name([&component.manufacturer, &metadata.manufacture]),
        supplier: first_name([&metadata.supplier, &component.supplier]),
    })
}

/// The first name of the organizations given, absent ones and those without a name skipped (SBR-12).
fn first_name<'a>(
    entities: impl IntoIterator<Item = &'a Option<OrganizationalEntity>>,
) -> Option<String> {
    first_filled(
        entities
            .into_iter()
            .flatten()
            .filter_map(|entity| entity.name.as_ref())
            .map(ToString::to_string),
    )
}

/// The components [`flatten`] keeps, the nested ones of a skipped component still read.
#[derive(Clone, Copy)]
enum Keep<'p> {
    /// The top-level components, each kept (SBR-6).
    All,
    /// The components nested in the product (SBR-13): one whose `bom-ref` one already read carries is skipped, and so
    /// is a target of the product, whose package URL has this base (see [`purl_base`]).
    NewAndNotTargetOf(Option<&'p str>),
}

/// A package URL without its qualifiers (`?`) and subpath (`#`): a target of a product keeps the base of its purl.
fn purl_base(purl: &str) -> &str {
    purl.split(['?', '#']).next().unwrap_or(purl)
}

/// Pushes each component, then its nested ones, depth first, recording the `bom-ref` of each in `read_refs`, a
/// blank one identifying nothing.
fn flatten<'a>(
    components: &'a [CdxComponent],
    into: &mut Vec<Component>,
    read_refs: &mut HashSet<&'a str>,
    keep: Keep,
) {
    for component in components {
        let fresh = component
            .bom_ref
            .as_deref()
            .filter(|bom_ref| !bom_ref.trim().is_empty())
            .is_none_or(|bom_ref| read_refs.insert(bom_ref));
        let kept = match keep {
            Keep::All => true,
            Keep::NewAndNotTargetOf(product) => {
                let purl = component.purl.as_ref().map(ToString::to_string);
                fresh && (product.is_none() || purl.as_deref().map(purl_base) != product)
            }
        };
        if kept {
            into.push(to_domain(component));
        }
        if let Some(nested) = &component.components {
            flatten(&nested.0, into, read_refs, keep);
        }
    }
}

fn to_domain(component: &CdxComponent) -> Component {
    Component {
        name: component.name.to_string(),
        version: component.version.as_ref().map(ToString::to_string),
        purl: component.purl.as_ref().map(ToString::to_string),
        supplier: component.supplier.as_ref().and_then(organization),
        manufacturer: component.manufacturer.as_ref().and_then(organization),
        authors: component
            .author
            .iter()
            .map(ToString::to_string)
            .chain(component.authors.iter().flatten().filter_map(author))
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

/// The identity of an organization (SBR-5): its name, else the first email of its contacts, else its
/// first URL (BSI TR-03183-2 asks for an email, a URL when there is none).
fn organization(entity: &OrganizationalEntity) -> Option<String> {
    let name = entity.name.iter().map(ToString::to_string);
    let urls = entity.url.iter().flatten().map(ToString::to_string);
    let emails = entity
        .contact
        .iter()
        .flatten()
        .filter_map(|contact| contact.email.as_ref())
        .map(ToString::to_string);
    first_filled(name.chain(emails).chain(urls))
}

/// The identity of an author (SBR-5): its name, else its email.
fn author(contact: &OrganizationalContact) -> Option<String> {
    first_filled(
        [&contact.name, &contact.email]
            .into_iter()
            .flatten()
            .map(ToString::to_string),
    )
}

/// The first value that is not empty nor only whitespace.
fn first_filled(mut values: impl Iterator<Item = String>) -> Option<String> {
    values.find(|value| !value.trim().is_empty())
}
