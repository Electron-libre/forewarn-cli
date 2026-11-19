//! The properties `trivy` writes on a component: the source package it was built from (`specs/sbom-reading.md`,
//! SBR-17). Their names stay in this adapter; the domain only sees a [`SourcePackage`].

use cyclonedx_bom::models::property::Properties;
use forewarn_domain::sbom::SourcePackage;

/// The prefix of the names of the properties of `trivy`.
const PREFIX: &str = "aquasecurity:trivy:";

/// The source package the properties name: `SrcName`, and the version `<SrcEpoch>:<SrcVersion>-<SrcRelease>`,
/// the epoch left out when absent or `0`, the release when absent; none without `SrcName`.
pub(crate) fn source(properties: Option<&Properties>) -> Option<SourcePackage> {
    let value = |suffix: &str| {
        properties?
            .0
            .iter()
            .find(|property| {
                property
                    .name
                    .strip_prefix(PREFIX)
                    .is_some_and(|name| name == suffix)
            })
            .map(|property| property.value.to_string().trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    let name = value("SrcName")?;
    let version = value("SrcVersion").map(|version| {
        let epoch = value("SrcEpoch")
            .filter(|epoch| epoch != "0")
            .map(|epoch| format!("{epoch}:"))
            .unwrap_or_default();
        let release = value("SrcRelease")
            .map(|release| format!("-{release}"))
            .unwrap_or_default();
        format!("{epoch}{version}{release}")
    });
    Some(SourcePackage { name, version })
}
