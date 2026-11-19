//! The packages of Debian, as image scanners write them (`pkg:deb/debian/<name>@<version>?distro=debian-<release>`),
//! mapped to the `Debian:<release>` ecosystems of OSV, named by their source package
//! (`specs/vulnerability-matching.md`, VMT-32 to VMT-34).

use crate::matching::ComponentReason;
use crate::purl::{PackageUrl, qualifier};

/// The package URL type of the Debian packages.
pub(crate) const PURL_TYPE: &str = "deb";

/// What a Debian package is matched under.
pub(crate) struct DebianPackage {
    /// `Debian:<release>`.
    pub(crate) ecosystem: String,
    /// The source package.
    pub(crate) name: String,
    /// The version of the source package, when the package URL gives it.
    pub(crate) source_version: Option<String>,
}

impl DebianPackage {
    /// The package of a `deb` package URL, read from `text`, or why it cannot be matched.
    pub(crate) fn of(purl: &PackageUrl, text: &str) -> Result<Self, ComponentReason> {
        if !purl.namespace.eq_ignore_ascii_case("debian") {
            return Err(ComponentReason::UnknownEcosystem);
        }
        let release = qualifier(text, "distro")
            .as_deref()
            .and_then(release)
            .ok_or(ComponentReason::UnknownRelease)?;
        let upstream = qualifier(text, "upstream").unwrap_or_default();
        let (source, source_version) = upstream.split_once('@').unwrap_or((&upstream, ""));
        let source = source.trim();
        let source_version = source_version.trim();
        Ok(Self {
            ecosystem: format!("Debian:{release}"),
            name: if source.is_empty() {
                purl.name.clone()
            } else {
                source.to_owned()
            },
            source_version: (!source_version.is_empty()).then(|| source_version.to_owned()),
        })
    }
}

/// The release of a `distro` qualifier: the digits after `debian-`, their leading zeros dropped (VMT-32).
fn release(distro: &str) -> Option<String> {
    let digits: String = distro
        .strip_prefix("debian-")?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        return None;
    }
    let release = digits.trim_start_matches('0');
    Some(if release.is_empty() { "0" } else { release }.to_owned())
}

/// Whether an OSV ecosystem is that of a Debian release, `Debian:` and digits.
pub(crate) fn is_ecosystem(ecosystem: &str) -> bool {
    ecosystem
        .strip_prefix("Debian:")
        .is_some_and(|release| !release.is_empty() && release.bytes().all(|b| b.is_ascii_digit()))
}
