//! The packages of Debian, as image scanners write them (`pkg:deb/debian/<name>@<version>?distro=debian-<release>`),
//! mapped to the `Debian:<release>` ecosystems of OSV, named by their source package
//! (`specs/debian-matching.md`, DEB-1 to DEB-5).

use crate::matching::ComponentReason;
use crate::purl::{PackageUrl, qualifier};
use crate::sbom::SourcePackage;

/// The package URL type of the Debian packages.
pub(crate) const PURL_TYPE: &str = "deb";

/// What a Debian package is matched under.
pub(crate) struct DebianPackage {
    /// `Debian:<release>`.
    pub(crate) ecosystem: String,
    /// The source package.
    pub(crate) name: String,
    /// The version of the source package when the package URL or the source the component carries gives it (DEB-3),
    /// else that of the component, else that of its package URL, these two preceded, when they lack one, by the epoch
    /// of the `epoch` qualifier, else that of the package URL version (DEB-5); none when none is given.
    pub(crate) version: Option<String>,
}

impl DebianPackage {
    /// The package of a `deb` package URL, read from `text`, of a component at `version` built from `source`, or
    /// why it cannot be matched.
    pub(crate) fn of(
        purl: &PackageUrl,
        text: &str,
        version: Option<&str>,
        source: Option<&SourcePackage>,
    ) -> Result<Self, ComponentReason> {
        if !purl.namespace.eq_ignore_ascii_case("debian") {
            return Err(ComponentReason::UnknownEcosystem);
        }
        let read = |key| qualifier(text, key).map_err(|_| ComponentReason::InvalidPackageUrl);
        let release = read("distro")?
            .as_deref()
            .and_then(release)
            .ok_or(ComponentReason::UnknownRelease)?;
        let upstream = read("upstream")?.unwrap_or_default();
        let epoch = read("epoch")?;
        let (name, upstream_version) = upstream.split_once('@').unwrap_or((&upstream, ""));
        let filled = |text: &str| {
            Some(text.trim())
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
        };
        let source = source.and_then(|source| Some((filled(&source.name)?, source)));
        let (name, source_version) = match (filled(name), source) {
            (Some(name), _) => (name, None),
            (None, Some((name, source))) => (name, source.version.as_deref().and_then(filled)),
            (None, None) => (purl.name.clone(), None),
        };
        let source_version = filled(upstream_version).or(source_version);
        let epoch = epoch.as_deref().and_then(filled).or_else(|| {
            let (epoch, _) = purl.version.as_deref()?.split_once(':')?;
            filled(epoch)
        });
        let with_epoch = |version: String| match &epoch {
            Some(epoch) if !version.contains(':') => format!("{epoch}:{version}"),
            _ => version,
        };
        Ok(Self {
            ecosystem: format!("Debian:{release}"),
            name,
            version: source_version.or_else(|| {
                [version, purl.version.as_deref()]
                    .into_iter()
                    .flatten()
                    .find_map(filled)
                    .map(with_epoch)
            }),
        })
    }
}

/// The first release OSV names by its major alone; it names those before by `<major>.<minor>` (`Debian:6.0`).
const FIRST_MAJOR_ONLY: u32 = 7;

/// The release of a `distro` qualifier: the digits after `debian-`, their leading zeros dropped, then for a release
/// before 7 `.` and the digits of its minor (DEB-1).
fn release(distro: &str) -> Option<String> {
    let rest = distro.strip_prefix("debian-")?;
    let (major, rest) = leading_number(rest)?;
    if major
        .parse::<u32>()
        .is_ok_and(|major| major >= FIRST_MAJOR_ONLY)
    {
        return Some(major);
    }
    let (minor, _) = leading_number(rest.strip_prefix('.')?)?;
    Some(format!("{major}.{minor}"))
}

/// The run of ASCII digits a text starts with, its leading zeros dropped, and what follows it.
fn leading_number(text: &str) -> Option<(String, &str)> {
    let length = text.bytes().take_while(u8::is_ascii_digit).count();
    if length == 0 {
        return None;
    }
    let number = text[..length].trim_start_matches('0');
    let number = if number.is_empty() { "0" } else { number };
    Some((number.to_owned(), &text[length..]))
}

/// Whether an OSV ecosystem is that of a Debian release: `Debian:` and digits, or digits, `.` and digits.
pub(crate) fn is_ecosystem(ecosystem: &str) -> bool {
    let is_number = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    ecosystem
        .strip_prefix("Debian:")
        .is_some_and(|release| match release.split_once('.') {
            Some((major, minor)) => is_number(major) && is_number(minor),
            None => is_number(release),
        })
}
