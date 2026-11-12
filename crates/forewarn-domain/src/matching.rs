//! The matching of the components of an SBOM against known vulnerabilities (`specs/vulnerability-matching.md`).

use std::cmp::Ordering;

use semver::Version;

use crate::purl::PackageUrl;
use crate::sbom::Component;
use crate::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};

/// How the name of a package URL type is built (VMT-4).
#[derive(Clone, Copy)]
enum NameForm {
    /// The name alone, any namespace left out.
    Name,
    /// `namespace/name`, or the name without a namespace.
    Slash,
    /// `namespace/name`; a namespace is required.
    SlashRequired,
    /// `namespace:name`; a namespace is required.
    ColonRequired,
}

/// The package URL types matching knows: type, OSV ecosystem, name form (VMT-4).
const ECOSYSTEMS: [(&str, &str, NameForm); 8] = [
    ("cargo", "crates.io", NameForm::Name),
    ("npm", "npm", NameForm::Slash),
    ("pypi", "PyPI", NameForm::Name),
    ("maven", "Maven", NameForm::ColonRequired),
    ("golang", "Go", NameForm::Slash),
    ("nuget", "NuGet", NameForm::Name),
    ("gem", "RubyGems", NameForm::Name),
    ("composer", "Packagist", NameForm::SlashRequired),
];

/// The ecosystems whose `ECOSYSTEM` ranges are compared by Semantic Versioning (VMT-9).
const SEMVER_ECOSYSTEMS: [&str; 2] = ["crates.io", "npm"];

/// Why a component cannot be matched at all (VMT-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentReason {
    /// The component has no package URL.
    NoPackageUrl,
    /// The package URL does not follow the specification, or lacks a namespace its type requires.
    InvalidPackageUrl,
    /// The package URL type maps to no OSV ecosystem matching knows.
    UnknownEcosystem,
    /// Neither the component nor its package URL has a version.
    NoVersion,
}

/// Why a pair of a component and a vulnerability naming its package cannot be evaluated (VMT-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairReason {
    /// A range of the package is ordered in a way matching does not compare yet.
    RangeNotEvaluated,
    /// The version, or a version of a range's events, is not Semantic Versioning.
    InvalidVersion,
}

/// Why a component, or a pair, was not evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The component cannot be matched against any vulnerability.
    Component(ComponentReason),
    /// The component cannot be matched against this vulnerability.
    Pair {
        vulnerability_id: String,
        reason: PairReason,
    },
}

/// A component as the report names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentRef {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
}

impl From<&Component> for ComponentRef {
    fn from(component: &Component) -> Self {
        Self {
            name: component.name.clone(),
            version: component.version.clone(),
            purl: component.purl.clone(),
        }
    }
}

/// A component affected by a vulnerability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub component: ComponentRef,
    pub vulnerability_id: String,
    pub aliases: Vec<String>,
    pub source: String,
}

/// A component, or a pair, matching could not evaluate: never to be read as unaffected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotEvaluated {
    pub component: ComponentRef,
    pub reason: Reason,
}

/// The result of matching: the matches, and apart from them what could not be evaluated, both in the order of the
/// SBOM's components, then of the vulnerability ids.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatchReport {
    matches: Vec<Match>,
    not_evaluated: Vec<NotEvaluated>,
}

impl MatchReport {
    /// The components affected, one per vulnerability.
    #[must_use]
    pub fn matches(&self) -> &[Match] {
        &self.matches
    }

    /// The components, and the pairs, that could not be evaluated.
    #[must_use]
    pub fn not_evaluated(&self) -> &[NotEvaluated] {
        &self.not_evaluated
    }
}

/// Matches each component against each vulnerability, withdrawn ones aside.
#[must_use]
pub fn match_components(
    components: &[Component],
    vulnerabilities: &[Vulnerability],
) -> MatchReport {
    let mut vulnerabilities: Vec<&Vulnerability> =
        vulnerabilities.iter().filter(|v| !v.withdrawn).collect();
    vulnerabilities.sort_by(|a, b| a.id.cmp(&b.id));
    let mut report = MatchReport::default();
    for component in components {
        let package = match ComponentPackage::of(component) {
            Ok(package) => package,
            Err(reason) => {
                report.not_evaluated.push(NotEvaluated {
                    component: component.into(),
                    reason: Reason::Component(reason),
                });
                continue;
            }
        };
        for vulnerability in &vulnerabilities {
            match package.outcome(vulnerability) {
                Outcome::Affected => report.matches.push(Match {
                    component: component.into(),
                    vulnerability_id: vulnerability.id.clone(),
                    aliases: vulnerability.aliases.clone(),
                    source: vulnerability.source.clone(),
                }),
                Outcome::NotAffected => {}
                Outcome::NotEvaluated(reason) => report.not_evaluated.push(NotEvaluated {
                    component: component.into(),
                    reason: Reason::Pair {
                        vulnerability_id: vulnerability.id.clone(),
                        reason,
                    },
                }),
            }
        }
    }
    report
}

/// What matching a component against one vulnerability gives.
enum Outcome {
    Affected,
    NotAffected,
    NotEvaluated(PairReason),
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
        let name = match (form, purl.namespace.is_empty()) {
            (NameForm::SlashRequired | NameForm::ColonRequired, true) => {
                return Err(ComponentReason::InvalidPackageUrl);
            }
            (NameForm::Name, _) | (NameForm::Slash, true) => purl.name,
            (NameForm::Slash | NameForm::SlashRequired, false) => {
                format!("{}/{}", purl.namespace, purl.name)
            }
            (NameForm::ColonRequired, false) => format!("{}:{}", purl.namespace, purl.name),
        };
        let version = [component.version.as_deref(), purl.version.as_deref()]
            .into_iter()
            .flatten()
            .map(str::trim)
            .find(|version| !version.is_empty())
            .ok_or(ComponentReason::NoVersion)?
            .to_owned();
        Ok(Self {
            ecosystem,
            name,
            version,
        })
    }

    /// Whether the vulnerability affects this package: affected by any listed version or range, else the first
    /// reason a range could not be evaluated, else not affected.
    fn outcome(&self, vulnerability: &Vulnerability) -> Outcome {
        let mut unevaluated = None;
        for affected in vulnerability
            .affected
            .iter()
            .filter(|a| self.is_named_by(a))
        {
            if affected.versions.iter().any(|v| v.trim() == self.version) {
                return Outcome::Affected;
            }
            let only_git = affected.ranges.iter().all(|r| r.kind == RangeKind::Git);
            for range in &affected.ranges {
                match self.in_range(range) {
                    Ok(true) => return Outcome::Affected,
                    Ok(false) => {}
                    Err(PairReason::RangeNotEvaluated)
                        if range.kind == RangeKind::Git && !only_git => {}
                    Err(reason) => {
                        unevaluated.get_or_insert(reason);
                    }
                }
            }
        }
        unevaluated.map_or(Outcome::NotAffected, Outcome::NotEvaluated)
    }

    fn is_named_by(&self, affected: &AffectedPackage) -> bool {
        affected.ecosystem == self.ecosystem
            && same_name(self.ecosystem, &affected.name, &self.name)
    }

    /// Whether the version is in the range, by the OSV algorithm (VMT-9).
    fn in_range(&self, range: &Range) -> Result<bool, PairReason> {
        let comparable = match range.kind {
            RangeKind::Semver => true,
            RangeKind::Ecosystem => SEMVER_ECOSYSTEMS.contains(&self.ecosystem),
            RangeKind::Git => false,
        };
        if !comparable {
            return Err(PairReason::RangeNotEvaluated);
        }
        let version = parse_semver(&self.version)?;
        let mut events = range
            .events
            .iter()
            .map(|event| {
                let at = match event {
                    Event::Introduced(at) if at.trim() == "0" => None,
                    _ => Some(parse_semver(event.version())?),
                };
                Ok((event, at))
            })
            .collect::<Result<Vec<_>, PairReason>>()?;
        events.sort_by(|(a_event, a), (b_event, b)| {
            compare(a.as_ref(), b.as_ref()).then(rank(a_event).cmp(&rank(b_event)))
        });
        let mut affected = false;
        for (event, at) in events {
            let order = at.map_or(Ordering::Greater, |at| version.cmp_precedence(&at));
            match event {
                Event::Introduced(_) if order.is_ge() => affected = true,
                Event::Fixed(_) if order.is_ge() => affected = false,
                Event::LastAffected(_) if order.is_gt() => affected = false,
                _ => {}
            }
        }
        Ok(affected)
    }
}

/// Whether two package names of an ecosystem are the same: exactly equal, or equal once normalized under `PyPI`, or
/// equal without regard to case under `NuGet` (VMT-6).
#[must_use]
pub fn same_name(ecosystem: &str, a: &str, b: &str) -> bool {
    match ecosystem {
        "PyPI" => normalize_pypi(a) == normalize_pypi(b),
        "NuGet" => a.to_lowercase() == b.to_lowercase(),
        _ => a == b,
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

/// Orders the versions of events, `None` (introduced `0`) first.
fn compare(a: Option<&Version>, b: Option<&Version>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp_precedence(b),
        (a, b) => a.is_some().cmp(&b.is_some()),
    }
}

/// The order of events at an equal version: `introduced`, `fixed`, `last_affected` (VMT-9).
fn rank(event: &Event) -> u8 {
    match event {
        Event::Introduced(_) => 0,
        Event::Fixed(_) => 1,
        Event::LastAffected(_) => 2,
    }
}

/// A Semantic Versioning 2.0 version, a leading `v` ignored.
fn parse_semver(version: &str) -> Result<Version, PairReason> {
    let version = version.trim();
    let version = version.strip_prefix('v').unwrap_or(version);
    Version::parse(version).map_err(|_| PairReason::InvalidVersion)
}
