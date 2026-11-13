//! The matching of the components of an SBOM against known vulnerabilities (`specs/vulnerability-matching.md`).

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

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

/// A component affected by a vulnerability, known by one record or several whose ids or aliases overlap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub component: ComponentRef,
    /// The id naming the vulnerability: its first CVE, else the first id of its records (VMT-16).
    pub id: String,
    /// Every other id and alias of its records, in byte order (VMT-17).
    pub aliases: Vec<String>,
    /// The records that hold it, by id (VMT-18).
    pub records: Vec<RecordRef>,
}

/// A record of a vulnerability, as the report names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRef {
    pub id: String,
    /// The database the record comes from (`RUSTSEC`, `GHSA`).
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

/// Matches each component against the vulnerabilities naming its package, found through an index by ecosystem and
/// name rather than by testing every vulnerability, withdrawn ones aside.
#[must_use]
pub fn match_components(
    components: &[Component],
    vulnerabilities: &[Vulnerability],
) -> MatchReport {
    let mut vulnerabilities: Vec<&Vulnerability> =
        vulnerabilities.iter().filter(|v| !v.withdrawn).collect();
    vulnerabilities.sort_by(|a, b| a.id.cmp(&b.id));
    let index = Index::new(&vulnerabilities);
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
        let mut groups: Vec<Group> = Vec::new();
        for vulnerability in index.naming(&package).iter().map(|&i| vulnerabilities[i]) {
            match package.outcome(vulnerability) {
                Outcome::NotNamed => {}
                outcome => Group::add(&mut groups, vulnerability, outcome),
            }
        }
        let mut matches = Vec::new();
        let mut pairs = Vec::new();
        for group in groups {
            if group.affected {
                matches.push(group.into_match(component));
            } else {
                pairs.extend(group.unevaluated);
            }
        }
        matches.sort_by(|a: &Match, b| a.id.cmp(&b.id));
        pairs.sort_by(|(a, _), (b, _)| a.id.cmp(&b.id));
        report.matches.extend(matches);
        for (vulnerability, reason) in pairs {
            report.not_evaluated.push(NotEvaluated {
                component: component.into(),
                reason: Reason::Pair {
                    vulnerability_id: vulnerability.id.clone(),
                    reason,
                },
            });
        }
    }
    report
}

/// The vulnerabilities by the ecosystem and the name key of their affected packages, so that a component meets only
/// the records naming its package.
struct Index<'a> {
    /// Per ecosystem, per name key, the places of the vulnerabilities in id order, each once.
    places: HashMap<&'a str, HashMap<Cow<'a, str>, Vec<usize>>>,
}

impl<'a> Index<'a> {
    /// Indexes vulnerabilities sorted by id.
    fn new(vulnerabilities: &[&'a Vulnerability]) -> Self {
        let mut places: HashMap<&str, HashMap<Cow<str>, Vec<usize>>> = HashMap::new();
        for (place, vulnerability) in vulnerabilities.iter().enumerate() {
            for affected in &vulnerability.affected {
                let list = places
                    .entry(affected.ecosystem.as_str())
                    .or_default()
                    .entry(name_key(&affected.ecosystem, &affected.name))
                    .or_default();
                if list.last() != Some(&place) {
                    list.push(place);
                }
            }
        }
        Self { places }
    }

    /// The places of the vulnerabilities an affected package of which names the package, in id order.
    fn naming(&self, package: &ComponentPackage) -> &[usize] {
        self.places
            .get(package.ecosystem)
            .and_then(|names| names.get(name_key(package.ecosystem, &package.name).as_ref()))
            .map_or(&[], Vec::as_slice)
    }
}

/// The records naming one component whose ids or aliases overlap (VMT-15): one vulnerability, a match when one of
/// them affects the component, whatever the others say (VMT-19, VMT-20).
struct Group<'a> {
    /// The ids and aliases of its records.
    ids: BTreeSet<&'a str>,
    records: Vec<&'a Vulnerability>,
    /// Whether one of its records affects the component.
    affected: bool,
    /// Its records that could not be evaluated, with their reason.
    unevaluated: Vec<(&'a Vulnerability, PairReason)>,
}

impl<'a> Group<'a> {
    /// Adds a record naming the component to the groups, merging every group it overlaps into one.
    fn add(groups: &mut Vec<Self>, record: &'a Vulnerability, outcome: Outcome) {
        let mut merged = Self {
            ids: std::iter::once(record.id.as_str())
                .chain(record.aliases.iter().map(String::as_str))
                .collect(),
            records: vec![record],
            affected: matches!(outcome, Outcome::Affected),
            unevaluated: match outcome {
                Outcome::NotEvaluated(reason) => vec![(record, reason)],
                _ => vec![],
            },
        };
        let mut index = 0;
        while index < groups.len() {
            if groups[index].ids.is_disjoint(&merged.ids) {
                index += 1;
            } else {
                let group = groups.swap_remove(index);
                merged.ids.extend(group.ids);
                merged.records.extend(group.records);
                merged.affected |= group.affected;
                merged.unevaluated.extend(group.unevaluated);
            }
        }
        groups.push(merged);
    }

    /// The match of the group: named by its first CVE, else its first record id (VMT-16, VMT-17, VMT-18).
    fn into_match(mut self, component: &Component) -> Match {
        self.records.sort_by(|a, b| a.id.cmp(&b.id));
        self.records.dedup_by(|a, b| a.id == b.id);
        let id = self
            .ids
            .iter()
            .find(|id| id.starts_with("CVE-"))
            .copied()
            .unwrap_or(self.records[0].id.as_str());
        Match {
            component: component.into(),
            id: id.to_owned(),
            aliases: self
                .ids
                .iter()
                .filter(|alias| **alias != id)
                .map(|alias| (*alias).to_owned())
                .collect(),
            records: self
                .records
                .iter()
                .map(|record| RecordRef {
                    id: record.id.clone(),
                    source: record.source.clone(),
                })
                .collect(),
        }
    }
}

/// What matching a component against one vulnerability gives.
#[derive(Clone, Copy)]
enum Outcome {
    /// No affected package of the vulnerability names the component.
    NotNamed,
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
    /// reason a range could not be evaluated, else not affected, or not named by any of its affected packages.
    fn outcome(&self, vulnerability: &Vulnerability) -> Outcome {
        let mut named = false;
        let mut unevaluated = None;
        for affected in vulnerability
            .affected
            .iter()
            .filter(|a| self.is_named_by(a))
        {
            named = true;
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
        match unevaluated {
            Some(reason) => Outcome::NotEvaluated(reason),
            None if named => Outcome::NotAffected,
            None => Outcome::NotNamed,
        }
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
    name_key(ecosystem, a) == name_key(ecosystem, b)
}

/// The form of a package name two names of an ecosystem are compared in (VMT-6).
fn name_key<'a>(ecosystem: &str, name: &'a str) -> Cow<'a, str> {
    match ecosystem {
        "PyPI" => Cow::Owned(normalize_pypi(name)),
        "NuGet" => Cow::Owned(name.to_lowercase()),
        _ => Cow::Borrowed(name),
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
