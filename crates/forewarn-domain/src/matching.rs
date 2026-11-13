//! The matching of the components of an SBOM against known vulnerabilities (`specs/vulnerability-matching.md`).

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::purl::PackageUrl;
use crate::sbom::Component;
use crate::version::{Maven, NuGet, Packagist, Pep440, RubyGems, Scheme, Semver, VersionOrder};
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

/// The package URL types matching knows: type, OSV ecosystem, name form (VMT-4), and the ordering of the versions of
/// its `ECOSYSTEM` ranges (VMT-23).
const ECOSYSTEMS: [(&str, &str, NameForm, Scheme); 8] = [
    ("cargo", "crates.io", NameForm::Name, Scheme::Semver),
    ("npm", "npm", NameForm::Slash, Scheme::Semver),
    ("pypi", "PyPI", NameForm::Name, Scheme::Pep440),
    ("maven", "Maven", NameForm::ColonRequired, Scheme::Maven),
    ("golang", "Go", NameForm::Slash, Scheme::Semver),
    ("nuget", "NuGet", NameForm::Name, Scheme::NuGet),
    ("gem", "RubyGems", NameForm::Name, Scheme::RubyGems),
    (
        "composer",
        "Packagist",
        NameForm::SlashRequired,
        Scheme::Packagist,
    ),
];

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
    /// The only ranges of the package are `GIT` ranges, which matching does not compare.
    RangeNotEvaluated,
    /// The version, or a version of a range's events, is not valid in the ordering the range is compared by.
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

/// A component affected by a vulnerability, known by one record or several whose ids or aliases overlap, never by
/// records of two CVEs (VMT-15, VMT-21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub component: ComponentRef,
    /// The id naming the vulnerability: the CVE its records share, else the first id of its records affecting the
    /// component or not evaluated (VMT-16).
    pub id: String,
    /// Every other id and alias of those records, in byte order, without another CVE nor the id of a record of
    /// another CVE (VMT-17).
    pub aliases: Vec<String>,
    /// Its records by id, each with its status: those not affecting the component are listed too (VMT-18, VMT-22).
    pub records: Vec<RecordRef>,
}

/// A record of a vulnerability, as the report names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRef {
    pub id: String,
    /// The database the record comes from (`RUSTSEC`, `GHSA`).
    pub source: String,
    /// Whether the record affects the component (VMT-18).
    pub status: RecordStatus,
}

/// What a record of a match says of the component (VMT-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordStatus {
    /// The record affects the component's version.
    Affects,
    /// The record names the component's package but not its version.
    DoesNotAffect,
    /// The record names the component's package and could not be evaluated (VMT-10).
    NotEvaluated,
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

    /// The matches and what could not be evaluated, taken out of the report.
    #[must_use]
    pub fn into_parts(self) -> (Vec<Match>, Vec<NotEvaluated>) {
        (self.matches, self.not_evaluated)
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
        let mut named: Vec<Named> = index
            .naming(&package)
            .iter()
            .map(|&i| vulnerabilities[i])
            .filter_map(|record| match package.outcome(record) {
                Outcome::NotNamed => None,
                outcome => Some(Named::new(record, outcome)),
            })
            .collect();
        named.dedup_by(|copy, kept| {
            let same = copy.record.id == kept.record.id;
            if same {
                kept.absorb(copy);
            }
            same
        });
        let groups = Group::of(&named);
        let mut matches: Vec<Match> = groups
            .iter()
            .filter(|group| group.affected)
            .map(|group| group.to_match(component, &named))
            .collect();
        matches.sort_by(|a, b| a.id.cmp(&b.id));
        let pairs = reported_pairs(&named, &groups);
        report.matches.extend(matches);
        for (record, reason) in pairs {
            report.not_evaluated.push(NotEvaluated {
                component: component.into(),
                reason: Reason::Pair {
                    vulnerability_id: record.id.clone(),
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
    /// Indexes vulnerabilities sorted by id, leaving aside the affected packages of an ecosystem no component maps to
    /// (VMT-4).
    fn new(vulnerabilities: &[&'a Vulnerability]) -> Self {
        let mut places: HashMap<&str, HashMap<Cow<str>, Vec<usize>>> = HashMap::new();
        for (place, vulnerability) in vulnerabilities.iter().enumerate() {
            let known = vulnerability.affected.iter().filter(|affected| {
                ECOSYSTEMS
                    .iter()
                    .any(|(_, ecosystem, _, _)| *ecosystem == affected.ecosystem)
            });
            for affected in known {
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

/// A record naming the component, with what matching the component against it gave.
struct Named<'a> {
    record: &'a Vulnerability,
    outcome: Outcome,
    /// Its id and aliases.
    ids: BTreeSet<&'a str>,
    /// The `CVE-` ids among them.
    cves: BTreeSet<&'a str>,
}

impl<'a> Named<'a> {
    fn new(record: &'a Vulnerability, outcome: Outcome) -> Self {
        let ids: BTreeSet<&str> = std::iter::once(record.id.as_str())
            .chain(record.aliases.iter().map(String::as_str))
            .collect();
        let cves = ids
            .iter()
            .copied()
            .filter(|id| id.starts_with("CVE-"))
            .collect();
        Self {
            record,
            outcome,
            ids,
            cves,
        }
    }

    /// Whether it affects the component or could not be evaluated: only such a record joins, bridges or names a
    /// match (VMT-15, VMT-22).
    fn is_active(&self) -> bool {
        !matches!(self.outcome, Outcome::NotAffected)
    }

    /// Takes in another copy of the same record: its ids, and its outcome when it says more (affected, then not
    /// evaluated, then not affected).
    fn absorb(&mut self, copy: &Self) {
        let weight = |outcome: Outcome| match outcome {
            Outcome::Affected => 2,
            Outcome::NotEvaluated(_) => 1,
            Outcome::NotAffected | Outcome::NotNamed => 0,
        };
        if weight(copy.outcome) > weight(self.outcome) {
            self.outcome = copy.outcome;
        }
        self.ids.extend(&copy.ids);
        self.cves.extend(&copy.cves);
    }
}

/// The records naming one component that stand for one vulnerability (VMT-15, VMT-21): those holding its CVE, or
/// with no CVE those whose ids or aliases overlap, a match when one of them affects the component (VMT-19).
struct Group<'a> {
    /// The `CVE-` id its records share, if any.
    cve: Option<&'a str>,
    /// Its records that affect the component or could not be evaluated, by their place among the named records.
    members: BTreeSet<usize>,
    /// Whether one of them affects the component.
    affected: bool,
}

impl<'a> Group<'a> {
    /// The groups of the named records: one per `CVE-` id the active records hold, each with the records holding it
    /// and the clusters of active records without CVE overlapping them; a cluster overlapping none is a group of its
    /// own. Records without CVE are clustered through the ids no record holding a CVE carries, so that two of them
    /// never meet through a record of one CVE (VMT-21).
    fn of(named: &[Named<'a>]) -> Vec<Self> {
        let anchored: BTreeSet<&str> = named
            .iter()
            .filter(|record| record.is_active() && !record.cves.is_empty())
            .flat_map(|record| record.ids.iter().copied())
            .collect();
        let mut by_cve: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
        // The ids a cluster is linked through, and its records.
        let mut clusters: Vec<(BTreeSet<&str>, BTreeSet<usize>)> = Vec::new();
        for (place, record) in named.iter().enumerate() {
            if !record.is_active() {
                continue;
            }
            if record.cves.is_empty() {
                let own = record.ids.difference(&anchored).copied().collect();
                let mut merged = (own, BTreeSet::from([place]));
                clusters.retain(|(ids, members)| {
                    if ids.is_disjoint(&merged.0) {
                        return true;
                    }
                    merged.0.extend(ids);
                    merged.1.extend(members);
                    false
                });
                clusters.push(merged);
            }
            for cve in &record.cves {
                by_cve.entry(cve).or_default().insert(place);
            }
        }
        let mut groups: Vec<Self> = by_cve
            .into_iter()
            .map(|(cve, members)| Self {
                cve: Some(cve),
                members,
                affected: false,
            })
            .collect();
        let with_cve = groups.len();
        for (_, members) in clusters {
            let mut joined = false;
            for group in &mut groups[..with_cve] {
                let overlaps = group
                    .members
                    .iter()
                    .filter(|&&member| !named[member].cves.is_empty())
                    .any(|&member| {
                        members
                            .iter()
                            .any(|&other| !named[member].ids.is_disjoint(&named[other].ids))
                    });
                if overlaps {
                    group.members.extend(&members);
                    joined = true;
                }
            }
            if !joined {
                groups.push(Self {
                    cve: None,
                    members,
                    affected: false,
                });
            }
        }
        for group in &mut groups {
            group.affected = group
                .members
                .iter()
                .any(|&member| matches!(named[member].outcome, Outcome::Affected));
        }
        groups
    }

    /// The match of the group: named by its CVE, else its first record id; its aliases without another CVE nor the
    /// id of a record of another CVE; its records, those not affecting that overlap it included (VMT-16 to VMT-18,
    /// VMT-22).
    fn to_match(&self, component: &Component, named: &[Named]) -> Match {
        let id = self.cve.unwrap_or_else(|| {
            self.members
                .iter()
                .map(|&member| named[member].record.id.as_str())
                .min()
                .unwrap_or_default()
        });
        let foreign: BTreeSet<&str> = named
            .iter()
            .filter(|record| record.is_active() && !record.cves.is_empty())
            .filter(|record| !record.cves.contains(id))
            .map(|record| record.record.id.as_str())
            .collect();
        let aliases: BTreeSet<&str> = self
            .members
            .iter()
            .flat_map(|&member| &named[member].ids)
            .copied()
            .filter(|alias| *alias != id)
            .filter(|alias| !alias.starts_with("CVE-") && !foreign.contains(alias))
            .collect();
        let mut records: Vec<&Named> = named
            .iter()
            .enumerate()
            .filter(|(place, record)| {
                self.members.contains(place)
                    || (!record.is_active()
                        && record
                            .ids
                            .iter()
                            .any(|alias| *alias == id || aliases.contains(alias)))
            })
            .map(|(_, record)| record)
            .collect();
        records.sort_by(|a, b| a.record.id.cmp(&b.record.id));
        Match {
            component: component.into(),
            id: id.to_owned(),
            aliases: aliases.into_iter().map(str::to_owned).collect(),
            records: records
                .into_iter()
                .map(|named| RecordRef {
                    id: named.record.id.clone(),
                    source: named.record.source.clone(),
                    status: match named.outcome {
                        Outcome::Affected => RecordStatus::Affects,
                        Outcome::NotEvaluated(_) => RecordStatus::NotEvaluated,
                        Outcome::NotAffected | Outcome::NotNamed => RecordStatus::DoesNotAffect,
                    },
                })
                .collect(),
        }
    }
}

/// The pairs not evaluated to report, by record id: those of a record in no match, or holding a `CVE-` id that names
/// no match (VMT-20).
fn reported_pairs<'a>(
    named: &[Named<'a>],
    groups: &[Group],
) -> Vec<(&'a Vulnerability, PairReason)> {
    let mut pairs: Vec<(&Vulnerability, PairReason)> = named
        .iter()
        .enumerate()
        .filter_map(|(place, record)| match record.outcome {
            Outcome::NotEvaluated(reason) => {
                let in_match = groups
                    .iter()
                    .any(|group| group.affected && group.members.contains(&place));
                let cves_matched = record.cves.iter().all(|cve| {
                    groups
                        .iter()
                        .any(|group| group.affected && group.cve == Some(*cve))
                });
                (!in_match || !cves_matched).then_some((record.record, reason))
            }
            _ => None,
        })
        .collect();
    pairs.sort_by(|(a, _), (b, _)| a.id.cmp(&b.id));
    pairs
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
    /// The ordering of the versions of the `ECOSYSTEM` ranges of its ecosystem.
    scheme: Scheme,
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
        let (_, ecosystem, form, scheme) = ECOSYSTEMS
            .iter()
            .find(|(purl_type, _, _, _)| *purl_type == purl.purl_type)
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
            scheme: *scheme,
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

    /// Whether the version is in the range, by the OSV algorithm, in the ordering of the range (VMT-9, VMT-23).
    fn in_range(&self, range: &Range) -> Result<bool, PairReason> {
        match Scheme::of(range.kind, self.scheme) {
            Some(Scheme::Semver) => in_range::<Semver>(&self.version, &range.events),
            Some(Scheme::Pep440) => in_range::<Pep440>(&self.version, &range.events),
            Some(Scheme::Maven) => in_range::<Maven>(&self.version, &range.events),
            Some(Scheme::RubyGems) => in_range::<RubyGems>(&self.version, &range.events),
            Some(Scheme::NuGet) => in_range::<NuGet>(&self.version, &range.events),
            Some(Scheme::Packagist) => in_range::<Packagist>(&self.version, &range.events),
            None => Err(PairReason::RangeNotEvaluated),
        }
    }
}

/// Whether the version is in the range of these events, by the OSV algorithm (VMT-9): events sorted by version, then
/// `introduced`, `fixed`, `last_affected` at an equal version.
fn in_range<O: VersionOrder>(version: &str, events: &[Event]) -> Result<bool, PairReason> {
    let parse = |version: &str| O::parse(version).ok_or(PairReason::InvalidVersion);
    let version = parse(version)?;
    let mut events = events
        .iter()
        .map(|event| {
            let at = match event {
                Event::Introduced(at) if at.trim() == "0" => None,
                _ => Some(parse(event.version())?),
            };
            Ok((event, at))
        })
        .collect::<Result<Vec<_>, PairReason>>()?;
    events.sort_by(|(a_event, a), (b_event, b)| {
        compare::<O>(a.as_ref(), b.as_ref()).then(rank(a_event).cmp(&rank(b_event)))
    });
    let mut affected = false;
    for (event, at) in events {
        let order = at.map_or(Ordering::Greater, |at| O::compare(&version, &at));
        match event {
            Event::Introduced(_) if order.is_ge() => affected = true,
            Event::Fixed(_) if order.is_ge() => affected = false,
            Event::LastAffected(_) if order.is_gt() => affected = false,
            _ => {}
        }
    }
    Ok(affected)
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
fn compare<O: VersionOrder>(a: Option<&O::Key>, b: Option<&O::Key>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => O::compare(a, b),
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
