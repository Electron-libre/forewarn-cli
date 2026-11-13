//! The matching of the components of an SBOM against known vulnerabilities (`specs/vulnerability-matching.md`).

use forewarn_domain::matching::{
    ComponentReason, ComponentRef, Match, MatchReport, NotEvaluated, PairReason, Reason, RecordRef,
    RecordStatus, match_components,
};
use forewarn_domain::sbom::Component;
use forewarn_domain::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};

fn component(purl: &str) -> Component {
    let name = purl
        .split('/')
        .next_back()
        .and_then(|last| last.split('@').next())
        .unwrap_or_default();
    Component {
        name: name.into(),
        purl: Some(purl.into()),
        ..Component::default()
    }
}

fn range(kind: RangeKind, events: &[Event]) -> Range {
    Range {
        kind,
        events: events.to_vec(),
    }
}

fn introduced(version: &str) -> Event {
    Event::Introduced(version.into())
}

fn fixed(version: &str) -> Event {
    Event::Fixed(version.into())
}

fn last_affected(version: &str) -> Event {
    Event::LastAffected(version.into())
}

fn vulnerability(id: &str, ecosystem: &str, name: &str, ranges: Vec<Range>) -> Vulnerability {
    Vulnerability {
        id: id.into(),
        aliases: vec![],
        source: "RUSTSEC".into(),
        withdrawn: false,
        affected: vec![AffectedPackage {
            ecosystem: ecosystem.into(),
            name: name.into(),
            versions: vec![],
            ranges,
        }],
    }
}

fn semver(events: &[Event]) -> Vulnerability {
    vulnerability(
        "RUSTSEC-0000-0001",
        "crates.io",
        "time",
        vec![range(RangeKind::Semver, events)],
    )
}

/// Whether `pkg:cargo/time@<version>` is affected by a single semver range.
fn affects(events: &[Event], version: &str) -> bool {
    let report = match_components(
        &[component(&format!("pkg:cargo/time@{version}"))],
        &[semver(events)],
    );
    assert_eq!(report.not_evaluated(), [], "{report:?}");
    !report.matches().is_empty()
}

fn record(id: &str, source: &str) -> RecordRef {
    record_with(id, source, RecordStatus::Affects)
}

fn record_with(id: &str, source: &str, status: RecordStatus) -> RecordRef {
    RecordRef {
        id: id.into(),
        source: source.into(),
        status,
    }
}

/// A record of `crates.io` `time` with its aliases and source, affecting every version from `introduced`.
fn time_record(id: &str, source: &str, aliases: &[&str], introduced_at: &str) -> Vulnerability {
    let mut record = vulnerability(
        id,
        "crates.io",
        "time",
        vec![range(RangeKind::Semver, &[introduced(introduced_at)])],
    );
    record.source = source.into();
    record.aliases = aliases.iter().map(|alias| (*alias).into()).collect();
    record
}

fn ids(report: &MatchReport) -> Vec<(&str, &str)> {
    report
        .matches()
        .iter()
        .map(|m| (m.component.name.as_str(), m.id.as_str()))
        .collect()
}

// spec: VMT-H1
#[test]
fn reports_a_crate_in_a_vulnerable_range() {
    let mut vulnerability = semver(&[introduced("0"), fixed("0.2.23")]);
    vulnerability.id = "RUSTSEC-2020-0071".into();
    vulnerability.aliases = vec!["CVE-2020-26235".into(), "GHSA-wcg3-cvx6-7396".into()];
    let report = match_components(&[component("pkg:cargo/time@0.1.43")], &[vulnerability]);
    assert_eq!(
        report.matches(),
        [Match {
            component: ComponentRef {
                name: "time".into(),
                version: None,
                purl: Some("pkg:cargo/time@0.1.43".into()),
            },
            id: "CVE-2020-26235".into(),
            aliases: vec!["GHSA-wcg3-cvx6-7396".into(), "RUSTSEC-2020-0071".into()],
            records: vec![record("RUSTSEC-2020-0071", "RUSTSEC")],
        }]
    );
    assert_eq!(report.not_evaluated(), []);
}

// spec: VMT-H2
#[test]
fn reports_nothing_affected_and_a_component_it_could_not_evaluate() {
    let unnamed = Component {
        name: "vendored".into(),
        version: Some("1.0.0".into()),
        ..Component::default()
    };
    let report = match_components(
        &[component("pkg:cargo/time@0.2.23"), unnamed],
        &[semver(&[introduced("0"), fixed("0.2.23")])],
    );
    assert_eq!(report.matches(), []);
    assert_eq!(
        report.not_evaluated(),
        [NotEvaluated {
            component: ComponentRef {
                name: "vendored".into(),
                version: Some("1.0.0".into()),
                purl: None,
            },
            reason: Reason::Component(ComponentReason::NoPackageUrl),
        }]
    );
}

// spec: VMT-1
#[test]
fn reports_each_pair_with_the_component_and_the_vulnerability() {
    let mut time = component("pkg:cargo/time@0.1.43");
    time.version = Some("0.1.43".into());
    let report = match_components(&[time], &[semver(&[introduced("0")])]);
    let found = &report.matches()[0];
    assert_eq!(
        (
            found.component.name.as_str(),
            found.component.version.as_deref(),
            found.component.purl.as_deref()
        ),
        ("time", Some("0.1.43"), Some("pkg:cargo/time@0.1.43"))
    );
    assert_eq!(
        (found.id.as_str(), found.records.as_slice()),
        (
            "RUSTSEC-0000-0001",
            [record("RUSTSEC-0000-0001", "RUSTSEC")].as_slice()
        )
    );
}

// spec: VMT-2
#[test]
fn does_not_report_a_version_no_vulnerability_affects() {
    let report = match_components(
        &[
            component("pkg:cargo/time@0.3.0"),
            component("pkg:cargo/itoa@1.0.0"),
        ],
        &[semver(&[introduced("0"), fixed("0.2.23")])],
    );
    assert_eq!(report.matches(), []);
    assert_eq!(report.not_evaluated(), []);
}

// spec: VMT-3, VMT-10
#[test]
fn reports_apart_each_component_it_could_not_evaluate_with_its_reason() {
    let cases = [
        (
            Component {
                name: "a".into(),
                purl: Some("cargo/time@1.0.0".into()),
                ..Component::default()
            },
            ComponentReason::InvalidPackageUrl,
        ),
        (
            component("pkg:deb/debian/curl@7.0"),
            ComponentReason::UnknownEcosystem,
        ),
        (component("pkg:cargo/time"), ComponentReason::NoVersion),
    ];
    for (component, reason) in cases {
        let report = match_components(
            std::slice::from_ref(&component),
            &[semver(&[introduced("0")])],
        );
        assert_eq!(report.matches(), []);
        assert_eq!(
            report
                .not_evaluated()
                .iter()
                .map(|n| n.reason.clone())
                .collect::<Vec<_>>(),
            [Reason::Component(reason)]
        );
    }
}

// spec: VMT-10
#[test]
fn reports_a_range_it_does_not_evaluate() {
    let pypi = vulnerability(
        "PYSEC-1",
        "PyPI",
        "django",
        vec![range(
            RangeKind::Ecosystem,
            &[introduced("0"), fixed("3.0")],
        )],
    );
    let git = vulnerability(
        "GIT-1",
        "crates.io",
        "time",
        vec![range(RangeKind::Git, &[introduced("abc123")])],
    );
    let report = match_components(
        &[
            component("pkg:pypi/django@2.1"),
            component("pkg:cargo/time@1.0.0"),
        ],
        &[pypi, git],
    );
    assert_eq!(report.matches(), []);
    let reasons: Vec<(&str, Reason)> = report
        .not_evaluated()
        .iter()
        .map(|n| (n.component.name.as_str(), n.reason.clone()))
        .collect();
    assert_eq!(
        reasons,
        [
            (
                "django",
                Reason::Pair {
                    vulnerability_id: "PYSEC-1".into(),
                    reason: PairReason::RangeNotEvaluated,
                }
            ),
            (
                "time",
                Reason::Pair {
                    vulnerability_id: "GIT-1".into(),
                    reason: PairReason::RangeNotEvaluated,
                }
            ),
        ]
    );
}

// spec: VMT-10
#[test]
fn reports_a_version_that_is_not_semantic_versioning() {
    for (version, event) in [("1.0", "0"), ("1.0.0", "1.x")] {
        let report = match_components(
            &[component(&format!("pkg:cargo/time@{version}"))],
            &[semver(&[introduced(event)])],
        );
        assert_eq!(report.matches(), []);
        assert_eq!(
            report.not_evaluated()[0].reason,
            Reason::Pair {
                vulnerability_id: "RUSTSEC-0000-0001".into(),
                reason: PairReason::InvalidVersion,
            },
            "{version} {event}"
        );
    }
}

// spec: VMT-8, VMT-10
#[test]
fn matches_a_listed_version_in_every_ecosystem() {
    let mut pypi = vulnerability(
        "PYSEC-1",
        "PyPI",
        "django",
        vec![range(
            RangeKind::Ecosystem,
            &[introduced("0"), fixed("3.0")],
        )],
    );
    pypi.affected[0].versions = vec!["2.0".into(), "2.0.1".into()];
    let report = match_components(
        &[
            component("pkg:pypi/django@2.0"),
            component("pkg:pypi/django@2.0.0"),
        ],
        &[pypi],
    );
    assert_eq!(ids(&report), [("django", "PYSEC-1")]);
    assert_eq!(report.not_evaluated().len(), 1, "2.0.0 is not listed");
}

// spec: VMT-9
#[test]
fn evaluates_a_range_by_the_osv_algorithm() {
    let window = [introduced("1.0.0"), fixed("1.2.0")];
    assert!(!affects(&window, "0.9.9"));
    assert!(affects(&window, "1.0.0"));
    assert!(affects(&window, "1.1.9"));
    assert!(!affects(&window, "1.2.0"));

    let up_to = [introduced("0"), last_affected("2.0.0")];
    assert!(affects(&up_to, "0.0.1"));
    assert!(affects(&up_to, "2.0.0"));
    assert!(!affects(&up_to, "2.0.1"));

    assert!(affects(&[introduced("1.0.0")], "9.0.0"));
    assert!(affects(
        &[introduced("1.0.0"), fixed("1.0.1")],
        "1.0.1-alpha"
    ));
    assert!(affects(&[introduced("1.0.0"), fixed("1.0.1")], "v1.0.0"));
    assert!(!affects(
        &[introduced("1.0.0"), fixed("1.0.1")],
        "1.0.1+build"
    ));

    let reopened = [
        fixed("1.1.0"),
        introduced("0"),
        introduced("2.0.0"),
        fixed("2.1.0"),
    ];
    assert!(affects(&reopened, "1.0.0"));
    assert!(!affects(&reopened, "1.5.0"));
    assert!(affects(&reopened, "2.0.5"));
    assert!(!affects(&reopened, "2.1.0"));
}

// spec: VMT-9
#[test]
fn evaluates_an_ecosystem_range_of_crates_io_and_npm() {
    for (purl, ecosystem, name) in [
        ("pkg:cargo/time@0.1.0", "crates.io", "time"),
        ("pkg:npm/%40babel/core@7.0.0", "npm", "@babel/core"),
    ] {
        let vulnerability = vulnerability(
            "ID-1",
            ecosystem,
            name,
            vec![range(
                RangeKind::Ecosystem,
                &[introduced("0"), fixed("8.0.0")],
            )],
        );
        let report = match_components(&[component(purl)], &[vulnerability]);
        assert_eq!(report.matches().len(), 1, "{purl}");
    }
}

// spec: VMT-6
#[test]
fn matches_a_pypi_name_normalized() {
    let mut pypi = vulnerability("PYSEC-1", "PyPI", "django-rest", vec![]);
    pypi.affected[0].versions = vec!["1.0".into()];
    let report = match_components(&[component("pkg:pypi/Django_Rest@1.0")], &[pypi]);
    assert_eq!(report.matches().len(), 1);
}

// spec: VMT-6
#[test]
fn matches_a_nuget_name_without_regard_to_case() {
    let mut nuget = vulnerability("GHSA-1", "NuGet", "Newtonsoft.Json", vec![]);
    nuget.affected[0].versions = vec!["12.0.1".into()];
    let report = match_components(&[component("pkg:nuget/newtonsoft.json@12.0.1")], &[nuget]);
    assert_eq!(report.matches().len(), 1);
}

// spec: VMT-11
#[test]
fn does_not_match_a_component_with_a_component_reason() {
    let report = match_components(
        &[component("pkg:cargo/time")],
        &[
            semver(&[introduced("0")]),
            vulnerability(
                "GIT-1",
                "crates.io",
                "time",
                vec![range(RangeKind::Git, &[])],
            ),
        ],
    );
    assert_eq!(report.matches(), []);
    assert_eq!(
        report
            .not_evaluated()
            .iter()
            .map(|n| n.reason.clone())
            .collect::<Vec<_>>(),
        [Reason::Component(ComponentReason::NoVersion)]
    );
}

// spec: VMT-12
#[test]
fn does_not_match_a_withdrawn_vulnerability() {
    let mut withdrawn = semver(&[introduced("0")]);
    withdrawn.withdrawn = true;
    let report = match_components(&[component("pkg:cargo/time@1.0.0")], &[withdrawn]);
    assert_eq!(report.matches(), []);
    assert_eq!(report.not_evaluated(), []);
}

// spec: VMT-13
#[test]
fn orders_by_component_then_vulnerability_id() {
    let time_b = vulnerability(
        "B-1",
        "crates.io",
        "time",
        vec![range(RangeKind::Semver, &[introduced("0")])],
    );
    let time_a = vulnerability(
        "A-1",
        "crates.io",
        "time",
        vec![range(RangeKind::Semver, &[introduced("0")])],
    );
    let itoa = vulnerability(
        "C-1",
        "crates.io",
        "itoa",
        vec![range(RangeKind::Semver, &[introduced("0")])],
    );
    let report = match_components(
        &[
            component("pkg:cargo/time@1.0.0"),
            component("pkg:cargo/itoa@1.0.0"),
            component("pkg:cargo/time@2.0.0"),
        ],
        &[itoa, time_b, time_a],
    );
    assert_eq!(
        ids(&report),
        [
            ("time", "A-1"),
            ("time", "B-1"),
            ("itoa", "C-1"),
            ("time", "A-1"),
            ("time", "B-1"),
        ]
    );
}

// spec: VMT-14
#[test]
fn reports_a_vulnerability_once_per_component() {
    let mut twice = semver(&[introduced("0")]);
    twice.affected[0]
        .ranges
        .push(range(RangeKind::Semver, &[introduced("1.0.0")]));
    twice.affected.push(twice.affected[0].clone());
    twice.affected[0].versions = vec!["1.0.0".into()];
    let report = match_components(&[component("pkg:cargo/time@1.0.0")], &[twice]);
    assert_eq!(report.matches().len(), 1);
}

// spec: VMT-14
#[test]
fn reports_a_pair_once_when_its_package_is_named_apart_twice() {
    let mut apart = vulnerability(
        "RUSTSEC-0000-0001",
        "crates.io",
        "time",
        vec![range(RangeKind::Git, &[introduced("abc123")])],
    );
    let mut regex = apart.affected[0].clone();
    regex.name = "regex".into();
    apart.affected.push(regex);
    apart.affected.push(apart.affected[0].clone());
    let report = match_components(&[component("pkg:cargo/time@1.0.0")], &[apart]);
    assert_eq!(report.matches(), []);
    assert_eq!(report.not_evaluated().len(), 1);
}

// spec: VMT-4
#[test]
fn ignores_the_affected_packages_of_an_ecosystem_matching_does_not_know() {
    let mut mixed = semver(&[introduced("0")]);
    let mut debian = mixed.affected[0].clone();
    debian.ecosystem = "Debian:12".into();
    mixed.affected.insert(0, debian);
    let report = match_components(&[component("pkg:cargo/time@1.0.0")], &[mixed]);
    assert_eq!(report.matches().len(), 1);
}

// spec: VMT-9
#[test]
fn orders_events_of_an_equal_version_by_their_kind() {
    assert!(!affects(
        &[fixed("1.0.0"), introduced("1.0.0+build")],
        "1.0.0"
    ));
    assert!(!affects(
        &[introduced("1.0.0+build"), fixed("1.0.0")],
        "1.0.0"
    ));
    assert!(affects(
        &[last_affected("1.0.0"), introduced("1.0.0")],
        "1.0.0"
    ));
    assert!(affects(
        &[introduced("1.0.0"), last_affected("1.0.0")],
        "1.0.0"
    ));
}

// spec: VMT-10
#[test]
fn leaves_a_git_range_aside_when_another_range_is_evaluated() {
    let both = vulnerability(
        "RUSTSEC-0000-0001",
        "crates.io",
        "time",
        vec![
            range(RangeKind::Semver, &[introduced("0"), fixed("1.0.0")]),
            range(RangeKind::Git, &[introduced("abc123")]),
        ],
    );
    let report = match_components(&[component("pkg:cargo/time@2.0.0")], &[both]);
    assert_eq!(report.matches(), []);
    assert_eq!(report.not_evaluated(), []);
}

// spec: VMT-H3
#[test]
fn reports_a_vulnerability_known_under_several_records_once() {
    let rustsec = time_record(
        "RUSTSEC-2020-0071",
        "RUSTSEC",
        &["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
        "0",
    );
    let ghsa = time_record("GHSA-wcg3-cvx6-7396", "GHSA", &["RUSTSEC-2020-0071"], "0");
    let report = match_components(&[component("pkg:cargo/time@0.1.43")], &[rustsec, ghsa]);
    assert_eq!(
        report.matches(),
        [Match {
            component: ComponentRef {
                name: "time".into(),
                version: None,
                purl: Some("pkg:cargo/time@0.1.43".into()),
            },
            id: "CVE-2020-26235".into(),
            aliases: vec!["GHSA-wcg3-cvx6-7396".into(), "RUSTSEC-2020-0071".into()],
            records: vec![
                record("GHSA-wcg3-cvx6-7396", "GHSA"),
                record("RUSTSEC-2020-0071", "RUSTSEC"),
            ],
        }]
    );
}

// spec: VMT-15
#[test]
fn groups_records_through_another_record() {
    let report = match_components(
        &[component("pkg:cargo/time@1.0.0")],
        &[
            time_record("A-1", "A", &["B-1"], "0"),
            time_record("B-1", "B", &[], "0"),
            time_record("C-1", "C", &["B-1"], "0"),
        ],
    );
    assert_eq!(ids(&report), [("time", "A-1")]);
    assert_eq!(
        report.matches()[0].records,
        [record("A-1", "A"), record("B-1", "B"), record("C-1", "C")]
    );
}

// spec: VMT-15
#[test]
fn groups_records_of_one_component_only() {
    let time = time_record("A-1", "A", &["CVE-1"], "0");
    let mut regex = time_record("B-1", "B", &["CVE-1"], "0");
    regex.affected[0].name = "regex".into();
    let report = match_components(
        &[
            component("pkg:cargo/time@0.1.43"),
            component("pkg:cargo/regex@1.0.0"),
        ],
        &[time, regex],
    );
    assert_eq!(ids(&report), [("time", "CVE-1"), ("regex", "CVE-1")]);
    assert_eq!(report.matches()[0].records, [record("A-1", "A")]);
    assert_eq!(report.matches()[1].records, [record("B-1", "B")]);
}

// spec: VMT-16, VMT-17
#[test]
fn names_a_group_without_a_cve_by_its_first_record_id() {
    let report = match_components(
        &[component("pkg:cargo/time@1.0.0")],
        &[
            time_record(
                "RUSTSEC-2021-0001",
                "RUSTSEC",
                &["GHSA-aaaa-bbbb-cccc"],
                "0",
            ),
            time_record("GHSA-aaaa-bbbb-cccc", "GHSA", &["RUSTSEC-2021-0001"], "0"),
        ],
    );
    assert_eq!(report.matches()[0].id, "GHSA-aaaa-bbbb-cccc");
    assert_eq!(report.matches()[0].aliases, ["RUSTSEC-2021-0001"]);
}

// spec: VMT-16, VMT-17, VMT-21
#[test]
fn names_each_match_by_its_cve_and_lists_every_other_id_once() {
    let report = match_components(
        &[component("pkg:cargo/time@1.0.0")],
        &[
            time_record("B-1", "B", &["CVE-2", "A-1", "CVE-1", "A-1"], "0"),
            time_record("A-1", "A", &["CVE-2", "B-1"], "0"),
        ],
    );
    assert_eq!(ids(&report), [("time", "CVE-1"), ("time", "CVE-2")]);
    assert_eq!(report.matches()[0].aliases, ["B-1"]);
    assert_eq!(report.matches()[1].aliases, ["A-1", "B-1"]);
}

// spec: VMT-18
#[test]
fn lists_the_records_of_a_match_by_id_with_their_source() {
    let report = match_components(
        &[component("pkg:cargo/time@1.0.0")],
        &[
            time_record("Z-1", "ZED", &["A-1"], "0"),
            time_record("A-1", "AYE", &[], "0"),
        ],
    );
    assert_eq!(
        report.matches()[0].records,
        [record("A-1", "AYE"), record("Z-1", "ZED")]
    );
}

// spec: VMT-18, VMT-19
#[test]
fn groups_records_that_disagree_on_the_affected_versions() {
    let rustsec = time_record("RUSTSEC-2020-0071", "RUSTSEC", &["GHSA-1"], "0");
    let mut ghsa = time_record("GHSA-1", "GHSA", &["RUSTSEC-2020-0071"], "0");
    ghsa.affected[0].ranges = vec![range(
        RangeKind::Semver,
        &[introduced("0"), fixed("0.1.40")],
    )];
    let report = match_components(&[component("pkg:cargo/time@0.1.43")], &[rustsec, ghsa]);
    assert_eq!(ids(&report), [("time", "RUSTSEC-2020-0071")]);
    assert_eq!(
        report.matches()[0].records,
        [
            record_with("GHSA-1", "GHSA", RecordStatus::DoesNotAffect),
            record("RUSTSEC-2020-0071", "RUSTSEC")
        ]
    );
}

// spec: VMT-18, VMT-20
#[test]
fn drops_a_pair_not_evaluated_of_a_record_grouped_into_a_match() {
    let rustsec = time_record("RUSTSEC-2020-0071", "RUSTSEC", &["GHSA-1"], "0");
    let mut ghsa = time_record("GHSA-1", "GHSA", &["RUSTSEC-2020-0071"], "0");
    ghsa.affected[0].ranges = vec![range(RangeKind::Git, &[introduced("abc")])];
    let report = match_components(&[component("pkg:cargo/time@0.1.43")], &[rustsec, ghsa]);
    assert_eq!(
        report.matches()[0].records,
        [
            record_with("GHSA-1", "GHSA", RecordStatus::NotEvaluated),
            record("RUSTSEC-2020-0071", "RUSTSEC")
        ]
    );
    assert_eq!(report.not_evaluated(), []);
}

// spec: VMT-18
#[test]
fn lists_a_record_given_twice_once() {
    let rustsec = time_record("RUSTSEC-2020-0071", "RUSTSEC", &["CVE-2020-26235"], "0");
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[rustsec.clone(), rustsec],
    );
    assert_eq!(
        report.matches()[0].records,
        [record("RUSTSEC-2020-0071", "RUSTSEC")]
    );
}

/// A record of `crates.io` `time` with its aliases, fixed at 0.1.40: not affecting 0.1.43.
fn fixed_time_record(id: &str, aliases: &[&str]) -> Vulnerability {
    let mut record = time_record(id, "GHSA", aliases, "0");
    record.affected[0].ranges = vec![range(
        RangeKind::Semver,
        &[introduced("0"), fixed("0.1.40")],
    )];
    record
}

/// A record of `crates.io` `time` with its aliases whose only range is a `GIT` range: not evaluated.
fn unevaluated_time_record(id: &str, aliases: &[&str]) -> Vulnerability {
    let mut record = time_record(id, "GHSA", aliases, "0");
    record.affected[0].ranges = vec![range(RangeKind::Git, &[introduced("abc")])];
    record
}

fn record_ids(found: &Match) -> Vec<&str> {
    found.records.iter().map(|r| r.id.as_str()).collect()
}

// spec: VMT-21, VMT-17
#[test]
fn keeps_two_cves_apart_and_puts_a_record_of_both_in_each() {
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[
            time_record("RUSTSEC-A", "RUSTSEC", &["CVE-1"], "0"),
            time_record("RUSTSEC-B", "RUSTSEC", &["CVE-2"], "0"),
            time_record("GHSA-X", "GHSA", &["CVE-1", "CVE-2"], "0"),
        ],
    );
    assert_eq!(ids(&report), [("time", "CVE-1"), ("time", "CVE-2")]);
    assert_eq!(record_ids(&report.matches()[0]), ["GHSA-X", "RUSTSEC-A"]);
    assert_eq!(record_ids(&report.matches()[1]), ["GHSA-X", "RUSTSEC-B"]);
    assert_eq!(report.matches()[0].aliases, ["GHSA-X", "RUSTSEC-A"]);
    assert_eq!(report.matches()[1].aliases, ["GHSA-X", "RUSTSEC-B"]);
}

// spec: VMT-21, VMT-17
#[test]
fn puts_a_record_without_cve_bridging_two_cves_in_each() {
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[
            time_record("RUSTSEC-A", "RUSTSEC", &["CVE-1"], "0"),
            time_record("RUSTSEC-B", "RUSTSEC", &["CVE-2"], "0"),
            time_record("GHSA-Y", "GHSA", &["RUSTSEC-A", "RUSTSEC-B"], "0"),
        ],
    );
    assert_eq!(ids(&report), [("time", "CVE-1"), ("time", "CVE-2")]);
    assert_eq!(record_ids(&report.matches()[0]), ["GHSA-Y", "RUSTSEC-A"]);
    assert_eq!(record_ids(&report.matches()[1]), ["GHSA-Y", "RUSTSEC-B"]);
    assert_eq!(report.matches()[0].aliases, ["GHSA-Y", "RUSTSEC-A"]);
    assert_eq!(report.matches()[1].aliases, ["GHSA-Y", "RUSTSEC-B"]);
}

// spec: VMT-21
#[test]
fn groups_records_without_cve_through_each_other_into_a_cve() {
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[
            time_record("RUSTSEC-A", "RUSTSEC", &["CVE-1"], "0"),
            time_record("GHSA-1", "GHSA", &["RUSTSEC-A"], "0"),
            time_record("OSV-1", "OSV", &["GHSA-1"], "0"),
        ],
    );
    assert_eq!(ids(&report), [("time", "CVE-1")]);
    assert_eq!(
        record_ids(&report.matches()[0]),
        ["GHSA-1", "OSV-1", "RUSTSEC-A"]
    );
}

// spec: VMT-22
#[test]
fn lists_a_record_not_affecting_in_each_match_without_bridging_them() {
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[
            time_record("RUSTSEC-A", "RUSTSEC", &[], "0"),
            time_record("RUSTSEC-C", "RUSTSEC", &[], "0"),
            fixed_time_record("GHSA-Z", &["RUSTSEC-A", "RUSTSEC-C"]),
        ],
    );
    assert_eq!(ids(&report), [("time", "RUSTSEC-A"), ("time", "RUSTSEC-C")]);
    assert_eq!(record_ids(&report.matches()[0]), ["GHSA-Z", "RUSTSEC-A"]);
    assert_eq!(record_ids(&report.matches()[1]), ["GHSA-Z", "RUSTSEC-C"]);
    assert_eq!(report.matches()[0].aliases, Vec::<String>::new());
}

// spec: VMT-22, VMT-16
#[test]
fn never_names_a_match_by_the_cve_of_a_record_not_affecting() {
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[
            time_record("RUSTSEC-A", "RUSTSEC", &["GHSA-M"], "0"),
            fixed_time_record("GHSA-M", &["CVE-9", "RUSTSEC-A"]),
        ],
    );
    assert_eq!(ids(&report), [("time", "RUSTSEC-A")]);
    assert_eq!(report.matches()[0].aliases, ["GHSA-M"]);
    assert_eq!(record_ids(&report.matches()[0]), ["GHSA-M", "RUSTSEC-A"]);
}

// spec: VMT-22
#[test]
fn reports_nothing_for_a_record_not_affecting_alone() {
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[fixed_time_record("GHSA-M", &["CVE-9"])],
    );
    assert_eq!(report, MatchReport::default());
}

// spec: VMT-20, VMT-21
#[test]
fn reports_the_pair_of_a_record_whose_other_cve_names_no_match() {
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[
            time_record("RUSTSEC-A", "RUSTSEC", &["CVE-1"], "0"),
            unevaluated_time_record("GHSA-X", &["CVE-1", "CVE-2"]),
        ],
    );
    assert_eq!(ids(&report), [("time", "CVE-1")]);
    assert_eq!(record_ids(&report.matches()[0]), ["GHSA-X", "RUSTSEC-A"]);
    assert_eq!(
        report.not_evaluated(),
        [NotEvaluated {
            component: report.matches()[0].component.clone(),
            reason: Reason::Pair {
                vulnerability_id: "GHSA-X".into(),
                reason: PairReason::RangeNotEvaluated,
            },
        }]
    );
}

// spec: VMT-20
#[test]
fn reports_the_pair_of_a_record_in_two_unaffected_groups_once() {
    let report = match_components(
        &[component("pkg:cargo/time@0.1.43")],
        &[unevaluated_time_record("GHSA-X", &["CVE-1", "CVE-2"])],
    );
    assert_eq!(report.matches(), []);
    assert_eq!(report.not_evaluated().len(), 1);
}
