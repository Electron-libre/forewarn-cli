//! The version orderings of the `ECOSYSTEM` ranges, observed through the matching of one component against one range
//! (`specs/vulnerability-matching.md`, VMT-23 to VMT-28).

use forewarn_domain::matching::{MatchReport, PairReason, Reason, match_components};
use forewarn_domain::sbom::Component;
use forewarn_domain::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};

/// A package of an ecosystem: its OSV ecosystem, its name there, and its package URL without a version.
#[derive(Clone, Copy)]
struct Package {
    ecosystem: &'static str,
    name: &'static str,
    purl: &'static str,
}

const PYPI: Package = Package {
    ecosystem: "PyPI",
    name: "django",
    purl: "pkg:pypi/django",
};

const MAVEN: Package = Package {
    ecosystem: "Maven",
    name: "org.apache.logging.log4j:log4j-core",
    purl: "pkg:maven/org.apache.logging.log4j/log4j-core",
};

const RUBYGEMS: Package = Package {
    ecosystem: "RubyGems",
    name: "rails",
    purl: "pkg:gem/rails",
};

const NUGET: Package = Package {
    ecosystem: "NuGet",
    name: "Newtonsoft.Json",
    purl: "pkg:nuget/Newtonsoft.Json",
};

const PACKAGIST: Package = Package {
    ecosystem: "Packagist",
    name: "laravel/framework",
    purl: "pkg:composer/laravel/framework",
};

fn introduced(version: &str) -> Event {
    Event::Introduced(version.into())
}

fn fixed(version: &str) -> Event {
    Event::Fixed(version.into())
}

fn last_affected(version: &str) -> Event {
    Event::LastAffected(version.into())
}

impl Package {
    /// The report of the component at `version` (given beside its package URL, VMT-7) matched against one
    /// `ECOSYSTEM` range of these events.
    fn report(self, version: &str, events: &[Event]) -> MatchReport {
        let component = Component {
            name: self.name.into(),
            version: Some(version.into()),
            purl: Some(self.purl.into()),
            ..Component::default()
        };
        let vulnerability = Vulnerability {
            id: "ID-1".into(),
            source: "GHSA".into(),
            affected: vec![AffectedPackage {
                ecosystem: self.ecosystem.into(),
                name: self.name.into(),
                versions: vec![],
                ranges: vec![Range {
                    kind: RangeKind::Ecosystem,
                    events: events.to_vec(),
                }],
            }],
            ..Vulnerability::default()
        };
        match_components(&[component], &[vulnerability])
    }

    /// Whether the range of these events affects the version, failing when it was not evaluated.
    fn affects(self, version: &str, events: &[Event]) -> bool {
        let report = self.report(version, events);
        assert_eq!(
            report.not_evaluated(),
            [],
            "{} {version} {events:?}",
            self.ecosystem
        );
        !report.matches().is_empty()
    }

    /// Asserts that each version orders strictly before the next one.
    fn assert_ordered(self, versions: &[&str]) {
        for pair in versions.windows(2) {
            let (lower, higher) = (pair[0], pair[1]);
            assert!(
                self.affects(lower, &[introduced("0"), fixed(higher)]),
                "{lower} < {higher}"
            );
            assert!(
                !self.affects(higher, &[introduced("0"), last_affected(lower)]),
                "{higher} > {lower}"
            );
        }
    }

    /// Asserts that two versions are equal in the ordering.
    fn assert_equal(self, a: &str, b: &str) {
        assert!(self.affects(b, &[introduced(a)]), "{b} >= {a}");
        assert!(
            self.affects(b, &[introduced("0"), last_affected(a)]),
            "{b} <= {a}"
        );
    }

    /// Asserts that the version, as the component's or as an event's, is reported invalid.
    fn assert_invalid(self, invalid: &str, valid: &str) {
        for (version, events) in [
            (invalid, vec![introduced("0"), fixed(valid)]),
            (valid, vec![introduced("0"), fixed(invalid)]),
        ] {
            let report = self.report(version, &events);
            assert_eq!(
                report.not_evaluated()[0].reason,
                Reason::Pair {
                    vulnerability_id: "ID-1".into(),
                    reason: PairReason::InvalidVersion,
                },
                "{} {version} {events:?}",
                self.ecosystem
            );
        }
    }
}

// spec: VMT-9, VMT-23, VMT-24
#[test]
fn evaluates_an_ecosystem_range_of_pypi_by_pep_440() {
    let window = [introduced("0"), fixed("3.0")];
    assert!(PYPI.affects("2.1", &window));
    assert!(!PYPI.affects("3.0.0", &window));
    assert!(!PYPI.affects("3.0.post1", &window));
    assert!(PYPI.affects("3.0rc1", &window));
    assert!(PYPI.affects("3.0.dev2", &window));
}

// spec: VMT-24
#[test]
fn orders_pypi_versions_by_pep_440() {
    PYPI.assert_ordered(&[
        "1.0.dev1",
        "1.0a1.dev1",
        "1.0a1",
        "1.0b2",
        "1.0b2.post3",
        "1.0c1",
        "1.0",
        "1.0+abc",
        "1.0+local.7",
        "1.0+7",
        "1.0.post1.dev1",
        "1.0.post1",
        "1.0.1",
        "1.10",
        "1!0.5",
    ]);
    PYPI.assert_equal("1.0-ALPHA.1", "1.0a1");
    PYPI.assert_equal("v1.0-1", "1.0.post1");
    PYPI.assert_equal("1.0.0.0", "1");
    PYPI.assert_equal("1.0_preview_2", "1.0rc2");
    PYPI.assert_equal("1.0-r", "1.0.post0");
    PYPI.assert_equal("1.0rev3", "1.0.post3");
    PYPI.assert_equal("1.0-dev", "1.0.dev0");
    PYPI.assert_equal("0!1.0", " 1.0 ");
    PYPI.assert_equal("1.0+Local-7", "1.0+local.7");
    PYPI.assert_equal("1.0.a.post1", "1.0a0.post1");
    PYPI.assert_ordered(&["99999999999999999999", "100000000000000000000"]);
}

// spec: VMT-24, VMT-10
#[test]
fn reports_a_pypi_version_pep_440_does_not_read_as_invalid() {
    for invalid in [
        "not a version",
        "1.0-",
        "1.0+",
        "1.0+a..b",
        "1..0",
        "1.0post1x",
    ] {
        PYPI.assert_invalid(invalid, "3.0");
    }
}

// spec: VMT-9, VMT-23, VMT-25
#[test]
fn evaluates_an_ecosystem_range_of_maven_by_its_ordering() {
    let window = [introduced("2.0-beta9"), fixed("2.15.0")];
    assert!(MAVEN.affects("2.14.1", &window));
    assert!(MAVEN.affects("2.0-beta9", &window));
    assert!(!MAVEN.affects("2.15.0", &window));
    assert!(!MAVEN.affects("2.0-alpha1", &window));
}

// spec: VMT-25
#[test]
fn orders_maven_versions_by_comparable_version() {
    MAVEN.assert_ordered(&[
        "1-alpha-1",
        "1-alpha-2",
        "1-beta2",
        "1-milestone",
        "1-RC1",
        "1-SNAPSHOT",
        "1",
        "1-sp",
        "1-abc",
        "1-xyz",
        "1-1",
        "1.0.1",
        "1.1",
        "1.10",
        "2",
        "99999999999999999999",
        "100000000000000000000",
    ]);
    for (a, b) in [
        ("1.0.0", "1"),
        ("1-ga", "1"),
        ("1-FINAL", "1"),
        ("1-release", "1"),
        ("1-0", "1"),
        ("1..", "1"),
        ("1-cr1", "1-rc1"),
        ("1-a1", "1-alpha-1"),
        ("1-b1", "1-beta-1"),
        ("1-m3", "1-milestone-3"),
        ("1.0-alpha", "1-alpha"),
        ("1rc1", "1-rc-1"),
        ("01.2", "1.2"),
    ] {
        MAVEN.assert_equal(a, b);
    }
    MAVEN.assert_ordered(&["1-alpha", "1-sp", "1-a", "1-b"]);
    MAVEN.assert_ordered(&["1.foo", "1-foo"]);
    MAVEN.assert_ordered(&["1-0-1", "1-1"]);
    MAVEN.assert_ordered(&["1-1", "1.0.1"]);
}

// spec: VMT-9, VMT-23, VMT-26
#[test]
fn evaluates_an_ecosystem_range_of_rubygems_by_gem_version() {
    let window = [introduced("0"), fixed("1.10")];
    assert!(RUBYGEMS.affects("1.9", &window));
    assert!(!RUBYGEMS.affects("1.10.0", &window));
    assert!(RUBYGEMS.affects("1.10.0.rc1", &window));
}

// spec: VMT-26
#[test]
fn orders_rubygems_versions_by_gem_version() {
    RUBYGEMS.assert_ordered(&[
        "1.0.B",
        "1.0.a",
        "1.0.a1",
        "1.0.b",
        "1.0-pre",
        "1.0",
        "1.0.1",
        "1.0.1.1",
        "1.2",
        "1.10",
        "99999999999999999999",
        "100000000000000000000",
    ]);
    for (a, b) in [
        ("1.0.0", "1"),
        ("1.0.0.a", "1.a"),
        ("1.0.a.0", "1.a"),
        ("1.0-rc.1", "1.0.pre.rc.1"),
        ("1.0rc1", "1.0.rc.1"),
        (" 1.0 ", "1"),
        ("01.2", "1.2"),
        ("", "0"),
        (" ", "0"),
    ] {
        RUBYGEMS.assert_equal(a, b);
    }
}

// spec: VMT-26, VMT-10
#[test]
fn reports_a_rubygems_version_gem_does_not_read_as_invalid() {
    for invalid in [
        "1.0 beta", "a1", "1a", "1.", "1..0", "1.0-", "1.0-a.", "v1.0", "1_0",
    ] {
        RUBYGEMS.assert_invalid(invalid, "2.0");
    }
}

// spec: VMT-9, VMT-23, VMT-27
#[test]
fn evaluates_an_ecosystem_range_of_nuget_by_nuget_versioning() {
    let window = [introduced("0"), fixed("13.0.1")];
    assert!(NUGET.affects("12.0.3", &window));
    assert!(!NUGET.affects("13.0.1.0", &window));
    assert!(NUGET.affects("13.0.1-beta1", &window));
}

// spec: VMT-27
#[test]
fn orders_nuget_versions_by_nuget_versioning() {
    NUGET.assert_ordered(&[
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.0.1",
        "1.0.1",
        "1.2",
        "1.10",
        "99999999999999999999",
        "100000000000000000000",
    ]);
    for (a, b) in [
        ("1.0", "1.0.0.0"),
        ("1", "1.0.0"),
        ("1.0.0-BETA", "1.0.0-beta"),
        ("1.0.0+abc", "1.0.0"),
        ("1.0.0-rc.1+build-5.x", "1.0.0-RC.1"),
        (" 1.0 ", "1.0.0"),
        ("01.2", "1.2"),
        ("1.0.0-beta.02", "1.0.0-beta.2"),
    ] {
        NUGET.assert_equal(a, b);
    }
    NUGET.assert_ordered(&["1.0.0-a.b", "1.0.0-a-b"]);
}

// spec: VMT-27, VMT-10
#[test]
fn reports_a_nuget_version_it_does_not_read_as_invalid() {
    for invalid in [
        ".",
        "v1.0",
        "1.0.0.0.0",
        "1.0.0-",
        "1.0.0+",
        "1..0",
        "1.0.",
        "1.0-beta..1",
        "1.0+a..b",
        "1.0-be_ta",
        "1.a",
        "-1.0",
    ] {
        NUGET.assert_invalid(invalid, "2.0");
    }
}

// spec: VMT-9, VMT-23, VMT-28
#[test]
fn evaluates_an_ecosystem_range_of_packagist_by_composer() {
    let window = [introduced("0"), fixed("10.2.1")];
    assert!(PACKAGIST.affects("v10.2.0", &window));
    assert!(!PACKAGIST.affects("10.2.1.0", &window));
    assert!(PACKAGIST.affects("10.2.1-RC1", &window));
}

// spec: VMT-28
#[test]
fn orders_packagist_versions_by_composer() {
    PACKAGIST.assert_ordered(&[
        "1.0-dev",
        "1.0-alpha1",
        "1.0-beta-dev",
        "1.0-beta",
        "1.0-beta2",
        "1.0-beta10",
        "1.0-RC1",
        "1.0",
        "1.0-patch1",
        "1.0.1",
        "1.0.x-dev",
        "1.1",
        "1.x-dev",
        "2.0",
        "99999",
        "20240101",
        "20240102",
    ]);
    for (a, b) in [
        ("1.0", "v1.0.0.0"),
        ("V1", "1.0.0"),
        (" 1.0 ", "1.0"),
        ("01.2", "1.2"),
        ("1.0b2", "1.0-beta.2"),
        ("1.0-BETA2", "1.0-beta2"),
        ("1.0a1", "1.0-alpha1"),
        ("1.0-rc1", "1.0-RC1"),
        ("1.0pl1", "1.0-patch1"),
        ("1.0p1", "1.0-patch1"),
        ("1.0-stable", "1.0"),
        ("1.0+build.5", "1.0"),
        ("1.0.dev", "1.0-dev"),
        ("1.0-beta1-dev", "1.0-beta.1.dev"),
        ("2024-01-01", "2024:01:01"),
    ] {
        PACKAGIST.assert_equal(a, b);
    }
}

// spec: VMT-28, VMT-10
#[test]
fn reports_a_packagist_version_composer_does_not_read_as_invalid() {
    for invalid in [
        "dev-main",
        "master",
        "1.0-foo",
        "1.0 beta",
        "1.0.0.0.0",
        "1.0+",
        "+1",
        "a1",
        "1.0 as 2.0",
        "1.0@dev",
        "12345678901234567890123",
    ] {
        PACKAGIST.assert_invalid(invalid, "2.0");
    }
}
