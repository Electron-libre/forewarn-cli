//! Reading an OSV record file into a domain vulnerability (`specs/osv-reading.md`).

use std::fs;
use std::path::{Path, PathBuf};

use forewarn_domain::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};
use forewarn_osv::{Cause, ReadError, read_record};
use serde_json::{Value, json};
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Writes `text` to a file `name` of a new temporary directory, kept alive by the returned guard.
fn file(name: &str, text: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("a temporary directory");
    let path = dir.path().join(name);
    fs::write(&path, text).expect("the file is written");
    (dir, path)
}

fn read_value(record: &Value) -> Result<Vulnerability, ReadError> {
    let (_dir, path) = file("record.json", &record.to_string());
    read_record(&path)
}

fn record(affected: &Value) -> Value {
    json!({
        "id": "RUSTSEC-2099-0001",
        "modified": "2026-11-12T00:00:00Z",
        "affected": affected,
    })
}

fn package(ecosystem: &str, name: &str, ranges: &Value) -> Value {
    json!({ "package": { "ecosystem": ecosystem, "name": name }, "ranges": ranges })
}

fn semver(events: Vec<Event>) -> Range {
    Range {
        kind: RangeKind::Semver,
        events,
    }
}

fn introduced(version: &str) -> Event {
    Event::Introduced(version.to_owned())
}

fn fixed(version: &str) -> Event {
    Event::Fixed(version.to_owned())
}

fn last_affected(version: &str) -> Event {
    Event::LastAffected(version.to_owned())
}

// spec: OSR-H1, OSR-1, OSR-4
#[test]
fn a_crates_io_advisory_is_read_with_its_alias_source_and_ranges() {
    let vulnerability =
        read_record(&fixture("RUSTSEC-2020-0071.json")).expect("the record is read");

    let mut events = vec![introduced("0.0.0-0"), fixed("0.2.0")];
    for patch in 1..=6 {
        events.push(introduced(&format!("0.2.{patch}-0")));
        events.push(fixed(&format!("0.2.{patch}")));
    }
    events.extend([introduced("0.2.7-0"), fixed("0.2.23")]);
    assert_eq!(
        vulnerability,
        Vulnerability {
            id: "RUSTSEC-2020-0071".to_owned(),
            aliases: vec![
                "CVE-2020-26235".to_owned(),
                "GHSA-wcg3-cvx6-7396".to_owned()
            ],
            source: "RUSTSEC".to_owned(),
            withdrawn: false,
            affected: vec![AffectedPackage {
                ecosystem: "crates.io".to_owned(),
                name: "time".to_owned(),
                versions: Vec::new(),
                ranges: vec![semver(events)],
            }],
        }
    );
}

// spec: OSR-4
#[test]
fn an_npm_advisory_keeps_its_packages_versions_and_last_affected_events_in_order() {
    let vulnerability =
        read_record(&fixture("GHSA-35jh-r3h4-6jhm.json")).expect("the record is read");

    assert_eq!(vulnerability.id, "GHSA-35jh-r3h4-6jhm");
    assert_eq!(vulnerability.source, "GHSA");
    assert_eq!(vulnerability.aliases, ["CVE-2021-23337"]);
    let packages: Vec<(&str, &str)> = vulnerability
        .affected
        .iter()
        .map(|p| (p.ecosystem.as_str(), p.name.as_str()))
        .collect();
    assert_eq!(
        packages,
        [
            ("npm", "lodash"),
            ("npm", "lodash-es"),
            ("npm", "lodash.template"),
            ("npm", "lodash-template"),
            ("RubyGems", "lodash-rails"),
        ]
    );
    assert_eq!(
        vulnerability.affected[2].ranges,
        [semver(vec![introduced("0"), last_affected("4.5.0")])]
    );
    let gem = &vulnerability.affected[4];
    assert_eq!(gem.versions.len(), 55);
    assert_eq!(gem.versions.first().map(String::as_str), Some("0.10.0"));
    assert_eq!(gem.versions.last().map(String::as_str), Some("4.6.1"));
    assert_eq!(
        gem.ranges,
        [Range {
            kind: RangeKind::Ecosystem,
            events: vec![introduced("0"), fixed("4.17.21")],
        }]
    );
}

// spec: OSR-4
#[test]
fn a_crates_io_record_carries_its_last_affected_event() {
    let vulnerability =
        read_record(&fixture("GHSA-2226-4v3c-cff8.json")).expect("the record is read");

    assert_eq!(vulnerability.aliases, ["RUSTSEC-2022-0004"]);
    assert_eq!(vulnerability.affected.len(), 1);
    assert_eq!(vulnerability.affected[0].name, "rustc-serialize");
    assert_eq!(
        vulnerability.affected[0].ranges,
        [semver(vec![introduced("0"), last_affected("0.3.24")])]
    );
}

// spec: OSR-4
#[test]
fn an_id_without_a_dash_is_its_own_source_and_absent_lists_are_empty() {
    let vulnerability =
        read_value(&json!({ "id": "OSV2099", "modified": "x" })).expect("the record is read");

    assert_eq!(
        vulnerability,
        Vulnerability {
            id: "OSV2099".to_owned(),
            source: "OSV2099".to_owned(),
            ..Vulnerability::default()
        }
    );
}

// spec: OSR-4
#[test]
fn a_git_range_is_read_with_its_kind() {
    let vulnerability = read_value(&record(&json!([package(
        "crates.io",
        "a",
        &json!([{ "type": "GIT", "repo": "https://example.com/a", "events": [{ "introduced": "0" }, { "fixed": "abc123" }] }]),
    )])))
    .expect("the record is read");

    assert_eq!(
        vulnerability.affected[0].ranges,
        [Range {
            kind: RangeKind::Git,
            events: vec![introduced("0"), fixed("abc123")],
        }]
    );
}

// spec: OSR-5
#[test]
fn an_affected_entry_without_a_package_is_skipped() {
    let vulnerability = read_value(&record(&json!([
        { "ranges": [{ "type": "GIT", "repo": "https://example.com/a", "events": [{ "introduced": "0" }] }] },
        package("crates.io", "kept", &json!([])),
    ])))
    .expect("the record is read");

    let names: Vec<&str> = vulnerability
        .affected
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names, ["kept"]);
}

// spec: OSR-5
#[test]
fn a_limit_event_and_the_fields_not_read_are_skipped() {
    let mut document = record(&json!([package(
        "crates.io",
        "a",
        &json!([{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "limit": "2.0.0" }], "database_specific": { "x": 1 } }]),
    )]));
    document["severity"] = json!([{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N" }]);
    document["database_specific"] = json!({ "anything": [1, 2] });
    document["future_field"] = json!({ "nested": true });

    let vulnerability = read_value(&document).expect("the record is read");

    assert_eq!(
        vulnerability.affected[0].ranges,
        [semver(vec![introduced("0")])]
    );
}

// spec: OSR-6
#[test]
fn a_withdrawn_record_is_kept_flagged_withdrawn() {
    let vulnerability =
        read_record(&fixture("GHSA-286m-6pg9-v42v.json")).expect("the record is read");

    assert!(vulnerability.withdrawn);
    assert_eq!(vulnerability.affected[0].name, "shlex");
}

// spec: OSR-6
#[test]
fn a_record_without_withdrawn_is_not_withdrawn() {
    let vulnerability = read_value(&record(&json!([]))).expect("the record is read");

    assert!(!vulnerability.withdrawn);
}

// spec: OSR-8, OSR-9
#[test]
fn a_schema_version_of_another_major_is_refused_quoting_it() {
    let mut document = record(&json!([]));
    document["schema_version"] = json!("2.0.0");

    let error = read_value(&document).expect_err("the record is refused");

    assert_eq!(
        error.cause,
        Cause::UnsupportedSchemaVersion("2.0.0".to_owned())
    );
    assert!(
        error
            .to_string()
            .contains("unsupported schema version \"2.0.0\"")
    );
}

// spec: OSR-8
#[test]
fn a_schema_version_of_major_one_is_read() {
    for version in ["1.7.4", "1.9.0", "1"] {
        let mut document = record(&json!([]));
        document["schema_version"] = json!(version);

        assert!(read_value(&document).is_ok(), "{version} is read");
    }
}

// spec: OSR-9
#[test]
fn an_unknown_range_type_is_an_invalid_record() {
    let error = read_value(&record(&json!([package(
        "crates.io",
        "a",
        &json!([{ "type": "CALVER", "events": [{ "introduced": "0" }] }]),
    )])))
    .expect_err("the record is refused");

    assert!(matches!(error.cause, Cause::Invalid(_)), "{error}");
    assert!(error.to_string().contains("invalid OSV record"), "{error}");
}

// spec: OSR-9
#[test]
fn a_record_without_a_string_id_is_invalid() {
    for document in [json!({ "modified": "x" }), json!({ "id": 7 })] {
        let error = read_value(&document).expect_err("the record is refused");

        assert!(
            matches!(error.cause, Cause::Invalid(_)),
            "{document}: {error}"
        );
    }
}

// spec: OSR-9
#[test]
fn a_field_of_the_wrong_type_is_an_invalid_record() {
    for document in [
        json!({ "id": "A-1", "aliases": "CVE-1" }),
        json!({ "id": "A-1", "affected": [{ "package": { "ecosystem": "npm", "name": 3 } }] }),
        json!({ "id": "A-1", "affected": [package("npm", "a", &json!([{ "type": "SEMVER", "events": [{ "fixed": 1 }] }]))] }),
        json!({ "id": "A-1", "withdrawn": 5 }),
    ] {
        let error = read_value(&document).expect_err("the record is refused");

        assert!(
            matches!(error.cause, Cause::Invalid(_)),
            "{document}: {error}"
        );
    }
}

// spec: OSR-9
#[test]
fn a_file_that_is_not_json_is_refused_naming_it() {
    let (_dir, path) = file("broken.json", "{ not json");

    let error = read_record(&path).expect_err("the file is refused");

    assert!(matches!(error.cause, Cause::NotJson(_)), "{error}");
    assert_eq!(error.path, path);
    let message = error.to_string();
    assert!(message.contains("broken.json"), "{message}");
    assert!(message.contains("not JSON"), "{message}");
}

// spec: OSR-9
#[test]
fn a_missing_file_cannot_be_read_and_is_named() {
    let dir = TempDir::new().expect("a temporary directory");
    let path = dir.path().join("absent.json");

    let error = read_record(&path).expect_err("the file is refused");

    assert!(matches!(error.cause, Cause::Io(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains("absent.json"), "{message}");
    assert!(message.contains("cannot read the input"), "{message}");
}

// spec: OSR-9
#[test]
fn an_event_of_an_unknown_kind_is_an_invalid_record() {
    for events in [
        json!([{ "introduced": "0" }, { "fixed_in": "1.2.0" }]),
        json!([{ "introduced": "0" }, {}]),
    ] {
        let error = read_value(&record(&json!([package(
            "crates.io",
            "a",
            &json!([{ "type": "SEMVER", "events": events }]),
        )])))
        .expect_err("the record is refused");

        assert!(
            matches!(error.cause, Cause::Invalid(_)),
            "{events}: {error}"
        );
    }
}

// spec: OSR-9
#[test]
fn a_field_that_appears_twice_is_an_invalid_record() {
    let (_dir, path) = file("record.json", r#"{"id":"A-1","id":"B-2"}"#);

    let error = read_record(&path).expect_err("the record is refused");

    assert!(matches!(error.cause, Cause::Invalid(_)), "{error}");
}

// spec: OSR-9
#[test]
fn a_shape_error_reports_its_position() {
    let (_dir, path) = file("record.json", r#"{"id":"A-1","aliases":"CVE-1"}"#);

    let error = read_record(&path).expect_err("the record is refused");

    assert!(error.to_string().contains("column"), "{error}");
}

// spec: OSR-8, OSR-9
#[test]
fn an_unsupported_schema_version_comes_before_a_shape_error() {
    let error = read_value(&json!({ "id": 7, "schema_version": "2.0.0" }))
        .expect_err("the record is refused");

    assert_eq!(
        error.cause,
        Cause::UnsupportedSchemaVersion("2.0.0".to_owned())
    );
}

// spec: OSR-5, OSR-8
#[test]
fn a_schema_version_or_a_limit_that_is_not_a_string_is_ignored() {
    let mut document = record(&json!([package(
        "crates.io",
        "a",
        &json!([{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "limit": 7 }] }]),
    )]));
    document["schema_version"] = json!(1);

    let vulnerability = read_value(&document).expect("the record is read");

    assert_eq!(
        vulnerability.affected[0].ranges,
        [semver(vec![introduced("0")])]
    );
}

// spec: OSR-4
#[test]
fn a_null_withdrawn_is_not_withdrawn() {
    let mut document = record(&json!([]));
    document["withdrawn"] = Value::Null;

    assert!(!read_value(&document).expect("the record is read").withdrawn);
}

// spec: OSR-4
#[test]
fn an_id_opening_with_a_dash_is_its_own_source() {
    let vulnerability = read_value(&json!({ "id": "-2099-1" })).expect("the record is read");

    assert_eq!(vulnerability.source, "-2099-1");
}
