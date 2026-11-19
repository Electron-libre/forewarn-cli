//! The draft of the CRA early warning of each actively exploited vulnerability (`specs/early-warning-draft.md`).

use forewarn_domain::date::{Date, Moment};
use forewarn_domain::deadlines::{DeadlinePastRange, reporting_deadlines};
use forewarn_domain::early_warning::{EarlyWarning, ToComplete, draft_early_warnings};
use forewarn_domain::exploited::{
    Evidence, ExploitedEntry, ExploitedList, FlaggedReport, flag_exploited,
};
use forewarn_domain::matching::match_components;
use forewarn_domain::sbom::{Component, Product};
use forewarn_domain::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};

/// A Maven component `group:name` at `version`.
fn component(group: &str, name: &str, version: &str) -> Component {
    Component {
        name: name.into(),
        version: Some(version.into()),
        purl: Some(format!("pkg:maven/{group}/{name}@{version}")),
        ..Component::default()
    }
}

/// A record affecting every version of the Maven package `group:name`.
fn record(id: &str, aliases: &[&str], package: &str) -> Vulnerability {
    Vulnerability {
        id: id.into(),
        aliases: aliases.iter().map(|alias| (*alias).into()).collect(),
        source: id.split('-').next().unwrap_or_default().into(),
        withdrawn: false,
        affected: vec![AffectedPackage {
            ecosystem: "Maven".into(),
            name: package.into(),
            versions: vec![],
            ranges: vec![Range {
                kind: RangeKind::Ecosystem,
                events: vec![Event::Introduced("0".into())],
            }],
        }],
    }
}

fn date(year: u16, month: u8, day: u8) -> Date {
    Date::new(year, month, day).unwrap()
}

fn at(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Moment {
    Moment::new(date(year, month, day), hour, minute, second).unwrap()
}

fn list(name: &str, entries: &[(&str, Option<Date>)]) -> ExploitedList {
    ExploitedList {
        name: name.into(),
        entries: entries
            .iter()
            .map(|(cve, added)| ExploitedEntry::new(cve, *added).unwrap())
            .collect(),
    }
}

fn kev() -> ExploitedList {
    list(
        "CISA KEV",
        &[
            ("CVE-2021-44228", Some(date(2021, 12, 10))),
            ("CVE-2022-0778", Some(date(2022, 3, 15))),
        ],
    )
}

fn product(name: &str, version: Option<&str>, manufacturer: Option<&str>) -> Product {
    Product {
        name: name.into(),
        version: version.map(Into::into),
        manufacturer: manufacturer.map(Into::into),
        ..Product::default()
    }
}

fn shop() -> Product {
    product("shop", Some("2.1.0"), Some("Acme"))
}

/// `log4j-core` affected by `CVE-2021-44228`.
fn log4j_report(lists: &[ExploitedList]) -> FlaggedReport {
    flag_exploited(
        match_components(
            &[component(
                "org.apache.logging.log4j",
                "log4j-core",
                "2.14.1",
            )],
            &[record(
                "GHSA-jfh8-c2jp-5v3q",
                &["CVE-2021-44228"],
                "org.apache.logging.log4j:log4j-core",
            )],
        ),
        lists,
    )
}

/// `log4j-core` and `log4j-api` affected by `CVE-2021-44228`, `openssl` by `CVE-2022-0778` and `zlib` by
/// `CVE-2018-25032`, in the order `log4j-core`, `openssl`, `log4j-api`, `zlib`.
fn four_matches(lists: &[ExploitedList]) -> FlaggedReport {
    flag_exploited(
        match_components(
            &[
                component("org.apache.logging.log4j", "log4j-core", "2.14.1"),
                component("org.openssl", "openssl", "3.0.1"),
                component("org.apache.logging.log4j", "log4j-api", "2.14.1"),
                component("net.zlib", "zlib", "1.2.11"),
            ],
            &[
                record(
                    "GHSA-jfh8-c2jp-5v3q",
                    &["CVE-2021-44228"],
                    "org.apache.logging.log4j:log4j-core",
                ),
                record(
                    "GHSA-0000-0000-0001",
                    &["CVE-2021-44228"],
                    "org.apache.logging.log4j:log4j-api",
                ),
                record(
                    "GHSA-0000-0000-0002",
                    &["CVE-2022-0778"],
                    "org.openssl:openssl",
                ),
                record("GHSA-0000-0000-0003", &["CVE-2018-25032"], "net.zlib:zlib"),
            ],
        ),
        lists,
    )
}

fn aware() -> Moment {
    at(2026, 11, 13, 9, 30, 0)
}

fn draft(report: &FlaggedReport, product: Option<&Product>) -> Vec<EarlyWarning> {
    draft_early_warnings(report, product, |_| aware(), None).unwrap()
}

fn component_names(warning: &EarlyWarning) -> Vec<&str> {
    warning
        .components
        .iter()
        .map(|affected| affected.component.name.as_str())
        .collect()
}

// spec: EWD-H1, EWD-1, EWD-3, EWD-4, EWD-5, EWD-6, EWD-7
#[test]
fn drafts_the_early_warning_of_an_exploited_match() {
    let report = log4j_report(&[kev()]);
    let warnings = draft(&report, Some(&shop()));
    assert_eq!(warnings.len(), 1);
    let warning = &warnings[0];
    assert_eq!(warning.product_name.as_deref(), Some("shop"));
    assert_eq!(warning.product_version.as_deref(), Some("2.1.0"));
    assert_eq!(warning.manufacturer.as_deref(), Some("Acme"));
    assert_eq!(component_names(warning), ["log4j-core"]);
    let affected = &warning.components[0];
    assert_eq!(affected.component.version.as_deref(), Some("2.14.1"));
    assert_eq!(
        affected.component.purl.as_deref(),
        Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    );
    assert_eq!(affected.vulnerability, report.matches()[0].found.id);
    assert_eq!(warning.cve, "CVE-2021-44228");
    assert_eq!(
        warning.evidence,
        [Evidence {
            list: "CISA KEV".into(),
            cve: "CVE-2021-44228".into(),
            added: Some(date(2021, 12, 10)),
            record: None,
        }]
    );
    assert_eq!(warning.aware_since, aware());
    assert_eq!(warning.measure_available, None);
    assert_eq!(
        warning.deadlines.early_warning.to_string(),
        "2026-11-14T09:30:00Z"
    );
    assert_eq!(
        warning.deadlines.notification.to_string(),
        "2026-11-16T09:30:00Z"
    );
    assert_eq!(warning.deadlines.final_report, None);
    assert_eq!(
        warning.to_complete,
        [
            ToComplete::Title,
            ToComplete::Summary,
            ToComplete::MemberStates
        ]
    );
}

// spec: EWD-H2, EWD-1, EWD-2, EWD-3
#[test]
fn drafts_one_early_warning_per_exploited_cve_listing_its_components() {
    let warnings = draft(&four_matches(&[kev()]), Some(&shop()));
    let drafted: Vec<_> = warnings
        .iter()
        .map(|warning| (warning.cve.as_str(), component_names(warning)))
        .collect();
    assert_eq!(
        drafted,
        [
            ("CVE-2021-44228", vec!["log4j-core", "log4j-api"]),
            ("CVE-2022-0778", vec!["openssl"]),
        ]
    );
}

// spec: EWD-4
#[test]
fn drafts_each_cve_from_its_own_moment_of_awareness() {
    let known = at(2026, 11, 13, 9, 30, 0);
    let found = at(2026, 11, 16, 8, 0, 0);
    let warnings = draft_early_warnings(
        &four_matches(&[kev()]),
        Some(&shop()),
        |cve| {
            if cve == "CVE-2021-44228" {
                known
            } else {
                found
            }
        },
        None,
    )
    .unwrap();
    let drafted: Vec<_> = warnings
        .iter()
        .map(|warning| {
            (
                warning.cve.as_str(),
                warning.aware_since.to_string(),
                warning.deadlines.early_warning.to_string(),
            )
        })
        .collect();
    assert_eq!(
        drafted,
        [
            (
                "CVE-2021-44228",
                "2026-11-13T09:30:00Z".to_owned(),
                "2026-11-14T09:30:00Z".to_owned()
            ),
            (
                "CVE-2022-0778",
                "2026-11-16T08:00:00Z".to_owned(),
                "2026-11-17T08:00:00Z".to_owned()
            ),
        ]
    );
}

// spec: EWD-2
#[test]
fn drafts_nothing_for_matches_no_list_names() {
    assert_eq!(draft(&four_matches(&[]), Some(&shop())), []);
    let unrelated = list("CISA KEV", &[("CVE-1999-0001", None)]);
    assert_eq!(draft(&four_matches(&[unrelated]), Some(&shop())), []);
}

// spec: EWD-3
#[test]
fn names_a_component_listed_twice_once() {
    let log4j = component("org.apache.logging.log4j", "log4j-core", "2.14.1");
    let report = flag_exploited(
        match_components(
            &[log4j.clone(), log4j],
            &[record(
                "GHSA-jfh8-c2jp-5v3q",
                &["CVE-2021-44228"],
                "org.apache.logging.log4j:log4j-core",
            )],
        ),
        &[kev()],
    );
    assert_eq!(report.matches().len(), 2);
    assert_eq!(
        component_names(&draft(&report, Some(&shop()))[0]),
        ["log4j-core"]
    );
}

// spec: EWD-3
#[test]
fn names_a_component_listed_twice_under_two_bom_refs_once() {
    let log4j = component("org.apache.logging.log4j", "log4j-core", "2.14.1");
    let at = |bom_ref: &str| Component {
        bom_ref: Some(bom_ref.into()),
        ..log4j.clone()
    };
    let report = flag_exploited(
        match_components(
            &[
                at("pkg:maven/x?package-id=1"),
                at("pkg:maven/x?package-id=2"),
            ],
            &[record(
                "GHSA-jfh8-c2jp-5v3q",
                &["CVE-2021-44228"],
                "org.apache.logging.log4j:log4j-core",
            )],
        ),
        &[kev()],
    );
    assert_eq!(
        component_names(&draft(&report, Some(&shop()))[0]),
        ["log4j-core"]
    );
}

// spec: EWD-1
#[test]
fn drafts_nothing_for_a_report_with_no_match() {
    let report = flag_exploited(match_components(&[], &[]), &[kev()]);
    assert_eq!(draft(&report, Some(&shop())), []);
}

// spec: EWD-4
#[test]
fn computes_the_final_report_deadline_from_the_measure() {
    let measure = at(2026, 11, 15, 17, 0, 0);
    let warnings = draft_early_warnings(
        &log4j_report(&[kev()]),
        Some(&shop()),
        |_| aware(),
        Some(measure),
    )
    .unwrap();
    let warning = &warnings[0];
    assert_eq!(warning.measure_available, Some(measure));
    assert_eq!(
        warning
            .deadlines
            .final_report
            .map(|due| due.to_string())
            .as_deref(),
        Some("2026-11-29T17:00:00Z")
    );
    assert_eq!(
        warning.deadlines,
        reporting_deadlines(aware(), Some(measure)).unwrap()
    );
}

// spec: EWD-6, EWD-9
#[test]
fn lists_the_fields_of_an_sbom_naming_no_product_to_complete() {
    let warning = &draft(&log4j_report(&[kev()]), None)[0];
    assert_eq!(warning.product_name, None);
    assert_eq!(warning.product_version, None);
    assert_eq!(warning.manufacturer, None);
    assert_eq!(
        warning.to_complete,
        [
            ToComplete::Title,
            ToComplete::Summary,
            ToComplete::MemberStates,
            ToComplete::ProductName,
            ToComplete::ProductVersion,
        ]
    );
}

// spec: EWD-6, EWD-9
#[test]
fn lists_the_version_and_manufacturer_a_product_lacks_to_complete() {
    let bare = product("shop", None, None);
    let warning = &draft(&log4j_report(&[kev()]), Some(&bare))[0];
    assert_eq!(warning.product_name.as_deref(), Some("shop"));
    assert_eq!(
        warning.to_complete,
        [
            ToComplete::Title,
            ToComplete::Summary,
            ToComplete::MemberStates,
            ToComplete::ProductVersion,
        ]
    );
}

// spec: EWD-10
#[test]
fn reads_a_blank_value_of_the_product_as_absent() {
    let blank = product(" ", Some("\t"), Some("  "));
    let warning = &draft(&log4j_report(&[kev()]), Some(&blank))[0];
    assert_eq!(warning.product_name, None);
    assert_eq!(warning.product_version, None);
    assert_eq!(warning.manufacturer, None);
    assert_eq!(
        warning.to_complete,
        [
            ToComplete::Title,
            ToComplete::Summary,
            ToComplete::MemberStates,
            ToComplete::ProductName,
            ToComplete::ProductVersion,
        ]
    );
}

// spec: EWD-3, EWD-7
#[test]
fn takes_the_cve_of_the_evidence_in_upper_case() {
    let report = flag_exploited(
        match_components(
            &[component(
                "org.apache.logging.log4j",
                "log4j-core",
                "2.14.1",
            )],
            &[record(
                "GHSA-jfh8-c2jp-5v3q",
                &["cve-2021-44228"],
                "org.apache.logging.log4j:log4j-core",
            )],
        ),
        &[kev()],
    );
    let warning = &draft(&report, Some(&shop()))[0];
    assert_eq!(warning.cve, "CVE-2021-44228");
    assert_eq!(
        warning.components[0].vulnerability,
        report.matches()[0].found.id
    );
}

// spec: EWD-8
#[test]
fn takes_the_euvd_id_among_the_aliases() {
    let report = |log4j_aliases: &[&str], api_aliases: &[&str]| {
        flag_exploited(
            match_components(
                &[
                    component("org.apache.logging.log4j", "log4j-core", "2.14.1"),
                    component("org.apache.logging.log4j", "log4j-api", "2.14.1"),
                ],
                &[
                    record(
                        "GHSA-jfh8-c2jp-5v3q",
                        log4j_aliases,
                        "org.apache.logging.log4j:log4j-core",
                    ),
                    record(
                        "GHSA-0000-0000-0001",
                        api_aliases,
                        "org.apache.logging.log4j:log4j-api",
                    ),
                ],
            ),
            &[kev()],
        )
    };
    let euvd = |report: &FlaggedReport| draft(report, Some(&shop()))[0].euvd.clone();
    let cve = "CVE-2021-44228";
    assert_eq!(
        euvd(&report(&[cve, "euvd-2021-1234"], &[cve])).as_deref(),
        Some("euvd-2021-1234")
    );
    assert_eq!(euvd(&report(&[cve], &[cve])), None);
    assert_eq!(
        euvd(&report(&[cve], &[cve, "EUVD-2021-1234"])).as_deref(),
        Some("EUVD-2021-1234")
    );
}

// spec: EWD-8
#[test]
fn takes_the_euvd_id_from_the_record_of_the_evidence_first() {
    let euvd_id = |record_id: &str| {
        let euvd = ExploitedList {
            name: "EUVD".into(),
            entries: vec![
                ExploitedEntry::new("CVE-2021-44228", None)
                    .unwrap()
                    .with_record(record_id),
            ],
        };
        let report = flag_exploited(
            match_components(
                &[component(
                    "org.apache.logging.log4j",
                    "log4j-core",
                    "2.14.1",
                )],
                &[record(
                    "GHSA-jfh8-c2jp-5v3q",
                    &["CVE-2021-44228", "EUVD-2021-9999"],
                    "org.apache.logging.log4j:log4j-core",
                )],
            ),
            &[kev(), euvd],
        );
        draft(&report, Some(&shop()))[0].euvd.clone()
    };

    assert_eq!(euvd_id("EUVD-2021-0001").as_deref(), Some("EUVD-2021-0001"));
    assert_eq!(euvd_id("euvd-2021-0001").as_deref(), Some("euvd-2021-0001"));
    assert_eq!(euvd_id("GSD-2021-0001").as_deref(), Some("EUVD-2021-9999"));
}

// spec: EWD-5
#[test]
fn carries_the_evidence_of_every_list_naming_the_match() {
    let euvd = list("EUVD", &[("CVE-2021-44228", Some(date(2021, 12, 11)))]);
    let warning = &draft(&log4j_report(&[kev(), euvd]), Some(&shop()))[0];
    let lists: Vec<_> = warning.evidence.iter().map(|e| e.list.as_str()).collect();
    assert_eq!(lists, ["CISA KEV", "EUVD"]);
}

// spec: EWD-11
#[test]
fn refuses_a_deadline_past_the_year_9999() {
    let late = at(9999, 12, 30, 0, 0, 1);
    assert_eq!(
        draft_early_warnings(&log4j_report(&[kev()]), Some(&shop()), |_| late, None),
        Err(DeadlinePastRange(late))
    );
    assert_eq!(
        draft_early_warnings(&log4j_report(&[]), Some(&shop()), |_| late, None),
        Ok(vec![])
    );
}
