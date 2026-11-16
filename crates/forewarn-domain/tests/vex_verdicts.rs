//! The application of the VEX verdicts to the matches (`specs/vex-verdicts.md`).

use forewarn_domain::exploited::{ExploitedEntry, ExploitedList, FlaggedReport, flag_exploited};
use forewarn_domain::matching::match_components;
use forewarn_domain::sbom::Component;
use forewarn_domain::vex::{Verdict, apply_verdicts};
use forewarn_domain::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};

const LOG4J: &str = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
const TEXT: &str = "pkg:maven/org.apache.commons/commons-text@1.9";

fn component(purl: &str, bom_ref: Option<&str>) -> Component {
    let name = purl
        .split('/')
        .next_back()
        .and_then(|last| last.split('@').next())
        .unwrap_or_default();
    Component {
        name: name.into(),
        purl: Some(purl.into()),
        bom_ref: bom_ref.map(Into::into),
        ..Component::default()
    }
}

/// A record affecting every version of the Maven package `group:name`.
fn maven_record(id: &str, aliases: &[&str], package: &str) -> Vulnerability {
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

/// `log4j-core` (`bom-ref` `log4j`) matched by `CVE-2021-44228`, which CISA KEV names, and `commons-text`
/// (`bom-ref` `text`) by `CVE-2022-42889`.
fn components() -> Vec<Component> {
    vec![
        component(LOG4J, Some("log4j")),
        component(TEXT, Some("text")),
    ]
}

fn flagged(components: &[Component]) -> FlaggedReport {
    let kev = ExploitedList {
        name: "CISA KEV".into(),
        entries: vec![ExploitedEntry::new("CVE-2021-44228", None).expect("a CVE")],
    };
    flag_exploited(
        match_components(
            components,
            &[
                maven_record(
                    "GHSA-jfh8-c2jp-5v3q",
                    &["CVE-2021-44228"],
                    "org.apache.logging.log4j:log4j-core",
                ),
                maven_record(
                    "GHSA-599f-7c49-w659",
                    &["CVE-2022-42889"],
                    "org.apache.commons:commons-text",
                ),
            ],
        ),
        [&kev],
    )
}

fn verdict(ids: &[&str], targets: &[&str], state: &str) -> Verdict {
    Verdict {
        ids: ids.iter().map(|id| (*id).into()).collect(),
        targets: targets.iter().map(|target| (*target).into()).collect(),
        state: state.into(),
        justification: None,
        detail: None,
    }
}

/// The ids of the matches left, then those of the matches set aside with the index of their verdict.
fn applied(verdicts: &[Verdict]) -> (Vec<String>, Vec<(String, usize)>) {
    applied_to(&components(), verdicts)
}

fn applied_to(
    components: &[Component],
    verdicts: &[Verdict],
) -> (Vec<String>, Vec<(String, usize)>) {
    let report = apply_verdicts(flagged(components), verdicts, components);
    (
        report
            .matches()
            .iter()
            .map(|left| left.found.id.clone())
            .collect(),
        report
            .set_aside()
            .iter()
            .map(|aside| (aside.found.found.id.clone(), aside.verdict))
            .collect(),
    )
}

// spec: VEX-3, VEX-5
#[test]
fn sets_aside_a_match_a_not_affected_verdict_names_with_its_verdict_and_evidence() {
    let mut not_affected = verdict(&["CVE-2021-44228"], &["log4j"], "not_affected");
    not_affected.justification = Some("code_not_reachable".into());
    let report = apply_verdicts(flagged(&components()), &[not_affected], &components());
    assert_eq!(report.set_aside().len(), 1);
    let aside = &report.set_aside()[0];
    assert_eq!(aside.found.found.id, "CVE-2021-44228");
    assert_eq!(aside.found.evidence.len(), 1, "the KEV evidence is kept");
    assert_eq!(aside.found.evidence[0].list, "CISA KEV");
    assert_eq!(aside.verdict, 0);
    let ids: Vec<&str> = report
        .matches()
        .iter()
        .map(|m| m.found.id.as_str())
        .collect();
    assert_eq!(ids, ["CVE-2022-42889"]);
    assert_eq!(report.exploited_count(), 0);
}

// spec: VEX-4
#[test]
fn keeps_a_match_no_verdict_names_or_a_verdict_keeps() {
    for state in ["exploitable", "in_triage"] {
        let (left, aside) = applied(&[verdict(&["CVE-2021-44228"], &["log4j"], state)]);
        assert_eq!(left, ["CVE-2021-44228", "CVE-2022-42889"], "{state}");
        assert_eq!(aside, [], "{state}");
    }
}

// spec: VEX-8
#[test]
fn sets_aside_or_keeps_by_the_state_of_the_table() {
    for (state, sets_aside) in [
        ("not_affected", true),
        ("false_positive", true),
        ("resolved", true),
        ("resolved_with_pedigree", true),
        ("exploitable", false),
        ("in_triage", false),
        ("unknown_state", false),
        ("NOT_AFFECTED", false),
    ] {
        let (_, aside) = applied(&[verdict(&["CVE-2022-42889"], &["text"], state)]);
        assert_eq!(!aside.is_empty(), sets_aside, "{state}");
    }
}

// spec: VEX-8
#[test]
fn sets_aside_a_match_no_list_names_with_no_evidence() {
    let report = apply_verdicts(
        flagged(&components()),
        &[verdict(&["CVE-2022-42889"], &["text"], "not_affected")],
        &components(),
    );
    assert_eq!(report.set_aside().len(), 1);
    assert_eq!(report.set_aside()[0].found.evidence, []);
}

// spec: VEX-6
#[test]
fn names_a_match_by_its_id_or_an_alias_a_cve_in_any_case() {
    let (_, aside) = applied(&[verdict(&["cve-2021-44228"], &["log4j"], "not_affected")]);
    assert_eq!(aside, [("CVE-2021-44228".to_owned(), 0)]);
    let (_, aside) = applied(&[verdict(
        &["GHSA-jfh8-c2jp-5v3q"],
        &["log4j"],
        "not_affected",
    )]);
    assert_eq!(aside, [("CVE-2021-44228".to_owned(), 0)], "an alias");
    let (_, aside) = applied(&[verdict(
        &["GHSA-JFH8-C2JP-5V3Q"],
        &["log4j"],
        "not_affected",
    )]);
    assert_eq!(aside, [], "only a CVE id is compared in upper case");
}

// spec: VEX-6
#[test]
fn names_a_match_by_any_of_its_ids() {
    let (_, aside) = applied(&[verdict(
        &["INTERNAL-1", "CVE-2021-44228"],
        &["log4j"],
        "not_affected",
    )]);
    assert_eq!(aside, [("CVE-2021-44228".to_owned(), 0)]);
}

// spec: VEX-7
#[test]
fn names_the_component_by_its_bom_ref() {
    let (left, aside) = applied(&[verdict(&["CVE-2021-44228"], &["text"], "not_affected")]);
    assert_eq!(aside, [], "the bom-ref of another component");
    assert_eq!(left.len(), 2);
    let (_, aside) = applied(&[verdict(
        &["CVE-2021-44228"],
        &["other", "log4j"],
        "not_affected",
    )]);
    assert_eq!(aside.len(), 1, "any of its targets");
}

// spec: VEX-7
#[test]
fn names_the_component_of_a_bom_link_by_its_bom_ref_whatever_the_serial_number() {
    let components = [
        component(LOG4J, Some("pkg:maven/log4j")),
        component(TEXT, None),
    ];
    let (_, aside) = applied_to(
        &components,
        &[verdict(
            &["CVE-2021-44228"],
            &["urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg%3Amaven%2Flog4j"],
            "not_affected",
        )],
    );
    assert_eq!(aside, [("CVE-2021-44228".to_owned(), 0)]);
}

// spec: VEX-7
#[test]
fn names_by_its_package_url_a_component_when_the_target_is_no_bom_ref() {
    let opaque = [
        component(LOG4J, Some("pkg:maven/x?package-id=1")),
        component(TEXT, Some("pkg:maven/y?package-id=2")),
    ];
    let (_, aside) = applied_to(
        &opaque,
        &[verdict(&["CVE-2021-44228"], &[LOG4J], "not_affected")],
    );
    assert_eq!(aside, [("CVE-2021-44228".to_owned(), 0)]);
    // A component whose bom-ref is the target is the only one it names.
    let mut shadowing = opaque.to_vec();
    shadowing.push(component("pkg:maven/acme/app@1.0", Some(LOG4J)));
    let (_, aside) = applied_to(
        &shadowing,
        &[verdict(&["CVE-2021-44228"], &[LOG4J], "not_affected")],
    );
    assert_eq!(aside, []);
}

// spec: VEX-7
#[test]
fn names_by_its_package_url_a_component_when_the_bom_ref_of_a_bom_link_is_no_bom_ref() {
    let opaque = [
        component(LOG4J, Some("pkg:maven/x?package-id=1")),
        component(TEXT, Some("pkg:maven/y?package-id=2")),
    ];
    let link = format!(
        "urn:cdx:abc/1#{}",
        LOG4J
            .replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40")
    );
    let (_, aside) = applied_to(
        &opaque,
        &[verdict(&["CVE-2021-44228"], &[&link], "not_affected")],
    );
    assert_eq!(aside, [("CVE-2021-44228".to_owned(), 0)]);
}

// spec: VEX-9
#[test]
fn keeps_a_match_one_of_its_verdicts_keeps_in_either_order() {
    let aside = verdict(&["CVE-2021-44228"], &["log4j"], "not_affected");
    let keeps = verdict(&["CVE-2021-44228"], &["log4j"], "exploitable");
    for verdicts in [[aside.clone(), keeps.clone()], [keeps, aside]] {
        let (left, set_aside) = applied(&verdicts);
        assert_eq!(set_aside, []);
        assert_eq!(left.len(), 2);
    }
}

// spec: VEX-9
#[test]
fn sets_aside_with_the_first_of_its_verdicts() {
    let (_, aside) = applied(&[
        verdict(&["CVE-2022-42889"], &["text"], "in_triage"),
        verdict(&["CVE-2021-44228"], &["log4j"], "false_positive"),
        verdict(&["CVE-2021-44228"], &["log4j"], "not_affected"),
    ]);
    assert_eq!(aside, [("CVE-2021-44228".to_owned(), 1)]);
}

// spec: VEX-10
#[test]
fn keeps_the_order_of_the_matches() {
    let (_, aside) = applied(&[
        verdict(&["CVE-2022-42889"], &["text"], "not_affected"),
        verdict(&["CVE-2021-44228"], &["log4j"], "not_affected"),
    ]);
    assert_eq!(
        aside,
        [
            ("CVE-2021-44228".to_owned(), 1),
            ("CVE-2022-42889".to_owned(), 0)
        ]
    );
}

// spec: VEX-13
#[test]
fn applying_no_verdict_leaves_the_report_unchanged() {
    let report = flagged(&components());
    assert_eq!(apply_verdicts(report.clone(), &[], &components()), report);
}

#[test]
fn tells_the_verdicts_that_name_no_match() {
    let report = apply_verdicts(
        flagged(&components()),
        &[
            verdict(&["CVE-2021-44228"], &["log4j"], "exploitable"),
            verdict(&["CVE-2021-44228"], &["missing"], "not_affected"),
            verdict(&["CVE-1999-0001"], &["log4j"], "not_affected"),
        ],
        &components(),
    );
    assert_eq!(report.unused_verdicts(), [1, 2]);
}
