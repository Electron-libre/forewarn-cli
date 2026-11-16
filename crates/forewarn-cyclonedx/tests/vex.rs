//! Reading the VEX verdicts of a CycloneDX document and applying them to the matches (`specs/vex-verdicts.md`), and
//! the `bom-ref` of a component (`specs/sbom-reading.md`, SBR-16).

use forewarn_cyclonedx::{ReadError, read_json, read_vex_json};
use forewarn_domain::exploited::{ExploitedEntry, ExploitedList, flag_exploited};
use forewarn_domain::matching::match_components;
use forewarn_domain::vex::{Verdict, apply_verdicts};
use forewarn_domain::vulnerability::{AffectedPackage, Event, Range, RangeKind, Vulnerability};
use serde_json::{Value, json};

const LOG4J: &str = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";
const TEXT: &str = "pkg:maven/org.apache.commons/commons-text@1.9";

fn components() -> Value {
    json!([
        { "type": "library", "bom-ref": "log4j", "name": "log4j-core", "version": "2.14.1", "purl": LOG4J },
        { "type": "library", "bom-ref": "text", "name": "commons-text", "version": "1.9", "purl": TEXT },
    ])
}

fn document(spec_version: &str, components: Option<Value>, vulnerabilities: &Value) -> Value {
    let mut document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "vulnerabilities": vulnerabilities,
    });
    if let Some(components) = components {
        document["components"] = components;
    }
    document
}

fn sbom_verdicts(vulnerabilities: &Value) -> Vec<Verdict> {
    read_json(
        document("1.6", Some(components()), vulnerabilities)
            .to_string()
            .as_bytes(),
    )
    .expect("a valid SBOM")
    .verdicts
}

fn vex_verdicts(document: &Value) -> Result<Vec<Verdict>, ReadError> {
    read_vex_json(document.to_string().as_bytes())
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

fn maven_record(id: &str, aliases: &[&str], package: &str) -> Vulnerability {
    Vulnerability {
        id: id.into(),
        aliases: aliases.iter().map(|alias| (*alias).into()).collect(),
        source: "GHSA".into(),
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

fn records() -> Vec<Vulnerability> {
    vec![
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
    ]
}

// spec: VEX-H1, VEX-1
#[test]
fn sets_aside_the_match_the_sbom_says_not_affected_keeping_its_kev_evidence() {
    let sbom = read_json(
        document(
            "1.6",
            Some(json!([components()[0].clone()])),
            &json!([{
                "id": "CVE-2021-44228",
                "analysis": { "state": "not_affected", "justification": "code_not_reachable" },
                "affects": [{ "ref": "log4j" }],
            }]),
        )
        .to_string()
        .as_bytes(),
    )
    .expect("a valid SBOM");
    let kev = ExploitedList {
        name: "CISA KEV".into(),
        entries: vec![ExploitedEntry::new("CVE-2021-44228", None).expect("a CVE")],
    };
    let flagged = flag_exploited(match_components(&sbom.components, &records()), [&kev]);
    let report = apply_verdicts(flagged, &sbom.verdicts, &sbom.components);
    assert_eq!(report.matches(), []);
    let aside = &report.set_aside()[0];
    assert_eq!(aside.found.found.id, "CVE-2021-44228");
    assert_eq!(aside.found.evidence[0].list, "CISA KEV");
    let used = &sbom.verdicts[aside.verdict];
    assert_eq!(used.state, "not_affected");
    assert_eq!(used.justification.as_deref(), Some("code_not_reachable"));
}

// spec: VEX-H2, VEX-2
#[test]
fn applies_the_verdicts_of_a_vex_document_apart_from_the_sbom() {
    let sbom = read_json(
        json!({ "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components() })
            .to_string()
            .as_bytes(),
    )
    .expect("a valid SBOM");
    assert_eq!(sbom.verdicts, []);
    let verdicts = vex_verdicts(&document(
        "1.6",
        None,
        &json!([
            { "id": "CVE-2021-44228", "analysis": { "state": "not_affected" }, "affects": [{ "ref": "log4j" }] },
            { "id": "CVE-2022-42889", "analysis": { "state": "in_triage" }, "affects": [{ "ref": "text" }] },
        ]),
    ))
    .expect("a valid VEX document");
    let flagged = flag_exploited(match_components(&sbom.components, &records()), []);
    let report = apply_verdicts(flagged, &verdicts, &sbom.components);
    let left: Vec<&str> = report
        .matches()
        .iter()
        .map(|m| m.found.id.as_str())
        .collect();
    let aside: Vec<&str> = report
        .set_aside()
        .iter()
        .map(|a| a.found.found.id.as_str())
        .collect();
    assert_eq!(left, ["CVE-2022-42889"]);
    assert_eq!(aside, ["CVE-2021-44228"]);
}

// spec: VEX-2
#[test]
fn reads_a_vex_document_that_also_lists_components() {
    let verdicts = vex_verdicts(&document(
        "1.5",
        Some(components()),
        &json!([{ "id": "CVE-2021-44228", "analysis": { "state": "false_positive" }, "affects": [{ "ref": "log4j" }] }]),
    ))
    .expect("a valid VEX document");
    assert_eq!(
        verdicts,
        [verdict(&["CVE-2021-44228"], &["log4j"], "false_positive")]
    );
}

// spec: VEX-5
#[test]
fn maps_the_fields_of_a_verdict() {
    let verdicts = sbom_verdicts(&json!([{
        "id": "INTERNAL-1",
        "references": [
            { "id": "CVE-2021-44228", "source": { "name": "NVD" } },
            { "id": "  ", "source": { "name": "blank" } },
            { "id": "GHSA-jfh8-c2jp-5v3q", "source": { "name": "GitHub" } },
        ],
        "analysis": {
            "state": "not_affected",
            "justification": "code_not_reachable",
            "detail": "JndiLookup is removed from the classpath.",
            "response": ["will_not_fix"],
        },
        "affects": [{ "ref": "log4j" }, { "ref": " " }, { "ref": "urn:cdx:abc/1#text" }],
    }]));
    assert_eq!(
        verdicts,
        [Verdict {
            ids: vec![
                "INTERNAL-1".into(),
                "CVE-2021-44228".into(),
                "GHSA-jfh8-c2jp-5v3q".into()
            ],
            targets: vec!["log4j".into(), "urn:cdx:abc/1#text".into()],
            state: "not_affected".into(),
            justification: Some("code_not_reachable".into()),
            detail: Some("JndiLookup is removed from the classpath.".into()),
        }]
    );
}

// spec: VEX-5
#[test]
fn reads_a_state_or_a_justification_the_enumerations_do_not_list_as_written() {
    let verdicts = sbom_verdicts(&json!([{
        "id": "CVE-2021-44228",
        "analysis": { "state": "under_review", "justification": "vendor_says_so", "detail": "  " },
        "affects": [{ "ref": "log4j" }],
    }]));
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].state, "under_review");
    assert_eq!(verdicts[0].justification.as_deref(), Some("vendor_says_so"));
    assert_eq!(verdicts[0].detail, None);
}

// spec: VEX-11
#[test]
fn a_vulnerability_without_an_analysis_state_gives_no_verdict() {
    let verdicts = sbom_verdicts(&json!([
        { "id": "CVE-2021-44228", "analysis": { "state": " " }, "affects": [{ "ref": "log4j" }] },
        { "id": "CVE-2021-44228", "ratings": [{ "severity": "critical" }], "affects": [{ "ref": "log4j" }] },
        { "id": "CVE-2022-42889", "analysis": { "detail": "looking" }, "affects": [{ "ref": "text" }] },
    ]));
    assert_eq!(verdicts, []);
}

// spec: VEX-11, VEX-12
#[test]
fn a_document_of_spec_version_1_3_gives_no_verdict() {
    let document = json!({ "bomFormat": "CycloneDX", "specVersion": "1.3", "version": 1, "components": components() });
    let sbom = read_json(document.to_string().as_bytes()).expect("a valid SBOM");
    assert_eq!(sbom.verdicts, []);
    assert_eq!(vex_verdicts(&document), Ok(vec![]));
}

// spec: VEX-12
#[test]
fn refuses_a_vex_document_that_is_not_readable_cyclonedx() {
    assert_eq!(
        vex_verdicts(&json!({ "specVersion": "1.6", "vulnerabilities": [] })),
        Err(ReadError::NotCycloneDx(None))
    );
    assert!(matches!(
        read_vex_json(&b"{"[..]),
        Err(ReadError::NotJson(_))
    ));
    assert_eq!(
        vex_verdicts(&json!({ "bomFormat": "CycloneDX", "specVersion": "1.2" })),
        Err(ReadError::UnsupportedSpecVersion("1.2".into()))
    );
    assert!(matches!(
        vex_verdicts(
            &json!({ "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "vulnerabilities": "none" })
        ),
        Err(ReadError::Invalid(_))
    ));
}

// spec: SBR-16
#[test]
fn reads_the_bom_ref_of_each_component() {
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            { "type": "library", "bom-ref": "pkg:cargo/serde@1.0.228", "name": "serde" },
            { "type": "library", "name": "itoa" },
        ],
    });
    let sbom = read_json(document.to_string().as_bytes()).expect("a valid SBOM");
    let bom_refs: Vec<Option<&str>> = sbom
        .components
        .iter()
        .map(|c| c.bom_ref.as_deref())
        .collect();
    assert_eq!(bom_refs, [Some("pkg:cargo/serde@1.0.228"), None]);
}
