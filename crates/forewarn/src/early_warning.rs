//! The written form of the draft CRA early warning: an adapter from the domain's [`EarlyWarning`] to a Markdown
//! document a person copies into the ENISA Single Reporting Platform form, with the numbers, names and order of the
//! CRA SRP glossary 1.6 (`specs/early-warning-draft.md`, EWD-12 to EWD-16, ADR 0012, ADR 0013). A change of the
//! glossary touches this module, not the domain.

use std::fmt::Write;

use forewarn_domain::early_warning::{AffectedComponent, EarlyWarning, ToComplete};

/// The mark of a field the vendor completes (EWD-13).
const TO_COMPLETE: &str = "**TO COMPLETE**";

const TITLE: &str = "2. Title";
const SUMMARY: &str = "3. Summary";
const MANUFACTURER: &str = "4. Manufacturer name";
const MEMBER_STATES: &str = "5. Member States where product available";
const PRODUCT_NAME: &str = "6. Product Name";
const PRODUCT_VERSION: &str = "7. Product Version";
const COMPONENT: &str = "12. Component name";
const CVE: &str = "v19. CVE ID";
const EUVD: &str = "v20. EUVD ID";
const MEASURE: &str = "v22. Date the corrective or mitigating measure became available";
const AWARE: &str = "v26. Date and time aware of the AEV";

/// The draft as a Markdown document: its title, the fields to complete, the deadlines, the evidence, then the fields
/// of the glossary (EWD-12).
pub fn markdown(draft: &EarlyWarning) -> String {
    let mut text = String::from("# Draft CRA early warning: ");
    push_escaped(&mut text, &draft.cve);
    text.push_str("\n\nTo complete before entering it into the ENISA Single Reporting Platform: ");
    if draft.to_complete.is_empty() {
        text.push_str("nothing");
    } else {
        let labels: Vec<&str> = draft
            .to_complete
            .iter()
            .map(|&field| label(field))
            .collect();
        text.push_str(&labels.join(", "));
    }
    text.push_str(".\n");

    push_deadlines(&mut text, draft);
    push_evidence(&mut text, draft);
    push_fields(&mut text, draft);
    text
}

/// The glossary label of a field to complete (EWD-14).
fn label(field: ToComplete) -> &'static str {
    match field {
        ToComplete::Title => TITLE,
        ToComplete::Summary => SUMMARY,
        ToComplete::MemberStates => MEMBER_STATES,
        ToComplete::ProductName => PRODUCT_NAME,
        ToComplete::ProductVersion => PRODUCT_VERSION,
    }
}

/// Pushes the moment of awareness and the deadlines computed from it (EWD-4, EWD-15).
fn push_deadlines(text: &mut String, draft: &EarlyWarning) {
    let deadlines = &draft.deadlines;
    let _ = write!(
        text,
        "\n## Reporting deadlines (CRA article 14(2))\n\n\
         - Aware since: {}\n\
         - Early warning due by: {}\n\
         - Notification due by: {}\n",
        draft.aware_since, deadlines.early_warning, deadlines.notification
    );
    match deadlines.final_report {
        Some(final_report) => {
            let _ = writeln!(text, "- Final report due by: {final_report}");
        }
        None => text.push_str(
            "- Final report due: 14 days after a corrective or mitigating measure is available\n",
        ),
    }
}

/// Pushes the evidence of exploitation, a list item per list naming the vulnerability (EWD-5).
fn push_evidence(text: &mut String, draft: &EarlyWarning) {
    text.push_str("\n## Evidence of active exploitation\n\n");
    for evidence in &draft.evidence {
        text.push_str("- ");
        push_escaped(text, &evidence.list);
        text.push_str(": ");
        push_escaped(text, &evidence.cve);
        if let Some(added) = evidence.added {
            let _ = write!(text, ", added {added}");
        }
        text.push('\n');
    }
}

/// Pushes the fields of the early warning, in the order of the glossary (EWD-14).
fn push_fields(text: &mut String, draft: &EarlyWarning) {
    text.push_str("\n## Fields of the early warning (ENISA CRA SRP glossary 1.6)\n\n");
    push_field(text, TITLE, None);
    push_field(text, SUMMARY, None);
    push_label(text, MANUFACTURER);
    if let Some(manufacturer) = &draft.manufacturer {
        push_escaped(text, manufacturer);
        text.push_str(" (filled by the platform from your registration: compare)\n");
    } else {
        text.push_str("not in the SBOM (filled by the platform from your registration)\n");
    }
    push_field(text, MEMBER_STATES, None);
    push_field(text, PRODUCT_NAME, draft.product_name.as_deref());
    push_field(text, PRODUCT_VERSION, draft.product_version.as_deref());
    let _ = writeln!(text, "- **{COMPONENT}**:");
    for affected in &draft.components {
        push_component(text, affected);
    }
    push_field(text, CVE, Some(&draft.cve));
    push_label(text, EUVD);
    match &draft.euvd {
        Some(euvd) => push_escaped(text, euvd),
        None => text.push_str("none known"),
    }
    text.push('\n');
    push_label(text, MEASURE);
    match draft.measure_available {
        Some(measure) => {
            let _ = write!(text, "{measure}");
        }
        None => text.push_str("none given"),
    }
    text.push('\n');
    push_label(text, AWARE);
    let _ = writeln!(text, "{}", draft.aware_since);
}

fn push_label(text: &mut String, label: &str) {
    let _ = write!(text, "- **{label}**: ");
}

/// Pushes a field holding `value`, escaped, or marked to complete when `None` (EWD-13).
fn push_field(text: &mut String, label: &str, value: Option<&str>) {
    push_label(text, label);
    match value {
        Some(value) => push_escaped(text, value),
        None => text.push_str(TO_COMPLETE),
    }
    text.push('\n');
}

/// Pushes the nested item of an affected component: its name, version, package URL and match id (EWD-14).
fn push_component(text: &mut String, affected: &AffectedComponent) {
    let component = &affected.component;
    text.push_str("  - ");
    push_escaped(text, &component.name);
    if let Some(version) = &component.version {
        text.push(' ');
        push_escaped(text, version);
    }
    if let Some(purl) = &component.purl {
        text.push_str(", ");
        push_escaped(text, purl);
    }
    text.push_str(", match ");
    push_escaped(text, &affected.vulnerability);
    text.push('\n');
}

/// Pushes a value of the SBOM or of a feed so that Markdown reads it as its text: a backslash before each ASCII
/// punctuation character, each control character written as its escape (`\n`, `\u{1b}`), itself escaped (EWD-16).
fn push_escaped(text: &mut String, value: &str) {
    let mut push = |c: char| {
        if c.is_ascii_punctuation() {
            text.push('\\');
        }
        text.push(c);
    };
    for c in value.chars() {
        if c.is_control() {
            c.escape_default().for_each(&mut push);
        } else {
            push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::markdown;
    use forewarn_domain::date::{Date, Moment};
    use forewarn_domain::deadlines::reporting_deadlines;
    use forewarn_domain::early_warning::{AffectedComponent, EarlyWarning, ToComplete};
    use forewarn_domain::exploited::Evidence;
    use forewarn_domain::matching::ComponentRef;

    fn date(year: u16, month: u8, day: u8) -> Date {
        Date::new(year, month, day).unwrap()
    }

    fn moment(year: u16, month: u8, day: u8, hour: u8, minute: u8) -> Moment {
        Moment::new(date(year, month, day), hour, minute, 0).unwrap()
    }

    /// The draft of EWD-H1: `shop` `2.1.0` by `Acme`, `log4j-core` `2.14.1` matched to `CVE-2021-44228`, which
    /// CISA KEV names since `2021-12-10`, aware at `2026-11-13T09:30:00Z`.
    fn log4shell() -> EarlyWarning {
        let aware_since = moment(2026, 11, 13, 9, 30);
        EarlyWarning {
            product_name: Some("shop".to_owned()),
            product_version: Some("2.1.0".to_owned()),
            manufacturer: Some("Acme".to_owned()),
            components: vec![AffectedComponent {
                component: ComponentRef {
                    name: "log4j-core".to_owned(),
                    version: Some("2.14.1".to_owned()),
                    purl: Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1".to_owned()),
                },
                vulnerability: "GHSA-jfh8-c2jp-5v3q".to_owned(),
            }],
            cve: "CVE-2021-44228".to_owned(),
            euvd: None,
            evidence: vec![Evidence {
                list: "CISA KEV".to_owned(),
                cve: "CVE-2021-44228".to_owned(),
                added: Some(date(2021, 12, 10)),
            }],
            aware_since,
            measure_available: None,
            deadlines: reporting_deadlines(aware_since, None).unwrap(),
            to_complete: vec![
                ToComplete::Title,
                ToComplete::Summary,
                ToComplete::MemberStates,
            ],
        }
    }

    fn field<'a>(text: &'a str, label: &str) -> &'a str {
        let start = format!("- **{label}**: ");
        text.lines()
            .find_map(|line| line.strip_prefix(start.as_str()))
            .unwrap_or_else(|| panic!("no field {label} in\n{text}"))
    }

    // spec: EWD-H3, EWD-12, EWD-13, EWD-14, EWD-15 (internal: no command writes a draft before cli_draft_early_warnings)
    #[test]
    fn the_draft_gives_the_deadlines_the_evidence_then_the_fields_of_the_glossary() {
        assert_eq!(
            markdown(&log4shell()),
            "# Draft CRA early warning: CVE\\-2021\\-44228\n\
             \n\
             To complete before entering it into the ENISA Single Reporting Platform: 2. Title, 3. Summary, \
             5. Member States where product available.\n\
             \n\
             ## Reporting deadlines (CRA article 14(2))\n\
             \n\
             - Aware since: 2026-11-13T09:30:00Z\n\
             - Early warning due by: 2026-11-14T09:30:00Z\n\
             - Notification due by: 2026-11-16T09:30:00Z\n\
             - Final report due: 14 days after a corrective or mitigating measure is available\n\
             \n\
             ## Evidence of active exploitation\n\
             \n\
             - CISA KEV: CVE\\-2021\\-44228, added 2021-12-10\n\
             \n\
             ## Fields of the early warning (ENISA CRA SRP glossary 1.6)\n\
             \n\
             - **2. Title**: **TO COMPLETE**\n\
             - **3. Summary**: **TO COMPLETE**\n\
             - **4. Manufacturer name**: Acme (filled by the platform from your registration: compare)\n\
             - **5. Member States where product available**: **TO COMPLETE**\n\
             - **6. Product Name**: shop\n\
             - **7. Product Version**: 2\\.1\\.0\n\
             - **12. Component name**:\n  \
               - log4j\\-core 2\\.14\\.1, pkg\\:maven\\/org\\.apache\\.logging\\.log4j\\/log4j\\-core\\@2\\.14\\.1, \
             match GHSA\\-jfh8\\-c2jp\\-5v3q\n\
             - **v19. CVE ID**: CVE\\-2021\\-44228\n\
             - **v20. EUVD ID**: none known\n\
             - **v22. Date the corrective or mitigating measure became available**: none given\n\
             - **v26. Date and time aware of the AEV**: 2026-11-13T09:30:00Z\n"
        );
    }

    // spec: EWD-13, EWD-14 (internal: no command writes a draft before cli_draft_early_warnings)
    #[test]
    fn a_draft_with_no_product_marks_its_name_and_version_to_complete() {
        let mut draft = log4shell();
        draft.product_name = None;
        draft.product_version = None;
        draft.manufacturer = None;
        draft
            .to_complete
            .extend([ToComplete::ProductName, ToComplete::ProductVersion]);
        let text = markdown(&draft);
        assert_eq!(field(&text, "6. Product Name"), "**TO COMPLETE**");
        assert_eq!(field(&text, "7. Product Version"), "**TO COMPLETE**");
        assert_eq!(
            field(&text, "4. Manufacturer name"),
            "not in the SBOM (filled by the platform from your registration)"
        );
        assert!(text.contains(
            "Platform: 2. Title, 3. Summary, 5. Member States where product available, 6. Product Name, \
             7. Product Version.\n"
        ));
    }

    // spec: EWD-14, EWD-15 (internal: no command writes a draft before cli_draft_early_warnings)
    #[test]
    fn a_draft_gives_its_euvd_id_and_the_measure_when_known() {
        let mut draft = log4shell();
        let measure = moment(2026, 11, 15, 17, 0);
        draft.euvd = Some("EUVD-2021-1234".to_owned());
        draft.measure_available = Some(measure);
        draft.deadlines = reporting_deadlines(draft.aware_since, Some(measure)).unwrap();
        let text = markdown(&draft);
        assert_eq!(field(&text, "v20. EUVD ID"), "EUVD\\-2021\\-1234");
        assert_eq!(
            field(
                &text,
                "v22. Date the corrective or mitigating measure became available"
            ),
            "2026-11-15T17:00:00Z"
        );
        assert!(text.contains("\n- Final report due by: 2026-11-29T17:00:00Z\n"));
    }

    // spec: EWD-14 (internal: no command writes a draft before cli_draft_early_warnings)
    #[test]
    fn a_component_with_no_version_nor_purl_gives_its_name_and_match() {
        let mut draft = log4shell();
        draft.components[0].component.version = None;
        draft.components[0].component.purl = None;
        assert!(markdown(&draft).contains(
            "- **12. Component name**:\n  - log4j\\-core, match GHSA\\-jfh8\\-c2jp\\-5v3q\n"
        ));
    }

    // spec: EWD-16 (internal: no command writes a draft before cli_draft_early_warnings)
    #[test]
    fn a_value_of_the_sbom_forges_no_markdown() {
        let mut draft = log4shell();
        draft.components[0].component.name = "a|b*c_[x](y)<i>".to_owned();
        draft.product_name = Some("shop\n# Title\u{1b}".to_owned());
        let text = markdown(&draft);
        assert!(text.contains("  - a\\|b\\*c\\_\\[x\\]\\(y\\)\\<i\\> 2\\.14\\.1, "));
        assert_eq!(
            field(&text, "6. Product Name"),
            "shop\\\\n\\# Title\\\\u\\{1b\\}"
        );
        assert!(!text.lines().any(|line| line.starts_with("# Title")));
    }
}
