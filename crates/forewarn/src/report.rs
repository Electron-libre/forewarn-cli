//! The report formats of `rollcall check`: adapters from the domain's results to text or JSON (`specs/cli-check.md`).

use std::fmt::Write;

use rollcall_domain::completeness::{CompletenessReport, Field};
use rollcall_domain::sbom::{Sbom, SpecVersion};
use serde_json::{Value, json};

/// The text report for a person: the spec version, then the incomplete components or that the SBOM is complete.
pub fn human(sbom: &Sbom, completeness: &CompletenessReport) -> String {
    let mut text = format!("SBOM: CycloneDX {}", sbom.spec_version);
    if sbom.spec_version.is_below_bsi_minimum() {
        let _ = write!(
            text,
            " (below the BSI TR-03183-2 minimum, {})",
            SpecVersion::BSI_MINIMUM
        );
    }
    text.push('\n');
    let checked = sbom.components.len();
    if completeness.is_complete() {
        let _ = writeln!(
            text,
            "Complete: {checked} {} checked, none missing a supplier, a license or a hash",
            components(checked)
        );
        return text;
    }
    let incomplete = completeness.incomplete();
    let _ = writeln!(
        text,
        "{} of {checked} {} incomplete:",
        incomplete.len(),
        components(checked)
    );
    for component in incomplete {
        text.push_str("  ");
        push_escaped(&mut text, &component.name);
        if let Some(version) = &component.version {
            text.push(' ');
            push_escaped(&mut text, version);
        }
        if let Some(purl) = &component.purl {
            text.push_str(" (");
            push_escaped(&mut text, purl);
            text.push(')');
        }
        let missing: Vec<&str> = component.missing.iter().copied().map(field_name).collect();
        let _ = writeln!(text, ": missing {}", missing.join(", "));
    }
    text
}

fn components(count: usize) -> &'static str {
    if count == 1 {
        "component"
    } else {
        "components"
    }
}

/// Pushes a value read from the SBOM with its control characters escaped (`\n`, `\u{1b}`), so that it cannot
/// forge a line of the report or a terminal sequence (CHK-14).
fn push_escaped(text: &mut String, value: &str) {
    for c in value.chars() {
        if c.is_control() {
            text.extend(c.escape_default());
        } else {
            text.push(c);
        }
    }
}

/// The JSON report for a machine: one object whose members CHK-10 lists, ending with a newline.
pub fn json(sbom: &Sbom, completeness: &CompletenessReport) -> String {
    let incomplete: Vec<Value> = completeness
        .incomplete()
        .iter()
        .map(|component| {
            json!({
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
                "missing": component.missing.iter().copied().map(field_name).collect::<Vec<_>>(),
            })
        })
        .collect();
    let report = json!({
        "specVersion": sbom.spec_version.to_string(),
        "belowBsiMinimum": sbom.spec_version.is_below_bsi_minimum(),
        "componentCount": sbom.components.len(),
        "complete": completeness.is_complete(),
        "incomplete": incomplete,
    });
    format!("{report:#}\n")
}

/// The name of a field in a report.
fn field_name(field: Field) -> &'static str {
    match field {
        Field::Supplier => "supplier",
        Field::License => "license",
        Field::Hash => "hash",
    }
}
