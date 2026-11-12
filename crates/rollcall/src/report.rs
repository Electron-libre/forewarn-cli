//! The report formats of `rollcall check`: adapters from the domain's results to text (`specs/cli-check.md`).

use std::fmt::Write;

use rollcall_domain::completeness::{CompletenessReport, Field};
use rollcall_domain::sbom::{Sbom, SpecVersion};

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
            "Complete: {checked} components checked, none missing a supplier, a license or a hash"
        );
        return text;
    }
    let incomplete = completeness.incomplete();
    let _ = writeln!(
        text,
        "{} of {checked} components incomplete:",
        incomplete.len()
    );
    for component in incomplete {
        text.push_str("  ");
        text.push_str(&component.name);
        if let Some(version) = &component.version {
            let _ = write!(text, " {version}");
        }
        if let Some(purl) = &component.purl {
            let _ = write!(text, " ({purl})");
        }
        let missing: Vec<&str> = component.missing.iter().copied().map(field_name).collect();
        let _ = writeln!(text, ": missing {}", missing.join(", "));
    }
    text
}

/// The name of a field in a report.
pub fn field_name(field: Field) -> &'static str {
    match field {
        Field::Supplier => "supplier",
        Field::License => "license",
        Field::Hash => "hash",
    }
}
