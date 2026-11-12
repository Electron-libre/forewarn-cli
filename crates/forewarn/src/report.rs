//! The report formats of `forewarn check` and `forewarn match`: adapters from the domain's results to text or JSON
//! (`specs/cli-check.md`, `specs/cli-match.md`).

use std::fmt::Write;
use std::path::Path;

use forewarn_domain::completeness::{CompletenessReport, Field};
use forewarn_domain::matching::{ComponentReason, ComponentRef, MatchReport, PairReason, Reason};
use forewarn_domain::sbom::{Sbom, SpecVersion};
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
        push_component(
            &mut text,
            &component.name,
            component.version.as_deref(),
            component.purl.as_deref(),
        );
        let missing: Vec<&str> = component.missing.iter().copied().map(field_name).collect();
        let _ = writeln!(text, ": missing {}", missing.join(", "));
    }
    text
}

/// Pushes an indented component: its name, then its version and package URL when it has them, escaped.
fn push_component(text: &mut String, name: &str, version: Option<&str>, purl: Option<&str>) {
    text.push_str("  ");
    push_escaped(text, name);
    if let Some(version) = version {
        text.push(' ');
        push_escaped(text, version);
    }
    if let Some(purl) = purl {
        text.push_str(" (");
        push_escaped(text, purl);
        text.push(')');
    }
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

/// Where the OSV records matched against came from (MCH-4).
pub enum Source<'a> {
    /// A record file or a directory the user gave with `--osv`.
    Local(&'a Path),
}

/// The text report of `forewarn match` for a person: the SBOM, the sources of the records, the matches, the
/// components and pairs not evaluated, and the count of clean components.
pub fn matching_human(sbom: &Sbom, sources: &[Source], matching: &MatchReport) -> String {
    let count = sbom.components.len();
    let mut text = format!(
        "SBOM: CycloneDX {}, {count} {}\n",
        sbom.spec_version,
        components(count)
    );
    if sources.is_empty() {
        text.push_str("OSV records: none\n");
    } else {
        text.push_str("OSV records:\n");
    }
    for source in sources {
        match source {
            Source::Local(path) => {
                text.push_str("  ");
                push_escaped(&mut text, &path.to_string_lossy());
                text.push_str(": local records\n");
            }
        }
    }
    let _ = writeln!(text, "Affected ({}):", matching.matches().len());
    for found in matching.matches() {
        push_component_ref(&mut text, &found.component);
        text.push_str(": ");
        push_escaped(&mut text, &found.vulnerability_id);
        if !found.aliases.is_empty() {
            text.push_str(" (");
            push_escaped(&mut text, &found.aliases.join(", "));
            text.push(')');
        }
        text.push_str(", source ");
        push_escaped(&mut text, &found.source);
        text.push('\n');
    }
    let _ = writeln!(text, "Not evaluated ({}):", matching.not_evaluated().len());
    for gap in matching.not_evaluated() {
        push_component_ref(&mut text, &gap.component);
        let (reason, vulnerability_id) = reason(&gap.reason);
        text.push_str(": ");
        if let Some(id) = vulnerability_id {
            push_escaped(&mut text, id);
            text.push_str(": ");
        }
        text.push_str(reason);
        text.push('\n');
    }
    let _ = writeln!(
        text,
        "Clean: {} of {count} {}",
        clean_count(sbom, matching),
        components(count)
    );
    text
}

fn push_component_ref(text: &mut String, component: &ComponentRef) {
    push_component(
        text,
        &component.name,
        component.version.as_deref(),
        component.purl.as_deref(),
    );
}

/// The JSON report of `forewarn match` for a machine: one object whose members MCH-16 lists, ending with a newline.
pub fn matching_json(sbom: &Sbom, sources: &[Source], matching: &MatchReport) -> String {
    let sources: Vec<Value> = sources
        .iter()
        .map(|source| match source {
            Source::Local(path) => json!({"kind": "local", "path": path.to_string_lossy()}),
        })
        .collect();
    let affected: Vec<Value> = matching
        .matches()
        .iter()
        .map(|found| {
            json!({
                "name": found.component.name,
                "version": found.component.version,
                "purl": found.component.purl,
                "id": found.vulnerability_id,
                "aliases": found.aliases,
                "source": found.source,
            })
        })
        .collect();
    let not_evaluated: Vec<Value> = matching
        .not_evaluated()
        .iter()
        .map(|gap| {
            let (reason, vulnerability_id) = reason(&gap.reason);
            json!({
                "name": gap.component.name,
                "version": gap.component.version,
                "purl": gap.component.purl,
                "reason": reason,
                "vulnerabilityId": vulnerability_id,
            })
        })
        .collect();
    let report = json!({
        "specVersion": sbom.spec_version.to_string(),
        "componentCount": sbom.components.len(),
        "cleanCount": clean_count(sbom, matching),
        "osv": sources,
        "affected": affected,
        "notEvaluated": not_evaluated,
    });
    format!("{report:#}\n")
}

/// The components neither affected nor named by a component or pair not evaluated (MCH-3).
fn clean_count(sbom: &Sbom, matching: &MatchReport) -> usize {
    sbom.components
        .iter()
        .map(ComponentRef::from)
        .filter(|component| {
            !matching.matches().iter().any(|m| m.component == *component)
                && !matching
                    .not_evaluated()
                    .iter()
                    .any(|gap| gap.component == *component)
        })
        .count()
}

/// The name of a reason in a report (VMT-10), and the id of the vulnerability of a pair.
fn reason(reason: &Reason) -> (&'static str, Option<&str>) {
    match reason {
        Reason::Component(reason) => (
            match reason {
                ComponentReason::NoPackageUrl => "no package URL",
                ComponentReason::InvalidPackageUrl => "invalid package URL",
                ComponentReason::UnknownEcosystem => "unknown ecosystem",
                ComponentReason::NoVersion => "no version",
            },
            None,
        ),
        Reason::Pair {
            vulnerability_id,
            reason,
        } => (
            match reason {
                PairReason::RangeNotEvaluated => "range not evaluated",
                PairReason::InvalidVersion => "invalid version",
            },
            Some(vulnerability_id),
        ),
    }
}
