//! The report formats of `forewarn check` and `forewarn match`: adapters from the domain's results to text or JSON
//! (`specs/cli-check.md`, `specs/cli-match.md`).

use std::collections::HashSet;
use std::fmt::Write;
use std::path::Path;

use forewarn_domain::completeness::{CompletenessReport, Field};
use forewarn_domain::matching::{ComponentReason, ComponentRef, MatchReport, PairReason, Reason};
use forewarn_domain::sbom::{Sbom, SpecVersion};
use std::time::SystemTime;

use forewarn_osv::fetch::Freshness;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::macros::format_description;

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

/// A value with its control characters escaped, for a line of standard error (MCH-23).
pub fn escaped(value: &str) -> String {
    let mut text = String::with_capacity(value.len());
    push_escaped(&mut text, value);
    text
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
    /// The archive of an ecosystem, fetched into the cache, and the number of records it held.
    Archive {
        ecosystem: &'a str,
        freshness: &'a Freshness,
        records: usize,
    },
    /// A record file or a directory the user gave with `--osv`, and the number of records it held.
    Local { path: &'a Path, records: usize },
}

/// The time of a download in RFC 3339, UTC, to the second (`2026-11-13T09:30:00Z`); `unknown` for a time a damaged
/// cache could hold that the calendar of `time` cannot write (before 1970 or after the year 9999).
fn utc(freshness: &Freshness) -> String {
    freshness
        .downloaded_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .and_then(|time| {
            time.format(format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
            ))
            .ok()
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn records(count: usize) -> &'static str {
    if count == 1 { "record" } else { "records" }
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
            Source::Archive {
                ecosystem,
                freshness,
                records: count,
            } => {
                text.push_str("  ");
                push_escaped(&mut text, ecosystem);
                let _ = write!(
                    text,
                    ": {count} {}, downloaded {} from ",
                    records(*count),
                    utc(freshness)
                );
                push_escaped(&mut text, &freshness.url);
                if let Some(last_modified) = &freshness.last_modified {
                    text.push_str(", Last-Modified ");
                    push_escaped(&mut text, last_modified);
                }
                text.push('\n');
            }
            Source::Local {
                path,
                records: count,
            } => {
                text.push_str("  ");
                push_escaped(&mut text, &path.to_string_lossy());
                let _ = writeln!(text, ": {count} {}, local", records(*count));
            }
        }
    }
    let _ = writeln!(text, "Affected ({}):", matching.matches().len());
    for found in matching.matches() {
        push_component_ref(&mut text, &found.component);
        text.push_str(": ");
        push_escaped(&mut text, &found.id);
        if !found.aliases.is_empty() {
            text.push_str(" (");
            push_escaped(&mut text, &found.aliases.join(", "));
            text.push(')');
        }
        text.push_str(", records ");
        for (i, record) in found.records.iter().enumerate() {
            if i > 0 {
                text.push_str(", ");
            }
            push_escaped(&mut text, &record.id);
            text.push_str(" from ");
            push_escaped(&mut text, &record.source);
        }
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
            Source::Archive {
                ecosystem,
                freshness,
                records,
            } => json!({
                "kind": "archive",
                "ecosystem": ecosystem,
                "url": freshness.url,
                "downloadedAt": utc(freshness),
                "lastModified": freshness.last_modified,
                "recordCount": records,
            }),
            Source::Local { path, records } => {
                json!({"kind": "local", "path": path.to_string_lossy(), "recordCount": records})
            }
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
                "id": found.id,
                "aliases": found.aliases,
                "records": found
                    .records
                    .iter()
                    .map(|record| json!({"id": record.id, "source": record.source}))
                    .collect::<Vec<Value>>(),
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
    let reported: HashSet<&ComponentRef> = matching
        .matches()
        .iter()
        .map(|found| &found.component)
        .chain(matching.not_evaluated().iter().map(|gap| &gap.component))
        .collect();
    sbom.components
        .iter()
        .filter(|component| !reported.contains(&ComponentRef::from(*component)))
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
