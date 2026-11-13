//! The report formats of `forewarn check` and `forewarn match`: adapters from the domain's results to text or JSON
//! (`specs/cli-check.md`, `specs/cli-match.md`).

use std::collections::HashSet;
use std::fmt::Write;
use std::path::Path;

use forewarn_domain::completeness::{CompletenessReport, Field};
use forewarn_domain::exploited::{Evidence, FlaggedMatch, FlaggedReport};
use forewarn_domain::matching::{ComponentReason, ComponentRef, PairReason, Reason, RecordStatus};
use forewarn_domain::sbom::{Sbom, SpecVersion};
use std::time::SystemTime;

use forewarn_domain::date::Date;
use forewarn_domain::exploited::ExploitedList;
use forewarn_osv::api::QueryFreshness;
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
    /// The OSV API, queried with `--osv-api`, and the number of records it named.
    Api {
        freshness: &'a QueryFreshness,
        records: usize,
    },
    /// A record file or a directory the user gave with `--osv`, and the number of records it held.
    Local { path: &'a Path, records: usize },
}

/// An exploited list the matches are flagged against, and where it came from (MCH-33).
pub struct ExploitedSource<'a> {
    pub list: &'a ExploitedList,
    /// The version and the release date of a catalog that gives them (CISA KEV); none for EUVD.
    pub release: Option<(&'a str, Date)>,
    pub origin: Origin<'a>,
}

/// Where an exploited list came from.
pub enum Origin<'a> {
    /// A file the user gave (`--kev`, `--euvd`).
    Local(&'a Path),
    /// Fetched into the cache, with the freshness of its download.
    Fetched(&'a Freshness),
}

/// A time of a download or of a query in RFC 3339, UTC, to the second (`2026-11-13T09:30:00Z`); `unknown` for a time
/// the calendar of `time` cannot write (before 1970 or after the year 9999), which a damaged cache or a clock set
/// wrong could give.
fn utc(time: SystemTime) -> String {
    time.duration_since(SystemTime::UNIX_EPOCH)
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

fn entries(count: usize) -> &'static str {
    if count == 1 { "entry" } else { "entries" }
}

/// The text report of `forewarn match` for a person: the SBOM, the sources of the records and the exploited lists,
/// the matches with the evidence of those actively exploited, the components and pairs not evaluated, and the count
/// of clean components.
pub fn matching_human(
    sbom: &Sbom,
    sources: &[Source],
    exploited: &[ExploitedSource],
    matching: &FlaggedReport,
) -> String {
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
        push_source(&mut text, source);
    }
    if exploited.is_empty() {
        text.push_str("Exploited lists: none, no match flagged\n");
    } else {
        text.push_str("Exploited lists:\n");
    }
    for source in exploited {
        push_exploited_source(&mut text, source);
    }
    let _ = writeln!(
        text,
        "Affected ({}, {} actively exploited):",
        matching.matches().len(),
        matching.exploited_count()
    );
    for flagged in matching.matches() {
        let found = &flagged.found;
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
            match record.status {
                RecordStatus::Affects => {}
                RecordStatus::DoesNotAffect => text.push_str(" (does not affect)"),
                RecordStatus::NotEvaluated => text.push_str(" (not evaluated)"),
            }
        }
        text.push('\n');
        if flagged.is_exploited() {
            push_evidence(&mut text, &flagged.evidence);
        }
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

/// Pushes a source of OSV records with its record count and freshness (MCH-4, MCH-22, MCH-26).
fn push_source(text: &mut String, source: &Source) {
    match source {
        Source::Archive {
            ecosystem,
            freshness,
            records: count,
        } => {
            text.push_str("  ");
            push_escaped(text, ecosystem);
            let _ = write!(text, ": {count} {}, ", records(*count));
            push_download(text, freshness);
            text.push('\n');
        }
        Source::Api {
            freshness,
            records: count,
        } => {
            let _ = write!(
                text,
                "  OSV API: {count} {}, queried {} from ",
                records(*count),
                utc(freshness.queried_at)
            );
            push_escaped(text, &freshness.url);
            text.push('\n');
        }
        Source::Local {
            path,
            records: count,
        } => {
            text.push_str("  ");
            push_escaped(text, &path.to_string_lossy());
            let _ = writeln!(text, ": {count} {}, local", records(*count));
        }
    }
}

/// Pushes an exploited list with its catalog's version and release date when it gives them, its entry count and where
/// it came from (MCH-33).
fn push_exploited_source(text: &mut String, source: &ExploitedSource) {
    text.push_str("  ");
    push_escaped(text, &source.list.name);
    text.push_str(": ");
    if let Some((version, released)) = source.release {
        text.push_str("catalog ");
        push_escaped(text, version);
        let _ = write!(text, " released {released}, ");
    }
    let count = source.list.entries.len();
    let _ = write!(text, "{count} {}, ", entries(count));
    match source.origin {
        Origin::Local(path) => {
            text.push_str("local ");
            push_escaped(text, &path.to_string_lossy());
        }
        Origin::Fetched(freshness) => push_download(text, freshness),
    }
    text.push('\n');
}

/// Pushes when and where a copy was downloaded, and its `Last-Modified` when the server sent one (MCH-4, MCH-33).
fn push_download(text: &mut String, freshness: &Freshness) {
    let _ = write!(text, "downloaded {} from ", utc(freshness.downloaded_at));
    push_escaped(text, &freshness.url);
    if let Some(last_modified) = &freshness.last_modified {
        text.push_str(", Last-Modified ");
        push_escaped(text, last_modified);
    }
}

/// Pushes the line marking a match actively exploited, with each list naming it (MCH-29).
fn push_evidence(text: &mut String, evidence: &[Evidence]) {
    text.push_str("    actively exploited: ");
    for (i, named) in evidence.iter().enumerate() {
        if i > 0 {
            text.push_str("; ");
        }
        push_escaped(text, &named.list);
        text.push(' ');
        push_escaped(text, &named.cve);
        if let Some(added) = named.added {
            let _ = write!(text, " added {added}");
        }
    }
    text.push('\n');
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
pub fn matching_json(
    sbom: &Sbom,
    sources: &[Source],
    exploited: &[ExploitedSource],
    matching: &FlaggedReport,
) -> String {
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
                "downloadedAt": utc(freshness.downloaded_at),
                "lastModified": freshness.last_modified,
                "recordCount": records,
            }),
            Source::Api { freshness, records } => json!({
                "kind": "api",
                "url": freshness.url,
                "queriedAt": utc(freshness.queried_at),
                "recordCount": records,
            }),
            Source::Local { path, records } => {
                json!({"kind": "local", "path": path.to_string_lossy(), "recordCount": records})
            }
        })
        .collect();
    let exploited_lists: Vec<Value> = exploited.iter().map(exploited_list_json).collect();
    let affected: Vec<Value> = matching.matches().iter().map(match_json).collect();
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
        "exploitedLists": exploited_lists,
        "exploitedCount": matching.exploited_count(),
        "affected": affected,
        "notEvaluated": not_evaluated,
    });
    format!("{report:#}\n")
}

/// An exploited list in the JSON report (MCH-16).
fn exploited_list_json(source: &ExploitedSource) -> Value {
    let mut list = json!({
        "name": source.list.name,
        "version": source.release.map(|(version, _)| version),
        "released": source.release.map(|(_, released)| released.to_string()),
        "entryCount": source.list.entries.len(),
    });
    match source.origin {
        Origin::Local(path) => {
            list["kind"] = json!("local");
            list["path"] = json!(path.to_string_lossy());
        }
        Origin::Fetched(freshness) => {
            list["kind"] = json!("fetched");
            list["url"] = json!(freshness.url);
            list["downloadedAt"] = json!(utc(freshness.downloaded_at));
            list["lastModified"] = json!(freshness.last_modified);
        }
    }
    list
}

/// A match in the JSON report, with its records and the evidence of the lists naming it (MCH-16).
fn match_json(flagged: &FlaggedMatch) -> Value {
    let found = &flagged.found;
    let records: Vec<Value> = found
        .records
        .iter()
        .map(|record| {
            let affects = match record.status {
                RecordStatus::Affects => Some(true),
                RecordStatus::DoesNotAffect => Some(false),
                RecordStatus::NotEvaluated => None,
            };
            json!({"id": record.id, "source": record.source, "affects": affects})
        })
        .collect();
    let exploited: Vec<Value> = flagged
        .evidence
        .iter()
        .map(|named| {
            json!({
                "list": named.list,
                "cve": named.cve,
                "dateAdded": named.added.map(|added| added.to_string()),
            })
        })
        .collect();
    json!({
        "name": found.component.name,
        "version": found.component.version,
        "purl": found.component.purl,
        "id": found.id,
        "aliases": found.aliases,
        "records": records,
        "exploited": exploited,
    })
}

/// The components neither affected nor named by a component or pair not evaluated (MCH-3).
fn clean_count(sbom: &Sbom, matching: &FlaggedReport) -> usize {
    let reported: HashSet<&ComponentRef> = matching
        .matches()
        .iter()
        .map(|flagged| &flagged.found.component)
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
