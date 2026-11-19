//! The report formats of `forewarn check` and `forewarn match`: adapters from the domain's results to text or JSON
//! (`specs/cli-check.md`, `specs/cli-match.md`, `specs/cli-match-exploited.md`).

use std::fmt::Write;
use std::path::Path;

use forewarn_domain::completeness::{CompletenessReport, Field, NotCheckedReason};
use forewarn_domain::exploited::{Evidence, FlaggedMatch, FlaggedReport};
use forewarn_domain::matching::{
    ComponentReason, ComponentRef, Match, PairReason, Reason, RecordRef, RecordStatus,
};
use forewarn_domain::sbom::{Sbom, SpecVersion};
use std::time::SystemTime;

use forewarn_domain::date::Date;
use forewarn_domain::exploited::ExploitedList;
use forewarn_osv::api::QueryFreshness;
use forewarn_osv::fetch::Freshness;
use serde_json::{Value, json};

use crate::awareness::Awareness;
use crate::drafts::{DraftFile, Drafts};
use crate::escape::{push_escaped, push_escaped_path};
use crate::vex::{self, Verdicts};
use time::OffsetDateTime;
use time::macros::format_description;

/// The text report for a person: the spec version, the incomplete components or that the SBOM is complete, then the
/// components not checked under a heading of their own.
pub fn human(sbom: &Sbom, completeness: &CompletenessReport) -> String {
    let mut text = checked_report(sbom, completeness);
    let not_checked = completeness.not_checked();
    if !not_checked.is_empty() {
        let _ = writeln!(
            text,
            "Not checked, file components ({}):",
            not_checked.len()
        );
        for skipped in not_checked {
            let NotCheckedReason::File = skipped.reason;
            push_component_ref(&mut text, &skipped.component);
            text.push('\n');
        }
    }
    text
}

/// The spec version, then the incomplete components or that the SBOM is complete.
fn checked_report(sbom: &Sbom, completeness: &CompletenessReport) -> String {
    let mut text = format!("SBOM: CycloneDX {}", sbom.spec_version);
    if sbom.spec_version.is_below_bsi_minimum() {
        let _ = write!(
            text,
            " (below the BSI TR-03183-2 minimum, {})",
            SpecVersion::BSI_MINIMUM
        );
    }
    text.push('\n');
    let checked = completeness.checked();
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
    let not_checked: Vec<Value> = completeness
        .not_checked()
        .iter()
        .map(|skipped| {
            json!({
                "name": skipped.component.name,
                "version": skipped.component.version,
                "purl": skipped.component.purl,
                "reason": not_checked_reason(skipped.reason),
            })
        })
        .collect();
    let report = json!({
        "specVersion": sbom.spec_version.to_string(),
        "belowBsiMinimum": sbom.spec_version.is_below_bsi_minimum(),
        "componentCount": completeness.checked(),
        "complete": completeness.is_complete(),
        "incomplete": incomplete,
        "notChecked": not_checked,
    });
    format!("{report:#}\n")
}

/// The reason a component was not checked, in the JSON report.
fn not_checked_reason(reason: NotCheckedReason) -> &'static str {
    match reason {
        NotCheckedReason::File => "file",
    }
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

/// An exploited list the matches are flagged against, and where it came from (MXL-5).
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

/// A time of the system clock to the second, UTC; `None` before 1970 or past the range of `time`.
pub fn offset_date_time(time: SystemTime) -> Option<OffsetDateTime> {
    let elapsed = time.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    OffsetDateTime::from_unix_timestamp(i64::try_from(elapsed.as_secs()).ok()?).ok()
}

/// A time of a download or of a query in RFC 3339, UTC, to the second (`2026-11-13T09:30:00Z`); `unknown` for a time
/// the calendar of `time` cannot write (before 1970 or after the year 9999), which a damaged cache or a clock set
/// wrong could give.
fn utc(time: SystemTime) -> String {
    offset_date_time(time)
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

/// What the report of `forewarn match` prints.
pub struct MatchReport<'a> {
    pub sbom: &'a Sbom,
    pub sources: &'a [Source<'a>],
    pub exploited: &'a [ExploitedSource<'a>],
    pub awareness: &'a Awareness,
    pub matching: &'a FlaggedReport,
    /// The draft early warnings written and the stale ones, `None` without `--drafts` (MXL-28, MXL-36).
    pub drafts: Option<&'a Drafts>,
    /// The VEX verdicts applied to the matches (MVX-1).
    pub verdicts: &'a Verdicts<'a>,
}

/// The text report of `forewarn match` for a person: the SBOM, the sources of the records and the exploited lists,
/// the matches with the evidence of those actively exploited, the drafts written, the components and pairs not
/// evaluated, and the count of clean components.
pub fn matching_human(report: &MatchReport) -> String {
    let MatchReport {
        sbom,
        sources,
        exploited,
        awareness,
        matching,
        drafts,
        verdicts,
    } = *report;
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
    vex::push_sources(&mut text, verdicts);
    if matching.exploited_count() > 0 {
        awareness.push_moments(&mut text);
    }
    let _ = writeln!(
        text,
        "Affected ({}, {} actively exploited):",
        matching.matches().len(),
        matching.exploited_count()
    );
    for flagged in matching.matches() {
        let found = &flagged.found;
        push_match_header(&mut text, found);
        push_records_by_status(&mut text, &found.records);
        text.push('\n');
        if flagged.is_exploited() {
            push_evidence(&mut text, &flagged.evidence);
            awareness.push_deadlines(&mut text, &flagged.evidence[0].cve);
        }
    }
    if let Some(drafts) = drafts {
        let _ = writeln!(text, "Draft early warnings ({}):", drafts.written.len());
        push_draft_files(&mut text, &drafts.written);
        if !drafts.stale.is_empty() {
            let _ = writeln!(
                text,
                "Stale draft early warnings, no longer drafted, left in place ({}):",
                drafts.stale.len()
            );
            push_draft_files(&mut text, &drafts.stale);
        }
    }
    vex::push_set_aside(&mut text, verdicts, matching);
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
        matching.clean_count(),
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
            push_escaped_path(text, path);
            let _ = writeln!(text, ": {count} {}, local", records(*count));
        }
    }
}

/// Pushes an exploited list with its catalog's version and release date when it gives them, its entry count and where
/// it came from (MXL-5).
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
            push_escaped_path(text, path);
        }
        Origin::Fetched(freshness) => push_download(text, freshness),
    }
    text.push('\n');
}

/// Pushes when and where a copy was downloaded, and its `Last-Modified` when the server sent one (MCH-4, MXL-5).
fn push_download(text: &mut String, freshness: &Freshness) {
    let _ = write!(text, "downloaded {} from ", utc(freshness.downloaded_at));
    push_escaped(text, &freshness.url);
    if let Some(last_modified) = &freshness.last_modified {
        text.push_str(", Last-Modified ");
        push_escaped(text, last_modified);
    }
}

/// Pushes the records of a match grouped under the status each gives, in the order affected, not affected, not
/// evaluated, each group left out when empty (MCH-1).
fn push_records_by_status(text: &mut String, records: &[RecordRef]) {
    let mut sorted: Vec<&RecordRef> = records.iter().collect();
    // A stable sort: the records of a group keep their order (VMT-18).
    sorted.sort_by_key(|record| status_group(record.status).0);
    let mut separator = ", ";
    for group in sorted.chunk_by(|a, b| a.status == b.status) {
        text.push_str(separator);
        text.push_str(status_group(group[0].status).1);
        for (i, record) in group.iter().enumerate() {
            if i > 0 {
                text.push_str(", ");
            }
            push_escaped(text, &record.id);
            text.push_str(" from ");
            push_escaped(text, &record.source);
        }
        separator = "; ";
    }
}

/// The rank and the label of the group of records of a status (MCH-1).
fn status_group(status: RecordStatus) -> (u8, &'static str) {
    match status {
        RecordStatus::Affects => (0, "affected per "),
        RecordStatus::DoesNotAffect => (1, "not affected per "),
        RecordStatus::NotEvaluated => (2, "not evaluated per "),
    }
}

/// Pushes the line marking a match actively exploited, with each list naming it (MXL-1).
pub(crate) fn push_evidence(text: &mut String, evidence: &[Evidence]) {
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

/// Pushes the component of a match, its id and its aliases (MCH-1).
pub(crate) fn push_match_header(text: &mut String, found: &Match) {
    push_component_ref(text, &found.component);
    text.push_str(": ");
    push_escaped(text, &found.id);
    if !found.aliases.is_empty() {
        text.push_str(" (");
        push_escaped(text, &found.aliases.join(", "));
        text.push(')');
    }
}

fn push_component_ref(text: &mut String, component: &ComponentRef) {
    push_component(
        text,
        &component.name,
        component.version.as_deref(),
        component.purl.as_deref(),
    );
}

/// A line per draft file, its CVE id escaped, then its path as `push_escaped_path` prints it (MXL-35, MXL-39, MCH-43).
fn push_draft_files(text: &mut String, files: &[DraftFile]) {
    for draft in files {
        text.push_str("  ");
        push_escaped(text, &draft.cve);
        text.push_str(": ");
        push_escaped_path(text, &draft.path);
        text.push('\n');
    }
}

/// The objects `{"cve", "path"}` of the draft files of MCH-16.
fn draft_files_json(files: &[DraftFile]) -> Vec<Value> {
    files
        .iter()
        .map(|draft| json!({"cve": draft.cve, "path": draft.path.to_string_lossy()}))
        .collect()
}

/// The JSON report of `forewarn match` for a machine: one object whose members MCH-16 lists, ending with a newline.
pub fn matching_json(report: &MatchReport) -> String {
    let MatchReport {
        sbom,
        sources,
        exploited,
        awareness,
        matching,
        drafts,
        verdicts,
    } = *report;
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
    let exploited_any = matching.exploited_count() > 0;
    let affected: Vec<Value> = matching
        .matches()
        .iter()
        .map(|flagged| match_json(flagged, awareness))
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
    let mut report = json!({
        "specVersion": sbom.spec_version.to_string(),
        "componentCount": sbom.components.len(),
        "cleanCount": matching.clean_count(),
        "osv": sources,
        "exploitedLists": exploited_lists,
        "exploitedCount": matching.exploited_count(),
        // Only with an exploited match, so that a run reading the clock gives the same report as long as none is.
        "awareSince": exploited_any.then(|| awareness.run_since.to_string()),
        "measureAvailable": awareness
            .measure_available
            .filter(|_| exploited_any)
            .map(|moment| moment.to_string()),
        "affected": affected,
        "drafts": drafts.map_or_else(Vec::new, |drafts| draft_files_json(&drafts.written)),
        "staleDrafts": drafts.map_or_else(Vec::new, |drafts| draft_files_json(&drafts.stale)),
        "notEvaluated": not_evaluated,
    });
    if let Value::Object(members) = &mut report {
        members.extend(vex::json_members(verdicts, matching, awareness));
    }
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

/// A match in the JSON report, with its records, the evidence of the lists naming it and, when one does, its reporting
/// deadlines (MCH-16, MXL-14).
pub(crate) fn match_json(flagged: &FlaggedMatch, awareness: &Awareness) -> Value {
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
        "awareSince": flagged
            .evidence
            .first()
            .map(|evidence| awareness.since(&evidence.cve).to_string()),
        "deadlines": flagged.evidence.first().map(|evidence| {
            let deadlines = awareness.deadlines(&evidence.cve);
            json!({
                "earlyWarning": deadlines.early_warning.to_string(),
                "notification": deadlines.notification.to_string(),
                "finalReport": deadlines.final_report.map(|moment| moment.to_string()),
            })
        }),
    })
}

/// The name of a reason in a report (VMT-10), and the id of the vulnerability of a pair.
fn reason(reason: &Reason) -> (&'static str, Option<&str>) {
    match reason {
        Reason::Component(reason) => (
            match reason {
                ComponentReason::FirstParty => "first-party",
                ComponentReason::NoPackageUrl => "no package URL",
                ComponentReason::InvalidPackageUrl => "invalid package URL",
                ComponentReason::LocalPath => "local path",
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
