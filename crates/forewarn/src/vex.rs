//! The VEX verdicts of a run, from the SBOM and the `--vex` files, and their part of the reports of `forewarn match`:
//! their sources, the matches they set aside and the verdicts that name no match (`specs/cli-match-vex.md`).

use std::fmt::Write as _;
use std::path::Path;

use forewarn_domain::exploited::FlaggedReport;
use forewarn_domain::sbom::Sbom;
use forewarn_domain::vex::Verdict;
use serde_json::{Map, Value, json};

use crate::escape::push_escaped;
use crate::report::{Awareness, match_json, push_component_ref, push_evidence};

/// Where a verdict was read.
#[derive(Clone, Copy)]
pub enum Origin<'a> {
    Sbom,
    File(&'a Path),
}

/// The verdicts of a run, those of the SBOM then those of each `--vex` file in the order of the options (MVX-2).
pub struct Verdicts<'a> {
    all: Vec<Verdict>,
    /// Each source with its number of verdicts, in the order of `all`.
    sources: Vec<(Origin<'a>, usize)>,
}

impl<'a> Verdicts<'a> {
    #[must_use]
    pub fn new(sbom: &Sbom, files: &'a [(&'a Path, Vec<Verdict>)]) -> Self {
        let mut all = sbom.verdicts.clone();
        let mut sources = vec![(Origin::Sbom, all.len())];
        for (path, verdicts) in files {
            all.extend(verdicts.iter().cloned());
            sources.push((Origin::File(path), verdicts.len()));
        }
        Self { all, sources }
    }

    /// Every verdict, in the order they apply.
    #[must_use]
    pub fn all(&self) -> &[Verdict] {
        &self.all
    }

    /// Where the verdict at `index` of [`Self::all`] was read.
    fn origin(&self, index: usize) -> Origin<'a> {
        let mut first = 0;
        for &(origin, count) in &self.sources {
            if index < first + count {
                return origin;
            }
            first += count;
        }
        Origin::Sbom
    }

    /// Whether the human report prints the verdicts: the SBOM holds one or a `--vex` file is given (MVX-3).
    fn shown(&self) -> bool {
        !self.all.is_empty() || self.sources.len() > 1
    }
}

/// Pushes the sources of verdicts with their counts (MVX-3).
pub fn push_sources(text: &mut String, verdicts: &Verdicts) {
    if !verdicts.shown() {
        return;
    }
    text.push_str("VEX verdicts:\n");
    for &(origin, count) in &verdicts.sources {
        text.push_str("  ");
        push_origin(text, origin);
        let noun = if count == 1 { "verdict" } else { "verdicts" };
        let _ = writeln!(text, ": {count} {noun}");
    }
}

/// Pushes the matches set aside with their verdict and evidence (MVX-1), then the verdicts that name no match
/// (MVX-6).
pub fn push_set_aside(text: &mut String, verdicts: &Verdicts, matching: &FlaggedReport) {
    if !verdicts.shown() {
        return;
    }
    let _ = writeln!(
        text,
        "Set aside by a VEX verdict ({}):",
        matching.set_aside().len()
    );
    for aside in matching.set_aside() {
        let found = &aside.found.found;
        push_component_ref(text, &found.component);
        text.push_str(": ");
        push_escaped(text, &found.id);
        if !found.aliases.is_empty() {
            text.push_str(" (");
            push_escaped(text, &found.aliases.join(", "));
            text.push(')');
        }
        text.push('\n');
        let verdict = &verdicts.all[aside.verdict];
        text.push_str("    ");
        push_escaped(text, &verdict.state);
        if let Some(justification) = &verdict.justification {
            text.push_str(", ");
            push_escaped(text, justification);
        }
        if let Some(detail) = &verdict.detail {
            text.push_str(": ");
            push_escaped(text, detail);
        }
        text.push_str(" (");
        push_origin(text, verdicts.origin(aside.verdict));
        text.push_str(")\n");
        if aside.found.is_exploited() {
            push_evidence(text, &aside.found.evidence);
        }
    }
    let unused = matching.unused_verdicts();
    if unused.is_empty() {
        return;
    }
    let _ = writeln!(text, "Unused VEX verdicts ({}):", unused.len());
    for &index in unused {
        let verdict = &verdicts.all[index];
        text.push_str("  ");
        push_escaped(text, &verdict.ids.join(", "));
        text.push_str(" for ");
        push_escaped(text, &verdict.targets.join(", "));
        text.push_str(" (");
        push_origin(text, verdicts.origin(index));
        text.push_str(")\n");
    }
}

fn push_origin(text: &mut String, origin: Origin) {
    match origin {
        Origin::Sbom => text.push_str("the SBOM"),
        Origin::File(path) => push_escaped(text, &path.to_string_lossy()),
    }
}

/// The members `vex`, `setAsideCount`, `setAside` and `unusedVerdicts` of the JSON report (MVX-8).
pub fn json_members(
    verdicts: &Verdicts,
    matching: &FlaggedReport,
    awareness: &Awareness,
) -> Map<String, Value> {
    let source = |index: usize| match verdicts.origin(index) {
        Origin::Sbom => json!("sbom"),
        Origin::File(path) => json!(path.to_string_lossy()),
    };
    let sources: Vec<Value> = verdicts
        .sources
        .iter()
        .map(|&(origin, count)| match origin {
            Origin::Sbom => json!({"kind": "sbom", "verdictCount": count}),
            Origin::File(path) => {
                json!({"kind": "file", "path": path.to_string_lossy(), "verdictCount": count})
            }
        })
        .collect();
    let set_aside: Vec<Value> = matching
        .set_aside()
        .iter()
        .map(|aside| {
            let mut entry = match_json(&aside.found, &awareness.deadlines);
            let verdict = &verdicts.all[aside.verdict];
            if let Value::Object(members) = &mut entry {
                members.remove("deadlines");
                members.insert(
                    "verdict".into(),
                    json!({
                        "state": verdict.state,
                        "justification": verdict.justification,
                        "detail": verdict.detail,
                        "source": source(aside.verdict),
                    }),
                );
            }
            entry
        })
        .collect();
    let unused: Vec<Value> = matching
        .unused_verdicts()
        .iter()
        .map(|&index| {
            let verdict = &verdicts.all[index];
            json!({"ids": verdict.ids, "targets": verdict.targets, "source": source(index)})
        })
        .collect();
    let mut members = Map::new();
    members.insert("vex".into(), Value::Array(sources));
    members.insert("setAsideCount".into(), json!(set_aside.len()));
    members.insert("setAside".into(), Value::Array(set_aside));
    members.insert("unusedVerdicts".into(), Value::Array(unused));
    members
}
