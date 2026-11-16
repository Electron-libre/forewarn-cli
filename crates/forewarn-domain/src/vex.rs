//! The VEX verdicts of the vendor and their application to the matches (`specs/vex-verdicts.md`). An adapter reads
//! the verdicts of a CycloneDX document into these types.

use std::borrow::Cow;
use std::collections::HashSet;

use crate::cve::read_cve;
use crate::exploited::{FlaggedMatch, FlaggedReport};
use crate::purl;
use crate::sbom::Component;

/// What a vendor says of a vulnerability for some components of their product (VEX-5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// The id of the vulnerability, then the ids of its references, in document order.
    pub ids: Vec<String>,
    /// The components it names: `bom-ref`s, BOM-Links or package URLs, as written (VEX-7).
    pub targets: Vec<String>,
    /// The state of the analysis, as written (`not_affected`).
    pub state: String,
    /// The justification of the analysis, as written (`code_not_reachable`).
    pub justification: Option<String>,
    /// The detail of the analysis, as written.
    pub detail: Option<String>,
}

impl Verdict {
    /// Whether its state sets a match aside (VEX-8).
    #[must_use]
    pub fn sets_aside(&self) -> bool {
        matches!(
            self.state.as_str(),
            "not_affected" | "false_positive" | "resolved" | "resolved_with_pedigree"
        )
    }
}

/// A match a verdict set aside, with the index of that verdict among those applied (VEX-3, VEX-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetAside {
    pub found: FlaggedMatch,
    pub verdict: usize,
}

/// Moves out of the matches of `report` each match the verdicts set aside, every verdict naming it setting it aside,
/// with the first of them (VEX-3 to VEX-10), and records the verdicts that name no match. `components` are those of
/// the SBOM, whose `bom-ref`s tell a target naming a component by its package URL (VEX-7).
#[must_use]
pub fn apply_verdicts(
    mut report: FlaggedReport,
    verdicts: &[Verdict],
    components: &[Component],
) -> FlaggedReport {
    if verdicts.is_empty() {
        return report;
    }
    let bom_refs: HashSet<&str> = components
        .iter()
        .filter_map(|component| component.bom_ref.as_deref())
        .collect();
    let read: Vec<Read> = verdicts
        .iter()
        .map(|verdict| Read::of(verdict, &bom_refs))
        .collect();
    let mut used = vec![false; verdicts.len()];
    for found in std::mem::take(&mut report.matches) {
        let ids: Vec<Cow<str>> = std::iter::once(&found.found.id)
            .chain(&found.found.aliases)
            .map(|id| canonical_id(id))
            .collect();
        let naming: Vec<usize> = (0..read.len())
            .filter(|&at| read[at].names(&found, &ids))
            .collect();
        for &at in &naming {
            used[at] = true;
        }
        match naming.first() {
            Some(&first) if naming.iter().all(|&at| verdicts[at].sets_aside()) => {
                report.set_aside.push(SetAside {
                    found,
                    verdict: first,
                });
            }
            _ => report.matches.push(found),
        }
    }
    report.unused_verdicts = (0..verdicts.len()).filter(|&at| !used[at]).collect();
    report
}

/// A verdict read for its comparisons: its ids, a CVE in upper case (VEX-6), and its targets, each a `bom-ref` or a
/// package URL (VEX-7).
struct Read<'a> {
    ids: Vec<Cow<'a, str>>,
    bom_refs: Vec<Cow<'a, str>>,
    /// The `bom-ref` of each target that is no component's, compared to the package URLs.
    purls: Vec<Cow<'a, str>>,
}

impl<'a> Read<'a> {
    fn of(verdict: &'a Verdict, bom_refs: &HashSet<&str>) -> Self {
        let mut read = Self {
            ids: verdict.ids.iter().map(|id| canonical_id(id)).collect(),
            bom_refs: Vec::new(),
            purls: Vec::new(),
        };
        for target in &verdict.targets {
            let bom_ref = bom_ref_of(target);
            if !bom_refs.contains(bom_ref.as_ref()) {
                read.purls.push(bom_ref.clone());
            }
            read.bom_refs.push(bom_ref);
        }
        read
    }

    /// Whether the verdict names the component of `found` and one of `ids`, the canonical ids of the match.
    fn names(&self, found: &FlaggedMatch, ids: &[Cow<str>]) -> bool {
        let component = &found.found.component;
        let names_component = component
            .bom_ref
            .as_deref()
            .is_some_and(|own| self.bom_refs.iter().any(|bom_ref| bom_ref == own))
            || component
                .purl
                .as_deref()
                .is_some_and(|own| self.purls.iter().any(|purl| purl == own));
        names_component && ids.iter().any(|id| self.ids.contains(id))
    }
}

/// The id as compared: a CVE id in upper case, any other id as written (VEX-6).
fn canonical_id(id: &str) -> Cow<'_, str> {
    read_cve(id).unwrap_or(Cow::Borrowed(id))
}

/// The `bom-ref` a target names: the percent-decoded fragment of a BOM-Link (`urn:cdx:<serial>/<version>#<bom-ref>`),
/// whatever its serial number and version, else the target as written (VEX-7).
fn bom_ref_of(target: &str) -> Cow<'_, str> {
    target
        .strip_prefix("urn:cdx:")
        .and_then(|link| link.split_once('#'))
        .and_then(|(_, fragment)| purl::decode(fragment).ok())
        .map_or(Cow::Borrowed(target), Cow::Owned)
}
