//! The draft of the CRA article 14(2)(a) early warning of an actively exploited vulnerability
//! (`specs/early-warning-draft.md`): the fields the tool knows exactly, and the fields the ENISA SRP glossary 1.6
//! requires that only the vendor knows, listed to complete (ADR 0012). An adapter writes it in a format.

use crate::date::Moment;
use crate::deadlines::{DeadlinePastRange, ReportingDeadlines, reporting_deadlines};
use crate::exploited::{Evidence, FlaggedMatch, FlaggedReport};
use crate::matching::ComponentRef;
use crate::sbom::Product;

/// A field the early warning requires that the draft leaves to the vendor, in the order of the glossary (EWD-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ToComplete {
    Title,
    Summary,
    MemberStates,
    ProductName,
    ProductVersion,
}

/// A component the vulnerability of a draft affects, with the id of its match (EWD-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffectedComponent {
    pub component: ComponentRef,
    /// The id of the match (VMT-16).
    pub vulnerability: String,
}

/// The draft early warning of one actively exploited vulnerability of the product.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarlyWarning {
    /// The name of the product, `None` when the SBOM gives none (EWD-10).
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    /// The manufacturer of the product, as the SBOM gives it, never to complete: the platform fills its own
    /// (ADR 0012).
    pub manufacturer: Option<String>,
    /// Each component the CVE affects, in the order of the report, each once (EWD-3).
    pub components: Vec<AffectedComponent>,
    /// The CVE id, in upper case (EWD-7).
    pub cve: String,
    /// The first `EUVD-` record id of the evidence, else the first `EUVD-` id of the matches (EWD-8).
    pub euvd: Option<String>,
    /// The evidence of exploitation of the first match (EWD-5).
    pub evidence: Vec<Evidence>,
    pub aware_since: Moment,
    pub measure_available: Option<Moment>,
    pub deadlines: ReportingDeadlines,
    /// The required fields left to the vendor, in the order of the glossary (EWD-6, EWD-9).
    pub to_complete: Vec<ToComplete>,
}

/// The draft early warning of each CVE of the actively exploited matches of `report`, in the order its first match
/// comes (EWD-1, EWD-2), about `product` as the SBOM describes it.
///
/// # Errors
/// [`DeadlinePastRange`] when a deadline from `aware_since` or `measure_available` falls past the year 9999, only
/// when a match is actively exploited (EWD-11).
pub fn draft_early_warnings(
    report: &FlaggedReport,
    product: Option<&Product>,
    aware_since: Moment,
    measure_available: Option<Moment>,
) -> Result<Vec<EarlyWarning>, DeadlinePastRange> {
    let product_name = product.and_then(|product| given(Some(&product.name)));
    let product_version = product.and_then(|product| given(product.version.as_ref()));
    let manufacturer = product.and_then(|product| given(product.manufacturer.as_ref()));
    let to_complete = [
        (ToComplete::Title, false),
        (ToComplete::Summary, false),
        (ToComplete::MemberStates, false),
        (ToComplete::ProductName, product_name.is_some()),
        (ToComplete::ProductVersion, product_version.is_some()),
    ]
    .into_iter()
    .filter_map(|(field, filled)| (!filled).then_some(field))
    .collect::<Vec<_>>();

    let mut by_cve: Vec<(&str, Vec<&FlaggedMatch>)> = Vec::new();
    for found in report.matches() {
        let Some(first) = found.evidence.first() else {
            continue;
        };
        match by_cve.iter_mut().find(|(cve, _)| *cve == first.cve) {
            Some((_, matches)) => matches.push(found),
            None => by_cve.push((&first.cve, vec![found])),
        }
    }
    if by_cve.is_empty() {
        return Ok(Vec::new());
    }
    let deadlines = reporting_deadlines(aware_since, measure_available)?;
    Ok(by_cve
        .into_iter()
        .map(|(cve, matches)| EarlyWarning {
            product_name: product_name.clone(),
            product_version: product_version.clone(),
            manufacturer: manufacturer.clone(),
            components: matches.iter().fold(Vec::new(), |mut components, flagged| {
                let affected = AffectedComponent {
                    component: flagged.found.component.clone(),
                    vulnerability: flagged.found.id.clone(),
                };
                // The same component and id, whatever their `bom-ref`, which the draft does not name (EWD-3).
                let same = |kept: &AffectedComponent| {
                    kept.vulnerability == affected.vulnerability
                        && kept.component.name == affected.component.name
                        && kept.component.version == affected.component.version
                        && kept.component.purl == affected.component.purl
                };
                if !components.iter().any(same) {
                    components.push(affected);
                }
                components
            }),
            cve: cve.to_owned(),
            euvd: matches[0]
                .evidence
                .iter()
                .filter_map(|evidence| evidence.record.as_ref())
                .chain(matches.iter().flat_map(|flagged| {
                    std::iter::once(&flagged.found.id).chain(&flagged.found.aliases)
                }))
                .find(|id| is_euvd(id))
                .cloned(),
            evidence: matches[0].evidence.clone(),
            aware_since,
            measure_available,
            deadlines,
            to_complete: to_complete.clone(),
        })
        .collect())
}

/// The value, `None` when absent or made only of white space (EWD-10).
fn given(value: Option<&String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty()).cloned()
}

/// Whether `id` starts with `EUVD-`, ignoring ASCII case (EWD-8).
fn is_euvd(id: &str) -> bool {
    id.get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("EUVD-"))
}
