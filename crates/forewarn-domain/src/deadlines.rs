//! The deadlines CRA article 14(2) sets for reporting an actively exploited vulnerability
//! (`specs/reporting-deadlines.md`): exact durations from the moments given, never later than the periods of
//! Regulation 1182/71 (ADR 0011).

use std::fmt;

use crate::date::Moment;

const HOUR: u64 = 3600;

/// From the moment of awareness to the early warning (article 14(2)(a), RDL-1).
pub const EARLY_WARNING_SECONDS: u64 = 24 * HOUR;

/// From the moment of awareness to the notification (article 14(2)(b), RDL-2).
pub const NOTIFICATION_SECONDS: u64 = 72 * HOUR;

/// From the moment a corrective or mitigating measure is available to the final report (article 14(2)(c), RDL-3).
pub const FINAL_REPORT_SECONDS: u64 = 14 * 24 * HOUR;

/// The latest moments of the three reports of an actively exploited vulnerability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportingDeadlines {
    pub early_warning: Moment,
    pub notification: Moment,
    /// `None` while no corrective or mitigating measure is available (RDL-4).
    pub final_report: Option<Moment>,
}

/// A moment whose deadline falls past `9999-12-31T23:59:59Z` (RDL-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlinePastRange(pub Moment);

impl fmt::Display for DeadlinePastRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a reporting deadline from `{}` falls past 9999-12-31T23:59:59Z",
            self.0
        )
    }
}

impl std::error::Error for DeadlinePastRange {}

/// The deadlines from the moment the vendor became aware of the vulnerability and, once one is available, the moment
/// of a corrective or mitigating measure, counted from it alone (RDL-11).
///
/// # Errors
/// [`DeadlinePastRange`] naming the moment a deadline would fall past the year 9999 from (RDL-10).
pub fn reporting_deadlines(
    aware_since: Moment,
    measure_available: Option<Moment>,
) -> Result<ReportingDeadlines, DeadlinePastRange> {
    let after = |moment: Moment, seconds| {
        moment
            .checked_add_seconds(seconds)
            .ok_or(DeadlinePastRange(moment))
    };
    Ok(ReportingDeadlines {
        early_warning: after(aware_since, EARLY_WARNING_SECONDS)?,
        notification: after(aware_since, NOTIFICATION_SECONDS)?,
        final_report: measure_available
            .map(|measure| after(measure, FINAL_REPORT_SECONDS))
            .transpose()?,
    })
}
