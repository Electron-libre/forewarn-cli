//! The moments the CRA reporting deadlines of `forewarn match` count from and are checked at, and their part of the
//! human report (`specs/cli-match-exploited.md`, MXL-14 to MXL-26).

use std::fmt::Write;
use std::time::SystemTime;

use forewarn_domain::date::Moment;
use forewarn_domain::deadlines::{
    DeadlinePastRange, DeadlineState, ReportingDeadlines, reporting_deadlines,
};

use crate::args::{GivenMoment, MatchArgs, moment};
use crate::report::offset_date_time;
use crate::usage_error;

/// The moments of a run: that of awareness of each actively exploited CVE (MXL-17), that of the measure (MXL-15) and
/// that of the check (MXL-23).
pub struct Awareness {
    /// The moment of awareness of the run.
    pub since: Moment,
    /// Whether it was given with `--aware-since`, else read from the clock.
    pub given: bool,
    pub measure_available: Option<Moment>,
    /// The moment the deadlines are checked at (MXL-23).
    pub checked_at: Moment,
    /// Whether it was given with `--now`, else read from the clock.
    pub checked_given: bool,
}

impl Awareness {
    /// The moments the arguments give, the clock read once for those they do not (MXL-17, MXL-23); exits with 2,
    /// naming the option and the value given, when a deadline falls past the year 9999 (MXL-20).
    pub fn of_run(args: &MatchArgs) -> Self {
        let run = (args.aware_since.is_none() || args.now.is_none()).then(|| {
            offset_date_time(SystemTime::now())
                .and_then(moment)
                .unwrap_or_else(|| {
                    let missing = [
                        (args.aware_since.is_none(), "--aware-since"),
                        (args.now.is_none(), "--now"),
                    ]
                    .into_iter()
                    .filter_map(|(missing, option)| missing.then_some(option))
                    .collect::<Vec<_>>()
                    .join(" and ");
                    usage_error(
                        clap::error::ErrorKind::InvalidValue,
                        &format!(
                            "the clock of the system gives no moment of the years 1 to 9999: give {missing}"
                        ),
                    )
                })
        });
        let given_or_run = |given: Option<&GivenMoment>| {
            given
                .map(|given| given.moment)
                .or(run)
                .expect("the clock is read when a moment is not given")
        };
        let since = given_or_run(args.aware_since.as_ref());
        // The moment of awareness first, so that the error of a final report names the measure (MXL-20).
        reporting_deadlines(since, None)
            .unwrap_or_else(|error| past_range("--aware-since", args.aware_since.as_ref(), error));
        let measure_available = args.measure_available.as_ref().map(|given| given.moment);
        reporting_deadlines(since, measure_available).unwrap_or_else(|error| {
            past_range(
                "--measure-available",
                args.measure_available.as_ref(),
                error,
            )
        });
        Self {
            since,
            given: args.aware_since.is_some(),
            measure_available,
            checked_at: given_or_run(args.now.as_ref()),
            checked_given: args.now.is_some(),
        }
    }

    /// The moment of awareness of `cve` (MXL-17).
    pub fn since(&self, _cve: &str) -> Moment {
        self.since
    }

    /// The reporting deadlines of `cve` (MXL-14 to MXL-16).
    pub fn deadlines(&self, cve: &str) -> ReportingDeadlines {
        reporting_deadlines(self.since(cve), self.measure_available)
            .expect("the deadlines of the moments of awareness were checked when they were read")
    }

    /// Pushes the moments the reporting deadlines are computed from and checked at, and where the moments of
    /// awareness and of the check came from (MXL-18, MXL-26).
    pub fn push_moments(&self, text: &mut String) {
        let origin = |given, option| {
            if given {
                option
            } else {
                "the moment of the run"
            }
        };
        let _ = write!(
            text,
            "Reporting deadlines (CRA article 14(2)): aware since {} ({}), ",
            self.since,
            origin(self.given, "--aware-since")
        );
        match self.measure_available {
            Some(measure) => {
                let _ = write!(text, "corrective measure available since {measure}");
            }
            None => text.push_str("no corrective measure given"),
        }
        let _ = writeln!(
            text,
            ", checked at {} ({})",
            self.checked_at,
            origin(self.checked_given, "--now")
        );
    }

    /// Pushes the line of the reporting deadlines of an actively exploited match of `cve`, each with the time left
    /// before it or overdue at the moment of the check (MXL-14 to MXL-16, MXL-22).
    pub fn push_deadlines(&self, text: &mut String, cve: &str) {
        let deadlines = self.deadlines(cve);
        let state = |deadline| state(DeadlineState::at(deadline, self.checked_at));
        let _ = write!(
            text,
            "    report by: early warning {} ({}), notification {} ({}), final report ",
            deadlines.early_warning,
            state(deadlines.early_warning),
            deadlines.notification,
            state(deadlines.notification)
        );
        match deadlines.final_report {
            Some(final_report) => {
                let _ = writeln!(text, "{final_report} ({})", state(final_report));
            }
            None => text.push_str("14 days after a corrective measure is available\n"),
        }
    }
}

/// Exits with 2 naming the option and the value given whose deadline falls past the year 9999 (MXL-20).
fn past_range(option: &str, given: Option<&GivenMoment>, error: DeadlinePastRange) -> ! {
    let text = given.map_or_else(|| error.0.to_string(), |given| given.text.clone());
    usage_error(
        clap::error::ErrorKind::InvalidValue,
        &format!("invalid value '{text}' for '{option}': {error}"),
    )
}

/// The time left before a deadline or overdue, `due now` for a deadline reached exactly (MXL-24).
fn state(state: DeadlineState) -> String {
    match state {
        DeadlineState::Left(0) => "due now".to_owned(),
        DeadlineState::Left(seconds) => format!("{} left", duration(seconds)),
        DeadlineState::Overdue(seconds) => format!("overdue by {}", duration(seconds)),
    }
}

/// Seconds in days, hours, minutes and seconds, the units before the first non-zero one left out (`1h 0m 0s`, MXL-24).
fn duration(seconds: u64) -> String {
    let units = [
        (seconds / 86_400, 'd'),
        (seconds / 3600 % 24, 'h'),
        (seconds / 60 % 60, 'm'),
        (seconds % 60, 's'),
    ];
    let first = units
        .iter()
        .position(|&(count, _)| count > 0)
        .unwrap_or(units.len() - 1);
    units[first..]
        .iter()
        .map(|(count, unit)| format!("{count}{unit}"))
        .collect::<Vec<_>>()
        .join(" ")
}
