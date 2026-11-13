//! The CRA reporting deadlines and the moments they are computed from (`specs/reporting-deadlines.md`).

use std::time::Duration;

use forewarn_domain::date::{Date, Instant, InvalidTime};
use forewarn_domain::deadlines::{DeadlinePastRange, ReportingDeadlines, reporting_deadlines};

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

/// The deadlines from `aware_since` and `measure`, written in RFC 3339.
fn deadlines(aware_since: Instant, measure: Option<Instant>) -> [Option<String>; 3] {
    let ReportingDeadlines {
        early_warning,
        notification,
        final_report,
    } = reporting_deadlines(aware_since, measure).unwrap();
    [
        Some(early_warning.to_string()),
        Some(notification.to_string()),
        final_report.map(|deadline| deadline.to_string()),
    ]
}

/// The deadlines expected, in the form of [`deadlines`].
fn due(early_warning: &str, notification: &str, final_report: Option<&str>) -> [Option<String>; 3] {
    [
        Some(early_warning.into()),
        Some(notification.into()),
        final_report.map(Into::into),
    ]
}

/// The moment of `YYYY-MM-DDTHH:MM:SSZ`, given as numbers.
fn at(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Instant {
    Instant::new(Date::new(year, month, day).unwrap(), hour, minute, second).unwrap()
}

// spec: RDL-5, RDL-6
#[test]
fn refuses_a_time_of_day_out_of_bounds_naming_it() {
    let date = Date::new(2026, 11, 13).unwrap();
    for (hour, minute, second) in [(24, 0, 0), (12, 60, 0), (12, 0, 60), (255, 255, 255)] {
        let refused = Instant::new(date, hour, minute, second).unwrap_err();
        assert_eq!(
            refused,
            InvalidTime {
                hour,
                minute,
                second
            }
        );
        assert_eq!(
            refused.to_string(),
            format!("not a time of day: `{hour:02}:{minute:02}:{second:02}`")
        );
    }
}

// spec: RDL-5
#[test]
fn accepts_the_first_and_the_last_second_of_a_day() {
    let first = at(2026, 11, 13, 0, 0, 0);
    let last = at(2026, 11, 13, 23, 59, 59);
    assert_eq!(first.date(), Date::new(2026, 11, 13).unwrap());
    assert_eq!((last.hour(), last.minute(), last.second()), (23, 59, 59));
}

// spec: RDL-7
#[test]
fn writes_a_moment_in_rfc_3339_utc() {
    assert_eq!(at(2026, 1, 5, 7, 3, 9).to_string(), "2026-01-05T07:03:09Z");
    assert_eq!(at(1, 1, 1, 0, 0, 0).to_string(), "0001-01-01T00:00:00Z");
}

// spec: RDL-8
#[test]
fn orders_moments_by_date_then_time_of_day() {
    assert!(at(2026, 11, 13, 23, 59, 59) < at(2026, 11, 14, 0, 0, 0));
    assert!(at(2026, 11, 13, 9, 30, 0) < at(2026, 11, 13, 9, 30, 1));
    assert!(at(2025, 12, 31, 23, 59, 59) < at(2026, 1, 1, 0, 0, 0));
}

// spec: RDL-9
#[test]
fn moves_a_moment_forward_across_days_months_years_and_29_february() {
    let cases = [
        (at(2026, 11, 13, 9, 30, 0), DAY, at(2026, 11, 14, 9, 30, 0)),
        (at(2026, 12, 31, 23, 0, 0), DAY, at(2027, 1, 1, 23, 0, 0)),
        (
            at(2026, 12, 31, 23, 0, 0),
            3 * DAY,
            at(2027, 1, 3, 23, 0, 0),
        ),
        (at(2028, 2, 28, 12, 0, 0), DAY, at(2028, 2, 29, 12, 0, 0)),
        (at(2028, 2, 28, 12, 0, 0), 3 * DAY, at(2028, 3, 2, 12, 0, 0)),
        (at(2027, 2, 28, 12, 0, 0), DAY, at(2027, 3, 1, 12, 0, 0)),
        (at(2000, 2, 28, 0, 0, 0), DAY, at(2000, 2, 29, 0, 0, 0)),
        (at(2100, 2, 28, 0, 0, 0), DAY, at(2100, 3, 1, 0, 0, 0)),
        (at(2026, 1, 31, 0, 0, 0), 3 * DAY, at(2026, 2, 3, 0, 0, 0)),
        (
            at(2026, 2, 20, 23, 59, 59),
            14 * DAY,
            at(2026, 3, 6, 23, 59, 59),
        ),
        (at(2026, 11, 13, 23, 59, 59), 1, at(2026, 11, 14, 0, 0, 0)),
        (at(2026, 11, 13, 9, 30, 0), 0, at(2026, 11, 13, 9, 30, 0)),
        (at(1, 1, 1, 0, 0, 0), 365 * DAY, at(2, 1, 1, 0, 0, 0)),
    ];
    for (from, seconds, expected) in cases {
        assert_eq!(
            from.checked_add(Duration::from_secs(seconds)),
            Some(expected),
            "{from} + {seconds} s"
        );
    }
}

// spec: RDL-9
#[test]
fn gives_no_moment_past_the_end_of_9999() {
    let last = at(9999, 12, 31, 23, 59, 59);
    assert_eq!(last.checked_add(Duration::ZERO), Some(last));
    assert_eq!(last.checked_add(Duration::from_secs(1)), None);
    assert_eq!(
        at(9999, 12, 28, 23, 59, 59).checked_add(Duration::from_secs(3 * DAY)),
        Some(last)
    );
    assert_eq!(at(2026, 1, 1, 0, 0, 0).checked_add(Duration::MAX), None);
}

// spec: RDL-H1, RDL-1, RDL-2, RDL-4, RDL-7
#[test]
fn gives_the_early_warning_and_notification_deadlines_and_no_final_report_before_a_measure() {
    assert_eq!(
        deadlines(at(2026, 11, 13, 9, 30, 0), None),
        due("2026-11-14T09:30:00Z", "2026-11-16T09:30:00Z", None)
    );
}

// spec: RDL-H2, RDL-1, RDL-2, RDL-3
#[test]
fn gives_the_final_report_deadline_14_days_after_a_measure() {
    assert_eq!(
        deadlines(at(2026, 11, 13, 9, 30, 0), Some(at(2026, 11, 15, 17, 0, 0))),
        due(
            "2026-11-14T09:30:00Z",
            "2026-11-16T09:30:00Z",
            Some("2026-11-29T17:00:00Z")
        )
    );
}

// spec: RDL-9
#[test]
fn computes_the_deadlines_across_the_ends_of_months_and_years() {
    let cases = [
        (
            at(2026, 12, 31, 23, 0, 0),
            "2027-01-01T23:00:00Z",
            "2027-01-03T23:00:00Z",
        ),
        (
            at(2028, 2, 28, 12, 0, 0),
            "2028-02-29T12:00:00Z",
            "2028-03-02T12:00:00Z",
        ),
        (
            at(2027, 2, 28, 12, 0, 0),
            "2027-03-01T12:00:00Z",
            "2027-03-03T12:00:00Z",
        ),
        (
            at(2026, 1, 31, 0, 0, 0),
            "2026-02-01T00:00:00Z",
            "2026-02-03T00:00:00Z",
        ),
    ];
    for (aware_since, early_warning, notification) in cases {
        assert_eq!(
            deadlines(aware_since, None),
            due(early_warning, notification, None),
            "{aware_since}"
        );
    }
}

// spec: RDL-3, RDL-9
#[test]
fn gives_the_final_report_deadline_across_the_end_of_february() {
    assert_eq!(
        deadlines(at(2026, 2, 20, 9, 0, 0), Some(at(2026, 2, 20, 23, 59, 59))),
        due(
            "2026-02-21T09:00:00Z",
            "2026-02-23T09:00:00Z",
            Some("2026-03-06T23:59:59Z")
        )
    );
}

// spec: RDL-10
#[test]
fn refuses_an_awareness_whose_deadline_falls_past_9999_naming_it() {
    let aware_since = at(9999, 12, 30, 0, 0, 1);
    let refused = reporting_deadlines(aware_since, None).unwrap_err();
    assert_eq!(refused, DeadlinePastRange(aware_since));
    assert_eq!(
        refused.to_string(),
        "a reporting deadline from `9999-12-30T00:00:01Z` falls past 9999-12-31T23:59:59Z"
    );
    assert_eq!(
        deadlines(at(9999, 12, 28, 23, 59, 59), None),
        due("9999-12-29T23:59:59Z", "9999-12-31T23:59:59Z", None)
    );
}

// spec: RDL-10
#[test]
fn refuses_a_measure_whose_final_report_falls_past_9999_naming_it() {
    let measure = at(9999, 12, 20, 0, 0, 0);
    assert_eq!(
        reporting_deadlines(at(9999, 12, 1, 0, 0, 0), Some(measure)),
        Err(DeadlinePastRange(measure))
    );
}

// spec: RDL-11
#[test]
fn counts_the_final_report_from_a_measure_that_precedes_the_awareness() {
    assert_eq!(
        deadlines(at(2026, 11, 13, 9, 30, 0), Some(at(2026, 11, 1, 8, 0, 0))),
        due(
            "2026-11-14T09:30:00Z",
            "2026-11-16T09:30:00Z",
            Some("2026-11-15T08:00:00Z")
        )
    );
}
