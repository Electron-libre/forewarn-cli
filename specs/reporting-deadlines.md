---
id: RDL
status: draft
adrs: [0011]
---

# CRA reporting deadlines

## Intent

Tell a vendor, for an actively exploited vulnerability, by when CRA article 14(2) requires its early warning, its
notification and its final report, from the moment the vendor became aware of it and the moment a corrective or
mitigating measure became available, so that no deadline is computed later than the regulation allows.

## Requirements

### Behaviour

- **RDL-1** (deterministic) Computing the deadlines from a moment of awareness must give the early warning deadline 24
  hours after that moment.
- **RDL-2** (deterministic) Computing the deadlines from a moment of awareness must give the notification deadline 72
  hours after that moment.
- **RDL-3** (deterministic) Computing the deadlines with the moment a corrective or mitigating measure became available
  must give the final report deadline 14 days of 24 hours after that moment.
- **RDL-4** (deterministic) Computing the deadlines with no moment of a corrective or mitigating measure must give no
  final report deadline, the report being due once a measure is available.

### Contract

- **RDL-5** (deterministic) A moment must be an instant of Coordinated Universal Time to the second, a day of the
  Gregorian calendar (`specs/exploited-flagging.md`, EXF-8) and a time of day from `00:00:00` to `23:59:59`.
- **RDL-6** (deterministic) Building a moment must refuse, naming it, a time of day out of those bounds (hour `24`,
  minute or second `60`).
- **RDL-7** (deterministic) A moment must be written in RFC 3339, in UTC: `YYYY-MM-DDTHH:MM:SSZ`.
- **RDL-8** (deterministic) Moments must be ordered by their date, then by their time of day.
- **RDL-9** (deterministic) A deadline must be the given moment moved forward by its exact duration in seconds, across
  the ends of days, months and years and the 29th of February.
- **RDL-10** (deterministic) Computing the deadlines must refuse, naming it, a moment whose deadline would fall after
  `9999-12-31T23:59:59Z`.
- **RDL-11** (deterministic) The final report deadline must be computed from the moment of the measure alone, even
  when that moment precedes the moment of awareness.

## Scenarios

- **RDL-H1** (happy; RDL-1, RDL-2, RDL-4, RDL-7) Given a vendor aware of an actively exploited vulnerability since
  `2026-11-13T09:30:00Z` and no corrective measure yet, when the deadlines are computed, then the early warning is due
  by `2026-11-14T09:30:00Z`, the notification by `2026-11-16T09:30:00Z`, and the final report has no deadline yet.
- **RDL-H2** (happy; RDL-1, RDL-2, RDL-3) Given a vendor aware since `2026-11-13T09:30:00Z` and a corrective release
  published at `2026-11-15T17:00:00Z`, when the deadlines are computed, then the early warning is due by
  `2026-11-14T09:30:00Z`, the notification by `2026-11-16T09:30:00Z` and the final report by `2026-11-29T17:00:00Z`.
- (RDL-9) Given an awareness at `2026-12-31T23:00:00Z`, when the deadlines are computed, then the early warning is due
  by `2027-01-01T23:00:00Z` and the notification by `2027-01-03T23:00:00Z`.
- (RDL-9) Given an awareness at `2028-02-28T12:00:00Z`, when the deadlines are computed, then the early warning is due
  by `2028-02-29T12:00:00Z` and the notification by `2028-03-02T12:00:00Z`; from `2027-02-28T12:00:00Z`, by
  `2027-03-01T12:00:00Z` and `2027-03-03T12:00:00Z`.
- (RDL-9) Given an awareness at `2026-01-31T00:00:00Z`, when the deadlines are computed, then the notification is due
  by `2026-02-03T00:00:00Z`.
- (RDL-3, RDL-9) Given a measure available at `2026-02-20T23:59:59Z`, when the deadlines are computed, then the final
  report is due by `2026-03-06T23:59:59Z`.
- (RDL-5, RDL-6) Given the time `24:00:00`, `12:60:00` or `12:00:60`, when a moment is built, then it is refused
  naming it; given `00:00:00` and `23:59:59`, it is accepted.
- (RDL-7) Given the moment of 5 January 2026 at 7 h 3 min 9 s UTC, when it is written, then it reads
  `2026-01-05T07:03:09Z`.
- (RDL-8) Given `2026-11-13T23:59:59Z` and `2026-11-14T00:00:00Z`, when they are compared, then the first comes first.
- (RDL-10) Given an awareness at `9999-12-30T00:00:01Z`, when the deadlines are computed, then they are refused naming
  that moment; given `9999-12-28T23:59:59Z`, the notification is due by `9999-12-31T23:59:59Z`.
- (RDL-10) Given a measure available at `9999-12-20T00:00:00Z`, when the deadlines are computed, then they are refused
  naming that moment.
- (RDL-11) Given an awareness at `2026-11-13T09:30:00Z` and a measure available since `2026-11-01T08:00:00Z`, when the
  deadlines are computed, then the final report is due by `2026-11-15T08:00:00Z`, before the notification.

## Non-goals

- Reading a clock or the moment of awareness: the caller gives each moment (the CLI, `cli_print_reporting_deadlines`).
- Time zones and offsets other than UTC: an adapter converts a moment given with an offset.
- The rules of Regulation (EEC, Euratom) No 1182/71 on periods and time limits (a period starting at the next hour or
  day, a period in days ending on a working day): the deadlines computed are never later than those, a vendor meeting
  them meets the regulation.
- The deadlines of a severe incident (article 14(4)) and the one-month final report of an incident.
- Telling the time left before a deadline or that it is overdue (`tell_overdue_reporting_deadlines`).
- The content of the reports, the member states the early warning names (milestone "Draft the CRA early warning").
- Remembering when a vulnerability was first seen across runs.
