# 0011. Compute the reporting deadlines on UTC seconds of the domain

- Status: accepted
- Date: 2026-11-13

## Context

CRA article 14(2) sets an early warning within 24 hours and a notification within 72 hours of the moment a vendor
becomes aware of an actively exploited vulnerability, and a final report within 14 days of the moment a corrective or
mitigating measure is available (`specs/reporting-deadlines.md`). The domain knows only a day of the calendar
(`forewarn_domain::date::Date`, written in the domain for the dates of the exploited lists); hours need a moment of the day.
The domain performs no I/O and depends on no adapter; a deadline is the costliest bug of the project.

## Decision

- **A moment written in the domain**: `forewarn_domain::date::Moment` (not `Instant`, the name of the monotonic
  clock of `std::time`), a `Date` and a time of day to the second, in
  UTC, ordered, written in RFC 3339 (`Z`). It converts to and from a count of seconds (days since 0001-01-01 from the
  civil calendar, times 86 400, plus the seconds of the day), on which a deadline adds its duration in whole seconds.
- **No time crate** (`jiff`, `time`, `chrono`): the deadlines need no time zone, no daylight saving time and no
  parsing of offsets in the domain, only additions of whole hours in UTC; a dependency would bring a second date type
  next to `Date`, and its own types would cross into the adapters.
- **UTC only**: an adapter converts a moment given with an offset; leap seconds are not counted, as in the Unix time
  of the clock the CLI reads: unlike RFC 3339, a second `60` is refused, and an adapter reading one takes `59`, which
  only moves the deadlines earlier.
- **Durations, not the rules of Regulation 1182/71**: 24 h, 72 h and 14 × 24 h from the moment itself, which are never
  later than the periods that regulation computes: a period in hours starts at the next hour, a period in days at the
  next day and, when it ends on a Saturday, a Sunday or a public holiday, ends on the next working day.

## Consequences

- The domain keeps no dependency for time; its arithmetic (days from the calendar, carries across months and years)
  is its own and is covered by the scenarios at the bounds of the spec.
- The early warning and the notification can fall up to an hour earlier, the final report up to a day plus the days
  to the next working day earlier, than a lawyer reading Regulation 1182/71 would compute: the vendor is warned early,
  never late. Only the final report, a period in days, ever moves to a working day.
- Parsing an RFC 3339 moment with an offset, if the CLI needs it, belongs to the CLI or to a time crate there.
