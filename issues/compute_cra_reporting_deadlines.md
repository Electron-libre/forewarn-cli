---
priority: high
why: 'the rule the whole milestone rests on, and the costliest bug of the project: the CLI only feeds and prints it'
---
# Compute the CRA reporting deadlines of an actively exploited vulnerability

# Goal
`forewarn match` flags the matches whose vulnerability is actively exploited (`specs/exploited-flagging.md`), but
says nothing of when the vendor must report it. CRA article 14(2) sets three deadlines for an actively exploited
vulnerability: an early warning within 24 hours of becoming aware of it, a notification within 72 hours of becoming
aware of it, and a final report no later than 14 days after a corrective or mitigating measure is available. The
domain should compute them, with no I/O, covered by scenarios at their bounds.

# Findings
* The domain only has `Date`, a day of the calendar (`crates/forewarn-domain/src/date.rs`): the 24 h and 72 h
  deadlines need an instant to the second or the minute, and a time zone (UTC).
* The final report does not count from the awareness but from the availability of a corrective or mitigating measure
  (article 14(2)(c)); the roadmap first said otherwise.
* The domain performs no I/O: the moment of awareness, and the one of the measure, are given to it, never read from a
  clock.

# Approach
1. An instant type in UTC: written in the domain (seconds since the epoch, built from and printed as RFC 3339 `Z`),
   or taken from a crate (`jiff`, `time`); the choice is an ADR (dependency weight, license, the domain's purity).
2. A rule taking the moment of awareness and, optionally, the moment a corrective or mitigating measure became
   available, giving the early warning (+24 h), the notification (+72 h) and the final report (+14 days after the
   measure, absent while no measure is known).
3. Scenarios at the bounds: across the end of a month, of a year, a 29 February, midnight; the order of the three
   deadlines; a measure available before the awareness (to settle: the final report still counts from the measure,
   but never falls before the notification?).

# Specs
* `specs/reporting-deadlines.md` (new, written at step 1): the deadlines, their anchors, their bounds.

# Milestone
Compute CRA reporting deadlines

# Resources
* Regulation (EU) 2024/2847 (Cyber Resilience Act), article 14(2) and 14(1): the obligations on actively exploited
  vulnerabilities; article 71: they apply from 11 September 2026.
* `crates/forewarn-domain/src/date.rs`: the day type and its validation (EXF-8).
* `specs/exploited-flagging.md`: the flagged match the deadlines attach to.
* `CLAUDE.md`: "Testing priority", hexagonal architecture, no copyleft dependency.

# Hints
* The date an exploited list gives for adding a CVE is evidence, not the moment of awareness (EXF non-goals).
* Article 14(2)(a) lets the early warning be due "without undue delay and in any event within 24 hours": the
  deadline is the latest moment, not a target.
* Remembering from one run to the next when a vulnerability was first seen needs a state: out of this milestone.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
A domain rule, no I/O: from the moment of awareness and, optionally, the moment a corrective measure became available
(UTC instants to the second, a type written in the domain), give the early warning (+24 h), notification (+72 h) and
final report (+14 × 24 h after the measure) deadlines. Out of scope: clock, offsets, printing, time left.

## Plan
1. [x] Instant: `date::Instant` (a `Date` and a time of day in UTC), its refusals, order, RFC 3339 writing and the
   addition of a duration in seconds across days, months and years; verified by `tests/reporting_deadlines.rs`;
   makes true RDL-5 to RDL-9. Spec and ADR 0011 drafts committed with it. (autonomous)
2. [x] Deadlines: `deadlines::ReportingDeadlines` computed from the awareness and an optional measure, refusing past
   9999; verified by the scenarios of the spec in `tests/reporting_deadlines.rs`; makes true RDL-1 to RDL-4, RDL-10,
   RDL-11; spec and ADR 0011 accepted. (autonomous)
3. [x] Review fixes of the issue: `Instant` renamed `Moment`, additions in whole seconds, RDL-10 cited at the
   bound of `Moment`, ADR 0011 on leap seconds and on the periods of Regulation 1182/71; verified by project-check.
   (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 37db817b2f42117106f4c0622446dd4f1bf7ae92
- Deadlines are exact durations from the moment itself (24 h, 72 h, 14 × 24 h), not the periods of Regulation 1182/71, never later than those.
- The final report counts from the measure alone, even before the awareness (RDL-11).
- Years 1 to 9999, as `Date`; a deadline past 9999 is refused (RDL-10).
- Follow-up for `cli_print_reporting_deadlines`: build a `Moment` from the clock (Unix seconds) in the domain, so
  the calendar arithmetic stays in one place (finding of the `high` review).

## Summary of deliverable 1
- done: `Instant` (a `Date` and a UTC time of day), its refusal `InvalidTime`, its order, RFC 3339 writing and
  `checked_add`, through a day count of the proleptic Gregorian calendar.
- checks: project-check passes (fmt, clippy pedantic, tests, specs); docs n/a until the deadlines exist (CLAUDE.md
  status at deliverable 2).
- red: RDL-5, RDL-6, RDL-7, RDL-8, RDL-9: unresolved imports `forewarn_domain::date::Instant`, `InvalidTime`.
- Code review: no findings
- not verified: none.

## Summary of deliverable 2
- done: `deadlines::reporting_deadlines` gives the early warning (+24 h), the notification (+72 h) and, from a
  measure, the final report (+14 × 24 h), refusing a deadline past 9999 naming its moment; spec and ADR 0011
  accepted; CLAUDE.md status names the capability.
- checks: project-check passes (fmt, clippy pedantic, tests, specs); docs: CLAUDE.md updated, README n/a (no CLI
  change yet).
- red: RDL-H1, RDL-H2, RDL-1, RDL-2, RDL-3, RDL-4, RDL-10, RDL-11: unresolved import `forewarn_domain::deadlines`.
- Code review: no findings
- not verified: the reading of Regulation 1182/71 the non-goal and ADR 0011 rest on (from memory, not checked against
  its text).

## Summary of deliverable 3
- done: fixes of the `high` review: `Moment` (not `std::time::Instant`), `checked_add_seconds` instead of a
  `Duration` whose fraction was dropped, `from_seconds` without unreachable fallible paths, RDL-10 cited at the bound,
  ADR 0011 and the spec non-goal exact on leap seconds and on Regulation 1182/71 (only periods in days move to a
  working day).
- checks: project-check passes; docs: CLAUDE.md, ADR 0011, spec non-goal updated.
- red: none (no new behaviour).
- Code review (high): 7 findings: 6 fixed here; `Moment` from the clock left to `cli_print_reporting_deadlines`
  (follow-up in Decisions).
- Code review: 1 finding: the `as u8` casts of `from_seconds` would trip `cast_possible_truncation`; not fixed,
  clippy passes and reports an `expect` of that lint there as unfulfilled (it bounds the value).
- not verified: the text of Regulation 1182/71 itself.
