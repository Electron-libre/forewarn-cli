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
2. [ ] Deadlines: `deadlines::ReportingDeadlines` computed from the awareness and an optional measure, refusing past
   9999; verified by the scenarios of the spec in `tests/reporting_deadlines.rs`; makes true RDL-1 to RDL-4, RDL-10,
   RDL-11; spec and ADR 0011 accepted.

## Decisions
- Mode: autonomous
- Base commit: 37db817b2f42117106f4c0622446dd4f1bf7ae92
- Deadlines are exact durations from the moment itself (24 h, 72 h, 14 × 24 h), not the periods of Regulation 1182/71, never later than those.
- The final report counts from the measure alone, even before the awareness (RDL-11).
- Years 1 to 9999, as `Date`; a deadline past 9999 is refused (RDL-10).

## Summary of deliverable 1
- done: `Instant` (a `Date` and a UTC time of day), its refusal `InvalidTime`, its order, RFC 3339 writing and
  `checked_add`, through a day count of the proleptic Gregorian calendar.
- checks: project-check passes (fmt, clippy pedantic, tests, specs); docs n/a until the deadlines exist (CLAUDE.md
  status at deliverable 2).
- red: RDL-5, RDL-6, RDL-7, RDL-8, RDL-9: unresolved imports `forewarn_domain::date::Instant`, `InvalidTime`.
- Code review: no findings
- not verified: none.
