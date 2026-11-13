---
priority: high
depends_on: [compute_cra_reporting_deadlines]
why: 'without it the deadlines stay in the domain: the vendor never sees them'
---
# Print the CRA reporting deadlines of each actively exploited match

# Goal
Once the domain computes the CRA reporting deadlines (`compute_cra_reporting_deadlines`), `forewarn match` should
print, for each match flagged actively exploited, its early warning, notification and final report deadlines, from a
moment of awareness the user gives or, by default, the moment of the run.

# Approach
1. A flag `--aware-since <RFC 3339 instant>` setting the moment of awareness; without it, the clock of the run, read
   in the CLI only (the domain gets the instant).
2. Optionally a flag for the moment a corrective or mitigating measure became available, without which the final
   report is printed as due 14 days after a measure is available, with no date.
3. The deadlines printed with the evidence of each exploited match, in UTC; the unmarked matches carry none.
4. Integration tests with a fixed `--aware-since`, so that the output is deterministic.

# Specs
* `specs/cli-match-exploited.md`: amended with the flags and the printed deadlines (new requirements).

# Milestone
Compute CRA reporting deadlines

# Resources
* `specs/cli-match-exploited.md`, `specs/cli-match.md` (its non-goals name the deadlines as a later milestone).
* `crates/forewarn/src/report.rs` and the wiring of `forewarn match` in `crates/forewarn`.
* `specs/reporting-deadlines.md`, written by `compute_cra_reporting_deadlines`.

# Hints
* A default taken from the clock makes the output vary: the tests always pass the instant.
* One moment of awareness per run applies to every match: a per-vulnerability moment needs a state kept between
  runs, out of this milestone.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
`forewarn match` prints the CRA article 14(2) deadlines with each actively exploited match, from `--aware-since` or the
clock of the run, the final report dated only with `--measure-available`. Out of scope: state kept between runs, time
left or overdue. The domain stays clock-free: the CLI parses RFC 3339 (offsets converted to UTC, fraction dropped).

## Plan
1. [x] Flags and JSON: `--aware-since`, `--measure-available` (RFC 3339, offsets converted, refused with exit 2
   before the SBOM), the clock default, `awareSince`, `measureAvailable` and `deadlines` in the JSON report; verified
   by integration tests in `crates/forewarn/tests/exploited.rs`; makes true MXL-14, MXL-15, MXL-16, MXL-17, MXL-19,
   MXL-20, MXL-21 and the rows of MCH-10 and MCH-16. (autonomous)
2. [x] Human report: the moment of awareness (given or from the clock) and the measure, then the deadlines under the
   evidence of each exploited match; verified by integration tests, MXL-H4 among them; makes true MXL-18 and the
   human side of MXL-14 to MXL-16. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: e327ea609414a0c7a9fffa442f7046082124a1b1
- Flag of the measure: `--measure-available` (JSON `measureAvailable`).
- Instants with an offset accepted, converted to UTC, the fraction of a second dropped.
- The human report prints the moment of awareness only when a match is actively exploited.
- MXL-H4 stays a fourth happy path.

## Deliverable 1
- done: `--aware-since`, `--measure-available` (RFC 3339, offset converted, fraction dropped, refused with 2 before
  the SBOM), the clock default, `awareSince`, `measureAvailable` and `deadlines` in the JSON report; README, CLAUDE.md.
- red: MXL-14, MXL-15, MXL-16, MXL-17, MXL-19, MXL-20, MXL-21: `unexpected argument '--aware-since' found`.
- Code review: no findings
- checks: project-check green, check-specs clean (both specs `draft` until deliverable 2 traces MXL-18).
- not verified: none.

## Deliverable 2
- done: the human report prints the moment of awareness (given or from the clock) and the measure above the matches
  when one is actively exploited, and a line `report by:` under the evidence of each; both specs `accepted`; README.
- red: MXL-H4, MXL-14, MXL-15, MXL-16, MXL-17, MXL-18, MXL-21: the report lacks `Reporting deadlines` and `report by:`.
- Code review: no findings
- checks: project-check green, check-specs clean.
- not verified: none.
