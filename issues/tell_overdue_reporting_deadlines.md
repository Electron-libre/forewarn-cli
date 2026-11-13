---
priority: medium
depends_on: [compute_cra_reporting_deadlines, cli_print_reporting_deadlines]
why: 'helps a vendor under pressure, but the deadlines printed already let them act'
---
# Tell the time left before each CRA reporting deadline, or that it is overdue

# Goal
A printed deadline still leaves the vendor to compare it with the clock. At a given moment, the domain should tell
for each deadline the time left before it or that it is overdue, and `forewarn match` should print it next to the
deadline.

# Approach
1. A domain rule taking the deadlines and an instant, giving for each the time left or the time overdue (a deadline
   reached exactly: to settle, due or overdue).
2. The CLI passes the moment of the run (or a flag fixing it, for the tests) and prints the state next to each
   deadline.
3. Scenarios at the bounds: one second before, at, one second after each deadline.

# Specs
* `specs/reporting-deadlines.md`: amended with the time left (new requirements).
* `specs/cli-match-exploited.md`: amended with the printed state.

# Milestone
Compute CRA reporting deadlines

# Resources
* `specs/reporting-deadlines.md` and the instant type of `compute_cra_reporting_deadlines`.
* The flags and output of `cli_print_reporting_deadlines`.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
At a moment, the domain tells for each deadline the seconds left (zero when reached exactly: still on time) or the
seconds overdue; `forewarn match` prints it next to each deadline in the human report, at `--now` or the moment of
the run. The JSON report is left as is (non-goal of MXL).

## Plan
1. [x] Domain state of a deadline at a moment (`ReportingDeadlines::at`, time left or overdue in seconds); verified by
   the scenarios of `crates/forewarn-domain/tests/reporting_deadlines.rs` one second before, at and after each
   deadline; makes true RDL-12 to RDL-15. (autonomous)
2. [x] `forewarn match --now` and the time left or overdue printed next to each deadline, with the moment of the check;
   verified by end-to-end tests of `crates/forewarn/tests/exploited.rs` at the bounds of each deadline; makes true
   MXL-22 to MXL-26. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: cc2d1123f819c0f390d861615befc1ef83e99e32
- A deadline reached exactly is due, not overdue (`due now`).
- The flag fixing the moment of the check is `--now`, visible.
- The JSON report gets no time left (non-goal).
- Durations as `2d 3h 4m 5s`, the leading zero units left out.

## Deliverable 1

done: `DeadlineState` (`Left` / `Overdue` seconds), `ReportingDeadlines::at`, `Moment::seconds_until`; spec RDL
accepted; CLAUDE.md status line.

| check | result |
|---|---|
| tests | pass |
| lint | pass |
| specs | pass |
| docs | CLAUDE.md |
| code review | low, clean |

red: RDL-H3, RDL-12, RDL-13, RDL-14, RDL-15: unresolved imports `forewarn_domain::deadlines::DeadlineState`, `DeadlineStates`; no method named `at` found for struct `ReportingDeadlines`

Code review: no findings

not verified: none
decisions needed: none

## Deliverable 2

done: `forewarn match --now`; the human report prints the moment of the check and, next to each deadline, the time
left, `due now` or `overdue by`; spec MXL accepted; README and CLAUDE.md.

| check | result |
|---|---|
| tests | pass |
| lint | pass |
| specs | pass |
| docs | README.md, CLAUDE.md |
| code review | low, clean |

red: MXL-H5, MXL-22, MXL-23, MXL-24, MXL-25, MXL-26: error: unexpected argument '--now' found

Code review: no findings

not verified: none
decisions needed: none
