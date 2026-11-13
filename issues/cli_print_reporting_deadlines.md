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
