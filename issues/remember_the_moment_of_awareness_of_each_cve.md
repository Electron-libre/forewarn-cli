---
priority: medium
why: 'a scheduled CI run restarts the 24 h and 72 h deadlines each day, so an ignored exploited CVE never shows overdue; the templates work without it'
---
# Remember the moment of awareness of each exploited CVE across runs

# Goal
The moment of awareness is `--aware-since`, else the moment of the run (MXL-17), one for every exploited match of the
run. A job that runs `forewarn match` each day (the GitHub Actions template) therefore counts the 24 h and 72 h
deadlines from each run again: a CVE left unreported never shows overdue, and one `--aware-since` cannot serve a CVE
known for a week and one found today. Each actively exploited CVE should keep the moment it was first flagged, so a
later run counts its deadlines from it.

# Findings
* Raised by the `high` review of `github_actions_template` (2026-11-19): the template's daily run, the deadlines
  restarting each day.
* `specs/cli-match-exploited.md`: MXL-17 (the moment of awareness), MXL-18 (printed with its origin).

# Approach
1. A file of the moments of awareness per product and CVE, read and written by `forewarn match` (an option naming it,
   or a place under the cache); kept between CI runs like the cache.
2. Or read the moment from the drafts of `--drafts` already written for that CVE (they print the deadlines), with no
   file of its own.
3. `--aware-since` keeps priority, for every CVE or per CVE (`--aware-since CVE-…=<instant>`).
Decided at step 1, weighing a state the CLI keeps against its determinism (same inputs, same output).

# Specs
* `specs/cli-match-exploited.md`: amends MXL-17, MXL-18.

# Resources
* `specs/reporting-deadlines.md`, ADR 0011: the deadlines on UTC seconds.
* `crates/forewarn/src/drafts.rs`: the drafts of a product and their names.
* `examples/ci/github-actions.yml`: the comment on the deadlines, to update once done.

# Hints
* The deadlines are the costliest bug area (`CLAUDE.md`, Testing priority): BDD scenarios for a moment read back.
