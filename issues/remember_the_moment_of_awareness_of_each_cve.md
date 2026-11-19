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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
`forewarn match --awareness <file>` reads, per product and CVE, the moment a run first flagged an exploited CVE,
records the new ones, and counts each match's deadlines (reports, drafts) from its own moment. Without the option,
nothing changes. Out of scope: a per-CVE `--aware-since`, reading the drafts back, locking the file.

## Plan
1. [x] Per-CVE moments inside a run, no new behaviour: the domain drafts each CVE from its own moment
   (`draft_early_warnings` takes the moment of each CVE), the reports take a moment per match; `Awareness`, its human
   lines and deadlines move from `report.rs` to a module `awareness` (keeps `report.rs` under 800 lines); verified by
   the existing tests unchanged; makes true nothing new (refactor). (autonomous)
2. [x] `--awareness <file>`: read, record the new CVEs (atomic write), deadlines, drafts, human and JSON reports from
   the moment of each CVE; verified by tests through the binary (`tests/awareness.rs`); makes true AWR-1 to AWR-9,
   AWR-12, the amended MXL-17, MXL-18 and the MCH-16 row. (autonomous)
3. [x] Refusals: the file unreadable or invalid (exit 3 before the SBOM), unwritable (exit 7, no draft); verified by
   tests through the binary; makes true AWR-10, AWR-11, the MCH-10 rows; sets AWR, MXL, MCH `accepted`. (autonomous, with 2)
4. [x] CI templates: `--awareness` under the kept cache directory (GitHub `~/.cache/forewarn/awareness.json`, GitLab
   `.forewarn-cache/awareness.json`), the comment on the deadlines updated; `ci_template_run.rs` and
   `ci_gitlab_template_run.rs` check that a second daily run reads the moment back and shows the early warning
   overdue; user guide, architecture, ADR 0019 accepted. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 05bdee2fd4cde94e4643b546db606c7933dc44c6
- 1 a: a file the user names, `--awareness <file>` (ADR 0019).
- 2 a: a recorded moment prevails; `--aware-since` gives the moment of the CVEs the file does not hold yet.
- 3 a: a file that cannot be written exits with 7.
- 4 a: the CI templates keep the file in the cache directory they already keep.
- Deliverables 2 and 3 merged (2026-11-19, autonomous): the refusals are the error paths of the reading and the
  writing the file needs, so their tests come first in one deliverable (~800 lines, under the limit); the plan keeps
  the numbering, 3 ticked with 2.
- Estimated size: ~250 + ~650 + ~250 + ~300 changed lines.

## Summaries

### 1. Per-CVE moments inside a run
- done: `draft_early_warnings` takes the moment of each CVE (EWD-4 amended); module `awareness` holds the moments of
  a run, the deadlines of a CVE and their human lines, moved from `report.rs` and `main.rs`; the reports and drafts
  ask it per CVE; the drafts of the specs AWR, MXL, MCH and ADR 0019 come with it.
- red: EWD-4: `expected Moment, found closure` (the domain took one moment for every CVE).
- Code review: no findings.
- checks: project-check passed (fmt, clippy, tests, specs).
- not verified: none.
- decisions needed: none.

### 2 and 3. `--awareness <file>` and its refusals
- done: option `--awareness`, module `awareness_file` (read before the SBOM, entries per product and CVE, rewritten
  whole through the temporary file of the drafts); the deadlines, drafts and reports of each CVE take its recorded
  moment; a per-match line of the human report and `awareSince` of each match in JSON (none in `setAside`, MVX-8
  amended); exit 3 for a file unreadable or invalid, 7 for one unwritable; AWR, MXL, MCH, MVX `accepted`; user guide,
  CLAUDE.md, architecture.
- red: AWR-H1, AWR-H2, AWR-1 to AWR-12, MCH-10, MCH-16: `unexpected argument '--awareness' found`.
- Code review: no findings.
- checks: project-check passed; `tests/matching.rs` (848 lines, over 800 before) gets only `awareSince` in two
  expectations, not split here.
- not verified: none.
- decisions needed: none.

### 4. CI templates
- done: both templates pass `--awareness` under the cache they keep (GitHub `~/.cache/forewarn/awareness.json`,
  GitLab `.forewarn-cache/awareness.json`), their comment on the deadlines rewritten; the runs of the templates check
  the file lies in the cache kept and a second daily run counts from the moment of the first; user guide (In CI),
  CLAUDE.md; ADR 0019 accepted.
- red: none traced (template tests): `examples/ci/gitlab-ci.yml: the match remembers the moments of awareness`.
- Code review: no findings.
- checks: project-check passed.
- not verified: the eviction of the GitHub cache after 7 days unused, a property of GitHub.
- decisions needed: none.
