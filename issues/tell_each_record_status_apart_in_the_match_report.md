---
priority: medium
depends_on: []
why: 'a reader can take a vulnerability that a source says affects the component for one that does not, and dismiss it'
---
# Tell the status of each record apart from the whole match in the human report of `match`

# Goal
When the records of one vulnerability disagree, the human report of `forewarn match` prints the status of the last
record at the end of the line, `… records GHSA-7xr5-9hcq-chf9 from GHSA, PYSEC-2025-47 from PYSEC (does not affect)`,
which reads as a verdict on the whole match listed under `Affected`. The report should show at a glance which records
say the component is affected and which do not, so that no one dismisses a match that a source still says affects
the component.

# Findings
* Demo run of 2026-11-16: a Maven and Python project, SBOM by `syft` (CycloneDX 1.6), `forewarn match` against the
  OSV archives of PyPI and Maven fetched that day.
* `django 3.2.0`: 11 of its 38 matches end with `(does not affect)`, e.g. CVE-2025-48432, CVE-2025-57833,
  CVE-2025-64458, CVE-2026-6873.
* The records truly disagree: for CVE-2025-48432, `GHSA-7xr5-9hcq-chf9` has a range `introduced 0, fixed 4.2.22`
  (3.2.0 affected), `PYSEC-2025-47` starts at `introduced 4.2` (3.2.0 not affected). The matching is right (VMT-18);
  only the rendering is ambiguous.
* `crates/forewarn/src/report.rs`, around line 271: the status is appended after `<id> from <source>` with nothing
  separating it from the next record or the end of the line. The JSON report already gives each record its own
  boolean (around line 602).

# Approach
1. Attach the status to its record unambiguously, e.g. `PYSEC-2025-47 from PYSEC: does not affect`, or put the
   records on their own indented lines.
2. Group the records by status: `affected per GHSA-7xr5-9hcq-chf9 (GHSA); not per PYSEC-2025-47 (PYSEC)`.
3. Mark a match whose sources disagree (`sources disagree`), so that a reader looking for doubtful matches finds them.

# Specs
* `specs/cli-match.md`: amends MCH-1 (how the status of a record is shown).

# Milestone
Proof-of-concept demo

# Resources
* `crates/forewarn/src/report.rs` (human report of `match`), `crates/forewarn/tests/matching.rs`.
* `specs/vulnerability-matching.md` (VMT-18), `crates/forewarn-domain/src/matching.rs` (`RecordStatus`).

# Hints
* Keep the escaping of record ids and sources through `push_escaped` (MCH-18).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
Print the records of a match grouped under their status (`affected per …; not affected per …; not evaluated per …`)
in the human report of `match`, so that a record that does not affect the component reads apart from the whole
match. Out of scope: the JSON report (already one boolean per record) and the matching itself (VMT-18 unchanged).

## Plan
1. [x] Group the records by status: `report.rs` prints each group under its label, in that order, empty groups left
   out; verified by `crates/forewarn/tests/matching.rs` (the mixed-status test and the strings that quote
   `records …`); makes true MCH-1 as amended. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 2027233a78e0dc51342b87292f7ae2ff111d5343
- 1 a: records grouped under `affected per`, `not affected per`, `not evaluated per`.

## Deliverable 1
- done: the human report of `match` prints the records of a match under `affected per`, `not affected per` and
  `not evaluated per`, in that order, the groups separated by `; `; README and MCH-1 say so.
- red: MCH-1: `records GHSA-fixed from GHSA (does not affect), GHSA-git from GHSA (not evaluated), RUSTSEC-2020-0071
  from RUSTSEC` printed instead of the grouped records.
- Code review: 1 finding: the doc comment of `push_evidence` sat above the new function, moved back; fixed.
- not verified: none; decisions needed: none.
- Docs: README.md (the `match` paragraph); CLAUDE.md n/a (does not describe the record format).
