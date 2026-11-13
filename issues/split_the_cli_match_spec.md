---
priority: low
why: 'a warning of check-specs, no behaviour at stake: the spec stays correct, only harder to read'
---
# Split the spec of `forewarn match`, its exploited lists apart

# Goal
`specs/cli-match.md` holds 41 requirements, over the bound of 40 (`spec_max_requirements`), and `cardinal run
check-specs` warns that it outgrows its capability. The flagging of exploited matches added a family of its own
(the options `--kev`, `--no-kev`, `--kev-url`, `--euvd`, `--no-euvd`, `--euvd-url`, the freshness of each list, their
cache entries, the exit code 6). Moving that family into a spec of its own leaves `cli-match.md` with the matching of
the OSV records, each spec under the bound.

# Findings
* `cardinal run check-specs` on 2026-11-13, after `issues/done/read_euvd_exploited_list.md` added MCH-36 to MCH-41:
  `specs/cli-match.md: outgrows its capability: 41 requirements over 40`.
* The exploited-list requirements are MCH-29 to MCH-41, plus rows of MCH-10, MCH-14 and MCH-16 (exit codes, error
  lines, `exploitedLists`, `exploitedCount`, `exploited`).

# Approach
1. List the requirements and scenarios that only concern the exploited lists, and the shared ones (MCH-10, MCH-14,
   MCH-16) that keep a row in `cli-match.md` and point to the new spec.
2. Move them as `skill:write-spec` says for a split: each takes the next number of the new spec (a new id, e.g.
   `MXL`), its old id stays as `withdrawn: moved to MXL-n`, and the tests cite the new id.
3. Check that both specs pass `check-specs` with no bound warning, and that no behaviour changes (the tests are only
   re-cited).

# Specs
* `specs/cli-match.md` (MCH-29 to MCH-41 withdrawn as moved) and a new spec of the exploited lists of `forewarn match`.

# Resources
* `specs/README.md` (format, withdrawn ids), `skill:write-spec` (the split rule).
* `crates/forewarn/tests/exploited.rs`, `crates/forewarn/tests/fetching.rs`: the tests citing those ids.

# Hints
* Never renumber an accepted requirement in place: tests and issues cite the ids.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Move the exploited-list family of `specs/cli-match.md` (MCH-29 to MCH-41, happy paths MCH-H4 to MCH-H6 and their edge
scenarios, two non-goals, ADRs 0008 and 0009) into `specs/cli-match-exploited.md` (id `MXL`); MCH-10, MCH-14 and
MCH-16 keep their rows, pointing to MXL ids. No behaviour changes: only citations move.

## Plan
1. [x] Split the spec: `specs/cli-match-exploited.md` with MXL-1 to MXL-13 and MXL-H1 to MXL-H3, MCH-29 to MCH-41
   `withdrawn: moved to MXL-n`, the tests of `exploited.rs`, `fetching.rs` and `main.rs` and the doc comments of
   `main.rs` and `report.rs` re-cited; verified by `check-specs` (no bound warning, both specs `accepted`) and
   `project-check` unchanged; makes true MXL-1 to MXL-13. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 81c02509f597eb7b0aa6bbde117eac32405abd86
- Mapping: MCH-29→MXL-1, 30→2, 31→3, 32→4, 33→5, 36→6, 37→7, 38→8, 39→9 (Behaviour), 34→10, 35→11, 40→12, 41→13
  (Contract); MCH-H4→MXL-H1, H5→H2, H6→H3. The happy paths cannot be withdrawn (the checker only knows withdrawn
  requirements), so MCH-H4 to MCH-H6 disappear and their tests cite the MXL ones.

## Summary of deliverable 1
- done: `specs/cli-match-exploited.md` (MXL-1 to MXL-13, MXL-H1 to MXL-H3) holds the exploited lists of `forewarn match`;
  `specs/cli-match.md` keeps 28 live requirements, MCH-29 to MCH-41 withdrawn as moved; tests and doc comments re-cited.
- checks: project-check pass (fmt, clippy, tests); check-specs pass, no bound warning; docs: CLAUDE.md and the
  non-goals of `exploited-flagging.md` and `euvd-reading.md` point to the new spec.
- red: none (no test added: the existing tests are only re-cited).
- Code review: no findings

## Deliverable 2: high review fixes
2. [x] Fix the five findings of the high review of the issue: the tests of the conflicting KEV and EUVD options and of
   an unreadable KEV file also cite MXL-3, MXL-4, MXL-7, MXL-8; three MCH scenarios name MXL-1, MXL-2, MXL-5; the
   module docs of `report.rs` and `fetching.rs` and the non-goal of `kev-reading.md` point to the new spec; verified by
   project-check and check-specs. (autonomous)
- red: none (citations and docs only).
- Code review: no findings
