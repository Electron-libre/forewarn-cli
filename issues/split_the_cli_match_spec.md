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
