---
priority: high
why: 'without VEX a vendor cannot record that a match does not affect its product, so a beta tester has no way to silence a false positive and the CI keeps failing'
---
# Read the VEX verdicts of an SBOM and apply them to the matches

# Goal
`CLAUDE.md` names VEX for the exploitability verdicts, but `forewarn` reads none: `specs/sbom-reading.md` lists
"Services, dependencies and VEX statements" as non-goals for later milestones. A vendor that analysed a match
(e.g. the vulnerable function is never called) has no way to tell `forewarn`, so `match` keeps reporting it, keeps
exiting with 6 when it is exploited, and keeps drafting an early warning. `forewarn` should read CycloneDX VEX
verdicts and report a match the vendor marked not affected apart from the affected ones, out of the exit code and
the drafts.

# Findings
* `cyclonedx-bom` 0.9.0 (already a dependency of `forewarn-cyclonedx`) models `vulnerabilities[]` with
  `analysis.state`: `resolved`, `resolved_with_pedigree`, `exploitable`, `in_triage`, `false_positive`,
  `not_affected`, and `affects[].ref` naming the components by `bom-ref`.
* `specs/early-warning-draft.md` already lists as a non-goal "A draft for a component the vendor's verdict (VEX)
  marks not affected".
* The adapter (`crates/forewarn-cyclonedx/src/lib.rs`, `read_json`) reads no `vulnerabilities` today.
* Unknown: whether vendors ship VEX inside the SBOM or as a separate CycloneDX document (both are allowed); what
  CSAF VEX or OpenVEX support beta testers would ask for.

# Approach
1. Read the VEX of a CycloneDX document in the adapter (inside the SBOM, and/or a separate file given with an option
   such as `--vex <file>`) into domain types: per vulnerability id (CVE or other alias) and component, a verdict.
2. In the domain, apply the verdicts to the matches: `not_affected` and `false_positive` (and maybe `resolved`)
   take a match out of the affected ones; `exploitable` and `in_triage` keep it; a verdict for an id matches through
   the aliases of the match.
3. In the CLI: list the matches set aside by a verdict apart, with the verdict and its justification, in text and
   JSON; no exit code 6 and no draft for them.
Likely two deliverables (adapter and domain, then CLI); propose a split at step 1 if larger.

# Specs
* `specs/sbom-reading.md` (amends the non-goal on VEX), `specs/vulnerability-matching.md` or a new
  `specs/vex-verdicts.md`, `specs/cli-match.md`, `specs/cli-match-exploited.md`, `specs/early-warning-draft.md`.

# Milestone
Beta

# Resources
* `crates/forewarn-cyclonedx/src/lib.rs`, `crates/forewarn-domain/src/` (matching, exploited), `crates/forewarn/src/report.rs`.
* ADR 0002 (the `cyclonedx-bom` types never leave the adapter).
* CycloneDX 1.6 specification, `vulnerabilities[].analysis`.

# Hints
* A verdict must never hide a match silently: the report lists what was set aside and why.
* Keep the CRA deadlines unchanged for the matches a verdict leaves affected.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-16

## Understanding
Read CycloneDX VEX verdicts (in the SBOM and in `--vex <file>` documents), set aside in the domain the matches a
`not_affected` / `false_positive` verdict names (by `bom-ref` and id or alias), and report them apart in `match`, out
of the exit code, the deadlines and the drafts. Out of scope: CSAF VEX, OpenVEX, verdicts in `check`, `--vex -`.
Means: verdicts applied after the flagging, so a set-aside match keeps its exploited evidence (ADR 0014).

## Plan
1. [x] Split `crates/forewarn/src/main.rs` (810 lines, over the file size limit): move the `clap` arguments into a module `args`, no change of behaviour; verified by `cargo test`; makes true nothing new (~300 lines, a move). (autonomous)
   Summary: done: `Cli`, `Command`, `CheckArgs`, `MatchArgs`, `Format`, `GivenMoment` and the parsers `parse_moment`, `moment`, `parse_refresh` moved to `crates/forewarn/src/args.rs` (main.rs 810 → 615 lines); the specs and ADR 0014 drafts committed with it. Checks: project-check green (fmt, clippy, tests, specs), docs (architecture, CLAUDE.md) updated. red: none (a move, no new test). Code review: no findings.
2. [x] Adapter and domain: `bom-ref` on `Component` and `ComponentRef`, the module `forewarn_domain::vex` (verdicts, applied to a `FlaggedReport`, the matches set aside), `read_json` returning the SBOM's verdicts and `read_vex_json` reading a VEX document; verified by tests in `forewarn-domain/tests/vex_verdicts.rs` and `forewarn-cyclonedx/tests/vex.rs`; makes true SBR-16, VEX-1 to VEX-13 (~750 lines). (autonomous)
   Summary: done: `Component` and `ComponentRef` carry the `bom-ref`; `forewarn_domain::vex` (`Verdict`, `SetAside`, `apply_verdicts`), the `FlaggedReport` gaining `set_aside()` and `unused_verdicts()`; `read_json` fills `Sbom::verdicts`, `read_vex_json` reads a VEX document. Checks: project-check green; specs `sbom-reading` and `vex-verdicts` accepted (all traced); docs (architecture, CLAUDE.md) updated; ADR 0014 accepted. red: SBR-16, VEX-1 to VEX-13: `unresolved import forewarn_domain::vex`, `struct Component has no field named bom_ref`, then `unresolved import read_vex_json`. Code review: no findings. Not verified: a real VEX document from a tool (the tests write theirs by hand).
3. [x] CLI: `--vex <path>` (repeatable), the set-aside matches, the sources of verdicts and the unused verdicts in the human and JSON reports (a module `set_aside` beside `report`, which is at 719 lines), exit codes and drafts without them; verified by `crates/forewarn/tests/vex.rs` through the binary; makes true MVX-1 to MVX-10 and the amended rows of MCH-10 and MCH-16 (~700 lines). (autonomous)
   Summary: done: `--vex <PATH>` (repeatable, `args`), module `vex` of the CLI (sources of verdicts, matches set aside, unused verdicts, in text and JSON), verdicts applied after the flagging in `main` (`matched`), a `--vex` file that cannot be read exits with 3; MVX-3 narrowed to print the VEX lines only when the SBOM holds a verdict or `--vex` is given, so reports without VEX are unchanged. Checks: project-check green; specs `cli-match-vex` and `cli-match` accepted; docs (user guide, architecture, CLAUDE.md) updated. red: MVX-1 to MVX-10: `unexpected argument '--vex'`, and exit 1 or 6 instead of 0 for a match the SBOM sets aside. `crates/forewarn/tests/matching.rs` was already over the file size limit (841 lines); it grows by 4 lines (the new JSON members), not split here. Code review: no findings.
4. [x] Fixes of the `high` review of the issue: the draft names a component once whatever its `bom-ref` (EWD-3); a BOM-Link whose `bom-ref` is no component's names a component by that `bom-ref` as package URL (VEX-7 amended); a blank `analysis.state` gives no verdict (VEX-5, VEX-11); the match header shared by the Affected and Set aside sections, the error of an unreadable CycloneDX document shared by the SBOM and `--vex`, the ids of a match read once per match; verified by new tests in `forewarn-domain/tests/early_warning.rs`, `vex_verdicts.rs` and `forewarn-cyclonedx/tests/vex.rs`. (autonomous)
   Summary: done as above; checks: project-check green, specs green. red: EWD-3: `names_a_component_listed_twice_under_two_bom_refs_once` gave two components; VEX-7: the BOM-Link test left the match affected; VEX-11: a blank state gave a verdict. High review: 10 findings: 1, 2, 4 fixed (bugs); 5, 6, 8 fixed (duplication, recomputation); 3 (a stale draft of an earlier run stays in `--drafts`) filed as `issues/done/remove_stale_draft_early_warnings.md`, it predates VEX (an upgraded component does the same); 7 (verdicts cloned into one list) not fixed: VEX documents are small and the copy keeps `Verdicts` self-contained; 9 (indices into the slice given to `apply_verdicts`) not fixed: the CLI builds that slice once and owns it, a separate outcome type would widen the change; 10 (`deadlines` built then removed in `setAside`) not fixed: the JSON test of MVX-8 pins its absence. Code review: no findings.

## Decisions
- Mode: autonomous
- Base commit: 714b050ee2157406aa87d7780c1a6f9bc4d4ac76
- `resolved` and `resolved_with_pedigree` set a match aside, like `not_affected` and `false_positive` (VEX-8).
- A target that is the `bom-ref` of no component names the components whose package URL equals it as written (VEX-7).
- A `--vex` file that cannot be read exits with 3, as an SBOM (MVX-7, MCH-10).
- The verdicts that name no match are listed (`unusedVerdicts`, MVX-6).
