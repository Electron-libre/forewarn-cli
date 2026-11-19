---
priority: low
why: 'a file component rarely carries a package URL, but when it does it can be reported as an affected package'
---
# Leave the file components out of the matching

# Goal
The reading tells the file components apart (SBR-15: a manifest or a lock file a tool read, CycloneDX type `file`),
and the completeness check already treats them apart, but the matching does not: a file component that carries a
package URL is matched like a package, and can be reported affected by the vulnerabilities of the package it names.
Expected outcome: the matching sets a file component apart with a reason of its own, as it does for the first-party
components, and never matches it.

# Findings
* 2026-11-19, tag `v0.3.0`: in `forewarn-domain`, only `completeness.rs` reads `Component::file`;
  `ComponentPackage::of` returns `ComponentReason::FirstParty` for a first-party component and has no case for a
  file, so `match_components` matches a file component whose package URL it can place.
* The table of VMT-10 has a `first-party` reason, applied before the others; it has none for a file.

# Approach
1. A `file` reason in the table of VMT-10 (applied before the reasons on the package URL, like `first-party`) and a
   `ComponentReason` variant for it in `ComponentPackage::of`; or leave the file components out of the report
   entirely, not even counted as not evaluated: decide at step 1.
2. The report of the CLI shows the new reason like the others.
3. A release under a new tag, so the crates that depend on `forewarn-domain` by tag can take it.

# Specs
* `specs/vulnerability-matching.md`: VMT-10 amended (a reason, or a new requirement leaving the files out), VMT-11.

# Resources
* `crates/forewarn-domain/src/matching.rs` (`ComponentPackage::of`, `ComponentReason`), `completeness.rs` (how the
  files are set apart there).
* `specs/vulnerability-matching.md` (VMT-10, VMT-11), `specs/sbom-reading.md` (SBR-14, SBR-15).

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
A file component (SBR-15) is never matched nor sent to the OSV API: `ComponentPackage::of` returns a new
`ComponentReason::File` after `FirstParty` and before the reasons on the package URL; the CLI reports it `file`.
Out of scope: leaving the files out of the report entirely (they stay listed, not evaluated, so nothing is hidden).

## Plan
1. [x] File reason: `ComponentReason::File` in the domain, `file` in the human and JSON reports, docs; verified by a
   domain test (`component_package.rs`) and a CLI test through `--osv-api` with a mirror (in `tests/api.rs`, beside
   its OSV API mirror; the oversized `tests/matching.rs` left alone); makes true VMT-10, VMT-11, MCH-44.
   (autonomous)

## Decisions
- Mode: autonomous
- Step 1 of the issue: a `file` reason (option 1), not leaving the files out of the report: a component a run does
  not evaluate is always shown (VMT-3).
- Step 3 of the issue (the release under a new tag) is proposed at the close, as the close of a milestone does.
- `vulnerability-matching.md` over `spec_max_bytes` (25,261 > 25,000): warning kept, its split filed as an issue.
- Base commit: c8f7850bfe749341c843faa503b84219c153ec85

## Deliverable 1
done: `ComponentReason::File` after `FirstParty` in `ComponentPackage::of`, reported `file` (human and JSON); specs
VMT-10 and MCH-44 amended and accepted again; user guide, architecture, `CLAUDE.md`, doc comment of `Component::file`.

| check | result |
|---|---|
| tests | pass (`cardinal run project-check`) |
| lint | pass |
| specs | pass; warning kept: `vulnerability-matching.md` over `spec_max_bytes`, filed as `issues/split_the_vulnerability_matching_spec.md` |
| docs | updated |
| code review | `/code-review low`: clean |

red: VMT-10, VMT-11: `ComponentPackage::of` returned `Ok(ComponentPackage { ecosystem: "crates.io", name: "time", .. })`
for a file, expected `Err(File)`; MCH-44: the `--osv-api` run exited 1 (`/Cargo.lock` matched as `time` 0.1.43), expected 0.

Code review: no findings

not verified: none.
decisions needed: none.
