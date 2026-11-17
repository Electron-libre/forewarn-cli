---
priority: low
depends_on: [distribute_the_binary]
why: 'the release SBOM reads and ships; its gaps only weaken the example forewarn sets, they block no beta tester'
---
# Complete the SBOM of the release binaries

# Goal
The release workflow ships a CycloneDX SBOM of each binary (`forewarn-<target>.cdx.json`, ADR 0015), and
`forewarn check` itself reports it incomplete. A tool that tells vendors which fields the CRA expects should ship an
SBOM it finds complete, or say why a field stays empty.

# Findings
* 2026-11-17, at `21b8733`: `cargo cyclonedx --manifest-path crates/forewarn/Cargo.toml -f json --spec-version 1.6
  --target aarch64-apple-darwin --no-build-deps`, read by `forewarn check`: 28 of 95 components incomplete.
* The five path crates `forewarn-*` lack a supplier and a hash; their package URL carries
  `download_url=file://../forewarn-<crate>`.
* Third-party crates (`clap`, `anstream`, `futures-core`…) lack a supplier: Cargo metadata has no supplier field.
* The release workflow runs `forewarn check --allow-incomplete` on each SBOM, so the gaps never fail it.
* 2026-11-17, at `c9968c9`, the four targets: 28 of 98 incomplete on Linux, 29 on macOS (`nix` too). The five path
  crates miss supplier and hash; 23 crates.io crates miss a supplier (no `authors` in their manifest), the other 70
  pass on their `authors`. All 93 others come from crates.io. `cargo-cyclonedx` also writes an SBOM in each member's
  directory.
* `cargo package --workspace --no-verify` gives reproducible `.crate` hashes, but only with a `version` on each path
  dependency and without `publish = false`.

# Approach
1. Measure: list the missing fields per component across the four targets.
2. The workspace crates: name the manufacturer as supplier (a post-processing step of the workflow, or the
   `[package.metadata]` cargo-cyclonedx reads, if any) and decide whether a hash of a crate built from source is
   meaningful; otherwise record why it stays empty.
3. Third-party crates: a supplier derived from crates.io (the registry as distributor) or left empty with the reason
   in the ADR; compare what `syft` or `cdxgen` fill for the same project.
4. Once complete, drop `--allow-incomplete` from the workflow so a regression fails the release.

# Milestone
Beta

# Resources
* `.github/workflows/release.yml` (job `notices`), ADR 0015, `specs/sbom-completeness.md`.
* `issues/done/distribute_the_binary.md` (Deliverable 3 summary, follow-up).

# Hints
* `cargo-cyclonedx` writes the SBOM of every workspace member; only that of `forewarn` is shipped.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-17

## Understanding
The release SBOMs pass `forewarn check` without `--allow-incomplete`: a `jq` step after `cargo-cyclonedx` names the
supplier of the workspace crates and the product's manufacturer, hashes each workspace crate from its source tree,
and names crates.io the supplier of the registry crates (ADR 0016 draft). No change to `forewarn` itself.

## Plan
1. [x] Complete the release SBOMs: the `jq` step and the crate hashes in `release.yml`, `--allow-incomplete` dropped,
   ADR 0016, user guide (how to recompute a crate hash); verified by `release_workflow.rs` (the check step passes no
   `--allow-incomplete`, the completion step runs before it) and by the step run locally on the four targets,
   `forewarn check` exiting 0 on each. (autonomous)
2. [x] Fixes of the `high` review of the issue: `git archive` outside a pipe so a failure fails the step, the hashes
   keyed by package name, only the hashed path crates named the manufacturer's, the product hashed, `core.autocrlf`
   fixed and Git 2.42 named, the test of the order searching the `jq` call, the manufacturer read from the
   workflow; verified by `release_workflow.rs` and the step rerun on the four targets. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: c9968c94997ea6a9de5a1e701b8be61154ebf23b
- Manufacturer: `Electron-libre` (`https://github.com/Electron-libre`), supplier of the workspace crates and
  manufacturer of the product.
- Hash of a workspace crate: SHA-256 of `git -c tar.umask=0022 archive --format=tar --mtime='1970-01-01 00:00:00
  +0000' <tag>:crates/<crate>`; the umask and the mtime are fixed because a tree given to `git archive` takes the
  current time and the local umask (checked: without them two runs differ).
- crates.io the supplier of every registry crate, their `authors` kept.

## Summary of deliverable 1
- done: `.github/sbom-complete.jq` completes the SBOM of each target in `release.yml` (manufacturer `Electron-libre`
  supplier of the workspace crates and manufacturer of the product, crates.io supplier of the registry crates, the
  source tree hash of each workspace crate); `forewarn check` runs without `--allow-incomplete`; ADR 0016.
- checks: project-check passes; the step run locally on the four targets, each SBOM `Complete: 98 components
  checked`.
- red: none (the release workflow has no spec); before the program: `jq` failed on the missing
  `.github/sbom-complete.jq`, and the workflow still passed `--allow-incomplete`.
- not verified: the step on the GitHub runners (the pull request runs it, the workflow file changed); `jq` on the
  Windows test runner (listed in the image).

## Summary of deliverable 2
- done: the 9 findings of the `high` review fixed (see the plan line).
- checks: project-check passes; the step extracted from `release.yml` and run locally on the four targets, each SBOM
  `Complete: 98 components checked`, the product with its manufacturer and hash.
- red: none (no spec); `a_path_crate_outside_the_workspace_keeps_no_supplier_nor_hash` written against the former
  program, which named any path crate the manufacturer's.
- not verified: the step on the GitHub runners (the pull request or the next tag runs it).
