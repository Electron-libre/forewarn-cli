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
* `issues/distribute_the_binary.md` (Deliverable 3 summary, follow-up).

# Hints
* `cargo-cyclonedx` writes the SBOM of every workspace member; only that of `forewarn` is shipped.
