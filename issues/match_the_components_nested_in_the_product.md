---
priority: medium
why: 'a component nested only under the product is never matched, so an exploited vulnerability in it is missed; no tool of the fixtures writes one yet'
---
# Match the components nested in the product an SBOM describes

# Goal
CycloneDX lets `metadata.component` nest components of its own (`metadata.component.components`). The adapter reads
the product but neither it nor `components` returns those nested components (`specs/sbom-reading.md`, non-goals), so
`forewarn match` never matches them and `forewarn check` never checks them. A library nested only there, say an
actively exploited one, would go unreported.

# Findings
* Raised by the `high` review of `read_the_product_of_the_sbom` (2026-11-13).
* The fixtures of `cargo-cyclonedx`, `syft` and `cdxgen` nest nothing under `metadata.component`; whether other tools
  (multi-module builds, workspaces) do is not measured.

# Approach
1. Measure first: generate SBOMs of a multi-module project with the tools of the fixtures and others (`cdxgen` on a
   Maven or npm workspace) and look for components nested under `metadata.component`.
2. Candidate: flatten them into the components (SBR-6), after the top-level ones, skipping a component already listed
   with the same `bom-ref`.

# Specs
* `specs/sbom-reading.md`: SBR-6 amended, the non-goal on the components nested in `metadata.component` dropped.

# Resources
* `crates/forewarn-cyclonedx/src/lib.rs` (`flatten`, `product`), `specs/sbom-reading.md`.
* `crates/forewarn-cyclonedx/tests/fixtures/README.md`: how the fixtures were generated.

# Hints
* A component listed both at the top level and nested under the product must not be matched twice.
