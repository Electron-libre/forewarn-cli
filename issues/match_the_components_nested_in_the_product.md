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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-14

## Understanding
Measured on 2026-11-14: `cdxgen` 13.2.0 on a Maven project of two modules nests the modules under
`metadata.component.components` and nowhere else; `syft` on the same project, and both tools on an npm workspace, nest
nothing. Contrary to the Findings, `cargo-cyclonedx` nests the binary target of the product there. Read them after the top-level components, skipping a `bom-ref` already read (SBR-13); SBR-6 is unchanged.

## Plan
1. [x] Nested product components: a `cdxgen` fixture of a two-module Maven sample, the adapter flattening
   `metadata.component.components` after the top-level ones with a `bom-ref` set; verified by `real_tools.rs` (the
   two modules read) and `reading.rs` (duplicate, depth, no `bom-ref`); makes true SBR-13, SBR-H4. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 488042e481c10326591230660a6fafdcfe1b900b
- Q1: a duplicate nested component is skipped, its own nested components still read.
- Q2 (raised by the `cargo-cyclonedx` fixture): the nested components are read for `check` as for `match`; the binary
  target of `cargo-cyclonedx` now shows in `check`, missing a supplier and a hash.

## Deliverable 1
- done: the adapter reads the components nested in the product after the top-level ones, a `bom-ref` already read
  skipped; `cdxgen` Maven fixture; specs, README, CLAUDE.md, fixtures README updated.
- red: SBR-13: `left: ["serde"]` vs `right: ["serde", "a", "a1", "b"]` (nested components not read).
- checks: project-check ok, deliverable-size 169 lines, specs accepted.
- Code review: no findings
- not verified: tools other than `cargo-cyclonedx`, `syft`, `cdxgen`.
