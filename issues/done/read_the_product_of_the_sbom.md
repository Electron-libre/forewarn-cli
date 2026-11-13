---
priority: high
why: 'the early warning names the product and its manufacturer; the domain does not read them yet'
---
# Read the product an SBOM describes

# Goal
A CRA early warning is about a product with digital elements, made available by a manufacturer, not about one of its
dependencies. The domain's `Sbom` holds only the spec version and the components; the product the SBOM describes
(CycloneDX `metadata.component`) and its manufacturer are dropped by the adapter. The CycloneDX adapter should read
them into a domain type, so that a draft early warning can name the product, its version and its manufacturer.

# Findings
* `crates/forewarn-domain/src/sbom.rs`: `Sbom` has `spec_version` and `components` only.
* `crates/forewarn-cyclonedx/src/lib.rs` already turns an organisational entity into a name, else an email or a URL
  (`organization`, used for a component's supplier and manufacturer).
* CycloneDX 1.6 has `metadata.manufacturer`, and `metadata.component` may carry its own `manufacturer` and `supplier`;
  1.5 and older have `metadata.manufacture` (deprecated in 1.6) and `metadata.supplier`.

# Approach
1. A domain type `Product` (name, version, purl, manufacturer, supplier), optional on `Sbom`.
2. The adapter fills it from `metadata.component`, the manufacturer taken from `metadata.manufacturer`, else
   `metadata.component.manufacturer`, else the deprecated `metadata.manufacture` (order to settle at step 1).
3. An SBOM with no `metadata.component`: read as today, the product absent; whether `forewarn check` reports it as a
   gap of completeness (BSI TR-03183-2 expects it) is a candidate, to decide at step 1.

# Specs
* `specs/sbom-reading.md`: a new requirement (SBR-n) for the product and its manufacturer.
* `specs/sbom-completeness.md`: amended only if step 1 decides an absent product is a gap.

# Milestone
Draft the CRA early warning

# Resources
* `crates/forewarn-domain/src/sbom.rs`, `crates/forewarn-cyclonedx/src/lib.rs`.
* `specs/sbom-reading.md`, ADR 0002 (the `cyclonedx-bom` types never leave the adapter).
* CycloneDX 1.6 and 1.7 specification, `metadata`.

# Hints
* The component of the metadata is not one of the `components`: it must not be matched against the vulnerabilities
  nor counted in the completeness report unless step 1 decides so.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
The CycloneDX adapter reads `metadata.component` into an optional domain `Product` (name, version, purl,
manufacturer, supplier) on `Sbom`; the product never joins the matched components. Out of scope: any change to
`forewarn check` or the reports (an absent product is not a completeness gap here).

## Plan
1. [x] Read the product: `Product` and `Sbom::product` in the domain, filled by the adapter with the manufacturer
   and supplier precedence of SBR-10; verified by tests of `crates/forewarn-cyclonedx/tests/reading.rs` and the real
   tool fixtures (~250 lines); makes true SBR-9, SBR-10, SBR-11. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 639a12ee2fd764f61b58b8b384474fa5772e2e5c
- Completeness: an SBOM without a product, or a product without a manufacturer, is not a gap in this issue (answer 1 a).
- Findings added at step 1: the SBOMs of `cargo-cyclonedx`, `syft` and `cdxgen` in the fixtures all write
  `metadata.component` with a name and version (purl except `syft`), and no manufacturer nor supplier.

## Deliverable 1
- done: `Sbom::product` read from `metadata.component`, manufacturer and supplier by SBR-10 precedence; spec
  `sbom-reading` accepted again; `CLAUDE.md` status line.
- checks: project-check (fmt, clippy, tests, specs) pass; docs updated.
- red: SBR-9, SBR-10, SBR-11: unresolved import `forewarn_domain::sbom::Product`, no field `product` on type `Sbom`.
- Code review: no findings
- not verified: none.
- decisions needed: none.

## Deliverable 2 (review fixes)
- done: the manufacturer of the product is that of `metadata.component`, else `metadata.manufacture`
  (`metadata.manufacturer` is the maker of the SBOM in 1.6); SBR-11 narrowed (syft and cdxgen also list the product
  among the components); precedence tests; `product` reuses `to_domain`; follow-up
  `match_the_components_nested_in_the_product`.
- checks: project-check pass.
- red: SBR-10: `takes_the_manufacturer_of_the_product_not_the_one_of_the_bom` got `SBOM Service`, expected `Acme`.
- Code review: no findings
- not verified: none.
- decisions needed: none.
