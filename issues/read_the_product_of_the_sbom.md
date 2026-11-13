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
