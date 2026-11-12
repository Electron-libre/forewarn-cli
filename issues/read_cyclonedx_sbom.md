---
priority: high
depends_on: [bootstrap_cargo_workspace]
why: 'every later step of the milestone and of matching works on the parsed components'
---
# Read a CycloneDX SBOM and check its version

# Goal
`rollcall` must read a CycloneDX SBOM in JSON, produced by an existing tool, into domain components (name, version,
package URL, supplier, licenses, hashes). It accepts spec versions 1.6 and 1.7, accepts older versions with a flag
(below the BSI TR-03183-2 threshold), and rejects a file that is not a CycloneDX JSON SBOM with a clear error.

# Findings
* Not measured yet: the support of spec versions 1.6 and 1.7 by the CycloneDX model crate of the
  `cyclonedx-rust-cargo` repository (`cyclonedx-bom`). `CLAUDE.md` asks to check it before relying on it.

# Approach
Measure first: check which spec versions the `cyclonedx-bom` crate parses (1.6, 1.7) and its license.
Then candidate solutions:
1. Use `cyclonedx-bom` if it parses 1.6 and 1.7, mapping its model to domain types in the adapter.
2. Otherwise, deserialize the subset of fields needed with `serde` in the adapter (the domain only needs a few fields).
3. Read `specVersion` before the full parse, so that an unsupported or older version is reported as such rather than
   as a parse error.
Test fixtures: one small SBOM produced by each of `cargo-cyclonedx`, `syft` and `cdxgen`, plus hand-made edge cases
(1.5 file, missing `specVersion`, not CycloneDX).

# Specs
* `specs/sbom-reading.md` (to write at step 1): accepted versions, the flag on older ones, the errors.

# Milestone
Read and check an SBOM

# Resources
* `CLAUDE.md`: design constraints (never build a scanner, input format).
* CycloneDX specification 1.6 and 1.7 (JSON schema).
* BSI TR-03183-2 (minimum SBOM version).

# Hints
* Never add dependency detection: the input is always an SBOM produced by another tool.
* Nested components (`components[].components`) exist in real SBOMs; decide whether to flatten them.
* XML input is out of scope for this milestone unless the crate gives it for free.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-12

## Understanding
Read a CycloneDX JSON SBOM into domain components with its spec version, flag 1.3–1.5 as below the BSI minimum and
refuse the rest with a named error (`specs/sbom-reading.md`). Out of scope: XML, the CLI command, completeness rules.
Means: option 1 of the issue (`cyclonedx-bom` 0.9.0 parses 1.3–1.7, measured), plus option 3 (pre-read of
`bomFormat` and `specVersion`); ADR 0002.

## Plan
1. [x] Domain types and the adapter's reading: `Sbom`, `Component`, `SpecVersion` with the BSI threshold in the
   domain; `read_json` in `rollcall-cyclonedx` over `cyclonedx-bom`, nested components flattened, the errors of
   SBR-7; MSRV 1.86; hand-made fixtures (1.6, 1.7, 1.5, 1.2, nested, unknown values, no specVersion, SPDX, not JSON,
   invalid); verified by tests in `crates/rollcall-cyclonedx/tests`; makes true SBR-1, SBR-2, SBR-3, SBR-5, SBR-6,
   SBR-7, SBR-8, SBR-H2. (autonomous)
2. [ ] Fixtures of real tools: one small SBOM each from `cargo-cyclonedx`, `syft` and `cdxgen` (generated on a tiny
   sample project, committed with the command that produced them); verified by tests reading each; makes true SBR-4,
   SBR-H1; sets the spec `accepted`.

## Decisions
- Mode: autonomous
- Base commit: fa69e7ca3d3e390a7290eb30bd7c100b25a3bfa2
- Spec versions 1.0 to 1.2 are refused as unsupported, not parsed by a second parser.
- Nested components are flattened in document order, parent before children.
- Supplier: `supplier.name`, with `author` and `publisher` kept apart for the completeness check to weigh.
- Real-tool fixtures are generated on a small sample project, committed as compact JSON with the command that
  produced them.

## Deliverable 1 summary
done: domain `sbom` module (`Sbom`, `Component`, `Hash`, `SpecVersion` with the BSI 1.6 minimum); `read_json` in
`rollcall-cyclonedx` over `cyclonedx-bom` 0.9.0 with the `bomFormat` / `specVersion` pre-checks and nested components
flattened; MSRV 1.86; spec SBR and ADR 0002 drafts; `CLAUDE.md` status and input format.

| check | result |
|---|---|
| tests | 13 adapter tests + 1 domain test pass |
| lint | clippy pedantic clean |
| specs | `check-specs` clean (spec `draft`) |
| docs | `CLAUDE.md` updated |
| code review | see below |

red: SBR-1, SBR-2, SBR-3, SBR-5, SBR-6, SBR-7, SBR-8, SBR-H2: `read_json` stub returned `invalid SBOM: not implemented`
for every input.

Code review: 1 finding
- `serde_json` duplicated under `[dev-dependencies]`: removed.

not verified: real tool outputs (deliverable 2).
decisions needed: none.
