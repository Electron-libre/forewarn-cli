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
