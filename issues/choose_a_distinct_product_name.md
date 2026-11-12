---
priority: medium
why: 'must be settled before the first publication, not before the proof of concept works'
---
# Choose a distinct product name

# Goal
Another open-source project already publishes CRA-oriented CycloneDX SBOM tooling under the name `rollcall`, with the
crates `rollcall`, `rollcall-cli` and `rollcall-core` on crates.io. Two CRA/SBOM tools with one name confuse users, and
`cargo publish` fails on the taken names. Choose a product name, and the crate names that follow from it, before the
first publication.

# Findings
* 2026-11-12, `cargo search rollcall`: `rollcall` 0.1.0, `rollcall-cli` 0.0.1, `rollcall-core` 0.1.0,
  `rollcall-identifiers`, `rollcall-assay` exist on crates.io, described as CRA-grade CycloneDX SBOMs from firmware
  build metadata (repository `github.com/smhasan94/rollcall`, Apache-2.0).
* The workspace sets `publish = false` and provisional package names until this is settled (`CLAUDE.md`, "Layout").

# Approach
1. List candidate names and check each on crates.io, GitHub and as a trademark in the EU.
2. Decide whether only the crates are renamed (prefix) or the product and the repository too.
3. Rename the packages, the binary, the docs and the repository references in one deliverable; drop `publish = false`
   when the names are free.

# Milestone
Proof-of-concept demo

# Resources
* `CLAUDE.md`: "Layout", "Public repository".
* `Cargo.toml` of the workspace (`publish`, the comment on the names).

# Hints
* The hosted service carries the same brand: the name decision is the user's, not the agent's.
