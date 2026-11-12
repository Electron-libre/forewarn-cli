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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-12

## Understanding
Pick a product name free of the CRA/SBOM `rollcall` project, then rename the packages, the binary, the docs and the
repository references to it. The choice of the name is the user's; the rename of the GitHub repository and of the
hosted service are the user's actions, outside this repository's diff.

Candidates checked on 2026-11-12 (crates.io API, `gh search repos`; EU trademark not checked, to verify on TMview):

| Name | crates.io | GitHub (top hits) |
|---|---|---|
| `forewarn` | free | unrelated (CMU robotics, a testdouble lib) |
| `tocsin` | taken (the bare name); `cra-tocsin`, `sbom-tocsin` free | — |
| `musterroll` | free | `cloudfleet/musterroll` (LDAP, dormant) |
| `cravat` | free | `KarchinLab/open-cravat` (genomics) |
| `picket` | free | `picketlink` (Java auth) |
| `herald`, `beacon`, `vigil`, `muster`, `roster`, `vedette`, `bellwether` | taken | — |

## Plan
1. [x] Move the crate directories to the new names (`git mv`, plus the member paths of the workspace `Cargo.toml`
   only); verified by `cardinal run project-check`; ~10 lines. (autonomous)
2. [x] Rename the packages, the binary, the crate imports, the docs, the specs, the ADRs, `CLAUDE.md`, `README.md`,
   `ROADMAP.md` and the `repository` URL; drop `publish = false` and its comment once the names are free on
   crates.io; verified by `cardinal run project-check` and the `check.rs` tests run through the new binary name;
   ~150 lines. The `.cdx.json` fixtures keep the name the tools recorded when generated. (autonomous)

## Deliverable 1
done: the crate directories moved to `crates/forewarn`, `crates/forewarn-cyclonedx`, `crates/forewarn-domain`; the
workspace members, the path dependencies, one fixture path of `check.rs` and the paths cited by `CLAUDE.md`,
`README.md` and ADR 0001 follow; the package names are unchanged.

| check | result |
|---|---|
| tests, fmt, clippy, specs | `cardinal run project-check` green |
| size | 858 changed lines (a move counts twice), within |

red: none (a move, no new behaviour; the existing tests prove it).

Code review: no findings

not verified: nothing.

decisions needed: none.

## Deliverable 2
done: the packages `forewarn`, `forewarn-cyclonedx`, `forewarn-domain`, the binary `forewarn`, the crate imports, the
doc comments, `README.md`, `CLAUDE.md`, `ROADMAP.md`, the specs, the ADRs, `LICENSE-MIT`, `.claude/cardinal.toml` and
the `repository` URL (`forewarn-cli`) use the new name; `publish = false` and its comment are gone; `CLAUDE.md` says
why the product was renamed; the fixture sample keeps `rollcall-fixture-sample`, which the generated SBOMs record.

| check | result |
|---|---|
| tests, fmt, clippy, specs | `cardinal run project-check` green |
| binary | `cargo run -p forewarn -- check <syft fixture>` prints the report |
| docs | `skill:update-docs`: README, CLAUDE.md, ROADMAP, specs, ADRs updated; no stale `rollcall` left but the history note and the fixture sample |
| size | 160 changed lines; the issue total reads 3,488 because `deliverable-size <base>` counts each moved and edited file twice |

red: none traced (a rename, no new behaviour); `check.rs` failed to build on `CARGO_BIN_EXE_forewarn` until the package was renamed.

Code review: 1 findings
- `publish = false` dropped and path dependencies without `version`: not fixed. The names were checked free on
  crates.io (`## Decisions`) and the issue asks to drop the guard; a `cargo publish` of `forewarn` still fails on the
  versionless path dependencies, so nothing can be published by accident. Making the crates publishable (versions
  on the path dependencies, metadata) belongs to the first publication: follow-up.

not verified: the EU trademark of `forewarn` (TMview).

decisions needed: none.

## Decisions
- Mode: autonomous
- Repository rename: the agent runs `gh repo rename` after the user agrees, once deliverable 2 is committed (answer 3b).
- Name: `forewarn`; crates `forewarn` (binary), `forewarn-domain`, `forewarn-cyclonedx`, all free on crates.io on 2026-11-12 (answer 1a).
- Scope: the product, the crates, the binary and the repository are renamed (answer 2a).
- Base commit: 759ab36b8926c59f18d39bdbfbc696aea0673b22
