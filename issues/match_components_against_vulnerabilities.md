---
priority: high
why: 'the exact matching is the core of the milestone; every other issue of it feeds or prints it'
---
# Match the components of an SBOM against known vulnerabilities

# Goal
The domain must tell, for each component of an SBOM, which known vulnerabilities affect it, by exact matching of its
package URL (ecosystem and name) and version against the affected packages and version ranges of each vulnerability.
The result lists each affected component with the vulnerability, its aliases (CVE) and its source, deterministically
and with no I/O.

# Findings
* `forewarn_domain::sbom::Component` already carries `purl` and `version` as written in the SBOM; nothing parses the
  package URL yet.
* The domain has no vulnerability type yet; `forewarn-domain/src/lib.rs` announces vulnerability matching in its doc.

# Approach
1. Domain types for a vulnerability as matching needs it, shaped after the OSV schema but owned by the domain: id,
   aliases, source, affected packages (ecosystem, name), their explicit `versions` and their ranges (`SEMVER`,
   `ECOSYSTEM`, with `introduced`, `fixed`, `last_affected` events).
2. Parse the package URL of a component into a type and a name (namespace included), mapped to an OSV ecosystem
   (`cargo` to `crates.io`, `npm`, `pypi` to `PyPI`…); a component without a purl or a version is not matched, and
   the result says so.
3. Version comparison: start with the semver ecosystems (crates.io, npm) and the explicit `versions` list, which is
   exact in every ecosystem; a range in an ecosystem whose ordering is not implemented is reported as not evaluated,
   never guessed. PEP 440, Maven and the others come in later issues.
4. A pure function from the components and the vulnerabilities to the matches, ordered deterministically.

# Specs
* `specs/vulnerability-matching.md` (to write at step 1): the purl mapping, the version rules, what is not evaluated.

# Milestone
Match known vulnerabilities (OSV)

# Resources
* `CLAUDE.md`: hexagonal architecture, deterministic matching.
* `crates/forewarn-domain/src/sbom.rs`: the component type.
* OSV schema (`affected`, `ranges`, `events`, `versions`) and the package URL specification (purl types).
* The SBOM fixtures of `crates/forewarn-cyclonedx/tests/fixtures/` (their purls show what real tools write).

# Hints
* The domain depends on no adapter: the OSV JSON is read by `read_osv_records`, not here.
* A purl may carry qualifiers and a subpath, and its name is percent-encoded; the version of the component may differ
  from the version in the purl, so settle which one wins at step 1.
* Semver pre-releases and build metadata change the ordering; OSV `SEMVER` ranges follow semver 2.0.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-12

## Understanding
A pure domain module: vulnerabilities shaped after OSV, package URL reading and its OSV ecosystem, and the exact
matching of components (explicit versions everywhere, semver ranges for crates.io and npm), with the components and
pairs not evaluated reported apart (`specs/vulnerability-matching.md`). Out of scope: reading OSV, the CLI.

## Plan
1. [x] Vulnerability types and package URL: `forewarn_domain::vulnerability` (vulnerability, affected package,
   range, events) and the package URL reading with its ecosystem and name, the component reasons; verified by tests in
   `crates/forewarn-domain/tests/`; makes true VMT-4, VMT-5, VMT-6, VMT-7. (~500 lines) (autonomous)
2. [x] Matching: `forewarn_domain::matching` (explicit versions, semver ranges by the OSV algorithm, pair reasons,
   withdrawn, order, one match per pair); verified by tests in `crates/forewarn-domain/tests/` and a happy path on the
   `cargo-cyclonedx` fixture; makes true VMT-1 to VMT-3, VMT-8 to VMT-14, VMT-H1, VMT-H2. (~700
   lines) (autonomous)

## Decisions
- Mode: autonomous
- Base commit: d8501e0e91a1d137c9d12ad7471743be85d5c943
- Package URL: read by a small parser of the domain, no dependency.
- Semver ranges: compared with the `semver` crate (MIT OR Apache-2.0), the first dependency of the domain.
- Version matched: the component's, else its package URL's (VMT-7).
- Happy path VMT-H1 traced on built components (`time` 0.1.43, as the spec says); the `cargo-cyclonedx` fixture is
  matched by a test of the adapter crate (VMT-1, VMT-5).

## Deliverable 1 summary
done: `forewarn_domain::vulnerability` (OSV-shaped types), `forewarn_domain::matching::{ComponentPackage, ComponentReason, same_name}`, a private package URL parser; spec VMT draft.

| check | result |
|---|---|
| tests | pass |
| lint | pass |
| specs | pass (VMT draft) |
| docs | n/a: the domain crate keeps its role; CLAUDE.md is updated when matching works (deliverable 2) |

red: VMT-4, VMT-5, VMT-6, VMT-7: `unresolved import forewarn_domain::matching`

Code review: no findings

not verified: none
decisions needed: none

## Deliverable 2 summary
done: `forewarn_domain::matching::match_components` and its `MatchReport` (matches, components and pairs not evaluated), `semver` added to the domain, spec VMT accepted, CLAUDE.md status.

| check | result |
|---|---|
| tests | pass |
| lint | pass |
| specs | pass (VMT accepted) |
| docs | CLAUDE.md project status |

red: VMT-1, VMT-2, VMT-3, VMT-8, VMT-9, VMT-10, VMT-11, VMT-12, VMT-13, VMT-14, VMT-H1, VMT-H2: `unresolved imports forewarn_domain::matching::match_components`

Code review: no findings

not verified: none
decisions needed: none
