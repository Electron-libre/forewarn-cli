---
priority: high
why: 'the upload adapter and the command both speak this contract: the milestone cannot start without it'
---
# Define the API types of an SBOM upload

# Goal
`forewarn` is to upload an SBOM with its product, version and date to a Forewarn service (milestone "Upload from CI").
No contract for that upload exists in this repository yet. The service may depend on crates of this repository, never
the reverse (`CLAUDE.md`, "Public repository"), so the contract belongs here: a crate of plain types for the request
and the answer, which the CLI's adapter and the service can both use, versioned so that either side can tell a
contract it does not know.

# Approach
1. A new crate `forewarn-api` (ADR 0001 layout, inherited license and lints, checked by
   `crates/forewarn/tests/workspace_policy.rs`): `serde` types only, no HTTP, no I/O.
2. The request: the SBOM document as given (its bytes, unchanged), the product name and version, the moment of the
   upload (UTC seconds, as the domain's `Instant`, ADR 0011), maybe the version of `forewarn` that sent it.
3. The answer: accepted (with an id the service gives the upload) or refused (a reason a user can read); an unknown
   field ignored, an unknown outcome told apart.
4. A version of the contract, in the path or in a field; an ADR records the choice and how the contract evolves.
5. Candidate shapes for the transport, decided at step 1 of `issue-workflow`: a JSON envelope carrying the SBOM, or the
   SBOM as the body with the product, version and date as headers or query parameters.

# Specs
* `specs/upload-api.md` (new): the request, the answer, their JSON form, the contract version.

# Milestone
Upload from CI

# Resources
* `CLAUDE.md`: "Public repository", "Design constraints" (configurable endpoint, only inventories leave the CI).
* `docs/adr/0001-workspace-crate-layout.md`, `docs/architecture.md`: where a new crate fits.
* `crates/forewarn-domain/src/sbom.rs`: `Product` (name, optional version).
* `docs/adr/0011-compute-the-reporting-deadlines-on-utc-seconds-of-the-domain.md`: the domain's moments.

# Hints
* This repository is public: the contract is written from this side only; nothing of the private service (code,
  internal URLs, documents) may be named here.
* The domain depends on no other crate of the workspace (`workspace_policy.rs`): `forewarn-api` may depend on the
  domain, not the reverse.
