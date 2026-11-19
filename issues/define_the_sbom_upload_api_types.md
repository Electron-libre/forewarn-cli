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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
A crate `forewarn-api` of `serde` types and pure functions, no I/O, holding the upload contract the service already
serves: `PUT /api/v1/products/{product}/versions/{version}/sbom`, the SBOM as body, the receipt (`201`/`200`), the
refusal (status, code, optional message), the account of a token (ADR 0017, `specs/upload-api.md`). Differs from the
issue: no envelope, no client date nor tool in the request (the service dates the upload), version in the path.
Out of scope: sending the request (next issue).

## Plan
1. [x] Route: crate `forewarn-api` (workspace member, inherited license and lints, scope `api`), the route of a product
   version, its segments percent-encoded, the names the service would refuse refused first; verified by
   `crates/forewarn-api/tests/route.rs`; makes true UPA-1, UPA-2, UPA-5, UPA-6. (autonomous)
2. [ ] Answers: the receipt, the refusal and its error codes, the warning codes, the account, read from a status and
   a body and written back as JSON; verified by `crates/forewarn-api/tests/answers.rs`; makes true UPA-3, UPA-4,
   UPA-7 to UPA-13, UPA-H1, UPA-H2; spec and ADR 0017 `accepted`.

## Decisions
- Mode: autonomous
- Base commit: dada2d9dc10e370860e14122b7b0f9e6677e38d9
- The contract follows the route the service already serves (checked against the service's own API documentation on
  2026-11-19), not the envelope the issue proposed.
- `received_at` and `first_uploaded_at` kept as text, as the service writes them (answer 1 a).
- `.` and `..` refused as a product name or a version on the client side (answer 2 a).
- The answer of `GET /api/v1/account` included (answer 3 a).
- Commit scope `api`, added to `commit_scopes` and to the crate table of `CLAUDE.md` (answer 4 a).

## Deliverable 1: route

- done: crate `forewarn-api`, `sbom_upload_path` (percent-encoded segments under `/api/v1`), `InvalidName` naming the
  product name or the version (blank, over 255 characters, control character, `.`/`..`); docs (`CLAUDE.md`,
  `docs/architecture.md`), scope `api`.
- red: UPA-1, UPA-2, UPA-5, UPA-6: `unresolved imports forewarn_api::InvalidName, Name, NameProblem, sbom_upload_path`
- Code review: no findings
