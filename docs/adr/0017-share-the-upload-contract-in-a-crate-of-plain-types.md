# 0017. Share the upload contract in a crate of plain types

- Status: proposed
- Date: 2026-11-19

## Context

`forewarn` is to upload the SBOM of a product version to a Forewarn service (milestone "Upload from CI"). The service
may depend on the crates of this repository, never the reverse, so the contract of the upload is written here, in a
crate both sides can use (ADR 0001). The service already answers an upload: a `PUT` whose body is the SBOM file as is,
the product and the version in the path under `/api/v1`, dated by its own clock, answered `201` or `200` with a receipt,
or with a status and an error code. The CLI and the service are released apart.

## Decision

- **A crate `forewarn-api`** of plain `serde` types and pure functions: the route of an upload, the checks of its
  product name and version, the receipt, the refusal and its codes, the account of a token (`specs/upload-api.md`). No
  HTTP client, no I/O: the upload adapter sends the request, the service serves it, both with these types.
- **The SBOM is the body, as is**: no envelope; it reaches the service byte for byte and the service reads it with the
  CycloneDX adapter. The product and the version are percent-encoded path segments, checked before anything is sent by
  the rules the service applies, plus a refusal of `.` and `..`, which a URL client would resolve.
- **No date and no tool in the request**: the service dates the upload when it has received it; a moment given by the
  CI would be one more field to trust.
- **The version in the path**, `/api/v1`: a breaking change of the contract takes a new path, which a service can serve
  next to the former one.
- **How the contract evolves within `v1`**: a field the reader does not name is ignored, and an error or a warning code
  it does not name is kept as unknown with its text, so adding a field or a code keeps `v1`. Removing or renaming a
  field, making one required or changing what a field or a code means takes `v2`.
- **The dates of the receipt stay text**, as the service writes them (RFC 3339 with a fraction of a second): the
  domain's `Moment` counts whole seconds (ADR 0011), and the CLI only shows them.

## Consequences

- The service can replace its own types of the answer with these when it moves to the release that holds them (its
  dependency is pinned to a tag of this repository).
- A test of this repository proves the contract without a network; the HTTP statuses it reads are plain numbers.
- An SBOM in XML, or a date given by the CI, would need a change of the contract.
