---
priority: medium
depends_on: [upload_an_sbom_to_the_service]
why: 'a revoked token reported as an unreachable service misleads a CI job, but only with a service that answers early'
---
# Tell refused credentials answered before the whole SBOM is sent

# Goal
A service or a reverse proxy may check the token first, answer `401`, `403` or `413`, and close the connection before
reading the whole body. `ureq` then fails while sending the SBOM (broken pipe, connection reset), and `upload` in
`crates/forewarn-upload/src/send.rs` maps that failure to `Unreachable`: a revoked token is reported as "cannot reach
the service", against UPL-3 and UPL-9 of `specs/sbom-upload.md`. The upload should report the answer the service gave.

# Findings
* Found by the `high` review of `issues/done/upload_an_sbom_to_the_service.md` (reading of the code, not reproduced).
* The loopback test server of `crates/forewarn-upload/tests/upload.rs` reads the whole body before answering, so no
  test covers an early answer.

# Approach
1. Reproduce first: a loopback server that answers `401` after the head and closes, with an SBOM of a few MiB.
2. Candidates, to choose from after the measure:
   1. `Expect: 100-continue`, if `ureq` 3 supports it: the service refuses before the body is sent.
   2. After a send error, read the answer the service may have written before closing.
   3. A `GET /api/v1/account` (UPA-12) before the `PUT`, which checks the token without the SBOM (one more request).

# Specs
* `specs/sbom-upload.md`: a scenario of UPL-9, maybe a requirement on an answer received before the whole body.

# Milestone
Upload from CI

# Resources
* `crates/forewarn-upload/src/send.rs`, ADR 0018.
* The `ureq` 3 configuration (`ConfigBuilder`), its handling of `Expect: 100-continue`.

# Hints
* The token must never reach an error, whatever path the fix takes (UPL-4).
