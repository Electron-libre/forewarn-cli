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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
Reproduced: a server answering `401` after the head and closing gives `Unreachable` ("Connection reset by peer").
Means: candidate 1, measured: with `Expect: 100-continue`, `ureq` 3.5.2 reads an answer other than `100` instead of
sending the body (no `100` within `timeout_await_100`, 1 s: the body is sent). Candidate 2 is impossible with the API
of `ureq` (a send error drops the connection); candidate 3 costs a request on a route the spec keeps a non-goal. Out
of scope: a refusal after a `100 Continue` (a proxy that buffers the body), a non-goal of the spec.

## Plan
1. [x] Early answer: the `PUT` sends `Expect: 100-continue`, the await of `100` set to 1 s in `send.rs`; the test
   server answers `100 Continue` when asked, as real servers do; verified by tests of an early `401` and `413` on an
   SBOM of 8 MiB and of a server that never answers `100`; ADR 0018 states the wait; makes true UPL-14, UPL-5. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 00a906aa524997be62051b4058b06d1c4de5153b

## Deliverable 1
- done: the `PUT` sends `Expect: 100-continue` and waits 1 s for `100 Continue`; an early `401`/`413` is read and
  mapped (UPL-14); spec `accepted`, ADR 0018, user guide and CLAUDE.md state it.
- red: UPL-14, UPL-9: `Unreachable { reason: "io: Connection reset by peer (os error 104)" }` for an early `401` and
  `413`; the SBOM test lacked the header `expect`.
- Code review: no findings
- not verified: a real reverse proxy (nginx, a cloud load balancer); the CLI tests whose server never answers
  `100 Continue` each wait 1 s (17 tests, 2.1 s in parallel).
