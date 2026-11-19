---
priority: high
depends_on: [define_the_sbom_upload_api_types]
why: 'the HTTP side of the upload: the command has nothing to call without it'
---
# Upload an SBOM to a Forewarn service

# Goal
With the contract of `forewarn-api`, an adapter sends an SBOM upload to the service at a given endpoint and reads its
answer, telling apart the errors a CI job must report differently: the endpoint unreachable, the credentials refused,
the upload refused by the service, an answer it cannot read.

# Approach
1. An adapter crate (or a module of `forewarn-api` behind a feature, decided at step 1) using `ureq` 3 with `rustls`,
   as the other adapters do.
2. HTTPS required; plain HTTP accepted only for a loopback address (tests, a local service).
3. The credentials: a bearer token read by the caller (an environment variable such as `FOREWARN_TOKEN`), never written
   in an error or a log.
4. Errors naming the endpoint (without its credentials), the HTTP status and the reason the service gave.
5. No retry at first; a candidate if a CI run proves it needed.
6. Tests against a loopback HTTP server, as `crates/forewarn-osv/tests/fetching.rs` does: no network.

# Specs
* `specs/sbom-upload.md` (new): the request sent, the endpoint rules, the credentials, the answers and errors.

# Milestone
Upload from CI

# Resources
* `crates/forewarn-osv/src/api.rs` and ADR 0006: an outbound HTTP source, its `ureq` agent and its errors.
* `crates/forewarn-cache/src/`: the shared `GET` and its error types.
* `CLAUDE.md`: "Hexagonal architecture" (HTTP upload is an adapter), "Configurable endpoint".

# Hints
* A token must never reach a report, an error line or a test snapshot.
* `cargo deny check` runs in CI: a new dependency must carry a license of `deny.toml` and `about.toml`.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
A new adapter crate `forewarn-upload` sends an SBOM with a bearer token to `<endpoint>/api/v1/products/…/sbom` and maps
the answer read by `forewarn-api` to a receipt or one of four errors (unreachable, credentials refused, upload refused,
unreadable answer). Out of scope: the `upload` command, the environment variables, the account route, retries.

## Plan
1. [x] Crate `forewarn-upload`, its endpoint and token checks: `Endpoint::parse` (HTTPS or loopback HTTP, no user
   information, query or fragment, named without credentials), `Token` (visible ASCII, `Debug` redacted); verified by
   `crates/forewarn-upload/tests/endpoint.rs`; makes true UPL-2, UPL-6, UPL-7, UPL-11. (autonomous)
2. [x] The upload itself: its own `ureq` agent (no redirect), the `PUT`, the answer mapped to a receipt or an error,
   the token redacted from the service's messages; verified by `crates/forewarn-upload/tests/upload.rs` against a
   loopback server; makes true UPL-1, UPL-3, UPL-4, UPL-5, UPL-8, UPL-9, UPL-10, UPL-12; docs (architecture, CLAUDE.md), ADR
   0018 accepted, spec accepted. (autonomous)
3. [x] The fixes of the `high` review: no proxy to a loopback endpoint in plain HTTP (UPL-13), every `@` refused and
   redacted, the host and port read from the URI `ureq` connects to, a refused endpoint quoted with its control
   characters escaped, `MAX_SBOM_BYTES` moved to `forewarn-api`; verified by `tests/proxy.rs` and new tests of
   `tests/endpoint.rs`; makes true UPL-6, UPL-11, UPL-13. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 6d1f79a3ed554018504e25420485eaed3229fef7
- An adapter crate of its own, not a feature of `forewarn-api` (ADR 0018); commit scope `api`.
- Content type `application/vnd.cyclonedx+json`; `401` and `403` are credentials refused; `localhost` accepted in
  plain HTTP (answers 1 a, 2 a, 3 a).

## Deliverable 1 summary
- done: crate `forewarn-upload` with `Endpoint::parse` (HTTPS or loopback HTTP, no user information, query or
  fragment, named without a trailing `/` and with user information as `***`) and `Token` (visible ASCII, debug form
  redacted); spec UPL and ADR 0018 drafts; architecture and CLAUDE.md.
- red: UPL-2, UPL-6, UPL-7, UPL-11, UPL-4: `https://example.com is accepted` (8 of 9 tests failed on the stubs).
- Code review: no findings
- not verified: the TLS path (no network in tests).

## Deliverable 2 summary
- done: `upload` in module `send`: its own agent (no redirect), one `PUT` with the bearer token and the CycloneDX
  content type, the answer mapped to `Stored` or `UploadError`, the token redacted from the service's code and message;
  spec UPL and ADR 0018 accepted; CLAUDE.md and architecture.
- red: UPL-H1, UPL-H2, UPL-1, UPL-3, UPL-4, UPL-5, UPL-8, UPL-9, UPL-10, UPL-11, UPL-12: `stored: TooLarge { size: 0 }`
  (13 of 13 tests failed on the stub).
- Code review: no findings
- not verified: the TLS path and the timeouts (no network, no wait in tests).
- note: a `401` or `403` whose body is not the contract's JSON (a proxy's HTML page) is an unreadable answer, as the
  table of UPL-9 says, not credentials refused.

## High review of the issue
8 findings:
1. Proxy of the environment used for a loopback HTTP endpoint (token sent through it): fixed, UPL-13, `tests/proxy.rs`.
2. Credentials printed for an endpoint whose user information holds `/`, `?`, `#` or has no `://`: fixed, any `@`
   refused and all before it written `***`.
3. Host and port read by hand, disagreeing with the URI `ureq` connects to: fixed, read from the parsed URI, a port
   that is not 0 to 65535 or an IPv6 host that is not an address refused.
4. `401` answered before the whole body is read reported as unreachable: not fixed, needs a measure; filed as
   `issues/tell_refused_credentials_answered_before_the_body.md`.
5. `MAX_SBOM_BYTES` not shared with the service: fixed, moved to `forewarn-api`, re-exported.
6. Control characters of a refused endpoint written raw: fixed, the endpoint quoted with escapes.
7. A `401`/`403` with a body that is not the contract's JSON is an unreadable answer: not fixed, the table of UPL-9
   says so (a decision for the user).
8. The "nothing listens" test reuses a freed port: not fixed, the same pattern as `crates/forewarn-osv/tests/api.rs`.

## Deliverable 3 summary
- done: the fixes of findings 1, 2, 3, 5, 6; spec UPL amended (UPL-6, UPL-11, UPL-13), ADR 0018, CLAUDE.md.
- red: UPL-13, UPL-6, UPL-11: `stored: Unreachable { ..., reason: "CONNECT proxy failed: proxy server responded 502/502" }`
  (the token went to the proxy); `http://localhost:abc is refused: Endpoint("http://localhost:abc")`.
- Code review: no findings
- not verified: a real proxy, the TLS path.
