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
