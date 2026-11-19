# 0018. Upload an SBOM from an adapter crate of its own

- Status: accepted
- Date: 2026-11-19

## Context

ADR 0017 writes the contract of an SBOM upload in `forewarn-api`, plain types with no I/O, which the service depends
on. The CLI needs the other half: send the request and read the answer (`specs/sbom-upload.md`). The request carries
the inventory and a bearer token; a CI job must report an endpoint it cannot reach, refused credentials, a refused
upload and an unreadable answer differently.

## Decision

- **A crate `forewarn-upload`**, an adapter like `forewarn-osv` and `forewarn-exploited`, depending on `forewarn-api`
  and `ureq` 3 with `rustls`. Not a feature of `forewarn-api`: the service would see an HTTP client in the crate of
  its contract, and a feature unified by another member of a workspace would pull it in unasked.
- **HTTPS, or a loopback host in plain HTTP** (`localhost`, `127.0.0.0/8`, `[::1]`): a local service or a test, never
  the SBOM and the token in clear over a network. The endpoint is parsed with the URI type `ureq` re-exports, no new
  dependency.
- **The token is a value of its own** whose `Debug` writes nothing of it, checked to be visible ASCII before it goes
  in a header; the endpoint carries no user information, so an error naming the endpoint names no credentials. An
  error writes the token as `***` wherever the service echoed it.
- **No redirect followed**: a `PUT` redirected to another host would send the token and the SBOM there.
- **No proxy for a loopback endpoint in plain HTTP**: a proxy the environment names would carry the token and the SBOM
  in clear to another machine, and reach its own loopback. An HTTPS endpoint goes through it, TLS end to end.
- **An agent of its own**: no redirect, connect 30 s, the head sent with `Expect: 100-continue` and the body sent once
  the service answers `100 Continue` or after 1 s (an answer before it, such as credentials refused, is read instead
  of lost in a reset), sending the body 5 min, waiting for the answer 2 min, reading it
  1 min; the cache's agent (`forewarn_cache::agent`) follows redirects and waits 30 min for a body.
- **No retry**: the request is sent once; the code `unavailable` tells the caller a retry is safe. Only a `417
  Expectation Failed`, which an intermediary gives without passing the request on, is sent again without the
  expectation, as RFC 9110 asks.
- **The SBOM is refused over 10 MiB before it is sent**, the limit of the service (UPA-9), rather than uploaded to be
  refused; the limit is `forewarn_api::MAX_SBOM_BYTES`, shared with the service.

## Consequences

- The service keeps a contract crate with no HTTP client.
- A test proves the adapter against a loopback server in plain HTTP; the TLS path is `ureq`'s and is not tested here.
- A service with a private certificate authority needs a later change.
- A change of the service's size limit needs a release of the CLI.
