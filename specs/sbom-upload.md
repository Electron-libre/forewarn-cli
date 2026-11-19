---
id: UPL
status: accepted
adrs: [0017, 0018]
---

# The upload of an SBOM to a Forewarn service

## Intent

The upload adapter sends the CycloneDX SBOM of a product version to a Forewarn service at the endpoint the caller
gives, with a bearer token, and reads its answer with the contract of `forewarn-api`, so that a CI job can tell an
endpoint it cannot reach, credentials refused, an upload refused and an answer it cannot read apart, and report each
differently.

## Requirements

### Behaviour

- **UPL-1** (deterministic) An upload must send the SBOM file as is, once, to the route of its product version under
  the endpoint, and return the receipt the service answered, telling a new version from a replaced SBOM.
- **UPL-2** (deterministic) An upload must refuse, before anything is sent, an endpoint that is not HTTPS, unless it
  names a loopback host, so that the SBOM and the token never travel in clear over a network.
- **UPL-3** (deterministic) A failed upload must tell apart an endpoint it cannot reach, credentials the service
  refuses, an upload the service refuses and an answer it cannot read, each error naming the endpoint.
- **UPL-4** (deterministic) No error of an upload, its text or its debug form, must hold the token.

### Contract

- **UPL-5** (deterministic) The request must be a `PUT` to the endpoint followed by the route of `sbom_upload_path`
  (UPA-5), one `/` between them, with the headers `Authorization: Bearer <token>` and `Content-Type:
  application/vnd.cyclonedx+json`, and the SBOM bytes as body.
- **UPL-6** (deterministic) The endpoint must be an absolute URL whose scheme is `https`, or `http` with the host
  `localhost`, an IPv4 address of `127.0.0.0/8` or `[::1]`, an IPv6 host being an address, a port of `0` to `65535`
  or none, a path or none (the root of the service), and no `@` (user information), no query and no fragment.
- **UPL-7** (deterministic) An upload must refuse, before anything is sent, a token that is empty or holds a character
  outside the visible ASCII characters (`!` to `~`), the error naming no character of it.
- **UPL-8** (deterministic) An upload must refuse, before anything is sent, a product name or a version the contract
  refuses (UPA-6), with the error of `forewarn-api`, and an SBOM over 10,485,760 bytes, the error naming its size.
- **UPL-9** (deterministic) The answers must be read with `read_upload_answer` (UPA-3) and mapped to the errors of the
  table below; an answer `201` or `200` is the receipt of UPL-1.

| Case | Error | Holds |
|---|---|---|
| no connection, a TLS failure, a timeout, a body not received whole | unreachable | the endpoint, the reason |
| a refusal of status `401` or `403` | credentials refused | the endpoint, the refusal (status, code, message) |
| any other refusal | upload refused | the endpoint, the refusal (status, code, message) |
| a body `read_upload_answer` cannot read (UPA-10), or over 1 MiB | unreadable answer | the endpoint, the status, the reason |

- **UPL-10** (deterministic) An upload must not follow a redirect: a `3xx` answer is read as any other status (UPL-9).
- **UPL-11** (deterministic) An error must name the endpoint as the caller gave it, without a trailing `/`, a refused
  endpoint holding a `@` with all before its last `@` past its `scheme://` written `***`, and a refused endpoint quoted
  with its control characters escaped.
- **UPL-12** (deterministic) An error must write each occurrence of the token in a message of the service as `***`.

- **UPL-13** (deterministic) An upload to a loopback endpoint in plain HTTP must reach it directly, never through a
  proxy the environment names (`ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`).

## Scenarios

- **UPL-H1** (happy; UPL-1, UPL-5, UPL-9) Given a service at `http://127.0.0.1:<port>/forewarn` that answers `201`
  with a receipt of 3 components, when the adapter uploads an SBOM of `@acme/gateway` `2.4.0` with the token
  `fw_secret`, then the service receives one `PUT /forewarn/api/v1/products/%40acme%2Fgateway/versions/2.4.0/sbom`
  with `Authorization: Bearer fw_secret`, the CycloneDX content type and the SBOM bytes, and the adapter returns a new
  version of 3 components.
- **UPL-H2** (happy; UPL-3, UPL-9, UPL-4) Given the service answers `401` with `{"error": "unauthorized"}`, when the
  adapter uploads, then it fails with credentials refused naming the endpoint, and neither the error's text nor its
  debug form holds the token.
- (UPL-1) Given the service answers `200` with a receipt, the adapter returns a replaced SBOM.
- (UPL-2, UPL-6) Given the endpoint `http://example.com`, the upload is refused and nothing is sent; given
  `https://example.com/root/`, `http://localhost:8080`, `http://127.0.0.2` or `http://[::1]:9000` it is accepted;
  given `ftp://example.com`, `example.com`, `https://example.com/?a=1` or `https://example.com/#x` it is refused.
- (UPL-6, UPL-11) Given `https://ci:fw_secret@example.com`, the upload is refused and the error names
  `https://***@example.com`.
- (UPL-7) Given the token `""`, or `"fw secret"`, or one holding a line feed, the upload is refused and nothing is sent.
- (UPL-8) Given an SBOM of 10,485,760 bytes it is sent; of 10,485,761 bytes, it is refused naming that size and nothing
  is sent. Given the product `..`, the upload is refused naming the product name.
- (UPL-9) Given an endpoint on a loopback port where nothing listens, the upload fails as unreachable naming the
  endpoint.
- (UPL-9) Given the service answers `403` with `{"error": "forbidden"}`, the upload fails with credentials refused.
- (UPL-9) Given the service answers `422` with `{"error": "unreadable_sbom", "message": "not CycloneDX"}`, the upload
  fails with upload refused carrying that code and message; given `503` with `unavailable`, the same, with that code.
- (UPL-9) Given the service answers `502` with an HTML page, the upload fails with unreadable answer naming `502`.
- (UPL-10) Given the service answers `307` with a `Location` to another path, that path receives no request and the
  upload fails with unreadable answer naming `307`.
- (UPL-11) Given the endpoint `http://127.0.0.1:<port>/`, an error names `http://127.0.0.1:<port>`.
- (UPL-6, UPL-11) Given `ci:fw_secret@example.com` or `https://ci:fw/secret@example.com`, the upload is refused naming
  `***@example.com` or `https://***@example.com`; given `http://localhost:abc`, `http://127.0.0.1:99999` or
  `http://[::1]evil.com`, it is refused as not an absolute URL; given `ftp://x` followed by a line feed, the error
  holds no line feed.
- (UPL-13) Given `HTTP_PROXY` naming a proxy and the endpoint `http://127.0.0.1:<port>`, the service receives the
  request and the proxy none.
- (UPL-12) Given the service answers `400` with a message holding the token, the error holds `***` in its place.

## Non-goals

- A retry: a request is sent once; a `503` is reported with its code, which says a retry is safe.
- Reading the token or the endpoint from the environment or the command line: the caller's (`forewarn upload`).
- Checking the SBOM: the caller reads it with the CycloneDX adapter before the upload.
- The account of a token (`/api/v1/account`): no command asks for it yet.
- A proxy of its own setting, a client certificate or a custom root certificate: an HTTPS endpoint goes through the
  proxy the environment names, as the other sources do, with the roots `ureq` ships.
- The timeouts of the request: a test cannot prove them without waiting; ADR 0018 states them.
