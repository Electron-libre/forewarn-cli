---
id: UPA
status: draft
adrs: [0001, 0017]
---

# The API contract of an SBOM upload

## Intent

`forewarn` uploads the CycloneDX SBOM of a product version to a Forewarn service. The contract of that upload (the
route of a product version, the names it accepts, the answers of the service and their JSON form) is shared by the CLI
and the service through the crate `forewarn-api`, so that both build and read the same requests and answers.

## Requirements

### Behaviour

- **UPA-1** (deterministic) The route of an upload must name the product and the version in the path, under the
  contract version `/api/v1`, relative to the root of the service the user gives: the body of the upload is the SBOM
  file as is.
- **UPA-2** (deterministic) Building the route must refuse a product name or a version the service would refuse, the
  error naming which of the two, so that the CLI refuses it before anything is sent.
- **UPA-3** (deterministic) Reading the answer of an upload must tell apart an SBOM stored for a new version, an SBOM
  that replaced the one of a known version, and a refused upload with its error code and, when the service gives one,
  its message.
- **UPA-4** (deterministic) Reading an answer must keep an error code or a warning code the contract does not name,
  told apart from the codes it names, not fail on it.

### Contract

- **UPA-5** (deterministic) The route must be `/api/v1/products/{product}/versions/{version}/sbom`, each segment
  percent-encoded as UTF-8, every byte but the unreserved characters of RFC 3986 (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`,
  `~`) written `%XX` in capitals.
- **UPA-6** (deterministic) Building the route must refuse a product name or a version that is empty, only white
  space, longer than 255 characters (Unicode scalar values), holding a control character, or `.` or `..` (a segment a
  URL client would resolve).
- **UPA-7** (deterministic) The answer `201` and the answer `200` must be read into a receipt holding the fields of
  the table below, `201` telling a new version, `200` a replaced SBOM.

| Field | JSON type | Content |
|---|---|---|
| `product` | string | the product name, decoded |
| `version` | string | the version, decoded |
| `spec_version` | string | the CycloneDX version read, such as `1.6` |
| `components` | number | the number of components stored |
| `received_at` | string | when this SBOM was received, RFC 3339 in UTC, kept as written |
| `first_uploaded_at` | string | when the version was first uploaded, RFC 3339 in UTC, kept as written |
| `warnings` | array | each item `{"code", "message"}`, empty when nothing applies |

- **UPA-8** (deterministic) Any other status must be read as a refusal from the body `{"error": <code>, "message":
  <text>}`, `message` optional, with the status, the code and the message.
- **UPA-9** (deterministic) The codes the contract names must be those of the table below, each read into a variant
  of its own; the warning code it names is `spec_version_below_minimum`.

| Status | `error` | Cause |
|---|---|---|
| `400` | `invalid_name` | the product name or the version refused (UPA-6) |
| `400` | `unreadable_body` | the body could not be received |
| `401` | `unauthorized` | no valid token |
| `413` | `too_large` | the body is over 10 MiB (10,485,760 bytes) |
| `422` | `unreadable_sbom` | the body is not a CycloneDX JSON SBOM the service reads |
| `422` | `invalid_component` | a component the service refuses |
| `503` | `unavailable` | the service cannot store now; a retry is safe |

- **UPA-10** (deterministic) Reading an answer must fail, with an error naming the status, on a body that is not the
  JSON object its status calls for or lacks one of its fields the tables do not mark optional.
- **UPA-11** (deterministic) Reading an answer must ignore a field the contract does not name.
- **UPA-12** (deterministic) The answer `200` of the route `/api/v1/account` must be read into the name of the account
  of the token, from the body `{"account": <name>}`.
- **UPA-13** (deterministic) Each type of the contract must write the JSON it reads, so that the service can answer with
  them.

## Scenarios

- **UPA-H1** (happy; UPA-1, UPA-5, UPA-3, UPA-7) Given the product `@acme/gateway` and the version `2.4.0+build 7`,
  when the CLI builds the route, then it is `/api/v1/products/%40acme%2Fgateway/versions/2.4.0%2Bbuild%207/sbom`;
  given the service answers `201` with a receipt of 3 components and no warning, the CLI reads a new version of 3
  components.
- **UPA-H2** (happy; UPA-3, UPA-8, UPA-9) Given the service answers `422` with `{"error": "unreadable_sbom",
  "message": "not CycloneDX"}`, when the CLI reads it, then it gets a refusal `unreadable_sbom` with that message.
- (UPA-6) Given a product name of 255 characters, the route is built; of 256 characters, or `" "`, or holding a line
  feed, or `..`, it is refused naming the product name.
- (UPA-7) Given an answer `200` with the warning `spec_version_below_minimum`, the CLI reads a replaced SBOM carrying
  that warning.
- (UPA-8) Given an answer `401` with `{"error": "unauthorized"}`, the CLI reads a refusal `unauthorized` with no message.
- (UPA-4) Given an answer `429` with `{"error": "rate_limited", "message": "later"}`, the CLI reads a refusal whose code
  is unknown and names `rate_limited`.
- (UPA-10) Given an answer `502` whose body is an HTML page, reading it fails naming the status `502`.
- (UPA-11) Given a receipt holding a field `stored_until`, it is read as if the field were absent.

## Non-goals

- The transport: sending the request, the root of the service, the credentials and the headers belong to the upload
  adapter (`specs/sbom-upload.md`); this crate performs no I/O.
- A date or a sending tool in the request: the service dates the upload with its own clock.
- Parsing `received_at` and `first_uploaded_at` into moments: they are kept as the service writes them.
- Checking the SBOM before it is sent: the CLI reads it with the CycloneDX adapter; the contract adds no rule.
- A contract version other than `v1`: a new version is a new path.
