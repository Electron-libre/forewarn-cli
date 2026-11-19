---
id: CUP
status: accepted
adrs: [0017, 0018]
---

# The `forewarn upload` command

## Intent

Let a CI job upload, in one command at each release, the CycloneDX SBOM of a product version to a Forewarn service, so
that the vendor's inventory there stays up to date without manual work, with an exit code that tells why an upload did
not go through.

## Requirements

### Behaviour

- **CUP-1** (deterministic) `forewarn upload <sbom>` must send the SBOM file as is, with the upload adapter
  (`specs/sbom-upload.md`), to the service at the endpoint given, for the product name and version the SBOM's
  `metadata.component` gives, and print what the service stored.
- **CUP-2** (deterministic) `forewarn upload` must read the SBOM with the CycloneDX adapter (`specs/sbom-reading.md`)
  before sending it, and send nothing when the adapter refuses it.
- **CUP-3** (deterministic) `forewarn upload --product <name> --product-version <version> <sbom>` must upload under
  that name and that version instead of those of the SBOM, each option alone overriding its own value.
- **CUP-4** (deterministic) `forewarn upload -` must read the SBOM from standard input and send the bytes it read.
- **CUP-5** (deterministic) `forewarn upload --dry-run <sbom>` must print the endpoint, the product name, the version
  and the size of the SBOM in bytes, and send nothing.
- **CUP-6** (deterministic) A failed upload must exit with a code of its own for an endpoint it cannot reach,
  credentials the service refuses, an upload refused and an answer it cannot read, so that a CI job can tell them
  apart.

### Contract

- **CUP-7** (deterministic) The endpoint must be the value of `--endpoint`, else of the environment variable
  `FOREWARN_ENDPOINT` when it is set and not empty, the option winning over the variable.
- **CUP-8** (deterministic) The bearer token must be the value of the environment variable `FOREWARN_TOKEN`, never of
  an option, so that it appears in no process list nor shell history, and is not read with `--dry-run`.
- **CUP-9** (deterministic) The command must exit with the code of this table, the first row that applies.

  | Situation | Exit code |
  |---|---|
  | the arguments are invalid (unknown option, no SBOM given, no endpoint, an endpoint UPL-6 refuses, no `FOREWARN_TOKEN` or a token UPL-7 refuses without `--dry-run`) | 2 |
  | the SBOM is over 10,485,760 bytes (UPL-8) | 10 |
  | the SBOM cannot be read (any error of SBR-7) | 3 |
  | the SBOM gives no product name, or a blank one, and `--product` is not given, or no product version, or a blank one, and `--product-version` is not given | 2 |
  | the product name or the version is one the contract refuses (UPA-6) | 10 |
  | the endpoint cannot be reached (UPL-9) | 8 |
  | the service refused the credentials (UPL-9) | 9 |
  | the service refused the upload (UPL-9) | 10 |
  | the answer of the service cannot be read (UPL-9) | 11 |
  | the report cannot be written to standard output, a closed pipe aside (CHK-13) | 4 |
  | the SBOM was stored, or `--dry-run` | 0 |

- **CUP-10** (deterministic) The arguments, the endpoint and the token must be checked before the SBOM is read, its size
  before it is read as CycloneDX, holding no more than 10,485,761 of its bytes in memory, and the SBOM, its product
  and version and their names before anything is sent.
- **CUP-11** (deterministic) An error must print nothing on standard output and one line on standard error: the line of
  SBR-7 naming the path for an SBOM that cannot be read (CHK-8), the error of the upload adapter (UPL-3, UPL-8, UPL-11)
  for an upload not stored, and the option to give for a product name or version missing (`--product`,
  `--product-version`).
- **CUP-12** (deterministic) The report of a stored SBOM must give the endpoint, the product name, the version, whether
  the service created the version or replaced its SBOM, the number of components stored, the moment the service
  received it as the service writes it, and each warning of the receipt with its code and message.
- **CUP-13** (deterministic) The report and the error lines must print the values of the SBOM and of the service escaped
  as CHK-14 escapes a value, so that neither can forge report lines or terminal sequences.
- **CUP-14** (deterministic) No output of the command, on standard output or standard error, must hold the token.
- **CUP-15** (deterministic) The path of the SBOM must follow the rules of the other commands: `-` for standard input,
  `./-` for a file named `-`, a path not valid UTF-8 read like any other, and a path an error names escaped as CHK-16
  says.

## Scenarios

- **CUP-H1** (happy; CUP-1, CUP-2, CUP-7, CUP-8, CUP-12, CUP-9) Given a CI job with `FOREWARN_ENDPOINT` naming a
  service and `FOREWARN_TOKEN` set, and an SBOM whose `metadata.component` is `acme-gateway` `2.4.0`, when it runs
  `forewarn upload sbom.json` and the service answers `201` with a receipt of 3 components, then the service receives
  the SBOM bytes as is on the route of `acme-gateway` `2.4.0`, the report says a new version of 3 components was
  stored with the moment it was received, and the command exits with 0.
- **CUP-H2** (happy; CUP-6, CUP-9, CUP-11, CUP-14) Given the service answers `401` with `{"error": "unauthorized"}`,
  when the job uploads, then standard error names the endpoint and the refused credentials, holds no token, and the
  command exits with 9.
- **CUP-H3** (happy; CUP-5, CUP-8) Given no `FOREWARN_TOKEN`, when a vendor runs
  `forewarn upload --dry-run --endpoint <url> sbom.json`, then they see the endpoint, `acme-gateway`, `2.4.0` and the
  size of the SBOM, nothing is sent, and the command exits with 0.
- (CUP-1, CUP-12) Given the service answers `200` with a receipt carrying the warning `spec_version_below_minimum`,
  the report says the SBOM of a known version was replaced and prints that warning; the command exits with 0.
- (CUP-3) Given an SBOM of `acme-gateway` `2.4.0` and `--product-version 2.4.1`, the route names `acme-gateway` and
  `2.4.1`.
- (CUP-4) Given an SBOM piped into `forewarn upload -`, the service receives the bytes piped.
- (CUP-7) Given `FOREWARN_ENDPOINT` naming an unreachable port and `--endpoint` naming the service, the service
  receives the upload; given `FOREWARN_ENDPOINT` empty and no `--endpoint`, the command exits with 2.
- (CUP-7, CUP-9) Given the endpoint `http://example.com`, the command exits with 2 naming it and sends nothing.
- (CUP-8, CUP-9) Given no `FOREWARN_TOKEN`, or one holding a space, without `--dry-run`, the command exits with 2 and
  reads no SBOM.
- (CUP-2, CUP-9, CUP-10) Given a CycloneDX 1.2 SBOM, the command exits with 3 and the service receives nothing.
- (CUP-9, CUP-11) Given an SBOM with no `metadata.component` version and no `--product-version`, the command exits with
  2 and standard error names `--product-version`; with a version `""`, the same; with no `metadata.component`, it
  names `--product`.
- (CUP-9, CUP-10) Given `--product ..`, the command exits with 10 naming the product name and sends nothing.
- (CUP-9, CUP-10) Given an SBOM over 10,485,760 bytes, the command exits with 10 naming its size and sends nothing;
  given a file of that size that is not JSON, the same.
- (CUP-6, CUP-9) Given an endpoint on a loopback port where nothing listens, the command exits with 8; given the
  service answers `422` `unreadable_sbom`, it exits with 10 and standard error names the code and the message; given
  `502` with an HTML page, it exits with 11.
- (CUP-13) Given a receipt whose warning message holds an escape sequence, the report prints it escaped.
- (CUP-14) Given the service answers `400` with a message holding the token, standard error holds `***` in its place.
- (CUP-15) Given, on Windows, a path `C:\sboms\shop.json` that does not exist, standard error names it as written.

## Non-goals

- A date sent with the upload: the service dates it with its own clock (UPA non-goals); the report prints the moment
  of the receipt.
- A token given on the command line or read from a file.
- A JSON report.
- Checking the completeness of the SBOM before the upload: `forewarn check` does it; the service warns of a spec
  version below the minimum.
- A retry: a CI job reruns the command; a `503` names its code, which says a retry is safe.
- Uploading several SBOMs in one run, or the account of a token.
