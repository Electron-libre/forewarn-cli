# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Early proof of concept. The CycloneDX adapter reads a JSON SBOM, its components (those nested in the product included, flagged first-party when of the
type and namespace of the product's package URL, as is a component naming the product's package) and the product it describes, into the
domain types (`specs/sbom-reading.md`); the domain lists the components missing a supplier, a license or a hash,
the file components (CycloneDX type `file`, the manifests a tool read) left out and listed apart
(`specs/sbom-completeness.md`); `forewarn check` prints both (`specs/cli-check.md`). The adapter also reads the VEX
verdicts of the SBOM's `vulnerabilities` and of a VEX document apart (`read_vex_json`), and the domain sets aside the
matches every verdict naming them (by `bom-ref`, else package URL, and id or alias) says do not affect the product,
keeping their evidence (`specs/vex-verdicts.md`, ADR
[0014](docs/adr/0014-apply-the-vex-verdicts-in-the-domain-after-the-flagging.md)). The domain also matches components against OSV-shaped vulnerabilities by package
URL and version, each ecosystem's versions in its own ordering (Semantic Versioning, PEP 440, Maven, RubyGems, NuGet, Composer)
(`specs/version-ordering.md`), grouping the records of one vulnerability that name each other, one CVE per match (`specs/vulnerability-matching.md`),
and flags a match as actively exploited when a list of exploited vulnerabilities names its CVE, with the list and the
date it gives as evidence (`specs/exploited-flagging.md`), and computes the CRA article 14(2) deadlines of such a
vulnerability, 24 h and 72 h from the moment of awareness and 14 days from the moment a corrective measure is
available, on a UTC moment of its own, and, at a given moment, the time left before each or how long it is overdue
(`specs/reporting-deadlines.md`, ADR
[0011](docs/adr/0011-compute-the-reporting-deadlines-on-utc-seconds-of-the-domain.md)), and drafts the early warning of
each CVE of the exploited matches: the product, its manufacturer, the components, the CVE, the evidence and the
deadlines filled, the other fields the ENISA SRP glossary 1.6 requires listed to complete (`specs/early-warning-draft.md`,
ADR [0012](docs/adr/0012-align-the-early-warning-draft-on-the-enisa-srp-glossary.md)), which the CLI crate writes as a
Markdown document, the fields numbered and named as the glossary does, those to complete marked `**TO COMPLETE**` (ADR [0013](docs/adr/0013-write-the-early-warning-draft-in-markdown-in-the-cli-crate.md)); the exploited-list adapter reads the CISA KEV catalog, from a file or
fetched into a cache under the refresh policy and the lock of the OSV archives (crate `forewarn-cache`), into such a
list, with the catalog's version and release date (`specs/kev-reading.md`, ADR
[0008](docs/adr/0008-exploited-lists-crate-and-a-shared-cache-crate.md)), and reads the exploited records of EUVD, from a
file or paged from the EUVD search into the same cache, into the list `EUVD`, an entry per CVE alias dated by `exploitedSince` and carrying the record's EUVD id, which the draft early warning names (`specs/euvd-reading.md`, ADR
[0009](docs/adr/0009-page-the-euvd-search-for-its-exploited-list.md)); the OSV adapter reads an OSV record file, or a directory of them (an extracted
ecosystem archive), into those vulnerabilities (`specs/osv-reading.md`, ADR
[0003](docs/adr/0003-osv-adapter-crate-with-own-serde-model.md)), and fetches the archive of each ecosystem
(`<ecosystem>/all.zip`) into a cache under a refresh policy, recording when it was downloaded (`specs/osv-fetching.md`, ADR
[0004](docs/adr/0004-fetch-osv-ecosystem-archives-into-a-cache.md)): only ecosystem names leave the CI. A file lock
per ecosystem makes concurrent runs sharing a cache wait for a run that downloads, while runs that only read share it (ADRs
[0005](docs/adr/0005-lock-each-ecosystem-of-the-osv-cache-with-a-file-lock.md),
[0007](docs/adr/0007-share-the-osv-cache-lock-between-readers.md)). It can also query the OSV API
(`/v1/querybatch`, then `/v1/vulns/<id>`), an opt-in source that sends the ecosystem, name and version of each
component out (ADR [0006](docs/adr/0006-query-the-osv-api-as-an-opt-in-source.md)).
`forewarn match` prints the affected components of an SBOM, apart from those not evaluated (the first-party ones
among them, never matched nor sent to the OSV API), matched against the cached
OSV archives of the ecosystems it uses, local records given with `--osv`, or, with `--osv-api`, the records the
OSV API names for its components (`specs/cli-match.md`), each match the CISA KEV catalog or EUVD names marked
actively exploited with its evidence (the catalog fetched into the same cache or read with `--kev`, the EUVD list paged
into it or read with `--euvd`), with its CRA reporting deadlines from `--aware-since` (by default the moment of the
run) and `--measure-available`, each with the time left before it or how long it is overdue at `--now` (by default the
moment of the run), and exits with 6 on such a match (`specs/cli-match-exploited.md`); with `--awareness <file>`, it
counts the deadlines of each such CVE from the moment the file records for the product and the CVE, records the
moment of awareness of the run (`--aware-since`, else the moment of the run) for those it does not, and rewrites the
file whole then (module `awareness_file`), exiting with 3 when the file cannot be read, 7 when it cannot be written
(`specs/cli-match-awareness.md`, ADR
[0019](docs/adr/0019-remember-the-moments-of-awareness-in-a-file-the-user-names.md)); with `--drafts <dir>`, it
writes the draft early warning of each such CVE into `<dir>/<product>-<CVE>.md` (module `drafts`), names the files in
the report, names apart the stale drafts of the product it no longer writes, left in place, and exits with 7 when one
cannot be written or the directory listed. It applies the VEX verdicts of the SBOM and of each
`--vex <file>`, listing the matches set aside with their verdict and evidence apart, out of the exit codes, the
deadlines and the drafts, and the verdicts that name no match (`specs/cli-match-vex.md`, module `vex`); a `--vex` file
that cannot be read exits with 3.
The crate `forewarn-api` holds the contract of an SBOM upload to a Forewarn service, shared with it: the route of a
product version, `/api/v1/products/{product}/versions/{version}/sbom`, its names percent-encoded and those the service
would refuse refused first, and the answers of the service read from a status and a body: the receipt of a version
created (`201`) or replaced (`200`) with its warnings, a refusal with its error code and message, an unknown code kept
with its text, the account of a token (`specs/upload-api.md`, ADR
[0017](docs/adr/0017-share-the-upload-contract-in-a-crate-of-plain-types.md)). The crate `forewarn-upload`, its
adapter, sends the SBOM as is in one `PUT` to that route under the endpoint of a service (HTTPS, or plain HTTP to a
loopback host, then reached without a proxy, no user information), with a bearer token never written in a debug form
or an error, no redirect followed and no retry, the SBOM sent after a `100 Continue` or 1 s so an answer before it is read (again without it after a `417`), an SBOM over 10 MiB (`MAX_SBOM_BYTES` of `forewarn-api`) refused first, and tells apart a receipt, the endpoint unreachable, the
credentials refused (`401`, `403`), the upload refused and an unreadable answer (`specs/sbom-upload.md`, ADR
[0018](docs/adr/0018-upload-an-sbom-from-an-adapter-crate-of-its-own.md)).
`forewarn upload <sbom>` reads the SBOM with the CycloneDX adapter, then sends its bytes as read for the product name
and version of its `metadata.component` (`--product`, `--product-version` override them) to the endpoint of
`--endpoint`, else `FOREWARN_ENDPOINT`, with the token of `FOREWARN_TOKEN` (never an option), prints what the service
stored, and exits with 8 (unreachable), 9 (credentials refused), 10 (upload refused) or 11 (unreadable answer) when it
is not stored (`specs/cli-upload.md`, module `upload`); `--dry-run` prints what it would send, reads no token and
sends nothing.
`just check` (i.e. `cardinal run project-check`) runs the `check_command` of `.claude/cardinal.toml`:
`cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`. The workflow
`.github/workflows/check.yml` runs that command on every push to `main` and every pull request, builds on the toolchain
of `rust-version` (read from `Cargo.toml`), runs the tests on macOS and Windows and runs `cargo deny check` against `deny.toml`
(licenses, RustSec advisories, yanked crates, sources), the latter also each day.
`cardinal run release <version>` writes the `CHANGELOG.md` section, then runs the `release_version_command` of
`.claude/cardinal.toml`, `just set-version <version>`, which writes `[workspace.package] version`, `Cargo.lock` and the
`FOREWARN_VERSION` the CI templates pin:
`forewarn --version` prints it, and `crates/forewarn/tests/workspace_policy.rs` checks it is the newest release of the
changelog, `crates/forewarn/tests/ci_templates.rs` that each template pins it.
Pushing the tag `v<version>` (X.Y.Z) runs `.github/workflows/release.yml` (ADR
[0015](docs/adr/0015-distribute-release-binaries-on-github-before-crates-io.md)): it refuses a tag that is not the
workspace version, builds `forewarn-<target>.tar.gz` for Linux (musl, x86_64 and aarch64) and macOS, each with the
third-party license notices `cargo-about` writes (`about.toml`, `about.hbs`) and the SBOM `cargo-cyclonedx` writes,
completed by `.github/sbom-complete.jq` (supplier, manufacturer, source hash of the workspace crates) and refused when
`forewarn check` finds it incomplete (ADR [0016](docs/adr/0016-complete-the-sbom-of-the-release-binaries-after-cargo-cyclonedx.md)), and
attaches them with the SBOMs and `SHA256SUMS`, their build provenance attested, to a GitHub release whose notes are the
changelog section; `crates/forewarn/tests/release_workflow.rs` checks the user guide and `about.toml` name the targets
it builds and runs that `jq` program (`jq` needed by `cargo test`); a pull request changing a manifest, `Cargo.lock`,
the notices or that program builds without publishing. crates.io waits
for its own decision.
`examples/ci/github-actions.yml` and `examples/ci/gitlab-ci.yml` are the CI templates vendors copy (install a pinned
release, `syft`, `check`, `match`, upload on a tag); `crates/forewarn/tests/ci_templates.rs` checks each option they
give `forewarn` exists and that they install an archive the release builds; `crates/forewarn/tests/ci_template_run.rs`
runs the `run:` blocks of the GitHub template with `bash` (Unix) against the binary of the commit, a fixture product
(`tests/fixtures/ci-template`) and local feeds: a daily run on the latest tag exits with 6 on an exploited match, the
next one counting its deadlines from the moment recorded in the cache kept (`--awareness`), a tag run passes on a match not exploited and uploads with `--dry-run`; a new step with a `run:` must be run or replaced there.
`crates/forewarn/tests/ci_gitlab_template_run.rs` runs the `script` of each GitLab job the same way, with `sh`, its
`before_script` replaced up to `cd "$CI_PROJECT_DIR"` and `syft` by a stub writing the fixture SBOM, and checks the
`needs`, `artifacts` and `rules` that carry the SBOM between its jobs on a schedule and a tag; a new job with a
`script` or a new `before_script` must be run or replaced there (the two share `tests/ci_template`).

## Layout

The architecture (crates, boundaries, the flow of a run, the ADRs) is described in `docs/architecture.md`, the commands
for their user in `docs/user-guide.md`; `README.md` stays a short pitch pointing to them.

Crates under `crates/` (ADR [0001](docs/adr/0001-workspace-crate-layout.md)), with their commit scope:

| Crate | Role | Scope |
|---|---|---|
| `forewarn-domain` | domain types and rules, no I/O, depends on no adapter | `domain` |
| `forewarn-cyclonedx` | CycloneDX adapter: SBOM into domain types | `sbom` |
| `forewarn-osv` | OSV adapter: vulnerability records, read, fetched into a cache or queried from the OSV API, into domain types | `feeds` |
| `forewarn-cache` | the cache of the downloads: refresh policy, freshness and the files of each download (ADR 0010), a file lock per entry (ADR 0008), one `GET` or the download of the source (ADR 0009) | `feeds` |
| `forewarn-exploited` | exploited-list adapter: the CISA KEV catalog (module `kev`), read or fetched into a cache, and the exploited records of EUVD (module `euvd`), read or paged into a cache, into the domain's exploited lists | `feeds` |
| `forewarn-api` | the contract of an SBOM upload shared with the service, no I/O: the route of a product version and the names it accepts, the answers of the service (module `answer`) (`specs/upload-api.md`, ADR 0017) | `api` |
| `forewarn-upload` | upload adapter: the endpoint of a service and the bearer token, checked (modules `endpoint`, `token`), the `PUT` of the SBOM and its answer mapped to a receipt or an error (module `send`) (`specs/sbom-upload.md`, ADR 0018) | `api` |
| `forewarn` | the CLI binary: arguments (module `args`), wiring, the moments of awareness, of the measure and of the check of a run (module `awareness`) and the file of `--awareness` remembering them per CVE (module `awareness_file`), the report formats (module `report`), the written early warning draft (module `early_warning`) and its files (module `drafts`), the VEX verdicts of a run and their part of the reports (module `vex`), the characters both writers escape (module `escape`), the error lines naming a file (module `error_line`), `forewarn upload` (module `upload`) | `cli` |

The product was first named `rollcall`; it became `forewarn` because another CRA/SBOM project publishes the `rollcall`
crates. `publish = false` stays until the first publication is decided (the path dependencies then need a `version`).
`crates/forewarn/tests/workspace_policy.rs` checks that every member inherits the license and the lints, and that the
domain depends on no other crate of the workspace.

## What this is

`forewarn`, an open-source Rust CLI that helps software vendors meet the EU Cyber Resilience Act (CRA) vulnerability
reporting obligation (article 14: early warning within 24 h, notification within 72 h, final report within 14 days).

First milestone (proof of concept), CLI only:
- Input: a CycloneDX SBOM, provided or generated by an existing tool (`cargo-cyclonedx`, `syft`, `cdxgen`…).
- Match its components against public lists of actively exploited vulnerabilities (KEV, EUVD, OSV).
- Output: the affected components, a draft CRA early warning for each, and an SBOM completeness check (missing
  supplier, license, hashes: fields the CRA expects but raw scans often leave empty).

The CLI can later upload SBOMs from CI to a hosted Forewarn service through its HTTP API.

## Public repository

This repository is public. A hosted Forewarn service lives in a separate private repository: nothing from it (code,
internal URLs, business documents) belongs here. The dependency goes one way only: the service may depend on crates of
this repository (matching logic, CycloneDX handling, API types shared with the service), never the reverse.

## Design constraints

- **Never build a scanner.** Consume CycloneDX produced by existing tools; do not add dependency detection.
- **Input format:** CycloneDX 1.6 minimum, 1.7 accepted (threshold of BSI TR-03183-2); older versions are accepted but
  flagged; 1.0 to 1.2 are refused. VEX for exploitability verdicts. Parsing goes through the `cyclonedx-bom` crate
  (ADR [0002](docs/adr/0002-parse-cyclonedx-with-cyclonedx-bom.md)); its types never leave the adapter.
- **Deterministic.** Exact SBOM ↔ vulnerability-list matching and deadline computation; no LLM.
- **Hexagonal architecture.** Domain (matching, completeness, reporting deadlines) isolated from adapters
  (vulnerability feeds, report formats, HTTP upload), so regulatory format changes only touch adapters.
- **Configurable endpoint** for uploads: `--endpoint` flag and an environment variable.
- **Only inventories leave the user's CI**, never source code.

## License

Dual-licensed `MIT OR Apache-2.0` (the Rust ecosystem default, the easiest to integrate). Every crate declares it,
inherited from `[workspace.package] license = "MIT OR Apache-2.0"` with `license.workspace = true`. Dependencies must
be compatible with both: no copyleft (GPL, AGPL, LGPL-only) crate. The `accepted` licenses of `about.toml` are those the
release binaries may include; `deny.toml` allows the same ones to every dependency (`cargo deny check` in CI,
`workspace_policy.rs` keeps the two lists equal). Adding a license changes both files.
Vendored data follows the same rule and keeps its license next to it: the Unicode 16.0 extracts of
`crates/forewarn/data/ucd-16.0.0` (Unicode License v3), test data only.

## Lint policy (requirement)

Every crate enables Clippy at its strictest: the `pedantic` group, denied. Set it once in the workspace root
`Cargo.toml` and have each crate inherit it; a crate without `[lints] workspace = true` is a defect.

```toml
# Cargo.toml (workspace root)
[workspace.lints.clippy]
pedantic = { level = "deny", priority = -1 }

# <crate>/Cargo.toml
[lints]
workspace = true
```

Silence a single pedantic lint only locally, with `#[expect(clippy::<lint>, reason = "...")]`, never by allowing it
workspace-wide. The project check runs `cargo clippy --all-targets -- -D warnings`.

## Testing priority

The 24 h / 72 h / 14-day reporting deadlines must be covered by BDD scenarios: a bug there costs the most.
