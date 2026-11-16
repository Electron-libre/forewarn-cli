# forewarn

**Know within minutes whether your release ships an actively exploited vulnerability, and when the EU Cyber
Resilience Act wants you to report it.**

Under CRA article 14, a manufacturer that learns of an actively exploited vulnerability in its product has 24 hours
for an early warning, 72 hours for a notification and 14 days for a final report. `forewarn` turns the SBOM you
already produce into that answer:

```console
$ forewarn match --drafts drafts/ sbom.cdx.json
...
Affected (2, 1 actively exploited):
  log4j-core 2.14.1 (pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1): CVE-2021-44228 (GHSA-jfh8-c2jp-5v3q), affected per GHSA-jfh8-c2jp-5v3q from GHSA
    actively exploited: CISA KEV CVE-2021-44228 added 2021-12-10
    report by: early warning 2026-11-14T09:30:00Z (1d 0h 0m 0s left), notification 2026-11-16T09:30:00Z (3d 0h 0m 0s left), final report 14 days after a corrective measure is available
  time 0.1.43 (pkg:cargo/time@0.1.43): CVE-2020-26235 (GHSA-wcg3-cvx6-7396, RUSTSEC-2020-0071), affected per RUSTSEC-2020-0071 from RUSTSEC
Draft early warnings (1):
  CVE-2021-44228: drafts/acme-gateway-CVE-2021-44228.md
```

## What it does

- **Matches** each component against [OSV](https://osv.dev), by package URL and version, in each ecosystem's own
  version ordering.
- **Flags** what is actively exploited, with evidence from the CISA KEV catalog and ENISA's EUVD.
- **Counts down** the 24 h / 72 h / 14-day deadlines from the moment you became aware.
- **Drafts** the early warning, laid out like the ENISA Single Reporting Platform, the fields only you know marked
  `TO COMPLETE`.
- **Checks** the SBOM itself: components missing the supplier, license or hash the CRA expects.

What it is not: a scanner (bring a CycloneDX SBOM from `cargo-cyclonedx`, `syft`, `cdxgen`…), an LLM (matching and
deadlines are deterministic), or a leak (only ecosystem names leave your CI by default, never source code).

## Quick start

```sh
# Linux x86_64; the other platforms, the checksums and pinning a version: docs/user-guide.md#install
curl -fsSL https://github.com/Electron-libre/forewarn-cli/releases/latest/download/forewarn-x86_64-unknown-linux-musl.tar.gz \
  | tar -xz --strip-components=1 forewarn-x86_64-unknown-linux-musl/forewarn
sudo install forewarn /usr/local/bin/

syft scan . -o cyclonedx-json > sbom.cdx.json
forewarn check sbom.cdx.json                  # is the SBOM complete?
forewarn match sbom.cdx.json                  # affected? exploited? by when must I report?
```

In CI, fail only on what must be reported:

```sh
forewarn match --allow-affected --format json --drafts drafts/ sbom.cdx.json > forewarn.json   # exits 6 if exploited
```

## Documentation

- [User guide](docs/user-guide.md): commands, sources and cache, air-gapped CI, deadlines, drafts, JSON reports, exit
  codes.
- [Architecture](docs/architecture.md): crates, boundaries, the flow of a run, decisions ([ADRs](docs/adr/)).
- [Specs](specs/README.md): the exact behaviour of each capability.
- [Changelog](CHANGELOG.md), [roadmap](ROADMAP.md).

Status: early proof of concept, CLI only.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
