# 0015. Distribute release binaries on GitHub, before any crates.io publication

- Status: accepted
- Date: 2026-11-17

## Context

The only install is `cargo install --path crates/forewarn` from a clone, which needs a Rust toolchain; the CI of a
vendor running `syft` or `cdxgen` often has none. A beta tester should install a released version in one command, and
a CI job should pin it.

Two channels exist. crates.io (`cargo install forewarn`, `cargo binstall`) needs a `version` on every path
dependency, a publication order of six crates, and makes the domain and adapter crates a public API that the hosted
service and others may depend on, before their shape has settled (ADR 0001). GitHub releases hold built binaries; the
tags `v0.1.0` and `v0.2.0` exist, none with a binary.

The crate depends on `ring` (through `rustls`), which builds natively on each target but needs a C compiler for the
target when cross-built. The tests run on Linux and macOS only: Windows waits for
`issues/support_windows_paths.md`.

## Decision

- **GitHub releases, built by a workflow of the repository** (`.github/workflows/release.yml`), on each pushed tag
  `v<version>`; crates.io waits for its own decision (`publish = false` stays).
- **A hand-written matrix**, each target built natively on a GitHub-hosted runner, rather than a release generator
  (`cargo-dist`): a short workflow the project reads whole, no installer script piped into a shell, no tool that
  rewrites the workflow.
- **Targets**: `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (static: they run on any Linux image,
  Alpine included), `aarch64-apple-darwin` and `x86_64-apple-darwin`. No Windows binary while the tests do not run on
  Windows.
- **One archive per target**, `forewarn-<target>.tar.gz` (no version in the name, so that
  `releases/latest/download/<archive>` always names the newest release), holding the binary, `LICENSE-MIT`,
  `LICENSE-APACHE`, `README.md`, `THIRD-PARTY-LICENSES` and the SBOM of the binary, `forewarn.cdx.json`; the SBOM
  also attached apart (`forewarn-<target>.cdx.json`), one `SHA256SUMS` file over the archives and the SBOMs; the
  release notes are the `CHANGELOG.md` section of the version.
- **The notices of the third-party crates** the binary includes travel with it, as their MIT, BSD, ISC and Apache
  licenses ask: `cargo-about` writes them for the targets of `about.toml`, which lists the licenses accepted; a crate
  under another license fails the release.
- **forewarn ships its own SBOM**, as the CRA asks of a product: `cargo-cyclonedx` writes one per target, in
  CycloneDX 1.6, and `forewarn check` reads it before the release.
- **The build provenance is attested** (`actions/attest-build-provenance`): `gh attestation verify` tells an archive
  built by this workflow from another.
- **The tag must name the workspace version**: the workflow refuses a tag `v<x>` when `[workspace.package] version`
  is not `<x>`, so `forewarn --version` matches the archive.
- **Built, not published, on a pull request** that changes the workflow, so a change of it is tried before a tag.

## Consequences

- One command installs a release: download the archive of the target, check it against `SHA256SUMS`, extract it. A CI
  job pins the version in the URL (`releases/download/v<version>/`).
- The library crates stay private to the repository; publishing them later is a new ADR, the GitHub releases staying.
- A Windows binary is added when `issues/support_windows_paths.md` is done, a container image when a user asks for it.
- The workflow only runs on a pushed tag; `cardinal run release --tag` creates it, the maintainer pushes it.
