# 0016. Complete the SBOM of the release binaries after cargo-cyclonedx

- Status: accepted
- Date: 2026-11-17

## Context

The release workflow ships the SBOM `cargo-cyclonedx` writes for each binary (ADR 0015), and `forewarn check` reports
it incomplete: on `v0.2.0`, 28 of 98 components on Linux, 29 on macOS (`nix`), the same on the four targets.

- The five workspace crates `forewarn-*` lack a supplier and a hash. Cargo metadata has no supplier field and the
  workspace declares no `authors`; a path crate has no registry checksum.
- 23 crates.io crates (`clap`, `rustls`, `libc`…) lack a supplier: `cargo-cyclonedx` fills only `authors`, from the
  optional `authors` of their manifest, which recent crates leave out. The other 70 pass on that `authors` alone.
- The workflow runs `forewarn check --allow-incomplete`, so the gaps never fail a release.

A tool that tells vendors which fields the CRA expects should ship an SBOM it finds complete. `cargo-cyclonedx`
0.5.10 reads no `[package.metadata]` that would fill a supplier or a hash.

## Decision

- **A post-processing step of the workflow**, `jq` on the SBOM `cargo-cyclonedx` wrote, before `forewarn check`;
  `forewarn` itself never edits an SBOM.
- **The workspace crates and the product**: supplier the manufacturer, `Electron-libre`
  (`https://github.com/Electron-libre`); the product (`metadata.component`) gets it as manufacturer, which the early
  warning draft reads. A path crate is of the workspace when the workflow hashed it, by package name: a vendored or
  patched path crate is left without supplier, so that the release fails rather than name the manufacturer supplier
  of code it did not write.
- **The hash of a workspace crate and of the product**: the SHA-256 of the tar of its source tree at the tag, the
  source the binary was built from, `git -c tar.umask=0022 -c core.autocrlf=false archive --format=tar
  --mtime='1970-01-01 00:00:00 +0000' <tag>:crates/<crate>` (Git 2.42 or later for `--mtime`): given a tree, `git
  archive` dates its entries with the current time, and a local `tar.umask` or `core.autocrlf` would change the
  bytes, so all three are fixed for anyone to recompute it. An unchanged crate keeps its hash from one release to
  the next. Not the `.crate` archive `cargo package` writes: it needs a `version` on every path dependency and no
  `publish = false`, the decision ADR 0015 defers.
- **The crates.io crates**: supplier `crates.io` (`https://crates.io`) for each, as the distributor CycloneDX allows a
  supplier to be; their `authors` stay as written.
- **`--allow-incomplete` is dropped**: an incomplete SBOM fails the release, and a pull request touching the
  manifests, which builds the SBOMs.

## Consequences

- A new crates.io dependency is covered without a change; a dependency from another source (git, another registry)
  stays without supplier and fails the release until the step names its supplier.
- The hash of a workspace crate is not that of an artifact a registry serves: the user guide says how to recompute it.
- The step depends on `jq`, present on the GitHub-hosted runners; the tests of `release_workflow.rs` run it too, so a
  developer running `cargo test` needs it.
