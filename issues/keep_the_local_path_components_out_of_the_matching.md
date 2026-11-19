---
priority: medium
why: 'every multi-crate Rust workspace gets its own crates matched, and sent to the OSV API with --osv-api, against the promise that the vendor code never leaves'
---
# Keep the components of a local path out of the matching

# Goal
`cargo-cyclonedx` lists the crates of a workspace as top-level components, not nested in the product, with only a
`download_url=file://…` qualifier to mark them. SBR-14 reads neither, so they are third-party: matched against OSV by
name, and with `--osv-api` their ecosystem, name and version are sent out, which the project promises never to do for
the vendor's own code. A crate of crates.io that later takes the name of one of them would also be reported against
the product. Treat a component whose package URL has a local `download_url` as not evaluated, with a reason of its own
(`local path`) rather than `first-party`, so a fork of a published crate kept by path (`[patch.crates-io]`), which this
also leaves out, stays visible in the report as not matched and why.

# Findings
* Release 0.5.0, SBOM `forewarn-x86_64-unknown-linux-musl.cdx.json` (run 44609918425 of `watch.yml`, 2026-11-19):
  100 components, 100 clean, `notEvaluated` empty. The 7 workspace crates are top-level components such as
  `pkg:cargo/forewarn-api@0.5.0?download_url=file://../forewarn-api`; the product `pkg:cargo/forewarn@0.5.0?download_url=file://.`
  nests only its binary target.
* `specs/sbom-reading.md` lists "Telling first-party code by a `file://` download URL" as a non-goal, for the vendored
  copy of a published package it may be.
* A crate vendored with `cargo vendor` keeps its crates.io source in the lock file: `cargo-cyclonedx` writes no
  `file://` for it (to confirm with a real SBOM). Only path dependencies (workspace members, `[patch]` or forks by
  path) carry one.
* `syft` writes no `download_url`: the change does not help an SBOM it produced. `cdxgen` not checked.
* The first-party flag is used by the matching only (`forewarn-domain/src/matching.rs`), not the completeness check.

# Approach
1. Confirm on real SBOMs what carries a `file://` `download_url`: a workspace, a `[patch]` by path, `cargo vendor`
   (`cargo-cyclonedx`), and what `cdxgen` writes for a Cargo or npm workspace.
2. The adapter reads the `download_url` qualifier of each package URL; a `file:` URL makes the component a local path
   one. Options for the domain: an origin of the component (third-party, first-party, local path) instead of the
   boolean `first_party`, or a second flag.
3. A new reason `local path` (VMT-10, applies to the component, after `first-party`), never matched nor sent to the OSV
   API (VMT-11, MCH-42), written in the human and JSON reports.
4. The user guide: what `local path` means, and that a fork kept by path must be followed by the vendor.

# Specs
* `specs/sbom-reading.md`: SBR-14 amended or a new requirement for the local path; the non-goal on `file://` removed.
* `specs/vulnerability-matching.md`: VMT-10 (the reason table).
* `specs/cli-match.md`: MCH-42 and the `reason` values of the JSON `notEvaluated`.

# Resources
* `issues/done/match_the_components_nested_in_the_product.md`, `issues/done/leave_file_components_out_of_the_matching.md`
* `crates/forewarn-cyclonedx/src/lib.rs` (`to_domain`), `crates/forewarn-domain/src/sbom.rs`, `matching.rs`
* `crates/forewarn-cyclonedx/tests/real_tools.rs` (SBOMs of real tools)
* the package URL specification: the `download_url` qualifier

# Hints
* Compare the qualifier by the package URL specification (percent-decoded, key lowercased), not as a substring.
* The JSON `reason` gains a value: additive, but scripts matching on `first-party` should be named in the changelog.
