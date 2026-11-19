---
priority: medium
why: 'the releases of forewarn may fall under the CRA reporting obligation, in force since 2026-09-11; no milestone needs it yet'
---
# Watch the released binaries with forewarn each day

# Goal
The release workflow checks the completeness of the SBOM of each target once, at the tag, but nothing matches the
released binaries against the vulnerability lists afterwards. A dependency of a published release can become actively
exploited without any change of this repository, and the CRA article 14 deadlines then run for its manufacturer. Run
forewarn on its own releases each day, as the CI templates tell vendors to do, so the project uses what it ships and
meets the reporting obligation for its own binaries.

# Findings
* `.github/workflows/release.yml` writes `sbom/forewarn-<target>.cdx.json` with `cargo-cyclonedx`, completes it with
  `.github/sbom-complete.jq` and runs `forewarn check` on it; the SBOMs are attached to the GitHub release.
* No workflow runs `forewarn match`: `check.yml` runs the project check and `cargo deny check` (RustSec advisories of
  the lock file, not the released binaries' SBOM nor the KEV/EUVD lists).
* `examples/ci/github-actions.yml` already has the daily run vendors copy: latest tag, feeds and `--awareness` kept in
  the cache, `--drafts`, exit 6 on an exploited match, upload on a tag. It produces the SBOM with `syft`, which names
  the product without a package URL; the release SBOM from `cargo-cyclonedx` does not have that problem.

# Approach
1. A scheduled workflow (daily, plus `workflow_dispatch`) that downloads the binary and the SBOMs of the latest
   release (`gh release download`, checked against `SHA256SUMS`), restores the feed cache and the awareness file, runs
   `forewarn match --awareness … --drafts drafts` on the SBOM of each target, saves the cache even on failure, and keeps
   the report and drafts as artifacts. The job fails (exit 6) on an exploited match, which notifies the maintainers.
2. Use the released binary, not one built from `main`: the run then checks what users have, with the tool they have.
3. Once a Forewarn service account exists for the project, upload the SBOM of each target on the tag (in
   `release.yml` after the release is published, or in the new workflow), with `FOREWARN_ENDPOINT` and
   `FOREWARN_TOKEN` as repository secrets. Can be a later cut.
4. Decide whether the targets share one SBOM report or each gets its own (their dependency trees may differ).

# Resources
* `.github/workflows/release.yml` (SBOMs, targets of `about.toml`)
* `examples/ci/github-actions.yml` (the daily run to follow)
* `specs/cli-match-awareness.md`, `specs/cli-match-exploited.md`
* `docs/user-guide.md` (section "In CI")

# Hints
* `crates/forewarn/tests/release_workflow.rs` and `ci_templates.rs` read workflow files: check whether a new
  workflow should be covered the same way.
* The cache key must be unique per run (GitHub never overwrites a key), as in the template.
* `just set-version` writes the `FOREWARN_VERSION` the templates pin; the new workflow should take the latest release
  instead, so it never needs a bump.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
A daily workflow `.github/workflows/watch.yml` that installs the binary of the latest GitHub release (checked against
its `SHA256SUMS`) and runs `forewarn match` on the SBOM of each released target, feeds, awareness file and drafts kept
in the cache, failing on an exploited match. Out of scope: the upload on a tag (no service account yet, a later issue).
No spec: CI of the project, no change of what the CLI does.

## Plan
1. [x] Daily watch workflow: `watch.yml` (schedule + `workflow_dispatch`, `gh release download` of the latest release,
   checksums, cache restore/save, `match --allow-affected --refresh 12h --awareness … --format json --drafts drafts`
   per target SBOM, artifacts, job failing when one run exits non-zero), its tests in `crates/forewarn/tests/` (each
   `forewarn` option it gives exists, each asset it downloads is one `release.yml` publishes), docs
   (`docs/architecture.md` CI part, `CLAUDE.md`); verified by those tests and a `workflow_dispatch` run after push. (autonomous)
2. [x] Fixes of the high review: drafts per target, concurrency group, attestation signed by `release.yml`, the copy
   of the SBOMs into the release checked, the 60-day schedule and the option of the latest release documented;
   verified by the project check. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: ddfe0243757f27f4cea350cb717167b9eba551b9
- Targets: the SBOM of each of the four released targets, matched in a loop; one awareness file for the product.
- Upload on a tag: out of scope, a follow-up issue once a service account exists.
- Tests: static (options the binary has, assets `release.yml` publishes); the real run checked by a `workflow_dispatch` after the push.
- Provenance: `gh attestation verify` of the archive, besides `SHA256SUMS`.

## Deliverable 1
- done: `.github/workflows/watch.yml` matches the SBOM of each target of the latest release each day with that
  release's binary; two tests in `ci_templates.rs`; `CLAUDE.md` and the docs map.
- Code review: 1 finding: the job exited with the code of the last failing target, hiding an exploited match (6)
  behind a later error; fixed, 6 now wins.
- red: none (no spec); the two tests failed first on `.github/workflows/watch.yml` missing.
- docs: `docs/architecture.md` has no CI part, left as is.
- not verified: the run on GitHub (`gh release download`, `gh attestation verify`, the cache), to check with a
  `workflow_dispatch` after the push; no local `actionlint`.

## Deliverable 2
- done: fixes of the `high` review of the issue.
- red: none (configuration and docs; the test change adds a check that passes on the current `release.yml`).
- Code review: no findings.
- High review: 8 findings. Fixed: drafts shared by the targets (overwritten, reported stale) now one directory per
  target; no concurrency group; attestation of any workflow accepted, now `--signer-workflow release.yml`; the copy of
  the SBOMs into `dist/` unchecked; the options of the latest release, not of the commit, documented in the workflow
  and `CLAUDE.md`; the schedule GitHub disables after 60 days documented. Not fixed: the `run:` blocks are not
  executed by a test (decision 3, static tests); a keep-alive for the 60-day disabling (a later issue if needed).
