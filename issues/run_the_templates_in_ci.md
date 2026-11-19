---
priority: medium
depends_on: [github_actions_template]
why: 'catches a template broken by a change before a vendor does; the milestone holds without it'
---
# Run the GitHub Actions template in the project's CI

# Goal
The GitHub Actions template is run by this repository's CI on every pull request, against a test SBOM and local feeds,
so a change of the CLI or of the template that breaks it turns the check red.

# Approach
1. A job of `.github/workflows/check.yml` (not `cardinal.yml`, synced by Cardinal) that runs the steps of the
   template with the binary built from the commit instead of a downloaded release, and the feeds given as files
   (`--osv`, `--kev`, `--euvd`) or `--refresh offline`: nothing fetched.
2. Candidates: the template made callable (`workflow_call`) with inputs for the binary and the sources, or a job that
   extracts and runs its `run:` blocks; decided at step 1, keeping the template readable as an example.
3. The expected exit codes checked on fixtures: one SBOM with an actively exploited match (the job sees 6), one without.
4. The upload step run against nothing, or with `--dry-run`.

# Milestone
CI integration templates

# Resources
* `.github/workflows/check.yml`: the jobs of the project check.
* `crates/forewarn/tests/fixtures`: SBOMs and feeds already used by the tests.
* `docs/user-guide.md`: section "The cache" (`--refresh offline`).

# Hints
* No secret is available to a pull request from a fork: the upload step must not need one there.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
The shell of the GitHub Actions template runs on every pull request against the binary of the commit, a fixture
product and local feeds, so a change of the CLI or of the template that breaks it turns the check red. Out of scope:
the GitLab template (a follow-up issue), the `uses:` actions (cache, artifact, syft), any download.
Means: an integration test of `cargo test` (Unix), run by the `check` job and the macOS one, instead of a new job: it
runs the `run:` blocks of the template's steps with `bash -e` in a temporary Git repository, the GitHub variables
(`GITHUB_REF_TYPE`, `GITHUB_OUTPUT`…) set by the test; no YAML of the template changes, no logic in the workflow.

## Plan
1. [x] Run the GitHub Actions template in a test: `crates/forewarn/tests/ci_template_run.rs` reads the `run:` block
   of each named step of `examples/ci/github-actions.yml`, fails on a step it neither runs nor replaces (install:
   the binary of the commit put first on `PATH`; syft: a fixture SBOM copied to `sbom.cdx.json`), adds to `forewarn
   match` the local feeds (`--osv`, `--kev`, `--euvd`: nothing fetched) and to `forewarn upload` `--dry-run`; two
   runs, a daily run on a repository tagged `v1.2.0` whose SBOM has an actively exploited `log4j-core` (match exits 6,
   a draft written, the tag checked out) and a tag run whose SBOM is only affected (exits 0, upload dry run prints the
   product and version); fixtures under `crates/forewarn/tests/fixtures/ci-template/`; docs (`CLAUDE.md`, user guide
   if it names the template checks); verified by the test itself, red first on a template whose match line is broken. (autonomous)
   Code review: no findings.
2. [x] Fixes of the `high` review of the issue: the shell of a step runs with only the job's variables (no
   `GIT_DIR` nor Git configuration of the caller), the variables of a step's `env:` all given, a `shell:` or
   `working-directory:` of a step run refused, `|-` and `|+` blocks read, `--refresh=` dropped too, a multiline output
   refused, the run of `common` reused; verified by the tests, also run under the `GIT_DIR` of this repository.
   (autonomous) Code review: no findings.

## Decisions
- Mode: autonomous
- Base commit: 19011d3e821b42c36e0b7d231a6a761b6b1708af
- Means: a `cargo test` integration test, not a job of `check.yml` nor a callable template (answer 1 a).
- The GitLab template gets a follow-up issue (answer 2 a).

## Deliverable 1
- done: `ci_template_run.rs` runs the shell of the GitHub template (check out, check, match, upload) against the
  binary of the commit, a fixture product and local feeds, in a daily run (exits 6, a draft) and a tag run (exits 0,
  upload dry run); `CLAUDE.md` and the update-docs map name it.
- red: none (no spec); the test failed on a template whose match gives `--allow-afected`:
  `error: unexpected argument '--allow-afected' found`.
- not verified: the steps that use an action (checkout, cache, artifact, syft), GitHub's.
- follow-up: the GitLab template, an issue of its own.

## Deliverable 2 (high review of the issue)
- done: the fixes listed in the plan.
- red: none (fixes of a test).
- Code review (high): 9 findings. Fixed: 1 (caller's `GIT_*`), 2 (global Git configuration), 4 (step `env:`,
  `working-directory:`, `shell:`), 5 (block indicators), 6 (dead branch of `--refresh`), 7 (`common::Run` reused),
  9 (multiline outputs). Not fixed: 3, wrong: a `run:` without `shell:` runs with `bash -e {0}` on GitHub, no
  `pipefail`; 8, `workspace_root` is copied in each test crate already, its sharing a refactor of its own.
