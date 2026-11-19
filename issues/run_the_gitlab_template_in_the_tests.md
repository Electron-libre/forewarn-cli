---
priority: low
depends_on: [run_the_templates_in_ci]
why: 'the GitHub template is run already; the GitLab one only has its options checked, a comfort for the milestone'
---
# Run the GitLab CI template in the tests

# Goal
`examples/ci/gitlab-ci.yml` is run by `cargo test` as `crates/forewarn/tests/ci_template_run.rs` runs the GitHub
Actions template: the `before_script` and `script` lines of its jobs against the binary of the commit, a fixture
product and local feeds, so a change of the CLI or of the template that breaks a vendor's pipeline turns the check red.

# Findings
* `crates/forewarn/tests/ci_templates.rs` checks only that the options the GitLab template gives `forewarn` exist and
  that it installs an archive the release builds; none of its shell runs.
* The GitHub run (issue `run_the_templates_in_ci`) reads the template line by line, runs each `run:` block with
  `bash -e` and only the job's variables, rewrites `forewarn match` with `--osv`, `--kev`, `--euvd` (its `--refresh`
  dropped, refused when nothing is fetched) and `forewarn upload` with `--dry-run`.

# Approach
1. Read the jobs `forewarn-sbom`, `forewarn-match`, `forewarn-upload`: their `script` lists, the variables of GitLab
   they read (`CI_COMMIT_TAG`, `CI_PROJECT_NAME`…), the files passed between them as artifacts.
2. Candidates: share the reading and the running of `ci_template_run.rs` (a module of `tests/common`), or a test of
   its own; GitLab runs each `script` line with `sh` (the `alpine` image), so the lines run with `sh -e`, not `bash`.
3. The same two runs: an actively exploited match (exit 6) and a match not exploited with the upload as a dry run.

# Milestone
CI integration templates

# Resources
* `crates/forewarn/tests/ci_template_run.rs`, `crates/forewarn/tests/fixtures/ci-template/`.
* `examples/ci/gitlab-ci.yml`, `docs/user-guide.md` (In CI).

# Hints
* The installation step (`apk`, the download of the release) is replaced by the binary of the commit, as in the
  GitHub run.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
`cargo test` runs the `script` lists of the jobs of `examples/ci/gitlab-ci.yml` with `sh -e` (and `pipefail` when the
shell has it, as the GitLab runner does) against the binary of the commit: a daily run on the latest tag (exit 6) and a
tag run (match not exploited, upload as a dry run). Tests only, no spec: no behaviour of the CLI changes. The
`before_script` installs (`apk`, forewarn, syft) are replaced; `syft` by a stub on `PATH` that records its arguments and
writes the fixture SBOM, so the shell of `forewarn-sbom` (tag resolution, `git checkout`) runs as written.

## Plan
1. [x] Share the sandbox of the GitHub run: move the helpers that are not GitHub's (fixture paths, quoting, the
   rewrites of `forewarn match` and `forewarn upload`, the product directory with its isolated environment, `git`, the
   report) into `crates/forewarn/tests/ci_template/mod.rs`, the template named by the caller; no change of behaviour;
   verified by `ci_template_run.rs` still green. (autonomous)
2. [x] Run the GitLab template: `crates/forewarn/tests/ci_gitlab_template_run.rs` reads the jobs (`script`,
   `before_script`, `extends`), checks each job with a `script` is run and each `before_script` replaced, and runs the
   two scenarios; fixtures README, `CLAUDE.md` and the docs updated; verified by the new tests (red first on a
   template step they do not run yet). (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 4ca94a7d1f995178af63ae5e2bbf9beab76e1aeb
- Shared code in `tests/ci_template/`, included by the two runs only (1 a).
- `syft` replaced by a stub that checks its arguments; the `script` of `forewarn-sbom` runs as written (2 a).

## Summaries

### 1. Share the sandbox of the GitHub run
- done: `tests/ci_template/mod.rs` holds the fixtures, the rewrites of `match` and `upload` and `Sandbox` (the product,
  its isolated environment, `git`, the tagged release, the report); `ci_template_run.rs` keeps the GitHub reading.
- red: none (no change of behaviour, the three GitHub tests unchanged and green).
- Code review: no findings (the `low` review reads no test file, and this diff holds only test files).
- checks: `project-check` green (fmt, clippy, tests, specs); size 382 lines.

### 2. Run the GitLab template
- done: `tests/ci_gitlab_template_run.rs` reads the jobs of the template (`extends`, `variables`, `before_script`,
  `script`), runs the `before_script` items after `cd "$CI_PROJECT_DIR"` and the `script` with `sh` (`errexit`,
  `pipefail` when the shell has it), `syft` a stub that records its arguments; the shared match rewrite also drops
  `--cache`, refused when nothing is fetched. `CLAUDE.md`, the docs map and the fixtures README name the new run.
- red: none (no spec); first run: `the line of forewarn match is rewritten word by word: ... --cache .forewarn-cache \`
  (the line continued with `\`, now unfolded), then `--cache and --refresh apply to what is fetched` (exit 2, not 6).
- Code review: no findings.
- checks: `project-check` green (fmt, clippy, tests, specs); size 457 lines; no file over the size limit.
