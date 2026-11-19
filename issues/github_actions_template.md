---
priority: high
why: 'half of the milestone goal: the GitHub Actions example a vendor copies'
---
# Provide a GitHub Actions workflow template

# Goal
A vendor runs `forewarn` at each release of their product by copying one workflow file. The template installs a pinned
release of `forewarn`, checks it, produces the SBOM with an existing tool, checks and matches it, keeps the report and
the draft early warnings as artifacts, and uploads the SBOM to a Forewarn service on a release tag. A job fails on what
matters (an actively exploited vulnerability) and not on what a vendor only needs to see.

# Findings
* `docs/user-guide.md`, section "In CI", gives four commands, not a pipeline: no install step, no cache, no artifacts.
* The Install section gives a pinned URL (`releases/download/v<version>`), `SHA256SUMS` and `gh attestation verify`.
* The exit codes tell apart incomplete (1), affected (1), actively exploited (6), drafts not written (7) and the
  upload failures (8 to 11); `--allow-incomplete` and `--allow-affected` keep a job green on the softer ones.
* The cache (`--cache`, `--refresh`) downloads the feeds once a day when kept between jobs.

# Approach
1. A file `examples/ci/github-actions.yml` (a copy-paste example, not a reusable action: decided with the user), each
   step commented:
   1. install the `x86_64-unknown-linux-musl` archive of a pinned version, checked against `SHA256SUMS`;
   2. produce the SBOM (`syft scan . -o cyclonedx-json`, with a comment naming `cargo cyclonedx` and `cdxgen`);
   3. `actions/cache` on a `--cache` directory, keyed on the day;
   4. `forewarn check --allow-incomplete`;
   5. `forewarn match --allow-affected --format json --drafts drafts/`, the report and `drafts/` uploaded as artifacts
      even when the step fails (`if: always()`);
   6. on a tag only, `forewarn upload` with `FOREWARN_ENDPOINT` and `FOREWARN_TOKEN` from the secrets.
2. The section "In CI" of the user guide points to it and says what each exit code does to the job.
3. A test reading the file (as `release_workflow.rs` does for the release workflow) checks that the commands and options
   it uses exist (`forewarn <command> --help`), so a renamed option breaks the build, not the users.

# Milestone
CI integration templates

# Resources
* `docs/user-guide.md`: sections "Install", "The cache", "In CI", "Exit codes".
* `.github/workflows/release.yml`: the archive names and the targets.
* `crates/forewarn/tests/release_workflow.rs`: a test reading a workflow file.
* `specs/cli-match-exploited.md`, `specs/cli-upload.md`: the exit codes and the environment variables.

# Hints
* The token only comes from a secret; the template never echoes it.
* Pin the actions the template uses to a version, as `check.yml` does.
* Keep the template free of anything about the hosted service other than the endpoint variable: this repository is
  public.

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
A commented workflow `examples/ci/github-actions.yml` a vendor copies: install a pinned, checked `forewarn`, produce
the SBOM with `syft`, `check`, `match` with report and drafts as artifacts, upload on a tag; the guide points to it, a
test keeps its commands and target valid. Out of scope: GitLab, the version bump at release, running it in CI (the
other issues of the milestone). No spec: an example in the docs, no behaviour of the CLI changes.

## Plan
1. [x] Template, test and guide: `examples/ci/github-actions.yml`; `crates/forewarn/tests/ci_templates.rs` checks that
   each `forewarn <command> --option` of its `run:` blocks is an option of `forewarn <command> --help` and that its
   target is one the release workflow builds; section "In CI" of `docs/user-guide.md` points to it and says what each
   exit code does to the job; verified by the new test (red before the file exists). (autonomous)

2. [x] Fixes of the `high` review of the issue: the daily run on the latest tag, `forewarn` installed out of the
   scanned checkout, the cache saved when the job fails, `--refresh 12h`, comments on the deadlines and on the product
   package URL `syft` leaves out, the option column and short options in the test; verified by `ci_templates`.
   (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 52db6f2df278938536942c7348859f4d5e8bea6f
- Triggers: a pushed tag `v*` and a daily run on the default branch (a vulnerability becomes exploited without a
  change of the code).
- The upload runs on a tag once the SBOM is produced, whatever `match` exits with: the service's inventory follows
  every release.
- `syft` installed with `anchore/sbom-action/download-syft`, pinned.

## Deliverable 1
done: `examples/ci/github-actions.yml`, its test `ci_templates.rs`, the guide's "In CI", a pointer in `README.md`,
`CLAUDE.md`, a row of `.claude/update-docs-map.md`.

| check | result |
|---|---|
| tests | pass (`ci_templates`: 2; an option renamed in the template turns it red) |
| lint | pass |
| specs | n/a (no behaviour of the CLI changes) |
| docs | user guide, README, CLAUDE.md, docs map |
| code review | no findings |

red: none traced; `ci_templates`: `examples/ci/github-actions.yml: No such file or directory`.

Code review: no findings.

not verified: the workflow has not run on GitHub (the issue `run_the_templates_in_ci` does); the `syft` flags
`--source-name` and `--source-version` and the action versions are taken from their latest releases, not run.

## Deliverable 2
done: the fixes of the `high` review (9 findings) in the template, its test and the guide's "In CI".

| check | result |
|---|---|
| tests | pass (`ci_templates`; a renamed long or short option turns it red) |
| lint | pass |
| specs | n/a |
| docs | user guide "In CI" |
| code review | 2 findings, fixed |

red: none traced; deliverable of fixes, its test already green.

`high` review: 9 findings. Fixed: the daily run on `main` (now the latest tag `v*`), the archive in the scanned
checkout (now `$RUNNER_TEMP`), the cache not saved on failure (`cache/restore` and `cache/save` with `always()`),
yesterday's lists under `--refresh 1d` (`12h`), the help descriptions read as options and `name:` lines read as
commands, short options unchecked. Commented, not fixable in the template: the product without a package URL from
`syft` (the guide and the template recommend the ecosystem's tool). Left to other issues: the pinned version against
the binary tested (`keep_the_templates_on_the_released_version`), the deadlines restarting at each daily run (new
issue `remember_the_moment_of_awareness_of_each_cve`, the template comment says to keep the first drafts).

Code review: 2 findings. Fixed: a scheduled run before any tag `v*` failed at `git describe` (now checks the commit,
with a notice); the cache saved under the day's key was never updated by a later run that day (now a key per run,
restored by prefix).

not verified: the workflow has not run on GitHub.
