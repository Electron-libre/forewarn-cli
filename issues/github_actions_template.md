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
