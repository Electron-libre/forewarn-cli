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
