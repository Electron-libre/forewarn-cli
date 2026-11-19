---
priority: high
depends_on: [upload_an_sbom_to_the_service]
why: 'the command a CI job runs: the milestone''s goal itself'
---
# Upload an SBOM from the command line

# Goal
A CI job runs `forewarn upload <sbom>` at each release to keep the vendor's inventory in a Forewarn service up to date
without manual work. The endpoint is set by `--endpoint` or an environment variable; the product and version come from
the SBOM; the job fails, with an exit code of its own, when the upload does not go through.

# Approach
1. Subcommand `upload` (module `args`): the SBOM path, `--endpoint` with an environment variable as fallback (such as
   `FOREWARN_ENDPOINT`), the flag winning; a run without an endpoint stops with a usage error.
2. The SBOM read by the CycloneDX adapter first: a document it refuses is not uploaded; the product name and version
   from `metadata.component` (`Product`), with options to override them, and a run without a product version stops
   with an error naming the option.
3. The date: the moment of the run, or `--now` as `forewarn match` takes it.
4. Exit codes distinct from those of `check` and `match`: endpoint unreachable, credentials refused, upload refused.
5. A candidate: `--dry-run`, printing what would be sent (endpoint, product, version, date, SBOM size) and sending
   nothing.
6. Docs: the user guide (a section, the reference, the exit codes, the table "What leaves your machine": the SBOM
   itself), `docs/architecture.md`.

# Specs
* `specs/cli-upload.md` (new): the arguments, the environment variables, the report, the exit codes.

# Milestone
Upload from CI

# Resources
* `crates/forewarn/src/args.rs`, `crates/forewarn/src/main.rs`: the subcommands and their wiring.
* `specs/cli-check.md`, `specs/cli-match.md`: the form of a CLI spec, the exit codes already taken.
* `docs/user-guide.md`: "In CI", "What leaves your machine", "Reference".

# Hints
* Only inventories leave the CI, never source code: the SBOM is sent as given, nothing else of the work tree.
* Windows paths are supported (`issues/done/support_windows_paths.md`): the SBOM path follows the same rules.
