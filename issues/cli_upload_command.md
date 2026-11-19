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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-19

## Understanding
`forewarn upload <sbom>` sends the SBOM as is to the service with `forewarn-upload`: endpoint from `--endpoint` or
`FOREWARN_ENDPOINT`, token from `FOREWARN_TOKEN`, product and version from the SBOM unless `--product`,
`--product-version`; exit codes 8 to 11 for the failures. Means differ from the issue: no date sent nor `--now` (the
contract leaves the date to the service clock, UPA non-goals); the report prints the receipt's `received_at`.

## Plan
1. [x] Upload: subcommand `upload` (module `args`), wiring, human report and exit codes in a module `upload` of the CLI
   crate, endpoint and token from the options and the environment, SBOM read then sent as is, overrides, the failures
   and their error lines; verified by `crates/forewarn/tests/upload.rs` against a loopback fake service; makes true
   CUP-1 to CUP-4, CUP-6 to CUP-15 (~800 lines). (autonomous)
2. [ ] `--dry-run`: prints endpoint, product, version, size, sends nothing, reads no token; docs of the whole command
   (user guide: section, "In CI", "What leaves your machine", exit codes; `docs/architecture.md`; `CLAUDE.md`);
   verified by the same test file; makes true CUP-5; spec `accepted` (~200 lines).

## Decisions
- Mode: autonomous
- Base commit: 4af6a300facd539dcda452ab3ba44e8926959bf8
- No date sent, no `--now`: the service dates the upload (UPA non-goals); the report prints the receipt's `received_at`.
- Token from `FOREWARN_TOKEN` only, no option.
- Overrides named `--product`, `--product-version`.
- Exit codes: 8 unreachable, 9 credentials refused, 10 upload refused (a name or a size refused before sending
  included), 11 unreadable answer.
- No JSON report in this issue.
- Deliverables 1 and 2 of the validated plan merged into one: the failure mapping is a dozen lines of the same module,
  its tests would have had no red phase apart; together 798 changed lines, under the limit.

## Summaries

### Deliverable 1
- done: `forewarn upload` sends the SBOM as read to the service, reports the receipt, exits with 2, 3, 8 to 11; guide,
  architecture and `CLAUDE.md` describe it.
- red: CUP-1, CUP-2, CUP-3, CUP-4, CUP-6, CUP-7, CUP-8, CUP-9, CUP-10, CUP-11, CUP-12, CUP-13, CUP-14, CUP-15:
  `error: unrecognized subcommand 'upload'` (exit 2) in each of the 15 tests.
- Code review: no findings
- not verified: the Windows path of CUP-15 (CI runs the tests on Windows; the test here covers the escaped path only).
