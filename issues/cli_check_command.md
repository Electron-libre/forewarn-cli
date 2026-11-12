---
priority: high
depends_on: [read_cyclonedx_sbom, check_sbom_completeness]
why: 'the milestone is only usable once the CLI exposes it'
---
# Add the `rollcall check` command

# Goal
A user runs `rollcall check <sbom>` and sees the spec version (and the flag when it is older than 1.6) and the
components missing the fields the CRA expects. The output must suit both a human and a CI job.

# Approach
1. CLI parsing with `clap` (derive), in the binary crate only.
2. Human-readable output by default, `--format json` for machines; the JSON shape belongs to an adapter.
3. Exit codes to settle at step 1, e.g. 0 complete, a distinct code for gaps found, another for an unreadable file;
   an option to make gaps non-fatal in CI is a candidate.
4. Reading from standard input (`-`) is a candidate for piping the output of an SBOM generator.

# Specs
* `specs/cli-check.md` (to write at step 1): arguments, output formats, exit codes.

# Milestone
Read and check an SBOM

# Resources
* `CLAUDE.md`: hexagonal architecture (formats are adapters).
* The issues `read_cyclonedx_sbom` and `check_sbom_completeness`.

# Hints
* Keep the command name open to later subcommands (`match`, `report`, `upload`).
