---
priority: high
depends_on: [write_the_early_warning_in_an_adapter]
why: 'what the user runs: without it the milestone delivers nothing a vendor can use'
---
# Write a draft early warning for each actively exploited match from the CLI

# Goal
A vendor runs `forewarn match` in CI or by hand; when a match is actively exploited they should get, in the same run,
a draft CRA early warning for it, ready to complete and copy into the ENISA Single Reporting Platform.

# Approach
1. The command: an option of `match` (e.g. `--draft <dir>`, writing one file per exploited match) or a subcommand
   (`forewarn draft`) taking the same inputs; to decide at step 1.
2. The file name: stable and unique per match (product, CVE), so that a rerun overwrites the draft of the same
   vulnerability rather than piling copies.
3. The report of `match` names the files written; the exit codes stay those of `specs/cli-match.md` and
   `specs/cli-match-exploited.md` (6 on an exploited match), a draft that cannot be written exiting with a code of its
   own.

# Specs
* `specs/cli-match-exploited.md` (MXL-n) or a new `specs/cli-draft.md`, depending on step 1.

# Milestone
Draft the CRA early warning

# Resources
* `crates/forewarn/src/main.rs` (arguments, `--aware-since`, `--measure-available`, `--now`).
* `specs/cli-match.md`, `specs/cli-match-exploited.md`.

# Hints
* `--aware-since` and `--now` already give a deterministic run: the drafts of the tests should use them.
