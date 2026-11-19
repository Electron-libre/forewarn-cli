# 0019. Remember the moments of awareness in a file the user names

- Status: proposed
- Date: 2026-11-19

## Context

The CRA counts the 24 h early warning and the 72 h notification from the moment the vendor became aware of an actively
exploited vulnerability. `forewarn match` took one moment for every match of a run: `--aware-since`, else the moment
of the run (MXL-17). A CI job that runs it each day, as the CI templates do, counted the deadlines from each run
again: a CVE left unreported never showed overdue, and one `--aware-since` could not serve a CVE known for a week and
one found today.

Remembering a moment per CVE means keeping a state between runs, while the CLI is deterministic: the same inputs give
the same output. Three places could hold it: a file of its own, the cache of the feeds, or the drafts `--drafts`
writes, which print the moment of awareness.

## Decision

- **A JSON file the user names with `--awareness <file>`**, read before the SBOM and rewritten whole (a temporary
  file renamed over it) when the run records a CVE it did not hold. Without the option, nothing is read or written:
  the behaviour of MXL-17 stays.
- **One entry per product and CVE**, sorted, so that one file serves several products and its diff reads in a review.
  An entry is never changed nor removed by a run: a vendor corrects a moment by editing the file.
- **A recorded moment prevails over `--aware-since`**, which gives the moment of the CVEs the file does not hold yet,
  as the clock does without it.

## Consequences

- The file is an input like the SBOM and the lists: the same SBOM, lists, file and `--now` give the same report. A
  run changes the file only when it flags a CVE for the first time.
- The CI keeps the file between runs as it keeps the cache (the templates put it under the cache directory); a lost
  file restarts the deadlines of every CVE from the next run, as before this decision.
- Not under the cache by default: a cache may be emptied at any time, and the moment it held would be lost silently.
- Not read back from the drafts: a person completes them, moves them, and their Markdown is written for a person, not
  parsed.
- Two runs writing the file at once leave the last one's whole file, the CVEs only the other recorded lost; no lock,
  unlike the cache, since a CI runs one job of a product at a time.
