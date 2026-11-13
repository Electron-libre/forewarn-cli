# 0010. Record the files of a download to tell a damaged cached copy

- Status: proposed
- Date: 2026-11-13

## Context

`forewarn-cache` took a cached copy as damaged when the source failed to read it, and downloaded it again once
(`issues/done/recover_a_damaged_cached_copy.md`). That heuristic misses a record file removed from an OSV snapshot: the
snapshot reads the files left, and `forewarn match` silently misses their vulnerabilities. It also takes for damage
what is not: a record a newer forewarn refuses (every run downloads the archive again and still fails), or an I/O error
such as a permission refused or too many open files (`issues/check_the_integrity_of_a_cached_copy.md`).

## Decision

- **A manifest in the freshness**: a download records in `forewarn-freshness`, beside the time and the URL, the name
  and the size of each file it stored in the entry directory.
- **Checked before a read**: a cached copy whose files differ from its manifest (a file missing, added, or of another
  size) is damaged: downloaded again once, as before, or refused under `offline` with the first file that differs. A
  copy that matches its manifest and fails to read is reported as it is, with no download.
- **Sizes, not hashes**: a size catches a removed, added or truncated file with one `stat` per file. Hashing would
  also catch an edit that keeps the size, but reads every byte of a large ecosystem (tens of thousands of files) at
  each read, on top of the source's own read. Modification times are not recorded: a CI cache restored by copy changes
  them, and every run would then download again.
- **An older freshness**, with no manifest, is downloaded again once under `if-missing` and `older-than`; under
  `offline` the copy is read as it is, since an air-gapped run has no other.

## Consequences

- A record file removed or truncated outside forewarn is detected; an edit that keeps its size is read as it now is.
- A record a newer forewarn refuses no longer downloads the archive at each run: it fails with the reason.
- The first fetch of each entry after the upgrade downloads it again.
