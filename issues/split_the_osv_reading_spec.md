---
priority: low
why: 'a warning of check-specs, no behaviour at stake: the spec stays correct, only harder to read'
---
# Split the spec of OSV reading, its cache of archives apart

# Goal
`specs/osv-reading.md` outgrows the bounds of `spec_max_*`: `cardinal run check-specs` warns that the accepted spec
does. Split it into specs of one capability each, so that each reads at a glance, with every cited id still resolving.

# Findings
* Crossed by `issues/check_the_integrity_of_a_cached_copy.md` (2026-11-13), which added OSR-38 to OSR-41: 40 live
  requirements and 25,134 bytes, against 37 and 23,020 before it.
* The spec holds three capabilities: reading OSV records (OSR-1 to OSR-12, OSR-34 to OSR-36), fetching the archives
  into the cache (OSR-13 to OSR-23, OSR-32, OSR-33, OSR-38 to OSR-41) and querying the OSV API (OSR-26 to OSR-31).

# Approach
1. Move the fetching of the archives, or the OSV API, into a spec of its own, with its own id; each moved
   requirement takes the next number of the new spec, its old one stays `withdrawn: moved to XYZ-n` (procedure of
   `skill:write-spec`, step 1), as `issues/done/split_the_cli_match_spec.md` did for `forewarn match`.
2. Re-cite the tests (`// spec:`) and the documents that cite the moved ids.

# Specs
* `specs/osv-reading.md`, and the new spec(s) it is split into.

# Resources
* `issues/done/split_the_cli_match_spec.md`, commit `9c22372`.
* `specs/README.md` (bounds, withdrawn requirements).

# Hints
* `crates/forewarn-osv/tests/fetching.rs` and `crates/forewarn-osv/tests/api.rs` hold most citations; `grep -rn "OSR-"`
  finds the others, the KEV and EUVD specs included.
