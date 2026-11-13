---
priority: low
why: 'a warning of check-specs, no behaviour at stake: the spec stays correct, only harder to read'
---
# Split the spec of OSV reading, its cache of archives apart

# Goal
`specs/osv-reading.md` outgrows the bounds of `spec_max_*`: `cardinal run check-specs` warns that the accepted spec
does. Split it into specs of one capability each, so that each reads at a glance, with every cited id still resolving.

# Findings
* Crossed by `issues/done/check_the_integrity_of_a_cached_copy.md` (2026-11-13), which added OSR-38 to OSR-41: 40 live
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

# Tracking

Plan: validated by Cedric Brancourt <cedric.brancourt@gmail.com> on 2026-11-13

## Understanding
Move the fetching of the OSV archives into the cache (OSR-10 to OSR-23, OSR-32, OSR-33, OSR-38 to
OSR-41, happy paths OSR-H3 to OSR-H5, their edge scenarios and non-goals, ADRs 0004, 0005, 0007, 0010) into
`specs/osv-fetching.md` (id `OSF`); the OSV API stays in `osv-reading.md` (20 live requirements each). No behaviour
changes: only citations move.

## Plan
1. [x] Split the spec: `specs/osv-fetching.md` with OSF-1 to OSF-20 and OSF-H1 to OSF-H3, the moved OSR ids
   `withdrawn: moved to OSF-n`; the tests of `fetching.rs`, the doc comments of `forewarn-osv` (`fetch.rs`, `lib.rs`),
   `specs/cli-match.md` and CLAUDE.md re-cited; verified by `check-specs` (no bound warning, both specs
   `accepted`) and `project-check` unchanged; makes true OSF-1 to OSF-20. (autonomous)

## Decisions
- Mode: autonomous
- Base commit: 46396dd2dc144fde067d5a1385d2386456435782
- Mapping: OSR-10→OSF-1, 11→2, 12→3, 19→4, 32→5, 33→6, 20→7, 21→8 (Behaviour), 13→9, 38→10, 39→11, 40→12, 41→13,
  14→14, 15→15, 16→16, 17→17, 18→18, 22→19, 23→20 (Contract); OSR-H3→OSF-H1, H4→H2, H5→H3. The happy paths cannot be
  withdrawn, so OSR-H3 to OSR-H5 disappear; OSR-H6 keeps its id (no renumbering of a cited id).
- The archives move rather than the API: moving the API alone (6 requirements) would leave 34 live requirements,
  still near the bound.

## Summary of deliverable 1
- done: `specs/osv-fetching.md` (OSF-1 to OSF-20, OSF-H1 to OSF-H3) holds the fetching of the OSV archives into the
  cache; `specs/osv-reading.md` keeps 20 live requirements, the moved ones withdrawn as moved; the tests of
  `fetching.rs`, the doc comments of `fetch.rs` and `lib.rs`, `specs/cli-match.md`, ADR 0008 and CLAUDE.md re-cited.
- checks: project-check pass (fmt, clippy, tests); check-specs pass, no bound warning; docs: CLAUDE.md.
- red: none (no test added: the existing tests are only re-cited).
- Code review: no findings

## Deliverable 2: high review fixes
2. [x] Fix the four findings of the high review of the issue: OSR-37 points to OSF-10 to OSF-13; the test and the
   scenario of a hidden file in a snapshot, fetched under `offline`, also cite OSF-11; ADR 0008 keeps its OSR ids (an
   accepted ADR is not rewritten, the withdrawn ids resolve); OSF-4 wrapped; verified by project-check and
   check-specs. (autonomous)
- red: none (citations and docs only).
- Code review: no findings
