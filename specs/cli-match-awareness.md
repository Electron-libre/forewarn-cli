---
id: AWR
status: accepted
adrs: [0011, 0019]
---

# The moments of awareness `forewarn match` remembers

## Intent

Let a vendor whose CI runs `forewarn match` each day count the CRA reporting deadlines of each actively exploited CVE
from the moment a run first flagged it, kept in a file they name, rather than from each run again, so that an
exploited CVE left unreported shows overdue.

## Requirements

### Behaviour

- **AWR-1** (deterministic) `forewarn match --awareness <file> <sbom>` must count the deadlines of each actively
  exploited match (MXL-14, MXL-15) from the moment of awareness the file records for the product of the SBOM and the
  CVE of the match, when it records one.
- **AWR-2** (deterministic) `forewarn match --awareness <file> <sbom>` must record in the file, for each CVE of the
  actively exploited matches of the run that it records no moment for, the moment of awareness of the run (MXL-17),
  and count the deadlines of its matches from that moment.
- **AWR-3** (deterministic) `forewarn match --awareness <file> <sbom>` must keep each moment the file records as it
  was, also that of a CVE no longer actively exploited, of a match set aside by a VEX verdict (MVX-1) or of another
  product, and also when `--aware-since` is given.
- **AWR-4** (deterministic) With `--awareness`, the human report must print, with the deadlines of each actively
  exploited match, its moment of awareness and where it came from: the file, when it recorded it before the run,
  else `--aware-since` or the moment of the run, as MXL-18 says.
- **AWR-5** (deterministic) With `--awareness` and `--drafts`, the draft early warning of each CVE (MXL-27) must be
  drafted from the moment of awareness of that CVE (AWR-1, AWR-2).
- **AWR-6** (deterministic) Without `--awareness`, `forewarn match` must read and write no file of moments of
  awareness, every actively exploited match taking the moment of the run (MXL-17).

### Contract

The exit codes (3 for a file of moments that cannot be read, 7 for one that cannot be written) and the JSON member
`awareSince` of each match are rows of MCH-10 and MCH-16.

- **AWR-7** (deterministic) The file of `--awareness` must be a JSON object holding the member `awareness`, an array
  of objects `{"product", "cve", "awareSince"}`: `product` the name of the product of the SBOM (SBR-9) without its
  leading and trailing white space, or `null` when the SBOM names none or a name made only of white space, `cve` the
  CVE id in capitals (EWD-7), `awareSince` an instant as MXL-21 writes it; one entry per product and CVE, written
  sorted by product, `null` first, then by CVE id, with two spaces of indentation and a final newline.
- **AWR-8** (deterministic) The file of `--awareness` must be created, with its missing parents, only when the run
  records a moment (AWR-2), a path that does not exist being read as a file recording no moment, and be left
  untouched when the run records none.
- **AWR-9** (deterministic) The file must hold the whole of its new content or keep its former one: it is written to a
  temporary file of the same directory, then renamed over it, before the drafts are written and the report printed.
- **AWR-10** (deterministic) When the file of `--awareness` cannot be read, is not JSON, does not hold the member
  `awareness` as AWR-7 says, holds two entries of one product and CVE, or records a moment that is not an RFC 3339
  instant, falls outside the years 1 to 9999 in UTC or gives a deadline past `9999-12-31T23:59:59Z` (RDL-10),
  `forewarn match` must exit with 3 before reading the SBOM, print nothing on standard output, and one line on
  standard error naming the file and the cause.
- **AWR-11** (deterministic) When the file of `--awareness` cannot be written, `forewarn match` must exit with 7,
  write no draft, print nothing on standard output, and one line on standard error naming the path and the cause.
- **AWR-12** (deterministic) The JSON report must give, in each object of `affected` (MCH-16), the member
  `awareSince`: the moment of awareness its deadlines count from, as MXL-21 writes it, or `null` when no list names
  the match; the top-level `awareSince` stays the moment of awareness of the run (MXL-17).

## Scenarios

- **AWR-H1** (happy; AWR-1, AWR-2, AWR-4, AWR-7, AWR-8) Given the SBOM of the product `shop` with `log4j-core`
  2.14.1, a KEV catalog file naming `CVE-2021-44228` and no file `state/awareness.json`, when a daily CI job, which
  learns of it at `2026-11-13T09:30:00Z`, runs `forewarn match --osv records/ --kev kev.json --no-euvd --awareness
  state/awareness.json --aware-since 2026-11-13T09:30:00Z sbom.json`, then `state/awareness.json` records `shop`,
  `CVE-2021-44228` and `2026-11-13T09:30:00Z`, the report gives the early warning due by `2026-11-14T09:30:00Z`, and
  the command exits with 6; when the job runs again the next day, `forewarn match --osv records/ --kev kev.json
  --no-euvd --awareness state/awareness.json --now 2026-11-14T09:30:01Z sbom.json`, then the file is left untouched,
  the report says the moment `2026-11-13T09:30:00Z` comes from `state/awareness.json`, and the early warning reads
  `overdue by 1s`.
- **AWR-H2** (happy; AWR-1, AWR-2, AWR-5, AWR-12) Given the file of AWR-H1 and a KEV catalog that now also names
  `CVE-2023-4966`, exploited in another component of `shop`, when the job runs with `--aware-since
  2026-11-16T08:00:00Z --drafts drafts/ --format json`, then the file records `CVE-2023-4966` at
  `2026-11-16T08:00:00Z` beside `CVE-2021-44228`, the match of `log4j-core` carries `"awareSince":
  "2026-11-13T09:30:00Z"`, that of the other component `"awareSince": "2026-11-16T08:00:00Z"`, and each draft gives
  the deadlines of its own moment.
- (AWR-2, AWR-3) Given a file recording `CVE-2021-44228` for `shop` at `2026-11-13T09:30:00Z`, when the job runs
  with `--aware-since 2026-11-10T00:00:00Z`, then the deadlines of `log4j-core` count from `2026-11-13T09:30:00Z`, a
  CVE the file does not record is recorded at `2026-11-10T00:00:00Z`, and the report says it was given with
  `--aware-since`.
- (AWR-3) Given a file recording `CVE-2021-44228` for `shop` and `CVE-2022-1234` for `other`, when the run of `shop`
  flags no match, or sets `log4j-core` aside with a `not_affected` verdict, then the file is left untouched.
- (AWR-7) Given an SBOM naming no product, when an exploited match is recorded, then its entry gives `"product":
  null`; given the product ` shop\n`, its entry gives `"product": "shop"` and a later run of `shop` reads it back.
- (AWR-7) Given two exploited matches of one CVE in two components, when the run records it, then the file holds one
  entry for that CVE.
- (AWR-8) Given `--awareness a/b/awareness.json` where `a` does not exist and no match actively exploited, when the
  SBOM is matched, then nothing is created; given an exploited match, `a/b/` is created with the file.
- (AWR-10, MCH-10) Given a directory, a file that is not JSON, a file `{}`, an entry whose `awareSince` is `2026-11-13`, two
  entries of `shop` and `CVE-2021-44228`, or a moment `9999-12-30T00:00:01Z`, when the command runs, then standard
  output is empty, standard error names the file, the command exits with 3 and the file is left untouched.
- (AWR-11, MCH-10) Given `--awareness` naming a path under a regular file, and an exploited match,
  when the command runs with `--drafts drafts/`, then no draft is written, standard output is empty, standard error
  names the path, and the command exits with 7.
- (AWR-6, AWR-12) Given no `--awareness`, when an exploited match is reported in JSON, then its `awareSince` is the
  top-level `awareSince`, that of a match no list names is `null`, and no file is written.
- (AWR-12, MVX-8) Given an exploited match set aside by a `not_affected` verdict, when it is reported in JSON, then
  its entry of `setAside` holds no `awareSince`.

## Non-goals

- Keeping the file between CI runs: the CI keeps it, as it keeps the cache (`examples/ci/`).
- A moment of awareness given per CVE on the command line (`--aware-since CVE-…=<instant>`): a vendor corrects a
  recorded moment by editing the file.
- Removing the entry of a CVE no longer actively exploited: it keeps its moment should the CVE come back.
- Reading the moments back from the drafts of `--drafts`, which a person completes and may move.
- Locking the file against two runs writing it at once: the last rename wins, each file whole.
- A moment of the measure (`--measure-available`) per CVE.
