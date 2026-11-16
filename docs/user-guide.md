# User guide

`forewarn` reads a CycloneDX SBOM and answers three questions a vendor faces under the EU Cyber Resilience Act:

1. **Is my SBOM good enough?** `forewarn check` lists the components missing a supplier, a license or a hash.
2. **Am I affected, and is it actively exploited?** `forewarn match` matches the components against OSV and flags those
   the CISA KEV catalog or ENISA's EUVD know to be exploited.
3. **When must I report, and what?** For each actively exploited vulnerability, `forewarn match` gives the article
   14(2) deadlines and can write a draft early warning to fill in.

- [Install](#install)
- [Check an SBOM](#check-an-sbom)
- [Match against vulnerabilities](#match-against-vulnerabilities)
- [Reporting deadlines](#reporting-deadlines)
- [Draft early warnings](#draft-early-warnings)
- [In CI](#in-ci)
- [What leaves your machine](#what-leaves-your-machine)
- [Reference](#reference): options, JSON reports, exit codes

## Install

Not published yet; build it from a clone (Rust stable):

```sh
cargo install --path crates/forewarn
```

`forewarn` does not detect dependencies: produce the SBOM with your usual tool, in CycloneDX JSON.

| Ecosystem | Example |
|---|---|
| Rust | `cargo cyclonedx --format json` |
| Any (containers, directories) | `syft scan . -o cyclonedx-json > sbom.cdx.json` |
| Many languages | `cdxgen -o sbom.cdx.json` |

CycloneDX 1.6 and 1.7 are accepted; 1.3 to 1.5 are read but flagged (below the BSI TR-03183-2 minimum); 1.0 to 1.2
are refused. Every command reads standard input when given `-`.

## Check an SBOM

```console
$ forewarn check sbom.cdx.json
SBOM: CycloneDX 1.6
2 of 2 components incomplete:
  log4j-core 2.14.1 (pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1): missing hash
  time 0.1.43 (pkg:cargo/time@0.1.43): missing supplier, license, hash
```

What is checked:

- every component, those nested under the product included (`cdxgen` nests the modules of a Maven project there);
- not the product's own targets (the binary target `cargo-cyclonedx` nests there);
- not the file components, the manifests a tool read (`/Cargo.lock`, `/pom.xml` in a `syft` SBOM): they are listed
  apart, outside the counts and the exit code.

It exits with 1 when a component is incomplete. To report the gaps without failing a job, add `--allow-incomplete`.

## Match against vulnerabilities

```console
$ forewarn match sbom.cdx.json
SBOM: CycloneDX 1.6, 2 components
OSV records:
  Maven: 5321 records, downloaded 2026-11-14T08:00:00Z from https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip
  crates.io: 1712 records, downloaded 2026-11-14T08:00:00Z from https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip
Exploited lists:
  CISA KEV: catalog 2026.11.10 released 2026-11-10, 1484 entries, downloaded 2026-11-14T08:00:00Z from https://www.cisa.gov/…
  EUVD: 1702 entries, downloaded 2026-11-14T08:00:00Z from https://euvdservices.enisa.europa.eu/api/search
Reporting deadlines (CRA article 14(2)): aware since 2026-11-14T08:00:00Z (the moment of the run), no corrective measure given, checked at 2026-11-14T08:00:00Z (the moment of the run)
Affected (2, 1 actively exploited):
  log4j-core 2.14.1 (pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1): CVE-2021-44228 (GHSA-jfh8-c2jp-5v3q), affected per GHSA-jfh8-c2jp-5v3q from GHSA
    actively exploited: CISA KEV CVE-2021-44228 added 2021-12-10; EUVD CVE-2021-44228 added 2021-12-10
    report by: early warning 2026-11-15T08:00:00Z (1d 0h 0m 0s left), notification 2026-11-17T08:00:00Z (3d 0h 0m 0s left), final report 14 days after a corrective measure is available
  time 0.1.43 (pkg:cargo/time@0.1.43): CVE-2020-26235 (GHSA-wcg3-cvx6-7396, RUSTSEC-2020-0071), affected per RUSTSEC-2020-0071 from RUSTSEC
Not evaluated (0):
Clean: 0 of 2 components
```

(Counts and moments are illustrative; the text layout may change, scripts read `--format json`.)

### How components are matched

- By package URL and version, each ecosystem's versions in their own ordering (SemVer, PEP 440, Maven, RubyGems,
  NuGet, Composer).
- One line per vulnerability: the records of one vulnerability that name each other (a `RUSTSEC` advisory and its
  `GHSA` mirror) are grouped, under its CVE when it has one; two CVEs are never merged. Each record is listed with
  what it says: `affected per`, `not affected per`, `not evaluated per`.
- **Not evaluated**, listed apart with the reason: your own code (the product, and the components of the type and
  namespace of its package URL: never matched, never sent out), a component without package URL or version, a version
  its ecosystem cannot read (a Composer `dev-` branch), a record whose only ranges are `GIT` ranges.

### Where the vulnerabilities come from

| Source | Option | What leaves the machine |
|---|---|---|
| OSV ecosystem archives, cached (default) | none; `--osv-url` for a mirror | the ecosystem names |
| Local OSV records (a file or an extracted archive) | `--osv <path>`, repeatable | nothing |
| OSV API | `--osv-api`; `--osv-api-url` for another | ecosystem, name and version of each component |

The default downloads `<ecosystem>/all.zip` for each ecosystem of the SBOM. The API answer depends on the moment of
the query, which the report gives; it is never on by default.

### Actively exploited

A match is flagged **actively exploited** when one of these lists names its CVE, with the list and its date as
evidence:

| List | Default | Read a file instead | Skip it | Mirror |
|---|---|---|---|---|
| CISA Known Exploited Vulnerabilities | downloaded into the cache | `--kev known_exploited_vulnerabilities.json` | `--no-kev` | `--kev-url` |
| ENISA EUVD, exploited records | paged from the EUVD search into the cache (about 18 requests) | `--euvd exploited.json` (`{"items": [...]}`) | `--no-euvd` | `--euvd-url` |

The report gives each list's version or size and when it was downloaded. Neither request names a component.

### Matches your VEX says do not affect you

Once you have analysed a match (the vulnerable code is never called, say), record it in CycloneDX VEX: in the
`vulnerabilities` of the SBOM, or in a VEX document of your own given with `--vex vex.json` (repeat it for several).

```json
{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "vulnerabilities": [{
  "id": "CVE-2021-44228",
  "analysis": {"state": "not_affected", "justification": "code_not_reachable", "detail": "JndiLookup is removed."},
  "affects": [{"ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]
}]}
```

| | |
|---|---|
| The vulnerability | its `id` or the `id` of one of its `references`, matched against the id and aliases of a match (a CVE in any case) |
| The component | `affects[].ref`: its `bom-ref`, a BOM-Link (`urn:cdx:<serial>/<version>#<bom-ref>`, whatever the serial), or its package URL as written when no component has that `bom-ref` (the `bom-ref`s of `syft` are opaque) |
| Set aside | `not_affected`, `false_positive`, `resolved`, `resolved_with_pedigree`, when every verdict naming the match says so |
| Kept | `exploitable`, `in_triage`, any other state |

A match set aside is listed under **Set aside by a VEX verdict**, with the verdict, where it was read, and the lists
naming it as actively exploited: it never disappears silently. It counts for neither exit code 1 nor 6, gets no
deadline and no draft. A verdict that names no match (a mistyped `bom-ref` or id) is listed under **Unused VEX
verdicts**. A `--vex` file that cannot be read stops the run with exit code 3.

### The cache

| | |
|---|---|
| Location | `$XDG_CACHE_HOME/forewarn/osv`, else `~/.cache/forewarn/osv`; `--cache <dir>` for another |
| Contents | one directory per OSV ecosystem, `cisa-kev`, `euvd-exploited` |
| Refresh | `--refresh 1d` by default; `offline` (never download), `if-missing`, `always`, or an age (`30m`, `12h`, `7d`) |
| Shared by several runs | yes: readers share it, a download waits for them and they for it, up to 40 minutes per entry |
| A copy damaged outside `forewarn` | downloaded again; under `--refresh offline`, the run fails with "damaged cached copy" |

For an air-gapped CI, fill the cache on a connected machine and copy it, then run with `--refresh offline`; or give
every source as a file (`--osv`, `--kev`, `--euvd`).

## Reporting deadlines

CRA article 14(2) requires, for an actively exploited vulnerability:

| Report | Due | From |
|---|---|---|
| Early warning | 24 hours | the moment you became aware: `--aware-since <instant>`, by default the moment of the run |
| Vulnerability notification | 72 hours | the same moment |
| Final report | 14 days | the moment a corrective or mitigating measure became available: `--measure-available <instant>`; without it, "14 days after a measure is available" |

```sh
forewarn match --aware-since 2026-11-13T09:30:00Z --measure-available 2026-11-15T12:00:00Z sbom.cdx.json
```

- Instants are RFC 3339; an offset is converted to UTC (`2026-11-13T10:30:00+01:00` is `09:30:00Z`).
- One moment of awareness applies to every match of the run.
- The human report shows the time left before each deadline (`23h 30m 0s left`, `due now`) or how long it is overdue
  (`overdue by 1d 0h 30m 0s`), at `--now <instant>`, by default the moment of the run. The JSON report gives the
  deadlines and leaves that comparison to its reader.
- The deadlines are 24 h, 72 h and 14 × 24 h from the moment itself, never later than the periods Regulation 1182/71
  computes (which start at the next hour or day and move to the next working day): reporting by them is never late.

## Draft early warnings

```sh
forewarn match --aware-since 2026-11-13T09:30:00Z --drafts drafts/ sbom.cdx.json
```

writes one Markdown file per actively exploited CVE, `drafts/<product>-<CVE>.md` (`<CVE>.md` when the SBOM names no
product), and names them in the report. The fields follow the ENISA Single Reporting Platform glossary 1.6, numbered and
named as it does:

```markdown
# Draft CRA early warning: CVE\-2021\-44228

To complete before entering it into the ENISA Single Reporting Platform: 2. Title, 3. Summary, 5. Member States where product available.

## Reporting deadlines (CRA article 14(2))

- Aware since: 2026-11-13T09:30:00Z
- Early warning due by: 2026-11-14T09:30:00Z
- Notification due by: 2026-11-16T09:30:00Z
- Final report due: 14 days after a corrective or mitigating measure is available

## Evidence of active exploitation

- CISA KEV: CVE\-2021\-44228, added 2021-12-10

## Fields of the early warning (ENISA CRA SRP glossary 1.6)

- **2. Title**: **TO COMPLETE**
- **3. Summary**: **TO COMPLETE**
- **4. Manufacturer name**: not in the SBOM (filled by the platform from your registration)
- **5. Member States where product available**: **TO COMPLETE**
- **6. Product Name**: acme\-gateway
- **7. Product Version**: 3\.2\.0
- **12. Component name**:
  - log4j\-core 2\.14\.1, pkg\:maven\/org\.apache\.logging\.log4j\/log4j\-core\@2\.14\.1, match CVE\-2021\-44228
- **v19. CVE ID**: CVE\-2021\-44228
- **v20. EUVD ID**: none known
- **v22. Date the corrective or mitigating measure became available**: none given
- **v26. Date and time aware of the AEV**: 2026-11-13T09:30:00Z
```

- Filled from the SBOM, the match and the moments: product, manufacturer (`metadata.component.manufacturer`, else the
  deprecated `metadata.manufacture`), version,
  components, CVE, EUVD id, evidence, deadlines.
- Marked `**TO COMPLETE**`: what only you know (title, summary, Member States).
- Values from the SBOM and the feeds are escaped, so they render as written and cannot inject Markdown or HTML.
- A rerun replaces a draft whole; drafts of a CVE no longer exploited stay in the directory.

A draft is a starting point: you submit the early warning yourself, on the ENISA Single Reporting Platform.

## In CI

The exit codes let a job fail on what matters:

```sh
# Fail only on an actively exploited vulnerability; keep the report and the drafts as artifacts.
forewarn match --allow-affected --format json --drafts drafts/ sbom.cdx.json > forewarn.json

# Report SBOM gaps without failing.
forewarn check --allow-incomplete sbom.cdx.json

# Generate and check in one pipe.
syft scan . -o cyclonedx-json | forewarn match --allow-affected -
```

With `--allow-affected`, a job exits with 0 when components are affected but none is actively exploited, and with 6
when one is. Keep the cache between jobs (a CI cache keyed on the day, for example) to download the feeds once a day.

## What leaves your machine

| Run | Sent out |
|---|---|
| `forewarn check` | nothing |
| `forewarn match` (default) | the names of the ecosystems of the SBOM (OSV archives); requests for the KEV catalog and the EUVD list, naming no component |
| `forewarn match --osv … --kev … --euvd …` or `--refresh offline` | nothing |
| `forewarn match --osv-api` | the ecosystem, name and version of each component, except your own code |

Never source code. Your own components (first-party) are never matched nor sent.

## Reference

`forewarn <command> --help` describes every option.

### `forewarn check` JSON report

```json
{
  "specVersion": "1.6",
  "belowBsiMinimum": false,
  "componentCount": 2,
  "complete": false,
  "incomplete": [{"name": "time", "version": "0.1.43", "purl": "pkg:cargo/time@0.1.43", "missing": ["supplier", "license", "hash"]}],
  "notChecked": [{"name": "/Cargo.lock", "version": null, "purl": null, "reason": "file"}]
}
```

### `forewarn match` JSON report

| Key | Holds |
|---|---|
| `specVersion`, `componentCount`, `cleanCount`, `exploitedCount` | the SBOM and the counts |
| `osv` | each source of records: `kind` (`archive`, `api`, `local`), `recordCount`, and when it was downloaded or queried, or its path |
| `exploitedLists` | each list used: `name`, `kind` (`fetched`, `local`), `entryCount`, the catalog's `version` and `released`, and `downloadedAt` or `path` |
| `awareSince`, `measureAvailable` | the moments of the deadlines, `null` when nothing is actively exploited |
| `affected` | each match: `name`, `version`, `purl`, `id` (the CVE when there is one), `aliases`, `records` (`id`, `source`, `affects`), `exploited` (`list`, `cve`, `dateAdded`), `deadlines` (`earlyWarning`, `notification`, `finalReport`) or `null` |
| `notEvaluated` | each component not evaluated, with its reason (`first-party`, `no package URL`, `invalid package URL`, `unknown ecosystem`, `no version`, `range not evaluated`, `invalid version`) |
| `drafts` | each draft written: `cve`, `path` |
| `vex` | each source of verdicts: `kind` (`sbom`, `file`), `verdictCount`, and the `path` of a file |
| `setAsideCount`, `setAside` | each match a VEX verdict set aside, as in `affected` without `deadlines`, with its `verdict` (`state`, `justification`, `detail`, `source`: `sbom` or the path) |
| `unusedVerdicts` | each verdict that names no match: `ids`, `targets`, `source` |

### Exit codes

| Code | `check` | `match` |
|---|---|---|
| 0 | the SBOM is complete (or `--allow-incomplete`) | nothing affected (or `--allow-affected` and nothing actively exploited) |
| 1 | a component is incomplete | a component is affected, a match set aside by VEX not counted |
| 2 | invalid arguments | invalid arguments, an instant refused |
| 3 | the SBOM cannot be read | the SBOM or a `--vex` file cannot be read |
| 4 | the report cannot be written | the report cannot be written |
| 5 | | the OSV records, the KEV catalog or the EUVD list cannot be read, fetched or queried |
| 6 | | a match is actively exploited, even with `--allow-affected` |
| 7 | | a draft cannot be written; nothing is printed on standard output |
