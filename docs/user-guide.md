# User guide

`forewarn` reads a CycloneDX SBOM and answers three questions a vendor faces under the EU Cyber Resilience Act:

1. **Is my SBOM good enough?** `forewarn check` lists the components missing a supplier, a license or a hash.
2. **Am I affected, and is it actively exploited?** `forewarn match` matches the components against OSV and flags those
   the CISA KEV catalog or ENISA's EUVD know to be exploited.
3. **When must I report, and what?** For each actively exploited vulnerability, `forewarn match` gives the article
   14(2) deadlines and can write a draft early warning to fill in.

`forewarn upload` keeps the inventory of a Forewarn service up to date: it sends the SBOM of each release there.

- [Install](#install)
- [Check an SBOM](#check-an-sbom)
- [Match against vulnerabilities](#match-against-vulnerabilities)
- [Reporting deadlines](#reporting-deadlines)
- [Draft early warnings](#draft-early-warnings)
- [Upload to a Forewarn service](#upload-to-a-forewarn-service)
- [In CI](#in-ci)
- [What leaves your machine](#what-leaves-your-machine)
- [Reference](#reference): options, JSON reports, exit codes

## Install

From 0.3.0, each release on [GitHub](https://github.com/Electron-libre/forewarn-cli/releases) holds a binary per
platform, in `forewarn-<target>.tar.gz`, the CycloneDX SBOM of each binary, `forewarn-<target>.cdx.json`, and a
`SHA256SUMS` file over them:

| Target | Platform |
|---|---|
| `x86_64-unknown-linux-musl` | Linux x86_64, static (any distribution, Alpine included) |
| `aarch64-unknown-linux-musl` | Linux ARM64, static |
| `aarch64-apple-darwin` | macOS, Apple silicon |
| `x86_64-apple-darwin` | macOS, Intel |

Download the archive of your platform, check it and install the binary:

```sh
target=x86_64-unknown-linux-musl
base=https://github.com/Electron-libre/forewarn-cli/releases/latest/download
curl -fsSL -O "$base/forewarn-$target.tar.gz" -O "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS      # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
tar -xzf "forewarn-$target.tar.gz"
sudo install "forewarn-$target/forewarn" /usr/local/bin/
```

The archive also holds the licenses of `forewarn`, the notices of the crates its binary includes
(`THIRD-PARTY-LICENSES`) and its SBOM (`forewarn.cdx.json`). GitHub attests where each file was built:
`gh attestation verify "forewarn-$target.tar.gz" --repo Electron-libre/forewarn-cli` checks it was built by the
release workflow of this repository.

The SBOM is complete for `forewarn check`: each crates.io crate has crates.io as supplier and the hash crates.io
serves; `forewarn` and each `forewarn-*` crate, built from source, have `Electron-libre` as manufacturer or supplier
and the SHA-256 of their source tree at the tag, which you recompute from a clone (Git 2.42 or later):

```sh
git -c tar.umask=0022 -c core.autocrlf=false archive --format=tar --mtime='1970-01-01 00:00:00 +0000' \
  v<version>:crates/forewarn-domain | sha256sum
```

A CI job pins a version with `base=https://github.com/Electron-libre/forewarn-cli/releases/download/v<version>`.
No Windows binary yet; on another platform, build it from a clone (Rust stable): `cargo install --path crates/forewarn`.

`forewarn --version` prints the release it was built from; give it when you report a bug.

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

The human reports and the error lines of both commands print a control character, a character that hides text and a
backslash escaped (`\n`, `\u{202e}`, `\\`), so that a value cannot forge a line. A path keeps its backslashes on
Windows, where they separate its parts: `C:\sboms\shop.json` prints as written.

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
- A rerun replaces a draft whole. A draft of the same product it no longer writes (the CVE set aside by a VEX
  verdict, no longer exploited, or the component upgraded) is left in place, since you may have completed it, and the
  report lists it under `Stale draft early warnings` (`staleDrafts` in JSON): remove it yourself before publishing the
  directory. A directory of `--drafts` that exists but cannot be listed exits with 7 and writes no draft.

A draft is a starting point: you submit the early warning yourself, on the ENISA Single Reporting Platform.

## Upload to a Forewarn service

```console
$ export FOREWARN_TOKEN=<token of the service>
$ forewarn upload --endpoint https://forewarn.example.com sbom.cdx.json
Uploaded acme-gateway 2.4.0 to https://forewarn.example.com
Stored: a new version, 42 components (CycloneDX 1.6), received at 2026-11-19T10:00:00Z
```

- **The endpoint**: `--endpoint`, else the environment variable `FOREWARN_ENDPOINT`; HTTPS, or plain HTTP to a
  loopback host (`localhost`, an address of `127.0.0.0/8`, `[::1]`) only, without credentials, a query or a fragment.
- **The token**: the environment variable `FOREWARN_TOKEN` only, never an option, so that it shows in no process list
  nor shell history; no output prints it.
- **The product and the version**: those of the SBOM's `metadata.component`; `--product` and `--product-version`
  override each. When the SBOM lacks one and its option is not given, the run stops, naming the option.
- **The SBOM**: read first, as `check` reads it (a CycloneDX 1.2 file is refused, nothing sent), then sent as is, up
  to 10 MiB. Uploading a version again replaces its SBOM: the report says `replaced the SBOM of a known version`.
  The service dates the upload with its own clock; the report prints when it received it, and its warnings (a spec
  version below 1.6, for example).

`--dry-run` prints what would be sent and sends nothing; it needs no token, so a job can check its setup first:

```console
$ forewarn upload --dry-run --endpoint https://forewarn.example.com sbom.cdx.json
Would upload acme-gateway 2.4.0 to https://forewarn.example.com: an SBOM of 18342 bytes; nothing sent (--dry-run)
```

It refuses what an upload would refuse before sending (exit codes 2, 3 and 10).

A request is sent once, never retried, and no redirect is followed; each failure has its exit code (8 to 11, see
[Exit codes](#exit-codes)): a `503` names the code `unavailable`, after which a rerun is safe. The request asks
`Expect: 100-continue` and sends the SBOM once the service agrees, or after 1 s without an answer, so a token the
service refuses within that second, before reading the SBOM, exits with 9, not 8; a proxy that agrees in the place
of the service lets the SBOM go, and a refusal while it is sent exits with 8. A `417 Expectation Failed` (an
intermediary that refuses the expectation) is the only answer after which the request is sent again, without it.

## In CI

[`examples/ci/github-actions.yml`](../examples/ci/github-actions.yml) is a GitHub Actions workflow to copy into
`.github/workflows/` of your product, each step commented. On each tag `v*`, and each day on the latest tag `v*`, it
installs a pinned release checked against its `SHA256SUMS`, produces the SBOM with `syft` (named after the repository
and the tag), keeps the cache of the feeds between runs, reports the gaps of the SBOM without failing, and runs
`forewarn match --allow-affected --refresh 12h`:

| `forewarn match` exits with | The job |
|---|---|
| 0: nothing affected, or affected but none actively exploited | passes; the report is an artifact |
| 6: a match is actively exploited | fails; the report and the draft early warnings are artifacts |
| 2 to 5, 7: an error (the arguments, the SBOM, a source, the report or a draft) | fails |

On a tag, it then uploads the SBOM whatever the match found (secrets `FOREWARN_ENDPOINT` and `FOREWARN_TOKEN`; remove
the step without a service). The daily run matters: a dependency becomes actively exploited without a change of your
code, and the 24 h deadline runs from the moment you know it. Each run counts the deadlines from itself: keep the drafts
of the first run that fails, the moment you knew. `syft` names your product without a package URL, so your own packages
are matched as third-party ones; the SBOM tool of your ecosystem (`cargo cyclonedx`, `cdxgen`) avoids it.

The exit codes let a job fail on what matters:

```sh
# Fail only on an actively exploited vulnerability; keep the report and the drafts as artifacts.
forewarn match --allow-affected --format json --drafts drafts/ sbom.cdx.json > forewarn.json

# Report SBOM gaps without failing.
forewarn check --allow-incomplete sbom.cdx.json

# Generate and check in one pipe.
syft scan . -o cyclonedx-json | forewarn match --allow-affected -

# At each release, keep the inventory of a Forewarn service up to date (FOREWARN_ENDPOINT and FOREWARN_TOKEN set as
# secrets of the job).
forewarn upload sbom.cdx.json
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
| `forewarn upload --dry-run` | nothing |
| `forewarn upload` | the SBOM itself, as given, with the product name, the version and the token, to the endpoint only |

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
| `staleDrafts` | each draft of the product left from an earlier run that this run no longer writes: `cve`, `path` |
| `vex` | each source of verdicts: `kind` (`sbom`, `file`), `verdictCount`, and the `path` of a file |
| `setAsideCount`, `setAside` | each match a VEX verdict set aside, as in `affected` without `deadlines`, with its `verdict` (`state`, `justification`, `detail`, `source`: `sbom` or the path) |
| `unusedVerdicts` | each verdict that names no match: `ids`, `targets`, `source` |

### Exit codes

| Code | `check` | `match` | `upload` |
|---|---|---|---|
| 0 | the SBOM is complete (or `--allow-incomplete`) | nothing affected (or `--allow-affected` and nothing actively exploited) | the SBOM is stored, or `--dry-run` |
| 1 | a component is incomplete | a component is affected, a match set aside by VEX not counted | |
| 2 | invalid arguments | invalid arguments, an instant refused | invalid arguments, no endpoint or one refused, no `FOREWARN_TOKEN` or one refused (without `--dry-run`), no product name or version |
| 3 | the SBOM cannot be read | the SBOM or a `--vex` file cannot be read | the SBOM cannot be read |
| 4 | the report cannot be written | the report cannot be written | the report cannot be written |
| 5 | | the OSV records, the KEV catalog or the EUVD list cannot be read, fetched or queried | |
| 6 | | a match is actively exploited, even with `--allow-affected` | |
| 7 | | a draft cannot be written, or the directory of the drafts listed; nothing is printed on standard output | |
| 8 | | | the endpoint cannot be reached |
| 9 | | | the service refused the credentials (`401`, `403`) |
| 10 | | | the upload is refused: by the service, or before anything is sent (a name the service would refuse, an SBOM over 10 MiB) |
| 11 | | | the answer of the service cannot be read |
