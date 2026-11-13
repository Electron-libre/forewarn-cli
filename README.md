# forewarn

An open-source CLI that checks a CycloneDX SBOM against actively exploited vulnerabilities and drafts the reports the
EU Cyber Resilience Act (article 14) requires.

Work in progress, not published yet: build it from a clone with `cargo install --path crates/forewarn`.

## Usage

```sh
forewarn check sbom.cdx.json                  # `-` reads the SBOM from standard input (`./-` for a file named -)
forewarn check --format json sbom.cdx.json    # one JSON document, for a CI job or a script
syft scan . -o cyclonedx-json | forewarn check --allow-incomplete -   # report gaps without failing the job
```

`forewarn check` prints the CycloneDX spec version of the SBOM, flagged when it is below 1.6 (the BSI TR-03183-2
minimum), and each component missing a supplier, a license or a hash. The JSON report holds `specVersion`,
`belowBsiMinimum`, `componentCount`, `complete` and `incomplete` (each component's `name`, `version`, `purl` and
`missing` fields); the text report's layout may change, scripts read the JSON one. It exits with:

| Code | Meaning |
|---|---|
| 0 | the SBOM is complete |
| 1 | at least one component is incomplete, unless `--allow-incomplete` is given |
| 2 | invalid arguments |
| 3 | the SBOM cannot be read |
| 4 | the report cannot be written to standard output |

```sh
forewarn match sbom.cdx.json                      # fetch the OSV archive of each ecosystem of the SBOM into a cache
forewarn match --refresh offline sbom.cdx.json    # an air-gapped CI: the cache only, no request
forewarn match --osv osv-records/ sbom.cdx.json   # an OSV record file or an extracted OSV archive; repeat --osv
forewarn match --osv-api sbom.cdx.json            # opt-in: query the OSV API, sending the packages of the SBOM out
forewarn match --kev kev.json sbom.cdx.json       # a CISA KEV catalog file instead of fetching the catalog
forewarn match --euvd euvd.json sbom.cdx.json     # an EUVD exploited list file instead of paging the list
```

`forewarn match` prints the components affected by a known OSV vulnerability, once per vulnerability even when several
records hold it (a `RUSTSEC` advisory and its `GHSA` mirror), two CVEs never merged: its id (its CVE, in upper case, when it has
one), its aliases and each record with its source, marked when it does not affect the version or was not evaluated,
apart from the components it could not evaluate (no package URL, no version, a version its ecosystem does
not read, such as a Composer `dev-` branch, a record whose only ranges are `GIT` ranges), how many are clean, and how fresh the OSV data is; `--format json` works as for `check`. Only the
names of the ecosystems leave the CI: it downloads `<ecosystem>/all.zip` from the OSV bucket (`--osv-url` for a
mirror) into `$XDG_CACHE_HOME/forewarn/osv`, else `~/.cache/forewarn/osv` (`--cache` for another), again once a day
(`--refresh`: `offline`, `if-missing`, `always` or an age such as `12h`). Runs that share a cache on one machine read
it together; a run that downloads waits for the runs reading, and they for it, at most 40 minutes per ecosystem (runs
that keep reading can hold a `--refresh always` run back that long). `--osv-api` queries the OSV API instead
(`--osv-api-url` for another): no archive is downloaded, but the OSV ecosystem, name and version of each component leave the CI, and the
answer depends on the moment of the query, which the report gives; it is never on by default.

Each match whose CVE the CISA Known Exploited Vulnerabilities catalog names is marked actively exploited, with the
catalog and the date it added the CVE as evidence (`exploited` in the JSON report); the report gives the catalog's
version, release date and number of entries, and when it was downloaded. The catalog is downloaded from CISA
(`--kev-url` for a mirror) into the directory `cisa-kev` of the same cache, under the same `--refresh` policy, also
with `--osv` or `--osv-api`: the request names no component. `--kev <file>` reads a downloaded catalog
(`known_exploited_vulnerabilities.json`) instead, for an air-gapped CI; `--no-kev` flags nothing against it.

The vulnerabilities ENISA's European Vulnerability Database (EUVD) knows to be exploited flag the matches the same
way, after the catalog, an entry per CVE of each EUVD record dated by its `exploitedSince` (undated when
EUVD writes it in a form it does not know); the report gives their
number and when they were downloaded. EUVD publishes no single file: the list is paged from its search
(`exploited=true`, 100 records a page, about 18 requests; `--euvd-url` for a mirror) into the directory
`euvd-exploited` of the same cache, under the same `--refresh` policy: the requests name no component. `--euvd <file>`
reads a file of the shape `{"items": [...]}` instead (a copy of `euvd-exploited/exploited.json`), for an air-gapped
CI; `--no-euvd` flags nothing against it. With `--no-kev` and `--no-euvd`, the report says that no list was used.

It exits with 6 when a match is actively exploited, even with `--allow-affected`, so that a CI job given
`--allow-affected` fails only on those; 1 when a component is affected; 5 when the OSV records, the KEV catalog or the EUVD
list cannot be read, fetched or queried; and otherwise as `check` does.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
