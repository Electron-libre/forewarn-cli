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
```

`forewarn match` prints the components affected by a known OSV vulnerability, once per vulnerability even when several
records hold it (a `RUSTSEC` advisory and its `GHSA` mirror), two CVEs never merged: its id (its CVE when it has
one), its aliases and each record with its source, marked when it does not affect the version or was not evaluated,
apart from the components it could not evaluate (no package URL, no version, an ecosystem
whose ranges are not compared yet), how many are clean, and how fresh the OSV data is; `--format json` and `--allow-affected` work as for `check`. Only the
names of the ecosystems leave the CI: it downloads `<ecosystem>/all.zip` from the OSV bucket (`--osv-url` for a
mirror) into `$XDG_CACHE_HOME/forewarn/osv`, else `~/.cache/forewarn/osv` (`--cache` for another), again once a day
(`--refresh`: `offline`, `if-missing`, `always` or an age such as `12h`). Two runs that share a cache on one machine
wait for each other, at most 40 minutes per ecosystem. It exits with 1 when a component is
affected, 5 when the OSV records cannot be read or fetched, and otherwise as `check` does.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
