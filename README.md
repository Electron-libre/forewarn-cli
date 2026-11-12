# rollcall

An open-source CLI that checks a CycloneDX SBOM against actively exploited vulnerabilities and drafts the reports the
EU Cyber Resilience Act (article 14) requires.

Work in progress: nothing to install yet.

## Usage

```sh
rollcall check sbom.cdx.json                  # or `-` to read the SBOM from standard input
rollcall check --format json sbom.cdx.json    # one JSON document, for a CI job or a script
```

`rollcall check` prints the CycloneDX spec version of the SBOM, flagged when it is below 1.6 (the BSI TR-03183-2
minimum), and each component missing a supplier, a license or a hash. The JSON report holds `specVersion`,
`belowBsiMinimum`, `componentCount`, `complete` and `incomplete` (each component's `name`, `version`, `purl` and
`missing` fields); the text report's layout may change, scripts read the JSON one. It exits with:

| Code | Meaning |
|---|---|
| 0 | the SBOM is complete |
| 1 | at least one component is incomplete |
| 2 | invalid arguments |
| 3 | the SBOM cannot be read |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
