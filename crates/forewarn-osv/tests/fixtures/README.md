# OSV record fixtures

Real OSV records, read by `../reading.rs`, served in archives by `../fetching.rs` and `../release_archive.rs`, and read
whole with `--osv` by the CLI tests (`crates/forewarn/tests/matching.rs` counts them), kept as the source served them
(compact JSON, one line). Fetched on 2026-11-12; refetch them only on purpose: the tests assert their content.

| File | What it shows | Fetched from |
|---|---|---|
| `RUSTSEC-2020-0071.json` | a crates.io advisory with a CVE alias | `https://api.osv.dev/v1/vulns/RUSTSEC-2020-0071` |
| `GHSA-35jh-r3h4-6jhm.json` | an npm advisory with a CVE alias, `last_affected` events and `versions` (a RubyGems package) | `https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm` |
| `GHSA-286m-6pg9-v42v.json` | a withdrawn record | the crates.io archive, `https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip` |
| `GHSA-2226-4v3c-cff8.json` | a crates.io record with a `last_affected` event | the same archive |
| `DEBIAN-CVE-2024-6387.json` | a Debian advisory naming its CVE in `upstream`, under `Debian:12`, `Debian:13` and `Debian:14` (fetched 2026-11-19) | `https://api.osv.dev/v1/vulns/DEBIAN-CVE-2024-6387` |
