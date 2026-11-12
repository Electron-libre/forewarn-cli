# SBOM fixtures of existing tools

The SBOMs of the small project in `sample/`, generated on 2026-11-12 by the tools that `rollcall` users run, and read by
`../real_tools.rs`. They are kept as the tools wrote them, saved as compact JSON (one line). Regenerate them only on
purpose: the tests assert their exact components.

| File | Tool | Spec version | Command, from `sample/` |
|---|---|---|---|
| `cargo-cyclonedx.cdx.json` | `cargo-cyclonedx` 0.5.10 | 1.6 | `cargo cyclonedx --format json --spec-version 1.6 --override-filename bom`, then `bom.json` compacted |
| `syft.cdx.json` | `syft` 1.57.1 | 1.6 | `docker run --rm -v "$PWD":/src:ro anchore/syft:v1.57.1 scan dir:/src --source-name rollcall-fixture-sample --source-version 0.1.0 -o cyclonedx-json@1.6` |
| `cdxgen.cdx.json` | `cdxgen` 13.2.0 | 1.7 | `docker run --rm -v "$PWD":/app:ro --entrypoint sh ghcr.io/cyclonedx/cdxgen:13.2.0 -c 'cdxgen -t rust -r /app -o /tmp/bom.json --spec-version 1.7 >/dev/null && cat /tmp/bom.json'` |

`sample/` is its own Cargo workspace root, outside the `rollcall` workspace; it is never built.
