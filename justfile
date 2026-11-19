# Development commands. `just` lists them; the agent harness uses the same entry points.
import 'cardinal.just'

default:
    @just --list

# Format, lint and test the project, then check the specs (when the feature `specs` is on): the `check_command` of
# `.claude/cardinal.toml`, quiet on success, since the agent reads all of its output.
check:
    @cardinal run project-check

# Write `version` into `[workspace.package]`, which every crate inherits, into `Cargo.lock` and into the
# `FOREWARN_VERSION` the CI templates of `examples/ci` pin: the `release_version_command` that
# `cardinal run release <version>` runs after writing the changelog.
set-version version:
    @printf '%s\n' '{{version}}' | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || { echo 'set-version: {{version}} is not X.Y.Z' >&2; exit 1; }
    sed -i.bak '/^\[workspace\.package\]/,/^\[/s/^version = ".*"/version = "{{version}}"/' Cargo.toml && rm Cargo.toml.bak
    @sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml | grep -qx 'version = "{{version}}"' || { echo 'set-version: [workspace.package] version not written' >&2; exit 1; }
    for template in examples/ci/*.yml; do sed -i.bak 's/^\( *FOREWARN_VERSION: \).*/\1{{version}}/' "$template" && rm "$template.bak"; done
    @for template in examples/ci/*.yml; do [ "$(grep -c '^ *FOREWARN_VERSION: ' "$template")" = 1 ] && grep -qx ' *FOREWARN_VERSION: {{version}}' "$template" || { echo "set-version: $template: no single FOREWARN_VERSION written" >&2; exit 1; }; done
    cargo update --workspace --offline -q
