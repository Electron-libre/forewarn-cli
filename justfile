# Development commands. `just` lists them; the agent harness uses the same entry points.
import 'cardinal.just'

default:
    @just --list

# Format, lint and test the project, then check the specs (when the feature `specs` is on): the `check_command` of
# `.claude/cardinal.toml`, quiet on success, since the agent reads all of its output.
check:
    @cardinal run project-check

# Write `version` into `[workspace.package]`, which every crate inherits, and into `Cargo.lock`: the
# `release_version_command` that `cardinal run release <version>` runs after writing the changelog.
set-version version:
    @printf '%s\n' '{{version}}' | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || { echo 'set-version: {{version}} is not X.Y.Z' >&2; exit 1; }
    sed -i.bak '/^\[workspace\.package\]/,/^\[/s/^version = ".*"/version = "{{version}}"/' Cargo.toml && rm Cargo.toml.bak
    @sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml | grep -qx 'version = "{{version}}"' || { echo 'set-version: [workspace.package] version not written' >&2; exit 1; }
    cargo update --workspace --offline -q
