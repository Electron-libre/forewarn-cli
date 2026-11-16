//! The version of the binary is the one of the last release: `cardinal run release <version>` writes the
//! `CHANGELOG.md` section and, through the `release_version_command` of `.claude/cardinal.toml` (`just set-version`),
//! the `[workspace.package] version` every crate inherits, which `forewarn --version` prints.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn workspace_version() -> String {
    let path = workspace_root().join("Cargo.toml");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let manifest: toml::Table = text
        .parse()
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    manifest["workspace"]["package"]["version"]
        .as_str()
        .expect("[workspace.package] version is a string")
        .to_owned()
}

/// The version of the first `## [X.Y.Z]` heading of `CHANGELOG.md`, the newest release.
fn newest_changelog_version() -> Option<String> {
    let path = workspace_root().join("CHANGELOG.md");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("## [")?;
        let (version, _) = rest.split_once(']')?;
        Some(version.to_owned())
    })
}

#[test]
fn the_workspace_version_is_the_newest_release_of_the_changelog() {
    assert_eq!(
        Some(workspace_version()),
        newest_changelog_version(),
        "[workspace.package] version differs from the newest section of CHANGELOG.md: run \
         `just set-version <version>` (the release_version_command of `cardinal run release`)"
    );
}

#[test]
fn the_binary_prints_the_workspace_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_forewarn"))
        .arg("--version")
        .output()
        .expect("forewarn runs");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("forewarn {}\n", workspace_version())
    );
}
