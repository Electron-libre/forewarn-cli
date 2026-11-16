//! The release binaries of ADR 0015: the targets `.github/workflows/release.yml` builds are the ones the Install
//! section of `docs/user-guide.md` offers, so the guide never names an archive no release holds.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The `target` of each entry of the build matrix: the lines `- target: <triple>`.
fn workflow_targets(workflow: &str) -> BTreeSet<String> {
    workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- target:"))
        .map(|target| target.trim().to_owned())
        .collect()
}

/// The first cell of each row of the tables of the Install section, a target written as code: `` | `<triple>` | ``.
fn guide_targets(guide: &str) -> BTreeSet<String> {
    guide
        .lines()
        .skip_while(|line| *line != "## Install")
        .skip(1)
        .take_while(|line| !line.starts_with("## "))
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|row| row.split_once('`'))
        .map(|(target, _)| target.to_owned())
        .filter(|target| target.matches('-').count() >= 2)
        .collect()
}

#[test]
fn the_user_guide_lists_the_targets_the_release_workflow_builds() {
    let built = workflow_targets(&read(".github/workflows/release.yml"));
    let listed = guide_targets(&read("docs/user-guide.md"));

    assert!(!built.is_empty(), "the release workflow builds no target");
    assert_eq!(listed, built);
}
