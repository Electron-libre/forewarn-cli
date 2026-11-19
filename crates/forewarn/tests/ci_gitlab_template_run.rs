//! The GitLab CI template of `examples/ci/` run as a vendor's pipeline would run it: the `script` of each of its jobs,
//! with `sh` as the runner runs it in the `alpine` image (`errexit`, and `pipefail` when the shell has it), in the
//! directory of a product, against the binary of this commit, a fixture SBOM and local feeds, so a change of the CLI
//! or of the template that breaks the pipeline turns this test red. The `before_script` lists, which install the
//! tools, are replaced: the binary of this commit is put on `PATH` instead of a release, and a `syft` that writes a
//! fixture SBOM instead of the one it would scan; nothing is fetched.
#![cfg(unix)]

mod ci_template;
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use ci_template::{Sandbox, ci_fixture, fixture, indent, literal_block};
use common::{Run, run_command};

const TEMPLATE: &str = "examples/ci/gitlab-ci.yml";

/// The jobs whose `script` is run, as the template writes it but for the feeds of `forewarn match` and the dry run of
/// the upload.
const SBOM: &str = "forewarn-sbom";
const MATCH: &str = "forewarn-match";
const UPLOAD: &str = "forewarn-upload";

/// The jobs whose `before_script` is replaced: the installation of forewarn, shared through `extends`, and of `syft`.
const INSTALL_FOREWARN: &str = ".forewarn";
const INSTALL_SYFT: &str = SBOM;

/// The item of a `before_script` that goes back to the project once the tools are installed: the items before it
/// are the installation, replaced; those after it are run.
const IN_PROJECT: &str = r#"cd "$CI_PROJECT_DIR""#;

/// A job of the template, hidden (a name starting with `.`, a base other jobs extend) or not.
#[derive(Default)]
struct TemplateJob {
    /// Its keys (`stage`, `variables`, `script`…), with their value when it is written on the line of the key
    /// (`extends: .forewarn`, `needs: [forewarn-sbom]`), else empty.
    keys: BTreeMap<String, String>,
    /// The items of its lists (`rules`, `before_script`, `script`…), a literal block of a shell list dedented.
    lists: BTreeMap<String, Vec<String>>,
    /// The keys of its maps (`variables`, `cache`, `artifacts`), with their value.
    maps: BTreeMap<String, BTreeMap<String, String>>,
}

impl TemplateJob {
    fn extends(&self) -> Option<&str> {
        self.keys.get("extends").map(String::as_str)
    }

    fn list(&self, key: &str) -> &[String] {
        self.lists.get(key).map_or(&[], Vec::as_slice)
    }

    fn map(&self, key: &str, entry: &str) -> Option<&str> {
        self.maps.get(key)?.get(entry).map(String::as_str)
    }
}

/// An item of a list that starts at line `i` with `- <value>`: the value, or for a shell list a literal block (`|`)
/// dedented; `i` moves past it. The items are indented to `dash`.
fn list_item(lines: &[&str], i: &mut usize, dash: usize, shell: bool, value: &str) -> String {
    let value = value.trim();
    *i += 1;
    if !shell {
        return value.to_owned();
    }
    if value == "|" {
        return literal_block(lines, i, dash);
    }
    assert!(
        !value.starts_with(['|', '>', '\'', '"']),
        "{TEMPLATE}: a shell item `- {value}`, read here as plain or `|` only"
    );
    value.to_owned()
}

/// Each job of the template, by name: a key at the top level, its keys indented two spaces, the items of its lists
/// and the keys of its maps four.
fn jobs(template: &str) -> BTreeMap<String, TemplateJob> {
    let lines: Vec<&str> = template.lines().collect();
    let mut found: BTreeMap<String, TemplateJob> = BTreeMap::new();
    let mut job = String::new();
    let mut key = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let (name, value) = trimmed.split_once(':').unwrap_or((trimmed, ""));
        let value = value.trim();
        match indent(line) {
            0 => {
                name.clone_into(&mut job);
                found.entry(job.clone()).or_default();
            }
            2 => {
                let current = found.get_mut(&job).expect("a key belongs to a job");
                current.keys.insert(name.to_owned(), value.to_owned());
                name.clone_into(&mut key);
            }
            4 => {
                let current = found.get_mut(&job).expect("a key belongs to a job");
                if let Some(item) = trimmed.strip_prefix("- ") {
                    let shell = matches!(key.as_str(), "before_script" | "script" | "after_script");
                    let item = list_item(&lines, &mut i, 4, shell, item);
                    current.lists.entry(key.clone()).or_default().push(item);
                    continue;
                }
                assert!(
                    !value.is_empty() && !value.contains('#'),
                    "{TEMPLATE}: `{key}: {name}:` in `{job}`, read here as one plain value only: {line}"
                );
                current
                    .maps
                    .entry(key.clone())
                    .or_default()
                    .insert(name.to_owned(), value.trim_matches(['"', '\'']).to_owned());
            }
            _ => {}
        }
        i += 1;
    }
    found
}

/// A run of the pipeline: the variables of GitLab and the directory of the product, with a `syft` that writes the
/// fixture SBOM where it is asked to, and records its arguments.
struct Pipeline {
    sandbox: Sandbox,
    jobs: BTreeMap<String, TemplateJob>,
    sbom: PathBuf,
    syft_args: PathBuf,
}

impl Pipeline {
    /// A pipeline with `env`, the predefined variables of GitLab that differ between triggers, whose SBOM is the
    /// fixture `sbom`.
    fn new(env: &[(&'static str, &str)], sbom: &str) -> Self {
        let template = fs::read_to_string(fixture(TEMPLATE)).expect("the template is read");
        let sandbox = Sandbox::new(env);
        symlink(ci_fixture("syft"), sandbox.bin.join("syft")).expect("the stub of syft is linked");
        let syft_args = sandbox.scratch().join("syft-args");
        Self {
            sandbox,
            jobs: jobs(&template),
            sbom: ci_fixture(sbom),
            syft_args,
        }
    }

    fn template_job(&self, job: &str) -> &TemplateJob {
        self.jobs
            .get(job)
            .unwrap_or_else(|| panic!("{TEMPLATE} has no job `{job}`"))
    }

    /// The job that holds `key` for `job`: itself, else the nearest job it extends.
    fn holding(&self, job: &str, key: &str) -> Option<&TemplateJob> {
        let mut next = Some(job);
        while let Some(name) = next {
            let template_job = self.template_job(name);
            if template_job.keys.contains_key(key) {
                return Some(template_job);
            }
            next = template_job.extends();
        }
        None
    }

    /// The variables of a job and of the jobs it extends, its own first.
    fn variables(&self, job: &str) -> BTreeMap<String, String> {
        let mut variables = BTreeMap::new();
        let mut next = Some(job);
        while let Some(name) = next {
            let template_job = self.template_job(name);
            for (variable, value) in template_job.maps.get("variables").into_iter().flatten() {
                variables
                    .entry(variable.clone())
                    .or_insert_with(|| value.clone());
            }
            next = template_job.extends();
        }
        variables
    }

    /// Runs the `script` of a job, `rewrite` applied to it, as the runner runs it with `sh`: the items of its
    /// `before_script` once in the project (the installation replaced), then those of its `script`, one after the
    /// other in one shell that stops at the first that fails, with the variables of the job, of the pipeline and the
    /// CI/CD variables `cicd` only; expects its exit code. The host's `sh` runs them, not the `ash` of the image: the
    /// scripts use no pipe whose status `pipefail` would change.
    fn job(
        &self,
        job: &str,
        rewrite: impl Fn(&TemplateJob, &str) -> String,
        cicd: &[(&str, &str)],
        code: i32,
    ) -> Run {
        let before = self
            .holding(job, "before_script")
            .map_or(&[][..], |holder| holder.list("before_script"));
        let in_project = before
            .iter()
            .rposition(|item| item == IN_PROJECT)
            .map_or(before.len(), |at| at + 1);
        let template_job = self.template_job(job);
        let script = rewrite(
            template_job,
            &before[in_project..]
                .iter()
                .chain(template_job.list("script"))
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let script = format!(
            "if set -o | grep pipefail > /dev/null; then set -o pipefail; fi\nset -o errexit\n{script}\n"
        );
        let mut command = self.sandbox.command("sh");
        command
            .envs(self.variables(job))
            .env("CI_PROJECT_DIR", &self.sandbox.product)
            .env("CI_PROJECT_NAME", "acme-app")
            .env("CI_COMMIT_SHA", "0000000000000000000000000000000000000000")
            .env("SYFT_STUB_ARGS", &self.syft_args)
            .env("SYFT_STUB_SBOM", &self.sbom);
        let env: Vec<(&str, Option<&str>)> = cicd
            .iter()
            .map(|(name, value)| (*name, Some(*value)))
            .collect();
        let ran = run_command(command, &["-c", &script], None, &env);
        assert_eq!(
            ran.code, code,
            "job `{job}`:\n{script}\nstdout:\n{}\nstderr:\n{}",
            ran.stdout, ran.stderr
        );
        ran
    }

    /// The arguments the SBOM job gave `syft`.
    fn syft_args(&self) -> Vec<String> {
        fs::read_to_string(&self.syft_args)
            .expect("syft ran")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Expects `syft` to have named the product `acme-app` at `version`.
    fn expect_sbom_of(&self, version: &str) {
        let args = self.syft_args();
        for (option, value) in [("--source-name", "acme-app"), ("--source-version", version)] {
            assert!(
                args.windows(2).any(|pair| pair == [option, value]),
                "syft is given `{option} {value}`: {args:?}"
            );
        }
        assert!(
            self.sandbox.product.join("sbom.cdx.json").is_file(),
            "the SBOM job writes sbom.cdx.json: {args:?}"
        );
    }
}

/// The items of an inline list, `[a, b]`.
fn inline_list(value: &str) -> Vec<&str> {
    value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or_else(|| panic!("{TEMPLATE}: an inline list `[…]`: {value}"))
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect()
}

fn unchanged(_: &TemplateJob, block: &str) -> String {
    block.to_owned()
}

/// The match with local feeds, its `--cache` the directory the job keeps between pipelines.
fn with_local_feeds(job: &TemplateJob, block: &str) -> String {
    let kept = job.map("cache", "paths").map(inline_list);
    let kept = match kept.as_deref() {
        None => None,
        Some([path]) => Some(*path),
        Some(paths) => panic!("{TEMPLATE}: one directory of feeds kept, not {paths:?}"),
    };
    ci_template::with_local_feeds(TEMPLATE, block, kept)
}

fn as_dry_run(_: &TemplateJob, block: &str) -> String {
    ci_template::as_dry_run(TEMPLATE, block)
}

#[test]
fn the_test_runs_each_job_of_the_template_and_replaces_each_installation() {
    let template = fs::read_to_string(fixture(TEMPLATE)).expect("the template is read");
    let found = jobs(&template);
    let with = |key: &str| -> BTreeSet<String> {
        found
            .iter()
            .filter(|(_, job)| job.keys.contains_key(key))
            .map(|(name, _)| name.clone())
            .collect()
    };
    assert_eq!(
        with("script"),
        BTreeSet::from([SBOM, MATCH, UPLOAD].map(str::to_owned)),
        "{TEMPLATE}: a job with a `script` this test does not run"
    );
    assert_eq!(
        with("before_script"),
        BTreeSet::from([INSTALL_FOREWARN, INSTALL_SYFT].map(str::to_owned)),
        "{TEMPLATE}: a `before_script` this test does not replace"
    );
    for key in ["after_script", "hooks"] {
        assert!(with(key).is_empty(), "{TEMPLATE}: a `{key}`, not run here");
    }
    // The replaced lists go back to the project, where this test runs what follows.
    for name in [INSTALL_FOREWARN, INSTALL_SYFT] {
        assert!(
            found[name]
                .list("before_script")
                .iter()
                .any(|item| item == IN_PROJECT),
            "{TEMPLATE}: the `before_script` of `{name}` goes back to the project"
        );
    }
    for name in [MATCH, UPLOAD] {
        assert_eq!(
            found[name].extends(),
            Some(INSTALL_FOREWARN),
            "{TEMPLATE}: `{name}` installs forewarn"
        );
    }
}

#[test]
fn the_jobs_after_the_sbom_receive_it_on_the_triggers_of_the_runs() {
    let template = fs::read_to_string(fixture(TEMPLATE)).expect("the template is read");
    let found = jobs(&template);
    // Each job runs in a fresh checkout: the SBOM reaches the others as an artifact they need, not as a file left in
    // the directory where this test runs them all.
    assert_eq!(
        found[SBOM].map("artifacts", "paths").map(inline_list),
        Some(vec!["sbom.cdx.json"]),
        "{TEMPLATE}: the SBOM job keeps sbom.cdx.json"
    );
    for name in [MATCH, UPLOAD] {
        assert_eq!(
            found[name]
                .keys
                .get("needs")
                .map(|needs| inline_list(needs)),
            Some(vec![SBOM]),
            "{TEMPLATE}: `{name}` needs the SBOM"
        );
    }
    // The runs of the tests: a schedule runs the SBOM and the match, a tag runs them and the upload, and only a tag.
    let base = found[SBOM]
        .extends()
        .expect("the SBOM job extends the base");
    assert_eq!(found[INSTALL_FOREWARN].extends(), Some(base));
    for rule in [
        "if: $CI_COMMIT_TAG =~ /^v/",
        r#"if: $CI_PIPELINE_SOURCE == "schedule""#,
    ] {
        assert!(
            found[base].list("rules").iter().any(|item| item == rule),
            "{TEMPLATE}: the jobs run on `{rule}`"
        );
    }
    assert!(
        !found[SBOM].keys.contains_key("rules") && !found[MATCH].keys.contains_key("rules"),
        "{TEMPLATE}: the SBOM and the match keep the rules of `{base}`"
    );
    assert_eq!(
        found[UPLOAD].list("rules"),
        ["if: $CI_COMMIT_TAG =~ /^v/"],
        "{TEMPLATE}: the upload runs on a tag only"
    );
}
#[test]
fn a_scheduled_run_checks_the_latest_tag_and_fails_on_an_actively_exploited_match() {
    let pipeline = Pipeline::new(&[("CI_PIPELINE_SOURCE", "schedule")], "exploited.cdx.json");
    let release = pipeline.sandbox.tagged_release_and_a_commit_after();

    pipeline.job(SBOM, unchanged, &[], 0);
    assert_eq!(
        pipeline.sandbox.git(&["rev-parse", "HEAD"]),
        release,
        "the latest tag is checked out"
    );
    pipeline.expect_sbom_of("1.2.0");

    pipeline.job(MATCH, with_local_feeds, &[], 6);
    let report = pipeline.sandbox.report();
    assert_eq!(report["exploitedCount"], 1, "{report}");
    assert!(
        pipeline
            .sandbox
            .product
            .join("drafts/acme-app-CVE-2021-44228.md")
            .is_file(),
        "the draft early warning of the exploited CVE is written"
    );
    // The moment of awareness is kept with the feeds, so that the next scheduled run counts the deadlines from it.
    let job = pipeline.template_job(MATCH);
    let kept = job
        .map("cache", "paths")
        .map(inline_list)
        .expect("the match keeps a cache");
    let file = ci_template::awareness_file(TEMPLATE, &job.list("script").join("\n"));
    assert!(
        kept.iter()
            .any(|dir| file.starts_with(&format!("{}/", dir.trim_end_matches('/')))),
        "{TEMPLATE}: the moments of awareness {file} under the cache kept {kept:?}"
    );
    let file = pipeline.sandbox.product.join(file);
    let first = ci_template::recorded_and_reported(&file, &report, "CVE-2021-44228");
    pipeline.job(MATCH, with_local_feeds, &[], 6);
    let next = pipeline.sandbox.report();
    assert_eq!(
        ci_template::recorded_and_reported(&file, &next, "CVE-2021-44228"),
        first,
        "the next run counts from the moment of the first"
    );
}

#[test]
fn a_tag_run_passes_on_a_match_not_exploited_and_uploads_the_sbom() {
    let pipeline = Pipeline::new(
        &[("CI_PIPELINE_SOURCE", "push"), ("CI_COMMIT_TAG", "v1.2.0")],
        "affected.cdx.json",
    );

    pipeline.job(SBOM, unchanged, &[], 0);
    pipeline.expect_sbom_of("1.2.0");

    pipeline.job(MATCH, with_local_feeds, &[], 0);
    let report = pipeline.sandbox.report();
    assert_eq!(report["exploitedCount"], 0, "{report}");
    assert!(
        !report["affected"].as_array().expect("an array").is_empty(),
        "time 0.1.43 is affected: {report}"
    );

    // The CI/CD variables the template asks for; the dry run reads no token.
    let upload = pipeline.job(
        UPLOAD,
        as_dry_run,
        &[
            ("FOREWARN_ENDPOINT", "https://forewarn.example.invalid"),
            ("FOREWARN_TOKEN", "a-token"),
        ],
        0,
    );
    assert!(
        upload.stdout.contains("acme-app 1.2.0"),
        "the upload names the product and version of the SBOM: {}",
        upload.stdout
    );
}
