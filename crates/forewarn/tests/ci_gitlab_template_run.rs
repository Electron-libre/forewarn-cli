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
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ci_template::{Sandbox, fixture, indent, quoted};
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

/// `script` with each line continued by a final `\\` joined to the next, as the shell reads it, so that a command
/// written over several lines is rewritten as one.
fn unfolded(script: &str) -> String {
    let mut joined = String::new();
    for line in script.lines() {
        if let Some(head) = line.strip_suffix('\\') {
            joined.push_str(head);
        } else {
            joined.push_str(line);
            joined.push('\n');
        }
    }
    joined
}

/// A job of the template, hidden (a name starting with `.`, a base other jobs extend) or not.
#[derive(Default)]
struct TemplateJob {
    /// The job it extends.
    extends: Option<String>,
    /// Its keys (`stage`, `variables`, `script`…).
    keys: BTreeSet<String>,
    /// The variables of its `variables:`, their values unquoted.
    variables: BTreeMap<String, String>,
    /// Its `before_script` and `script`, one shell item each, a literal block dedented.
    before_script: Vec<String>,
    script: Vec<String>,
}

/// An item of a list of shell lines that starts at line `i` with `- <value>`: the value, or a literal block (`|`)
/// dedented; `i` moves past it. The items are indented to `dash`.
fn shell_item(lines: &[&str], i: &mut usize, dash: usize, value: &str) -> String {
    let value = value.trim();
    *i += 1;
    if value != "|" {
        assert!(
            !value.starts_with(['|', '>', '\'', '"']),
            "{TEMPLATE}: an item `- {value}`, read here as plain or `|` only"
        );
        return value.to_owned();
    }
    let mut block = String::new();
    let mut body_indent = None;
    while *i < lines.len() && (lines[*i].trim().is_empty() || indent(lines[*i]) > dash) {
        let body = lines[*i];
        if !body.trim().is_empty() {
            let start = *body_indent.get_or_insert(indent(body));
            block.push_str(body.get(start..).unwrap_or(""));
        }
        block.push('\n');
        *i += 1;
    }
    block
}

/// Each job of the template, by name: a key at the top level, its keys indented two spaces, the items of its lists
/// and its variables four.
fn jobs(template: &str) -> BTreeMap<String, TemplateJob> {
    let lines: Vec<&str> = template.lines().collect();
    let mut found: BTreeMap<String, TemplateJob> = BTreeMap::new();
    let mut job: Option<String> = None;
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
        match indent(line) {
            0 => {
                job = Some(name.to_owned());
                found.entry(name.to_owned()).or_default();
            }
            2 => {
                let current = found
                    .get_mut(job.as_deref().expect("a key belongs to a job"))
                    .expect("the job is found");
                current.keys.insert(name.to_owned());
                if name == "extends" {
                    current.extends = Some(value.trim().to_owned());
                }
                name.clone_into(&mut key);
            }
            4 => {
                let current = found
                    .get_mut(job.as_deref().expect("a key belongs to a job"))
                    .expect("the job is found");
                if let Some(item) = trimmed.strip_prefix("- ") {
                    let item = shell_item(&lines, &mut i, 4, item);
                    match key.as_str() {
                        "before_script" => current.before_script.push(item),
                        "script" => current.script.push(item),
                        _ => {}
                    }
                    continue;
                }
                if key == "variables" {
                    current.variables.insert(
                        name.to_owned(),
                        value.trim().trim_matches(['"', '\'']).to_owned(),
                    );
                }
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
    syft_args: PathBuf,
}

impl Pipeline {
    /// A pipeline with `env`, the predefined variables of GitLab that differ between triggers, whose SBOM is the
    /// fixture `sbom`.
    fn new(env: &[(&'static str, &str)], sbom: &str) -> Self {
        let template = fs::read_to_string(fixture(TEMPLATE)).expect("the template is read");
        let sandbox = Sandbox::new(env);
        let syft_args = sandbox.scratch().join("syft-args");
        let syft = sandbox.bin.join("syft");
        let sbom = fixture(&format!(
            "crates/forewarn/tests/fixtures/ci-template/{sbom}"
        ));
        fs::write(
            &syft,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {args}\nfor arg; do\n  case $arg in\n    \
                 cyclonedx-json=*) cp {sbom} \"${{arg#cyclonedx-json=}}\" ;;\n  esac\ndone\n",
                args = quoted(&syft_args),
                sbom = quoted(&sbom),
            ),
        )
        .expect("the stub of syft is written");
        fs::set_permissions(&syft, fs::Permissions::from_mode(0o755))
            .expect("the stub of syft is executable");
        Self {
            sandbox,
            jobs: jobs(&template),
            syft_args,
        }
    }

    fn template_job(&self, job: &str) -> &TemplateJob {
        self.jobs
            .get(job)
            .unwrap_or_else(|| panic!("{TEMPLATE} has no job `{job}`"))
    }

    /// The variables of a job and of the jobs it extends, its own first.
    fn variables(&self, job: &str) -> BTreeMap<String, String> {
        let mut variables = BTreeMap::new();
        let mut next = Some(job);
        while let Some(name) = next {
            let template_job = self.template_job(name);
            for (variable, value) in &template_job.variables {
                variables
                    .entry(variable.clone())
                    .or_insert_with(|| value.clone());
            }
            next = template_job.extends.as_deref();
        }
        variables
    }

    /// The `before_script` of a job, its own or that of the job it extends.
    fn before_script(&self, job: &str) -> &[String] {
        let mut next = Some(job);
        while let Some(name) = next {
            let template_job = self.template_job(name);
            if template_job.keys.contains("before_script") {
                return &template_job.before_script;
            }
            next = template_job.extends.as_deref();
        }
        &[]
    }

    /// Runs the `script` of a job, `rewrite` applied to it, as the runner runs it with `sh`: the items of its
    /// `before_script` once in the project (the installation replaced), then those of its `script`, one after the
    /// other in one shell that stops at the first that fails, with the variables of the job, of the pipeline and the
    /// CI/CD variables `cicd` only; expects its exit code.
    fn job(
        &self,
        job: &str,
        rewrite: impl Fn(&str) -> String,
        cicd: &[(&str, &str)],
        code: i32,
    ) -> Run {
        let before = self.before_script(job);
        let in_project = before
            .iter()
            .rposition(|item| item == IN_PROJECT)
            .map_or(before.len(), |at| at + 1);
        let script = rewrite(&unfolded(
            &before[in_project..]
                .iter()
                .chain(&self.template_job(job).script)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
        ));
        let script = format!(
            "if set -o | grep pipefail > /dev/null; then set -o pipefail; fi\nset -o errexit\n{script}\n"
        );
        let mut command = self.sandbox.command("sh");
        command
            .envs(self.variables(job))
            .env("CI_PROJECT_DIR", &self.sandbox.product)
            .env("CI_PROJECT_NAME", "acme-app")
            .env("CI_COMMIT_SHA", "0000000000000000000000000000000000000000");
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

fn unchanged(block: &str) -> String {
    block.to_owned()
}

fn with_local_feeds(block: &str) -> String {
    ci_template::with_local_feeds(TEMPLATE, block)
}

fn as_dry_run(block: &str) -> String {
    ci_template::as_dry_run(TEMPLATE, block)
}

#[test]
fn the_test_runs_each_job_of_the_template_and_replaces_each_installation() {
    let template = fs::read_to_string(fixture(TEMPLATE)).expect("the template is read");
    let found = jobs(&template);
    let with = |key: &str| -> BTreeSet<String> {
        found
            .iter()
            .filter(|(_, job)| job.keys.contains(key))
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
                .before_script
                .iter()
                .any(|item| item == IN_PROJECT),
            "{TEMPLATE}: the `before_script` of `{name}` goes back to the project"
        );
    }
    for name in [MATCH, UPLOAD] {
        assert_eq!(
            found[name].extends.as_deref(),
            Some(INSTALL_FOREWARN),
            "{TEMPLATE}: `{name}` installs forewarn"
        );
    }
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
