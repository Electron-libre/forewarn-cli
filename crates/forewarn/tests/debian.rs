//! `forewarn match` on the Debian packages of a container image, as an image scanner lists them
//! (`specs/debian-matching.md`, DEB-H1 to DEB-H3, DEB-1 to DEB-3, DEB-5).

mod common;

use std::fs;
use std::path::Path;

use common::{bom, json_report, run};
use serde_json::{Value, json};
use tempfile::TempDir;

fn component(name: &str, version: &str, purl: &str) -> Value {
    json!({"type": "library", "name": name, "version": version, "purl": purl})
}

/// Three packages of a Debian 13 image as Syft lists them, and one without a `distro` qualifier.
fn image_sbom() -> Vec<u8> {
    bom(
        "1.6",
        &json!([
            component(
                "libssl3t64",
                "3.5.7-1~deb13u3",
                "pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3?arch=amd64&distro=debian-13.7&upstream=openssl",
            ),
            component(
                "libc6",
                "2.41-12+deb13u4",
                "pkg:deb/debian/libc6@2.41-12%2Bdeb13u4?arch=amd64&distro=debian-13.7&upstream=glibc",
            ),
            component(
                "zlib1g",
                "1:1.3.dfsg+really1.3.1-1+deb13u1",
                "pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1%2Bdeb13u1?arch=amd64&distro=debian-13.7&upstream=zlib",
            ),
            component(
                "tzdata",
                "2025b-4",
                "pkg:deb/debian/tzdata@2025b-4?arch=all"
            ),
        ]),
    )
}

/// A record of OSV affecting a source package of a Debian release, fixed at `fixed`.
fn debian_record(id: &str, release: &str, name: &str, fixed: &str) -> Value {
    json!({
        "id": id,
        "modified": "2026-11-01T00:00:00Z",
        "aliases": [],
        "affected": [{
            "package": {"ecosystem": format!("Debian:{release}"), "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
    })
}

// spec: DEB-H1, VMT-4, DEB-1, DEB-2, VMT-9
#[test]
fn matches_the_debian_packages_of_an_image_against_the_advisories_of_their_release() {
    let osv = TempDir::new().expect("a temporary directory");
    for record in [
        debian_record("DSA-6001-1", "13", "openssl", "3.5.7-1~deb13u4"),
        debian_record("DSA-6002-1", "12", "openssl", "3.0.20-1~deb12u1"),
        debian_record("DSA-6003-1", "13", "glibc", "2.41-12+deb13u3"),
        debian_record(
            "DSA-6004-1",
            "13",
            "zlib",
            "1:1.3.dfsg+really1.3.1-1+deb13u2",
        ),
    ] {
        fs::write(
            osv.path()
                .join(format!("{}.json", record["id"].as_str().expect("an id"))),
            record.to_string(),
        )
        .expect("the record is written");
    }
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            osv.path().to_str().expect("UTF-8 path"),
            "-",
        ],
        Some(&image_sbom()),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    let report = json_report(&run);
    let affected: Vec<Value> = report["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|a| json!([a["name"], a["id"]]))
        .collect();
    assert_eq!(
        affected,
        [
            json!(["libssl3t64", "DSA-6001-1"]),
            json!(["zlib1g", "DSA-6004-1"])
        ]
    );
    let not_evaluated: Vec<Value> = report["notEvaluated"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|n| json!([n["name"], n["reason"]]))
        .collect();
    assert_eq!(not_evaluated, [json!(["tzdata", "unknown release"])]);
    assert_eq!(report["cleanCount"], json!(1));
}

// spec: OSR-42, VMT-21, VMT-16
#[test]
fn a_debian_advisory_is_reported_and_flagged_under_the_cve_it_names_upstream() {
    let osv = TempDir::new().expect("a temporary directory");
    let mut dsa = debian_record("DSA-6001-1", "13", "openssl", "3.5.7-1~deb13u4");
    dsa["upstream"] = json!(["CVE-2026-0001", "DEBIAN-CVE-2026-0001"]);
    let mut debian_cve = debian_record("DEBIAN-CVE-2026-0001", "13", "openssl", "3.5.7-1~deb13u4");
    debian_cve["upstream"] = json!(["CVE-2026-0001"]);
    for record in [dsa, debian_cve] {
        fs::write(
            osv.path()
                .join(format!("{}.json", record["id"].as_str().expect("an id"))),
            record.to_string(),
        )
        .expect("the record is written");
    }
    let kev = osv.path().with_extension("kev.json");
    fs::write(
        &kev,
        json!({
            "catalogVersion": "2026.11.18",
            "dateReleased": "2026-11-18T18:00:00.000Z",
            "vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-11-18"}],
        })
        .to_string(),
    )
    .expect("the catalog is written");
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--kev",
            kev.to_str().expect("UTF-8 path"),
            "--format",
            "json",
            "--osv",
            osv.path().to_str().expect("UTF-8 path"),
            "-",
        ],
        Some(&image_sbom()),
    );
    fs::remove_file(&kev).expect("the catalog is removed");
    assert_eq!(run.code, 6, "{}", run.stderr);
    let report = json_report(&run);
    assert_eq!(report["affected"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["affected"][0]["id"], json!("CVE-2026-0001"));
    assert_eq!(report["exploitedCount"], json!(1));
}

/// A package of a Debian 12 image as Trivy lists it: no `upstream`, its source in its properties.
fn trivy_component(name: &str, version: &str, purl: &str, source: [&str; 3]) -> Value {
    let property = |suffix: &str, value: &str| json!({"name": format!("aquasecurity:trivy:{suffix}"), "value": value});
    json!({
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [
            property("PkgType", "debian"),
            property("SrcName", source[0]),
            property("SrcRelease", source[1]),
            property("SrcVersion", source[2]),
        ],
    })
}

// spec: DEB-H2, DEB-2, DEB-3, SBR-17
#[test]
fn matches_the_debian_packages_of_a_trivy_sbom_under_their_source() {
    let osv = TempDir::new().expect("a temporary directory");
    for record in [
        debian_record("DSA-6101-1", "12", "glibc", "2.36-9+deb12u15"),
        debian_record("DSA-6102-1", "12", "bash", "5.2.15-2+b1"),
        debian_record("DSA-6103-1", "12", "libpam0g", "9.9"),
    ] {
        fs::write(
            osv.path()
                .join(format!("{}.json", record["id"].as_str().expect("an id"))),
            record.to_string(),
        )
        .expect("the record is written");
    }
    let sbom = bom(
        "1.7",
        &json!([
            trivy_component(
                "libc6",
                "2.36-9+deb12u14",
                "pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15",
                ["glibc", "9+deb12u14", "2.36"],
            ),
            trivy_component(
                "bash",
                "5.2.15-2+b13",
                "pkg:deb/debian/bash@5.2.15-2%2Bb13?arch=amd64&distro=debian-12.15",
                ["bash", "2", "5.2.15"],
            ),
            trivy_component(
                "libpam0g",
                "1.5.2-6+deb12u2",
                "pkg:deb/debian/libpam0g@1.5.2-6%2Bdeb12u2?arch=amd64&distro=debian-12.15",
                ["pam", "6+deb12u2", "1.5.2"],
            ),
        ]),
    );
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            osv.path().to_str().expect("UTF-8 path"),
            "-",
        ],
        Some(&sbom),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    let report = json_report(&run);
    let affected: Vec<Value> = report["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|a| json!([a["name"], a["version"], a["id"]]))
        .collect();
    assert_eq!(
        affected,
        [
            json!(["libc6", "2.36-9+deb12u14", "DSA-6101-1"]),
            json!(["bash", "5.2.15-2+b13", "DSA-6102-1"]),
        ]
    );
    assert_eq!(report["cleanCount"], json!(1));
}

// spec: DEB-5
#[test]
fn keeps_the_epoch_of_the_package_url_version_a_component_version_lacks() {
    let osv = TempDir::new().expect("a temporary directory");
    for record in [
        debian_record("DSA-6101-1", "12", "login", "1:4.13+dfsg1-1"),
        debian_record("DSA-6102-1", "12", "login", "1:4.13+dfsg1-2"),
    ] {
        fs::write(
            osv.path()
                .join(format!("{}.json", record["id"].as_str().expect("an id"))),
            record.to_string(),
        )
        .expect("the record is written");
    }
    let sbom = bom(
        "1.6",
        &json!([component(
            "login",
            "4.13+dfsg1-1",
            "pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?arch=amd64&distro=debian-12",
        )]),
    );
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            osv.path().to_str().expect("UTF-8 path"),
            "-",
        ],
        Some(&sbom),
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    let affected: Vec<Value> = json_report(&run)["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|a| json!([a["name"], a["version"], a["id"]]))
        .collect();
    assert_eq!(affected, [json!(["login", "4.13+dfsg1-1", "DSA-6102-1"])]);
}

// spec: DEB-H3, DEB-1, DEB-2, DEB-5
#[test]
fn matches_the_source_packages_a_cdxgen_sbom_lists_beside_the_binaries() {
    let osv = TempDir::new().expect("a temporary directory");
    for record in [
        debian_record("DSA-6104-1", "12", "shadow", "1:4.13+dfsg1-1+deb12u3"),
        debian_record("DSA-6105-1", "12", "glibc", "2.36-9+deb12u15"),
        debian_record("DSA-6106-1", "12", "util-linux", "2.38.1-5+deb12u4"),
        debian_record("DSA-6107-1", "12", "shadow", "4.14"),
    ] {
        fs::write(
            osv.path()
                .join(format!("{}.json", record["id"].as_str().expect("an id"))),
            record.to_string(),
        )
        .expect("the record is written");
    }
    let sbom = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../forewarn-cyclonedx/tests/fixtures/cdxgen-debian.cdx.json");
    let run = run(
        &[
            "match",
            "--no-euvd",
            "--no-kev",
            "--format",
            "json",
            "--osv",
            osv.path().to_str().expect("UTF-8 path"),
            sbom.to_str().expect("UTF-8 path"),
        ],
        None,
    );
    assert_eq!(run.code, 1, "{}", run.stderr);
    let report = json_report(&run);
    let mut affected: Vec<Value> = report["affected"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|a| json!([a["name"], a["version"], a["id"]]))
        .collect();
    affected.sort_by_key(ToString::to_string);
    assert_eq!(
        affected,
        [
            json!(["glibc", "2.36-9+deb12u14", "DSA-6105-1"]),
            json!(["shadow", "1:4.13+dfsg1-1+deb12u2", "DSA-6104-1"]),
            json!(["util-linux", "2.38.1-5+deb12u3", "DSA-6106-1"]),
        ]
    );
    assert_eq!(report["cleanCount"], json!(4));
}
