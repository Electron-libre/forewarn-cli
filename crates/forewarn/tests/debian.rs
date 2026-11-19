//! `forewarn match` on the Debian packages of a container image, as an image scanner lists them
//! (`specs/vulnerability-matching.md`, VMT-H4, VMT-32 to VMT-34).

mod common;

use std::fs;

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

// spec: VMT-H4, VMT-4, VMT-32, VMT-33, VMT-9
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
