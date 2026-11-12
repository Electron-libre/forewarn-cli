//! The package a component is matched under: its OSV ecosystem, name and version (`specs/vulnerability-matching.md`).

use forewarn_domain::matching::{ComponentPackage, ComponentReason, same_name};
use forewarn_domain::sbom::Component;

fn component(purl: &str, version: Option<&str>) -> Component {
    Component {
        name: "anything".into(),
        version: version.map(Into::into),
        purl: Some(purl.into()),
        ..Component::default()
    }
}

fn package(purl: &str) -> ComponentPackage {
    ComponentPackage::of(&component(purl, None)).expect("a package")
}

// spec: VMT-4
#[test]
fn maps_each_package_url_type_to_its_osv_ecosystem_and_name() {
    let cases = [
        ("pkg:cargo/time@0.1.43", "crates.io", "time"),
        ("pkg:npm/%40babel/core@7.0.0", "npm", "@babel/core"),
        ("pkg:npm/left-pad@1.3.0", "npm", "left-pad"),
        ("pkg:pypi/django@4.2.0", "PyPI", "django"),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "Maven",
            "org.apache.logging.log4j:log4j-core",
        ),
        (
            "pkg:golang/golang.org/x/net@v0.17.0",
            "Go",
            "golang.org/x/net",
        ),
        (
            "pkg:nuget/Newtonsoft.Json@13.0.1",
            "NuGet",
            "Newtonsoft.Json",
        ),
        ("pkg:gem/rails@7.0.0", "RubyGems", "rails"),
        (
            "pkg:composer/laravel/framework@10.0.0",
            "Packagist",
            "laravel/framework",
        ),
    ];
    for (purl, ecosystem, name) in cases {
        let package = package(purl);
        assert_eq!(
            (package.ecosystem, package.name.as_str()),
            (ecosystem, name),
            "{purl}"
        );
    }
}

// spec: VMT-4
#[test]
fn leaves_out_a_namespace_the_table_does_not_name() {
    assert_eq!(package("pkg:cargo/extra/time@1.0.0").name, "time");
}

// spec: VMT-5
#[test]
fn reads_the_package_url_by_its_specification() {
    let cases = [
        ("pkg:npm/%40babel/core@7.0.0", "@babel/core", "7.0.0"),
        ("PKG:CARGO/time@1.0.0", "time", "1.0.0"),
        ("pkg://cargo/time@1.0.0", "time", "1.0.0"),
        (
            "pkg:cargo/sample@0.1.0?download_url=file://.#src/main.rs",
            "sample",
            "0.1.0",
        ),
        ("pkg:npm/@babel/core@7.0.0", "@babel/core", "7.0.0"),
        ("pkg:npm/a%20b@1.0.0%2Bbuild", "a b", "1.0.0+build"),
        (
            "pkg:golang/github.com/foo/bar@v1.0.0",
            "github.com/foo/bar",
            "v1.0.0",
        ),
    ];
    for (purl, name, version) in cases {
        let package = package(purl);
        assert_eq!(
            (package.name.as_str(), package.version.as_str()),
            (name, version),
            "{purl}"
        );
    }
}

// spec: VMT-5
#[test]
fn refuses_a_package_url_that_does_not_follow_the_specification() {
    for purl in [
        "cargo/time@1.0.0",
        "pkg:",
        "pkg:cargo",
        "pkg:cargo/",
        "pkg:cargo/@1.0.0",
        "pkg:1cargo/time@1.0.0",
        "pkg:car go/time@1.0.0",
        "pkg:cargo/ti%ZZme@1.0.0",
        "pkg:cargo/ti%FFme@1.0.0",
    ] {
        assert_eq!(
            ComponentPackage::of(&component(purl, Some("1.0.0"))),
            Err(ComponentReason::InvalidPackageUrl),
            "{purl}"
        );
    }
}

// spec: VMT-6
#[test]
fn compares_names_exactly_except_under_pypi() {
    assert!(same_name("crates.io", "time", "time"));
    assert!(!same_name("crates.io", "Time", "time"));
    assert!(!same_name("npm", "left_pad", "left-pad"));
    assert!(same_name("PyPI", "Django_Rest", "django-rest"));
    assert!(same_name("PyPI", "zope.interface", "Zope-Interface"));
    assert!(same_name("PyPI", "a-_.b", "a_b"));
    assert!(!same_name("PyPI", "ab", "a-b"));
}

// spec: VMT-7
#[test]
fn matches_the_component_version_else_the_package_url_version() {
    let both = ComponentPackage::of(&component("pkg:cargo/time@1.0.0", Some("1.0.1")));
    assert_eq!(both.expect("a package").version, "1.0.1");
    let blank = ComponentPackage::of(&component("pkg:cargo/time@1.0.0", Some("  ")));
    assert_eq!(blank.expect("a package").version, "1.0.0");
    let component_only = ComponentPackage::of(&component("pkg:cargo/time", Some("2.0.0")));
    assert_eq!(component_only.expect("a package").version, "2.0.0");
}

// spec: VMT-4, VMT-7
#[test]
fn gives_the_component_reason_it_cannot_be_matched() {
    let no_purl = Component {
        name: "time".into(),
        version: Some("1.0.0".into()),
        ..Component::default()
    };
    assert_eq!(
        ComponentPackage::of(&no_purl),
        Err(ComponentReason::NoPackageUrl)
    );
    assert_eq!(
        ComponentPackage::of(&component("pkg:deb/debian/curl@7.0", None)),
        Err(ComponentReason::UnknownEcosystem)
    );
    assert_eq!(
        ComponentPackage::of(&component("pkg:cargo/time", None)),
        Err(ComponentReason::NoVersion)
    );
}

// spec: VMT-4
#[test]
fn refuses_a_maven_or_composer_package_url_without_a_namespace() {
    for purl in [
        "pkg:maven/log4j-core@2.14.1",
        "pkg:composer/framework@10.0.0",
    ] {
        assert_eq!(
            ComponentPackage::of(&component(purl, None)),
            Err(ComponentReason::InvalidPackageUrl),
            "{purl}"
        );
    }
    assert_eq!(package("pkg:golang/stdlib@1.21.0").name, "stdlib");
}

// spec: VMT-5
#[test]
fn splits_the_version_before_the_path() {
    let package = package("pkg:golang/example.com/mod@release/v1");
    assert_eq!(
        (package.name.as_str(), package.version.as_str()),
        ("example.com/mod", "release/v1")
    );
}

// spec: VMT-6
#[test]
fn compares_nuget_names_without_regard_to_case() {
    assert!(same_name("NuGet", "newtonsoft.json", "Newtonsoft.Json"));
    assert!(!same_name("NuGet", "newtonsoft-json", "Newtonsoft.Json"));
}

// spec: VMT-5
#[test]
fn reads_an_unencoded_npm_scope_without_a_version() {
    let package =
        ComponentPackage::of(&component("pkg:npm/@babel/core", Some("7.0.0"))).expect("a package");
    assert_eq!(
        (package.name.as_str(), package.version.as_str()),
        ("@babel/core", "7.0.0")
    );
}
