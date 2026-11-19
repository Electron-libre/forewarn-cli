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
        (
            "pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3?arch=amd64&distro=debian-13.7&upstream=openssl",
            "Debian:13",
            "openssl",
        ),
    ];
    for (purl, ecosystem, name) in cases {
        let package = package(purl);
        assert_eq!(
            (package.ecosystem.as_str(), package.name.as_str()),
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
            "pkg:cargo/sample@0.1.0?download_url=https://example.com/sample.crate#src/main.rs",
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
        ComponentPackage::of(&component("pkg:apk/alpine/curl@7.0", None)),
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

// spec: VMT-10, VMT-11
#[test]
fn keeps_a_first_party_component_out_before_any_other_reason() {
    let first_party = |component: Component| Component {
        first_party: true,
        ..component
    };
    for component in [
        component("pkg:cargo/time@0.1.43", None),
        component("pkg:apk/alpine/curl@7.0", None),
        Component::default(),
    ] {
        assert_eq!(
            ComponentPackage::of(&first_party(component)),
            Err(ComponentReason::FirstParty)
        );
    }
}

// spec: VMT-10, VMT-11, VMT-31
#[test]
fn keeps_a_component_pointing_to_a_local_path_out() {
    for purl in [
        "pkg:cargo/itoa@1.0.9?download_url=file://../forks/itoa",
        "pkg:cargo/lib@0.1.0?Download_URL=FILE%3A..%2Flib",
        "pkg:cargo/lib@0.1.0?checksum=sha256:00&download_url=file:///src/lib#src/lib.rs",
        "pkg:cargo/lib@0.1.0?download_url=file://../50%off",
        "pkg:cargo/lib@0.1.0?download_url=fil%65:../caf%E9",
    ] {
        assert_eq!(
            ComponentPackage::of(&component(purl, None)),
            Err(ComponentReason::LocalPath),
            "{purl}"
        );
    }
}

// spec: VMT-31
#[test]
fn matches_a_component_whose_download_url_is_remote_or_whose_local_url_is_another_qualifier() {
    for purl in [
        "pkg:cargo/ryu@1.0.23?download_url=https://example.com/ryu.crate",
        "pkg:cargo/ryu@1.0.23?vcs_url=file://../ryu",
        "pkg:cargo/ryu@1.0.23#file:",
    ] {
        assert_eq!(package(purl).name, "ryu", "{purl}");
    }
}

// spec: VMT-10
#[test]
fn keeps_a_first_party_component_pointing_to_a_local_path_out_as_first_party() {
    let product = Component {
        first_party: true,
        ..component("pkg:cargo/app@0.1.0?download_url=file://.", None)
    };

    assert_eq!(
        ComponentPackage::of(&product),
        Err(ComponentReason::FirstParty)
    );
}

// spec: VMT-10
#[test]
fn reports_an_invalid_package_url_before_a_local_path() {
    assert_eq!(
        ComponentPackage::of(&component("pkg:cargo/a%4?download_url=file://.", None)),
        Err(ComponentReason::InvalidPackageUrl)
    );
}

// spec: VMT-10
#[test]
fn reports_the_component_reasons_before_a_local_path() {
    assert_eq!(
        ComponentPackage::of(&component("pkg:generic/x@1?download_url=file:.", None)),
        Err(ComponentReason::UnknownEcosystem)
    );
    assert_eq!(
        ComponentPackage::of(&component(
            "pkg:maven/foo@1.0?download_url=file:../foo",
            None
        )),
        Err(ComponentReason::InvalidPackageUrl)
    );
    assert_eq!(
        ComponentPackage::of(&component("pkg:cargo/lib?download_url=file:../lib", None)),
        Err(ComponentReason::NoVersion)
    );
}

// spec: VMT-32
#[test]
fn maps_a_debian_package_to_the_release_of_its_distro_qualifier() {
    for (purl, ecosystem) in [
        (
            "pkg:deb/debian/libc6@2.41-12?distro=debian-13.7",
            "Debian:13",
        ),
        ("pkg:deb/debian/libc6@2.41-12?distro=debian-13", "Debian:13"),
        (
            "pkg:deb/debian/libc6@2.36-9?arch=amd64&Distro=debian-012",
            "Debian:12",
        ),
        (
            "pkg:deb/debian/libc6@2.36-9?distro=debian%2D12",
            "Debian:12",
        ),
        (
            "pkg:deb/debian/libc6@2.36-9?distro=debian-12x#sub",
            "Debian:12",
        ),
    ] {
        assert_eq!(package(purl).ecosystem, ecosystem, "{purl}");
    }
}

// spec: VMT-10, VMT-32
#[test]
fn reports_a_debian_package_without_a_release_as_unknown_release() {
    for purl in [
        "pkg:deb/debian/libc6@2.41-12?arch=amd64",
        "pkg:deb/debian/libc6@2.41-12?distro=trixie",
        "pkg:deb/debian/libc6@2.41-12?distro=debian-",
        "pkg:deb/debian/libc6@2.41-12?distro=ubuntu-24.04",
        "pkg:deb/debian/libc6@2.41-12?distro=",
        "pkg:deb/debian/libc6@2.11.3-4?distro=debian-6",
        "pkg:deb/debian/libc6@2.11.3-4?distro=debian-6.",
    ] {
        assert_eq!(
            ComponentPackage::of(&component(purl, None)),
            Err(ComponentReason::UnknownRelease),
            "{purl}"
        );
    }
}

// spec: VMT-4
#[test]
fn leaves_the_deb_packages_of_another_namespace_unmapped() {
    for purl in [
        "pkg:deb/ubuntu/libc6@2.39-0ubuntu8?distro=ubuntu-24.04",
        "pkg:deb/libc6@2.41-12?distro=debian-13",
    ] {
        assert_eq!(
            ComponentPackage::of(&component(purl, None)),
            Err(ComponentReason::UnknownEcosystem),
            "{purl}"
        );
    }
}

// spec: VMT-5, VMT-33
#[test]
fn names_a_debian_package_by_its_source() {
    let without_upstream = package("pkg:deb/debian/zlib1g@1%3A1.3.dfsg-3?distro=debian-13");
    assert_eq!(
        (
            without_upstream.name.as_str(),
            without_upstream.version.as_str()
        ),
        ("zlib1g", "1:1.3.dfsg-3")
    );
    for (purl, name) in [
        (
            "pkg:deb/debian/libc6@2.41-12?distro=debian-13&upstream=glibc",
            "glibc",
        ),
        (
            "pkg:deb/debian/libc6@2.41-12?distro=debian-13&Upstream=glib%63",
            "glibc",
        ),
        (
            "pkg:deb/debian/libc6@2.41-12?distro=debian-13&upstream=",
            "libc6",
        ),
        (
            "pkg:deb/debian/libc6@2.41-12?distro=debian-13&upstream=@2.41-12",
            "libc6",
        ),
    ] {
        assert_eq!(package(purl).name, name, "{purl}");
    }
}

// spec: VMT-7, VMT-34
#[test]
fn matches_a_debian_package_at_the_version_of_its_source() {
    let purl = "pkg:deb/debian/libc6@2.41-12%2Bb1?distro=debian-13&upstream=glibc%402.41-12";
    for (purl, version, expected) in [
        (purl.to_owned(), None, "2.41-12"),
        (purl.to_owned(), Some("2.41-12+b1"), "2.41-12"),
        (purl.replace("%402.41-12", "@"), None, "2.41-12+b1"),
        (
            purl.replace("%402.41-12", ""),
            Some("2.41-12+b2"),
            "2.41-12+b2",
        ),
    ] {
        let package = ComponentPackage::of(&component(&purl, version)).expect("a package");
        assert_eq!(package.version, expected, "{purl} {version:?}");
    }
}

// spec: VMT-6
#[test]
fn compares_debian_names_exactly() {
    assert!(same_name("Debian:13", "glibc", "glibc"));
    assert!(!same_name("Debian:13", "glibc", "GLIBC"));
}

// spec: VMT-10, VMT-35
#[test]
fn reports_a_debian_qualifier_that_does_not_decode_as_an_invalid_package_url() {
    for purl in [
        "pkg:deb/debian/libssl3@3.0.11-1?distro=debian-12&upstream=openssl%4",
        "pkg:deb/debian/libssl3@3.0.11-1?distro=debian-1%2",
    ] {
        assert_eq!(
            ComponentPackage::of(&component(purl, None)),
            Err(ComponentReason::InvalidPackageUrl),
            "{purl}"
        );
    }
}
