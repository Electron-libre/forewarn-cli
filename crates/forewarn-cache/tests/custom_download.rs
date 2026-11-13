//! A source that downloads its entry itself, as a paginated API does (ADR 0009): the cache hands it the file to write,
//! records the `Last-Modified` it returns, and keeps the former copy when it fails.

use std::fs;
use std::path::Path;
use std::time::SystemTime;

use forewarn_cache::{Cache, Error, Refresh, Source};
use tempfile::TempDir;

fn read(directory: &Path) -> Result<String, String> {
    fs::read_to_string(directory.join("list")).map_err(|e| e.to_string())
}

fn unpack(download: &Path, directory: &Path) -> Result<(), String> {
    fs::rename(download, directory.join("list")).map_err(|e| e.to_string())
}

#[test]
fn a_source_that_downloads_itself_fills_the_entry_with_the_file_it_writes() {
    let dir = TempDir::new().expect("a directory");
    let cache = Cache::new(dir.path().to_path_buf(), Refresh::IfMissing);
    let source: Source<'_, String, String> = Source {
        url: "https://example.invalid/api/search".into(),
        download: &|_: &ureq::Agent, url: &str, file: &Path| {
            fs::write(file, format!("pages of {url}")).expect("the file is written");
            Ok(Some("Fri, 13 Nov 2026 10:00:00 GMT".to_owned()))
        },
        unpack: &unpack,
        read: &read,
    };

    let fetched = cache
        .fetch(&forewarn_cache::agent(), "list", &source, &SystemTime::now)
        .expect("fetched");

    assert_eq!(fetched.value, "pages of https://example.invalid/api/search");
    assert_eq!(fetched.freshness.url, "https://example.invalid/api/search");
    assert_eq!(
        fetched.freshness.last_modified.as_deref(),
        Some("Fri, 13 Nov 2026 10:00:00 GMT")
    );
}

#[test]
fn a_failed_download_of_a_source_leaves_the_former_copy() {
    let dir = TempDir::new().expect("a directory");
    let first: Source<'_, String, String> = Source {
        url: "https://example.invalid/list".into(),
        download: &|_: &ureq::Agent, _: &str, file: &Path| {
            fs::write(file, "first").expect("the file is written");
            Ok(None)
        },
        unpack: &unpack,
        read: &read,
    };
    Cache::new(dir.path().to_path_buf(), Refresh::IfMissing)
        .fetch(&forewarn_cache::agent(), "list", &first, &SystemTime::now)
        .expect("fetched");
    let failing: Source<'_, String, String> = Source {
        url: first.url.clone(),
        download: &|_: &ureq::Agent, _: &str, _: &Path| Err(Error::Source("page repeated".into())),
        unpack: &unpack,
        read: &read,
    };

    let error = Cache::new(dir.path().to_path_buf(), Refresh::Always)
        .fetch(&forewarn_cache::agent(), "list", &failing, &SystemTime::now)
        .expect_err("the download fails");
    let kept = Cache::new(dir.path().to_path_buf(), Refresh::Offline)
        .fetch(&forewarn_cache::agent(), "list", &first, &SystemTime::now)
        .expect("the former copy");

    assert_eq!(error, Error::Source("page repeated".to_owned()));
    assert_eq!(kept.value, "first");
}
