//! The cache refuses an entry name that could reach outside its directory or into its scratch paths, before it
//! touches the cache (ADR 0008).

use std::path::Path;
use std::time::SystemTime;

use forewarn_cache::{Cache, Error, Refresh, Source};
use tempfile::TempDir;

#[test]
fn an_entry_name_that_could_escape_the_cache_is_refused_before_any_write() {
    let dir = TempDir::new().expect("a directory");
    let cache = Cache::new(dir.path().join("cache"), Refresh::IfMissing);
    let source: Source<'_, (), String> = Source {
        url: "http://127.0.0.1:9/unused".into(),
        unpack: &|_: &Path, _: &Path| Ok(()),
        read: &|_: &Path| Ok(()),
    };

    for name in ["", "../x", "a/b", ".former-npm", "a\\b"] {
        let error = cache
            .fetch(&forewarn_cache::agent(), name, &source, &SystemTime::now)
            .expect_err("the name is refused");
        assert!(
            matches!(&error, Error::Cache(reason) if reason.contains("invalid entry name")),
            "{name:?}: {error:?}"
        );
    }
    assert!(!dir.path().join("cache").exists(), "the cache is untouched");
}
