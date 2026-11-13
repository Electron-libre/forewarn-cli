//! The one reading of a CVE id shared by matching and flagging (VMT-29, EXF-7).

use std::borrow::Cow;

/// Whether `id` is `CVE-YYYY-NNNN`, four digits or more after the year, the prefix in any ASCII case (EXF-7).
pub(crate) fn is_cve(id: &str) -> bool {
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    id.get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CVE-"))
        && id[4..].split_once('-').is_some_and(|(year, number)| {
            year.len() == 4 && digits(year) && number.len() >= 4 && digits(number)
        })
}

/// The id as the domain reads it: a CVE id in upper case, any other as written (VMT-29).
pub(crate) fn read_id(id: &str) -> Cow<'_, str> {
    if is_cve(id) && id.bytes().any(|b| b.is_ascii_lowercase()) {
        Cow::Owned(id.to_ascii_uppercase())
    } else {
        Cow::Borrowed(id)
    }
}
