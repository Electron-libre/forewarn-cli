//! The characters of a value read from the SBOM or a feed that the writers of the CLI escape, shared by the reports
//! (`report`, CHK-14, MCH-18, MCH-23) and the early warning draft (`early_warning`, EWD-16) so that they cannot drift.

/// Whether `c` is a bidirectional, zero-width or separator formatting character, which a viewer draws as nothing or
/// uses to reorder the text around it (the "Trojan Source" trick).
pub fn is_formatting(c: char) -> bool {
    matches!(
        c,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
    )
}
