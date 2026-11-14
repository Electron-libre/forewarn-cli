//! The escaping of a value read from the SBOM or a feed, shared by the reports and the error lines (`report`, `main`,
//! CHK-14, MCH-18, MCH-23) and the early warning draft (`early_warning`, EWD-16) so that the writers cannot drift.

/// Passes `c` to `push`, or its escape when it is a control character (`\n`, `\u{1b}`) or a bidirectional or
/// invisible formatting character (`\u{202e}`), so that it cannot forge a line or a terminal sequence, nor reorder or
/// hide the text around it.
pub fn escape_char(c: char, mut push: impl FnMut(char)) {
    if c.is_control() {
        c.escape_default().for_each(push);
    } else if is_formatting(c) {
        c.escape_unicode().for_each(push);
    } else {
        push(c);
    }
}

/// Pushes `value` with each of its characters escaped as `escape_char` does (CHK-14, MCH-18).
pub fn push_escaped(text: &mut String, value: &str) {
    for c in value.chars() {
        escape_char(c, |e| text.push(e));
    }
}

/// `value` escaped as `escape_char` does, for a line of standard error (MCH-23).
pub fn escaped(value: &str) -> String {
    let mut text = String::with_capacity(value.len());
    push_escaped(&mut text, value);
    text
}

/// Whether `c` is a bidirectional, zero-width or separator formatting character, which a viewer draws as nothing or
/// uses to reorder the text around it (the "Trojan Source" trick).
fn is_formatting(c: char) -> bool {
    matches!(
        c,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
    )
}
