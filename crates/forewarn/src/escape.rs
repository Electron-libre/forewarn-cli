//! The escaping of a value read from the SBOM or a feed, shared by the reports and the error lines (`report`, `main`,
//! CHK-14, MCH-18, MCH-23) and the early warning draft (`early_warning`, EWD-16) so that the writers cannot drift.

/// Passes `c` to `push`, or its escape when it is a control character (`\n`, `\u{1b}`) or a character that hides or
/// reorders text (`\u{202e}`), so that it cannot forge a line or a terminal sequence, nor reorder or hide the text
/// around it. The backslash passes: the reports escape it (`push_escaped`), the draft as Markdown punctuation (EWD-16).
pub fn escape_char(c: char, mut push: impl FnMut(char)) {
    if c.is_control() {
        c.escape_default().for_each(push);
    } else if hides_text(c) {
        c.escape_unicode().for_each(push);
    } else {
        push(c);
    }
}

/// Pushes `value` with each of its characters escaped as `escape_char` does and each backslash as `\\`, so that each
/// escape reads back to one value (CHK-14, MCH-18).
pub fn push_escaped(text: &mut String, value: &str) {
    for c in value.chars() {
        if c == '\\' {
            text.push_str("\\\\");
        } else {
            escape_char(c, |e| text.push(e));
        }
    }
}

/// `value` escaped as `push_escaped` does, for a line of standard error (MCH-23).
pub fn escaped(value: &str) -> String {
    let mut text = String::with_capacity(value.len());
    push_escaped(&mut text, value);
    text
}

/// Whether `c` hides or reorders text (EWD-16): of the general category Cf, the separator U+2028 or U+2029, or a
/// `Default_Ignorable_Code_Point`, as Unicode 16.0 lists them (`DerivedGeneralCategory.txt`,
/// `DerivedCoreProperties.txt`). A viewer draws them as nothing or uses them to reorder the text around them (the
/// "Trojan Source" trick, the tag characters of "ASCII smuggling", the Hangul fillers).
fn hides_text(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

#[cfg(test)]
mod tests {
    use super::escaped;

    // spec: EWD-16 (internal: the whole table, which no SBOM fixture would walk through)
    #[test]
    fn each_character_that_hides_text_is_escaped_and_the_letters_around_it_are_not() {
        for c in [
            '\u{ad}',
            '\u{34f}',
            '\u{600}',
            '\u{61c}',
            '\u{115f}',
            '\u{1160}',
            '\u{180e}',
            '\u{200c}',
            '\u{200d}',
            '\u{2028}',
            '\u{2029}',
            '\u{206a}',
            '\u{206f}',
            '\u{3164}',
            '\u{fe00}',
            '\u{fe0f}',
            '\u{ffa0}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{e0001}',
            '\u{e0041}',
            '\u{e007f}',
            '\u{e0100}',
            '\u{e01ef}',
        ] {
            assert_eq!(
                escaped(&c.to_string()),
                format!("\\u{{{:x}}}", u32::from(c))
            );
        }
        for c in ['a', 'é', 'ی', 'क', '\u{3165}', '\u{fffc}', '\u{1f600}'] {
            assert_eq!(escaped(&c.to_string()), c.to_string());
        }
    }
}
