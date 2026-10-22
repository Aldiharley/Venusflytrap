//! A pragmatic subset of the Unicode UTS#39 confusables table: map common
//! Cyrillic/Greek/look-alike code points to their Latin ASCII skeleton so a
//! homoglyph attack (e.g. Cyrillic 'о' for Latin 'o') collapses to the same
//! token stream the backend would see. This is deliberately a curated subset,
//! not the full table — it covers the letters attackers actually substitute in
//! SQL/JS keywords.

/// Map a single character to its Latin skeleton where a well-known confusable
/// exists; otherwise return the character unchanged.
pub fn skeleton_char(c: char) -> char {
    match c {
        // Cyrillic lowercase look-alikes
        '\u{0430}' => 'a', // а
        '\u{0435}' => 'e', // е
        '\u{043e}' => 'o', // о
        '\u{0440}' => 'p', // р
        '\u{0441}' => 'c', // с
        '\u{0443}' => 'y', // у
        '\u{0445}' => 'x', // х
        '\u{0456}' => 'i', // і
        '\u{0458}' => 'j', // ј
        '\u{0501}' => 'd', // ԁ
        '\u{043d}' => 'h', // н (visually h-ish in some fonts)
        // Cyrillic uppercase look-alikes
        '\u{0410}' => 'A',
        '\u{0415}' => 'E',
        '\u{041e}' => 'O',
        '\u{0420}' => 'P',
        '\u{0421}' => 'C',
        '\u{0425}' => 'X',
        '\u{0412}' => 'B',
        '\u{041c}' => 'M',
        '\u{041d}' => 'H',
        '\u{041a}' => 'K',
        '\u{0422}' => 'T',
        // Greek look-alikes
        '\u{03bf}' => 'o', // ο
        '\u{03b1}' => 'a', // α
        '\u{03c1}' => 'p', // ρ
        '\u{03bd}' => 'v', // ν
        '\u{0391}' => 'A',
        '\u{0392}' => 'B',
        '\u{0395}' => 'E',
        '\u{039f}' => 'O',
        '\u{03a1}' => 'P',
        '\u{03a4}' => 'T',
        '\u{03a7}' => 'X',
        // Fullwidth letters/digits are handled by NFKC already, but keep a few
        // common punctuation confusables:
        '\u{2044}' => '/', // fraction slash
        '\u{2215}' => '/', // division slash
        '\u{FF0F}' => '/', // fullwidth solidus (NFKC usually covers, belt+braces)
        _ => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_confusables() {
        assert_eq!(skeleton_char('\u{043e}'), 'o');
        assert_eq!(skeleton_char('\u{0430}'), 'a');
    }

    #[test]
    fn passes_through_ascii() {
        for c in "abcdefg0123 <>/'\"".chars() {
            assert_eq!(skeleton_char(c), c);
        }
    }
}
