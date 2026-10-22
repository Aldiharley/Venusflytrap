//! FR1 — Normalizer: iterative decode to a fixpoint, Unicode folding
//! (NFKC + full-width + a confusable/homoglyph skeleton), and
//! whitespace/comment canonicalization.
//!
//! The job is to peel disguises off a payload before the graph engine sees it,
//! while staying bounded so a decode bomb can never hang the process.

mod confusables;

use base64::Engine as _;

/// Flags raised during normalization — themselves weak signals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub deep_nesting: bool,
    pub mixed_script: bool,
    pub conditional_comment: bool,
    pub had_comment: bool,
}

#[derive(Debug, Clone)]
pub struct Normalized {
    /// Fully decoded + comment-stripped text, lowercased for matching.
    pub text: String,
    /// Decoded text with original case preserved (for logging/XSS casing).
    pub cased: String,
    /// Number of decode layers peeled.
    pub layers: u8,
    pub flags: Flags,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub max_payload: usize,
    pub decode_cap: u8,
    pub deep_threshold: u8,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_payload: 64 * 1024,
            decode_cap: 14,
            deep_threshold: 3,
        }
    }
}

/// Normalize a single field value.
pub fn normalize(input: &str, opts: &Options) -> Normalized {
    // Bound the work first.
    let bounded: String = input.chars().take(opts.max_payload).collect();

    let mut flags = Flags::default();
    if count_scripts(&bounded) >= 2 {
        flags.mixed_script = true;
    }

    let (decoded, layers) = decode_fixpoint(&bounded, opts.decode_cap);
    if layers >= opts.deep_threshold {
        flags.deep_nesting = true;
    }

    let mut folded = fold_unicode(&decoded);
    // Cap post-fold length: NFKC can expand some code points many-fold, so bound
    // the string again before tokenization (L3).
    if folded.chars().count() > opts.max_payload {
        folded = folded.chars().take(opts.max_payload).collect();
    }
    let canon = canonicalize_ws_comments(&folded, &mut flags);

    Normalized {
        text: canon.to_lowercase(),
        cased: canon,
        layers,
        flags,
    }
}

/// Apply decoders repeatedly until a pass makes no change or the cap is hit.
pub fn decode_fixpoint(input: &str, cap: u8) -> (String, u8) {
    let mut cur = input.to_string();
    let mut layers = 0u8;
    for _ in 0..cap {
        let next = decode_once(&cur);
        if next == cur {
            break;
        }
        cur = next;
        layers += 1;
    }
    (cur, layers)
}

/// One decode pass: URL -> HTML entity -> \xNN/\uNNNN -> whole-string base64.
/// Each stage only applies if it changes the string.
fn decode_once(s: &str) -> String {
    let mut out = s.to_string();

    // URL / percent decoding.
    if out.contains('%') || out.contains('+') {
        let replaced = out.replace('+', " ");
        if let Ok(dec) = percent_encoding::percent_decode_str(&replaced).decode_utf8() {
            let d = dec.into_owned();
            if d != out {
                out = d;
            }
        }
    }

    // HTML entities (named + numeric).
    if out.contains('&') {
        let d = decode_html_entities(&out);
        if d != out {
            out = d;
        }
    }

    // \xNN and \uNNNN escapes.
    if out.contains("\\x") || out.contains("\\u") {
        let d = decode_backslash_escapes(&out);
        if d != out {
            out = d;
        }
    }

    // Base64, only when the whole token looks like base64 and decodes to text.
    if let Some(d) = try_whole_base64(&out) {
        if d != out {
            out = d;
        }
    }

    out
}

fn decode_html_entities(s: &str) -> String {
    // Char-based so arbitrary (possibly invalid-looking) UTF-8 never causes a
    // mid-code-point slice.
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        if chars[i] == '&' {
            // Find a ';' within a bounded window (entities are short).
            let mut j = i + 1;
            let limit = (i + 12).min(n);
            while j < limit && chars[j] != ';' {
                j += 1;
            }
            if j < limit && chars[j] == ';' && j > i + 1 {
                let ent: String = chars[i + 1..j].iter().collect();
                let decoded = if let Some(hex) =
                    ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X"))
                {
                    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                } else if let Some(dec) = ent.strip_prefix('#') {
                    dec.parse::<u32>().ok().and_then(char::from_u32)
                } else {
                    named_entity(&ent)
                };
                if let Some(c) = decoded {
                    out.push(c);
                    i = j + 1;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn named_entity(name: &str) -> Option<char> {
    Some(match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        "sol" => '/',
        "colon" => ':',
        "lpar" => '(',
        "rpar" => ')',
        "nbsp" => ' ',
        _ => return None,
    })
}

fn decode_backslash_escapes(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let hexn = |a: usize, b: usize| -> Option<u32> {
        if b > n {
            return None;
        }
        let h: String = chars[a..b].iter().collect();
        if h.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&h, 16).ok()
        } else {
            None
        }
    };
    while i < n {
        if chars[i] == '\\' && i + 1 < n {
            match chars[i + 1] {
                'x' | 'X' => {
                    if let Some(v) = hexn(i + 2, i + 4) {
                        if let Some(c) = char::from_u32(v) {
                            out.push(c);
                            i += 4;
                            continue;
                        }
                    }
                }
                'u' | 'U' => {
                    if let Some(v) = hexn(i + 2, i + 6) {
                        if let Some(c) = char::from_u32(v) {
                            out.push(c);
                            i += 6;
                            continue;
                        }
                    }
                }
                _ => {}
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn try_whole_base64(s: &str) -> Option<String> {
    let t = s.trim();
    // Heuristic: reasonably long, base64 alphabet only, length multiple of 4.
    if t.len() < 8 || !t.len().is_multiple_of(4) {
        return None;
    }
    if !t
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
    {
        return None;
    }
    // Must contain at least one non-alpha hint to avoid decoding ordinary words,
    // OR be clearly not a plain word (mixed case + digits).
    let decoded = base64::engine::general_purpose::STANDARD.decode(t).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    // Only accept if the result is printable and differs meaningfully.
    if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') && text != s {
        Some(text)
    } else {
        None
    }
}

/// NFKC + full-width fold + confusable skeleton.
pub fn fold_unicode(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let nfkc: String = s.nfkc().collect();
    nfkc.chars().map(confusables::skeleton_char).collect()
}

fn count_scripts(s: &str) -> usize {
    let mut latin = false;
    let mut cyrillic = false;
    let mut greek = false;
    for c in s.chars() {
        let u = c as u32;
        if c.is_ascii_alphabetic() || (0x00C0..=0x024F).contains(&u) {
            latin = true;
        } else if (0x0400..=0x04FF).contains(&u) {
            cyrillic = true;
        } else if (0x0370..=0x03FF).contains(&u) {
            greek = true;
        }
    }
    [latin, cyrillic, greek].iter().filter(|x| **x).count()
}

/// Collapse whitespace, strip SQL comments, flag conditional comments.
///
/// Char-based (UTF-8 safe) and with per-comment conditional handling: the
/// conditional flag describes the comment currently being processed, it is not
/// sticky across comments. This closes the H1 panic (a later plain `/**/` after
/// a `/*! */` used to slice with conditional-form offsets).
pub fn canonicalize_ws_comments(s: &str, flags: &mut Flags) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        // /* ... */  (and /*! ... */ conditional)
        if chars[i] == '/' && i + 1 < n && chars[i + 1] == '*' {
            flags.had_comment = true;
            let conditional = i + 2 < n && chars[i + 2] == '!';
            if conditional {
                flags.conditional_comment = true;
            }
            // find closing "*/"
            let mut j = i + 2;
            let mut close = None;
            while j + 1 < n {
                if chars[j] == '*' && chars[j + 1] == '/' {
                    close = Some(j);
                    break;
                }
                j += 1;
            }
            match close {
                Some(c) => {
                    if conditional {
                        // keep the enclosed SQL (`/*!…*/`), surrounded by spaces
                        let inner_start = (i + 3).min(c);
                        out.push(' ');
                        for ch in &chars[inner_start..c] {
                            out.push(*ch);
                        }
                        out.push(' ');
                    } else {
                        out.push(' ');
                    }
                    i = c + 2;
                    continue;
                }
                None => break, // unterminated comment: drop the rest
            }
        }
        // -- line comment
        if chars[i] == '-' && i + 1 < n && chars[i + 1] == '-' {
            flags.had_comment = true;
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            out.push(' ');
            continue;
        }
        // # line comment — only when preceded by whitespace (so "#ff0000" colors,
        // "#hashtag", and URL fragments survive; `… 1=1 #x` still strips) (L4).
        if chars[i] == '#' && i > 0 && chars[i - 1].is_whitespace() {
            flags.had_comment = true;
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            out.push(' ');
            continue;
        }
        if chars[i].is_whitespace() {
            if !out.ends_with(' ') {
                out.push(' ');
            }
        } else {
            out.push(chars[i]);
        }
        i += 1;
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> Normalized {
        normalize(s, &Options::default())
    }

    #[test]
    fn url_decodes_union_select() {
        let n = norm("%55NION%20%53ELECT");
        assert!(n.text.contains("union select"), "got: {}", n.text);
        assert!(n.layers >= 1);
    }

    #[test]
    fn double_encoded_is_peeled() {
        // %2553 -> %53 -> S
        let n = norm("%2555NION");
        assert!(n.text.contains("union"), "got: {}", n.text);
        assert!(n.layers >= 2, "layers: {}", n.layers);
        assert!(n.flags.deep_nesting || n.layers >= 2);
    }

    #[test]
    fn fullwidth_folds_to_ascii() {
        // Full-width "SELECT"
        let n = norm("\u{ff33}\u{ff25}\u{ff2c}\u{ff25}\u{ff23}\u{ff34}");
        assert!(n.text.contains("select"), "got: {}", n.text);
    }

    #[test]
    fn cyrillic_homoglyph_folds() {
        // 'о' (Cyrillic) 'r' -> "or"
        let n = norm("\u{043e}r 1=1");
        assert!(n.text.contains("or 1=1"), "got: {}", n.text);
        assert!(n.flags.mixed_script);
    }

    #[test]
    fn html_entities_decoded() {
        let n = norm("&lt;script&gt;");
        assert!(n.text.contains("<script>"), "got: {}", n.text);
    }

    #[test]
    fn sql_comment_stripped_but_conditional_kept() {
        let mut f = Flags::default();
        let out = canonicalize_ws_comments("UNION/**/SELECT", &mut f);
        assert_eq!(out.to_lowercase(), "union select");
        assert!(f.had_comment);

        let mut f2 = Flags::default();
        let out2 = canonicalize_ws_comments("/*!UNION*/ SELECT", &mut f2);
        assert!(out2.to_lowercase().contains("union"));
        assert!(f2.conditional_comment);
    }

    #[test]
    fn mixed_comments_do_not_panic() {
        // H1 regression: a conditional comment followed by an empty/plain comment,
        // and a multibyte char right after `/*`, must not panic.
        for s in [
            "/*!a*/x/**/",
            "/*!a*/\u{20ac}/*\u{20ac}*/",
            "/**/",
            "/*!*/",
            "a /*! union */ b /**/ c",
            "/*unterminated",
        ] {
            let mut f = Flags::default();
            let _ = canonicalize_ws_comments(s, &mut f);
        }
    }

    #[test]
    fn hash_color_survives_but_trailing_comment_strips() {
        let mut f = Flags::default();
        assert_eq!(canonicalize_ws_comments("#ff0000", &mut f), "#ff0000");
        let mut f2 = Flags::default();
        let out = canonicalize_ws_comments("1=1 #dropme", &mut f2);
        assert_eq!(out, "1=1");
        assert!(f2.had_comment);
    }

    #[test]
    fn decode_is_bounded() {
        let bomb = "%25".repeat(10_000);
        let (_out, layers) = decode_fixpoint(&bomb, 14);
        assert!(layers <= 14);
    }
}
