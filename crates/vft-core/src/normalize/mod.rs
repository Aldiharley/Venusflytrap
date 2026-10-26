//! FR1 — Normalizer: iterative decode to a fixpoint, Unicode folding
//! (NFKC + full-width + a confusable/homoglyph skeleton), and
//! whitespace/comment canonicalization.
//!
//! The job is to peel disguises off a payload before the graph engine sees it,
//! while staying bounded so a decode bomb can never hang the process.

mod confusables;

use base64::Engine as _;

use crate::graph::sinks::{self, Disabled};

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
    /// Normalization cut text: the input exceeded `max_payload`, or NFKC expansion did.
    pub truncated: bool,
    /// Folded chars this normalization produced (at most `max_payload`): what it
    /// costs against the per-request `shield.max_normalize_work`.
    pub work: usize,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub max_payload: usize,
    pub decode_cap: u8,
    pub deep_threshold: u8,
    /// Decoders switched off (`shield.disabled`).
    pub disabled: Disabled,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_payload: 64 * 1024,
            decode_cap: 14,
            deep_threshold: 3,
            disabled: Disabled::default(),
        }
    }
}

/// Normalize a single field value: [`decode`] it, then [`fold`] the whole
/// decoded text.
pub fn normalize(input: &str, opts: &Options) -> Normalized {
    let d = decode(input, opts);
    fold(&d, &d.text, opts)
}

/// A piece after the decode stage, before Unicode folding: bounded to
/// `max_payload` chars and decoded to a fixpoint. Decoding never adds chars, so
/// `text` has at most `max_payload` chars. When the fold of `text` is cut, the
/// shield splits `text` (not the raw piece, whose encoding a split can break) and
/// folds each part with [`fold`] / [`fold_unless_cut`].
#[derive(Debug, Clone)]
pub struct Decoded {
    /// The decoded text.
    pub text: String,
    /// Flags of the whole piece (mixed script, deep nesting).
    flags: Flags,
    /// Number of decode layers peeled.
    pub layers: u8,
    /// The raw piece was longer than `max_payload` chars.
    pub truncated: bool,
}

/// The decode stage of [`normalize`]: bound, flag mixed script, decode to a fixpoint.
pub fn decode(input: &str, opts: &Options) -> Decoded {
    // Bound the work first.
    let input_chars = input.chars().count();
    let truncated = input_chars > opts.max_payload;
    let bounded: String = input.chars().take(opts.max_payload).collect();

    let mut flags = Flags::default();
    if count_scripts(&bounded) >= 2 {
        flags.mixed_script = true;
    }

    let (text, layers) = decode_fixpoint_with(&bounded, opts.decode_cap, &opts.disabled);
    if layers >= opts.deep_threshold {
        flags.deep_nesting = true;
    }
    Decoded { text, flags, layers, truncated }
}

/// Fold and canonicalize `text`, which is `d.text` or a part of it, carrying
/// `d`'s flags and layers. The result is cut (`truncated`) when the fold passes
/// `max_payload` chars or the raw piece was bounded.
pub fn fold(d: &Decoded, text: &str, opts: &Options) -> Normalized {
    finish(fold_stage(d, text, opts))
}

/// [`fold`] for a part that is split when cut: a cut stops after folding and
/// returns `Err(work)`, skipping canonicalization of text nobody reads.
pub fn fold_unless_cut(d: &Decoded, text: &str, opts: &Options) -> Result<Normalized, usize> {
    let f = fold_stage(d, text, opts);
    if f.truncated {
        Err(f.work)
    } else {
        Ok(finish(f))
    }
}

/// Bounded, decoded and folded text, before whitespace/comment canonicalization.
struct Folded {
    folded: String,
    flags: Flags,
    layers: u8,
    truncated: bool,
    work: usize,
}

fn fold_stage(d: &Decoded, text: &str, opts: &Options) -> Folded {
    // Cap post-fold length: NFKC can expand some code points many-fold, so bound
    // the string again before tokenization (L3). Folding stops at the cap, so a
    // cut costs O(max_payload), not O(18 x input).
    let (folded, cut) = fold_unicode_capped(text, opts.max_payload);
    let work = folded.chars().count();
    Folded { folded, flags: d.flags.clone(), layers: d.layers, truncated: d.truncated || cut, work }
}

fn finish(f: Folded) -> Normalized {
    let mut flags = f.flags;
    let canon = canonicalize_ws_comments(&f.folded, &mut flags);
    Normalized {
        text: canon.to_lowercase(),
        cased: canon,
        layers: f.layers,
        flags,
        truncated: f.truncated,
        work: f.work,
    }
}

/// NFKC expands one code point into at most 18 (U+FDFA); decoding never adds chars.
pub const MAX_FOLD_EXPANSION: usize = 18;

/// An upper bound on [`Normalized::work`] for an input of `input_chars` chars.
pub fn work_bound(input_chars: usize, max_payload: usize) -> usize {
    input_chars.min(max_payload).saturating_mul(MAX_FOLD_EXPANSION).min(max_payload)
}

/// Characters shared by neighbouring chunks (and by the halves of a split piece),
/// so any span of up to this many chars lies whole in one chunk. This makes
/// chunking lossless for text, not for constructs: a construct whose span is
/// longer (e.g. `union` + 400 spaces + `select`, `%20` x 150 or `/*x400*/` filler,
/// `<svg` + 400 spaces + `onload=`) can still straddle a seam and be missed.
/// Stitching seams in normalized-token space is a Plan B item.
pub const CHUNK_OVERLAP: usize = 256;

/// Split `s` into chunks of at most `max` chars that overlap by
/// [`CHUNK_OVERLAP`] chars. A string of at most `max` chars is one chunk.
pub fn chunks(s: &str, max: usize) -> Vec<&str> {
    chunk_ranges(s, max).into_iter().map(|r| &s[r]).collect()
}

/// The byte ranges of [`chunks`]: ascending, on char boundaries, and each one
/// ends after the previous one, so `end - previous_end` is the bytes it adds.
/// A `max` of 0 is treated as 1.
pub fn chunk_ranges(s: &str, max: usize) -> Vec<std::ops::Range<usize>> {
    let max = max.max(1);
    let idx: Vec<usize> = s.char_indices().map(|(i, _)| i).collect();
    let n = idx.len();
    if n <= max {
        return std::iter::once(0..s.len()).collect();
    }
    let step = max.saturating_sub(CHUNK_OVERLAP).max(1);
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let end = (start + max).min(n);
        let lo = idx[start];
        let hi = if end == n { s.len() } else { idx[end] };
        out.push(lo..hi);
        if end == n {
            break;
        }
        start += step;
    }
    out
}

/// Apply decoders repeatedly until a pass makes no change or the cap is hit.
pub fn decode_fixpoint(input: &str, cap: u8) -> (String, u8) {
    decode_fixpoint_with(input, cap, &Disabled::default())
}

/// [`decode_fixpoint`] with some decoders switched off.
pub fn decode_fixpoint_with(input: &str, cap: u8, disabled: &Disabled) -> (String, u8) {
    let mut cur = input.to_string();
    let mut layers = 0u8;
    for _ in 0..cap {
        let next = decode_once(&cur, disabled);
        if next == cur {
            break;
        }
        cur = next;
        layers += 1;
    }
    (cur, layers)
}

/// Percent-decode to bytes, then UTF-8 lossily. One invalid byte (`%ff`) yields
/// U+FFFD instead of disabling URL decoding for the whole field (H1).
pub fn percent_decode_lossy(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One decode pass: whole-string base64 first (if it decodes, the pass ends
/// there), else URL -> HTML entity -> \xNN/\uNNNN -> whole-string base64 again.
/// Each stage only applies if it changes the string.
fn decode_once(s: &str, disabled: &Disabled) -> String {
    // Whole-field base64 first: '+' is a base64 character, and the URL step
    // below turns it into a space (L5).
    if !disabled.is(&sinks::DECODE_B64_WHOLE) {
        if let Some(d) = try_whole_base64(s) {
            return d;
        }
    }

    let mut out = s.to_string();

    // URL / percent decoding.
    if (out.contains('%') || out.contains('+')) && !disabled.is(&sinks::DECODE_PERCENT_LOSSY) {
        let d = percent_decode_lossy(&out.replace('+', " "));
        if d != out {
            out = d;
        }
    }

    // HTML entities (named + numeric).
    if out.contains('&') && !disabled.is(&sinks::DECODE_ENTITY) {
        let d = decode_html_entities(&out);
        if d != out {
            out = d;
        }
    }

    // \xNN and \uNNNN escapes.
    if (out.contains("\\x") || out.contains("\\u")) && !disabled.is(&sinks::DECODE_ESC_HEX) {
        let d = decode_backslash_escapes(&out);
        if d != out {
            out = d;
        }
    }

    // Base64, only when the whole token looks like base64 and decodes to text.
    if !disabled.is(&sinks::DECODE_B64_WHOLE) {
        if let Some(d) = try_whole_base64(&out) {
            if d != out {
                out = d;
            }
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

/// The first `cap` chars of [`fold_unicode`], and whether the full fold is longer.
/// Folding stops at char `cap + 1`, so the cost is bounded by `cap`, not by the
/// input's expansion.
pub fn fold_unicode_capped(s: &str, cap: usize) -> (String, bool) {
    use unicode_normalization::UnicodeNormalization;
    let mut out = String::new();
    for (i, c) in s.nfkc().enumerate() {
        if i == cap {
            return (out, true);
        }
        out.push(confusables::skeleton_char(c));
    }
    (out, false)
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
    fn chunks_cover_everything_with_overlap() {
        let s: String = "ab€".repeat(1000); // 3,000 chars, multi-byte included
        let cs = chunks(&s, 1024);
        assert!(cs.iter().all(|c| c.chars().count() <= 1024));
        assert!(s.starts_with(cs[0]) && s.ends_with(cs[cs.len() - 1]));
        for w in cs.windows(2) {
            let tail: String = w[0].chars().rev().take(CHUNK_OVERLAP).collect::<Vec<_>>().into_iter().rev().collect();
            assert!(w[1].starts_with(&tail), "chunks must overlap by CHUNK_OVERLAP chars");
        }
        assert_eq!(chunks("short", 1024), vec!["short"]);
    }

    #[test]
    fn a_zero_chunk_size_does_not_panic() {
        // Reachable only through an unvalidated `max_payload = 0` (`Shield::new`).
        let cs = chunks("ab\u{20ac}", 0);
        assert_eq!(cs.concat(), "ab\u{20ac}");
        assert!(cs.iter().all(|c| c.chars().count() == 1));
        assert_eq!(chunks("", 0), vec![""]);
    }

    #[test]
    fn base64_with_plus_decodes() {
        // base64 of `<svg onload=alert(1)>>` contains '+'
        let n = norm("PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+Pg==");
        assert!(n.text.contains("<svg onload=alert(1)>"), "got: {}", n.text);
    }

    #[test]
    fn decoders_can_be_disabled() {
        let opts = Options { disabled: Disabled::resolve(&["decode.entity".into()]), ..Options::default() };
        assert!(normalize("&lt;script&gt;", &opts).text.contains("&lt;script&gt;"));
        let opts = Options { disabled: Disabled::resolve(&["decode.esc-hex".into()]), ..Options::default() };
        assert!(normalize("\\x3cscript", &opts).text.contains("\\x3cscript"));
    }

    #[test]
    fn one_bad_byte_does_not_disable_url_decoding() {
        let n = norm("admin%27%20or%201%3D1--%20&x=%ff");
        assert!(n.text.contains("admin' or 1=1"), "got: {}", n.text);
    }

    #[test]
    fn percent_decode_lossy_cases() {
        assert_eq!(percent_decode_lossy("a%41%2"), "aA%2");
        assert_eq!(percent_decode_lossy("%ff"), "\u{fffd}");
        assert_eq!(percent_decode_lossy("%zz"), "%zz");
    }

    #[test]
    fn disabling_percent_decoding_leaves_the_field_encoded() {
        let opts = Options { disabled: Disabled::resolve(&["decode.percent-lossy".to_string()]), ..Options::default() };
        assert_eq!(normalize("a%41", &opts).text, "a%41");
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
    fn capped_fold_matches_the_full_fold() {
        for s in ["", "abc", "\u{FDFA}\u{FDFA}x", "\u{FF41}\u{0430}e\u{301}", "\u{FB01}\u{2460}"] {
            let full: Vec<char> = fold_unicode(s).chars().collect();
            for cap in 0..=full.len() + 2 {
                let want: String = full.iter().take(cap).collect();
                assert_eq!(fold_unicode_capped(s, cap), (want, full.len() > cap), "{s:?} cap {cap}");
            }
        }
    }

    #[test]
    fn normalize_cuts_exactly_when_the_fold_exceeds_the_cap() {
        let opts = Options { max_payload: 1024, ..Options::default() };
        let fdfa = "\u{FDFA}".repeat(56); // folds to 1,008 chars
        let fits = normalize(&format!("{fdfa}{}", "a".repeat(16)), &opts);
        assert!(!fits.truncated);
        assert_eq!(fits.work, 1024);
        let cut = normalize(&format!("{fdfa}{}", "a".repeat(17)), &opts);
        assert!(cut.truncated);
        assert_eq!(cut.work, 1024);
        assert_eq!(normalize("abc", &opts).work, 3);
        let uncut = format!("{fdfa}{}", "a".repeat(16));
        let d = decode(&uncut, &opts);
        let n = fold_unless_cut(&d, &d.text, &opts).map(|n| n.text);
        assert_eq!(n, Ok(normalize(&uncut, &opts).text));
        let d = decode(&format!("{fdfa}{}", "a".repeat(17)), &opts);
        assert_eq!(fold_unless_cut(&d, &d.text, &opts).map(|n| n.work), Err(1024));
    }

    #[test]
    fn a_decoded_part_folds_with_the_pieces_flags() {
        // Halves of a decoded piece keep its layers and flags; only the fold differs.
        let d = decode("%3Csvg%20onload%3Dalert(1)%3E\u{0430}", &Options::default());
        assert_eq!(d.layers, 1);
        let part = fold(&d, &d.text[..4], &Options::default());
        assert_eq!(part.text, "<svg");
        assert_eq!(part.layers, 1);
        assert!(part.flags.mixed_script);
        assert!(!part.truncated);
    }

    #[test]
    fn work_bound_covers_the_largest_expansion() {
        for k in [0usize, 1, 10, 56, 57, 2000] {
            let s = "\u{FDFA}".repeat(k);
            let opts = Options { max_payload: 1024, ..Options::default() };
            assert!(normalize(&s, &opts).work <= work_bound(k, 1024), "k {k}");
        }
    }

    #[test]
    fn decode_is_bounded() {
        let bomb = "%25".repeat(10_000);
        let (_out, layers) = decode_fixpoint(&bomb, 14);
        assert!(layers <= 14);
    }
}
