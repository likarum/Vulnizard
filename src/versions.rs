//! Ordering of versions, and whether a version falls in what a source
//! records as affected.

/// A version starts with a number (after an optional `v`); a commit hash does not count
pub fn is_version(text: &str) -> bool {
    let text = text.trim_start_matches(['v', 'V']);
    let hash = text.len() >= 20 && text.chars().all(|c| c.is_ascii_hexdigit());
    !hash && text.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// Orders two versions (semantic versioning, and close enough for PyPI,
/// Maven and what NVD records): numbers first, then a pre-release (`-rc1`,
/// `b2`, `.dev3`) comes before its release, and anything else after it
/// (`.post1`, `p2`, the `g` of OpenSSL 1.0.1g).
pub fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    fn split(version: &str) -> (Vec<u64>, String) {
        let version = version.trim().trim_start_matches(['v', 'V']);
        // Build metadata does not order versions
        let version = version.split('+').next().unwrap_or(version);
        let mut numbers = Vec::new();
        let mut rest = version;
        loop {
            let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
            if digits == 0 {
                break;
            }
            numbers.push(rest[..digits].parse().unwrap_or(u64::MAX));
            rest = &rest[digits..];
            match rest.strip_prefix('.') {
                Some(next) if next.starts_with(|c: char| c.is_ascii_digit()) => rest = next,
                _ => break,
            }
        }
        (numbers, rest.trim_start_matches(['-', '.', '_']).to_lowercase())
    }
    // 0 for a pre-release, 1 for the release itself, 2 for what follows it
    fn rank(suffix: &str) -> u8 {
        const PRE: [&str; 10] = ["alpha", "beta", "rc", "cr", "pre", "preview", "dev", "snapshot", "canary", "nightly"];
        const FINAL: [&str; 3] = ["final", "release", "ga"];
        let word: String = suffix.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
        // 1.0a1, 1.0b2, 1.0c1 and 2.0-M3 are pre-releases; a letter alone is
        // a later patch (OpenSSL 1.0.1g)
        let numbered = suffix[word.len()..].starts_with(|c: char| c.is_ascii_digit());
        if suffix.is_empty() || FINAL.contains(&word.as_str()) {
            1
        } else if PRE.contains(&word.as_str()) || (numbered && ["a", "b", "c", "m"].contains(&word.as_str())) {
            0
        } else {
            2
        }
    }
    // Text and numbers of a suffix, numbers compared as numbers: rc10 after rc9
    fn chunks(suffix: &str) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        let mut chars = suffix.chars().peekable();
        while chars.peek().is_some() {
            let mut word = String::new();
            while let Some(c) = chars.next_if(|c| !c.is_ascii_digit()) {
                if c.is_ascii_alphabetic() {
                    word.push(c);
                }
            }
            let mut digits = String::new();
            while let Some(c) = chars.next_if(|c| c.is_ascii_digit()) {
                digits.push(c);
            }
            out.push((word, digits.parse().unwrap_or(0)));
        }
        out
    }
    let ((na, sa), (nb, sb)) = (split(a), split(b));
    for i in 0..na.len().max(nb.len()) {
        let order = na.get(i).copied().unwrap_or(0).cmp(&nb.get(i).copied().unwrap_or(0));
        if order != Ordering::Equal {
            return order;
        }
    }
    match (rank(&sa), rank(&sb)) {
        (1, 1) => Ordering::Equal,
        (ra, rb) => ra.cmp(&rb).then_with(|| chunks(&sa).cmp(&chunks(&sb))),
    }
}

/// A product name as it is compared: case and separators do not count
/// (`Home-Assistant`, `home_assistant` and `homeassistant` are one product),
/// everything else does (`podman` is not `podman_desktop`).
pub fn name_key(name: &str) -> String {
    name.chars().filter(|c| !matches!(c, '_' | '-' | '.' | ' ')).flat_map(char::to_lowercase).collect()
}

/// Whether a product is a variant of another by its name: the same name
/// followed by a separator and something else (`nginx_open_source`,
/// `nginx-plus` for `nginx`; not `nginxui`, nor `openssl.js` for `openssl`).
pub fn is_name_variant(product: &str, name: &str) -> bool {
    let (product, name) = (product.to_lowercase(), name.to_lowercase());
    product.strip_prefix(name.as_str()).is_some_and(|rest| rest.len() > 1 && rest.starts_with(['_', '-', ' ']))
}

/// What a source says of a version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The version is in what the source gives as affected
    Affected,
    /// The source gives versions, and this one is not among them: before the
    /// first one affected, or from the one that fixes it on
    NotAffected,
    /// The version is past the last one the source gives as affected ("up to
    /// 5.2 included"). That names the last version known to be affected, not
    /// a fix: sources often write the latest release of the day there.
    PastLastAffected,
    /// The source says every version is affected and that no fix exists
    NoFix,
    /// The source gives nothing to judge by: no version recorded, or none asked
    Unknown,
}

/// For one CVE, what several sources (or several entries of one) say
/// together. Better a false alert than a missed one, but not against a
/// source that knows:
/// - a version inside an affected range is affected;
/// - else a source naming the fix, or a first affected version, decides
///   against those that say "every version";
/// - else "past the last version known to be affected" is enough when nothing
///   else is said, but not against a source saying no fix exists;
/// - and when no source gives any version, the application is kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Verdicts {
    affected: bool,
    not_affected: bool,
    past_last: bool,
    no_fix: bool,
}

impl Verdicts {
    pub fn add(&mut self, verdict: Verdict) {
        match verdict {
            Verdict::Affected => self.affected = true,
            Verdict::NotAffected => self.not_affected = true,
            Verdict::PastLastAffected => self.past_last = true,
            Verdict::NoFix => self.no_fix = true,
            Verdict::Unknown => {}
        }
    }

    pub fn affected(&self) -> bool {
        self.affected || (!self.not_affected && (self.no_fix || !self.past_last))
    }

    /// Whether a source places the version inside an affected range (as
    /// opposed to an application kept because no source says enough)
    pub fn in_a_range(&self) -> bool {
        self.affected
    }
}

/// What a product entry of a CVE says of a version: an exact version
/// (`version`), or a range whose bounds may each be included or not (NVD:
/// `versionStartIncluding` / `versionStartExcluding`, `versionEndIncluding` /
/// `versionEndExcluding`). `*` and `-` (version not given) without a range
/// say nothing.
pub fn product_verdict(
    query: Option<&str>,
    version: Option<&str>,
    start: Option<&str>,
    start_excluded: bool,
    end: Option<&str>,
    end_included: bool,
) -> Verdict {
    use std::cmp::Ordering::{Greater, Less};
    let Some(query) = query else {
        return Verdict::Unknown;
    };
    let version = version.unwrap_or("*");
    let yes = |affected: bool| if affected { Verdict::Affected } else { Verdict::NotAffected };
    // An exact version, or a version of that line: 2.4 covers 2.4.1
    if version != "*" && version != "-" {
        return yes(version == query || query.starts_with(&format!("{version}.")));
    }
    if start.is_none() && end.is_none() {
        return Verdict::Unknown;
    }
    let after_start = start.is_none_or(|start| match cmp(query, start) {
        Less => false,
        Greater => true,
        _ => !start_excluded,
    });
    let before_end = end.is_none_or(|end| match cmp(query, end) {
        Less => true,
        Greater => false,
        _ => end_included,
    });
    if after_start && !before_end && end_included {
        return Verdict::PastLastAffected;
    }
    yes(after_start && before_end)
}

/// Whether a version may be affected by a product entry: yes unless the
/// entry gives versions and this one is not among them.
pub fn product_affects(
    query: Option<&str>,
    version: Option<&str>,
    start: Option<&str>,
    start_excluded: bool,
    end: Option<&str>,
    end_included: bool,
) -> bool {
    !matches!(product_verdict(query, version, start, start_excluded, end, end_included), Verdict::NotAffected | Verdict::PastLastAffected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_product_name_ignores_case_and_separators_only() {
        assert_eq!(name_key("Home-Assistant"), name_key("home_assistant"));
        assert_eq!(name_key("adguard_home"), name_key("AdGuardHome"));
        assert_eq!(name_key("node.js"), "nodejs");
        assert_ne!(name_key("podman"), name_key("podman_desktop"));
        assert!(is_name_variant("nginx_open_source", "nginx") && is_name_variant("NGINX-Plus", "nginx"));
        assert!(!is_name_variant("nginx", "nginx") && !is_name_variant("nginxui", "nginx") && !is_name_variant("ingress-nginx", "nginx"));
        assert!(!is_name_variant("openssl.js", "openssl"));
    }

    #[test]
    fn a_precise_source_decides_against_one_that_says_every_version() {
        use Verdict::{Affected, NoFix, NotAffected, PastLastAffected, Unknown};
        let together = |verdicts: &[Verdict]| {
            let mut all = Verdicts::default();
            verdicts.iter().for_each(|v| all.add(*v));
            all.affected()
        };
        // Nobody gives a version: kept
        assert!(together(&[Unknown]) && together(&[Unknown, NoFix]) && together(&[NoFix]) && together(&[]));
        // A fix is named: it decides, whatever says "every version"
        assert!(!together(&[Unknown, NotAffected]) && !together(&[NotAffected, NoFix]) && !together(&[NotAffected]));
        assert!(together(&[NotAffected, Affected]) && together(&[Affected, Unknown]));
        // Past the last version known affected: enough alone, not against "no fix"
        assert!(!together(&[PastLastAffected]) && !together(&[PastLastAffected, Unknown]));
        assert!(together(&[PastLastAffected, NoFix]));
        assert!(!together(&[PastLastAffected, NoFix, NotAffected]));
    }

    #[test]
    fn versions_are_ordered() {
        use std::cmp::Ordering::{Equal, Greater, Less};
        for (a, b, expected) in [
            ("3.7.16", "3.7.3", Greater),
            ("3.7.3", "3.7.16", Less),
            ("10.0", "9.0", Greater),
            ("v3.7.3", "3.7.3", Equal),
            ("3.0", "3.0.0", Equal),
            ("3.0.0", "3.0.0-beta5", Greater),
            ("3.0.0-beta5", "3.0.0-rc1", Less),
            ("3.0.0-rc9", "3.0.0-rc10", Less),
            ("1.5.0-rc5", "1.5.0", Less),
            ("2.0.0b1", "2.0.0", Less),
            ("2.0.0.dev3", "2.0.0", Less),
            ("2.0.0.post1", "2.0.0", Greater),
            ("1.0.0+build7", "1.0.0", Equal),
            ("1.2.3.Final", "1.2.3", Equal),
            ("2.0.0-M3", "2.0.0", Less),
            ("1.0.1g", "1.0.1f", Greater),
            ("1.0.1a", "1.0.1", Greater),
            ("1.9.5p2", "1.9.5p1", Greater),
            ("1.9.17p2", "1.9.5p2", Greater),
            ("1.2.3-4", "1.2.3", Greater),
            ("2020-12-14", "2021-02-28", Less),
        ] {
            assert_eq!(cmp(a, b), expected, "{a} against {b}");
        }
    }

    #[test]
    fn a_range_includes_or_excludes_each_of_its_bounds() {
        let affects = |query: &str, start: Option<&str>, start_excluded: bool, end: Option<&str>, end_included: bool| {
            product_affects(Some(query), Some("*"), start, start_excluded, end, end_included)
        };
        // Before 1.0.1g: 1.0.1f is affected, 1.0.1g is the fix
        assert!(affects("1.0.1f", Some("1.0.1"), false, Some("1.0.1g"), false));
        assert!(!affects("1.0.1g", Some("1.0.1"), false, Some("1.0.1g"), false));
        assert!(!affects("3.6.5", Some("1.0.1"), false, Some("1.0.1g"), false));
        // Up to 2.0.1 included: 2.0.1 is the last affected version
        assert!(affects("2.0.1", Some("2.0.0"), false, Some("2.0.1"), true));
        assert!(!affects("2.0.2", Some("2.0.0"), false, Some("2.0.1"), true));
        // After 1.9.0, itself not affected
        assert!(!affects("1.9.0", Some("1.9.0"), true, Some("1.9.5p2"), false));
        assert!(affects("1.9.5p1", Some("1.9.0"), true, Some("1.9.5p2"), false));
        assert!(!affects("1.9.17p2", Some("1.9.0"), true, Some("1.9.5p2"), false));
        // From a version, without an end
        assert!(affects("1.48.0", Some("1.30.0"), false, None, false));
        assert!(!affects("1.29.0", Some("1.30.0"), false, None, false));
        // Nothing recorded (`*` or `-`), or nothing asked: nothing to judge by
        assert!(affects("1.29.0", None, false, None, false));
        assert!(product_affects(None, Some("2.0"), None, false, None, false));
        assert_eq!(product_verdict(Some("1.0"), Some("*"), None, false, None, false), Verdict::Unknown);
        assert_eq!(product_verdict(Some("1.0"), Some("-"), None, false, None, false), Verdict::Unknown);
        assert_eq!(product_verdict(None, Some("2.0"), None, false, None, false), Verdict::Unknown);
        assert_eq!(product_verdict(Some("1.0"), Some("*"), None, false, Some("2.0"), false), Verdict::Affected);
        assert_eq!(product_verdict(Some("3.0"), Some("*"), None, false, Some("2.0"), false), Verdict::NotAffected);
        assert_eq!(product_verdict(Some("3.0"), Some("*"), None, false, Some("2.0"), true), Verdict::PastLastAffected);
        assert_eq!(product_verdict(Some("0.5"), Some("*"), Some("1.0"), false, Some("2.0"), true), Verdict::NotAffected);
        // An exact version covers its line, not its neighbours
        assert!(product_affects(Some("2.4.1"), Some("2.4"), None, false, None, false));
        assert!(!product_affects(Some("2.41"), Some("2.4"), None, false, None, false));
    }
}
