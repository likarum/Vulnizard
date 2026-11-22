//! Password hashing (Argon2id) and opaque tokens (sessions, API tokens).
//! Tokens are random 256-bit values; only their SHA-256 is stored.

use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// NIST SP 800-63B rev. 4: fifteen characters when the password may be the only factor
pub const MIN_PASSWORD_LEN: usize = 15;
pub const MAX_PASSWORD_LEN: usize = 1024;

/// What the forms say about the rules of a new password
pub const PASSWORD_RULES: &str = "At least 15 characters. No other rule, but passwords that are easy to guess are refused.";

/// Words that the most common passwords are made of. A password made only of
/// these (with digits and symbols around) is refused, whatever its length.
const COMMON_WORDS: [&str; 96] = [
    "password", "passwort", "passwd", "motdepasse", "contrasena", "qwerty", "qwertz", "azerty", "asdf", "zxcv",
    "letmein", "welcome", "bienvenue", "admin", "administrator", "root", "login", "user", "guest", "default",
    "changeme", "change", "secret", "test", "temp", "demo", "hello", "bonjour", "iloveyou", "love",
    "monkey", "dragon", "master", "sunshine", "princess", "football", "baseball", "soccer", "hockey", "superman",
    "batman", "trustno", "shadow", "michael", "jennifer", "jordan", "killer", "ninja", "mustang", "access",
    "abc", "xyz", "pass", "word", "correct", "horse", "battery", "staple", "vulnizard", "security",
    "server", "system", "computer", "internet", "google", "facebook", "starwars", "pokemon", "minecraft", "summer",
    "winter", "spring", "autumn", "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december", "monday", "friday", "sunday", "the", "my", "me",
    "you", "is", "to", "and", "new", "old",
];

/// Rows of the usual keyboards, and the alphabet
const SEQUENCES: [&str; 6] = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "1234567890",
    "qwertyuiopasdfghjklzxcvbnm",
    "azertyuiopqsdfghjklmwxcvbn",
    "qwertzuiopasdfghjklyxcvbnm",
];

/// Reads "p@ssw0rd" as "password"
fn unleet(c: char) -> char {
    match c {
        '@' | '4' => 'a',
        '0' => 'o',
        '1' | '!' => 'i',
        '3' => 'e',
        '$' | '5' => 's',
        '7' => 't',
        _ => c,
    }
}

/// Whether `text` is a concatenation of common words
fn made_of_common_words(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut reachable = vec![false; bytes.len() + 1];
    reachable[0] = true;
    for i in 0..bytes.len() {
        if !reachable[i] {
            continue;
        }
        for word in COMMON_WORDS {
            if bytes[i..].starts_with(word.as_bytes()) {
                reachable[i + word.len()] = true;
            }
        }
    }
    reachable[bytes.len()]
}

/// Whether the text repeats one short unit ("abcabcabcabcabc", "aaaaaaaaaaaaaaa")
fn is_repetition(chars: &[char]) -> bool {
    (1..=chars.len() / 2).any(|unit| chars.iter().enumerate().all(|(i, c)| *c == chars[i % unit]))
}

/// Whether the text walks along the alphabet or a keyboard row, either way
fn is_sequence(lower: &str) -> bool {
    let reversed: String = lower.chars().rev().collect();
    SEQUENCES.iter().any(|row| {
        let looped = row.repeat(lower.len() / row.len() + 2);
        looped.contains(lower) || looped.contains(&reversed)
    })
}

/// Rules of a new password, wherever it is chosen (setup, registration,
/// change, creation by an administrator, command line). Length first, as NIST
/// SP 800-63B asks, then a refusal of what is guessed first: the username,
/// repetitions, keyboard walks and common words. No composition rule.
pub fn check_new_password(password: &str, username: &str) -> std::result::Result<(), String> {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < MIN_PASSWORD_LEN {
        return Err(format!("Password is too short: at least {MIN_PASSWORD_LEN} characters."));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err("Password is too long.".into());
    }
    let guessable = |why: &str| Err(format!("This password is too easy to guess ({why}). Choose another one."));
    let lower = password.to_lowercase();
    let lower_chars: Vec<char> = lower.chars().collect();
    if is_repetition(&lower_chars) {
        return guessable("it repeats the same few characters");
    }
    if is_sequence(&lower) {
        return guessable("it follows the alphabet or the keyboard");
    }
    // Without the username, what is left must still be a password
    let username = username.trim().to_lowercase();
    if username.chars().count() >= 3 {
        let rest = lower.replace(&username, "");
        if rest.chars().count() < 8 {
            return guessable("it is built on the username");
        }
    }
    // Letters only, read without the usual substitutions, then without digits and symbols
    let letters: String = lower.chars().map(unleet).filter(|c| c.is_alphabetic()).collect();
    let plain: String = lower.chars().filter(|c| c.is_alphabetic()).collect();
    for candidate in [&letters, &plain] {
        if candidate.chars().count() >= 3 && candidate.is_ascii() && made_of_common_words(candidate) {
            return guessable("it is made of very common words");
        }
    }
    // Digits and symbols alone around a sequence ("qwertyuiop12345!")
    if !plain.is_empty() && plain.chars().count() >= 6 && (is_sequence(&plain) || is_repetition(&plain.chars().collect::<Vec<_>>())) {
        return guessable("it follows the alphabet or the keyboard");
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hashing failed: {e}"))?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

/// Returns (plain token, hash to store)
pub fn new_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Protects password verification, the only costly unauthenticated operation:
/// bounds the number of concurrent Argon2 computations (memory/CPU) and
/// throttles repeated failures on the same username (online guessing).
pub struct LoginGuard {
    /// (running, waiting) Argon2 computations
    slots: Mutex<(usize, usize)>,
    released: Condvar,
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

/// Concurrent Argon2 computations (about 19 MiB each)
const MAX_CONCURRENT_HASHES: usize = 4;
/// Requests allowed to wait for a slot before being refused
const MAX_QUEUED_HASHES: usize = 32;
/// Wrong answers accepted on one throttling key within the window
pub const MAX_FAILURES: u32 = 10;
/// Wrong passwords accepted on one account from every client together
pub const MAX_ACCOUNT_FAILURES: u32 = 100;
/// Sign-ins one client may start (SSO, passkey) within the window
pub const MAX_STARTS: u32 = 30;
const FAILURE_WINDOW: Duration = Duration::from_secs(600);
const MAX_TRACKED_KEYS: usize = 100_000;

/// What a counter of wrong answers is attached to. The kinds never collide:
/// whatever a caller types as username, it only reaches keys of its own kind.
pub struct ThrottleKey;

impl ThrottleKey {
    fn name(username: &str) -> String {
        username.trim().to_lowercase().chars().take(64).collect()
    }

    /// Passwords tried for an account by one client (network address)
    pub fn password(client: &str, username: &str) -> String {
        format!("pw\u{1f}{}\u{1f}{}", client.chars().take(64).collect::<String>(), Self::name(username))
    }

    /// Passwords tried for an account by every client together
    pub fn account(username: &str) -> String {
        format!("account\u{1f}{}", Self::name(username))
    }

    /// Passwords typed by the holder of a session to confirm a change
    pub fn confirmation(user_id: i64) -> String {
        format!("confirm\u{1f}{user_id}")
    }

    /// Answers to the second step of an account
    pub fn second_step(user_id: i64) -> String {
        format!("mfa\u{1f}{user_id}")
    }

    /// Passwords tried from a browser that already signed in to this account
    pub fn device(mark: &str) -> String {
        format!("device\u{1f}{}", mark.chars().take(64).collect::<String>())
    }

    /// Sign-ins started (SSO, passkey) by one client
    pub fn start(client: &str) -> String {
        format!("start\u{1f}{}", client.chars().take(64).collect::<String>())
    }
}

/// Slot for one Argon2 computation, released on drop
pub struct HashSlot<'a>(&'a LoginGuard);

impl Drop for HashSlot<'_> {
    fn drop(&mut self) {
        self.0.slots.lock().unwrap_or_else(|e| e.into_inner()).0 -= 1;
        self.0.released.notify_one();
    }
}

impl Default for LoginGuard {
    fn default() -> Self {
        Self {
            slots: Mutex::new((0, 0)),
            released: Condvar::new(),
            failures: Mutex::new(HashMap::new()),
        }
    }
}

impl LoginGuard {
    /// Waits for a hashing slot; `None` when too many requests are already queued.
    pub fn slot(&self) -> Option<HashSlot<'_>> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        if slots.0 >= MAX_CONCURRENT_HASHES {
            if slots.1 >= MAX_QUEUED_HASHES {
                return None;
            }
            slots.1 += 1;
            while slots.0 >= MAX_CONCURRENT_HASHES {
                slots = self.released.wait(slots).unwrap_or_else(|e| e.into_inner());
            }
            slots.1 -= 1;
        }
        slots.0 += 1;
        Some(HashSlot(self))
    }

    /// True when this key has failed `MAX_FAILURES` times recently
    pub fn is_locked(&self, key: &str) -> bool {
        self.is_locked_at(key, MAX_FAILURES)
    }

    /// True when this key has failed `limit` times recently
    pub fn is_locked_at(&self, key: &str, limit: u32) -> bool {
        let failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        failures.get(key).is_some_and(|(n, since)| *n >= limit && since.elapsed() < FAILURE_WINDOW)
    }

    pub fn record(&self, key: &str, success: bool) {
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if success {
            failures.remove(key);
            return;
        }
        if failures.len() >= MAX_TRACKED_KEYS && !failures.contains_key(key) {
            Self::make_room(&mut failures);
        }
        let entry = failures.entry(key.to_string()).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= FAILURE_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    /// Frees space without ever forgetting a key that is locked: filling the
    /// table with made-up names must not unlock the accounts under attack.
    fn make_room(failures: &mut HashMap<String, (u32, Instant)>) {
        failures.retain(|_, (_, since)| since.elapsed() < FAILURE_WINDOW);
        if failures.len() < MAX_TRACKED_KEYS {
            return;
        }
        failures.retain(|_, (n, _)| *n >= MAX_FAILURES);
        if failures.len() < MAX_TRACKED_KEYS {
            return;
        }
        // Only locked keys are left: let go of the oldest tenth
        let mut ages: Vec<Instant> = failures.values().map(|(_, since)| *since).collect();
        ages.sort();
        let cutoff = ages[ages.len() / 10];
        failures.retain(|_, (_, since)| *since > cutoff);
    }
}

/// Names shown as the author of automatic or non-interactive changes in the
/// audit trail: no account may carry them.
const RESERVED_USERNAMES: [&str; 10] =
    ["system", "cli", "mcp", "mcp-stdio", "rescan", "unknown", "default", "config", "inventory", "scim"];

pub fn is_reserved_username(username: &str) -> bool {
    RESERVED_USERNAMES.iter().any(|r| r.eq_ignore_ascii_case(username.trim()))
}

/// Local username derived from an identity provider's name ("Jane Doe",
/// "jdoe@corp.example"): the part before `@`, lowercased, unsafe characters
/// replaced. `None` when nothing usable remains.
pub fn derive_username(source: &str) -> Option<String> {
    let local = source.split('@').next().unwrap_or("");
    let slug: String = local
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' })
        .take(32)
        .collect();
    let slug = slug.trim_matches(|c| c == '-' || c == '.').to_string();
    (valid_slug(&slug, 3, 32) && !is_reserved_username(&slug)).then_some(slug)
}

/// Usernames, organization and project names created from the web UI
pub fn valid_slug(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !s.starts_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_passwords_are_long_and_not_what_is_guessed_first() {
        let ok = |p: &str| check_new_password(p, "alice");
        // Length, counted in characters, is the first rule; there is no composition rule
        assert!(ok("short-pass-0001").is_ok());
        assert!(ok("short-pass-001").unwrap_err().contains("at least 15"));
        assert!(ok("éééé-èèèè-àà-ùù").is_ok());
        assert!(ok("tout en minuscules sans chiffre").is_ok());
        assert!(ok("493 817 265 004 1").is_ok());
        assert!(ok(&"x".repeat(MAX_PASSWORD_LEN + 1)).unwrap_err().contains("too long"));
        // What everyone tries first, however long
        for guessable in [
            "aaaaaaaaaaaaaaaa",
            "abcabcabcabcabcabc",
            "1212121212121212",
            "123456789012345",
            "0987654321098765",
            "abcdefghijklmnopqrst",
            "qwertyuiopasdfgh",
            "QwertyUiopAsdfgh",
            "azertyuiopqsdfgh",
            "lkjhgfdsapoiuytr",
            "passwordpassword",
            "PasswordPassword1",
            "P@ssw0rdP@ssw0rd",
            "password123456789",
            "!!!password2024!!!",
            "iloveyouiloveyou",
            "welcometomysystem",
            "correcthorsebatterystaple",
            "Correct Horse Battery Staple",
            "adminadminadmin1",
            "letmein-letmein-1",
            "vulnizardvulnizard",
            "qwertyuiop12345!",
            "changeme-changeme",
            "Summer2024Winter2025",
        ] {
            assert!(ok(guessable).unwrap_err().contains("easy to guess"), "{guessable} is accepted");
        }
        // The username with a little around it
        assert!(ok("alice-alice-2024").unwrap_err().contains("username"));
        assert!(check_new_password("Jean.Dupont!2024", "jean.dupont").unwrap_err().contains("username"));
        assert!(check_new_password("jd-and-a-real-long-secret", "jd").is_ok());
        assert!(ok("alice likes 7 green teapots").is_ok());
        // Ordinary passphrases and random strings pass
        for fine in [
            "a-long-password",
            "audit-pass-0001",
            "trois petits chats gris",
            "Xk7#mP2$vL9@qR4",
            "gravel-otter-plume-27",
            "mon chien dort sous la table",
        ] {
            assert!(ok(fine).is_ok(), "{fine} is refused: {:?}", ok(fine));
        }
    }


    #[test]
    fn password_roundtrip() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("x", "not-a-hash"));
    }

    #[test]
    fn tokens_are_unique_and_hashed() {
        let (a, ha) = new_token();
        let (b, _) = new_token();
        assert_ne!(a, b);
        assert_eq!(ha, hash_token(&a));
        assert_ne!(a, ha);
    }

    #[test]
    fn repeated_failures_lock_a_key_until_success_or_expiry() {
        let guard = LoginGuard::default();
        let key = |name: &str| ThrottleKey::password("10.0.0.1", name);
        for _ in 0..MAX_FAILURES - 1 {
            guard.record(&key("Alice"), false);
        }
        assert!(!guard.is_locked(&key("alice")));
        guard.record(&key("alice "), false);
        assert!(guard.is_locked(&key("ALICE")));
        assert!(!guard.is_locked(&key("bob")));
        // Another client is not locked out by this one, up to the limit of the account
        assert!(!guard.is_locked(&ThrottleKey::password("10.0.0.2", "alice")));
        assert!(!guard.is_locked_at(&ThrottleKey::account("alice"), MAX_ACCOUNT_FAILURES));
        guard.record(&key("alice"), true);
        assert!(!guard.is_locked(&key("alice")));
    }

    #[test]
    fn a_typed_username_never_reaches_another_kind_of_key() {
        // Whatever is typed in the login form only makes password keys
        for typed in ["mfa:5", "mfa\u{1f}5", "confirm\u{1f}5", "account\u{1f}alice"] {
            let key = ThrottleKey::password("10.0.0.1", typed);
            assert!(key.starts_with("pw\u{1f}"));
            assert_ne!(key, ThrottleKey::second_step(5));
            assert_ne!(key, ThrottleKey::confirmation(5));
            assert_ne!(key, ThrottleKey::account("alice"));
        }
    }

    #[test]
    fn filling_the_table_does_not_unlock_anyone() {
        let guard = LoginGuard::default();
        let victim = ThrottleKey::password("10.0.0.1", "victim");
        for _ in 0..MAX_FAILURES {
            guard.record(&victim, false);
        }
        assert!(guard.is_locked(&victim));
        for i in 0..MAX_TRACKED_KEYS + 500 {
            guard.record(&ThrottleKey::password("10.0.0.9", &format!("made-up-{i}")), false);
        }
        assert!(guard.is_locked(&victim));
        assert!(guard.failures.lock().unwrap().len() <= MAX_TRACKED_KEYS);
    }

    #[test]
    fn hashing_slots_are_bounded() {
        let guard = LoginGuard::default();
        let held: Vec<_> = (0..MAX_CONCURRENT_HASHES).map(|_| guard.slot().unwrap()).collect();
        guard.slots.lock().unwrap().1 = MAX_QUEUED_HASHES;
        assert!(guard.slot().is_none());
        guard.slots.lock().unwrap().1 = 0;
        drop(held);
        assert!(guard.slot().is_some());
    }

    #[test]
    fn audit_actor_names_are_reserved() {
        for name in ["system", "System", "cli", "MCP", "unknown", " default "] {
            assert!(is_reserved_username(name), "{name}");
        }
        assert!(!is_reserved_username("systems") && !is_reserved_username("alice"));
    }

    #[test]
    fn usernames_are_derived_from_provider_names() {
        assert_eq!(derive_username("Jane Doe").as_deref(), Some("jane-doe"));
        assert_eq!(derive_username("JDoe@corp.example").as_deref(), Some("jdoe"));
        assert_eq!(derive_username("../x"), None);
        assert_eq!(derive_username("system@corp.example"), None);
        assert_eq!(derive_username(""), None);
    }

    #[test]
    fn slug_validation() {
        assert!(valid_slug("my-org_1", 1, 64));
        assert!(!valid_slug("a b", 1, 64));
        assert!(!valid_slug("../x", 1, 64));
        assert!(!valid_slug("", 1, 64));
    }
}
