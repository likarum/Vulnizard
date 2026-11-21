//! Second factor of local accounts: time-based one-time passwords (RFC 6238,
//! the "authenticator app" codes) and single-use recovery codes. Passkeys are
//! handled by `web::mfa` with the `webauthn-rs` library.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

/// Seconds a code stays valid
const PERIOD: u64 = 30;
const DIGITS: u32 = 6;
/// Number of recovery codes given at once
pub const RECOVERY_CODES: usize = 10;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding (what authenticator apps expect)
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes().filter(|c| *c != b'=' && *c != b' ') {
        let value = BASE32.iter().position(|b| *b == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// New random secret (160 bits), base32-encoded
pub fn new_secret() -> String {
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

/// Time step of a Unix timestamp
pub fn step_at(unix_seconds: u64) -> u64 {
    unix_seconds / PERIOD
}

pub fn current_step() -> u64 {
    step_at(chrono::Utc::now().timestamp().max(0) as u64)
}

/// Code of a time step (HOTP of RFC 4226 with the step as counter)
pub fn code_at(secret: &str, step: u64) -> Option<String> {
    let key = base32_decode(secret)?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
    Some(format!("{:0width$}", binary % 10u32.pow(DIGITS), width = DIGITS as usize))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Checks a code against the current step and its two neighbours (clock
/// drift). Returns the matching step, which must be greater than the last
/// accepted one: a code is never accepted twice.
pub fn verify(secret: &str, code: &str, now_step: u64, last_step: u64) -> Option<u64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    (now_step.saturating_sub(1)..=now_step + 1)
        .filter(|step| *step > last_step)
        .find(|step| code_at(secret, *step).is_some_and(|expected| constant_time_eq(expected.as_bytes(), code.as_bytes())))
}

/// What the authenticator app reads from the QR code
pub fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        enc(issuer),
        enc(account),
        enc(issuer)
    )
}

/// QR code of a text, as an inline SVG element
pub fn qr_svg(text: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let svg = code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    // Keep the element only: the XML prolog has no place inside a page
    svg.find("<svg").map(|start| svg[start..].to_string())
}

/// Single-use recovery codes, e.g. `k3f9a-zq2xw` (50 bits each)
pub fn new_recovery_codes() -> Vec<String> {
    const ALPHABET: &[u8; 32] = b"abcdefghjkmnpqrstuvwxyz23456789x";
    let mut rng = rand::thread_rng();
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut bytes = [0u8; 10];
            rng.fill_bytes(&mut bytes);
            let chars: String = bytes.iter().map(|b| ALPHABET[(b & 31) as usize] as char).collect();
            format!("{}-{}", &chars[..5], &chars[5..])
        })
        .collect()
}

/// Recovery code as typed (case, spaces and the dash do not matter)
pub fn normalize_recovery_code(code: &str) -> String {
    let compact: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();
    if compact.len() == 10 {
        format!("{}-{}", &compact[..5], &compact[5..])
    } else {
        compact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_the_rfc_6238_vectors() {
        // RFC 6238 appendix B, SHA-1, secret "12345678901234567890" (8 digits there, the last 6 here)
        let secret = base32_encode(b"12345678901234567890");
        assert_eq!(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&secret).unwrap(), b"12345678901234567890");
        for (time, code) in [(59u64, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")] {
            assert_eq!(code_at(&secret, step_at(time)).unwrap(), code);
        }
    }

    #[test]
    fn a_code_is_accepted_once_within_one_step_of_drift() {
        let secret = new_secret();
        let now = 1000;
        let code = code_at(&secret, now).unwrap();
        assert_eq!(verify(&secret, &code, now, 0), Some(now));
        assert_eq!(verify(&secret, &format!(" {} {} ", &code[..3], &code[3..]), now + 1, 0), Some(now));
        // Too old, already used, malformed
        assert_eq!(verify(&secret, &code, now + 2, 0), None);
        assert_eq!(verify(&secret, &code, now, now), None);
        assert_eq!(verify(&secret, "12345", now, 0), None);
        assert_eq!(verify(&secret, "abcdef", now, 0), None);
    }

    #[test]
    fn recovery_codes_are_distinct_and_normalized() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), RECOVERY_CODES);
        assert_eq!(normalize_recovery_code(&codes[0].to_uppercase().replace('-', " ")), codes[0]);
    }

    #[test]
    fn the_qr_code_is_an_inline_svg_of_the_uri() {
        let uri = otpauth_uri("Vulnizard", "alice@x", "ABC");
        assert!(uri.starts_with("otpauth://totp/Vulnizard:alice%40x?secret=ABC&issuer=Vulnizard"));
        let svg = qr_svg(&uri).unwrap();
        assert!(svg.starts_with("<svg") && !svg.contains("style="));
    }
}
