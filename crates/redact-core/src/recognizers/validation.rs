// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Validation functions for PII patterns.
//!
//! These functions provide additional validation beyond regex matching
//! to reduce false positives. For example, credit card numbers must
//! pass the Luhn checksum, and IBANs have country-specific formats.

use crate::types::EntityType;
use chrono::NaiveDate;

/// Validate a detected entity value based on its type.
///
/// Returns a confidence adjustment factor:
/// - 1.0: Validation passed or not applicable
/// - 0.0-0.99: Validation partially passed (reduces confidence)
/// - 0.0: Validation failed (entity should be rejected)
pub fn validate_entity(entity_type: &EntityType, value: &str) -> f32 {
    match entity_type {
        EntityType::CreditCard => validate_credit_card(value),
        EntityType::IbanCode | EntityType::Iban => validate_iban(value),
        EntityType::UsSsn => validate_us_ssn(value),
        EntityType::UkNino => validate_uk_nino(value),
        EntityType::UkNhs => validate_uk_nhs(value),
        EntityType::Isbn => validate_isbn(value),
        EntityType::IpAddress => validate_ip_address(value),
        EntityType::DateTime => validate_date_time(value),
        EntityType::MacAddress => validate_mac_address(value),
        _ => 1.0, // No validation available
    }
}

/// Validate calendar date (and optional time) for `DATE_TIME` matches.
///
/// Accepts `YYYY-MM-DD` with optional `T`/` ` time (`HH:MM` or `HH:MM:SS`).
/// Impossible calendar dates (e.g. month 99, Feb 31) return `0.0`.
pub fn validate_date_time(value: &str) -> f32 {
    let value = value.trim();
    let date_part = value.split(['T', ' ']).next().unwrap_or(value);

    if NaiveDate::parse_from_str(date_part, "%Y-%m-%d").is_err() {
        return 0.0;
    }

    if let Some(rest) = value
        .strip_prefix(date_part)
        .map(str::trim_start)
        .filter(|s| !s.is_empty())
    {
        let time = rest.trim_start_matches(['T', ' ']);
        let ok = matches!(time.len(), 5 | 8)
            && time.as_bytes().get(2) == Some(&b':')
            && (time.len() == 5 || time.as_bytes().get(5) == Some(&b':'))
            && time.chars().all(|c| c.is_ascii_digit() || c == ':');
        if !ok {
            return 0.0;
        }
        let hh: u32 = time.get(0..2).and_then(|s| s.parse().ok()).unwrap_or(99);
        let mm: u32 = time.get(3..5).and_then(|s| s.parse().ok()).unwrap_or(99);
        if hh > 23 || mm > 59 {
            return 0.0;
        }
        if time.len() == 8 {
            let ss: u32 = time.get(6..8).and_then(|s| s.parse().ok()).unwrap_or(99);
            if ss > 59 {
                return 0.0;
            }
        }
    }

    1.0
}

/// Validate MAC addresses, rejecting null and broadcast forms.
pub fn validate_mac_address(value: &str) -> f32 {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if cleaned.len() != 12 {
        return 0.0;
    }
    if cleaned.chars().all(|c| c == '0') || cleaned.chars().all(|c| c == 'f') {
        return 0.0;
    }
    1.0
}

/// Surrounding-text precision gate applied after value validation.
///
/// Returns a multiplicative factor (`0.0` rejects, `1.0` keeps).
pub fn precision_gate(
    entity_type: &EntityType,
    text: &str,
    start: usize,
    end: usize,
    value: &str,
) -> f32 {
    let left = left_context(text, start, 50);
    let left_lower = left.to_ascii_lowercase();

    match entity_type {
        EntityType::PhoneNumber | EntityType::CreditCard => {
            if order_like_context(&left_lower) && !phone_or_card_cue(&left_lower) {
                0.0
            } else {
                1.0
            }
        }
        EntityType::Sha1Hash => {
            if left_lower.contains("commit") {
                0.0
            } else {
                1.0
            }
        }
        EntityType::DomainName => {
            if junk_domain_fragment(text, start, value) {
                0.0
            } else {
                1.0
            }
        }
        _ => {
            let _ = end;
            1.0
        }
    }
}

fn left_context(text: &str, start: usize, window: usize) -> &str {
    let ctx_start = start.saturating_sub(window);
    // Align to char boundary
    let mut idx = ctx_start;
    while idx < start && !text.is_char_boundary(idx) {
        idx += 1;
    }
    &text[idx..start]
}

fn order_like_context(left_lower: &str) -> bool {
    left_lower.contains("order_id")
        || left_lower.contains("orderid")
        || left_lower
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|tok| tok == "order")
}

fn phone_or_card_cue(left_lower: &str) -> bool {
    const CUES: &[&str] = &[
        "phone",
        "tel",
        "mobile",
        "cell",
        "call",
        "card",
        "visa",
        "mastercard",
        "amex",
        "payment",
        "credit",
    ];
    CUES.iter().any(|c| left_lower.contains(c))
}

fn junk_domain_fragment(text: &str, start: usize, value: &str) -> bool {
    if let Some(prev) = text[..start].chars().next_back() {
        if matches!(prev, '%' | '\\' | '@') {
            return true;
        }
    }
    let lower = value.to_ascii_lowercase();
    // Percent-decoded / unicode-escape debris: `40example.com`, `u0040example.com`
    if lower.starts_with(|c: char| c.is_ascii_digit()) {
        return true;
    }
    if lower.starts_with("u00") && lower.len() > 6 {
        let hex = &lower[3..5];
        if hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }
    false
}

/// Validate credit card number using Luhn algorithm.
///
/// The Luhn algorithm (mod 10) is used by most credit card issuers.
pub fn validate_credit_card(value: &str) -> f32 {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return 0.0;
    }

    if luhn_check(&digits) {
        1.0
    } else {
        0.0
    }
}

/// Luhn algorithm implementation
fn luhn_check(digits: &[u32]) -> bool {
    let mut sum = 0;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum.is_multiple_of(10)
}

/// Validate IBAN format and checksum.
///
/// IBAN validation:
/// 1. Check length matches country-specific requirements
/// 2. Verify mod-97 checksum
pub fn validate_iban(value: &str) -> f32 {
    let cleaned: String = value.chars().filter(|c| c.is_alphanumeric()).collect();

    if cleaned.len() < 15 || cleaned.len() > 34 {
        return 0.0;
    }

    // Check country code (first 2 chars must be letters)
    let country_code: String = cleaned.chars().take(2).collect();
    if !country_code.chars().all(|c| c.is_ascii_alphabetic()) {
        return 0.0;
    }

    // Validate length for known countries
    let expected_length = get_iban_length(&country_code);
    if expected_length > 0 && cleaned.len() != expected_length {
        return 0.5; // Partial match - wrong length for country
    }

    // Mod-97 checksum validation
    if validate_iban_checksum(&cleaned) {
        1.0
    } else {
        0.0
    }
}

/// Get expected IBAN length for a country
fn get_iban_length(country_code: &str) -> usize {
    match country_code.to_uppercase().as_str() {
        "GB" => 22,
        "DE" => 22,
        "FR" => 27,
        "ES" => 24,
        "IT" => 27,
        "NL" => 18,
        "BE" => 16,
        "AT" => 20,
        "CH" => 21,
        "IE" => 22,
        "PL" => 28,
        "PT" => 25,
        "SE" => 24,
        "NO" => 15,
        "DK" => 18,
        "FI" => 18,
        _ => 0, // Unknown country
    }
}

/// Validate IBAN mod-97 checksum
fn validate_iban_checksum(iban: &str) -> bool {
    // Move first 4 chars to end
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);

    // Convert letters to numbers (A=10, B=11, etc.)
    let mut numeric = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_alphabetic() {
            let val = c.to_ascii_uppercase() as u32 - 'A' as u32 + 10;
            numeric.push_str(&val.to_string());
        }
    }

    // Calculate mod 97 (handle large numbers by processing in chunks)
    let mut remainder: u64 = 0;
    for chunk in numeric.as_bytes().chunks(9) {
        let chunk_str: String = std::str::from_utf8(chunk).unwrap_or("0").to_string();
        let combined = format!("{}{}", remainder, chunk_str);
        remainder = combined.parse::<u64>().unwrap_or(0) % 97;
    }

    remainder == 1
}

/// Validate US Social Security Number format.
///
/// SSN rules:
/// - Cannot start with 000, 666, or 900-999
/// - Middle group cannot be 00
/// - Last group cannot be 0000
pub fn validate_us_ssn(value: &str) -> f32 {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return 0.0;
    }

    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);

    // Invalid area numbers
    if area == 0 || area == 666 || area >= 900 {
        return 0.0;
    }

    // Invalid group or serial
    if group == 0 || serial == 0 {
        return 0.0;
    }

    1.0
}

/// Validate UK National Insurance Number format.
///
/// NINO format: 2 letters + 6 digits + 1 letter (A-D)
/// First letter cannot be D, F, I, Q, U, V
/// Second letter cannot be D, F, I, O, Q, U, V
/// Prefixes BG, GB, NK, KN, TN, NT, ZZ are invalid
pub fn validate_uk_nino(value: &str) -> f32 {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    if cleaned.len() != 9 {
        return 0.0;
    }

    let prefix: String = cleaned.chars().take(2).collect();
    let suffix = cleaned.chars().last().unwrap_or('X');

    // Check invalid prefixes
    let invalid_prefixes = ["BG", "GB", "NK", "KN", "TN", "NT", "ZZ"];
    if invalid_prefixes.contains(&prefix.as_str()) {
        return 0.0;
    }

    // Check first letter restrictions
    let first = prefix.chars().next().unwrap_or('X');
    if "DFIQUV".contains(first) {
        return 0.0;
    }

    // Check second letter restrictions
    let second = prefix.chars().nth(1).unwrap_or('X');
    if "DFIOQUV".contains(second) {
        return 0.0;
    }

    // Check suffix is A-D
    if !"ABCD".contains(suffix) {
        return 0.0;
    }

    // Check middle 6 characters are digits
    let middle: String = cleaned.chars().skip(2).take(6).collect();
    if !middle.chars().all(|c| c.is_ascii_digit()) {
        return 0.0;
    }

    1.0
}

/// Validate UK NHS Number using mod-11 checksum.
pub fn validate_uk_nhs(value: &str) -> f32 {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 10 {
        return 0.0;
    }

    // Mod-11 checksum: multiply first 9 digits by weights 10-2
    let weights = [10, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits
        .iter()
        .take(9)
        .zip(weights.iter())
        .map(|(d, w)| d * w)
        .sum();

    let remainder = 11 - (sum % 11);
    let check_digit = if remainder == 11 { 0 } else { remainder };

    if check_digit == 10 {
        return 0.0; // Invalid NHS number
    }

    if digits[9] == check_digit {
        1.0
    } else {
        0.0
    }
}

/// Validate ISBN-10 or ISBN-13 checksum.
pub fn validate_isbn(value: &str) -> f32 {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'X' || *c == 'x')
        .collect();

    match cleaned.len() {
        10 => validate_isbn10(&cleaned),
        13 => validate_isbn13(&cleaned),
        _ => 0.0,
    }
}

fn validate_isbn10(isbn: &str) -> f32 {
    let mut sum = 0;
    for (i, c) in isbn.chars().enumerate() {
        let digit = if c == 'X' || c == 'x' {
            10
        } else {
            c.to_digit(10).unwrap_or(0)
        };
        sum += digit * (10 - i as u32);
    }

    if sum.is_multiple_of(11) {
        1.0
    } else {
        0.0
    }
}

fn validate_isbn13(isbn: &str) -> f32 {
    let digits: Vec<u32> = isbn.chars().filter_map(|c| c.to_digit(10)).collect();

    if digits.len() != 13 {
        return 0.0;
    }

    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(i, &d)| if i % 2 == 0 { d } else { d * 3 })
        .sum();

    if sum.is_multiple_of(10) {
        1.0
    } else {
        0.0
    }
}

/// Validate IPv4 address octets are in valid range.
pub fn validate_ip_address(value: &str) -> f32 {
    let octets: Vec<&str> = value.split('.').collect();

    if octets.len() != 4 {
        return 0.0;
    }

    for octet in octets {
        match octet.parse::<u32>() {
            Ok(n) if n <= 255 => continue,
            _ => return 0.0,
        }
    }

    1.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid_cards() {
        // Valid test card numbers
        assert_eq!(validate_credit_card("4532015112830366"), 1.0);
        assert_eq!(validate_credit_card("5425233430109903"), 1.0);
        assert_eq!(validate_credit_card("374245455400126"), 1.0);
    }

    #[test]
    fn test_luhn_invalid_cards() {
        assert_eq!(validate_credit_card("4532015112830367"), 0.0);
        assert_eq!(validate_credit_card("1234567890123456"), 0.0);
    }

    #[test]
    fn test_valid_ssn() {
        assert_eq!(validate_us_ssn("123-45-6789"), 1.0);
        assert_eq!(validate_us_ssn("123456789"), 1.0);
    }

    #[test]
    fn test_invalid_ssn() {
        assert_eq!(validate_us_ssn("000-12-3456"), 0.0); // Invalid area
        assert_eq!(validate_us_ssn("666-12-3456"), 0.0); // Invalid area
        assert_eq!(validate_us_ssn("900-12-3456"), 0.0); // Invalid area
        assert_eq!(validate_us_ssn("123-00-3456"), 0.0); // Invalid group
        assert_eq!(validate_us_ssn("123-45-0000"), 0.0); // Invalid serial
    }

    #[test]
    fn test_valid_uk_nino() {
        assert_eq!(validate_uk_nino("AB123456C"), 1.0);
        assert_eq!(validate_uk_nino("JG103759A"), 1.0);
    }

    #[test]
    fn test_invalid_uk_nino() {
        assert_eq!(validate_uk_nino("BG123456A"), 0.0); // Invalid prefix
        assert_eq!(validate_uk_nino("DA123456A"), 0.0); // Invalid first letter
        assert_eq!(validate_uk_nino("AB123456E"), 0.0); // Invalid suffix
    }

    #[test]
    fn test_valid_iban() {
        assert_eq!(validate_iban("GB82WEST12345698765432"), 1.0);
        assert_eq!(validate_iban("DE89370400440532013000"), 1.0);
    }

    #[test]
    fn test_invalid_iban() {
        assert_eq!(validate_iban("GB82WEST12345698765433"), 0.0); // Bad checksum
        assert_eq!(validate_iban("XX00000000000000"), 0.0);
    }

    #[test]
    fn test_valid_isbn() {
        assert_eq!(validate_isbn("0-306-40615-2"), 1.0); // ISBN-10
        assert_eq!(validate_isbn("978-0-306-40615-7"), 1.0); // ISBN-13
    }

    #[test]
    fn test_valid_ip() {
        assert_eq!(validate_ip_address("192.168.1.1"), 1.0);
        assert_eq!(validate_ip_address("0.0.0.0"), 1.0);
        assert_eq!(validate_ip_address("255.255.255.255"), 1.0);
    }

    #[test]
    fn test_invalid_ip() {
        assert_eq!(validate_ip_address("256.1.1.1"), 0.0);
        assert_eq!(validate_ip_address("1.1.1"), 0.0);
    }

    #[test]
    fn test_date_time_calendar() {
        assert_eq!(validate_date_time("2026-07-13"), 1.0);
        assert_eq!(validate_date_time("2026-07-13T08:15:30"), 1.0);
        assert_eq!(validate_date_time("2026-99-13"), 0.0);
        assert_eq!(validate_date_time("2026-02-31"), 0.0);
    }

    #[test]
    fn test_mac_null_broadcast_rejected() {
        assert_eq!(validate_mac_address("00:00:00:00:00:00"), 0.0);
        assert_eq!(validate_mac_address("ff:ff:ff:ff:ff:ff"), 0.0);
        assert_eq!(validate_mac_address("02:42:ac:11:00:02"), 1.0);
    }

    #[test]
    fn test_precision_gate_order_and_commit() {
        let phone = "order 202-555-0142";
        assert_eq!(
            precision_gate(&EntityType::PhoneNumber, phone, 6, 18, "202-555-0142"),
            0.0
        );
        let call = "Call (202) 555-0142";
        assert_eq!(
            precision_gate(&EntityType::PhoneNumber, call, 5, 19, "(202) 555-0142"),
            1.0
        );
        let card = "order_id=4111111111111111";
        assert_eq!(
            precision_gate(&EntityType::CreditCard, card, 9, 25, "4111111111111111"),
            0.0
        );
        let commit = "commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            precision_gate(
                &EntityType::Sha1Hash,
                commit,
                7,
                47,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            0.0
        );
    }

    #[test]
    fn test_precision_gate_junk_domain() {
        let text = "contact=ada%40example.com";
        assert_eq!(
            precision_gate(&EntityType::DomainName, text, 12, 25, "40example.com"),
            0.0
        );
        let ok = "visit example.com today";
        assert_eq!(
            precision_gate(&EntityType::DomainName, ok, 6, 17, "example.com"),
            1.0
        );
    }
}
