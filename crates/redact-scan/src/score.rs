// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Name and type heuristics for layer 0.

use redact_core::EntityType;

/// Map a column name token to an entity type and confidence.
pub fn name_entity(column: &str) -> Option<(EntityType, f32)> {
    let n = normalize(column);
    let rules: &[(&str, EntityType, f32)] = &[
        ("email", EntityType::EmailAddress, 0.85),
        ("e_mail", EntityType::EmailAddress, 0.85),
        ("ssn", EntityType::UsSsn, 0.9),
        ("social_security", EntityType::UsSsn, 0.9),
        ("dob", EntityType::DateTime, 0.7),
        ("date_of_birth", EntityType::DateTime, 0.75),
        ("birth_date", EntityType::DateTime, 0.75),
        ("phone", EntityType::PhoneNumber, 0.8),
        ("mobile", EntityType::PhoneNumber, 0.7),
        ("addr", EntityType::Location, 0.55),
        ("address", EntityType::Location, 0.6),
        ("tax_id", EntityType::UsSsn, 0.65),
        ("iban", EntityType::IbanCode, 0.9),
        ("passport", EntityType::PassportNumber, 0.8),
        ("mrn", EntityType::MedicalRecordNumber, 0.8),
        ("medical_record", EntityType::MedicalRecordNumber, 0.8),
        ("first_name", EntityType::Person, 0.7),
        ("last_name", EntityType::Person, 0.7),
        ("full_name", EntityType::Person, 0.7),
        ("credit_card", EntityType::CreditCard, 0.9),
        ("card_number", EntityType::CreditCard, 0.85),
        ("ip_address", EntityType::IpAddress, 0.8),
        ("ipv4", EntityType::IpAddress, 0.8),
        ("ipv6", EntityType::IpAddress, 0.8),
    ];
    let mut best: Option<(EntityType, f32, usize)> = None;
    for (needle, ty, conf) in rules {
        if n == *needle || n.contains(needle) {
            let cand = (ty.clone(), *conf, needle.len());
            let take = match &best {
                None => true,
                Some((_, bconf, blen)) => {
                    *conf > *bconf || (*conf == *bconf && needle.len() > *blen)
                }
            };
            if take {
                best = Some(cand);
            }
        }
    }
    best.map(|(ty, conf, _)| (ty, conf))
}

/// True for `json` / `jsonb` (candidates only, not L0 findings).
pub fn is_json_type(udt: &str) -> bool {
    matches!(udt, "json" | "jsonb")
}

/// True for `inet` / `cidr`.
pub fn is_inet_type(udt: &str) -> bool {
    matches!(udt, "inet" | "cidr")
}

/// True for date/timestamp types.
pub fn is_date_type(udt: &str) -> bool {
    matches!(udt, "date" | "timestamp" | "timestamptz")
}

/// True for text-like types that may hold identifiers.
pub fn is_textish(udt: &str) -> bool {
    matches!(udt, "text" | "varchar" | "bpchar" | "citext")
}

fn normalize(name: &str) -> String {
    name.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_name() {
        let (ty, _) = name_entity("user_email").unwrap();
        assert_eq!(ty, EntityType::EmailAddress);
    }

    #[test]
    fn dob_name() {
        let (ty, _) = name_entity("date_of_birth").unwrap();
        assert_eq!(ty, EntityType::DateTime);
    }

    #[test]
    fn status_is_not_pii() {
        assert!(name_entity("status").is_none());
        assert!(name_entity("active").is_none());
    }

    #[test]
    fn ip_address_is_not_location() {
        let (ty, _) = name_entity("ip_address").unwrap();
        assert_eq!(ty, EntityType::IpAddress);
        let (ty, _) = name_entity("client_ipv4").unwrap();
        assert_eq!(ty, EntityType::IpAddress);
    }

    #[test]
    fn email_address_is_email_not_location() {
        let (ty, _) = name_entity("email_address").unwrap();
        assert_eq!(ty, EntityType::EmailAddress);
        let (ty, _) = name_entity("contact_email_addr").unwrap();
        assert_eq!(ty, EntityType::EmailAddress);
    }
}
