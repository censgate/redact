// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Entity types supported by the PII detection engine
/// Compatible with Microsoft Presidio entity types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntityType {
    // Personal identifiers (NER-based)
    Person,
    Location,
    Organization,
    DateTime,

    // Contact information
    EmailAddress,
    PhoneNumber,
    IpAddress,
    Url,
    DomainName,

    // Financial
    CreditCard,
    Iban,
    IbanCode,
    UsBankNumber,

    // US-specific identifiers
    UsSsn,
    UsDriverLicense,
    UsPassport,
    UsZipCode,

    // UK-specific identifiers
    UkNhs,
    UkNino,
    UkPostcode,
    UkDriverLicense,
    UkPassportNumber,
    UkPhoneNumber,
    UkMobileNumber,
    UkSortCode,
    UkCompanyNumber,

    // Healthcare
    MedicalLicense,
    MedicalRecordNumber,

    // Generic identifiers
    PassportNumber, // Generic, non-country specific
    Age,
    Isbn,
    PoBox,

    // Crypto
    CryptoWallet,
    BtcAddress,
    EthAddress,

    // Technical
    Guid,
    MacAddress,
    Md5Hash,
    Sha1Hash,
    Sha256Hash,

    // Generic
    Custom(String),
}

impl EntityType {
    /// Get the string representation for the entity type
    pub fn as_str(&self) -> &str {
        match self {
            EntityType::Person => "PERSON",
            EntityType::Location => "LOCATION",
            EntityType::Organization => "ORGANIZATION",
            EntityType::DateTime => "DATE_TIME",
            EntityType::EmailAddress => "EMAIL_ADDRESS",
            EntityType::PhoneNumber => "PHONE_NUMBER",
            EntityType::IpAddress => "IP_ADDRESS",
            EntityType::Url => "URL",
            EntityType::DomainName => "DOMAIN_NAME",
            EntityType::CreditCard => "CREDIT_CARD",
            EntityType::Iban => "IBAN",
            EntityType::IbanCode => "IBAN_CODE",
            EntityType::UsBankNumber => "US_BANK_NUMBER",
            EntityType::UsSsn => "US_SSN",
            EntityType::UsDriverLicense => "US_DRIVER_LICENSE",
            EntityType::UsPassport => "US_PASSPORT",
            EntityType::UsZipCode => "US_ZIP_CODE",
            EntityType::UkNhs => "UK_NHS",
            EntityType::UkNino => "UK_NINO",
            EntityType::UkPostcode => "UK_POSTCODE",
            EntityType::UkDriverLicense => "UK_DRIVER_LICENSE",
            EntityType::UkPassportNumber => "UK_PASSPORT_NUMBER",
            EntityType::UkPhoneNumber => "UK_PHONE_NUMBER",
            EntityType::UkMobileNumber => "UK_MOBILE_NUMBER",
            EntityType::UkSortCode => "UK_SORT_CODE",
            EntityType::UkCompanyNumber => "UK_COMPANY_NUMBER",
            EntityType::MedicalLicense => "MEDICAL_LICENSE",
            EntityType::MedicalRecordNumber => "MEDICAL_RECORD_NUMBER",
            EntityType::PassportNumber => "PASSPORT_NUMBER",
            EntityType::Age => "AGE",
            EntityType::Isbn => "ISBN",
            EntityType::PoBox => "PO_BOX",
            EntityType::CryptoWallet => "CRYPTO_WALLET",
            EntityType::BtcAddress => "BTC_ADDRESS",
            EntityType::EthAddress => "ETH_ADDRESS",
            EntityType::Guid => "GUID",
            EntityType::MacAddress => "MAC_ADDRESS",
            EntityType::Md5Hash => "MD5_HASH",
            EntityType::Sha1Hash => "SHA1_HASH",
            EntityType::Sha256Hash => "SHA256_HASH",
            EntityType::Custom(name) => name,
        }
    }

    /// Get the default replacement text for this entity type
    pub fn default_replacement(&self) -> String {
        format!("[{}]", self.as_str())
    }

    /// Check if this is a high-sensitivity entity requiring elevated protection
    pub fn is_high_sensitivity(&self) -> bool {
        matches!(
            self,
            EntityType::UsSsn
                | EntityType::CreditCard
                | EntityType::UsBankNumber
                | EntityType::UsPassport
                | EntityType::UkNhs
                | EntityType::UkNino
                | EntityType::MedicalLicense
        )
    }

    /// Get the specificity score for this entity type.
    /// Higher scores indicate more specific patterns that should take precedence
    /// over generic patterns when there's an overlap.
    ///
    /// Specificity tiers:
    /// - 100: Highly specific with validation (credit cards, SSN, checksummed IDs)
    /// - 80: Country/region-specific identifiers
    /// - 60: Domain-specific but generic format (medical, crypto)
    /// - 40: Generic identifiers (email, phone, URL)
    /// - 20: Very generic patterns prone to false positives (dates, ages, hashes)
    pub fn specificity_score(&self) -> u8 {
        match self {
            // Highly specific - validated formats or unique patterns
            EntityType::CreditCard => 100,
            EntityType::UsSsn => 100,
            EntityType::IbanCode | EntityType::Iban => 95,
            EntityType::BtcAddress => 95,
            EntityType::EthAddress => 95,
            EntityType::Guid => 95,
            EntityType::MacAddress => 90,

            // Country-specific identifiers
            EntityType::UkNino => 85,
            EntityType::UkDriverLicense => 85,
            EntityType::UkNhs => 80,
            EntityType::UkPassportNumber => 75,
            EntityType::UkCompanyNumber => 75,
            EntityType::UkSortCode => 70,
            EntityType::UkPostcode => 70,
            EntityType::UkMobileNumber => 70,
            EntityType::UkPhoneNumber => 65,
            EntityType::UsDriverLicense => 70,
            EntityType::UsPassport => 70,

            // Domain-specific
            EntityType::MedicalLicense => 75,
            EntityType::MedicalRecordNumber => 70,
            EntityType::CryptoWallet => 70,
            EntityType::Isbn => 70,
            EntityType::PassportNumber => 60,

            // Generic but well-defined
            EntityType::EmailAddress => 80,
            EntityType::Url => 75,
            EntityType::DomainName => 60,
            EntityType::IpAddress => 70,
            EntityType::PhoneNumber => 50,
            EntityType::PoBox => 60,

            // NER-based (high quality when available)
            EntityType::Person => 85,
            EntityType::Organization => 85,
            EntityType::Location => 85,

            // Generic/prone to false positives
            EntityType::UsBankNumber => 40,
            EntityType::UsZipCode => 30,
            EntityType::Age => 25,
            EntityType::DateTime => 20,
            EntityType::Md5Hash => 30,
            EntityType::Sha1Hash => 30,
            EntityType::Sha256Hash => 35,

            // Custom types default to medium specificity
            EntityType::Custom(_) => 50,
        }
    }

    /// Check if this entity type should be suppressed when a more specific
    /// entity type is detected at the same location.
    ///
    /// For example, if we detect both a UK mobile number and a generic phone number
    /// at the same position, we should suppress the generic phone detection.
    pub fn is_suppressed_by(&self, other: &EntityType) -> bool {
        // Generic phone suppressed by country-specific phone types
        if *self == EntityType::PhoneNumber {
            return matches!(
                other,
                EntityType::UkPhoneNumber | EntityType::UkMobileNumber
            );
        }

        // Generic passport suppressed by country-specific
        if *self == EntityType::PassportNumber {
            return matches!(other, EntityType::UsPassport | EntityType::UkPassportNumber);
        }

        // Generic crypto wallet suppressed by specific addresses
        if *self == EntityType::CryptoWallet {
            return matches!(other, EntityType::BtcAddress | EntityType::EthAddress);
        }

        // IBAN suppressed by IBAN_CODE (they're the same)
        if *self == EntityType::Iban {
            return *other == EntityType::IbanCode;
        }

        // Hash types: longer hashes suppress shorter ones at same position
        // (SHA256 contains valid MD5 and SHA1 patterns)
        if *self == EntityType::Md5Hash {
            return matches!(other, EntityType::Sha1Hash | EntityType::Sha256Hash);
        }
        if *self == EntityType::Sha1Hash {
            return *other == EntityType::Sha256Hash;
        }

        false
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<String> for EntityType {
    fn from(s: String) -> Self {
        match s.to_uppercase().as_str() {
            "PERSON" => EntityType::Person,
            "LOCATION" => EntityType::Location,
            "ORGANIZATION" => EntityType::Organization,
            "DATE_TIME" => EntityType::DateTime,
            "EMAIL_ADDRESS" => EntityType::EmailAddress,
            "PHONE_NUMBER" => EntityType::PhoneNumber,
            "IP_ADDRESS" => EntityType::IpAddress,
            "URL" => EntityType::Url,
            "DOMAIN_NAME" => EntityType::DomainName,
            "CREDIT_CARD" => EntityType::CreditCard,
            "IBAN" | "IBAN_CODE" => EntityType::IbanCode,
            "US_SSN" => EntityType::UsSsn,
            "US_DRIVER_LICENSE" => EntityType::UsDriverLicense,
            "US_PASSPORT" => EntityType::UsPassport,
            "US_BANK_NUMBER" => EntityType::UsBankNumber,
            "UK_NHS" => EntityType::UkNhs,
            "UK_NINO" => EntityType::UkNino,
            "UK_POSTCODE" => EntityType::UkPostcode,
            "UK_DRIVER_LICENSE" => EntityType::UkDriverLicense,
            "UK_PASSPORT_NUMBER" => EntityType::UkPassportNumber,
            "UK_PHONE_NUMBER" => EntityType::UkPhoneNumber,
            "UK_MOBILE_NUMBER" => EntityType::UkMobileNumber,
            "UK_SORT_CODE" => EntityType::UkSortCode,
            "UK_COMPANY_NUMBER" => EntityType::UkCompanyNumber,
            "MEDICAL_LICENSE" => EntityType::MedicalLicense,
            "CRYPTO_WALLET" => EntityType::CryptoWallet,
            "BTC_ADDRESS" => EntityType::BtcAddress,
            "ETH_ADDRESS" => EntityType::EthAddress,
            "GUID" => EntityType::Guid,
            "MAC_ADDRESS" => EntityType::MacAddress,
            "MD5_HASH" => EntityType::Md5Hash,
            "SHA1_HASH" => EntityType::Sha1Hash,
            "SHA256_HASH" => EntityType::Sha256Hash,
            _ => EntityType::Custom(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_type_as_str() {
        assert_eq!(EntityType::Person.as_str(), "PERSON");
        assert_eq!(EntityType::UsSsn.as_str(), "US_SSN");
        assert_eq!(EntityType::EmailAddress.as_str(), "EMAIL_ADDRESS");
    }

    #[test]
    fn test_entity_type_default_replacement() {
        assert_eq!(EntityType::Person.default_replacement(), "[PERSON]");
        assert_eq!(EntityType::UsSsn.default_replacement(), "[US_SSN]");
    }

    #[test]
    fn test_high_sensitivity() {
        assert!(EntityType::UsSsn.is_high_sensitivity());
        assert!(EntityType::CreditCard.is_high_sensitivity());
        assert!(!EntityType::EmailAddress.is_high_sensitivity());
    }

    #[test]
    fn test_from_string() {
        assert_eq!(EntityType::from("PERSON".to_string()), EntityType::Person);
        assert_eq!(EntityType::from("person".to_string()), EntityType::Person);
        assert_eq!(EntityType::from("US_SSN".to_string()), EntityType::UsSsn);
    }
}
