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

    // Secrets and credentials
    PrivateKey,
    JwtToken,
    AwsAccessKey,
    GithubToken,
    GitlabToken,
    SlackToken,
    SlackWebhook,
    StripeApiKey,
    GoogleApiKey,
    OpenAiApiKey,
    AnthropicApiKey,
    NpmToken,
    PyPiToken,
    SendGridApiKey,
    TwilioApiKey,
    TelegramBotToken,
    HashicorpVaultToken,
    DatabaseConnectionString,
    GenericSecret,

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
            EntityType::PrivateKey => "PRIVATE_KEY",
            EntityType::JwtToken => "JWT_TOKEN",
            EntityType::AwsAccessKey => "AWS_ACCESS_KEY",
            EntityType::GithubToken => "GITHUB_TOKEN",
            EntityType::GitlabToken => "GITLAB_TOKEN",
            EntityType::SlackToken => "SLACK_TOKEN",
            EntityType::SlackWebhook => "SLACK_WEBHOOK",
            EntityType::StripeApiKey => "STRIPE_API_KEY",
            EntityType::GoogleApiKey => "GOOGLE_API_KEY",
            EntityType::OpenAiApiKey => "OPENAI_API_KEY",
            EntityType::AnthropicApiKey => "ANTHROPIC_API_KEY",
            EntityType::NpmToken => "NPM_TOKEN",
            EntityType::PyPiToken => "PYPI_TOKEN",
            EntityType::SendGridApiKey => "SENDGRID_API_KEY",
            EntityType::TwilioApiKey => "TWILIO_API_KEY",
            EntityType::TelegramBotToken => "TELEGRAM_BOT_TOKEN",
            EntityType::HashicorpVaultToken => "HASHICORP_VAULT_TOKEN",
            EntityType::DatabaseConnectionString => "DATABASE_CONNECTION_STRING",
            EntityType::GenericSecret => "GENERIC_SECRET",
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
                | EntityType::PrivateKey
                | EntityType::JwtToken
                | EntityType::AwsAccessKey
                | EntityType::GithubToken
                | EntityType::GitlabToken
                | EntityType::SlackToken
                | EntityType::SlackWebhook
                | EntityType::StripeApiKey
                | EntityType::GoogleApiKey
                | EntityType::OpenAiApiKey
                | EntityType::AnthropicApiKey
                | EntityType::NpmToken
                | EntityType::PyPiToken
                | EntityType::SendGridApiKey
                | EntityType::TwilioApiKey
                | EntityType::TelegramBotToken
                | EntityType::HashicorpVaultToken
                | EntityType::DatabaseConnectionString
                | EntityType::GenericSecret
        )
    }

    /// Prefixed / structured secret types (not `GENERIC_SECRET`).
    pub fn is_named_secret(&self) -> bool {
        matches!(
            self,
            EntityType::PrivateKey
                | EntityType::JwtToken
                | EntityType::AwsAccessKey
                | EntityType::GithubToken
                | EntityType::GitlabToken
                | EntityType::SlackToken
                | EntityType::SlackWebhook
                | EntityType::StripeApiKey
                | EntityType::GoogleApiKey
                | EntityType::OpenAiApiKey
                | EntityType::AnthropicApiKey
                | EntityType::NpmToken
                | EntityType::PyPiToken
                | EntityType::SendGridApiKey
                | EntityType::TwilioApiKey
                | EntityType::TelegramBotToken
                | EntityType::HashicorpVaultToken
                | EntityType::DatabaseConnectionString
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

            // Secrets - anchored, high-precision prefixes
            EntityType::PrivateKey => 100,
            EntityType::JwtToken => 95,
            EntityType::AwsAccessKey => 100,
            EntityType::GithubToken => 100,
            EntityType::GitlabToken => 100,
            EntityType::SlackToken => 100,
            EntityType::SlackWebhook => 100,
            EntityType::StripeApiKey => 100,
            EntityType::GoogleApiKey => 100,
            EntityType::OpenAiApiKey => 95,
            EntityType::AnthropicApiKey => 100,
            EntityType::NpmToken => 100,
            EntityType::PyPiToken => 100,
            EntityType::SendGridApiKey => 100,
            EntityType::TwilioApiKey => 90,
            EntityType::TelegramBotToken => 100,
            EntityType::HashicorpVaultToken => 100,
            EntityType::DatabaseConnectionString => 95,
            EntityType::GenericSecret => 35,

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
        // A hex run can also occur inside a PEM key body, so the whole
        // private key block should win over any hash detected within it.
        if *self == EntityType::Md5Hash {
            return matches!(
                other,
                EntityType::Sha1Hash | EntityType::Sha256Hash | EntityType::PrivateKey
            );
        }
        if *self == EntityType::Sha1Hash {
            return matches!(other, EntityType::Sha256Hash | EntityType::PrivateKey);
        }
        if *self == EntityType::Sha256Hash {
            return *other == EntityType::PrivateKey;
        }

        // An Anthropic key (`sk-ant-...`) also matches the generic OpenAI
        // `sk-...` shape; the more specific Anthropic match must win.
        if *self == EntityType::OpenAiApiKey {
            return *other == EntityType::AnthropicApiKey;
        }

        // Slack incoming webhook URLs are also valid generic URLs / domains.
        if *self == EntityType::Url {
            return *other == EntityType::SlackWebhook;
        }
        if *self == EntityType::DomainName {
            return matches!(
                other,
                EntityType::SlackWebhook | EntityType::DatabaseConnectionString
            );
        }

        // GENERIC_SECRET loses to every named secret type.
        if *self == EntityType::GenericSecret {
            return other.is_named_secret();
        }

        // Hash / GUID detections on a secret-keyword assignment lose to
        // GENERIC_SECRET. Default policy allows hashes and GUIDs, so the
        // reverse would un-redact `api_key=<32 hex>`.
        if matches!(
            self,
            EntityType::Guid | EntityType::Md5Hash | EntityType::Sha1Hash | EntityType::Sha256Hash
        ) {
            return *other == EntityType::GenericSecret;
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
            "US_ZIP_CODE" => EntityType::UsZipCode,
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
            "MEDICAL_RECORD_NUMBER" => EntityType::MedicalRecordNumber,
            "PASSPORT_NUMBER" => EntityType::PassportNumber,
            "AGE" => EntityType::Age,
            "ISBN" => EntityType::Isbn,
            "PO_BOX" => EntityType::PoBox,
            "CRYPTO_WALLET" => EntityType::CryptoWallet,
            "BTC_ADDRESS" => EntityType::BtcAddress,
            "ETH_ADDRESS" => EntityType::EthAddress,
            "GUID" => EntityType::Guid,
            "MAC_ADDRESS" => EntityType::MacAddress,
            "MD5_HASH" => EntityType::Md5Hash,
            "SHA1_HASH" => EntityType::Sha1Hash,
            "SHA256_HASH" => EntityType::Sha256Hash,
            "PRIVATE_KEY" => EntityType::PrivateKey,
            "JWT_TOKEN" => EntityType::JwtToken,
            "AWS_ACCESS_KEY" => EntityType::AwsAccessKey,
            "GITHUB_TOKEN" => EntityType::GithubToken,
            "GITLAB_TOKEN" => EntityType::GitlabToken,
            "SLACK_TOKEN" => EntityType::SlackToken,
            "SLACK_WEBHOOK" => EntityType::SlackWebhook,
            "STRIPE_API_KEY" => EntityType::StripeApiKey,
            "GOOGLE_API_KEY" => EntityType::GoogleApiKey,
            "OPENAI_API_KEY" => EntityType::OpenAiApiKey,
            "ANTHROPIC_API_KEY" => EntityType::AnthropicApiKey,
            "NPM_TOKEN" => EntityType::NpmToken,
            "PYPI_TOKEN" => EntityType::PyPiToken,
            "SENDGRID_API_KEY" => EntityType::SendGridApiKey,
            "TWILIO_API_KEY" => EntityType::TwilioApiKey,
            "TELEGRAM_BOT_TOKEN" => EntityType::TelegramBotToken,
            "HASHICORP_VAULT_TOKEN" => EntityType::HashicorpVaultToken,
            "DATABASE_CONNECTION_STRING" => EntityType::DatabaseConnectionString,
            "GENERIC_SECRET" => EntityType::GenericSecret,
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

    fn all_named_variants() -> Vec<EntityType> {
        vec![
            EntityType::Person,
            EntityType::Location,
            EntityType::Organization,
            EntityType::DateTime,
            EntityType::EmailAddress,
            EntityType::PhoneNumber,
            EntityType::IpAddress,
            EntityType::Url,
            EntityType::DomainName,
            EntityType::CreditCard,
            EntityType::IbanCode,
            EntityType::UsBankNumber,
            EntityType::UsSsn,
            EntityType::UsDriverLicense,
            EntityType::UsPassport,
            EntityType::UsZipCode,
            EntityType::UkNhs,
            EntityType::UkNino,
            EntityType::UkPostcode,
            EntityType::UkDriverLicense,
            EntityType::UkPassportNumber,
            EntityType::UkPhoneNumber,
            EntityType::UkMobileNumber,
            EntityType::UkSortCode,
            EntityType::UkCompanyNumber,
            EntityType::MedicalLicense,
            EntityType::MedicalRecordNumber,
            EntityType::PassportNumber,
            EntityType::Age,
            EntityType::Isbn,
            EntityType::PoBox,
            EntityType::CryptoWallet,
            EntityType::BtcAddress,
            EntityType::EthAddress,
            EntityType::Guid,
            EntityType::MacAddress,
            EntityType::Md5Hash,
            EntityType::Sha1Hash,
            EntityType::Sha256Hash,
            EntityType::PrivateKey,
            EntityType::JwtToken,
            EntityType::AwsAccessKey,
            EntityType::GithubToken,
            EntityType::GitlabToken,
            EntityType::SlackToken,
            EntityType::SlackWebhook,
            EntityType::StripeApiKey,
            EntityType::GoogleApiKey,
            EntityType::OpenAiApiKey,
            EntityType::AnthropicApiKey,
            EntityType::NpmToken,
            EntityType::PyPiToken,
            EntityType::SendGridApiKey,
            EntityType::TwilioApiKey,
            EntityType::TelegramBotToken,
            EntityType::HashicorpVaultToken,
            EntityType::DatabaseConnectionString,
            EntityType::GenericSecret,
        ]
    }

    #[test]
    fn as_str_from_round_trip() {
        for variant in all_named_variants() {
            let label = variant.as_str().to_string();
            let parsed = EntityType::from(label.clone());
            assert_eq!(parsed, variant, "round-trip failed for {label}");
        }
    }
}
