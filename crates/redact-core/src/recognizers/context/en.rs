// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! English context terms. These are the historical keyword lists.

use super::{Concept, ExtraPattern, Fixture};
use crate::types::EntityType;

pub const UK_NHS_CONCEPTS: &[Concept] = &[Concept::Nhs, Concept::Patient, Concept::Health];
pub const PO_BOX_CONCEPTS: &[Concept] = &[Concept::Address, Concept::Mail, Concept::Ship];
pub const PASSPORT_CONCEPTS: &[Concept] = &[Concept::Passport, Concept::Travel];
pub const MRN_CONCEPTS: &[Concept] = &[Concept::Patient, Concept::Medical, Concept::Hospital];
pub const AGE_CONCEPTS: &[Concept] = &[Concept::Years, Concept::Old, Concept::Age];
pub const US_DRIVER_CONCEPTS: &[Concept] =
    &[Concept::Driver, Concept::License, Concept::Dl, Concept::Dmv];
pub const US_PASSPORT_CONCEPTS: &[Concept] =
    &[Concept::Passport, Concept::Travel, Concept::StateDepartment];
pub const US_BANK_CONCEPTS: &[Concept] = &[
    Concept::Account,
    Concept::Bank,
    Concept::Routing,
    Concept::Checking,
    Concept::Savings,
];
pub const UK_PASSPORT_CONCEPTS: &[Concept] = &[Concept::Passport, Concept::Travel, Concept::Hmpo];
pub const UK_COMPANY_CONCEPTS: &[Concept] = &[
    Concept::Company,
    Concept::CompaniesHouse,
    Concept::Registration,
    Concept::Crn,
];
pub const MEDICAL_LICENSE_CONCEPTS: &[Concept] = &[
    Concept::License,
    Concept::Medical,
    Concept::Physician,
    Concept::Doctor,
    Concept::Nurse,
];
pub const CRYPTO_CONCEPTS: &[Concept] = &[
    Concept::Wallet,
    Concept::Crypto,
    Concept::Address,
    Concept::Coin,
];

pub const TERMS: &[(Concept, &[&str])] = &[
    (Concept::Nhs, &["NHS"]),
    (Concept::Patient, &["patient"]),
    (Concept::Health, &["health"]),
    (Concept::Address, &["address"]),
    (Concept::Mail, &["mail"]),
    (Concept::Ship, &["ship"]),
    (Concept::Passport, &["passport"]),
    (Concept::Travel, &["travel"]),
    (Concept::Medical, &["medical"]),
    (Concept::Hospital, &["hospital"]),
    (Concept::Years, &["years"]),
    (Concept::Old, &["old"]),
    (Concept::Age, &["age"]),
    (Concept::Driver, &["driver"]),
    (Concept::License, &["license"]),
    (Concept::Dl, &["DL"]),
    (Concept::Dmv, &["DMV"]),
    (Concept::StateDepartment, &["state department"]),
    (Concept::Account, &["account"]),
    (Concept::Bank, &["bank"]),
    (Concept::Routing, &["routing"]),
    (Concept::Checking, &["checking"]),
    (Concept::Savings, &["savings"]),
    (Concept::Hmpo, &["HMPO"]),
    (Concept::Company, &["company"]),
    (Concept::CompaniesHouse, &["companies house"]),
    (Concept::Registration, &["registration"]),
    (Concept::Crn, &["CRN"]),
    (Concept::Physician, &["physician"]),
    (Concept::Doctor, &["doctor"]),
    (Concept::Nurse, &["nurse"]),
    (Concept::Wallet, &["wallet"]),
    (Concept::Crypto, &["crypto"]),
    (Concept::Coin, &["coin"]),
];

pub fn extras() -> Vec<ExtraPattern> {
    Vec::new()
}

pub const FIXTURES: &[Fixture] = &[
    Fixture {
        text: "account bank routing checking savings 841234567890",
        entity: EntityType::UsBankNumber,
        expect: true,
    },
    Fixture {
        text: "841234567890",
        entity: EntityType::UsBankNumber,
        expect: false,
    },
    Fixture {
        text: "age: 42",
        entity: EntityType::Age,
        expect: true,
    },
    Fixture {
        text: "PO BOX 1234",
        entity: EntityType::PoBox,
        expect: true,
    },
];
