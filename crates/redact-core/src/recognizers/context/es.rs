// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Spanish context terms. Unaccented spellings are listed on purpose.

use super::{Concept, ExtraPattern, Fixture};
use crate::types::EntityType;

pub const TERMS: &[(Concept, &[&str])] = &[
    (Concept::Nhs, &["seguridad social"]),
    (Concept::Patient, &["paciente"]),
    (Concept::Health, &["salud"]),
    (Concept::Address, &["dirección", "direccion"]),
    (Concept::Mail, &["correo"]),
    (Concept::Ship, &["envío", "envio"]),
    (Concept::Passport, &["pasaporte"]),
    (Concept::Travel, &["viaje"]),
    (Concept::Medical, &["médico", "medico"]),
    (Concept::Hospital, &["hospital"]),
    (Concept::Years, &["años", "anos"]),
    (Concept::Old, &["mayor"]),
    (Concept::Age, &["edad"]),
    (Concept::Driver, &["conductor"]),
    (Concept::License, &["licencia"]),
    (Concept::Dl, &["licencia de conducir"]),
    (Concept::Dmv, &["tráfico", "trafico"]),
    (Concept::StateDepartment, &["departamento de estado"]),
    (Concept::Account, &["cuenta"]),
    (Concept::Bank, &["banco"]),
    (Concept::Routing, &["enrutamiento"]),
    (Concept::Checking, &["cuenta corriente"]),
    (Concept::Savings, &["ahorros"]),
    (
        Concept::Hmpo,
        &["pasaporte británico", "pasaporte britanico"],
    ),
    (Concept::Company, &["empresa"]),
    (Concept::CompaniesHouse, &["registro mercantil"]),
    (Concept::Registration, &["registro"]),
    (Concept::Crn, &["número de empresa", "numero de empresa"]),
    (Concept::Physician, &["facultativo"]),
    (Concept::Doctor, &["doctor"]),
    (Concept::Nurse, &["enfermera", "enfermero"]),
    (Concept::Wallet, &["billetera"]),
    (Concept::Crypto, &["cripto"]),
    (Concept::Coin, &["moneda"]),
];

pub fn extras() -> Vec<ExtraPattern> {
    vec![
        ExtraPattern {
            entity: EntityType::UsBankNumber,
            regex: r"(?i)(?:cuenta\s+bancaria|n[uú]mero\s+de\s+cuenta)\s*:?\s*\d{8,17}",
            score: 0.6,
            concepts: super::en::US_BANK_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::Age,
            regex: r"(?i)\bedad\s*:?\s*\d{1,3}\b|\b\d{1,3}\s*a[nñ]os\b",
            score: 0.8,
            concepts: super::en::AGE_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::PoBox,
            regex: r"(?i)apartado\s+(?:de\s+)?correos\s+\d+",
            score: 0.85,
            concepts: super::en::PO_BOX_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::MedicalRecordNumber,
            regex: r"(?i)(?:historia\s+cl[ií]nica|n[uú]mero\s+de\s+historia)\s*:?\s*[A-Z0-9]{6,12}",
            score: 0.85,
            concepts: super::en::MRN_CONCEPTS,
        },
    ]
}

pub const FIXTURES: &[Fixture] = &[
    Fixture {
        text: "Cuenta bancaria: 841234567890",
        entity: EntityType::UsBankNumber,
        expect: true,
    },
    Fixture {
        text: "841234567890",
        entity: EntityType::UsBankNumber,
        expect: false,
    },
    Fixture {
        text: "edad: 42",
        entity: EntityType::Age,
        expect: true,
    },
    Fixture {
        text: "Apartado de correos 1234",
        entity: EntityType::PoBox,
        expect: true,
    },
    Fixture {
        text: "Historia clínica ABC123456",
        entity: EntityType::MedicalRecordNumber,
        expect: true,
    },
];
