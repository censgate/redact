// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Simplified Chinese context terms.
//!
//! Chinese is not space-delimited, so terms stay long enough to be distinctive
//! and are matched as substrings.

use super::{Concept, ExtraPattern, Fixture};
use crate::types::EntityType;

pub const TERMS: &[(Concept, &[&str])] = &[
    (Concept::Nhs, &["国民保健"]),
    (Concept::Patient, &["患者"]),
    (Concept::Health, &["健康"]),
    (Concept::Address, &["地址"]),
    (Concept::Mail, &["邮件"]),
    (Concept::Ship, &["邮寄"]),
    (Concept::Passport, &["护照"]),
    (Concept::Travel, &["旅行"]),
    (Concept::Medical, &["医疗"]),
    (Concept::Hospital, &["医院"]),
    (Concept::Years, &["岁数"]),
    (Concept::Old, &["高龄"]),
    (Concept::Age, &["年龄"]),
    (Concept::Driver, &["司机"]),
    (Concept::License, &["执照"]),
    (Concept::Dl, &["驾照"]),
    (Concept::Dmv, &["车管所"]),
    (Concept::StateDepartment, &["国务院"]),
    (Concept::Account, &["账户"]),
    (Concept::Bank, &["银行"]),
    (Concept::Routing, &["路由号码"]),
    (Concept::Checking, &["支票账户"]),
    (Concept::Savings, &["储蓄"]),
    (Concept::Hmpo, &["英国护照"]),
    (Concept::Company, &["公司"]),
    (Concept::CompaniesHouse, &["公司注册处"]),
    (Concept::Registration, &["注册"]),
    (Concept::Crn, &["公司编号"]),
    (Concept::Physician, &["医师"]),
    (Concept::Doctor, &["医生"]),
    (Concept::Nurse, &["护士"]),
    (Concept::Wallet, &["钱包"]),
    (Concept::Crypto, &["加密货币"]),
    (Concept::Coin, &["代币"]),
];

pub fn extras() -> Vec<ExtraPattern> {
    vec![
        ExtraPattern {
            entity: EntityType::UsBankNumber,
            regex: r"(?:银行账号|银行账户|账号)\s*[:：]?\s*\d{8,17}",
            score: 0.6,
            concepts: super::en::US_BANK_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::Age,
            regex: r"\d{1,3}\s*岁",
            score: 0.8,
            concepts: super::en::AGE_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::PoBox,
            regex: r"邮政信箱\s*\d+",
            score: 0.85,
            concepts: super::en::PO_BOX_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::MedicalRecordNumber,
            regex: r"病历号\s*:?\s*[A-Z0-9]{6,12}",
            score: 0.85,
            concepts: super::en::MRN_CONCEPTS,
        },
    ]
}

pub const FIXTURES: &[Fixture] = &[
    Fixture {
        text: "银行账号：841234567890",
        entity: EntityType::UsBankNumber,
        expect: true,
    },
    Fixture {
        text: "841234567890",
        entity: EntityType::UsBankNumber,
        expect: false,
    },
    Fixture {
        text: "年龄42岁",
        entity: EntityType::Age,
        expect: true,
    },
    Fixture {
        text: "邮政信箱1234",
        entity: EntityType::PoBox,
        expect: true,
    },
    Fixture {
        text: "病历号ABC123456",
        entity: EntityType::MedicalRecordNumber,
        expect: true,
    },
];
