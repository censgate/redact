// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Vietnamese context terms. Unaccented spellings are listed on purpose.

use super::{Concept, ExtraPattern, Fixture};
use crate::types::EntityType;

pub const TERMS: &[(Concept, &[&str])] = &[
    (Concept::Nhs, &["bảo hiểm y tế", "bao hiem y te"]),
    (Concept::Patient, &["bệnh nhân", "benh nhan"]),
    (Concept::Health, &["sức khỏe", "suc khoe"]),
    (Concept::Address, &["địa chỉ", "dia chi"]),
    (Concept::Mail, &["bưu điện", "buu dien"]),
    (Concept::Ship, &["giao hàng", "giao hang"]),
    (Concept::Passport, &["hộ chiếu", "ho chieu"]),
    (Concept::Travel, &["du lịch", "du lich"]),
    (Concept::Medical, &["y tế", "y te"]),
    (Concept::Hospital, &["bệnh viện", "benh vien"]),
    (Concept::Years, &["năm tuổi", "nam tuoi"]),
    (Concept::Old, &["cao tuổi", "cao tuoi"]),
    (Concept::Age, &["tuổi", "tuoi"]),
    (Concept::Driver, &["tài xế", "tai xe"]),
    (Concept::License, &["giấy phép", "giay phep"]),
    (Concept::Dl, &["bằng lái", "bang lai"]),
    (Concept::Dmv, &["sở giao thông", "so giao thong"]),
    (
        Concept::StateDepartment,
        &["bộ ngoại giao", "bo ngoai giao"],
    ),
    (Concept::Account, &["tài khoản", "tai khoan"]),
    (Concept::Bank, &["ngân hàng", "ngan hang"]),
    (Concept::Routing, &["định tuyến", "dinh tuyen"]),
    (Concept::Checking, &["thanh toán", "thanh toan"]),
    (Concept::Savings, &["tiết kiệm", "tiet kiem"]),
    (Concept::Hmpo, &["hộ chiếu anh", "ho chieu anh"]),
    (Concept::Company, &["công ty", "cong ty"]),
    (
        Concept::CompaniesHouse,
        &["đăng ký kinh doanh", "dang ky kinh doanh"],
    ),
    (Concept::Registration, &["đăng ký", "dang ky"]),
    (Concept::Crn, &["mã số doanh nghiệp", "ma so doanh nghiep"]),
    (Concept::Physician, &["thầy thuốc", "thay thuoc"]),
    (Concept::Doctor, &["bác sĩ", "bac si"]),
    (Concept::Nurse, &["y tá", "y ta"]),
    (Concept::Wallet, &["ví tiền", "vi tien"]),
    (Concept::Crypto, &["tiền điện tử", "tien dien tu"]),
    (Concept::Coin, &["tiền mã hóa", "tien ma hoa"]),
];

pub fn extras() -> Vec<ExtraPattern> {
    vec![
        ExtraPattern {
            entity: EntityType::UsBankNumber,
            regex: r"(?i)(?:số\s+tài\s+khoản|so\s+tai\s+khoan)(?:\s+ngân\s+hàng|\s+ngan\s+hang)?\s*:?\s*\d{8,17}",
            score: 0.6,
            concepts: super::en::US_BANK_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::Age,
            regex: r"(?i)(?:tuổi|tuoi)\s*:?\s*\d{1,3}\b|\b\d{1,3}\s*(?:tuổi|tuoi)\b",
            score: 0.8,
            concepts: super::en::AGE_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::PoBox,
            regex: r"(?i)(?:hòm\s+thư|hom\s+thu|hộp\s+thư|hop\s+thu)\s*(?:số\s*|so\s*)?\d+",
            score: 0.85,
            concepts: super::en::PO_BOX_CONCEPTS,
        },
        ExtraPattern {
            entity: EntityType::MedicalRecordNumber,
            regex: r"(?i)(?:mã\s+bệnh\s+án|ma\s+benh\s+an|hồ\s+sơ\s+bệnh\s+án|ho\s+so\s+benh\s+an)\s*:?\s*[A-Z0-9]{6,12}",
            score: 0.85,
            concepts: super::en::MRN_CONCEPTS,
        },
    ]
}

pub const FIXTURES: &[Fixture] = &[
    Fixture {
        text: "Số tài khoản ngân hàng: 841234567890",
        entity: EntityType::UsBankNumber,
        expect: true,
    },
    Fixture {
        text: "so tai khoan ngan hang: 841234567890",
        entity: EntityType::UsBankNumber,
        expect: true,
    },
    Fixture {
        text: "841234567890",
        entity: EntityType::UsBankNumber,
        expect: false,
    },
    Fixture {
        text: "Bệnh nhân 42 tuổi",
        entity: EntityType::Age,
        expect: true,
    },
    Fixture {
        text: "Hòm thư số 1234",
        entity: EntityType::PoBox,
        expect: true,
    },
    Fixture {
        text: "Mã bệnh án ABC123456",
        entity: EntityType::MedicalRecordNumber,
        expect: true,
    },
];
