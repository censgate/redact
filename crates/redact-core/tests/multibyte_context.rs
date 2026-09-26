//! Issue 180: context boosting must not panic on multi-byte text.

use std::sync::OnceLock;

use redact_core::{AnalyzerEngine, EntityType};

fn engine() -> &'static AnalyzerEngine {
    static ENGINE: OnceLock<AnalyzerEngine> = OnceLock::new();
    ENGINE.get_or_init(AnalyzerEngine::new)
}

fn check(text: &str) -> Vec<(EntityType, String, f32)> {
    let result = engine().analyze(text, None).expect("analyze");
    result
        .detected_entities
        .iter()
        .map(|entity| {
            assert!(
                text.is_char_boundary(entity.start) && text.is_char_boundary(entity.end),
                "span {}..{} in {text:?}",
                entity.start,
                entity.end
            );
            (
                entity.entity_type.clone(),
                text[entity.start..entity.end].to_string(),
                entity.score,
            )
        })
        .collect()
}

#[test]
fn issue_repro_end_side_o_acute() {
    check(&format!("841234567890{}ó", " ".repeat(49)));
}

#[test]
fn issue_repro_start_side_u_horn_hook() {
    check(&format!("ử{}841234567890", " ".repeat(49)));
}

#[test]
fn emoji_and_vietnamese_vowels_at_every_nearby_padding() {
    for ch in ["📄", "ố", "ó", "你"] {
        for pad in 45..=52 {
            check(&format!("841234567890{}{ch}", " ".repeat(pad)));
            check(&format!("{ch}{}841234567890", " ".repeat(pad)));
        }
    }
}

#[test]
fn real_vietnamese_sentences_precomposed_and_decomposed() {
    let sentences = [
        "Số tài khoản của tôi là 841234567890, vui lòng chuyển khoản trước ngày mai nhé 📄",
        "Gọi cho tôi theo số 0912345678 hoặc 841234567890 — cảm ơn bạn rất nhiều!",
        "Mã đơn hàng 20260916 đã được xử lý thành công. Tổng cộng: 1.250.000 đồng.",
        "Hồ sơ bệnh án MRN: ABC123456 của bệnh nhân Nguyễn Văn Ánh, tuổi age: 42, ở Hà Nội.",
        "Bác sĩ MD-1234567 kê đơn. Hộ chiếu số AB1234567 hết hạn năm 2030. Địa chỉ PO BOX 1234 ở Đà Nẵng.",
        "Ví tiền điện tử LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL — đừng chia sẻ với ai nhé",
        "Mã số doanh nghiệp 12345678 đăng ký tại Sở Kế hoạch và Đầu tư Thành phố Hồ Chí Minh.",
    ];
    for sentence in sentences {
        check(sentence);
        let decomposed = sentence
            .replace('ó', "o\u{301}")
            .replace('ố', "o\u{302}\u{301}")
            .replace('ử', "u\u{31b}\u{309}")
            .replace('ạ', "a\u{323}");
        check(&decomposed);
    }
}

#[test]
fn context_patterns_do_not_panic_when_a_scalar_straddles_the_window() {
    let samples = [
        "841234567890",
        "9434765919",
        "PO BOX 1234",
        "AB1234567",
        "MRN: ABC123456",
        "age: 42",
        "A1234567",
        "123456789",
        "12345678",
        "MD-1234567",
        "LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL",
    ];
    let scalars = [
        "ó",
        "ử",
        "ố",
        "ạ",
        "📄",
        "你",
        "한",
        "o\u{301}",
        "👨\u{200d}👩\u{200d}👧",
    ];
    for sample in samples {
        for scalar in scalars {
            for pad in [0usize, 49, 50, 51] {
                let gap = " ".repeat(pad);
                check(&format!("{sample}{gap}{scalar}"));
                check(&format!("{scalar}{gap}{sample}"));
            }
        }
    }
}
