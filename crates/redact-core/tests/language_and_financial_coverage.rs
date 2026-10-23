//! Pattern recognizers run for every language. Card, IBAN, bank-number, and
//! email patterns cover grouped digits, spaced IBANs, and CJK-adjacent values.
use redact_core::{
    anonymizers::{AnonymizationStrategy, AnonymizerConfig},
    AnalyzerEngine, EntityType,
};

const LANGUAGES: [&str; 5] = ["es", "vi", "zh", "de", "ja"];

fn sample_aws_access_key() -> String {
    format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE")
}

fn multilingual_sample(aws_key: &str) -> String {
    format!(
        "correo maria@example.es tarjeta 4532 0151 1283 0366 clave {aws_key} \
         IBAN DE89 3704 0044 0532 0130 00"
    )
}

fn assert_detected(text: &str, language: &str, entity_type: EntityType, surface: &str) {
    let engine = AnalyzerEngine::new();
    let result = engine
        .analyze(text, Some(language))
        .unwrap_or_else(|e| panic!("analyze {language}: {e}"));
    assert!(
        result
            .detected_entities
            .iter()
            .any(|e| { e.entity_type == entity_type && e.text.as_deref() == Some(surface) }),
        "expected {entity_type:?} {surface:?} in {language}: {:?}",
        result.detected_entities
    );
}

fn digit_runs_of_at_least(text: &str, min: usize) -> Vec<String> {
    let mut runs = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if !cur.is_empty() {
            if cur.len() >= min {
                runs.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= min {
        runs.push(cur);
    }
    runs
}

fn four_plus_digit_substrings(value: &str) -> Vec<String> {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for start in 0..=digits.len() - 4 {
        for end in start + 4..=digits.len() {
            out.push(digits[start..end].to_string());
        }
    }
    out
}

#[test]
fn languages_detect_email_card_aws_and_iban() {
    let aws_key = sample_aws_access_key();
    let text = multilingual_sample(&aws_key);
    for language in LANGUAGES {
        assert_detected(
            &text,
            language,
            EntityType::EmailAddress,
            "maria@example.es",
        );
        assert_detected(
            &text,
            language,
            EntityType::CreditCard,
            "4532 0151 1283 0366",
        );
        assert_detected(&text, language, EntityType::AwsAccessKey, &aws_key);
        assert_detected(
            &text,
            language,
            EntityType::IbanCode,
            "DE89 3704 0044 0532 0130 00",
        );
    }
}

#[test]
fn languages_redact_email_card_aws_and_iban() {
    let engine = AnalyzerEngine::new();
    let aws_key = sample_aws_access_key();
    let text = multilingual_sample(&aws_key);
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };
    for language in LANGUAGES {
        let anonymized = engine
            .anonymize(&text, Some(language), &config)
            .unwrap_or_else(|e| panic!("anonymize {language}: {e}"));
        assert!(
            anonymized.text.contains("[EMAIL_ADDRESS]"),
            "{language}: {}",
            anonymized.text
        );
        assert!(
            anonymized.text.contains("[CREDIT_CARD]"),
            "{language}: {}",
            anonymized.text
        );
        assert!(
            anonymized.text.contains("[AWS_ACCESS_KEY]"),
            "{language}: {}",
            anonymized.text
        );
        assert!(
            anonymized.text.contains("[IBAN_CODE]"),
            "{language}: {}",
            anonymized.text
        );
        assert!(
            !anonymized.text.contains("maria@example.es"),
            "{language}: email left in {}",
            anonymized.text
        );
        assert!(
            !anonymized.text.contains(&aws_key),
            "{language}: aws key left in {}",
            anonymized.text
        );
    }
}

#[test]
fn spaced_amex_4_6_5_is_fully_masked() {
    let engine = AnalyzerEngine::new();
    let text = "pagar Amex 3782 822463 10005 ahora";
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };
    let result = engine.analyze(text, Some("es")).unwrap();
    let card = result
        .detected_entities
        .iter()
        .find(|e| e.entity_type == EntityType::CreditCard)
        .expect("Amex");
    assert_eq!(card.text.as_deref(), Some("3782 822463 10005"));
    let anonymized = engine.anonymize(text, Some("es"), &config).unwrap();
    assert!(anonymized.text.contains("[CREDIT_CARD]"));
    assert!(!anonymized.text.contains("3782"));
    assert!(!anonymized.text.contains("822463"));
    assert!(!anonymized.text.contains("10005"));
}

#[test]
fn spaced_iban_is_detected() {
    assert_detected(
        "transfer GB82 WEST 1234 5698 7654 32",
        "de",
        EntityType::IbanCode,
        "GB82 WEST 1234 5698 7654 32",
    );
}

#[test]
fn context_bank_number_masks_whole_16_to_19_digits() {
    let engine = AnalyzerEngine::new();
    let number = "123456789012345678";
    let text = format!("account number {number} noted");
    let result = engine.analyze(&text, Some("en")).unwrap();
    let bank = result
        .detected_entities
        .iter()
        .find(|e| e.entity_type == EntityType::UsBankNumber)
        .expect("bank number");
    assert_eq!(bank.text.as_deref(), Some(number));
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };
    let anonymized = engine.anonymize(&text, Some("en"), &config).unwrap();
    assert!(anonymized.text.contains("[US_BANK_NUMBER]"));
    assert!(!anonymized.text.contains(number));
    for phrase_text in [
        "acct 12345678901234567",
        "account no 12345678901234567",
        "Kontonummer 12345678901234567",
        "número de cuenta 12345678901234567",
        "số tài khoản 12345678901234567",
        "账号12345678901234567",
        "口座番号12345678901234567",
    ] {
        let result = engine.analyze(phrase_text, Some("en")).unwrap();
        assert!(
            result
                .detected_entities
                .iter()
                .any(|e| e.entity_type == EntityType::UsBankNumber),
            "expected bank number for {phrase_text:?}: {:?}",
            result.detected_entities
        );
    }
    assert!(
        !anonymized.text.contains(&number[number.len() - 4..]),
        "trailing digits left in {}",
        anonymized.text
    );
}

#[test]
fn email_and_card_detected_next_to_cjk() {
    let text = "邮箱maria@example.com卡4532015112830366";
    assert_detected(text, "zh", EntityType::EmailAddress, "maria@example.com");
    assert_detected(text, "zh", EntityType::CreditCard, "4532015112830366");
}

#[test]
fn anonymize_leaves_no_four_plus_digit_substring() {
    let engine = AnalyzerEngine::new();
    let bank_18 = "123456789012345678";
    let bank_19 = "1234567890123456789";
    let originals = [
        "maria@example.es",
        "4532 0151 1283 0366",
        "4532-0151-1283-0366",
        "3782 822463 10005",
        "DE89 3704 0044 0532 0130 00",
        bank_18,
        bank_19,
    ];
    let text = format!(
        "correo maria@example.es tarjeta 4532 0151 1283 0366 \
         card 4532-0151-1283-0366 Amex 3782 822463 10005 \
         IBAN DE89 3704 0044 0532 0130 00 \
         account number {bank_18} account number {bank_19}"
    );
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };
    for language in LANGUAGES {
        let anonymized = engine
            .anonymize(&text, Some(language), &config)
            .unwrap_or_else(|e| panic!("anonymize {language}: {e}"));
        for original in originals {
            for fragment in four_plus_digit_substrings(original) {
                assert!(
                    !anonymized.text.contains(&fragment),
                    "{language}: digit substring {fragment} from {original} survived in {}",
                    anonymized.text
                );
            }
        }
        for run in digit_runs_of_at_least(&anonymized.text, 4) {
            panic!(
                "{language}: anonymized text still has 4+ digit run {run} in {}",
                anonymized.text
            );
        }
        assert!(
            !anonymized.text.contains("maria@example.es"),
            "{language}: email left in {}",
            anonymized.text
        );
    }
}

fn assert_not_bank_number(text: &str) {
    let engine = AnalyzerEngine::new();
    let result = engine.analyze(text, Some("en")).unwrap();
    assert!(
        result
            .detected_entities
            .iter()
            .all(|e| e.entity_type != EntityType::UsBankNumber),
        "unexpected US_BANK_NUMBER in {text:?}: {:?}",
        result.detected_entities
    );
}

#[test]
fn bank_number_ignores_dates_phones_and_order_ids() {
    assert_not_bank_number("account opened 20240115");
    assert_not_bank_number("call the bank at 5551234567");
    assert_not_bank_number("routing order 1234567890123");
    assert_not_bank_number("meeting on 2024-01-15");
    assert_not_bank_number("call 555-123-4567");
    assert_not_bank_number("order 1234567890123");
}
