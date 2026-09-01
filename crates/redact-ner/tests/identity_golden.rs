// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Golden cases for hybrid identity detection (contextual + optional ONNX NER).
//!
//! Contextual-only covers the household-identity paragraph and the
//! adversarial table. ONNX cases run only when `CENSGATE_NER_MODEL_PATH`
//! points at a loadable model so CI without the artifact still stays green.

use redact_core::{EntityType, Recognizer};
use redact_ner::IdentityRecognizer;

const CATS_PARAGRAPH: &str = "I have two female cats: Nola ( black American short hair, 12 ) and Pip ( ginger tabby, 3 ). We live in Cedar Hollow, Caledonia ( Riverton metro area ). I have a wife and a daughter ( 11 ).";

fn spans(rec: &IdentityRecognizer, text: &str) -> Vec<(EntityType, String)> {
    rec.analyze(text, "en")
        .unwrap()
        .into_iter()
        .map(|r| (r.entity_type, text[r.start..r.end].to_string()))
        .collect()
}

fn types_of(rec: &IdentityRecognizer, text: &str, ty: EntityType) -> Vec<String> {
    spans(rec, text)
        .into_iter()
        .filter(|(t, _)| *t == ty)
        .map(|(_, s)| s)
        .collect()
}

#[test]
fn cats_paragraph_tokenizes_pets_and_places_not_american() {
    let rec = IdentityRecognizer::contextual_only();
    let people = types_of(&rec, CATS_PARAGRAPH, EntityType::Person);
    let places = types_of(&rec, CATS_PARAGRAPH, EntityType::Location);

    assert_eq!(people, vec!["Nola".to_string(), "Pip".to_string()]);
    assert_eq!(
        places,
        vec![
            "Cedar Hollow".to_string(),
            "Caledonia".to_string(),
            "Riverton".to_string()
        ]
    );
    assert!(!spans(&rec, CATS_PARAGRAPH)
        .iter()
        .any(|(_, t)| t == "American"));
}

#[test]
fn weekdays_without_identity_context_are_left_alone() {
    let rec = IdentityRecognizer::contextual_only();
    assert!(spans(&rec, "I work Mondays and Fridays.").is_empty());
}

#[test]
fn greeting_and_relationship_yield_person() {
    let rec = IdentityRecognizer::contextual_only();
    assert_eq!(
        types_of(&rec, "Hi Ada, welcome back.", EntityType::Person),
        vec!["Ada".to_string()]
    );
    assert_eq!(
        types_of(&rec, "my daughter Ada called earlier", EntityType::Person),
        vec!["Ada".to_string()]
    );
}

#[test]
fn pet_context_emits_person_including_calendar_words() {
    let rec = IdentityRecognizer::contextual_only();
    assert_eq!(
        types_of(&rec, "my cat pip is loud", EntityType::Person),
        vec!["pip".to_string()]
    );
    assert_eq!(
        types_of(&rec, "my cat Monday sleeps all day", EntityType::Person),
        vec!["Monday".to_string()]
    );
}

#[test]
fn jordan_type_follows_local_context_not_a_global_rank() {
    let rec = IdentityRecognizer::contextual_only();
    assert_eq!(
        types_of(&rec, "we live in jordan now", EntityType::Location),
        vec!["jordan".to_string()]
    );
    assert_eq!(
        types_of(&rec, "my daughter Jordan starts school", EntityType::Person),
        vec!["Jordan".to_string()]
    );
    assert!(types_of(&rec, "we live in jordan now", EntityType::Person).is_empty());
    assert!(types_of(
        &rec,
        "my daughter Jordan starts school",
        EntityType::Location
    )
    .is_empty());
}

#[test]
fn capitalization_alone_never_creates_an_entity() {
    let rec = IdentityRecognizer::contextual_only();
    assert!(spans(&rec, "Please review the Quarterly Report on Mondays.").is_empty());
    assert!(spans(&rec, "ada").is_empty());
}

#[test]
fn common_words_after_identity_cues_are_not_names() {
    let rec = IdentityRecognizer::contextual_only();
    assert!(spans(&rec, "my daughter starts school").is_empty());
    assert!(spans(&rec, "my daughter loves school").is_empty());
    assert!(spans(&rec, "we live in constant fear").is_empty());
    assert!(spans(&rec, "we live in peace now").is_empty());
    assert!(spans(&rec, "my cat eats tuna").is_empty());
    assert_eq!(
        types_of(&rec, "my pets: Nola and Pip are loud", EntityType::Person),
        vec!["Nola".to_string(), "Pip".to_string()]
    );
}

#[test]
fn named_and_called_are_strong_person_context() {
    let rec = IdentityRecognizer::contextual_only();
    assert_eq!(
        types_of(&rec, "a colleague named Ada joined", EntityType::Person),
        vec!["Ada".to_string()]
    );
    assert_eq!(
        types_of(&rec, "the stray is called pip", EntityType::Person),
        vec!["pip".to_string()]
    );
}

#[test]
fn onnx_org_and_bare_apple_when_model_present() {
    let Some(rec) = IdentityRecognizer::from_env_optional() else {
        return;
    };
    if !rec.ner_available() {
        return;
    }

    let org = types_of(
        &rec,
        "Apple released iOS last week",
        EntityType::Organization,
    );
    assert!(
        org.iter().any(|s| s.eq_ignore_ascii_case("Apple")),
        "expected ONNX to tag Apple as ORGANIZATION, got {org:?}"
    );

    let ate = spans(&rec, "I ate an apple");
    assert!(
        !ate.iter()
            .any(|(ty, s)| *ty == EntityType::Organization && s.eq_ignore_ascii_case("apple")),
        "food apple must not become ORGANIZATION: {ate:?}"
    );
}
