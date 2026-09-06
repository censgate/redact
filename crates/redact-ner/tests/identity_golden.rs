// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Golden cases for hybrid identity detection (contextual + optional ONNX NER).
//!
//! Contextual-only covers a synthetic kennel/lab roster and the
//! adversarial table. ONNX cases run only when `CENSGATE_NER_MODEL_PATH`
//! points at a loadable model so CI without the artifact still stays green.

use redact_core::{EntityType, Recognizer};
use redact_ner::IdentityRecognizer;

/// One kennel dog + one place list. Not a household roster.
const KENNEL_PARAGRAPH: &str = "The kennel lists one dog: Kestrel ( black terrier, 8 ). We live in Harbor Mill, Westfield ( Elmsford metro area ). A colleague named Bram dropped by.";

/// Synthetic lab roster — invented names and counts, not an operator household.
const LAB_ROSTER: &str = "The lab mascot is Nimbus. Nimbus's badge is yellow. Desk neighbors are Reed, Sable, and Quill. Sorrel runs the front desk. Reed files the badges.";

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
fn kennel_paragraph_tokenizes_pet_colleague_and_places() {
    let rec = IdentityRecognizer::contextual_only();
    let people = types_of(&rec, KENNEL_PARAGRAPH, EntityType::Person);
    let places = types_of(&rec, KENNEL_PARAGRAPH, EntityType::Location);

    assert_eq!(people, vec!["Kestrel".to_string(), "Bram".to_string()]);
    assert_eq!(
        places,
        vec![
            "Harbor Mill".to_string(),
            "Westfield".to_string(),
            "Elmsford".to_string()
        ]
    );
    assert!(!spans(&rec, KENNEL_PARAGRAPH)
        .iter()
        .any(|(_, t)| t == "American" || t == "terrier"));
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
        types_of(
            &rec,
            "my pets: Kestrel and Bram are loud",
            EntityType::Person
        ),
        vec!["Kestrel".to_string(), "Bram".to_string()]
    );
}

#[test]
fn existing_vault_tokens_are_not_identity() {
    let rec = IdentityRecognizer::contextual_only();
    let text = "The kennel lists one dog: [PERSON_1] ( black terrier, 8 ). The yard is in [LOCATION_1], [LOCATION_2] ( [LOCATION_3] metro area ). A colleague named [PERSON_2] dropped by.";
    assert!(
        spans(&rec, text).is_empty(),
        "sealed tokens must not be re-detected as PERSON/LOCATION: {:?}",
        spans(&rec, text)
    );
    assert!(spans(&rec, "[PERSON_6] lives in [LOCATION_4]").is_empty());
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
fn lab_roster_contextual_covers_mascot_neighbors_and_desk_lead() {
    let rec = IdentityRecognizer::contextual_only();
    let people = types_of(&rec, LAB_ROSTER, EntityType::Person);
    assert_eq!(
        people,
        vec![
            "Nimbus".to_string(),
            "Nimbus".to_string(),
            "Reed".to_string(),
            "Sable".to_string(),
            "Quill".to_string(),
            "Sorrel".to_string(),
            "Reed".to_string(),
        ]
    );
    assert!(people.iter().all(|s| !s.contains('\'') && !s.contains('’')));
}

#[test]
fn who_runs_the_front_desk_is_not_a_person() {
    let rec = IdentityRecognizer::contextual_only();
    let people = types_of(&rec, "Who runs the front desk?", EntityType::Person);
    assert!(
        people.is_empty(),
        "interrogative Who must not become PERSON: {people:?}"
    );
    assert!(spans(&rec, "Who runs the front desk?").is_empty());
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

    let people = types_of(&rec, LAB_ROSTER, EntityType::Person);
    assert!(
        people
            .iter()
            .all(|s| !s.contains('\'') && !s.contains('’') && s != "s"),
        "lab-roster PERSON spans must be bare names, got {people:?}"
    );
    let sorrel: Vec<_> = people
        .iter()
        .filter(|s| s.contains("Sor") || s.contains("rel"))
        .collect();
    assert!(
        sorrel.iter().all(|s| s.eq_ignore_ascii_case("Sorrel")) || sorrel.is_empty(),
        "Sorrel must be one PERSON span if detected: {people:?}"
    );
}
