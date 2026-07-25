/// End-to-End NER Testing with ONNX Models
///
/// This test suite validates complete NER functionality with actual ONNX models.
/// Tests are ignored by default since they require downloading models.
///
/// # Setup Instructions
///
/// 1. Download a small NER model (recommended: ~50MB):
///    ```bash
///    python scripts/export_ner_model.py \
///        --model dslim/bert-base-NER \
///        --output tests/fixtures/models/bert-base-ner
///    ```
///
/// 2. Run tests with the ignored flag:
///    ```bash
///    cargo test --package redact-ner --test ner_e2e -- --ignored
///    ```
///
/// # Test Models
///
/// Recommended models for testing:
/// - `dslim/bert-base-NER` (~420MB) - Excellent accuracy, CoNLL-2003 trained
/// - `dbmdz/bert-large-cased-finetuned-conll03-english` (~1.2GB) - High accuracy
/// - `Davlan/distilbert-base-multilingual-cased-ner-hrl` (~500MB) - Multilingual
///
/// For faster CI testing, use quantized or distilled models (~50-100MB).
///
/// # Model Directory Structure
///
/// The export script creates a directory with the following structure:
/// ```
/// models/bert-base-ner/
/// ├── model.onnx          # ONNX model file (required)
/// ├── tokenizer.json      # HuggingFace tokenizer (required)
/// ├── config.json         # Model configuration with label mappings
/// ├── special_tokens_map.json
/// └── tokenizer_config.json
/// ```
///
/// Only `model.onnx` and `tokenizer.json` are required for inference.
use anyhow::Result;
use redact_core::{
    anonymizers::{AnonymizationStrategy, AnonymizerConfig},
    AnalyzerEngine, EntityType, Recognizer,
};
use redact_ner::{NerConfig, NerRecognizer};
use std::path::Path;
use std::sync::Arc;

/// Test fixture with expected entities
struct NerTestCase {
    text: &'static str,
    expected_entities: Vec<(EntityType, &'static str)>,
}

/// Get test cases for NER validation
fn get_test_cases() -> Vec<NerTestCase> {
    vec![
        NerTestCase {
            text: "John Doe works at Microsoft in Seattle.",
            expected_entities: vec![
                (EntityType::Person, "John Doe"),
                (EntityType::Organization, "Microsoft"),
                (EntityType::Location, "Seattle"),
            ],
        },
        NerTestCase {
            text: "Marie Curie conducted research in Paris.",
            expected_entities: vec![
                (EntityType::Person, "Marie Curie"),
                (EntityType::Location, "Paris"),
            ],
        },
        NerTestCase {
            text: "Apple Inc. was founded by Steve Jobs in California.",
            expected_entities: vec![
                (EntityType::Organization, "Apple Inc."),
                (EntityType::Person, "Steve Jobs"),
                (EntityType::Location, "California"),
            ],
        },
    ]
}

/// Helper to check if a model directory exists
fn model_exists(path: &str) -> bool {
    let model_path = Path::new(path).join("model.onnx");
    let tokenizer_path = Path::new(path).join("tokenizer.json");
    model_path.exists() && tokenizer_path.exists()
}

/// Test NER with BERT-base model
#[test]
#[ignore] // Requires downloading model first
fn test_ner_with_bert_base() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        eprintln!("Model not found at: {}", model_dir);
        eprintln!(
            "Run: python scripts/export_ner_model.py --model dslim/bert-base-NER --output {}",
            model_dir
        );
        return Ok(()); // Skip test if model not available
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        ..Default::default()
    };

    let recognizer = NerRecognizer::from_config(config)?;
    assert!(
        recognizer.is_available(),
        "NER should be available with model"
    );

    // Test each case
    for test_case in get_test_cases() {
        let results = recognizer.analyze(test_case.text, "en")?;

        // Verify expected entities are detected
        for (expected_type, expected_text) in &test_case.expected_entities {
            let found = results.iter().any(|r| {
                r.entity_type == *expected_type && r.text.as_deref() == Some(*expected_text)
            });

            assert!(
                found,
                "Expected to find {:?} '{}' in text: '{}'\nDetected: {:?}",
                expected_type, expected_text, test_case.text, results
            );
        }
    }

    Ok(())
}

/// Test NER with multilingual model
#[test]
#[ignore] // Requires downloading model first
fn test_ner_multilingual() -> Result<()> {
    let model_dir = "tests/fixtures/models/multilingual-ner";

    if !model_exists(model_dir) {
        eprintln!("Multilingual model not found");
        return Ok(());
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        ..Default::default()
    };

    let recognizer = NerRecognizer::from_config(config)?;

    // Test multiple languages
    let test_cases = vec![
        ("en", "Barack Obama visited London."),
        ("es", "Gabriel García Márquez nació en Colombia."),
        ("fr", "Emmanuel Macron est le président de la France."),
        ("de", "Angela Merkel war Bundeskanzlerin von Deutschland."),
    ];

    for (lang, text) in test_cases {
        let results = recognizer.analyze(text, lang)?;
        assert!(
            !results.is_empty(),
            "Should detect entities in {}: {}",
            lang,
            text
        );
    }

    Ok(())
}

/// Test NER character offset accuracy
#[test]
#[ignore] // Requires model
fn test_ner_character_offsets() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        return Ok(());
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        ..Default::default()
    };

    let recognizer = NerRecognizer::from_config(config)?;

    let text = "John Doe works at Microsoft.";
    let results = recognizer.analyze(text, "en")?;

    // Verify character offsets are accurate
    for result in &results {
        let extracted = &text[result.start..result.end];
        assert_eq!(
            extracted,
            result.text.as_ref().unwrap(),
            "Character offsets should extract exact text"
        );
    }

    Ok(())
}

/// Test NER with long text (max sequence length handling)
#[test]
#[ignore] // Requires model
fn test_ner_long_text() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        return Ok(());
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        max_seq_length: 128, // Test with smaller sequence length
        ..Default::default()
    };

    let recognizer = NerRecognizer::from_config(config)?;

    // Create a long text with entities throughout
    let long_text = "John Smith works at Microsoft. Jane Doe works at Apple. \
                     Bob Johnson works at Google. Alice Williams works at Amazon. \
                     Charlie Brown works at Facebook. Diana Prince works at Tesla. \
                     This text exceeds 512 tokens when tokenized, testing truncation.";

    let results = recognizer.analyze(long_text, "en")?;

    // Should detect at least the entities within max_seq_length
    assert!(
        !results.is_empty(),
        "Should detect entities even in long text"
    );

    Ok(())
}

/// Test NER integration with AnalyzerEngine
#[test]
#[ignore] // Requires model
fn test_ner_with_analyzer_engine() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        return Ok(());
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        ..Default::default()
    };

    let ner = NerRecognizer::from_config(config)?;

    // Create analyzer engine with both pattern and NER recognizers
    let mut engine = AnalyzerEngine::new();
    engine
        .recognizer_registry_mut()
        .add_recognizer(Arc::new(ner));

    let text = "Contact John Doe at john@example.com or visit Microsoft.com. SSN: 123-45-6789.";
    let result = engine.analyze(text, None)?;

    // Should detect both pattern-based entities (email, SSN) and NER entities (person, org)
    let has_email = result
        .detected_entities
        .iter()
        .any(|e| e.entity_type == EntityType::EmailAddress);
    let has_ssn = result
        .detected_entities
        .iter()
        .any(|e| e.entity_type == EntityType::UsSsn);
    let has_person = result
        .detected_entities
        .iter()
        .any(|e| e.entity_type == EntityType::Person);

    assert!(has_email, "Should detect email (pattern-based)");
    assert!(has_ssn, "Should detect SSN (pattern-based)");
    assert!(has_person, "Should detect person (NER-based)");

    Ok(())
}

/// Benchmark NER inference latency
#[test]
#[ignore] // Requires model and --ignored flag
fn test_ner_performance() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        return Ok(());
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        ..Default::default()
    };

    let recognizer = NerRecognizer::from_config(config)?;

    let text = "John Doe works at Microsoft in Seattle.";

    // Warm-up
    let _ = recognizer.analyze(text, "en")?;

    // Measure inference time
    let start = std::time::Instant::now();
    let iterations = 100;

    for _ in 0..iterations {
        let _ = recognizer.analyze(text, "en")?;
    }

    let elapsed = start.elapsed();
    let avg_latency = elapsed / iterations;

    println!("Average NER inference latency: {:?}", avg_latency);
    println!(
        "Throughput: {:.2} req/s",
        1000.0 / avg_latency.as_millis() as f64
    );

    // Assert reasonable performance (adjust based on hardware)
    assert!(
        avg_latency.as_millis() < 100,
        "NER inference should be < 100ms on average (was {:?})",
        avg_latency
    );

    Ok(())
}

/// Test thread safety - concurrent NER inference
#[test]
#[ignore] // Requires model
fn test_ner_thread_safety() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        return Ok(());
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        ..Default::default()
    };

    let recognizer = std::sync::Arc::new(NerRecognizer::from_config(config)?);

    // Spawn multiple threads
    let mut handles = vec![];

    for i in 0..4 {
        let rec = recognizer.clone();
        let handle = std::thread::spawn(move || {
            let text = format!("Thread {} analyzing John Doe at Microsoft.", i);
            for _ in 0..10 {
                let results = rec.analyze(&text, "en").unwrap();
                assert!(!results.is_empty(), "Thread {} should detect entities", i);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}

/// Test NER with empty and edge case inputs
#[test]
#[ignore] // Requires model
fn test_ner_edge_cases() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        return Ok(());
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        ..Default::default()
    };

    let recognizer = NerRecognizer::from_config(config)?;

    // Empty string
    let results = recognizer.analyze("", "en")?;
    assert_eq!(results.len(), 0, "Empty text should return no entities");

    // Only whitespace
    let results = recognizer.analyze("   \n\t  ", "en")?;
    assert_eq!(results.len(), 0, "Whitespace should return no entities");

    // Special characters
    let results = recognizer.analyze("!@#$%^&*()", "en")?;
    assert_eq!(results.len(), 0, "Special chars should return no entities");

    // Very short text
    let _results = recognizer.analyze("Hi.", "en")?;
    // May or may not detect entities - just ensure it doesn't crash

    Ok(())
}

/// Test full NER integration with redaction/anonymization
///
/// This test verifies the complete pipeline:
/// 1. Load NER model
/// 2. Detect Person/Organization/Location entities
/// 3. Anonymize detected entities
/// 4. Verify redaction in output
#[test]
#[ignore] // Requires model
fn test_ner_with_redaction() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        eprintln!("Model not found at: {}", model_dir);
        eprintln!(
            "Run: python scripts/export_ner_model.py --model dslim/bert-base-NER --output {}",
            model_dir
        );
        return Ok(()); // Skip test if model not available
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.7,
        ..Default::default()
    };

    let ner = NerRecognizer::from_config(config)?;

    // Create analyzer engine with NER
    let mut engine = AnalyzerEngine::new();
    engine
        .recognizer_registry_mut()
        .add_recognizer(Arc::new(ner));

    // Test text with multiple entity types
    let text = "John Doe works at Microsoft in Seattle. Contact him at john@example.com.";

    // Step 1: Analyze and verify detection
    let analysis = engine.analyze(text, None)?;

    // Verify NER entities detected
    let has_person = analysis
        .detected_entities
        .iter()
        .any(|e| e.entity_type == EntityType::Person);
    let has_org = analysis
        .detected_entities
        .iter()
        .any(|e| e.entity_type == EntityType::Organization);
    let has_location = analysis
        .detected_entities
        .iter()
        .any(|e| e.entity_type == EntityType::Location);
    let has_email = analysis
        .detected_entities
        .iter()
        .any(|e| e.entity_type == EntityType::EmailAddress);

    assert!(has_person, "Should detect PERSON (John Doe)");
    assert!(has_org, "Should detect ORGANIZATION (Microsoft)");
    assert!(has_location, "Should detect LOCATION (Seattle)");
    assert!(has_email, "Should detect EMAIL (john@example.com)");

    // Step 2: Anonymize with replace strategy
    let anonymizer_config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };

    let anonymized = engine.anonymize(text, None, &anonymizer_config)?;

    // Step 3: Verify redaction
    assert!(
        !anonymized.text.contains("John Doe"),
        "Person name should be redacted. Got: {}",
        anonymized.text
    );
    assert!(
        !anonymized.text.contains("Microsoft"),
        "Organization should be redacted. Got: {}",
        anonymized.text
    );
    assert!(
        !anonymized.text.contains("Seattle"),
        "Location should be redacted. Got: {}",
        anonymized.text
    );
    assert!(
        !anonymized.text.contains("john@example.com"),
        "Email should be redacted. Got: {}",
        anonymized.text
    );

    // Verify placeholders are present
    assert!(
        anonymized.text.contains("[PERSON]"),
        "Should have [PERSON] placeholder"
    );
    assert!(
        anonymized.text.contains("[EMAIL_ADDRESS]"),
        "Should have [EMAIL_ADDRESS] placeholder"
    );

    println!("Original: {}", text);
    println!("Redacted: {}", anonymized.text);

    Ok(())
}

/// Test NER detects all three main entity types
#[test]
#[ignore] // Requires model
fn test_ner_entity_types() -> Result<()> {
    let model_dir = "tests/fixtures/models/bert-base-ner";

    if !model_exists(model_dir) {
        return Ok(());
    }

    let model_path = format!("{}/model.onnx", model_dir);
    let config = NerConfig {
        model_path,
        tokenizer_path: Some(format!("{}/tokenizer.json", model_dir)),
        min_confidence: 0.5, // Lower threshold to catch all entities
        ..Default::default()
    };

    let recognizer = NerRecognizer::from_config(config)?;

    // Test cases for each entity type
    let test_cases = vec![
        ("Marie Curie won the Nobel Prize.", EntityType::Person),
        (
            "Apple Inc. is based in Cupertino.",
            EntityType::Organization,
        ),
        ("The Eiffel Tower is in Paris.", EntityType::Location),
    ];

    for (text, expected_type) in test_cases {
        let results = recognizer.analyze(text, "en")?;

        let found = results.iter().any(|r| r.entity_type == expected_type);

        assert!(
            found,
            "Should detect {:?} in: '{}'\nDetected: {:?}",
            expected_type, text, results
        );
    }

    Ok(())
}
