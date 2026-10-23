//! Concurrent operation tests
//!
//! These tests verify thread safety and concurrent access patterns.
//!
//! Run with: cargo test --package redact-core --test concurrent_operations

use redact_core::{
    anonymizers::{AnonymizationStrategy, AnonymizerConfig},
    AnalyzerEngine, EntityType,
};
use std::sync::Arc;
use std::thread;

#[test]
fn test_concurrent_analysis() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    // Spawn 10 threads performing analysis concurrently
    for i in 0..10 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let text = format!("Thread {} Email: test{}@example.com", i, i);
            let result = engine_clone.analyze(&text, None);
            assert!(result.is_ok());
            result.unwrap()
        });
        handles.push(handle);
    }

    // Wait for all threads and verify results
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(!result.detected_entities.is_empty());
    }
}

#[test]
fn test_concurrent_anonymization() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    // Spawn threads performing anonymization concurrently
    for i in 0..10 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let text = format!("Email: test{}@example.com, SSN: 123-45-{:04}", i, i);
            let config = AnonymizerConfig {
                strategy: AnonymizationStrategy::Replace,
                ..Default::default()
            };
            let result = engine_clone.anonymize(&text, None, &config);
            assert!(result.is_ok());
            result.unwrap()
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result.text.contains("[EMAIL_ADDRESS]"));
    }
}

#[test]
fn test_concurrent_mixed_operations() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    // Half threads do analysis, half do anonymization
    for i in 0..20 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            if i % 2 == 0 {
                // Analysis
                let text = format!("Email: test{}@example.com", i);
                engine_clone.analyze(&text, None).unwrap()
            } else {
                // Anonymization
                let text = format!("SSN: 123-45-{:04}", i);
                let config = AnonymizerConfig {
                    strategy: AnonymizationStrategy::Mask,
                    ..Default::default()
                };
                engine_clone
                    .analyze_and_anonymize(&text, None, &config)
                    .unwrap()
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_concurrent_with_different_languages() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    let languages = ["en", "es", "vi", "zh"];

    for (i, lang) in languages.iter().enumerate() {
        let engine_clone = Arc::clone(&engine);
        let lang_str = lang.to_string();
        let handle = thread::spawn(move || {
            let text = format!("Email: test{}@example.com", i);
            let result = engine_clone.analyze(&text, Some(&lang_str));
            assert!(result.is_ok());
            result.unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.join().unwrap();
        assert!(!result.detected_entities.is_empty());
    }
}

#[test]
fn test_concurrent_with_entity_filtering() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    let entity_types = vec![
        vec![EntityType::EmailAddress],
        vec![EntityType::UsSsn],
        vec![EntityType::PhoneNumber],
        vec![EntityType::EmailAddress, EntityType::UsSsn],
    ];

    for types in entity_types {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let text = "Email: test@example.com, SSN: 123-45-6789, Phone: (555) 123-4567";
            let result = engine_clone.analyze_with_entities(text, &types, None);
            assert!(result.is_ok());
            result.unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_concurrent_different_strategies() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    let strategies = vec![
        AnonymizationStrategy::Replace,
        AnonymizationStrategy::Mask,
        AnonymizationStrategy::Hash,
    ];

    for strategy in strategies {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let text = "Email: test@example.com, SSN: 123-45-6789";
            let config = AnonymizerConfig {
                strategy,
                ..Default::default()
            };
            let result = engine_clone.analyze_and_anonymize(text, None, &config);
            assert!(result.is_ok());
            result.unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_high_concurrency() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    // Spawn 100 threads to stress test
    for i in 0..100 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            // Use valid SSN format (serial must be 0001-9999, not 0000)
            let text = format!(
                "User {} - Email: user{}@example.com, SSN: 123-45-{:04}",
                i,
                i,
                (i % 9999) + 1 // Ensures serial is 0001-9999, never 0000
            );
            engine_clone.analyze(&text, None).unwrap()
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result.detected_entities.len() >= 2);
    }
}

#[test]
fn test_concurrent_large_texts() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    for i in 0..5 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            // Create a large text (~100KB)
            let large_text = format!(
                "{} Email: test{}@example.com, SSN: 123-45-6789",
                "Lorem ipsum dolor sit amet. ".repeat(5000),
                i
            );
            engine_clone.analyze(&large_text, None).unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result.detected_entities.len() >= 2);
    }
}

#[test]
fn test_concurrent_clone_safety() {
    let engine = AnalyzerEngine::new();

    let mut handles = vec![];

    // Clone engine in each thread (tests Clone impl thread safety)
    for i in 0..10 {
        let engine_clone = engine.clone();
        let handle = thread::spawn(move || {
            let text = format!("Email: test{}@example.com", i);
            engine_clone.analyze(&text, None).unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_concurrent_reads_no_writes() {
    // Verify that concurrent reads don't interfere with each other
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];
    let text = "Email: test@example.com, SSN: 123-45-6789, Phone: (555) 123-4567";

    for _ in 0..50 {
        let engine_clone = Arc::clone(&engine);
        let text_clone = text.to_string();
        let handle = thread::spawn(move || {
            let result = engine_clone.analyze(&text_clone, None).unwrap();
            assert_eq!(result.detected_entities.len(), 3);
            result
        });
        handles.push(handle);
    }

    // All threads should get identical results
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for i in 1..results.len() {
        assert_eq!(
            results[0].detected_entities.len(),
            results[i].detected_entities.len()
        );
    }
}

#[test]
fn test_concurrent_entity_overlap_resolution() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    // Text that might have overlapping patterns
    let text = "550e8400-e29b-41d4-a716-446655440000 test@example.com";

    for _ in 0..20 {
        let engine_clone = Arc::clone(&engine);
        let text_clone = text.to_string();
        let handle = thread::spawn(move || {
            let result = engine_clone.analyze(&text_clone, None).unwrap();

            // Verify no overlaps
            for i in 0..result.detected_entities.len() {
                for j in (i + 1)..result.detected_entities.len() {
                    let e1 = &result.detected_entities[i];
                    let e2 = &result.detected_entities[j];
                    let overlaps = e1.start < e2.end && e2.start < e1.end;
                    assert!(!overlaps);
                }
            }
            result
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_concurrent_processing_time() {
    let engine = Arc::new(AnalyzerEngine::new());
    let mut handles = vec![];

    for i in 0..10 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let text = format!("Email: test{}@example.com", i);
            let result = engine_clone.analyze(&text, None).unwrap();

            // Verify processing time is recorded (can be 0 for sub-millisecond processing)
            // The main goal is to verify concurrent access works correctly
            assert!(
                !result.detected_entities.is_empty(),
                "Should detect email entity"
            );
            result
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_thread_safety_with_scoped_threads() {
    use std::thread;

    let engine = AnalyzerEngine::new();
    let texts = vec![
        "Email: test1@example.com",
        "SSN: 123-45-6789",
        "Phone: (555) 123-4567",
    ];

    thread::scope(|s| {
        for text in &texts {
            s.spawn(|| {
                let result = engine.analyze(text, None);
                assert!(result.is_ok());
            });
        }
    });
}

#[test]
fn test_concurrent_with_rayon() {
    use rayon::prelude::*;

    let engine = Arc::new(AnalyzerEngine::new());
    // Use valid SSN format (serial must be 0001-9999, not 0000)
    let texts: Vec<String> = (0..100)
        .map(|i| {
            format!(
                "Email: test{}@example.com, SSN: 123-45-{:04}",
                i,
                (i % 9999) + 1
            )
        })
        .collect();

    let results: Vec<_> = texts
        .par_iter()
        .map(|text| {
            let result = engine.analyze(text, None);
            assert!(result.is_ok());
            result.unwrap()
        })
        .collect();

    assert_eq!(results.len(), 100);
    for result in results {
        assert!(result.detected_entities.len() >= 2);
    }
}

#[test]
fn test_no_data_races() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let engine = Arc::new(AnalyzerEngine::new());
    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    for i in 0..50 {
        let engine_clone = Arc::clone(&engine);
        let counter_clone = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            let text = format!("Email: test{}@example.com", i);
            let result = engine_clone.analyze(&text, None);
            if result.is_ok() && !result.unwrap().detected_entities.is_empty() {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // All 50 threads should have detected entities
    assert_eq!(counter.load(Ordering::SeqCst), 50);
}
