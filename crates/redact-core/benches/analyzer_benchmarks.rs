//! Performance benchmarks for the PII analyzer
//!
//! Run with: cargo bench --package redact-core
//! Run specific benchmark: cargo bench --package redact-core --bench analyzer_benchmarks

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use redact_core::{
    anonymizers::{AnonymizationStrategy, AnonymizerConfig},
    AnalyzerEngine, EntityType,
};
use std::hint::black_box;

/// Benchmark simple email detection
fn bench_analyze_email(c: &mut Criterion) {
    let engine = AnalyzerEngine::new();
    let text = "Contact me at john.doe@example.com for more information.";

    c.bench_function("analyze_single_email", |b| {
        b.iter(|| engine.analyze(black_box(text), None).unwrap())
    });
}

/// Benchmark multiple entity detection
fn bench_analyze_multiple(c: &mut Criterion) {
    let engine = AnalyzerEngine::new();
    let text = "John Doe (SSN: 123-45-6789) can be reached at john@example.com \
                or (555) 123-4567. Credit card: 4532123456789010.";

    c.bench_function("analyze_multiple_entities", |b| {
        b.iter(|| engine.analyze(black_box(text), None).unwrap())
    });
}

/// Benchmark with entity type filtering
fn bench_analyze_filtered(c: &mut Criterion) {
    let engine = AnalyzerEngine::new();
    let text = "Email: john@example.com, SSN: 123-45-6789, Phone: (555) 123-4567";

    c.bench_function("analyze_with_filter", |b| {
        b.iter(|| {
            engine
                .analyze_with_entities(black_box(text), &[EntityType::EmailAddress], None)
                .unwrap()
        })
    });
}

/// Benchmark text of varying lengths
fn bench_analyze_by_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("analyze_by_text_length");

    for size in [100, 500, 1000, 5000].iter() {
        let engine = AnalyzerEngine::new();
        let text = format!(
            "{}. Contact: test@example.com, SSN: 123-45-6789",
            "Lorem ipsum dolor sit amet ".repeat(*size / 30)
        );

        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &text, |b, text| {
            b.iter(|| engine.analyze(black_box(text), None).unwrap())
        });
    }
    group.finish();
}

/// Benchmark anonymization strategies
fn bench_anonymize_strategies(c: &mut Criterion) {
    let mut group = c.benchmark_group("anonymize_strategies");
    let engine = AnalyzerEngine::new();
    let text = "Email: john@example.com, SSN: 123-45-6789, Phone: (555) 123-4567";

    for strategy in [
        AnonymizationStrategy::Replace,
        AnonymizationStrategy::Mask,
        AnonymizationStrategy::Hash,
    ]
    .iter()
    {
        let config = AnonymizerConfig {
            strategy: *strategy,
            ..Default::default()
        };

        group.bench_with_input(
            BenchmarkId::new("anonymize", format!("{:?}", strategy)),
            &config,
            |b, config| {
                b.iter(|| {
                    engine
                        .analyze_and_anonymize(black_box(text), None, black_box(config))
                        .unwrap()
                })
            },
        );
    }
    group.finish();
}

/// Benchmark pattern recognizer performance
fn bench_pattern_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_recognition");
    let engine = AnalyzerEngine::new();

    let test_cases = vec![
        ("email", "Contact: john.doe@example.com"),
        ("ssn", "SSN: 123-45-6789"),
        ("phone", "Phone: (555) 123-4567"),
        ("credit_card", "Card: 4532123456789010"),
        ("ip", "IP: 192.168.1.1"),
        ("url", "Visit: https://example.com/path"),
        ("guid", "ID: 550e8400-e29b-41d4-a716-446655440000"),
    ];

    for (name, text) in test_cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), &text, |b, text| {
            b.iter(|| engine.analyze(black_box(text), None).unwrap())
        });
    }
    group.finish();
}

/// Benchmark cold vs warm performance
fn bench_cold_warm(c: &mut Criterion) {
    let text = "Email: test@example.com, SSN: 123-45-6789";

    c.bench_function("cold_start", |b| {
        b.iter(|| {
            let engine = AnalyzerEngine::new();
            engine.analyze(black_box(text), None).unwrap()
        })
    });

    let engine = AnalyzerEngine::new();
    c.bench_function("warm_analysis", |b| {
        b.iter(|| engine.analyze(black_box(text), None).unwrap())
    });
}

/// Benchmark entity overlap resolution
fn bench_overlap_resolution(c: &mut Criterion) {
    let engine = AnalyzerEngine::new();
    // Text with potentially overlapping patterns
    let text = "User ID: 550e8400-e29b-41d4-a716-446655440000 Email: admin@example.com \
                Phone: (555) 123-4567 SSN: 123-45-6789 Card: 4532123456789010";

    c.bench_function("overlap_resolution", |b| {
        b.iter(|| engine.analyze(black_box(text), None).unwrap())
    });
}

/// Benchmark throughput for batch processing
fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    let engine = AnalyzerEngine::new();

    for batch_size in [10, 50, 100].iter() {
        let texts: Vec<String> = (0..*batch_size)
            .map(|i| format!("Email {}: user{}@example.com, SSN: 123-45-{:04}", i, i, i))
            .collect();

        let total_bytes: usize = texts.iter().map(|s| s.len()).sum();
        group.throughput(Throughput::Bytes(total_bytes as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &texts,
            |b, texts| {
                b.iter(|| {
                    for text in texts {
                        engine.analyze(black_box(text), None).unwrap();
                    }
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_analyze_email,
    bench_analyze_multiple,
    bench_analyze_filtered,
    bench_analyze_by_length,
    bench_anonymize_strategies,
    bench_pattern_types,
    bench_cold_warm,
    bench_overlap_resolution,
    bench_throughput,
);
criterion_main!(benches);
