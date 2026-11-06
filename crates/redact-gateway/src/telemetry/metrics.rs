// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! OpenTelemetry instruments for the gateway.
//!
//! All instruments are created from the SDK meter provider. There is no
//! parallel bespoke registry: when the `prometheus` feature is enabled the
//! Prometheus exporter reads from the same provider.

use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider, UpDownCounter};
use opentelemetry::KeyValue;

use crate::redact::RedactionOutcome;

use super::semconv;

/// OpenTelemetry instruments used by the request path.
#[derive(Debug, Clone)]
pub struct Metrics {
    http_server_duration: Histogram<f64>,
    http_client_duration: Histogram<f64>,
    http_server_active: UpDownCounter<i64>,
    redactions: Counter<u64>,
    policy_decisions: Counter<u64>,
    tokenmap_operations: Counter<u64>,
    tokenmap_duration: Histogram<f64>,
    audit_dropped: Counter<u64>,
    batch_admission: Counter<u64>,
    batch_result: Counter<u64>,
    batch_stage_duration: Histogram<f64>,
    batch_leaves: Counter<u64>,
    batch_bytes: Counter<u64>,
    batch_tokens: Counter<u64>,
    batch_onnx_rounds: Counter<u64>,
}

impl Metrics {
    /// Build instruments from a meter.
    pub fn new(meter: &Meter) -> Self {
        Self {
            http_server_duration: meter
                .f64_histogram(semconv::HTTP_SERVER_REQUEST_DURATION)
                .with_description("Duration of inbound HTTP requests")
                .with_unit("s")
                .with_boundaries(semconv::HTTP_DURATION_BOUNDS.to_vec())
                .build(),
            http_client_duration: meter
                .f64_histogram(semconv::HTTP_CLIENT_REQUEST_DURATION)
                .with_description("Duration of outbound HTTP requests")
                .with_unit("s")
                .with_boundaries(semconv::HTTP_DURATION_BOUNDS.to_vec())
                .build(),
            http_server_active: meter
                .i64_up_down_counter(semconv::HTTP_SERVER_ACTIVE_REQUESTS)
                .with_description("Number of inbound HTTP requests currently being processed")
                .with_unit("{request}")
                .build(),
            redactions: meter
                .u64_counter(semconv::REDACT_GATEWAY_REDACTIONS)
                .with_description("Number of redactions applied by the gateway")
                .with_unit("{redaction}")
                .build(),
            policy_decisions: meter
                .u64_counter(semconv::REDACT_GATEWAY_POLICY_DECISIONS)
                .with_description("Policy decisions made by the gateway")
                .with_unit("{decision}")
                .build(),
            tokenmap_operations: meter
                .u64_counter(semconv::REDACT_GATEWAY_TOKENMAP_OPERATIONS)
                .with_description("Token map operations performed by the gateway")
                .with_unit("{operation}")
                .build(),
            tokenmap_duration: meter
                .f64_histogram(semconv::REDACT_GATEWAY_TOKENMAP_OPERATION_DURATION)
                .with_description("Duration of token map operations")
                .with_unit("s")
                .with_boundaries(semconv::HTTP_DURATION_BOUNDS.to_vec())
                .build(),
            audit_dropped: meter
                .u64_counter(semconv::REDACT_GATEWAY_AUDIT_RECORDS_DROPPED)
                .with_description("Audit records dropped because the dispatch queue was full")
                .with_unit("{record}")
                .build(),
            batch_admission: meter
                .u64_counter(semconv::REDACT_GATEWAY_BATCH_ADMISSION)
                .with_description("texts[] admission decisions")
                .with_unit("{request}")
                .build(),
            batch_result: meter
                .u64_counter(semconv::REDACT_GATEWAY_BATCH_RESULT)
                .with_description("texts[] results after admission")
                .with_unit("{request}")
                .build(),
            batch_stage_duration: meter
                .f64_histogram(semconv::REDACT_GATEWAY_BATCH_STAGE_DURATION)
                .with_description("Duration of texts[] queue, NER, and vault stages")
                .with_unit("s")
                .with_boundaries(semconv::BATCH_STAGE_DURATION_BOUNDS.to_vec())
                .build(),
            batch_leaves: meter
                .u64_counter(semconv::REDACT_GATEWAY_BATCH_LEAVES)
                .with_description("Leaves offered to texts[] requests")
                .with_unit("{leaf}")
                .build(),
            batch_bytes: meter
                .u64_counter(semconv::REDACT_GATEWAY_BATCH_BYTES)
                .with_description("Leaf bytes offered to texts[] requests")
                .with_unit("By")
                .build(),
            batch_tokens: meter
                .u64_counter(semconv::REDACT_GATEWAY_BATCH_TOKENS)
                .with_description("Tokens persisted by texts[] requests")
                .with_unit("{token}")
                .build(),
            batch_onnx_rounds: meter
                .u64_counter(semconv::REDACT_GATEWAY_BATCH_ONNX_ROUNDS)
                .with_description("ONNX forwards inside texts[] requests")
                .with_unit("{forward}")
                .build(),
        }
    }

    /// No-op instruments for when the SDK is disabled.
    pub fn noop() -> Self {
        let provider = opentelemetry::metrics::noop::NoopMeterProvider::new();
        let meter = provider.meter("redact-gateway");
        Self::new(&meter)
    }

    /// Record an inbound HTTP request duration and status.
    ///
    /// `route` must be the matched route template, never a raw URL path.
    /// `error_type` is set only when the request failed.
    pub fn record_http_server(
        &self,
        duration_secs: f64,
        method: &str,
        scheme: &str,
        route: &str,
        status_code: u16,
        error_type: Option<&str>,
    ) {
        let mut attrs = vec![
            KeyValue::new(semconv::HTTP_REQUEST_METHOD, method.to_string()),
            KeyValue::new(semconv::URL_SCHEME, scheme.to_string()),
            KeyValue::new(semconv::HTTP_ROUTE, route.to_string()),
            KeyValue::new(semconv::HTTP_RESPONSE_STATUS_CODE, i64::from(status_code)),
        ];
        if let Some(err) = error_type {
            attrs.push(KeyValue::new(semconv::ERROR_TYPE, err.to_string()));
        }
        self.http_server_duration.record(duration_secs, &attrs);
    }

    /// Record an outbound HTTP request duration.
    pub fn record_http_client(
        &self,
        duration_secs: f64,
        method: &str,
        status_code: Option<u16>,
        error_type: Option<&str>,
    ) {
        let mut attrs = vec![KeyValue::new(
            semconv::HTTP_REQUEST_METHOD,
            method.to_string(),
        )];
        if let Some(code) = status_code {
            attrs.push(KeyValue::new(
                semconv::HTTP_RESPONSE_STATUS_CODE,
                i64::from(code),
            ));
        }
        if let Some(err) = error_type {
            attrs.push(KeyValue::new(semconv::ERROR_TYPE, err.to_string()));
        }
        self.http_client_duration.record(duration_secs, &attrs);
    }

    /// Increment the active inbound request gauge.
    pub fn http_server_active_add(&self, delta: i64, method: &str, scheme: &str) {
        self.http_server_active.add(
            delta,
            &[
                KeyValue::new(semconv::HTTP_REQUEST_METHOD, method.to_string()),
                KeyValue::new(semconv::URL_SCHEME, scheme.to_string()),
            ],
        );
    }

    /// Record counters derived from a [`RedactionOutcome`].
    ///
    /// Each entity type is attributed to the action actually applied to it, so
    /// a payload that masks a card number and tokenizes a name produces two
    /// correctly labelled series. The policy decision for the request as a
    /// whole is recorded separately by the caller.
    pub fn record_redaction_outcome(&self, outcome: &RedactionOutcome, profile: &str) {
        let _ = profile;
        for (entity_type, actions) in &outcome.entity_action_counts {
            for (action, count) in actions {
                self.record_redaction(entity_type, action, *count as u64);
            }
        }
    }

    /// Record a single redaction with explicit entity type and action.
    pub fn record_redaction(&self, entity_type: &str, action: &str, count: u64) {
        self.redactions.add(
            count,
            &[
                KeyValue::new(semconv::REDACT_ENTITY_TYPE, entity_type.to_string()),
                KeyValue::new(semconv::REDACT_ACTION, action.to_string()),
            ],
        );
    }

    /// Record a policy decision.
    pub fn record_policy_decision(&self, profile: &str, decision: &str) {
        self.policy_decisions.add(
            1,
            &[
                KeyValue::new(semconv::REDACT_POLICY_PROFILE, profile.to_string()),
                KeyValue::new(semconv::REDACT_POLICY_DECISION, decision.to_string()),
            ],
        );
    }

    /// Record a token map operation.
    pub fn record_tokenmap_operation(
        &self,
        backend: &str,
        operation: &str,
        duration_secs: f64,
        error_type: Option<&str>,
    ) {
        let mut attrs = vec![
            KeyValue::new(semconv::REDACT_TOKENMAP_BACKEND, backend.to_string()),
            KeyValue::new(semconv::REDACT_TOKENMAP_OPERATION, operation.to_string()),
        ];
        if let Some(err) = error_type {
            attrs.push(KeyValue::new(semconv::ERROR_TYPE, err.to_string()));
        }
        self.tokenmap_operations.add(1, &attrs);
        self.tokenmap_duration.record(duration_secs, &attrs);
    }

    /// Increment the audit drop counter.
    pub fn record_audit_dropped(&self, count: u64) {
        self.audit_dropped.add(count, &[]);
    }

    /// Record a texts[] admission decision. `outcome` is `accepted` or `overload`.
    /// Counts and durations are metadata only.
    pub fn record_batch_admission(
        &self,
        outcome: &'static str,
        queue_secs: f64,
        leaves: u64,
        bytes: u64,
    ) {
        let outcome_attr = KeyValue::new(semconv::REDACT_BATCH_OUTCOME, outcome);
        self.batch_admission.add(1, &[outcome_attr.clone()]);
        self.batch_stage_duration.record(
            queue_secs,
            &[
                outcome_attr.clone(),
                KeyValue::new(semconv::REDACT_BATCH_STAGE, "queue"),
            ],
        );
        self.batch_leaves.add(leaves, &[outcome_attr.clone()]);
        self.batch_bytes.add(bytes, &[outcome_attr]);
    }

    /// Record a texts[] result after a permit was taken.
    /// `outcome` is `completed`, `deadline`, `session_map_full`, or `error`.
    pub fn record_batch_result(
        &self,
        outcome: &'static str,
        ner_secs: f64,
        onnx_secs: f64,
        vault_secs: f64,
        tokens: u64,
        onnx_rounds: u64,
    ) {
        let outcome_attr = KeyValue::new(semconv::REDACT_BATCH_OUTCOME, outcome);
        self.batch_result.add(1, &[outcome_attr.clone()]);
        self.batch_stage_duration.record(
            ner_secs,
            &[
                outcome_attr.clone(),
                KeyValue::new(semconv::REDACT_BATCH_STAGE, "ner"),
            ],
        );
        self.batch_stage_duration.record(
            onnx_secs,
            &[
                outcome_attr.clone(),
                KeyValue::new(semconv::REDACT_BATCH_STAGE, "onnx"),
            ],
        );
        self.batch_stage_duration.record(
            vault_secs,
            &[
                outcome_attr.clone(),
                KeyValue::new(semconv::REDACT_BATCH_STAGE, "vault"),
            ],
        );
        if tokens > 0 {
            self.batch_tokens.add(tokens, &[outcome_attr.clone()]);
        }
        if onnx_rounds > 0 {
            self.batch_onnx_rounds.add(onnx_rounds, &[outcome_attr]);
        }
    }
}
