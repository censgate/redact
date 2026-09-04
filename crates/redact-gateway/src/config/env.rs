// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Environment variable names and the overlay that applies them.
//!
//! Every gateway knob uses the `CENSGATE_` prefix, one name per setting. The
//! only unprefixed variables read here are the ones another system already
//! owns: `VAULT_ADDR` / `VAULT_TOKEN` (and their OpenBao `BAO_` spellings) are
//! the canonical configuration of the token map server, so an operator who has
//! already exported them does not have to restate them.
//!
//! Telemetry transport is deliberately absent: exporters, endpoints, protocol,
//! sampling and resource attributes are configured with the standard `OTEL_*`
//! variables defined by the OpenTelemetry specification.
//!
//! The inference destination is called the *provider* throughout, matching the
//! vocabulary of the OpenTelemetry GenAI conventions this gateway emits
//! (`gen_ai.provider.name`). "Backend" is reserved for the token map storage
//! backend, which is a different thing.

use std::path::PathBuf;
use std::str::FromStr;

use super::schema::GatewayDocument;
use super::{
    AuditExport, AuthMode, ConfigError, ConfigSourceKind, ResolvedConfig, StreamMode, TraceLevel,
    VaultBackend,
};
use crate::policy::PolicySet;

/// Selects the configuration source: `env`, `file` or `layered`.
pub const CONFIG_SOURCE: &str = "CENSGATE_CONFIG_SOURCE";
/// Path to the gateway configuration document.
pub const CONFIG_FILE: &str = "CENSGATE_CONFIG_FILE";
/// Path to a standalone policy document.
pub const POLICY_FILE: &str = "CENSGATE_POLICY_FILE";
/// Overrides the default policy profile name.
pub const DEFAULT_PROFILE: &str = "CENSGATE_DEFAULT_PROFILE";
/// Bind address.
pub const HOST: &str = "CENSGATE_HOST";
/// Bind port.
pub const PORT: &str = "CENSGATE_PORT";
/// Provider identity reported as `gen_ai.provider.name`.
pub const PROVIDER_NAME: &str = "CENSGATE_PROVIDER_NAME";
/// Base URL of the inference provider.
pub const PROVIDER_BASE_URL: &str = "CENSGATE_PROVIDER_BASE_URL";
/// Bearer token sent to the provider.
pub const PROVIDER_API_KEY: &str = "CENSGATE_PROVIDER_API_KEY";
/// Forward the caller's `Authorization` header to the provider.
pub const FORWARD_CLIENT_AUTH: &str = "CENSGATE_PROVIDER_FORWARD_CLIENT_AUTHORIZATION";
/// Emit HTTP request tracing.
pub const ENABLE_TRACING: &str = "CENSGATE_ENABLE_TRACING";
/// Serve the pull-based metrics endpoint.
pub const METRICS_ENDPOINT: &str = "CENSGATE_METRICS_ENDPOINT";
/// Connect timeout for provider requests, in seconds.
pub const CONNECT_TIMEOUT_SECS: &str = "CENSGATE_PROVIDER_CONNECT_TIMEOUT_SECS";
/// Overall timeout for provider requests, in seconds.
pub const REQUEST_TIMEOUT_SECS: &str = "CENSGATE_PROVIDER_REQUEST_TIMEOUT_SECS";
/// Cap on buffered provider response bodies.
pub const MAX_BODY_BYTES: &str = "CENSGATE_PROVIDER_MAX_BODY_BYTES";
/// Streaming redaction mode.
pub const STREAM_MODE: &str = "CENSGATE_STREAM_MODE";
/// Bytes held back in incremental streaming mode.
pub const STREAM_HOLDBACK_BYTES: &str = "CENSGATE_STREAM_HOLDBACK_BYTES";
/// Header carrying the caller's session identifier.
pub const SESSION_HEADER: &str = "CENSGATE_SESSION_HEADER";
/// Header selecting a policy profile.
pub const PROFILE_HEADER: &str = "CENSGATE_PROFILE_HEADER";
/// Whether the profile header is honored.
pub const ALLOW_PROFILE_HEADER: &str = "CENSGATE_ALLOW_PROFILE_HEADER";
/// Additional pattern pack files or directories.
pub const PATTERN_PACKS: &str = "CENSGATE_PATTERN_PACKS";
/// Disable the patterns compiled into the engine.
pub const DISABLE_BUILTIN_PATTERNS: &str = "CENSGATE_DISABLE_BUILTIN_PATTERNS";
/// Path to the ONNX NER model (`model.onnx`).
pub const NER_MODEL_PATH: &str = "CENSGATE_NER_MODEL_PATH";
/// When true, a missing or unloadable NER model fails gateway startup.
pub const NER_REQUIRED: &str = "CENSGATE_NER_REQUIRED";
/// Bounded ONNX session pool size (default 2, cap 4). Read by redact-ner.
pub const NER_SESSION_POOL: &str = "CENSGATE_NER_SESSION_POOL";
/// Token map backend.
pub const VAULT_BACKEND: &str = "CENSGATE_VAULT_BACKEND";
/// Token map server address.
pub const VAULT_ADDR: &str = "CENSGATE_VAULT_ADDR";
/// Token map authentication token.
pub const VAULT_TOKEN: &str = "CENSGATE_VAULT_TOKEN";
/// KV v2 mount point.
pub const VAULT_MOUNT: &str = "CENSGATE_VAULT_MOUNT";
/// Path prefix under the mount.
pub const VAULT_PATH_PREFIX: &str = "CENSGATE_VAULT_PATH_PREFIX";
/// Enterprise namespace header.
pub const VAULT_NAMESPACE: &str = "CENSGATE_VAULT_NAMESPACE";
/// Mapping lifetime in seconds.
pub const TOKEN_TTL_SECS: &str = "CENSGATE_TOKEN_TTL_SECS";
/// Base64 encoded 32-byte key used to seal mappings.
pub const TOKEN_DEK: &str = "CENSGATE_TOKEN_DEK";
/// Inbound authentication mode.
pub const AUTH_MODE: &str = "CENSGATE_AUTH_MODE";
/// Comma-separated static API keys.
pub const API_KEYS: &str = "CENSGATE_API_KEYS";
/// Legacy switch that selects OIDC mode.
pub const OIDC_ENABLED: &str = "CENSGATE_OIDC_ENABLED";
/// OIDC issuer URL.
pub const OIDC_ISSUER: &str = "CENSGATE_OIDC_ISSUER";
/// Expected OIDC audience.
pub const OIDC_AUDIENCE: &str = "CENSGATE_OIDC_AUDIENCE";
/// Explicit JWKS URL.
pub const OIDC_JWKS_URL: &str = "CENSGATE_OIDC_JWKS_URL";
/// Comma-separated scopes that must all be present.
pub const OIDC_REQUIRED_SCOPES: &str = "CENSGATE_OIDC_REQUIRED_SCOPES";
/// Claim carrying the tenant identifier.
pub const OIDC_TENANT_CLAIM: &str = "CENSGATE_OIDC_TENANT_CLAIM";
/// Claim carrying the policy profile name.
pub const OIDC_PROFILE_CLAIM: &str = "CENSGATE_OIDC_PROFILE_CLAIM";
/// JWKS refresh interval in seconds.
pub const OIDC_JWKS_REFRESH_SECS: &str = "CENSGATE_OIDC_JWKS_REFRESH_SECS";
/// Allowed clock skew in seconds.
pub const OIDC_LEEWAY_SECS: &str = "CENSGATE_OIDC_LEEWAY_SECS";
/// Allow omitting OIDC audience (unsafe).
pub const OIDC_ALLOW_MISSING_AUDIENCE: &str = "CENSGATE_OIDC_ALLOW_MISSING_AUDIENCE";
/// Audit sink selection.
pub const AUDIT_EXPORT: &str = "CENSGATE_AUDIT_EXPORT";
/// Audit file path for the `file` sink.
pub const AUDIT_FILE: &str = "CENSGATE_AUDIT_FILE";
/// Bounded audit queue capacity.
pub const AUDIT_QUEUE_CAPACITY: &str = "CENSGATE_AUDIT_QUEUE_CAPACITY";
/// Operation span detail level.
pub const TRACE_OPERATIONS: &str = "CENSGATE_TRACE_OPERATIONS";
/// Span target filter directive.
pub const TRACE_FILTER: &str = "CENSGATE_TRACE_FILTER";
/// Emit development-stage `gen_ai.*` attributes.
pub const GENAI_ATTRIBUTES: &str = "CENSGATE_GENAI_ATTRIBUTES";
/// Standard OpenTelemetry semantic convention opt-in.
pub const OTEL_SEMCONV_STABILITY_OPT_IN: &str = "OTEL_SEMCONV_STABILITY_OPT_IN";

/// Read the first non-empty value among `keys`.
fn first(keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

fn parse<T: FromStr>(key: &str, raw: &str) -> Result<T, ConfigError>
where
    T::Err: std::fmt::Display,
{
    raw.parse::<T>().map_err(|e| ConfigError::InvalidValue {
        key: key.to_string(),
        message: e.to_string(),
    })
}

fn parse_bool(key: &str, raw: &str) -> Result<bool, ConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "enabled" => Ok(true),
        "0" | "false" | "no" | "off" | "disabled" => Ok(false),
        other => Err(ConfigError::InvalidValue {
            key: key.to_string(),
            message: format!("expected a boolean, got `{other}`"),
        }),
    }
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split([',', ';'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_paths(raw: &str) -> Vec<PathBuf> {
    raw.split([',', ':', ';'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Load configuration for the current process environment.
///
/// The source is chosen by `CENSGATE_CONFIG_SOURCE`. When unset it is `layered`
/// if a configuration file is present and `env` otherwise, so the gateway runs
/// with zero configuration but picks up a file as soon as one is provided.
pub fn load() -> Result<ResolvedConfig, ConfigError> {
    let file = first(&[CONFIG_FILE]).map(PathBuf::from);
    let source = match first(&[CONFIG_SOURCE]) {
        Some(raw) => ConfigSourceKind::from_str(&raw)?,
        None if file.is_some() => ConfigSourceKind::Layered,
        None => ConfigSourceKind::Env,
    };
    load_from(source, file)
}

/// Load configuration for an explicit source and optional file path.
pub fn load_from(
    source: ConfigSourceKind,
    file: Option<PathBuf>,
) -> Result<ResolvedConfig, ConfigError> {
    let mut config = ResolvedConfig {
        source,
        ..ResolvedConfig::default()
    };

    if matches!(source, ConfigSourceKind::File | ConfigSourceKind::Layered) {
        let path = file.ok_or_else(|| {
            ConfigError::Invalid(format!(
                "config source is `{}` but {CONFIG_FILE} is not set",
                source.as_str()
            ))
        })?;
        let document = GatewayDocument::from_path(&path)?;
        let base_dir = path.parent().map(std::path::Path::to_path_buf);
        document.apply(&mut config, base_dir.as_deref())?;
        config.config_path = Some(path);
    }

    if matches!(source, ConfigSourceKind::Env | ConfigSourceKind::Layered) {
        overlay_env(&mut config)?;
    }

    config.validate()?;
    Ok(config)
}

/// Apply environment overrides onto an existing configuration.
pub fn overlay_env(config: &mut ResolvedConfig) -> Result<(), ConfigError> {
    if let Some(value) = first(&[HOST]) {
        config.server.host = value;
    }
    if let Some(value) = first(&[PORT]) {
        config.server.port = parse(PORT, &value)?;
    }
    if let Some(value) = first(&[ENABLE_TRACING]) {
        config.server.enable_http_trace = parse_bool(ENABLE_TRACING, &value)?;
    }
    if let Some(value) = first(&[METRICS_ENDPOINT]) {
        config.server.metrics_endpoint = parse_bool(METRICS_ENDPOINT, &value)?;
    }

    if let Some(value) = first(&[PROVIDER_NAME]) {
        config.provider.name = value;
    }
    if let Some(value) = first(&[PROVIDER_BASE_URL]) {
        config.provider.base_url = value;
    }
    if let Some(value) = first(&[PROVIDER_API_KEY]) {
        config.provider.api_key = Some(value);
    }
    if let Some(value) = first(&[FORWARD_CLIENT_AUTH]) {
        config.provider.forward_client_authorization = parse_bool(FORWARD_CLIENT_AUTH, &value)?;
    }
    if let Some(value) = first(&[CONNECT_TIMEOUT_SECS]) {
        config.provider.connect_timeout_secs = parse(CONNECT_TIMEOUT_SECS, &value)?;
    }
    if let Some(value) = first(&[REQUEST_TIMEOUT_SECS]) {
        config.provider.request_timeout_secs = parse(REQUEST_TIMEOUT_SECS, &value)?;
    }
    if let Some(value) = first(&[MAX_BODY_BYTES]) {
        config.provider.max_body_bytes = parse(MAX_BODY_BYTES, &value)?;
    }

    if let Some(value) = first(&[STREAM_MODE]) {
        config.redaction.stream_mode = StreamMode::from_str(&value)?;
    }
    if let Some(value) = first(&[STREAM_HOLDBACK_BYTES]) {
        config.redaction.stream_holdback_bytes = parse(STREAM_HOLDBACK_BYTES, &value)?;
    }
    if let Some(value) = first(&[SESSION_HEADER]) {
        config.redaction.session_header = value.to_ascii_lowercase();
    }
    if let Some(value) = first(&[PROFILE_HEADER]) {
        config.redaction.profile_header = value.to_ascii_lowercase();
    }
    if let Some(value) = first(&[ALLOW_PROFILE_HEADER]) {
        config.redaction.allow_profile_header = parse_bool(ALLOW_PROFILE_HEADER, &value)?;
    }

    if let Some(value) = first(&[PATTERN_PACKS]) {
        config.packs.paths = split_paths(&value);
    }
    if let Some(value) = first(&[DISABLE_BUILTIN_PATTERNS]) {
        config.packs.disable_builtin = parse_bool(DISABLE_BUILTIN_PATTERNS, &value)?;
    }
    if let Some(value) = first(&[NER_MODEL_PATH]) {
        config.ner.model_path = Some(PathBuf::from(value));
    }
    if let Some(value) = first(&[NER_REQUIRED]) {
        config.ner.required = parse_bool(NER_REQUIRED, &value)?;
    }
    // Pool size is consumed by redact-ner at ONNX load (not a gateway schema field).
    let _ = first(&[NER_SESSION_POOL]);

    if let Some(value) = first(&[VAULT_BACKEND]) {
        config.vault.backend = VaultBackend::from_str(&value)?;
    }
    if let Some(value) = first(&[VAULT_ADDR, "VAULT_ADDR", "BAO_ADDR"]) {
        config.vault.address = Some(value);
    }
    if let Some(value) = first(&[VAULT_TOKEN, "VAULT_TOKEN", "BAO_TOKEN"]) {
        config.vault.token = Some(value);
    }
    if let Some(value) = first(&[VAULT_MOUNT]) {
        config.vault.mount = value;
    }
    if let Some(value) = first(&[VAULT_PATH_PREFIX]) {
        config.vault.path_prefix = value;
    }
    if let Some(value) = first(&[VAULT_NAMESPACE, "VAULT_NAMESPACE"]) {
        config.vault.namespace = Some(value);
    }
    if let Some(value) = first(&[TOKEN_TTL_SECS]) {
        config.vault.ttl_secs = parse(TOKEN_TTL_SECS, &value)?;
    }
    if let Some(value) = first(&[TOKEN_DEK]) {
        config.vault.data_encryption_key = Some(value);
    }

    if let Some(value) = first(&[AUTH_MODE]) {
        config.auth.mode = AuthMode::from_str(&value)?;
    } else if let Some(value) = first(&[OIDC_ENABLED]) {
        if parse_bool(OIDC_ENABLED, &value)? {
            config.auth.mode = AuthMode::Oidc;
        }
    }
    if let Some(value) = first(&[API_KEYS]) {
        config.auth.api_keys = split_list(&value);
    }
    if let Some(value) = first(&[OIDC_ISSUER]) {
        config.auth.oidc.issuer = Some(value);
    }
    if let Some(value) = first(&[OIDC_AUDIENCE]) {
        config.auth.oidc.audience = Some(value);
    }
    if let Some(value) = first(&[OIDC_JWKS_URL]) {
        config.auth.oidc.jwks_url = Some(value);
    }
    if let Some(value) = first(&[OIDC_REQUIRED_SCOPES]) {
        config.auth.oidc.required_scopes = split_list(&value);
    }
    if let Some(value) = first(&[OIDC_TENANT_CLAIM]) {
        config.auth.oidc.tenant_claim = Some(value);
    }
    if let Some(value) = first(&[OIDC_PROFILE_CLAIM]) {
        config.auth.oidc.profile_claim = Some(value);
    }
    if let Some(value) = first(&[OIDC_JWKS_REFRESH_SECS]) {
        config.auth.oidc.jwks_refresh_secs = parse(OIDC_JWKS_REFRESH_SECS, &value)?;
    }
    if let Some(value) = first(&[OIDC_LEEWAY_SECS]) {
        config.auth.oidc.leeway_secs = parse(OIDC_LEEWAY_SECS, &value)?;
    }
    if let Some(value) = first(&[OIDC_ALLOW_MISSING_AUDIENCE]) {
        config.auth.oidc.allow_missing_audience = parse_bool(OIDC_ALLOW_MISSING_AUDIENCE, &value)?;
    }

    if let Some(value) = first(&[AUDIT_EXPORT]) {
        config.audit.export = AuditExport::from_str(&value)?;
    }
    if let Some(value) = first(&[AUDIT_FILE]) {
        config.audit.file_path = Some(PathBuf::from(value));
    }
    if let Some(value) = first(&[AUDIT_QUEUE_CAPACITY]) {
        config.audit.queue_capacity = parse(AUDIT_QUEUE_CAPACITY, &value)?;
    }

    if let Some(value) = first(&[TRACE_OPERATIONS]) {
        config.telemetry.operations = TraceLevel::from_str(&value)?;
    }
    if let Some(value) = first(&[TRACE_FILTER]) {
        config.telemetry.filter = Some(value);
    }
    if let Some(value) = first(&[GENAI_ATTRIBUTES]) {
        config.telemetry.genai_attributes = parse_bool(GENAI_ATTRIBUTES, &value)?;
    } else if let Some(value) = first(&[OTEL_SEMCONV_STABILITY_OPT_IN]) {
        config.telemetry.genai_attributes = value
            .split(',')
            .map(str::trim)
            .any(|token| token.eq_ignore_ascii_case("gen_ai_latest_experimental"));
    }

    if let Some(path) = first(&[POLICY_FILE]) {
        let path = PathBuf::from(path);
        let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        config.policy = std::sync::Arc::new(PolicySet::from_yaml(&text)?);
        config.policy_path = Some(path);
    }

    if let Some(value) = first(&[DEFAULT_PROFILE]) {
        let mut policy = (*config.policy).clone();
        if !policy.profiles.contains_key(&value) {
            return Err(ConfigError::InvalidValue {
                key: DEFAULT_PROFILE.to_string(),
                message: format!(
                    "unknown profile `{value}`; configured profiles are {:?}",
                    policy.profile_names()
                ),
            });
        }
        policy.default_profile = value;
        config.policy = std::sync::Arc::new(policy);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_and_path_splitting_ignores_blanks() {
        assert_eq!(split_list("a, b ,,c"), vec!["a", "b", "c"]);
        assert_eq!(
            split_paths("/a:/b,/c"),
            vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c")
            ]
        );
    }

    #[test]
    fn boolean_parsing_accepts_common_spellings() {
        assert!(parse_bool("K", "on").unwrap());
        assert!(parse_bool("K", "TRUE").unwrap());
        assert!(!parse_bool("K", "off").unwrap());
        assert!(parse_bool("K", "maybe").is_err());
    }
}
