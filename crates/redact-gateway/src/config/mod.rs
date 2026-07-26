// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Resolved gateway configuration and the sources that produce it.
//!
//! Configuration reaches the request path through exactly one type,
//! [`ResolvedConfig`]. File documents and environment variables are mapped
//! into it by adapters in [`schema`] and [`env`], so parser types never leak
//! onto the hot path. Handlers read an immutable snapshot through
//! [`ConfigHandle`], which can be swapped atomically on reload.

pub mod env;
pub mod schema;

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::policy::{PolicyError, PolicySet};

/// Configuration load failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A value could not be parsed from its textual form.
    #[error("invalid value for {key}: {message}")]
    InvalidValue {
        /// Environment variable or YAML field.
        key: String,
        /// What was wrong with it.
        message: String,
    },

    /// A referenced file could not be read.
    #[error("could not read {path}: {source}")]
    Io {
        /// Path that failed.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A YAML document could not be parsed.
    #[error("could not parse {path}: {message}")]
    Parse {
        /// Path that failed.
        path: String,
        /// Parser message.
        message: String,
    },

    /// The resulting configuration is not internally consistent.
    #[error("invalid configuration: {0}")]
    Invalid(String),

    /// The policy embedded in or referenced by the configuration is invalid.
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// Where configuration is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigSourceKind {
    /// Environment variables and CLI flags only.
    Env,
    /// A YAML file only.
    File,
    /// A YAML file overlaid with environment variables.
    Layered,
}

impl ConfigSourceKind {
    /// Stable name for telemetry attributes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::File => "file",
            Self::Layered => "layered",
        }
    }
}

impl std::str::FromStr for ConfigSourceKind {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "env" | "environment" => Ok(Self::Env),
            "file" | "local" | "yaml" => Ok(Self::File),
            "layered" => Ok(Self::Layered),
            other => Err(ConfigError::InvalidValue {
                key: env::CONFIG_SOURCE.to_string(),
                message: format!("expected env, file or layered, got `{other}`"),
            }),
        }
    }
}

/// How streamed responses are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamMode {
    /// Buffer the whole upstream stream, redact once, then emit.
    Buffered,
    /// Emit redacted text as it becomes safe, holding back a trailing window.
    Incremental,
}

impl StreamMode {
    /// Stable name for telemetry attributes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Buffered => "buffered",
            Self::Incremental => "incremental",
        }
    }
}

impl std::str::FromStr for StreamMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "buffered" | "buffer" => Ok(Self::Buffered),
            "incremental" | "stream" => Ok(Self::Incremental),
            other => Err(ConfigError::InvalidValue {
                key: env::STREAM_MODE.to_string(),
                message: format!("expected buffered or incremental, got `{other}`"),
            }),
        }
    }
}

/// Token map backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultBackend {
    /// Tokenization disabled.
    Off,
    /// Process-local map. Suitable for development and single-node testing.
    Memory,
    /// KV version 2 secrets engine (HashiCorp Vault or OpenBao).
    VaultKv2,
}

impl VaultBackend {
    /// Stable name for telemetry attributes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Memory => "memory",
            Self::VaultKv2 => "vault_kv2",
        }
    }
}

impl std::str::FromStr for VaultBackend {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" => Ok(Self::Off),
            "memory" | "inmemory" | "in_memory" => Ok(Self::Memory),
            "vault_kv2" | "vault" | "kv2" | "openbao" => Ok(Self::VaultKv2),
            other => Err(ConfigError::InvalidValue {
                key: env::VAULT_BACKEND.to_string(),
                message: format!("expected off, memory or vault_kv2, got `{other}`"),
            }),
        }
    }
}

/// Inbound authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// No inbound authentication. Only appropriate on a trusted network.
    None,
    /// Static bearer keys compared in constant time.
    ApiKey,
    /// OIDC/OAuth 2.0 resource server validating bearer JWTs.
    Oidc,
}

impl AuthMode {
    /// Stable name for telemetry attributes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ApiKey => "api_key",
            Self::Oidc => "oidc",
        }
    }
}

impl std::str::FromStr for AuthMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "off" | "disabled" => Ok(Self::None),
            "api_key" | "apikey" | "key" => Ok(Self::ApiKey),
            "oidc" | "jwt" | "oauth2" => Ok(Self::Oidc),
            other => Err(ConfigError::InvalidValue {
                key: env::AUTH_MODE.to_string(),
                message: format!("expected none, api_key or oidc, got `{other}`"),
            }),
        }
    }
}

/// Where audit records are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditExport {
    /// Audit emission disabled.
    Off,
    /// One JSON object per line on standard output.
    Stdout,
    /// One JSON object per line appended to a file.
    File,
    /// OpenTelemetry log records exported over OTLP.
    Otlp,
}

impl AuditExport {
    /// Stable name for telemetry attributes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Stdout => "stdout",
            Self::File => "file",
            Self::Otlp => "otlp",
        }
    }
}

impl std::str::FromStr for AuditExport {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" => Ok(Self::Off),
            "stdout" | "console" => Ok(Self::Stdout),
            "file" => Ok(Self::File),
            "otlp" | "otel" => Ok(Self::Otlp),
            other => Err(ConfigError::InvalidValue {
                key: env::AUDIT_EXPORT.to_string(),
                message: format!("expected off, stdout, file or otlp, got `{other}`"),
            }),
        }
    }
}

/// How much operation detail the gateway records as spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceLevel {
    /// Only HTTP server and client spans.
    Off,
    /// One span per pipeline stage.
    Basic,
    /// Pipeline spans plus per-entity-type and per-chunk detail.
    Detailed,
}

impl TraceLevel {
    /// Stable name for telemetry attributes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Basic => "basic",
            Self::Detailed => "detailed",
        }
    }

    /// Whether pipeline stage spans should be created.
    pub fn records_operations(&self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Whether high-detail attributes should be attached.
    pub fn is_detailed(&self) -> bool {
        matches!(self, Self::Detailed)
    }
}

impl std::str::FromStr for TraceLevel {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "false" => Ok(Self::Off),
            "basic" | "on" | "true" => Ok(Self::Basic),
            "detailed" | "debug" | "verbose" => Ok(Self::Detailed),
            other => Err(ConfigError::InvalidValue {
                key: env::TRACE_OPERATIONS.to_string(),
                message: format!("expected off, basic or detailed, got `{other}`"),
            }),
        }
    }
}

/// Listener and HTTP surface settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Bind address.
    pub host: String,
    /// Bind port.
    pub port: u16,
    /// Emit `tower-http` request tracing.
    pub enable_http_trace: bool,
    /// Serve a pull-based metrics endpoint at `/metrics`.
    pub metrics_endpoint: bool,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            enable_http_trace: true,
            metrics_endpoint: true,
        }
    }
}

/// Inference provider settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSettings {
    /// Provider identity reported as `gen_ai.provider.name`.
    ///
    /// The OpenTelemetry GenAI conventions define well-known values such as
    /// `openai`, `anthropic`, `azure.ai.openai`, `aws.bedrock`, `gcp.gemini`,
    /// `mistral_ai` and `groq`. The default is `openai` because the gateway
    /// speaks the OpenAI wire format; set it to the value that matches who
    /// actually serves the request.
    pub name: String,
    /// Base URL of the OpenAI-compatible provider.
    pub base_url: String,
    /// Bearer token sent to the provider. Never logged or exported.
    #[serde(skip_serializing)]
    pub api_key: Option<String>,
    /// TCP connect timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Overall provider request timeout in seconds.
    pub request_timeout_secs: u64,
    /// Cap on buffered provider response bodies.
    pub max_body_bytes: usize,
    /// Forward the caller's `Authorization` header instead of the configured key.
    pub forward_client_authorization: bool,
}

impl Default for ProviderSettings {
    fn default() -> Self {
        Self {
            name: "openai".to_string(),
            base_url: "http://127.0.0.1:11434".to_string(),
            api_key: None,
            connect_timeout_secs: 10,
            request_timeout_secs: 600,
            max_body_bytes: 33_554_432,
            forward_client_authorization: false,
        }
    }
}

/// Request-path redaction behavior that is not part of a policy profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionSettings {
    /// Streaming redaction strategy.
    pub stream_mode: StreamMode,
    /// Bytes held back from the client in incremental mode so entities that
    /// straddle chunk boundaries are still detected before emission.
    pub stream_holdback_bytes: usize,
    /// Header carrying the caller's session identifier for token reuse.
    pub session_header: String,
    /// Header allowing a caller to select a policy profile.
    pub profile_header: String,
    /// Honor the profile header.
    ///
    /// Off by default: an unauthenticated caller who can set a header must not
    /// be able to choose a weaker profile than the operator configured. Enable
    /// it only when callers are trusted, or when authentication is on and the
    /// set of reachable profiles is acceptable for every caller.
    pub allow_profile_header: bool,
}

impl Default for RedactionSettings {
    fn default() -> Self {
        Self {
            stream_mode: StreamMode::Buffered,
            stream_holdback_bytes: 256,
            session_header: "x-censgate-session-id".to_string(),
            profile_header: "x-censgate-profile".to_string(),
            allow_profile_header: false,
        }
    }
}

/// Pattern pack loading.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackSettings {
    /// Directories or files scanned for pattern pack YAML documents.
    pub paths: Vec<PathBuf>,
    /// Skip the pattern packs compiled into `redact-core`.
    pub disable_builtin: bool,
}

/// Token map backend settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Selected backend.
    pub backend: VaultBackend,
    /// Base address of the KV v2 server.
    pub address: Option<String>,
    /// Authentication token. Never logged or exported.
    #[serde(skip_serializing)]
    pub token: Option<String>,
    /// KV v2 mount point.
    pub mount: String,
    /// Path prefix under the mount.
    pub path_prefix: String,
    /// Optional enterprise namespace header.
    pub namespace: Option<String>,
    /// Lifetime of stored mappings in seconds.
    pub ttl_secs: u64,
    /// Base64 encoded 32-byte data encryption key used to seal mappings.
    #[serde(skip_serializing)]
    pub data_encryption_key: Option<String>,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            backend: VaultBackend::Off,
            address: None,
            token: None,
            mount: "secret".to_string(),
            path_prefix: "redact-gateway".to_string(),
            namespace: None,
            ttl_secs: 3600,
            data_encryption_key: None,
        }
    }
}

/// OIDC resource-server settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcSettings {
    /// Issuer URL used for discovery and `iss` validation.
    pub issuer: Option<String>,
    /// Expected `aud` value.
    pub audience: Option<String>,
    /// Explicit JWKS URL, bypassing discovery.
    pub jwks_url: Option<String>,
    /// Scopes that must all be present.
    pub required_scopes: Vec<String>,
    /// Claim carrying the tenant identifier.
    pub tenant_claim: Option<String>,
    /// Claim carrying the policy profile name.
    pub profile_claim: Option<String>,
    /// How often the JWKS document is refreshed, in seconds.
    pub jwks_refresh_secs: u64,
    /// Allowed clock skew when validating time-based claims, in seconds.
    pub leeway_secs: u64,
    /// Allow omitting `audience` (disables `aud` validation). Unsafe: any JWT
    /// from the configured issuer then authenticates, including tokens minted
    /// for other applications. Prefer setting `audience`.
    #[serde(default)]
    pub allow_missing_audience: bool,
}

/// Inbound authentication settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSettings {
    /// Selected mode.
    pub mode: AuthMode,
    /// Accepted static keys. Never logged or exported.
    #[serde(skip_serializing)]
    pub api_keys: Vec<String>,
    /// OIDC settings, used when `mode` is `oidc`.
    pub oidc: OidcSettings,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            mode: AuthMode::None,
            api_keys: Vec::new(),
            oidc: OidcSettings {
                jwks_refresh_secs: 300,
                leeway_secs: 60,
                ..OidcSettings::default()
            },
        }
    }
}

/// Audit emission settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSettings {
    /// Selected sink.
    pub export: AuditExport,
    /// Destination path when the sink is `file`.
    pub file_path: Option<PathBuf>,
    /// Bounded queue capacity before records are dropped.
    pub queue_capacity: usize,
    /// Include the list of detected entity types in each record.
    pub include_entity_types: bool,
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            export: AuditExport::Off,
            file_path: None,
            queue_capacity: 4096,
            include_entity_types: true,
        }
    }
}

/// Telemetry settings that are not covered by the OpenTelemetry environment
/// variables. Exporter selection, endpoints, protocol, sampling and resource
/// attributes are all configured through the standard `OTEL_*` variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySettings {
    /// How much pipeline detail is recorded as spans.
    pub operations: TraceLevel,
    /// Optional `EnvFilter` directive scoped to gateway span targets.
    pub filter: Option<String>,
    /// Emit `gen_ai.*` attributes, which are still in development upstream.
    pub genai_attributes: bool,
}

impl Default for TelemetrySettings {
    fn default() -> Self {
        Self {
            operations: TraceLevel::Basic,
            filter: None,
            genai_attributes: false,
        }
    }
}

/// The single configuration view used by the request path.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedConfig {
    /// Which source produced this snapshot.
    pub source: ConfigSourceKind,
    /// Listener settings.
    pub server: ServerSettings,
    /// Inference provider settings.
    pub provider: ProviderSettings,
    /// Redaction behavior outside of policy profiles.
    pub redaction: RedactionSettings,
    /// Pattern pack loading.
    pub packs: PackSettings,
    /// Token map backend.
    pub vault: VaultSettings,
    /// Inbound authentication.
    pub auth: AuthSettings,
    /// Audit emission.
    pub audit: AuditSettings,
    /// Telemetry detail.
    pub telemetry: TelemetrySettings,
    /// Redaction policy profiles.
    pub policy: Arc<PolicySet>,
    /// Path of the configuration file, when one was used.
    pub config_path: Option<PathBuf>,
    /// Path of a standalone policy file, when one was used.
    pub policy_path: Option<PathBuf>,
}

impl Default for ResolvedConfig {
    fn default() -> Self {
        Self {
            source: ConfigSourceKind::Env,
            server: ServerSettings::default(),
            provider: ProviderSettings::default(),
            redaction: RedactionSettings::default(),
            packs: PackSettings::default(),
            vault: VaultSettings::default(),
            auth: AuthSettings::default(),
            audit: AuditSettings::default(),
            telemetry: TelemetrySettings::default(),
            policy: Arc::new(PolicySet::default()),
            config_path: None,
            policy_path: None,
        }
    }
}

impl ResolvedConfig {
    /// Load configuration according to `CENSGATE_CONFIG_SOURCE`.
    pub fn load() -> Result<Self, ConfigError> {
        env::load()
    }

    /// Bind address in `host:port` form.
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    /// Reject combinations that would silently weaken protection.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.provider.base_url.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "provider base URL must not be empty".to_string(),
            ));
        }
        if !self.provider.base_url.starts_with("http://")
            && !self.provider.base_url.starts_with("https://")
        {
            return Err(ConfigError::Invalid(format!(
                "provider base URL must start with http:// or https://, got `{}`",
                self.provider.base_url
            )));
        }
        if self.auth.mode == AuthMode::ApiKey && self.auth.api_keys.is_empty() {
            return Err(ConfigError::Invalid(
                "auth mode is api_key but no API keys are configured".to_string(),
            ));
        }
        if self.auth.mode == AuthMode::Oidc && self.auth.oidc.issuer.is_none() {
            return Err(ConfigError::Invalid(
                "auth mode is oidc but no issuer is configured".to_string(),
            ));
        }
        if self.auth.mode == AuthMode::Oidc
            && self
                .auth
                .oidc
                .audience
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty)
            && !self.auth.oidc.allow_missing_audience
        {
            return Err(ConfigError::Invalid(
                "auth mode is oidc but no audience is configured; set auth.oidc.audience or \
                 explicitly set auth.oidc.allow_missing_audience: true (unsafe)"
                    .to_string(),
            ));
        }
        if self.vault.backend == VaultBackend::VaultKv2 && self.vault.address.is_none() {
            return Err(ConfigError::Invalid(
                "token map backend is vault_kv2 but no address is configured".to_string(),
            ));
        }
        if self.audit.export == AuditExport::File && self.audit.file_path.is_none() {
            return Err(ConfigError::Invalid(
                "audit export is file but no path is configured".to_string(),
            ));
        }
        if self.redaction.stream_holdback_bytes == 0 {
            return Err(ConfigError::Invalid(
                "stream holdback must be greater than zero".to_string(),
            ));
        }

        // Forwarding the caller's credential upstream would hand the gateway's
        // own inbound credential to the provider, because that is the same
        // header the caller authenticated with.
        if self.provider.forward_client_authorization && self.auth.mode != AuthMode::None {
            return Err(ConfigError::Invalid(format!(
                "provider.forward_client_authorization cannot be used with auth mode `{}`: \
                 the caller's Authorization header carries the gateway credential and would \
                 be sent to the provider. Configure provider.api_key instead, or run with \
                 auth mode `none` on a trusted network.",
                self.auth.mode.as_str()
            )));
        }

        if let Some(key) = &self.vault.data_encryption_key {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(key.trim())
                .map_err(|e| {
                    ConfigError::Invalid(format!("token sealing key is not valid base64: {e}"))
                })?;
            if decoded.len() != 32 {
                return Err(ConfigError::Invalid(format!(
                    "token sealing key must decode to 32 bytes, got {}",
                    decoded.len()
                )));
            }
            // A key of all zeroes is what deployment templates carry as a
            // placeholder; treating it as real would silently make every
            // replica's ciphertext trivially forgeable.
            if decoded.iter().all(|byte| *byte == 0) {
                return Err(ConfigError::Invalid(
                    "token sealing key is all zero bytes, which is a placeholder value; \
                     generate one with `openssl rand -base64 32`"
                        .to_string(),
                ));
            }
        }

        self.warn_about_risky_combinations();
        Ok(())
    }

    /// Log combinations that are legal but easy to deploy by accident.
    fn warn_about_risky_combinations(&self) {
        if self.redaction.allow_profile_header && self.auth.mode == AuthMode::None {
            tracing::warn!(
                header = %self.redaction.profile_header,
                "profile selection by header is enabled without authentication: any caller can \
                 choose any configured profile, including weaker ones"
            );
        }

        let tokenizing = self
            .policy
            .profiles
            .values()
            .any(|profile| profile.uses_tokenization());
        if tokenizing && self.vault.backend == VaultBackend::Off {
            tracing::warn!(
                "policy uses the tokenize action with no token map backend: tokens are restored \
                 within the request that minted them, but cannot be resumed by a later request, \
                 recovered through /v1/restore, or shared with another replica"
            );
        }
        if tokenizing
            && self.vault.backend == VaultBackend::Memory
            && self.vault.data_encryption_key.is_none()
        {
            tracing::warn!(
                "token map backend is memory with a generated sealing key: tokens do not survive \
                 a restart and cannot be restored by another replica"
            );
        }
    }

    /// Build the configuration that a reload may actually install.
    ///
    /// Startup-built subsystems (listener, provider client, packs, token map,
    /// authenticator, audit sink) keep the values from `self`. Hot fields from
    /// `next` (policy, redaction, telemetry detail, …) are retained. The result
    /// is what handlers will observe, so `/readyz` and `forward_client_authorization`
    /// cannot disagree with the frozen authenticator.
    pub fn effective_for_reload(&self, mut next: ResolvedConfig) -> ResolvedConfig {
        next.server.host = self.server.host.clone();
        next.server.port = self.server.port;
        next.server.enable_http_trace = self.server.enable_http_trace;
        next.provider.base_url = self.provider.base_url.clone();
        next.provider.api_key = self.provider.api_key.clone();
        next.provider.connect_timeout_secs = self.provider.connect_timeout_secs;
        next.provider.request_timeout_secs = self.provider.request_timeout_secs;
        next.provider.max_body_bytes = self.provider.max_body_bytes;
        next.provider.forward_client_authorization = self.provider.forward_client_authorization;
        next.provider.name = self.provider.name.clone();
        next.packs = self.packs.clone();
        next.vault = self.vault.clone();
        next.auth = self.auth.clone();
        next.audit.export = self.audit.export;
        next.audit.file_path = self.audit.file_path.clone();
        next.audit.queue_capacity = self.audit.queue_capacity;
        next.telemetry.filter = self.telemetry.filter.clone();
        // Provenance fields (source, config_path, policy_path) stay from `next`
        // so operators can see which document produced the hot fields.
        next
    }

    /// Settings that a reload cannot apply, because they are consumed once at
    /// startup to build a listener, a client, or a subsystem.
    ///
    /// Returns the names of the fields that differ between `self` and `next`
    /// and would therefore only take effect after a restart.
    pub fn restart_required_changes(&self, next: &ResolvedConfig) -> Vec<&'static str> {
        let mut changed = Vec::new();

        if self.server.host != next.server.host {
            changed.push("server.host");
        }
        if self.server.port != next.server.port {
            changed.push("server.port");
        }
        if self.server.enable_http_trace != next.server.enable_http_trace {
            changed.push("server.enable_http_trace");
        }
        if self.provider.base_url != next.provider.base_url {
            changed.push("provider.base_url");
        }
        if self.provider.api_key != next.provider.api_key {
            changed.push("provider.api_key");
        }
        if self.provider.connect_timeout_secs != next.provider.connect_timeout_secs {
            changed.push("provider.connect_timeout_secs");
        }
        if self.provider.request_timeout_secs != next.provider.request_timeout_secs {
            changed.push("provider.request_timeout_secs");
        }
        if self.provider.max_body_bytes != next.provider.max_body_bytes {
            changed.push("provider.max_body_bytes");
        }
        if self.provider.forward_client_authorization != next.provider.forward_client_authorization
        {
            changed.push("provider.forward_client_authorization");
        }
        if self.provider.name != next.provider.name {
            changed.push("provider.name");
        }
        if self.packs.paths != next.packs.paths {
            changed.push("packs.paths");
        }
        if self.packs.disable_builtin != next.packs.disable_builtin {
            changed.push("packs.disable_builtin");
        }
        if self.vault.backend != next.vault.backend {
            changed.push("vault.backend");
        }
        if self.vault.address != next.vault.address
            || self.vault.token != next.vault.token
            || self.vault.mount != next.vault.mount
            || self.vault.path_prefix != next.vault.path_prefix
            || self.vault.namespace != next.vault.namespace
            || self.vault.ttl_secs != next.vault.ttl_secs
        {
            changed.push("vault.*");
        }
        if self.vault.data_encryption_key != next.vault.data_encryption_key {
            changed.push("vault.data_encryption_key");
        }
        if self.auth.mode != next.auth.mode {
            changed.push("auth.mode");
        }
        if self.auth.api_keys != next.auth.api_keys {
            changed.push("auth.api_keys");
        }
        if self.auth.oidc.issuer != next.auth.oidc.issuer
            || self.auth.oidc.audience != next.auth.oidc.audience
            || self.auth.oidc.jwks_url != next.auth.oidc.jwks_url
            || self.auth.oidc.required_scopes != next.auth.oidc.required_scopes
            || self.auth.oidc.tenant_claim != next.auth.oidc.tenant_claim
            || self.auth.oidc.profile_claim != next.auth.oidc.profile_claim
            || self.auth.oidc.jwks_refresh_secs != next.auth.oidc.jwks_refresh_secs
            || self.auth.oidc.leeway_secs != next.auth.oidc.leeway_secs
            || self.auth.oidc.allow_missing_audience != next.auth.oidc.allow_missing_audience
        {
            changed.push("auth.oidc.*");
        }
        if self.audit.export != next.audit.export {
            changed.push("audit.export");
        }
        if self.audit.file_path != next.audit.file_path {
            changed.push("audit.file_path");
        }
        if self.audit.queue_capacity != next.audit.queue_capacity {
            changed.push("audit.queue_capacity");
        }
        if self.telemetry.filter != next.telemetry.filter {
            changed.push("telemetry.filter");
        }

        changed
    }

    /// Redacted, human-readable summary suitable for logs and `print-config`.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "source": self.source.as_str(),
            "config_path": self.config_path,
            "policy_path": self.policy_path,
            "server": {
                "bind": self.bind_address(),
                "http_trace": self.server.enable_http_trace,
                "metrics_endpoint": self.server.metrics_endpoint,
            },
            "provider": {
                "name": self.provider.name,
                "base_url": self.provider.base_url,
                "api_key": self.provider.api_key.as_ref().map(|_| "<set>"),
                "forward_client_authorization": self.provider.forward_client_authorization,
                "connect_timeout_secs": self.provider.connect_timeout_secs,
                "request_timeout_secs": self.provider.request_timeout_secs,
                "max_body_bytes": self.provider.max_body_bytes,
            },
            "redaction": {
                "stream_mode": self.redaction.stream_mode.as_str(),
                "stream_holdback_bytes": self.redaction.stream_holdback_bytes,
                "profile_header": self.redaction.profile_header,
                "allow_profile_header": self.redaction.allow_profile_header,
            },
            "policy": {
                "default_profile": self.policy.default_profile,
                "profiles": self.policy.profile_names(),
            },
            "packs": {
                "paths": self.packs.paths,
                "disable_builtin": self.packs.disable_builtin,
            },
            "vault": {
                "backend": self.vault.backend.as_str(),
                "address": self.vault.address,
                "mount": self.vault.mount,
                "path_prefix": self.vault.path_prefix,
                "ttl_secs": self.vault.ttl_secs,
                "token": self.vault.token.as_ref().map(|_| "<set>"),
                "data_encryption_key": self.vault.data_encryption_key.as_ref().map(|_| "<set>"),
            },
            "auth": {
                "mode": self.auth.mode.as_str(),
                "api_keys": self.auth.api_keys.len(),
                "oidc_issuer": self.auth.oidc.issuer,
                "oidc_audience": self.auth.oidc.audience,
                "oidc_required_scopes": self.auth.oidc.required_scopes,
            },
            "audit": {
                "export": self.audit.export.as_str(),
                "file_path": self.audit.file_path,
                "queue_capacity": self.audit.queue_capacity,
            },
            "telemetry": {
                "operations": self.telemetry.operations.as_str(),
                "filter": self.telemetry.filter,
                "genai_attributes": self.telemetry.genai_attributes,
            },
        })
    }
}

/// An atomically swappable configuration snapshot.
///
/// Handlers call [`ConfigHandle::load`] once per request and work from that
/// snapshot, so a reload can never change behavior mid-request.
#[derive(Debug, Clone)]
pub struct ConfigHandle {
    inner: Arc<ArcSwap<ResolvedConfig>>,
}

impl ConfigHandle {
    /// Wrap an initial configuration.
    pub fn new(config: ResolvedConfig) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(config)),
        }
    }

    /// Read the current snapshot.
    pub fn load(&self) -> Arc<ResolvedConfig> {
        self.inner.load_full()
    }

    /// Replace the current snapshot.
    pub fn store(&self, config: ResolvedConfig) {
        self.inner.store(Arc::new(config));
    }
}

impl From<ResolvedConfig> for ConfigHandle {
    fn from(config: ResolvedConfig) -> Self {
        Self::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        let config = ResolvedConfig::default();
        config.validate().expect("default config should be valid");
        assert_eq!(config.bind_address(), "0.0.0.0:8080");
        assert_eq!(config.auth.mode, AuthMode::None);
        assert_eq!(config.vault.backend, VaultBackend::Off);
        assert_eq!(config.audit.export, AuditExport::Off);
        assert_eq!(config.telemetry.operations, TraceLevel::Basic);
    }

    #[test]
    fn api_key_mode_requires_keys() {
        let mut config = ResolvedConfig::default();
        config.auth.mode = AuthMode::ApiKey;
        assert!(config.validate().is_err());
        config.auth.api_keys.push("secret".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn vault_kv2_requires_an_address() {
        let mut config = ResolvedConfig::default();
        config.vault.backend = VaultBackend::VaultKv2;
        assert!(config.validate().is_err());
        config.vault.address = Some("http://127.0.0.1:8200".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn the_profile_header_is_off_by_default() {
        assert!(!ResolvedConfig::default().redaction.allow_profile_header);
    }

    #[test]
    fn forwarding_the_caller_credential_is_refused_when_auth_is_on() {
        let mut config = ResolvedConfig::default();
        config.provider.forward_client_authorization = true;
        config.auth.mode = AuthMode::ApiKey;
        config.auth.api_keys.push("secret".to_string());

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("forward_client_authorization"), "{err}");

        // Forwarding is legitimate when the gateway itself does not authenticate.
        config.auth.mode = AuthMode::None;
        config.auth.api_keys.clear();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_placeholder_sealing_key_is_refused() {
        use base64::Engine as _;
        let mut config = ResolvedConfig::default();
        config.vault.data_encryption_key =
            Some(base64::engine::general_purpose::STANDARD.encode([0u8; 32]));
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("placeholder"), "{err}");

        config.vault.data_encryption_key =
            Some(base64::engine::general_purpose::STANDARD.encode([7u8; 32]));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_short_sealing_key_is_refused() {
        use base64::Engine as _;
        let mut config = ResolvedConfig::default();
        config.vault.data_encryption_key =
            Some(base64::engine::general_purpose::STANDARD.encode([7u8; 16]));
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "{err}");
    }

    #[test]
    fn every_startup_only_auth_field_is_reported_on_reload() {
        let current = ResolvedConfig::default();
        for mutate in [
            (|c: &mut ResolvedConfig| c.auth.oidc.tenant_claim = Some("tid".into()))
                as fn(&mut ResolvedConfig),
            |c: &mut ResolvedConfig| c.auth.oidc.profile_claim = Some("profile".into()),
            |c: &mut ResolvedConfig| c.auth.oidc.jwks_refresh_secs = 30,
            |c: &mut ResolvedConfig| c.auth.oidc.leeway_secs = 5,
        ] {
            let mut next = ResolvedConfig::default();
            mutate(&mut next);
            assert_eq!(
                current.restart_required_changes(&next),
                vec!["auth.oidc.*"],
                "an authenticator is built once at startup, so this cannot reload silently"
            );
        }
    }

    #[test]
    fn restart_required_changes_names_startup_only_settings() {
        let current = ResolvedConfig::default();

        let mut next = ResolvedConfig::default();
        next.server.port = 9000;
        next.provider.base_url = "https://api.openai.com".to_string();
        next.auth.mode = AuthMode::None;
        assert_eq!(
            current.restart_required_changes(&next),
            vec!["server.port", "provider.base_url"]
        );

        // Settings the request path reads from the snapshot reload cleanly.
        let mut hot = ResolvedConfig::default();
        hot.redaction.allow_profile_header = true;
        hot.telemetry.operations = TraceLevel::Detailed;
        hot.server.metrics_endpoint = false;
        assert!(current.restart_required_changes(&hot).is_empty());

        let mut forward = ResolvedConfig::default();
        forward.provider.forward_client_authorization = true;
        assert_eq!(
            current.restart_required_changes(&forward),
            vec!["provider.forward_client_authorization"]
        );
    }

    #[test]
    fn effective_reload_retains_startup_auth_and_forward_flag() {
        let mut current = ResolvedConfig::default();
        current.auth.mode = AuthMode::ApiKey;
        current.auth.api_keys = vec!["gateway-secret".into()];
        current.provider.forward_client_authorization = false;

        let mut next = ResolvedConfig::default();
        next.auth.mode = AuthMode::None;
        next.provider.forward_client_authorization = true;
        next.redaction.allow_profile_header = true;

        let effective = current.effective_for_reload(next);
        assert_eq!(effective.auth.mode, AuthMode::ApiKey);
        assert!(!effective.provider.forward_client_authorization);
        assert!(effective.redaction.allow_profile_header);
        // Mixed snapshot must still validate: frozen api_key + hot forward=false.
        assert!(effective.validate().is_ok());
    }

    #[test]
    fn summary_never_reveals_secrets() {
        let mut config = ResolvedConfig::default();
        config.provider.api_key = Some("sk-supersecret".to_string());
        config.vault.token = Some("hvs.supersecret".to_string());
        config.vault.data_encryption_key = Some("QUJDREVGRw==".to_string());
        config.auth.api_keys = vec!["client-key".to_string()];

        let rendered = serde_json::to_string(&config.summary()).unwrap();
        assert!(!rendered.contains("supersecret"));
        assert!(!rendered.contains("client-key"));
        assert!(!rendered.contains("QUJDREVGRw"));
        assert!(rendered.contains("<set>"));
    }

    #[test]
    fn serialized_config_omits_secret_fields() {
        let mut config = ResolvedConfig::default();
        config.provider.api_key = Some("sk-supersecret".to_string());
        config.vault.token = Some("hvs.supersecret".to_string());
        let rendered = serde_json::to_string(&config).unwrap();
        assert!(!rendered.contains("supersecret"));
    }

    #[test]
    fn handle_swaps_snapshots_atomically() {
        let handle = ConfigHandle::new(ResolvedConfig::default());
        let first = handle.load();
        let mut next = ResolvedConfig::default();
        next.server.port = 9999;
        handle.store(next);
        assert_eq!(first.server.port, 8080, "existing snapshot is unchanged");
        assert_eq!(handle.load().server.port, 9999);
    }

    #[test]
    fn trace_level_gates_operation_spans() {
        assert!(!TraceLevel::Off.records_operations());
        assert!(TraceLevel::Basic.records_operations());
        assert!(!TraceLevel::Basic.is_detailed());
        assert!(TraceLevel::Detailed.is_detailed());
    }
}
