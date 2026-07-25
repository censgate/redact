// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! YAML document schema and its mapping into [`ResolvedConfig`].
//!
//! The document types in this module are an anti-corruption boundary: they
//! model the on-disk file format and never escape into the request path. Only
//! [`GatewayDocument::apply`] converts them into resolved settings.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{AuditExport, ConfigError, ResolvedConfig, StreamMode, TraceLevel, VaultBackend};
use crate::config::AuthMode;
use crate::policy::PolicySet;

/// Root of a gateway configuration file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayDocument {
    /// Listener settings.
    #[serde(default)]
    pub server: Option<ServerDocument>,
    /// Upstream provider settings.
    #[serde(default)]
    pub upstream: Option<UpstreamDocument>,
    /// Redaction behavior outside of policy profiles.
    #[serde(default)]
    pub redaction: Option<RedactionDocument>,
    /// Pattern pack loading.
    #[serde(default)]
    pub packs: Option<PacksDocument>,
    /// Token map backend.
    #[serde(default)]
    pub vault: Option<VaultDocument>,
    /// Inbound authentication.
    #[serde(default)]
    pub auth: Option<AuthDocument>,
    /// Audit emission.
    #[serde(default)]
    pub audit: Option<AuditDocument>,
    /// Telemetry detail.
    #[serde(default)]
    pub telemetry: Option<TelemetryDocument>,
    /// Policy defined inline.
    #[serde(default)]
    pub policy: Option<PolicySet>,
    /// Policy loaded from a separate file, relative to this document.
    #[serde(default)]
    pub policy_file: Option<PathBuf>,
}

/// Listener section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerDocument {
    /// Bind address.
    pub host: Option<String>,
    /// Bind port.
    pub port: Option<u16>,
    /// Emit HTTP request tracing.
    pub enable_http_trace: Option<bool>,
    /// Serve `/metrics`.
    pub metrics_endpoint: Option<bool>,
}

/// Upstream section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamDocument {
    /// Base URL of the OpenAI-compatible provider.
    pub base_url: Option<String>,
    /// Bearer token sent upstream.
    pub api_key: Option<String>,
    /// TCP connect timeout in seconds.
    pub connect_timeout_secs: Option<u64>,
    /// Overall request timeout in seconds.
    pub request_timeout_secs: Option<u64>,
    /// Cap on buffered upstream bodies.
    pub max_body_bytes: Option<usize>,
    /// Forward the caller's `Authorization` header upstream.
    pub forward_client_authorization: Option<bool>,
}

/// Redaction section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionDocument {
    /// `buffered` or `incremental`.
    pub stream_mode: Option<StreamMode>,
    /// Trailing bytes held back in incremental mode.
    pub stream_holdback_bytes: Option<usize>,
    /// Header carrying the session identifier.
    pub session_header: Option<String>,
    /// Header selecting a policy profile.
    pub profile_header: Option<String>,
    /// Honor the profile header.
    pub allow_profile_header: Option<bool>,
}

/// Pattern pack section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacksDocument {
    /// Files or directories to load, relative to the document.
    pub paths: Option<Vec<PathBuf>>,
    /// Skip patterns compiled into the engine.
    pub disable_builtin: Option<bool>,
}

/// Token map section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultDocument {
    /// `off`, `memory` or `vault_kv2`.
    pub backend: Option<VaultBackend>,
    /// Base address of the KV v2 server.
    pub address: Option<String>,
    /// Authentication token.
    pub token: Option<String>,
    /// KV v2 mount point.
    pub mount: Option<String>,
    /// Path prefix under the mount.
    pub path_prefix: Option<String>,
    /// Enterprise namespace header.
    pub namespace: Option<String>,
    /// Mapping lifetime in seconds.
    pub ttl_secs: Option<u64>,
    /// Base64 encoded 32-byte sealing key.
    pub data_encryption_key: Option<String>,
}

/// Authentication section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthDocument {
    /// `none`, `api_key` or `oidc`.
    pub mode: Option<AuthMode>,
    /// Accepted static keys.
    pub api_keys: Option<Vec<String>>,
    /// OIDC resource-server settings.
    pub oidc: Option<OidcDocument>,
}

/// OIDC subsection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcDocument {
    /// Issuer URL.
    pub issuer: Option<String>,
    /// Expected audience.
    pub audience: Option<String>,
    /// Explicit JWKS URL.
    pub jwks_url: Option<String>,
    /// Scopes that must all be present.
    pub required_scopes: Option<Vec<String>>,
    /// Claim carrying the tenant identifier.
    pub tenant_claim: Option<String>,
    /// Claim carrying the profile name.
    pub profile_claim: Option<String>,
    /// JWKS refresh interval in seconds.
    pub jwks_refresh_secs: Option<u64>,
    /// Allowed clock skew in seconds.
    pub leeway_secs: Option<u64>,
}

/// Audit section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDocument {
    /// `off`, `stdout`, `file` or `otlp`.
    pub export: Option<AuditExport>,
    /// Destination path for the `file` sink.
    pub file_path: Option<PathBuf>,
    /// Bounded queue capacity.
    pub queue_capacity: Option<usize>,
    /// Include detected entity types in records.
    pub include_entity_types: Option<bool>,
}

/// Telemetry section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryDocument {
    /// `off`, `basic` or `detailed`.
    pub operations: Option<TraceLevel>,
    /// Span target filter directive.
    pub filter: Option<String>,
    /// Emit development-stage `gen_ai.*` attributes.
    pub genai_attributes: Option<bool>,
}

impl GatewayDocument {
    /// Parse a configuration document from a YAML string.
    pub fn from_yaml(yaml: &str, origin: &str) -> Result<Self, ConfigError> {
        serde_norway::from_str(yaml).map_err(|e| ConfigError::Parse {
            path: origin.to_string(),
            message: e.to_string(),
        })
    }

    /// Read and parse a configuration document from disk.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml(&text, &path.display().to_string())
    }

    /// Map this document onto a resolved configuration.
    ///
    /// `base_dir` resolves relative `policy_file` and pack paths so a document
    /// can be moved without rewriting its contents.
    pub fn apply(
        self,
        config: &mut ResolvedConfig,
        base_dir: Option<&Path>,
    ) -> Result<(), ConfigError> {
        if let Some(server) = self.server {
            apply_opt(&mut config.server.host, server.host);
            apply_opt(&mut config.server.port, server.port);
            apply_opt(
                &mut config.server.enable_http_trace,
                server.enable_http_trace,
            );
            apply_opt(&mut config.server.metrics_endpoint, server.metrics_endpoint);
        }

        if let Some(upstream) = self.upstream {
            apply_opt(&mut config.upstream.base_url, upstream.base_url);
            if upstream.api_key.is_some() {
                config.upstream.api_key = upstream.api_key.filter(|v| !v.is_empty());
            }
            apply_opt(
                &mut config.upstream.connect_timeout_secs,
                upstream.connect_timeout_secs,
            );
            apply_opt(
                &mut config.upstream.request_timeout_secs,
                upstream.request_timeout_secs,
            );
            apply_opt(&mut config.upstream.max_body_bytes, upstream.max_body_bytes);
            apply_opt(
                &mut config.upstream.forward_client_authorization,
                upstream.forward_client_authorization,
            );
        }

        if let Some(redaction) = self.redaction {
            apply_opt(&mut config.redaction.stream_mode, redaction.stream_mode);
            apply_opt(
                &mut config.redaction.stream_holdback_bytes,
                redaction.stream_holdback_bytes,
            );
            apply_opt(
                &mut config.redaction.session_header,
                redaction.session_header,
            );
            apply_opt(
                &mut config.redaction.profile_header,
                redaction.profile_header,
            );
            apply_opt(
                &mut config.redaction.allow_profile_header,
                redaction.allow_profile_header,
            );
        }

        if let Some(packs) = self.packs {
            if let Some(paths) = packs.paths {
                config.packs.paths = paths
                    .into_iter()
                    .map(|path| resolve_path(base_dir, path))
                    .collect();
            }
            apply_opt(&mut config.packs.disable_builtin, packs.disable_builtin);
        }

        if let Some(vault) = self.vault {
            apply_opt(&mut config.vault.backend, vault.backend);
            if vault.address.is_some() {
                config.vault.address = vault.address.filter(|v| !v.is_empty());
            }
            if vault.token.is_some() {
                config.vault.token = vault.token.filter(|v| !v.is_empty());
            }
            apply_opt(&mut config.vault.mount, vault.mount);
            apply_opt(&mut config.vault.path_prefix, vault.path_prefix);
            if vault.namespace.is_some() {
                config.vault.namespace = vault.namespace.filter(|v| !v.is_empty());
            }
            apply_opt(&mut config.vault.ttl_secs, vault.ttl_secs);
            if vault.data_encryption_key.is_some() {
                config.vault.data_encryption_key =
                    vault.data_encryption_key.filter(|v| !v.is_empty());
            }
        }

        if let Some(auth) = self.auth {
            apply_opt(&mut config.auth.mode, auth.mode);
            if let Some(keys) = auth.api_keys {
                config.auth.api_keys = keys.into_iter().filter(|k| !k.is_empty()).collect();
            }
            if let Some(oidc) = auth.oidc {
                if oidc.issuer.is_some() {
                    config.auth.oidc.issuer = oidc.issuer.filter(|v| !v.is_empty());
                }
                if oidc.audience.is_some() {
                    config.auth.oidc.audience = oidc.audience.filter(|v| !v.is_empty());
                }
                if oidc.jwks_url.is_some() {
                    config.auth.oidc.jwks_url = oidc.jwks_url.filter(|v| !v.is_empty());
                }
                if let Some(scopes) = oidc.required_scopes {
                    config.auth.oidc.required_scopes = scopes;
                }
                if oidc.tenant_claim.is_some() {
                    config.auth.oidc.tenant_claim = oidc.tenant_claim.filter(|v| !v.is_empty());
                }
                if oidc.profile_claim.is_some() {
                    config.auth.oidc.profile_claim = oidc.profile_claim.filter(|v| !v.is_empty());
                }
                apply_opt(
                    &mut config.auth.oidc.jwks_refresh_secs,
                    oidc.jwks_refresh_secs,
                );
                apply_opt(&mut config.auth.oidc.leeway_secs, oidc.leeway_secs);
            }
        }

        if let Some(audit) = self.audit {
            apply_opt(&mut config.audit.export, audit.export);
            if let Some(path) = audit.file_path {
                config.audit.file_path = Some(resolve_path(base_dir, path));
            }
            apply_opt(&mut config.audit.queue_capacity, audit.queue_capacity);
            apply_opt(
                &mut config.audit.include_entity_types,
                audit.include_entity_types,
            );
        }

        if let Some(telemetry) = self.telemetry {
            apply_opt(&mut config.telemetry.operations, telemetry.operations);
            if telemetry.filter.is_some() {
                config.telemetry.filter = telemetry.filter.filter(|v| !v.is_empty());
            }
            apply_opt(
                &mut config.telemetry.genai_attributes,
                telemetry.genai_attributes,
            );
        }

        if self.policy.is_some() && self.policy_file.is_some() {
            return Err(ConfigError::Invalid(
                "configuration sets both `policy` and `policy_file`; choose one".to_string(),
            ));
        }

        if let Some(mut policy) = self.policy {
            policy.normalize()?;
            config.policy = Arc::new(policy);
        } else if let Some(policy_file) = self.policy_file {
            let path = resolve_path(base_dir, policy_file);
            let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Io {
                path: path.display().to_string(),
                source,
            })?;
            config.policy = Arc::new(PolicySet::from_yaml(&text)?);
            config.policy_path = Some(path);
        }

        Ok(())
    }
}

fn apply_opt<T>(target: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *target = value;
    }
}

fn resolve_path(base_dir: Option<&Path>, path: PathBuf) -> PathBuf {
    match base_dir {
        Some(dir) if path.is_relative() => dir.join(path),
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::EntityAction;
    use redact_core::EntityType;

    #[test]
    fn empty_document_leaves_defaults_untouched() {
        let doc = GatewayDocument::from_yaml("{}", "test").unwrap();
        let mut config = ResolvedConfig::default();
        doc.apply(&mut config, None).unwrap();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.upstream.base_url, "http://127.0.0.1:11434");
    }

    #[test]
    fn document_maps_onto_resolved_settings() {
        let yaml = r#"
server:
  host: 127.0.0.1
  port: 9090
  metrics_endpoint: false
upstream:
  base_url: https://api.openai.com
  request_timeout_secs: 120
redaction:
  stream_mode: incremental
  stream_holdback_bytes: 64
vault:
  backend: memory
  ttl_secs: 900
auth:
  mode: api_key
  api_keys: [alpha, beta]
audit:
  export: stdout
telemetry:
  operations: detailed
  genai_attributes: true
"#;
        let doc = GatewayDocument::from_yaml(yaml, "test").unwrap();
        let mut config = ResolvedConfig::default();
        doc.apply(&mut config, None).unwrap();

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9090);
        assert!(!config.server.metrics_endpoint);
        assert_eq!(config.upstream.base_url, "https://api.openai.com");
        assert_eq!(config.upstream.request_timeout_secs, 120);
        assert_eq!(config.redaction.stream_mode, StreamMode::Incremental);
        assert_eq!(config.redaction.stream_holdback_bytes, 64);
        assert_eq!(config.vault.backend, VaultBackend::Memory);
        assert_eq!(config.vault.ttl_secs, 900);
        assert_eq!(config.auth.mode, AuthMode::ApiKey);
        assert_eq!(config.auth.api_keys.len(), 2);
        assert_eq!(config.audit.export, AuditExport::Stdout);
        assert_eq!(config.telemetry.operations, TraceLevel::Detailed);
        assert!(config.telemetry.genai_attributes);
    }

    #[test]
    fn quoted_off_parses_as_a_backend_not_a_boolean() {
        let doc = GatewayDocument::from_yaml("vault:\n  backend: \"off\"\n", "test").unwrap();
        let mut config = ResolvedConfig::default();
        doc.apply(&mut config, None).unwrap();
        assert_eq!(config.vault.backend, VaultBackend::Off);
    }

    #[test]
    fn inline_policy_replaces_the_bundled_default() {
        let yaml = r#"
policy:
  default_profile: only
  profiles:
    only:
      default_action: mask
      min_confidence: 0.4
"#;
        let doc = GatewayDocument::from_yaml(yaml, "test").unwrap();
        let mut config = ResolvedConfig::default();
        doc.apply(&mut config, None).unwrap();
        assert_eq!(config.policy.default_profile, "only");
        let profile = config.policy.default_profile();
        assert_eq!(profile.name, "only");
        assert_eq!(
            profile.decide(&EntityType::EmailAddress, 0.9),
            EntityAction::Mask
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = GatewayDocument::from_yaml("server:\n  prot: 8080\n", "test").unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn policy_and_policy_file_are_mutually_exclusive() {
        let yaml = r#"
policy_file: ./policy.yaml
policy:
  default_profile: default
  profiles:
    default: {}
"#;
        let doc = GatewayDocument::from_yaml(yaml, "test").unwrap();
        let mut config = ResolvedConfig::default();
        assert!(doc.apply(&mut config, None).is_err());
    }

    #[test]
    fn relative_paths_resolve_against_the_document() {
        let doc =
            GatewayDocument::from_yaml("packs:\n  paths: [packs/extra.yaml]\n", "test").unwrap();
        let mut config = ResolvedConfig::default();
        doc.apply(&mut config, Some(Path::new("/etc/redact")))
            .unwrap();
        assert_eq!(
            config.packs.paths,
            vec![PathBuf::from("/etc/redact/packs/extra.yaml")]
        );
    }
}
