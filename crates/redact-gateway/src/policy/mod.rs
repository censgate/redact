// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Redaction policy: per-entity actions evaluated on the request hot path.
//!
//! A [`PolicySet`] holds named [`Profile`]s. Each profile maps an entity type
//! to an [`EntityAction`] (`allow`, `block`, `mask`, `replace`, `hash`, or
//! `tokenize`), with a confidence floor and optional per-entity overrides.
//! Profiles are immutable once resolved; the request path only ever reads an
//! [`std::sync::Arc`] snapshot of them.

use std::collections::BTreeMap;
use std::sync::Arc;

use redact_core::EntityType;
use serde::{Deserialize, Serialize};

/// What the gateway does with a detected entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityAction {
    /// Leave the value untouched.
    Allow,
    /// Reject the whole request.
    Block,
    /// Replace the value with a mask (for example `j***@e*****.com`).
    Mask,
    /// Replace the value with an entity label such as `[EMAIL_ADDRESS]`.
    Replace,
    /// Replace the value with a salted digest.
    Hash,
    /// Replace the value with a reversible placeholder backed by the token map.
    Tokenize,
}

impl EntityAction {
    /// Stable lowercase name used in telemetry attributes and audit records.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Mask => "mask",
            Self::Replace => "replace",
            Self::Hash => "hash",
            Self::Tokenize => "tokenize",
        }
    }

    /// Whether the action rewrites the matched span.
    pub fn rewrites(&self) -> bool {
        !matches!(self, Self::Allow | Self::Block)
    }
}

impl std::fmt::Display for EntityAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for EntityAction {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allow" | "pass" => Ok(Self::Allow),
            "block" | "reject" => Ok(Self::Block),
            "mask" => Ok(Self::Mask),
            "replace" | "redact" => Ok(Self::Replace),
            "hash" => Ok(Self::Hash),
            "tokenize" | "transform" => Ok(Self::Tokenize),
            other => Err(PolicyError::UnknownAction(other.to_string())),
        }
    }
}

/// Policy validation and lookup failures.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The action name is not one of the supported verbs.
    #[error(
        "unknown entity action `{0}` (expected allow, block, mask, replace, hash or tokenize)"
    )]
    UnknownAction(String),

    /// A profile name was referenced but not defined.
    #[error("unknown policy profile `{0}`")]
    UnknownProfile(String),

    /// The policy document is structurally invalid.
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// Per-entity override within a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRule {
    /// Action applied to matches of this entity type.
    pub action: EntityAction,
    /// Confidence floor for this entity type; falls back to the profile floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f32>,
    /// Literal replacement used when `action` is `replace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

impl EntityRule {
    /// Build a rule that applies `action` with profile defaults.
    pub fn new(action: EntityAction) -> Self {
        Self {
            action,
            min_confidence: None,
            replacement: None,
        }
    }
}

/// Masking options mirroring `redact_core::AnonymizerConfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskOptions {
    /// Character substituted for masked positions.
    #[serde(default = "MaskOptions::default_char")]
    pub mask_char: char,
    /// Leading characters left visible.
    #[serde(default)]
    pub start_chars: usize,
    /// Trailing characters left visible.
    #[serde(default)]
    pub end_chars: usize,
    /// Keep punctuation and separators, masking only alphanumerics.
    #[serde(default)]
    pub preserve_format: bool,
}

impl MaskOptions {
    fn default_char() -> char {
        '*'
    }
}

impl Default for MaskOptions {
    fn default() -> Self {
        Self {
            mask_char: '*',
            start_chars: 0,
            end_chars: 0,
            preserve_format: false,
        }
    }
}

/// Hashing options for the `hash` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HashOptions {
    /// Salt mixed into the digest. Without a salt, digests are comparable
    /// across deployments, which is rarely desirable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
}

/// Which parts of a payload are scanned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTargets {
    /// `messages[].content`, including text content parts.
    #[serde(default = "crate::policy::default_true")]
    pub request_messages: bool,
    /// `messages[].tool_calls[].function.arguments` on requests.
    #[serde(default = "crate::policy::default_true")]
    pub request_tool_calls: bool,
    /// `tools[].function.description` and schema description strings.
    #[serde(default = "crate::policy::default_true")]
    pub request_tools: bool,
    /// The top-level OpenAI `user` field.
    #[serde(default = "crate::policy::default_true")]
    pub request_user: bool,
    /// `input` on the embeddings surface and `prompt` on legacy completions.
    #[serde(default = "crate::policy::default_true")]
    pub request_input: bool,
    /// `choices[].message.content` on responses.
    #[serde(default = "crate::policy::default_true")]
    pub response_messages: bool,
    /// `choices[].message.tool_calls[].function.arguments` on responses.
    #[serde(default = "crate::policy::default_true")]
    pub response_tool_calls: bool,
    /// Additional RFC 6901 JSON pointers scanned on requests.
    #[serde(default)]
    pub request_pointers: Vec<String>,
    /// Additional RFC 6901 JSON pointers scanned on responses.
    #[serde(default)]
    pub response_pointers: Vec<String>,
}

impl Default for ScanTargets {
    fn default() -> Self {
        Self {
            request_messages: true,
            request_tool_calls: true,
            request_tools: true,
            request_user: true,
            request_input: true,
            response_messages: true,
            response_tool_calls: true,
            request_pointers: Vec::new(),
            response_pointers: Vec::new(),
        }
    }
}

pub(crate) fn default_true() -> bool {
    true
}

fn default_min_confidence() -> f32 {
    0.5
}

/// A named set of redaction rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Profile name as referenced by requests and credentials.
    #[serde(default)]
    pub name: String,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Action for entity types without an explicit rule.
    #[serde(default = "Profile::default_action_default")]
    pub default_action: EntityAction,
    /// Confidence floor below which detections are ignored.
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f32,
    /// Per-entity overrides keyed by entity type name (for example `US_SSN`).
    #[serde(default)]
    pub entities: BTreeMap<String, EntityRule>,
    /// Restore tokenized values in responses when the token map is available.
    #[serde(default = "crate::policy::default_true")]
    pub restore_responses: bool,
    /// Reject requests when a required subsystem fails instead of forwarding.
    #[serde(default = "crate::policy::default_true")]
    pub fail_closed: bool,
    /// Payload locations scanned by this profile.
    #[serde(default)]
    pub scan: ScanTargets,
    /// Pattern packs enabled for this profile. Empty means every loaded pack.
    #[serde(default)]
    pub packs: Vec<String>,
    /// Masking options for the `mask` action.
    #[serde(default)]
    pub mask: MaskOptions,
    /// Hashing options for the `hash` action.
    #[serde(default)]
    pub hash: HashOptions,
}

impl Profile {
    fn default_action_default() -> EntityAction {
        EntityAction::Replace
    }

    /// Resolve the action for a detection, honoring confidence floors.
    ///
    /// Detections below the applicable floor are treated as [`EntityAction::Allow`]
    /// so low-confidence noise never rewrites user content.
    pub fn decide(&self, entity_type: &EntityType, score: f32) -> EntityAction {
        match self.entities.get(entity_type.as_str()) {
            Some(rule) => {
                let floor = rule.min_confidence.unwrap_or(self.min_confidence);
                if score < floor {
                    EntityAction::Allow
                } else {
                    rule.action
                }
            }
            None => {
                if score < self.min_confidence {
                    EntityAction::Allow
                } else {
                    self.default_action
                }
            }
        }
    }

    /// Literal replacement configured for an entity type, if any.
    pub fn replacement_for(&self, entity_type: &EntityType) -> Option<&str> {
        self.entities
            .get(entity_type.as_str())
            .and_then(|rule| rule.replacement.as_deref())
    }

    /// Whether any rule in this profile can produce reversible tokens.
    pub fn uses_tokenization(&self) -> bool {
        self.default_action == EntityAction::Tokenize
            || self
                .entities
                .values()
                .any(|rule| rule.action == EntityAction::Tokenize)
    }

    /// Whether any rule in this profile can block a request.
    pub fn can_block(&self) -> bool {
        self.default_action == EntityAction::Block
            || self
                .entities
                .values()
                .any(|rule| rule.action == EntityAction::Block)
    }

    /// Validate ranges and rule combinations.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(PolicyError::Invalid(format!(
                "profile `{}` min_confidence must be between 0.0 and 1.0",
                self.name
            )));
        }
        for (entity, rule) in &self.entities {
            if let Some(conf) = rule.min_confidence {
                if !(0.0..=1.0).contains(&conf) {
                    return Err(PolicyError::Invalid(format!(
                        "profile `{}` entity `{entity}` min_confidence must be between 0.0 and 1.0",
                        self.name
                    )));
                }
            }
            if rule.replacement.is_some() && rule.action != EntityAction::Replace {
                return Err(PolicyError::Invalid(format!(
                    "profile `{}` entity `{entity}` sets a replacement but its action is `{}`",
                    self.name, rule.action
                )));
            }
        }
        if !self.packs.is_empty() {
            return Err(PolicyError::Invalid(format!(
                "profile `{}` sets packs: {:?}, but per-profile pack filtering is not supported yet; \
                 leave packs empty (all loaded packs apply) or omit the field",
                self.name, self.packs
            )));
        }
        Ok(())
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: None,
            default_action: EntityAction::Replace,
            min_confidence: default_min_confidence(),
            entities: BTreeMap::new(),
            restore_responses: true,
            fail_closed: true,
            scan: ScanTargets::default(),
            packs: Vec::new(),
            mask: MaskOptions::default(),
            hash: HashOptions::default(),
        }
    }
}

/// All profiles known to the gateway plus the default selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    /// Profile applied when a request does not select one.
    #[serde(default = "PolicySet::default_profile_name")]
    pub default_profile: String,
    /// Profiles by name.
    #[serde(default)]
    pub profiles: BTreeMap<String, Arc<Profile>>,
}

impl PolicySet {
    fn default_profile_name() -> String {
        "default".to_string()
    }

    /// Parse a policy document from YAML, filling in profile names and validating.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let mut set: PolicySet = serde_norway::from_str(yaml)
            .map_err(|e| PolicyError::Invalid(format!("could not parse policy YAML: {e}")))?;
        set.normalize()?;
        Ok(set)
    }

    /// Fill in profile names from their map keys and validate every profile.
    pub fn normalize(&mut self) -> Result<(), PolicyError> {
        let named: BTreeMap<String, Arc<Profile>> = self
            .profiles
            .iter()
            .map(|(key, profile)| {
                let mut profile = (**profile).clone();
                if profile.name.is_empty() {
                    profile.name = key.clone();
                }
                (key.clone(), Arc::new(profile))
            })
            .collect();
        self.profiles = named;

        if self.profiles.is_empty() {
            return Err(PolicyError::Invalid(
                "policy defines no profiles".to_string(),
            ));
        }
        if !self.profiles.contains_key(&self.default_profile) {
            return Err(PolicyError::UnknownProfile(self.default_profile.clone()));
        }
        for profile in self.profiles.values() {
            profile.validate()?;
        }
        Ok(())
    }

    /// Look up a profile by name, falling back to the default profile.
    ///
    /// Returns [`PolicyError::UnknownProfile`] when an explicit name is unknown,
    /// so a request can never silently downgrade to weaker rules.
    pub fn profile(&self, name: Option<&str>) -> Result<Arc<Profile>, PolicyError> {
        let key = name.unwrap_or(&self.default_profile);
        self.profiles
            .get(key)
            .cloned()
            .ok_or_else(|| PolicyError::UnknownProfile(key.to_string()))
    }

    /// The default profile.
    pub fn default_profile(&self) -> Arc<Profile> {
        self.profiles
            .get(&self.default_profile)
            .cloned()
            .expect("normalized policy always contains its default profile")
    }

    /// Names of every configured profile.
    pub fn profile_names(&self) -> Vec<&str> {
        self.profiles.keys().map(String::as_str).collect()
    }
}

/// The policy shipped with the gateway, used when no policy file is configured.
pub const DEFAULT_POLICY_YAML: &str = include_str!("default_policy.yaml");

impl Default for PolicySet {
    fn default() -> Self {
        Self::from_yaml(DEFAULT_POLICY_YAML).expect("bundled default policy is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_default_policy_is_valid() {
        let set = PolicySet::default();
        assert!(set.profiles.contains_key("default"));
        assert!(set.profiles.contains_key("strict"));
        assert!(set.profiles.contains_key("permissive"));
        assert_eq!(set.default_profile, "default");
    }

    #[test]
    fn secrets_are_blocked_in_the_default_profile() {
        let set = PolicySet::default();
        let profile = set.default_profile();
        assert_eq!(
            profile.decide(&EntityType::AwsAccessKey, 0.99),
            EntityAction::Block
        );
        assert_eq!(
            profile.decide(&EntityType::PrivateKey, 0.99),
            EntityAction::Block
        );
    }

    #[test]
    fn low_confidence_detections_are_left_alone() {
        let profile = Profile {
            min_confidence: 0.8,
            ..Profile::default()
        };
        assert_eq!(
            profile.decide(&EntityType::EmailAddress, 0.5),
            EntityAction::Allow
        );
        assert_eq!(
            profile.decide(&EntityType::EmailAddress, 0.9),
            EntityAction::Replace
        );
    }

    #[test]
    fn entity_rules_override_the_default_action() {
        let mut entities = BTreeMap::new();
        entities.insert("US_SSN".to_string(), EntityRule::new(EntityAction::Block));
        let profile = Profile {
            default_action: EntityAction::Mask,
            entities,
            ..Profile::default()
        };
        assert_eq!(profile.decide(&EntityType::UsSsn, 0.9), EntityAction::Block);
        assert_eq!(
            profile.decide(&EntityType::EmailAddress, 0.9),
            EntityAction::Mask
        );
        assert!(profile.can_block());
    }

    #[test]
    fn unknown_profile_is_an_error_rather_than_a_fallback() {
        let set = PolicySet::default();
        assert!(set.profile(Some("nope")).is_err());
        assert!(set.profile(None).is_ok());
    }

    #[test]
    fn action_parsing_accepts_aliases() {
        use std::str::FromStr;
        assert_eq!(
            EntityAction::from_str("transform").unwrap(),
            EntityAction::Tokenize
        );
        assert_eq!(
            EntityAction::from_str("REDACT").unwrap(),
            EntityAction::Replace
        );
        assert!(EntityAction::from_str("shred").is_err());
    }

    #[test]
    fn replacement_on_a_non_replace_rule_is_rejected() {
        let mut entities = BTreeMap::new();
        entities.insert(
            "EMAIL_ADDRESS".to_string(),
            EntityRule {
                action: EntityAction::Hash,
                min_confidence: None,
                replacement: Some("[EMAIL]".to_string()),
            },
        );
        let profile = Profile {
            entities,
            ..Profile::default()
        };
        assert!(profile.validate().is_err());
    }
}
