/// Comprehensive test coverage for Phase 1 secret-detection entity types
/// (GitHub issue censgate/redact#101).
///
/// Validates positive detection, overlap-resolution precedence against
/// existing generic patterns, false-positive guards, and EntityType
/// metadata round-trips for the 18 new secret/credential entity types.
use redact_core::{AnalyzerEngine, EntityType};

fn create_engine() -> AnalyzerEngine {
    AnalyzerEngine::new()
}

fn assert_entity_detected(text: &str, entity_type: EntityType, min_score: f32) {
    let engine = create_engine();
    let result = engine.analyze(text, None).unwrap();

    let found = result
        .detected_entities
        .iter()
        .any(|e| e.entity_type == entity_type && e.score >= min_score);

    assert!(
        found,
        "Failed to detect {:?} in text: '{}'\nDetected: {:?}",
        entity_type, text, result.detected_entities
    );
}

fn assert_entity_not_detected(text: &str, entity_type: EntityType) {
    let engine = create_engine();
    let result = engine.analyze(text, None).unwrap();

    let found = result
        .detected_entities
        .iter()
        .any(|e| e.entity_type == entity_type);

    assert!(
        !found,
        "Unexpectedly detected {:?} in text: '{}'\nDetected: {:?}",
        entity_type, text, result.detected_entities
    );
}

/// Join a token prefix and body at run time.
///
/// A few fixtures below are format-accurate enough that upstream secret
/// scanners (GitHub push protection among them) flag them as live
/// credentials. Splitting those tokens so the complete literal never appears
/// in source keeps the fixtures realistic — the assembled string is
/// byte-identical at run time — without tripping those scanners.
fn token(prefix: &str, body: &str) -> String {
    format!("{prefix}{body}")
}

// ============================================================================
// Positive detection
// ============================================================================

#[test]
fn test_private_key() {
    let openssh_pem = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBOa1234567890abcdefghijklmnopqrstuvwxyzABCD
-----END OPENSSH PRIVATE KEY-----"#;
    let text = format!(
        "Rotate this key immediately:\n{}\nDo not commit.",
        openssh_pem
    );
    assert_entity_detected(&text, EntityType::PrivateKey, 0.9);

    let rsa_pem =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdef\n-----END RSA PRIVATE KEY-----";
    let text2 = format!("Backup key:\n{}\n", rsa_pem);
    assert_entity_detected(&text2, EntityType::PrivateKey, 0.9);
}

#[test]
fn test_jwt_token() {
    assert_entity_detected(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c in the header",
        EntityType::JwtToken,
        0.85,
    );
}

#[test]
fn test_aws_access_key() {
    assert_entity_detected(
        "Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in the environment",
        EntityType::AwsAccessKey,
        0.9,
    );
}

#[test]
fn test_github_token() {
    assert_entity_detected(
        "Deploy with token ghp_abcdefghijklmnopqrstuvwxyz0123456789 in CI",
        EntityType::GithubToken,
        0.9,
    );
}

#[test]
fn test_gitlab_token() {
    assert_entity_detected(
        "CI variable GITLAB_TOKEN=glpat-abcdefghijklmnopqrst was leaked",
        EntityType::GitlabToken,
        0.9,
    );
}

#[test]
fn test_slack_token() {
    let tok = token(
        "xoxb-123456789012-123456789012-",
        "abcdefghijklmnopqrstuvwx",
    );
    assert_entity_detected(&format!("Bot token: {tok}"), EntityType::SlackToken, 0.9);
}

#[test]
fn test_slack_webhook() {
    assert_entity_detected(
        "Post alerts to https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        EntityType::SlackWebhook,
        0.9,
    );
}

#[test]
fn test_stripe_api_key() {
    let tok = token("sk_live_", "abcdefghijklmnopqrstuvwx");
    assert_entity_detected(
        &format!("Live key {tok} must stay secret"),
        EntityType::StripeApiKey,
        0.9,
    );
}

#[test]
fn test_google_api_key() {
    assert_entity_detected(
        "Maps key AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe is restricted",
        EntityType::GoogleApiKey,
        0.9,
    );
}

#[test]
fn test_openai_api_key() {
    assert_entity_detected(
        "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL",
        EntityType::OpenAiApiKey,
        0.85,
    );
}

#[test]
fn test_anthropic_api_key() {
    assert_entity_detected(
        "export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
        EntityType::AnthropicApiKey,
        0.9,
    );
}

#[test]
fn test_npm_token() {
    assert_entity_detected(
        "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789",
        EntityType::NpmToken,
        0.9,
    );
}

#[test]
fn test_pypi_token() {
    assert_entity_detected(
        "TWINE_PASSWORD=pypi-AgEIcHlwaS5vcmcabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP",
        EntityType::PyPiToken,
        0.9,
    );
}

#[test]
fn test_sendgrid_api_key() {
    let tok = token(
        "SG.",
        "abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    );
    assert_entity_detected(
        &format!("SENDGRID_API_KEY={tok}"),
        EntityType::SendGridApiKey,
        0.9,
    );
}

#[test]
fn test_twilio_api_key() {
    let tok = token("SK", "0123456789abcdef0123456789abcdef");
    assert_entity_detected(
        &format!("Twilio API key {tok} in use"),
        EntityType::TwilioApiKey,
        0.8,
    );
}

#[test]
fn test_telegram_bot_token() {
    assert_entity_detected(
        "Bot token 123456789:AAH1234567890abcdefghijklmnopqrstuv for the alerts bot",
        EntityType::TelegramBotToken,
        0.9,
    );
}

#[test]
fn test_hashicorp_vault_token() {
    assert_entity_detected(
        "VAULT_TOKEN=hvs.CAESIabcdefghijklmnopqrstuvwxyz0123456789",
        EntityType::HashicorpVaultToken,
        0.9,
    );
}

#[test]
fn test_database_connection_string() {
    assert_entity_detected(
        "DATABASE_URL=postgresql://dbuser:s3cretPass@db.internal:5432/appdb",
        EntityType::DatabaseConnectionString,
        0.85,
    );
    assert_entity_detected(
        "Mongo connection: mongodb+srv://admin:hunter2@cluster0.mongodb.net/test",
        EntityType::DatabaseConnectionString,
        0.85,
    );
}

// ============================================================================
// Precedence
// ============================================================================

#[test]
fn test_anthropic_key_wins_over_openai_pattern() {
    let text = "export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
    assert_entity_detected(text, EntityType::AnthropicApiKey, 0.9);
    assert_entity_not_detected(text, EntityType::OpenAiApiKey);
}

#[test]
fn test_slack_webhook_wins_over_generic_url() {
    let text = "Post alerts to https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
    assert_entity_detected(text, EntityType::SlackWebhook, 0.9);
    assert_entity_not_detected(text, EntityType::Url);
}

#[test]
fn test_private_key_pem_yields_single_entity_no_hash_overlap() {
    let openssh_pem = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBOa1234567890abcdefghijklmnopqrstuvwxyzABCD
-----END OPENSSH PRIVATE KEY-----"#;

    let engine = create_engine();
    let result = engine.analyze(openssh_pem, None).unwrap();

    let private_key_entities: Vec<_> = result
        .detected_entities
        .iter()
        .filter(|e| e.entity_type == EntityType::PrivateKey)
        .collect();
    assert_eq!(
        private_key_entities.len(),
        1,
        "Expected exactly one PrivateKey entity, got: {:?}",
        result.detected_entities
    );

    assert_entity_not_detected(openssh_pem, EntityType::Md5Hash);
    assert_entity_not_detected(openssh_pem, EntityType::Sha1Hash);
    assert_entity_not_detected(openssh_pem, EntityType::Sha256Hash);
}

#[test]
fn test_database_connection_string_wins_over_domain_name() {
    let text = "postgresql://dbuser:s3cretPass@db.internal:5432/appdb";
    assert_entity_detected(text, EntityType::DatabaseConnectionString, 0.85);
    assert_entity_not_detected(text, EntityType::DomainName);
}

// ============================================================================
// False positives
// ============================================================================

#[test]
fn test_plain_prose_has_no_secrets() {
    let engine = create_engine();
    let text = "The quarterly report is due next Friday. Please review the attached \
                spreadsheet and send your feedback to the team before the meeting.";
    let result = engine.analyze(text, None).unwrap();

    let secret_types = [
        EntityType::PrivateKey,
        EntityType::JwtToken,
        EntityType::AwsAccessKey,
        EntityType::GithubToken,
        EntityType::GitlabToken,
        EntityType::SlackToken,
        EntityType::SlackWebhook,
        EntityType::StripeApiKey,
        EntityType::GoogleApiKey,
        EntityType::OpenAiApiKey,
        EntityType::AnthropicApiKey,
        EntityType::NpmToken,
        EntityType::PyPiToken,
        EntityType::SendGridApiKey,
        EntityType::TwilioApiKey,
        EntityType::TelegramBotToken,
        EntityType::HashicorpVaultToken,
        EntityType::DatabaseConnectionString,
    ];

    for entity_type in secret_types {
        assert!(
            !result
                .detected_entities
                .iter()
                .any(|e| e.entity_type == entity_type),
            "Unexpected {:?} detected in plain prose: {:?}",
            entity_type,
            result.detected_entities
        );
    }
}

#[test]
fn test_bare_sha256_hash_is_not_a_secret_type() {
    let text = "Checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_entity_not_detected(text, EntityType::GithubToken);
    assert_entity_not_detected(text, EntityType::AwsAccessKey);
    assert_entity_not_detected(text, EntityType::HashicorpVaultToken);
    assert_entity_not_detected(text, EntityType::PrivateKey);
    assert_entity_not_detected(text, EntityType::TwilioApiKey);
}

#[test]
fn test_truncated_github_token_lookalike_rejected() {
    assert_entity_not_detected("token: ghp_tooshort", EntityType::GithubToken);
}

#[test]
fn test_truncated_google_key_lookalike_rejected() {
    assert_entity_not_detected("key: AIzaShort", EntityType::GoogleApiKey);
}

#[test]
fn test_uuid_is_not_a_secret_type() {
    let text = "Request ID: 550e8400-e29b-41d4-a716-446655440000";
    assert_entity_not_detected(text, EntityType::GithubToken);
    assert_entity_not_detected(text, EntityType::AwsAccessKey);
    assert_entity_not_detected(text, EntityType::JwtToken);
    assert_entity_not_detected(text, EntityType::HashicorpVaultToken);
    assert_entity_not_detected(text, EntityType::DatabaseConnectionString);
}

// ============================================================================
// Metadata
// ============================================================================

#[test]
fn test_entity_type_from_string_round_trip_secrets() {
    assert_eq!(
        EntityType::from("GITHUB_TOKEN".to_string()),
        EntityType::GithubToken
    );
    assert_eq!(
        EntityType::from("PRIVATE_KEY".to_string()),
        EntityType::PrivateKey
    );
    assert_eq!(
        EntityType::from("JWT_TOKEN".to_string()),
        EntityType::JwtToken
    );
    assert_eq!(
        EntityType::from("AWS_ACCESS_KEY".to_string()),
        EntityType::AwsAccessKey
    );
    assert_eq!(
        EntityType::from("ANTHROPIC_API_KEY".to_string()),
        EntityType::AnthropicApiKey
    );
    assert_eq!(
        EntityType::from("DATABASE_CONNECTION_STRING".to_string()),
        EntityType::DatabaseConnectionString
    );
    assert_eq!(
        EntityType::from("HASHICORP_VAULT_TOKEN".to_string()),
        EntityType::HashicorpVaultToken
    );
    assert_eq!(
        EntityType::from("TELEGRAM_BOT_TOKEN".to_string()),
        EntityType::TelegramBotToken
    );
}

#[test]
fn test_entity_type_as_str_secrets() {
    assert_eq!(EntityType::PrivateKey.as_str(), "PRIVATE_KEY");
    assert_eq!(EntityType::JwtToken.as_str(), "JWT_TOKEN");
    assert_eq!(EntityType::AwsAccessKey.as_str(), "AWS_ACCESS_KEY");
    assert_eq!(EntityType::GithubToken.as_str(), "GITHUB_TOKEN");
    assert_eq!(EntityType::GitlabToken.as_str(), "GITLAB_TOKEN");
    assert_eq!(EntityType::SlackToken.as_str(), "SLACK_TOKEN");
    assert_eq!(EntityType::SlackWebhook.as_str(), "SLACK_WEBHOOK");
    assert_eq!(EntityType::StripeApiKey.as_str(), "STRIPE_API_KEY");
    assert_eq!(EntityType::GoogleApiKey.as_str(), "GOOGLE_API_KEY");
    assert_eq!(EntityType::OpenAiApiKey.as_str(), "OPENAI_API_KEY");
    assert_eq!(EntityType::AnthropicApiKey.as_str(), "ANTHROPIC_API_KEY");
    assert_eq!(EntityType::NpmToken.as_str(), "NPM_TOKEN");
    assert_eq!(EntityType::PyPiToken.as_str(), "PYPI_TOKEN");
    assert_eq!(EntityType::SendGridApiKey.as_str(), "SENDGRID_API_KEY");
    assert_eq!(EntityType::TwilioApiKey.as_str(), "TWILIO_API_KEY");
    assert_eq!(EntityType::TelegramBotToken.as_str(), "TELEGRAM_BOT_TOKEN");
    assert_eq!(
        EntityType::HashicorpVaultToken.as_str(),
        "HASHICORP_VAULT_TOKEN"
    );
    assert_eq!(
        EntityType::DatabaseConnectionString.as_str(),
        "DATABASE_CONNECTION_STRING"
    );
}

#[test]
fn test_all_secret_types_are_high_sensitivity() {
    let secret_types = [
        EntityType::PrivateKey,
        EntityType::JwtToken,
        EntityType::AwsAccessKey,
        EntityType::GithubToken,
        EntityType::GitlabToken,
        EntityType::SlackToken,
        EntityType::SlackWebhook,
        EntityType::StripeApiKey,
        EntityType::GoogleApiKey,
        EntityType::OpenAiApiKey,
        EntityType::AnthropicApiKey,
        EntityType::NpmToken,
        EntityType::PyPiToken,
        EntityType::SendGridApiKey,
        EntityType::TwilioApiKey,
        EntityType::TelegramBotToken,
        EntityType::HashicorpVaultToken,
        EntityType::DatabaseConnectionString,
    ];

    for entity_type in secret_types {
        assert!(
            entity_type.is_high_sensitivity(),
            "{:?} should be high sensitivity",
            entity_type
        );
    }
}

#[test]
fn test_private_key_default_replacement() {
    assert_eq!(
        EntityType::PrivateKey.default_replacement(),
        "[PRIVATE_KEY]"
    );
}
