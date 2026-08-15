/// Comprehensive test coverage for Phase 1 secret-detection entity types
/// (GitHub issue censgate/redact#101).
///
/// Validates positive detection, overlap-resolution precedence against
/// existing generic patterns, false-positive guards, and EntityType
/// metadata round-trips for the 18 new secret/credential entity types.
///
/// # Secret-like fixtures
///
/// Format-accurate fixtures are required for these tests, but committing
/// complete secret-shaped literals trips GitHub secret scanning / push
/// protection (false positives — the values are never live credentials).
/// Every fixture below is assembled at run time from split parts so the
/// contiguous token never appears in source.
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
fn token(prefix: &str, body: &str) -> String {
    format!("{prefix}{body}")
}

/// Join an arbitrary number of fragments at run time.
fn join(parts: &[&str]) -> String {
    parts.concat()
}

/// Build a PEM private-key block without a contiguous BEGIN/END literal.
fn pem_block(kind: &str, body: &str) -> String {
    let begin = format!("-----{} {}-----", "BEGIN", kind);
    let end = format!("-----{} {}-----", "END", kind);
    format!("{begin}\n{body}\n{end}")
}

/// Synthetic OpenSSH PEM used by several tests.
fn sample_openssh_pem() -> String {
    let body = join(&[
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
        "\n",
        "QyNTUxOQAAACBOa1234567890abcdefghijklmnopqrstuvwxyzABCD",
    ]);
    pem_block("OPENSSH PRIVATE KEY", &body)
}

/// Classic three-segment JWT assembled from split header/payload/sig parts.
fn sample_jwt() -> String {
    let header = join(&["eyJ", "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"]);
    let payload = join(&["eyJ", "zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"]);
    let sig = join(&["SflKxwRJ", "SMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"]);
    format!("{header}.{payload}.{sig}")
}

fn sample_aws_access_key() -> String {
    // AWS documentation example shape; split so scanners do not see a full ID.
    token("AKIA", "IOSFODNN7EXAMPLE")
}

fn sample_github_token() -> String {
    token("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789")
}

fn sample_gitlab_token() -> String {
    token("glpat-", "abcdefghijklmnopqrst")
}

fn sample_slack_token() -> String {
    join(&[
        "xoxb-",
        "123456789012-",
        "123456789012-",
        "abcdefghijklmnopqrstuvwx",
    ])
}

fn sample_slack_webhook() -> String {
    join(&[
        "https://hooks.",
        "slack.com/services/",
        "T00000000/B00000000/",
        "XXXXXXXXXXXXXXXXXXXXXXXX",
    ])
}

fn sample_stripe_secret_key() -> String {
    token("sk_live_", "abcdefghijklmnopqrstuvwx")
}

fn sample_stripe_publishable_key() -> String {
    token("pk_live_", "abcdefghijklmnopqrstuvwx")
}

fn sample_google_api_key() -> String {
    // 39 chars after "AIza" to satisfy `\bAIza[A-Za-z0-9_-]{35}`.
    token("AIza", "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe")
}

fn sample_openai_api_key() -> String {
    token("sk-", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL")
}

fn sample_openai_project_key() -> String {
    token(
        "sk-proj-",
        "abcdefghij_klmnopqrst-uvwxyz0123456789ABCDEFGHIJ",
    )
}

fn sample_anthropic_api_key() -> String {
    token(
        "sk-ant-",
        "api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
    )
}

fn sample_npm_token() -> String {
    token("npm_", "abcdefghijklmnopqrstuvwxyz0123456789")
}

fn sample_pypi_token() -> String {
    token(
        "pypi-",
        "AgEIcHlwaS5vcmcabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP",
    )
}

fn sample_sendgrid_api_key() -> String {
    token(
        "SG.",
        "abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    )
}

fn sample_twilio_api_key() -> String {
    token("SK", "0123456789abcdef0123456789abcdef")
}

fn sample_telegram_bot_token() -> String {
    token("123456789:", "AAH1234567890abcdefghijklmnopqrstuv")
}

fn sample_vault_token() -> String {
    token("hvs.", "CAESIabcdefghijklmnopqrstuvwxyz0123456789")
}

fn sample_postgres_url() -> String {
    join(&[
        "postgresql://",
        "dbuser:s3cretPass@",
        "db.internal:5432/appdb",
    ])
}

fn sample_mongo_url() -> String {
    join(&[
        "mongodb+srv://",
        "admin:hunter2@",
        "cluster0.mongodb.net/test",
    ])
}

fn sample_mongo_url_with_query() -> String {
    format!("{}?retryWrites=true", sample_mongo_url())
}

// ============================================================================
// Positive detection
// ============================================================================

#[test]
fn test_private_key() {
    let openssh_pem = sample_openssh_pem();
    let text = format!("Rotate this key immediately:\n{openssh_pem}\nDo not commit.");
    assert_entity_detected(&text, EntityType::PrivateKey, 0.9);

    let rsa_pem = pem_block("RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA1234567890abcdef");
    let text2 = format!("Backup key:\n{rsa_pem}\n");
    assert_entity_detected(&text2, EntityType::PrivateKey, 0.9);
}

#[test]
fn test_jwt_token() {
    let jwt = sample_jwt();
    assert_entity_detected(
        &format!("Authorization: Bearer {jwt} in the header"),
        EntityType::JwtToken,
        0.85,
    );
}

#[test]
fn test_aws_access_key() {
    let key = sample_aws_access_key();
    assert_entity_detected(
        &format!("Set AWS_ACCESS_KEY_ID={key} in the environment"),
        EntityType::AwsAccessKey,
        0.9,
    );
}

#[test]
fn test_github_token() {
    let tok = sample_github_token();
    assert_entity_detected(
        &format!("Deploy with token {tok} in CI"),
        EntityType::GithubToken,
        0.9,
    );
}

#[test]
fn test_gitlab_token() {
    let tok = sample_gitlab_token();
    assert_entity_detected(
        &format!("CI variable GITLAB_TOKEN={tok} was leaked"),
        EntityType::GitlabToken,
        0.9,
    );
}

#[test]
fn test_slack_token() {
    let tok = sample_slack_token();
    assert_entity_detected(&format!("Bot token: {tok}"), EntityType::SlackToken, 0.9);
}

#[test]
fn test_slack_webhook() {
    let url = sample_slack_webhook();
    assert_entity_detected(
        &format!("Post alerts to {url}"),
        EntityType::SlackWebhook,
        0.9,
    );
}

#[test]
fn test_stripe_api_key() {
    let tok = sample_stripe_secret_key();
    assert_entity_detected(
        &format!("Live key {tok} must stay secret"),
        EntityType::StripeApiKey,
        0.9,
    );
}

#[test]
fn test_google_api_key() {
    let key = sample_google_api_key();
    assert_entity_detected(
        &format!("Maps key {key} is restricted"),
        EntityType::GoogleApiKey,
        0.9,
    );
}

#[test]
fn test_openai_api_key() {
    let classic = sample_openai_api_key();
    assert_entity_detected(
        &format!("export OPENAI_API_KEY={classic}"),
        EntityType::OpenAiApiKey,
        0.85,
    );
    // Project-scoped keys are a distinct shape and may contain `-` / `_`.
    let project = sample_openai_project_key();
    assert_entity_detected(
        &format!("export OPENAI_API_KEY={project}"),
        EntityType::OpenAiApiKey,
        0.85,
    );
}

#[test]
fn test_anthropic_api_key() {
    let tok = sample_anthropic_api_key();
    assert_entity_detected(
        &format!("export ANTHROPIC_API_KEY={tok}"),
        EntityType::AnthropicApiKey,
        0.9,
    );
}

#[test]
fn test_npm_token() {
    let tok = sample_npm_token();
    assert_entity_detected(
        &format!("//registry.npmjs.org/:_authToken={tok}"),
        EntityType::NpmToken,
        0.9,
    );
}

#[test]
fn test_pypi_token() {
    let tok = sample_pypi_token();
    assert_entity_detected(&format!("TWINE_PASSWORD={tok}"), EntityType::PyPiToken, 0.9);
}

#[test]
fn test_sendgrid_api_key() {
    let tok = sample_sendgrid_api_key();
    assert_entity_detected(
        &format!("SENDGRID_API_KEY={tok}"),
        EntityType::SendGridApiKey,
        0.9,
    );
}

#[test]
fn test_twilio_api_key() {
    let tok = sample_twilio_api_key();
    assert_entity_detected(
        &format!("Twilio API key {tok} in use"),
        EntityType::TwilioApiKey,
        0.8,
    );
}

#[test]
fn test_telegram_bot_token() {
    let tok = sample_telegram_bot_token();
    assert_entity_detected(
        &format!("Bot token {tok} for the alerts bot"),
        EntityType::TelegramBotToken,
        0.9,
    );
}

#[test]
fn test_hashicorp_vault_token() {
    let tok = sample_vault_token();
    assert_entity_detected(
        &format!("VAULT_TOKEN={tok}"),
        EntityType::HashicorpVaultToken,
        0.9,
    );
}

#[test]
fn test_database_connection_string() {
    let pg = sample_postgres_url();
    assert_entity_detected(
        &format!("DATABASE_URL={pg}"),
        EntityType::DatabaseConnectionString,
        0.85,
    );
    let mongo = sample_mongo_url();
    assert_entity_detected(
        &format!("Mongo connection: {mongo}"),
        EntityType::DatabaseConnectionString,
        0.85,
    );
}

#[test]
fn test_database_connection_string_captures_path_and_query() {
    let engine = create_engine();
    let pg = format!("DATABASE_URL={}", sample_postgres_url());
    let mongo = format!("Mongo: {}", sample_mongo_url_with_query());

    for (text, expected_tail) in [
        (pg.as_str(), "/appdb"),
        (mongo.as_str(), "/test?retryWrites=true"),
    ] {
        let result = engine.analyze(text, None).unwrap();
        let entity = result
            .detected_entities
            .iter()
            .find(|e| e.entity_type == EntityType::DatabaseConnectionString)
            .unwrap_or_else(|| panic!("no connection string detected in: {text}"));

        let matched = &text[entity.start..entity.end];
        assert!(
            matched.ends_with(expected_tail),
            "connection string should capture the trailing path/query; \
             expected it to end with {expected_tail:?}, got {matched:?}"
        );
    }
}

// ============================================================================
// Precedence
// ============================================================================

#[test]
fn test_anthropic_key_wins_over_openai_pattern() {
    let text = format!("export ANTHROPIC_API_KEY={}", sample_anthropic_api_key());
    assert_entity_detected(&text, EntityType::AnthropicApiKey, 0.9);
    assert_entity_not_detected(&text, EntityType::OpenAiApiKey);
}

#[test]
fn test_slack_webhook_wins_over_generic_url() {
    let text = format!("Post alerts to {}", sample_slack_webhook());
    assert_entity_detected(&text, EntityType::SlackWebhook, 0.9);
    assert_entity_not_detected(&text, EntityType::Url);
}

#[test]
fn test_private_key_pem_yields_single_entity_no_hash_overlap() {
    let openssh_pem = sample_openssh_pem();

    let engine = create_engine();
    let result = engine.analyze(&openssh_pem, None).unwrap();

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

    assert_entity_not_detected(&openssh_pem, EntityType::Md5Hash);
    assert_entity_not_detected(&openssh_pem, EntityType::Sha1Hash);
    assert_entity_not_detected(&openssh_pem, EntityType::Sha256Hash);
}

#[test]
fn test_database_connection_string_wins_over_domain_name() {
    let text = sample_postgres_url();
    assert_entity_detected(&text, EntityType::DatabaseConnectionString, 0.85);
    assert_entity_not_detected(&text, EntityType::DomainName);
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
    let short = token("ghp_", "tooshort");
    assert_entity_not_detected(&format!("token: {short}"), EntityType::GithubToken);
}

#[test]
fn test_truncated_google_key_lookalike_rejected() {
    let short = token("AIza", "Short");
    assert_entity_not_detected(&format!("key: {short}"), EntityType::GoogleApiKey);
}

#[test]
fn test_stripe_publishable_key_is_not_flagged() {
    // Publishable keys are designed to ship in client-side code. Only the
    // secret (`sk_`) and restricted (`rk_`) forms are worth redacting.
    let tok = sample_stripe_publishable_key();
    assert_entity_not_detected(
        &format!("Frontend initialises Stripe with {tok} openly"),
        EntityType::StripeApiKey,
    );
}

#[test]
fn test_hyphenated_identifier_is_not_an_openai_key() {
    // A loose `sk-[A-Za-z0-9_-]{20,}` would match ordinary identifiers.
    assert_entity_not_detected(
        "Checkout branch sk-feature-branch-for-the-new-redaction-work",
        EntityType::OpenAiApiKey,
    );
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
    assert_eq!(EntityType::GenericSecret.as_str(), "GENERIC_SECRET");
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
        EntityType::GenericSecret,
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

fn sample_generic_hex_secret() -> String {
    "a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string()
}

#[test]
fn test_generic_secret_assignment() {
    let secret = sample_generic_hex_secret();
    let text = format!("api_key={secret}");
    assert_entity_detected(&text, EntityType::GenericSecret, 0.6);
}

#[test]
fn test_generic_secret_value_only_span() {
    let engine = create_engine();
    let secret = sample_generic_hex_secret();
    let text = format!("api_key={secret}");
    let result = engine.analyze(&text, None).unwrap();
    let hit = result
        .detected_entities
        .iter()
        .find(|e| e.entity_type == EntityType::GenericSecret)
        .expect("GENERIC_SECRET");
    assert_eq!(&text[hit.start..hit.end], secret);
}

#[test]
fn test_named_github_token_wins_over_generic() {
    let tok = token("ghp_", &"A".repeat(36));
    let text = format!("token = {tok}");
    assert_entity_detected(&text, EntityType::GithubToken, 0.9);
    assert_entity_not_detected(&text, EntityType::GenericSecret);
}

#[test]
fn test_generic_secret_ignores_stopwords_and_lockfile_integrity() {
    assert_entity_not_detected("password=password", EntityType::GenericSecret);
    assert_entity_not_detected("api_key=your-key-here", EntityType::GenericSecret);
    let integrity = format!("integrity=sha512-{}", "A".repeat(64));
    assert_entity_not_detected(&integrity, EntityType::GenericSecret);
}

#[test]
fn test_generic_secret_uuid_under_strong_keyword() {
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    assert_entity_detected(&format!("api_key={uuid}"), EntityType::GenericSecret, 0.6);
    assert_entity_not_detected(&format!("revision={uuid}"), EntityType::GenericSecret);
}
