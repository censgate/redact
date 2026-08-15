// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! CLI tool for PII detection and anonymization
//! Replacement for redactctl

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use redact_core::{
    anonymizers::{AnonymizationStrategy, AnonymizerConfig},
    AnalysisResult, AnalyzerEngine, EntityType,
};
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "redact")]
#[command(about = "PII detection and anonymization CLI", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(short, long, global = true, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Language for analysis
    #[arg(short, long, global = true, default_value = "en")]
    language: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze text for PII entities
    Analyze {
        /// Text to analyze (reads from stdin if not provided)
        text: Option<String>,

        /// Read from file(s) instead. Accepts multiple paths: `-i f1 f2` or repeated `-i f1 -i f2`.
        #[arg(short = 'i', long = "file", alias = "files", num_args = 1..)]
        files: Vec<PathBuf>,

        /// Entity types to detect (all if not specified)
        #[arg(short, long)]
        entities: Vec<String>,

        /// Entity types to exclude after `--entities` (or from the full set).
        #[arg(long = "disable")]
        disable: Vec<String>,

        /// Exit with code 1 when PII entities are detected.
        ///
        /// Useful for CI gates and pre-commit hooks. Output is printed
        /// normally before exiting. Default (off) preserves existing
        /// behavior of exiting 0 on successful analysis regardless of
        /// detections.
        #[arg(long, alias = "fail-on-detection", visible_alias = "fail-on-find")]
        fail_on_detect: bool,
    },
    /// Anonymize detected PII
    Anonymize {
        /// Text to anonymize (reads from stdin if not provided)
        text: Option<String>,

        /// Read from file(s) instead. Accepts multiple paths: `-i f1 f2` or repeated `-i f1 -i f2`.
        #[arg(short = 'i', long = "file", alias = "files", num_args = 1..)]
        files: Vec<PathBuf>,

        /// Anonymization strategy
        #[arg(short, long, value_enum, default_value = "replace")]
        strategy: StrategyArg,

        /// Entity types to anonymize (all if not specified)
        #[arg(short, long)]
        entities: Vec<String>,

        /// Entity types to exclude after `--entities` (or from the full set).
        #[arg(long = "disable")]
        disable: Vec<String>,
    },
    /// Print compiled entity types as JSON
    ListEntities,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
enum StrategyArg {
    Replace,
    Mask,
    Hash,
    Encrypt,
}

impl From<StrategyArg> for AnonymizationStrategy {
    fn from(arg: StrategyArg) -> Self {
        match arg {
            StrategyArg::Replace => AnonymizationStrategy::Replace,
            StrategyArg::Mask => AnonymizationStrategy::Mask,
            StrategyArg::Hash => AnonymizationStrategy::Hash,
            StrategyArg::Encrypt => AnonymizationStrategy::Encrypt,
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            text,
            files,
            entities,
            disable,
            fail_on_detect,
        } => {
            let inputs = collect_inputs(text, &files)?;
            let entity_types = resolve_entity_filter(&entities, &disable)?;
            let detected = analyze(&inputs, &cli.language, &entity_types, cli.format)?;
            if fail_on_detect && detected > 0 {
                std::process::exit(1);
            }
        }
        Commands::Anonymize {
            text,
            files,
            strategy,
            entities,
            disable,
        } => {
            let inputs = collect_inputs(text, &files)?;
            let entity_types = resolve_entity_filter(&entities, &disable)?;
            anonymize(
                &inputs,
                &cli.language,
                strategy.into(),
                &entity_types,
                cli.format,
            )?;
        }
        Commands::ListEntities => {
            print_entity_list(cli.format)?;
        }
    }

    Ok(())
}

fn collect_inputs(
    text: Option<String>,
    files: &[PathBuf],
) -> Result<Vec<(Option<String>, String)>> {
    if let Some(text) = text {
        return Ok(vec![(None, text)]);
    }
    if !files.is_empty() {
        let mut inputs = Vec::with_capacity(files.len());
        for f in files {
            let content = std::fs::read_to_string(f)
                .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", f.display(), e))?;
            inputs.push((Some(f.display().to_string()), content));
        }
        return Ok(inputs);
    }
    // Read from stdin
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(vec![(None, buffer)])
}

fn parse_one_entity_type(label: &str) -> Result<EntityType> {
    let from_upper = EntityType::from(label.to_uppercase());
    if !matches!(from_upper, EntityType::Custom(_)) {
        return Ok(from_upper);
    }
    match label {
        "Person" => Ok(EntityType::Person),
        "Location" => Ok(EntityType::Location),
        "Organization" => Ok(EntityType::Organization),
        "DateTime" => Ok(EntityType::DateTime),
        "EmailAddress" => Ok(EntityType::EmailAddress),
        "PhoneNumber" => Ok(EntityType::PhoneNumber),
        "IpAddress" => Ok(EntityType::IpAddress),
        "Url" => Ok(EntityType::Url),
        "DomainName" => Ok(EntityType::DomainName),
        "CreditCard" => Ok(EntityType::CreditCard),
        "Iban" | "IbanCode" => Ok(EntityType::IbanCode),
        "UsBankNumber" => Ok(EntityType::UsBankNumber),
        "UsSsn" => Ok(EntityType::UsSsn),
        "UsDriverLicense" => Ok(EntityType::UsDriverLicense),
        "UsPassport" => Ok(EntityType::UsPassport),
        "UsZipCode" => Ok(EntityType::UsZipCode),
        "UkNhs" => Ok(EntityType::UkNhs),
        "UkNino" => Ok(EntityType::UkNino),
        "UkPostcode" => Ok(EntityType::UkPostcode),
        "UkDriverLicense" => Ok(EntityType::UkDriverLicense),
        "UkPassportNumber" => Ok(EntityType::UkPassportNumber),
        "UkPhoneNumber" => Ok(EntityType::UkPhoneNumber),
        "UkMobileNumber" => Ok(EntityType::UkMobileNumber),
        "UkSortCode" => Ok(EntityType::UkSortCode),
        "UkCompanyNumber" => Ok(EntityType::UkCompanyNumber),
        "MedicalLicense" => Ok(EntityType::MedicalLicense),
        "MedicalRecordNumber" => Ok(EntityType::MedicalRecordNumber),
        "PassportNumber" => Ok(EntityType::PassportNumber),
        "Age" => Ok(EntityType::Age),
        "Isbn" => Ok(EntityType::Isbn),
        "PoBox" => Ok(EntityType::PoBox),
        "CryptoWallet" => Ok(EntityType::CryptoWallet),
        "BtcAddress" => Ok(EntityType::BtcAddress),
        "EthAddress" => Ok(EntityType::EthAddress),
        "Guid" => Ok(EntityType::Guid),
        "MacAddress" => Ok(EntityType::MacAddress),
        "Md5Hash" => Ok(EntityType::Md5Hash),
        "Sha1Hash" => Ok(EntityType::Sha1Hash),
        "Sha256Hash" => Ok(EntityType::Sha256Hash),
        // Secrets and credentials
        "PrivateKey" => Ok(EntityType::PrivateKey),
        "JwtToken" => Ok(EntityType::JwtToken),
        "AwsAccessKey" => Ok(EntityType::AwsAccessKey),
        "GithubToken" => Ok(EntityType::GithubToken),
        "GitlabToken" => Ok(EntityType::GitlabToken),
        "SlackToken" => Ok(EntityType::SlackToken),
        "SlackWebhook" => Ok(EntityType::SlackWebhook),
        "StripeApiKey" => Ok(EntityType::StripeApiKey),
        "GoogleApiKey" => Ok(EntityType::GoogleApiKey),
        "OpenAiApiKey" => Ok(EntityType::OpenAiApiKey),
        "AnthropicApiKey" => Ok(EntityType::AnthropicApiKey),
        "NpmToken" => Ok(EntityType::NpmToken),
        "PyPiToken" => Ok(EntityType::PyPiToken),
        "SendGridApiKey" => Ok(EntityType::SendGridApiKey),
        "TwilioApiKey" => Ok(EntityType::TwilioApiKey),
        "TelegramBotToken" => Ok(EntityType::TelegramBotToken),
        "HashicorpVaultToken" => Ok(EntityType::HashicorpVaultToken),
        "DatabaseConnectionString" => Ok(EntityType::DatabaseConnectionString),
        "HuggingFaceToken" => Ok(EntityType::HuggingFaceToken),
        "DatabricksToken" => Ok(EntityType::DatabricksToken),
        "DigitalOceanToken" => Ok(EntityType::DigitalOceanToken),
        "NotionApiKey" => Ok(EntityType::NotionApiKey),
        "PerplexityApiKey" => Ok(EntityType::PerplexityApiKey),
        "HttpBasicAuth" => Ok(EntityType::HttpBasicAuth),
        "GenericSecret" => Ok(EntityType::GenericSecret),
        _ => Err(anyhow::anyhow!(
            "Invalid entity type: {}. See --help for valid types",
            label
        )),
    }
}

fn parse_entity_types(entities: &[String]) -> Result<Option<Vec<EntityType>>> {
    if entities.is_empty() {
        return Ok(None);
    }
    let types: Result<Vec<EntityType>> =
        entities.iter().map(|e| parse_one_entity_type(e)).collect();
    Ok(Some(types?))
}

fn all_engine_entity_types() -> Vec<EntityType> {
    let engine = AnalyzerEngine::new();
    let mut types = Vec::new();
    for recognizer in engine.recognizer_registry().recognizers() {
        for entity in recognizer.supported_entities() {
            if !types.contains(entity) {
                types.push(entity.clone());
            }
        }
    }
    types
}

fn resolve_entity_filter(
    entities: &[String],
    disable: &[String],
) -> Result<Option<Vec<EntityType>>> {
    let disabled = disable
        .iter()
        .map(|e| parse_one_entity_type(e))
        .collect::<Result<Vec<_>>>()?;
    if entities.is_empty() && disabled.is_empty() {
        return Ok(None);
    }
    let mut selected = if entities.is_empty() {
        all_engine_entity_types()
    } else {
        parse_entity_types(entities)?.unwrap_or_default()
    };
    selected.retain(|t| !disabled.contains(t));
    if selected.is_empty() {
        return Err(anyhow::anyhow!(
            "--disable removed every selected entity type"
        ));
    }
    Ok(Some(selected))
}

fn print_entity_list(format: OutputFormat) -> Result<()> {
    let mut labels: Vec<String> = all_engine_entity_types()
        .into_iter()
        .map(|t| t.as_str().to_string())
        .collect();
    labels.sort();
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&labels)?);
        }
        OutputFormat::Text => {
            for label in labels {
                println!("{label}");
            }
        }
    }
    Ok(())
}

fn analyze(
    inputs: &[(Option<String>, String)],
    language: &str,
    entity_types: &Option<Vec<EntityType>>,
    format: OutputFormat,
) -> Result<usize> {
    let engine = AnalyzerEngine::new();
    let multi = inputs.len() > 1;
    let is_json = matches!(format, OutputFormat::Json);
    let mut total = 0;
    let mut json_entries: Vec<serde_json::Value> = Vec::new();

    for (label, content) in inputs {
        let result = if let Some(types) = entity_types {
            engine.analyze_with_entities(content, types, Some(language))?
        } else {
            engine.analyze(content, Some(language))?
        };
        total += result.detected_entities.len();

        if is_json {
            if multi {
                let entry = serde_json::json!({
                    "file": label,
                    "result": serde_json::to_value(&result)?,
                });
                json_entries.push(entry);
            } else {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        } else {
            if multi {
                println!("--- {} ---", label.as_deref().unwrap_or("stdin"));
            }
            print_analysis_text(&result);
        }
    }

    if is_json && multi {
        println!("{}", serde_json::to_string_pretty(&json_entries)?);
    }

    Ok(total)
}

fn print_analysis_text(result: &AnalysisResult) {
    if result.detected_entities.is_empty() {
        println!("No PII entities detected.");
    } else {
        println!(
            "Detected {} PII entities:\n",
            result.detected_entities.len()
        );
        for entity in &result.detected_entities {
            let text_preview = entity.text.as_deref().unwrap_or("");
            println!(
                "  {:?} at {}..{} (score: {:.2}): {}",
                entity.entity_type, entity.start, entity.end, entity.score, text_preview
            );
        }
        println!(
            "\nProcessing time: {}ms",
            result.metadata.processing_time_ms
        );
    }
}

fn anonymize(
    inputs: &[(Option<String>, String)],
    language: &str,
    strategy: AnonymizationStrategy,
    entity_types: &Option<Vec<EntityType>>,
    format: OutputFormat,
) -> Result<()> {
    let engine = AnalyzerEngine::new();
    let config = AnonymizerConfig {
        strategy,
        ..Default::default()
    };
    let multi = inputs.len() > 1;
    let is_json = matches!(format, OutputFormat::Json);
    let mut json_entries: Vec<serde_json::Value> = Vec::new();

    for (label, content) in inputs {
        let analysis = if let Some(ref types) = entity_types {
            engine.analyze_with_entities(content, types, Some(language))?
        } else {
            engine.analyze(content, Some(language))?
        };

        let anonymized = engine.anonymizer_registry().anonymize(
            content,
            analysis.detected_entities.clone(),
            &config,
        )?;

        if is_json {
            let mut result = analysis;
            result.anonymized = Some(anonymized);
            if multi {
                let entry = serde_json::json!({
                    "file": label,
                    "result": serde_json::to_value(&result)?,
                });
                json_entries.push(entry);
            } else {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        } else {
            if multi {
                println!("--- {} ---", label.as_deref().unwrap_or("stdin"));
            }
            println!("{}", anonymized.text);
        }
    }

    if is_json && multi {
        println!("{}", serde_json::to_string_pretty(&json_entries)?);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_entity_types_empty() {
        let result = parse_entity_types(&[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_entity_types_valid() {
        let entities = vec!["EmailAddress".to_string(), "UsSsn".to_string()];
        let result = parse_entity_types(&entities).unwrap();
        assert!(result.is_some());
        let types = result.unwrap();
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn test_parse_entity_types_invalid() {
        let entities = vec!["InvalidType".to_string()];
        let result = parse_entity_types(&entities);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_screaming_snake_and_generic_secret() {
        let types = parse_entity_types(&[
            "GENERIC_SECRET".to_string(),
            "GenericSecret".to_string(),
            "AwsAccessKey".to_string(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(types[0], EntityType::GenericSecret);
        assert_eq!(types[1], EntityType::GenericSecret);
        assert_eq!(types[2], EntityType::AwsAccessKey);
    }

    #[test]
    fn test_disable_subtracts_after_allow_list() {
        let filtered = resolve_entity_filter(
            &["EmailAddress".to_string(), "GenericSecret".to_string()],
            &["GENERIC_SECRET".to_string()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(filtered, vec![EntityType::EmailAddress]);
    }

    #[test]
    fn test_disable_all_is_an_error() {
        let err = resolve_entity_filter(
            &["GenericSecret".to_string()],
            &["GenericSecret".to_string()],
        )
        .unwrap_err();
        assert!(err.to_string().contains("removed every"));
    }

    #[test]
    fn test_strategy_conversion() {
        let strategy: AnonymizationStrategy = StrategyArg::Replace.into();
        assert!(matches!(strategy, AnonymizationStrategy::Replace));

        let strategy: AnonymizationStrategy = StrategyArg::Mask.into();
        assert!(matches!(strategy, AnonymizationStrategy::Mask));

        let strategy: AnonymizationStrategy = StrategyArg::Hash.into();
        assert!(matches!(strategy, AnonymizationStrategy::Hash));

        let strategy: AnonymizationStrategy = StrategyArg::Encrypt.into();
        assert!(matches!(strategy, AnonymizationStrategy::Encrypt));
    }
}
