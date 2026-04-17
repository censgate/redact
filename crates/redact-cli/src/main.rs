// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! CLI tool for PII detection and anonymization
//! Replacement for redactctl

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use redact_core::{
    anonymizers::{AnonymizationStrategy, AnonymizerConfig},
    AnalyzerEngine, EntityType,
};
use serde_json;
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

        /// Read from file instead
        #[arg(short = 'i', long)]
        file: Option<PathBuf>,

        /// Entity types to detect (all if not specified)
        #[arg(short, long)]
        entities: Vec<String>,
    },
    /// Anonymize detected PII
    Anonymize {
        /// Text to anonymize (reads from stdin if not provided)
        text: Option<String>,

        /// Read from file instead
        #[arg(short = 'i', long)]
        file: Option<PathBuf>,

        /// Anonymization strategy
        #[arg(short, long, value_enum, default_value = "replace")]
        strategy: StrategyArg,

        /// Entity types to anonymize (all if not specified)
        #[arg(short, long)]
        entities: Vec<String>,
    },
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
            file,
            entities,
        } => {
            let input = get_input(text, file)?;
            let entity_types = parse_entity_types(&entities)?;
            analyze(&input, &cli.language, entity_types, cli.format)?;
        }
        Commands::Anonymize {
            text,
            file,
            strategy,
            entities,
        } => {
            let input = get_input(text, file)?;
            let entity_types = parse_entity_types(&entities)?;
            anonymize(
                &input,
                &cli.language,
                strategy.into(),
                entity_types,
                cli.format,
            )?;
        }
    }

    Ok(())
}

fn get_input(text: Option<String>, file: Option<PathBuf>) -> Result<String> {
    if let Some(text) = text {
        Ok(text)
    } else if let Some(file_path) = file {
        Ok(std::fs::read_to_string(file_path)?)
    } else {
        // Read from stdin
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer)
    }
}

fn parse_entity_types(entities: &[String]) -> Result<Option<Vec<EntityType>>> {
    if entities.is_empty() {
        return Ok(None);
    }

    let types: Result<Vec<EntityType>> = entities
        .iter()
        .map(|e| {
            // Parse entity type from string
            match e.as_str() {
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
                _ => Err(anyhow::anyhow!(
                    "Invalid entity type: {}. See --help for valid types",
                    e
                )),
            }
        })
        .collect();

    Ok(Some(types?))
}

fn analyze(
    text: &str,
    language: &str,
    entity_types: Option<Vec<EntityType>>,
    format: OutputFormat,
) -> Result<()> {
    let engine = AnalyzerEngine::new();

    let result = if let Some(types) = entity_types {
        engine.analyze_with_entities(text, &types, Some(language))?
    } else {
        engine.analyze(text, Some(language))?
    };

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Text => {
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
    }

    Ok(())
}

fn anonymize(
    text: &str,
    language: &str,
    strategy: AnonymizationStrategy,
    entity_types: Option<Vec<EntityType>>,
    format: OutputFormat,
) -> Result<()> {
    let engine = AnalyzerEngine::new();

    // First analyze with entity type filtering if specified
    let analysis = if let Some(ref types) = entity_types {
        engine.analyze_with_entities(text, types, Some(language))?
    } else {
        engine.analyze(text, Some(language))?
    };

    let config = AnonymizerConfig {
        strategy,
        ..Default::default()
    };

    // Then anonymize the detected entities
    let anonymized = engine.anonymizer_registry().anonymize(
        text,
        analysis.detected_entities.clone(),
        &config,
    )?;

    match format {
        OutputFormat::Json => {
            let mut result = analysis;
            result.anonymized = Some(anonymized);
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Text => {
            println!("{}", anonymized.text);
        }
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
