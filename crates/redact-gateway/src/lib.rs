// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! OpenAI-compatible AI privacy gateway that embeds `redact-core` in-process.
//!
//! The gateway sits between an application and a model provider. On the way
//! out it detects sensitive values and applies the action a policy profile
//! specifies for each entity type: allow, block, mask, replace, hash, or
//! tokenize. On the way back it can restore tokenized values so the caller
//! sees a complete answer while the provider only ever saw placeholders.
//!
//! ```no_run
//! use redact_gateway::{config::ResolvedConfig, GatewayServer};
//!
//! # async fn run() -> anyhow::Result<()> {
//! let config = ResolvedConfig::load()?;
//! GatewayServer::new(config).await?.run().await
//! # }
//! ```

pub mod config;
pub mod error;
pub mod openai;
pub mod policy;
pub mod proxy;
pub mod redact;
pub mod routes;
pub mod server;
pub mod stream;

pub use config::{ConfigError, ConfigHandle, ResolvedConfig};
pub use error::GatewayError;
pub use policy::{EntityAction, PolicySet, Profile};
pub use server::GatewayServer;
