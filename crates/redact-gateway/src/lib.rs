// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Censgate Gateway — OpenAI-compatible AI privacy gateway.
//!
//! Embeds [`redact_core::AnalyzerEngine`] in-process to redact prompts before
//! forwarding to an upstream OpenAI-compatible backend.

pub mod config;
pub mod openai;
pub mod proxy;
pub mod redact;
pub mod routes;
pub mod server;
pub mod stream;

pub use config::GatewayConfig;
pub use server::GatewayServer;
