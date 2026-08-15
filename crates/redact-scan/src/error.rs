// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::scrub::scrub_secret;
use std::fmt;

/// Scanner error. [`Display`](std::fmt::Display) and [`Debug`] never include raw credentials.
#[derive(Debug)]
pub struct ScanError {
    message: String,
}

impl ScanError {
    /// Build an error after running the credential scrubber on `message`.
    pub fn new(message: impl std::fmt::Display) -> Self {
        Self {
            message: crate::scrub::scrub(&message.to_string()),
        }
    }

    /// Build an error, also replacing every occurrence of `secret`.
    pub fn with_secret(message: impl std::fmt::Display, secret: &str) -> Self {
        Self {
            message: scrub_secret(&message.to_string(), secret),
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ScanError {}

impl From<anyhow::Error> for ScanError {
    fn from(err: anyhow::Error) -> Self {
        Self::new(err)
    }
}

impl From<sqlx::Error> for ScanError {
    fn from(err: sqlx::Error) -> Self {
        Self::new(err)
    }
}
