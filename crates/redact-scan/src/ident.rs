// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Identifier quoting. Only `[A-Za-z0-9_]+` is accepted.

use anyhow::{anyhow, Result};

/// Quote a Postgres identifier after validating it is `[A-Za-z0-9_]+`.
pub fn quote_ident(name: &str) -> Result<String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(anyhow!("unsafe identifier"));
    }
    Ok(format!("\"{name}\""))
}

/// `schema.table` with both parts quoted.
pub fn qualify_table(schema: &str, table: &str) -> Result<String> {
    Ok(format!("{}.{}", quote_ident(schema)?, quote_ident(table)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_injection() {
        assert!(quote_ident("foo;drop").is_err());
        assert!(quote_ident("ok_name").is_ok());
        assert_eq!(
            qualify_table("public", "users").unwrap(),
            "\"public\".\"users\""
        );
    }
}
