// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Identifier quoting. Values are always double-quoted.

use anyhow::{anyhow, Result};

/// Quote a Postgres identifier. Embedded quotes are doubled.
pub fn quote_ident(name: &str) -> Result<String> {
    if name.is_empty() || name.contains('\0') {
        return Err(anyhow!("unsafe identifier"));
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

/// `schema.table` with both parts quoted.
pub fn qualify_table(schema: &str, table: &str) -> Result<String> {
    Ok(format!("{}.{}", quote_ident(schema)?, quote_ident(table)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_escapes() {
        assert_eq!(quote_ident("ok_name").unwrap(), "\"ok_name\"");
        assert_eq!(quote_ident("e-mail").unwrap(), "\"e-mail\"");
        assert_eq!(quote_ident("foo;drop").unwrap(), "\"foo;drop\"");
        assert_eq!(quote_ident("a\"b").unwrap(), "\"a\"\"b\"");
        assert!(quote_ident("").is_err());
        assert_eq!(
            qualify_table("public", "users").unwrap(),
            "\"public\".\"users\""
        );
    }
}
