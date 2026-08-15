// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Read-only session setup and privilege refusal.

use sqlx::{postgres::PgConnectOptions, postgres::PgPoolOptions, PgPool};
use std::str::FromStr;
use std::time::Duration;

use crate::error::ScanError;

/// Privilege names that must not be present on a scan role.
pub const WRITE_PRIVILEGES: &[&str] = &["INSERT", "UPDATE", "DELETE", "TRUNCATE"];

/// Open a single-connection pool, force read-only, and refuse write roles.
pub struct SafePool {
    /// sqlx pool (`max_connections = 1`).
    pub pool: PgPool,
    secret: String,
}

impl SafePool {
    /// Wrap an error with this connection's password scrubbed.
    pub fn scrub(&self, msg: impl std::fmt::Display) -> ScanError {
        ScanError::with_secret(msg, &self.secret)
    }
}

/// Connect and enforce the safety session.
pub async fn connect_readonly(
    url: &str,
    statement_timeout: Duration,
    schema: &str,
) -> Result<SafePool, ScanError> {
    let secret = password_from_url(url).unwrap_or_default();
    let timeout_ms = statement_timeout.as_millis().max(1);
    let options = PgConnectOptions::from_str(url)
        .map_err(|e| ScanError::with_secret(e, &secret))?
        .application_name("redact-scan");

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_read_only = on")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query(&format!("SET statement_timeout = '{timeout_ms}ms'"))
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("SET lock_timeout = '5s'")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .map_err(|e| ScanError::with_secret(e, &secret))?;

    let safe = SafePool { pool, secret };
    verify_readonly(&safe, schema).await?;
    Ok(safe)
}

async fn verify_readonly(safe: &SafePool, schema: &str) -> Result<(), ScanError> {
    let ro: String = sqlx::query_scalar("SHOW default_transaction_read_only")
        .fetch_one(&safe.pool)
        .await
        .map_err(|e| safe.scrub(e))?;
    if !ro.eq_ignore_ascii_case("on") {
        return Err(ScanError::new(
            "refusing to run: default_transaction_read_only is not on",
        ));
    }

    let is_super: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false)",
    )
    .fetch_one(&safe.pool)
    .await
    .map_err(|e| safe.scrub(e))?;
    if is_super {
        return Err(ScanError::new(
            "refusing to run: role is superuser; use a SELECT-only role",
        ));
    }

    let info_writes: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT privilege_type
        FROM information_schema.role_table_grants
        WHERE grantee = current_user
        "#,
    )
    .fetch_all(&safe.pool)
    .await
    .map_err(|e| safe.scrub(e))?;
    if has_write_grants(info_writes.iter().map(String::as_str)) {
        return Err(ScanError::new(
            "refusing to run: role holds write grants (INSERT/UPDATE/DELETE/TRUNCATE)",
        ));
    }

    let acl_writes: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1
          AND c.relkind IN ('r', 'p', 'v', 'm')
          AND (
            has_table_privilege(current_user, c.oid, 'INSERT')
            OR has_table_privilege(current_user, c.oid, 'UPDATE')
            OR has_table_privilege(current_user, c.oid, 'DELETE')
            OR has_table_privilege(current_user, c.oid, 'TRUNCATE')
          )
        "#,
    )
    .bind(schema)
    .fetch_one(&safe.pool)
    .await
    .map_err(|e| safe.scrub(e))?;
    if acl_writes > 0 {
        return Err(ScanError::new(
            "refusing to run: role holds write grants (INSERT/UPDATE/DELETE/TRUNCATE)",
        ));
    }
    Ok(())
}

/// True when any privilege is a table write grant.
pub fn has_write_grants<'a>(privileges: impl IntoIterator<Item = &'a str>) -> bool {
    privileges
        .into_iter()
        .any(|p| WRITE_PRIVILEGES.iter().any(|w| p.eq_ignore_ascii_case(w)))
}

/// Extract the password from a Postgres URL, percent-decoded.
pub fn password_from_url(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let creds = rest.split('@').next()?;
    let pass = creds.split_once(':')?.1;
    if pass.is_empty() {
        return None;
    }
    Some(crate::scrub::percent_decode(pass))
}

/// Host and database name from a connection URL. The host is hashed later.
pub fn host_db_from_url(url: &str) -> Result<(String, String), ScanError> {
    let opts = PgConnectOptions::from_str(url).map_err(ScanError::new)?;
    let host = opts.get_host().to_string();
    let db = opts
        .get_database()
        .ok_or_else(|| ScanError::new("connection URL is missing a database name"))?
        .to_string();
    Ok((host, db))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_percent_decoded_password() {
        let p = password_from_url("postgres://u:p%40ss@localhost/db").unwrap();
        assert_eq!(p, "p@ss");
    }

    #[test]
    fn write_grant_rows_are_refused() {
        assert!(has_write_grants(["SELECT", "INSERT"]));
        assert!(has_write_grants(["truncate"]));
        assert!(!has_write_grants(["SELECT", "USAGE"]));
    }
}
