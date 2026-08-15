// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Optional HTTP POST of the report JSON.

use crate::error::ScanError;
use crate::report::ScanReport;

/// POST `report` to `url`. 2xx required. Optional Bearer key and extra headers.
pub async fn post_report(
    url: &str,
    api_key: Option<&str>,
    headers: &[String],
    report: &ScanReport,
) -> Result<(), ScanError> {
    let client = reqwest::Client::new();
    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .json(report);
    if let Some(key) = api_key {
        if !key.is_empty() {
            req = req.bearer_auth(key);
        }
    }
    for h in headers {
        let (name, value) = parse_header(h)?;
        req = req.header(name, value);
    }
    let resp = req.send().await.map_err(ScanError::new)?;
    if !resp.status().is_success() {
        return Err(ScanError::new(format!(
            "report POST failed with HTTP {}",
            resp.status()
        )));
    }
    Ok(())
}

/// Split `Name: value`.
pub fn parse_header(h: &str) -> Result<(&str, &str), ScanError> {
    let (name, value) = h
        .split_once(':')
        .ok_or_else(|| ScanError::new("invalid --report-header; expected Name: value"))?;
    Ok((name.trim(), value.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_split() {
        let (n, v) = parse_header("X-Run: abc").unwrap();
        assert_eq!(n, "X-Run");
        assert_eq!(v, "abc");
        assert!(parse_header("nope").is_err());
    }
}
