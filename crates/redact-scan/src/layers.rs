// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Discovery layer. Serialized as JSON numbers `0`, `0.5`, `1`, or `2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanLayer {
    /// Layer 0: catalog metadata only (no user-table reads).
    Metadata,
    /// Layer 0.5: planner statistics (`pg_stats`).
    Stats,
    /// Layer 1: bounded `TABLESAMPLE` of candidate columns.
    Sample,
    /// Layer 2: JSON/JSONB path sampling.
    Json,
}

impl ScanLayer {
    /// Numeric form used on the CLI and in report JSON.
    pub fn as_f64(self) -> f64 {
        match self {
            ScanLayer::Metadata => 0.0,
            ScanLayer::Stats => 0.5,
            ScanLayer::Sample => 1.0,
            ScanLayer::Json => 2.0,
        }
    }

    /// Parse the numeric layer token.
    pub fn from_f64(v: f64) -> Result<Self> {
        if (v - 0.0).abs() < f64::EPSILON {
            Ok(ScanLayer::Metadata)
        } else if (v - 0.5).abs() < f64::EPSILON {
            Ok(ScanLayer::Stats)
        } else if (v - 1.0).abs() < f64::EPSILON {
            Ok(ScanLayer::Sample)
        } else if (v - 2.0).abs() < f64::EPSILON {
            Ok(ScanLayer::Json)
        } else {
            Err(anyhow!("invalid layer {v}; expected 0, 0.5, 1, or 2"))
        }
    }
}

impl fmt::Display for ScanLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanLayer::Metadata => write!(f, "0"),
            ScanLayer::Stats => write!(f, "0.5"),
            ScanLayer::Sample => write!(f, "1"),
            ScanLayer::Json => write!(f, "2"),
        }
    }
}

impl FromStr for ScanLayer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let t = s.trim();
        match t {
            "0" | "metadata" => Ok(ScanLayer::Metadata),
            "0.5" | "stats" => Ok(ScanLayer::Stats),
            "1" | "sample" => Ok(ScanLayer::Sample),
            "2" | "json" => Ok(ScanLayer::Json),
            other => {
                let v: f64 = other
                    .parse()
                    .map_err(|_| anyhow!("invalid layer {other}; expected 0, 0.5, 1, or 2"))?;
                ScanLayer::from_f64(v)
            }
        }
    }
}

impl Serialize for ScanLayer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f64(self.as_f64())
    }
}

impl<'de> Deserialize<'de> for ScanLayer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = f64::deserialize(deserializer)?;
        ScanLayer::from_f64(v).map_err(serde::de::Error::custom)
    }
}

/// Parse a comma-separated layer list (`0,0.5,1,2`).
pub fn parse_layers(s: &str) -> Result<Vec<ScanLayer>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let layer = ScanLayer::from_str(part)?;
        if !out.contains(&layer) {
            out.push(layer);
        }
    }
    if out.is_empty() {
        return Err(anyhow!("--layers must select at least one layer"));
    }
    Ok(out)
}

/// Default layer set: `0,0.5,1,2`.
pub fn default_layers() -> Vec<ScanLayer> {
    vec![
        ScanLayer::Metadata,
        ScanLayer::Stats,
        ScanLayer::Sample,
        ScanLayer::Json,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_list() {
        let layers = parse_layers("0,0.5,1,2").unwrap();
        assert_eq!(layers.len(), 4);
        assert_eq!(layers[1], ScanLayer::Stats);
    }

    #[test]
    fn serde_roundtrip() {
        let json = serde_json::to_string(&ScanLayer::Stats).unwrap();
        assert_eq!(json, "0.5");
        let back: ScanLayer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ScanLayer::Stats);
    }
}
