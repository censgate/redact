//! Input errors returned before a verification report can be produced.

use std::fmt;

/// A stable category for malformed, unreadable, or unsupported verifier input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputErrorKind {
    /// The envelope or decoded body is not valid JSON or has the wrong shape.
    InvalidFormat,
    /// A required base64 value is malformed.
    InvalidEncoding,
    /// A local file could not be read.
    Io,
    /// The supplied local trust material is malformed.
    InvalidTrust,
}

/// An input error that prevents production of a verification report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError {
    /// Stable input error category.
    pub kind: InputErrorKind,
    /// Stable issue code suitable for machine handling.
    pub code: &'static str,
    /// A value-free diagnostic message.
    pub message: String,
}

impl InputError {
    /// Creates an input error with a stable code and safe diagnostic.
    pub fn new(kind: InputErrorKind, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for InputError {}
