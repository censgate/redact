// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Char-boundary helpers.
//!
//! `str::floor_char_boundary` and `str::ceil_char_boundary` stabilized in Rust
//! 1.91. This workspace's MSRV is 1.88, so the same behavior lives here.

/// Largest char boundary at or before `index`.
///
/// Indexes past `s.len()` clamp to the end. `0` and `s.len()` are always
/// boundaries.
pub fn floor_char_boundary(s: &str, mut index: usize) -> usize {
    if index > s.len() {
        index = s.len();
    }
    while index > 0 && !s.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Smallest char boundary at or after `index`.
///
/// Indexes past `s.len()` clamp to the end.
pub fn ceil_char_boundary(s: &str, mut index: usize) -> usize {
    if index > s.len() {
        index = s.len();
    }
    while index < s.len() && !s.is_char_boundary(index) {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snaps_multibyte_scalars_without_passing_the_ends() {
        let text = "ó📄你";
        assert_eq!(floor_char_boundary(text, 0), 0);
        assert_eq!(floor_char_boundary(text, 1), 0);
        assert_eq!(ceil_char_boundary(text, 1), 2);
        assert_eq!(floor_char_boundary(text, text.len() + 5), text.len());
        assert_eq!(ceil_char_boundary(text, text.len()), text.len());
        assert!(text.is_char_boundary(floor_char_boundary(text, 3)));
        assert!(text.is_char_boundary(ceil_char_boundary(text, 3)));
    }
}
