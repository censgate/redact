// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Stage-span gate for `/v1/redact` children.
//!
//! Recognizers live below the gateway crate, so they cannot see `TraceLevel`.
//! The gateway enables this thread-local for the duration of a pass when
//! operations tracing is on. Call sites still use `tracing::info_span!` with a
//! literal name so the tracing macros stay valid.

use std::cell::Cell;

thread_local! {
    static OPERATIONS: Cell<bool> = const { Cell::new(false) };
}

/// Run `f` with stage spans enabled or disabled for this thread.
pub fn with_operation_spans<R>(enabled: bool, f: impl FnOnce() -> R) -> R {
    OPERATIONS.with(|flag| {
        let prev = flag.replace(enabled);
        let out = f();
        flag.set(prev);
        out
    })
}

/// Whether the current pass should emit detect-stage child spans.
pub fn operations_enabled() -> bool {
    OPERATIONS.with(Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default() {
        assert!(!operations_enabled());
    }

    #[test]
    fn on_inside_scope() {
        with_operation_spans(true, || {
            assert!(operations_enabled());
        });
        assert!(!operations_enabled());
    }
}
