//! porthole-gui: library surface shared between the binary and its tests.
//!
//! Split into a library and a binary, the same shape `porthole-helper`
//! already uses, because an integration test under `tests/` can only link
//! against a crate's library target -- there is nothing to `use` from a
//! bin-only crate.

pub mod app;
pub mod open_now;
pub mod window;
