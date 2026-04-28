// simplewall-rs — library crate.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Module surface for the Rust port of simplewall. The companion binary
// (`src/main.rs`) is a thin entry point that opens the WFP engine and
// drives the rest of the library; everything testable lives here so
// integration tests in `tests/` and unit tests inside each module can
// exercise it without the full main flow.
//
// Modules are Windows-only by definition (the project targets the
// Windows Filtering Platform). They're gated with `#[cfg(windows)]`
// at this level so a non-Windows `cargo check` or `cargo doc` still
// produces an empty-but-valid library rather than a hard error,
// keeping cross-platform tooling like rust-analyzer-on-Linux happy
// for prose / Cargo.toml work.

#[cfg(windows)]
pub mod wfp;
