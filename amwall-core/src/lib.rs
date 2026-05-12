//! amwall-core — types and TOML I/O shared between amwall-daemon,
//! amwall-cli, and (eventually) the Windows crate at the repo root.
//!
//! This crate intentionally lives at the REPO ROOT (not under linux/)
//! so the Windows crate can adopt it incrementally without a path
//! that crosses platform-specific subdirectories. Linux workspace
//! members consume it via linux/Cargo.toml's [workspace.dependencies]
//! `amwall-core = { path = "../amwall-core" }`.
//!
//! Windows adoption (post-Phase-5b commit) will be:
//!   1. root Cargo.toml: `amwall-core = { path = "amwall-core" }`
//!   2. src/rules/*.rs: re-export or replace internal Rule type
//!      with amwall_core::rules types where the schemas align.
//!
//! The TOML schema here is Linux's wire format. Windows still owns
//! the simplewall XML profile schema and the rule-string AST under
//! src/rules/parse.rs — those are NOT yet shared. Future work.

pub mod rules;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
