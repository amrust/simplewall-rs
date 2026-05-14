// amwall — GUI app state.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.

use std::cell::RefCell;
use std::path::PathBuf;

use crate::internal_rules_state::InternalRulesState;
use crate::profile::Profile;

use super::settings::Settings;

/// In-memory state for the running GUI. Heap-allocated as `Box<App>`
/// in `gui::run` and parked in the main window's `GWLP_USERDATA`
/// slot so every WndProc invocation can reach it.
///
/// Both fields are wrapped in `RefCell` because handlers receive
/// `&App` (via `state_ref`) and need to swap out the profile / path
/// when actions like Refresh or Open Profile fire. WndProc dispatch
/// is single-threaded per window so the runtime borrow checker
/// won't surprise us at runtime — borrows always finish inside one
/// message handler.
pub struct App {
    /// The currently-loaded *user* profile (apps + custom rules +
    /// rule_configs). Refresh re-reads from disk; Open Profile…
    /// replaces wholesale.
    pub profile: RefCell<Profile>,
    /// Path the user profile was loaded from (and where Save
    /// Profile… would write). Defaults to
    /// `%APPDATA%\amwall\profile.xml`, matching the CLI.
    pub profile_path: RefCell<PathBuf>,
    /// Bundled internal profile — system rules + blocklist rules
    /// shipped with amwall. Loaded once at startup from the
    /// embedded `assets/profile_internal.xml`. Read-only at
    /// runtime; the user can't mutate this (matches upstream
    /// behaviour).
    pub internal_profile: Profile,
    /// Persistent UI settings (View / Settings menu toggles).
    /// Mutated by the toggle handlers, saved back to
    /// `settings_path` after each change.
    pub settings: RefCell<Settings>,
    /// Path settings persist to —
    /// `%APPDATA%\amwall\settings.txt` by default.
    pub settings_path: RefCell<PathBuf>,
    /// User overrides for the bundled rules in `internal_profile`
    /// (system rules, blocklist rules, preset custom rules). The
    /// `is_enabled` flag on a rule inside `internal_profile` is
    /// fixed at compile time; this map lets the user flip the
    /// effective state per-rule and have that survive restarts.
    /// Mutated by the rules-tab checkbox handler, saved to
    /// `internal_rules_state_path` after each change.
    pub internal_rules_state: RefCell<InternalRulesState>,
    /// Path the overrides persist to —
    /// `%APPDATA%\amwall\internal_rules_state.txt` by default,
    /// alongside `settings.txt` and `profile.xml`.
    pub internal_rules_state_path: RefCell<PathBuf>,
}
