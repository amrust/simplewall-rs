// amwall — portable / installed path resolution (M9.1).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Two layouts:
//
//   Portable: `amwall.ini` exists next to `amwall.exe`. All
//             persistent state (profile, settings, log, locale)
//             lives in the same directory as the exe. Lets users
//             carry a configured copy on a USB drive or sync it
//             to a different machine without leaking into
//             `%APPDATA%`. Mirrors upstream simplewall's portable
//             mode (where the marker is `simplewall.ini`).
//
//   Installed: marker absent. State lives under
//              `%APPDATA%\amwall\`, the default since v0.0.1.
//
// The marker file (`amwall.ini`) doubles as the settings file in
// portable mode — its content is the same line-oriented `key=value`
// store the installed-mode `settings.txt` uses, just under a
// different name. Detection only looks at file existence, so
// creating an empty `amwall.ini` next to the exe is enough to
// flip into portable mode on next launch.

use std::path::PathBuf;

/// Filename that gates portable mode. Presence next to the exe →
/// portable layout. Content can be empty or a settings-format
/// `key=value` file.
pub const PORTABLE_MARKER: &str = "amwall.ini";

/// `true` when `amwall.ini` is next to the exe. Drives `data_dir`,
/// `settings_path`, `profile_path`, etc. Cheap (one stat per call)
/// — callers that hot-path it can wrap in a `OnceLock`, but for
/// startup-only path resolution the bare syscall is fine.
pub fn is_portable() -> bool {
    exe_dir()
        .map(|d| d.join(PORTABLE_MARKER).is_file())
        .unwrap_or(false)
}

/// Where amwall reads / writes per-user state. `<exe_dir>` in
/// portable mode, `%APPDATA%\amwall\` otherwise. Falls back to the
/// current directory if neither resolves (e.g. running as SYSTEM
/// with no APPDATA in the environment) — the I/O calls downstream
/// will then surface a permission error rather than silently
/// landing files in an unexpected location.
pub fn data_dir() -> PathBuf {
    if is_portable() {
        return exe_dir().unwrap_or_else(|| PathBuf::from("."));
    }
    appdata_amwall_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// Settings file path. Portable mode reuses `amwall.ini` (the
/// marker) since its on-disk format is already line-oriented
/// key=value; installed mode keeps the historical `settings.txt`.
pub fn settings_path() -> PathBuf {
    if is_portable() {
        data_dir().join(PORTABLE_MARKER)
    } else {
        data_dir().join("settings.txt")
    }
}

/// User profile (`profile.xml`) path. Same filename in both modes.
pub fn profile_path() -> PathBuf {
    data_dir().join("profile.xml")
}

/// Default packet-log path used by `event_log` when
/// `Settings.log_path` is empty. Lives under `data_dir()` so
/// portable mode keeps logs alongside the exe.
pub fn default_log_path() -> PathBuf {
    data_dir().join("amwall.log")
}

/// Directory containing the exe, or `None` if `current_exe`
/// fails (rare — sandboxes that block `GetModuleFileNameW`).
pub fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
}

fn appdata_amwall_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("amwall"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_marker_is_amwall_ini() {
        // Sanity: future renames need to update the comment block
        // at the top of the file too — this test catches accidental
        // changes that diverge from the contract.
        assert_eq!(PORTABLE_MARKER, "amwall.ini");
    }

    #[test]
    fn paths_share_a_common_data_dir() {
        // Whatever data_dir resolves to, the per-file helpers
        // should hang every artifact off it. Catches regressions
        // where one helper hardcodes %APPDATA% and the other
        // doesn't, splitting state across two locations.
        let dir = data_dir();
        assert!(profile_path().starts_with(&dir));
        assert!(default_log_path().starts_with(&dir));
        // Settings can be either `<dir>/amwall.ini` (portable) or
        // `<dir>/settings.txt` (installed) — both still under `dir`.
        assert!(settings_path().starts_with(&dir));
    }
}
