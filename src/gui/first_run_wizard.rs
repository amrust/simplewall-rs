// amwall — first-run wizard (M9.4).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// On first launch, look for an existing simplewall profile at
// `%APPDATA%\simplewall\profile.xml`. If found and non-trivial,
// pop a TaskDialog asking whether to import it. The Settings
// flag `first_run_done` flips to `true` after either choice so
// the wizard stops nagging on subsequent runs.
//
// "Import" copies simplewall's XML over to amwall's profile
// path (same schema — both projects port upstream's). After
// import, amwall manages those rules; simplewall's existing
// kernel filters under `GUID_WfpProvider` remain untouched, so
// the user should disable simplewall before clicking
// `Enable filters` in amwall to avoid double-installation. The
// dialog tells them so.

#![cfg(windows)]

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOG_FLAGS, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0,
    TASKDIALOGCONFIG_1, TaskDialogIndirect,
};
use windows::core::PCWSTR;

use crate::profile::Profile;

use super::wide;

/// Outcome of running the wizard. Caller persists the choice into
/// `Settings.first_run_done`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// User picked "Import" and the import succeeded. The new
    /// profile is in `state.app.profile`; the caller still needs
    /// to save settings (`first_run_done = true`).
    Imported,
    /// User picked "Start fresh" — wizard records they made a
    /// choice but no profile change happened.
    StartFresh,
    /// No simplewall config detected — wizard didn't show. Treat
    /// as `StartFresh` for `first_run_done` purposes.
    NotApplicable,
    /// Dialog couldn't be displayed (rare — TaskDialog failure).
    /// Caller leaves `first_run_done = false` so the wizard
    /// retries next launch.
    Skipped,
}

/// Detected simplewall config + parsed profile, used to populate
/// the wizard's body text with rule counts.
struct SimplewallProfile {
    path: PathBuf,
    profile: Profile,
}

/// Look for simplewall's `profile.xml`, return it if non-empty.
/// Modern installers (v3.7+) store under
/// `%APPDATA%\Henry++\simplewall\` — Henry++ is the publisher
/// subfolder added when the project switched from the bare
/// `simplewall\` layout. The legacy path is checked as a fallback
/// so older installs still get picked up. Empty / missing /
/// unreadable yields `None` so the wizard skips the prompt — no
/// point asking about a non-existent migration source.
fn detect_simplewall() -> Option<SimplewallProfile> {
    let appdata = std::env::var_os("APPDATA")?;
    let appdata = PathBuf::from(appdata);
    let candidates = [
        appdata.join("Henry++").join("simplewall").join("profile.xml"),
        appdata.join("simplewall").join("profile.xml"),
    ];
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        let xml = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let profile = match crate::profile::parse_str(&xml) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if profile.apps.is_empty() && profile.custom_rules.is_empty() {
            // File exists but is the upstream-empty default —
            // skip and try the next candidate (rare: both paths
            // present, one stale).
            continue;
        }
        return Some(SimplewallProfile { path, profile });
    }
    None
}

/// Run the wizard if simplewall is present and the user hasn't
/// already dismissed it. Returns the user's choice; the caller
/// persists `first_run_done` and reloads the profile in the
/// `Imported` branch.
pub fn maybe_run(parent: HWND, amwall_profile_path: &Path) -> Choice {
    let detected = match detect_simplewall() {
        Some(d) => d,
        None => return Choice::NotApplicable,
    };

    let app_n = detected.profile.apps.len();
    let rule_n = detected.profile.custom_rules.len();
    let body = rust_i18n::t!(
        "wizard.body",
        path = detected.path.display().to_string(),
        apps = app_n,
        rules = rule_n,
    ).into_owned();

    let choice = match show_dialog(parent, &body) {
        Some(c) => c,
        None => return Choice::Skipped,
    };

    if choice == ChoiceRaw::Import {
        match copy_profile(&detected.path, amwall_profile_path) {
            Ok(()) => Choice::Imported,
            Err(e) => {
                eprintln!(
                    "amwall: first-run import failed: {e} (source {}, dest {})",
                    detected.path.display(),
                    amwall_profile_path.display(),
                );
                // The user picked Import but it failed — still
                // mark the wizard done so we don't pester them
                // every launch with a broken import path.
                Choice::StartFresh
            }
        }
    } else {
        Choice::StartFresh
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum ChoiceRaw {
    Import,
    StartFresh,
}

const ID_IMPORT: i32 = 1001;
const ID_START_FRESH: i32 = 1002;

fn show_dialog(parent: HWND, body: &str) -> Option<ChoiceRaw> {
    let title = wide(&rust_i18n::t!("wizard.title"));
    let main = wide(&rust_i18n::t!("wizard.subtitle"));
    let body_w = wide(body);
    // Plain short labels — the body already explains the trade-
    // off, so the buttons just carry the verb. The earlier
    // multi-line "title\nDescription" form ran together because
    // I conflated TDF_ALLOW_DIALOG_CANCELLATION (0x0008) with
    // TDF_USE_COMMAND_LINKS (0x0010); even with the right flag
    // the long-form labels were too wordy for a 2-button choice.
    let import_label = wide(&rust_i18n::t!("wizard.import_btn"));
    let fresh_label = wide(&rust_i18n::t!("wizard.start_fresh_btn"));

    let buttons = [
        TASKDIALOG_BUTTON {
            nButtonID: ID_IMPORT,
            pszButtonText: PCWSTR(import_label.as_ptr()),
        },
        TASKDIALOG_BUTTON {
            nButtonID: ID_START_FRESH,
            pszButtonText: PCWSTR(fresh_label.as_ptr()),
        },
    ];

    let cfg = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: parent,
        // 0x0008 = TDF_ALLOW_DIALOG_CANCELLATION — Esc / X close
        // the wizard without picking a custom button (we treat
        // that as Start fresh in the receiving switch).
        dwFlags: TASKDIALOG_FLAGS(0x0008),
        pszWindowTitle: PCWSTR(title.as_ptr()),
        pszMainInstruction: PCWSTR(main.as_ptr()),
        pszContent: PCWSTR(body_w.as_ptr()),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: ID_IMPORT,
        Anonymous1: TASKDIALOGCONFIG_0::default(),
        Anonymous2: TASKDIALOGCONFIG_1::default(),
        ..Default::default()
    };

    let mut button_id: i32 = 0;
    let hr = unsafe {
        TaskDialogIndirect(&cfg, Some(&mut button_id), None, None)
    };
    if hr.is_err() {
        return None;
    }
    match button_id {
        ID_IMPORT => Some(ChoiceRaw::Import),
        ID_START_FRESH => Some(ChoiceRaw::StartFresh),
        // IDCANCEL (window X / Esc) — return None so the caller's
        // `Skipped` branch fires and `first_run_done` stays false.
        // Effect: the wizard re-shows on next launch. Beats the
        // old behaviour of treating X as Start fresh, which locked
        // the user out after a single accidental dismiss.
        _ => None,
    }
}

fn copy_profile(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dst)?;
    Ok(())
}
