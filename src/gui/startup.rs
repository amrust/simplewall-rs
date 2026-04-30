// amwall — "Load on system startup" registry plumbing.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Settings → General → "Load on system startup" writes
// `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
// with `amwall` = "<full exe path>" (REG_SZ). Explorer reads this
// hive at user logon and launches every entry. Per-user (HKCU)
// rather than per-machine (HKLM) so we never need elevation just
// to flip the toggle — the firewall itself still requires admin
// to install filters, but that's a separate runtime concern.
//
// Match upstream simplewall's behaviour: the value is the literal
// exe path with no wrapping quotes (Explorer handles paths with
// spaces correctly via its own argv parser). On disable, we delete
// the value entirely rather than blanking it, so a clean uninstall
// of amwall doesn't leave a dangling registry footprint.

#![cfg(windows)]

use std::io;

use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegDeleteValueW, RegOpenKeyExW,
    RegSetValueExW,
};
use windows::core::PCWSTR;

use super::wide;

/// Subkey path under HKCU. Same hive Explorer reads for "Run on
/// logon" entries.
const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Value name we register under `Run`. Distinct from upstream
/// simplewall's "simplewall" entry so the two can coexist on a
/// machine where the user is migrating between them.
const RUN_VALUE_NAME: &str = "amwall";

/// Toggle the auto-start registry entry. `enabled = true` writes
/// the current exe path; `enabled = false` deletes the value
/// (idempotent — deleting a missing value is treated as success).
pub fn set_load_on_startup(enabled: bool) -> io::Result<()> {
    if enabled {
        write_run_entry()
    } else {
        delete_run_entry()
    }
}

fn write_run_entry() -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let exe_str = exe.display().to_string();

    let subkey = wide(RUN_SUBKEY);
    let value_name = wide(RUN_VALUE_NAME);
    // REG_SZ data must include the trailing null wide char that
    // wide() already appends.
    let data_w = wide(&exe_str);
    // Treat as raw byte slice for RegSetValueExW (it asks for
    // cbData in bytes).
    let data_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            data_w.as_ptr() as *const u8,
            data_w.len() * std::mem::size_of::<u16>(),
        )
    };

    let mut hkey = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if status.is_err() {
        return Err(io::Error::other(format!(
            "RegOpenKeyExW(Run) failed: {status:?}"
        )));
    }

    let result = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            0,
            REG_SZ,
            Some(data_bytes),
        )
    };

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    if result.is_err() {
        return Err(io::Error::other(format!(
            "RegSetValueExW(amwall) failed: {result:?}"
        )));
    }
    Ok(())
}

fn delete_run_entry() -> io::Result<()> {
    let subkey = wide(RUN_SUBKEY);
    let value_name = wide(RUN_VALUE_NAME);

    let mut hkey = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if status.is_err() {
        // Subkey doesn't exist → nothing to delete.
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        return Err(io::Error::other(format!(
            "RegOpenKeyExW(Run) failed: {status:?}"
        )));
    }

    let result = unsafe { RegDeleteValueW(hkey, PCWSTR(value_name.as_ptr())) };

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    // Treat "value not found" as success — caller's intent
    // ("not auto-starting") is already true.
    if result.is_err() && result != ERROR_FILE_NOT_FOUND {
        return Err(io::Error::other(format!(
            "RegDeleteValueW(amwall) failed: {result:?}"
        )));
    }
    Ok(())
}
