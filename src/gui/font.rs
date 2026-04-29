// amwall — system font helpers.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Win32 dialog templates auto-bind the dialog font (Segoe UI 9pt
// with ClearType on Windows 10+) via DS_SHELLFONT. Plain
// CreateWindowEx-created controls don't inherit it — they default
// to the legacy bitmap "System" font, which renders without
// anti-aliasing and looks visibly out of place next to dialog
// content. The main window + its toolbar / tab / listviews are
// all CreateWindowEx-built, so they need the font applied
// manually via WM_SETFONT.
//
// Two pieces:
//   - `load_message_font()` calls SystemParametersInfoW with
//     SPI_GETNONCLIENTMETRICS to get the user's currently
//     configured menu/message font, then CreateFontIndirectW
//     to materialise an HFONT.
//   - `apply_recursive(root, font)` walks the entire window
//     tree under `root` and broadcasts WM_SETFONT. Controls
//     that were created before this call inherit the new
//     font; ones that get created after still need their own
//     WM_SETFONT (or they'll render in System font for one
//     paint cycle until the next layout pass).
//
// Caller owns the HFONT and is responsible for DeleteObject on
// teardown — leaking is fine for the process lifetime, but we
// clean up properly in WM_NCDESTROY paths to keep clippy /
// gdileak quiet.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{CreateFontIndirectW, HFONT};
use windows::Win32::UI::WindowsAndMessaging::{
    GW_CHILD, GW_HWNDNEXT, GetWindow, NONCLIENTMETRICSW, SPI_GETNONCLIENTMETRICS,
    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SendMessageW, SystemParametersInfoW, WM_SETFONT,
};

/// Look up the user's current message font (Segoe UI 9pt on
/// Windows 10/11 default) and create an HFONT for it. Returns
/// a default (invalid) HFONT if the SystemParametersInfo call
/// fails — Win32 treats that as "use the system default font",
/// which is correct fallback behaviour.
pub fn load_message_font() -> HFONT {
    let mut metrics = NONCLIENTMETRICSW {
        cbSize: std::mem::size_of::<NONCLIENTMETRICSW>() as u32,
        ..Default::default()
    };
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            std::mem::size_of::<NONCLIENTMETRICSW>() as u32,
            Some(&mut metrics as *mut _ as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    if ok.is_err() {
        return HFONT::default();
    }
    unsafe { CreateFontIndirectW(&metrics.lfMessageFont) }
}

/// Toggle Windows 10/11's "immersive dark mode" on the title bar
/// of `hwnd`. Effects:
///   - Title bar + caption buttons render dark.
///   - Default text color flips to light.
///
/// On older Windows or when DWM doesn't expose the attribute the
/// call returns Err — we silently ignore.
pub fn set_dark_mode(hwnd: HWND, on: bool) {
    use windows::Win32::Graphics::Dwm::{
        DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute,
    };
    let value: i32 = if on { 1 } else { 0 };
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &value as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        );
    }
}

/// Walk every descendant of `root` and broadcast WM_SETFONT.
/// `font` is HFONT cast to wparam; lparam = TRUE asks for an
/// immediate repaint. Recurses depth-first via GW_CHILD /
/// GW_HWNDNEXT.
pub fn apply_recursive(root: HWND, font: HFONT) {
    if font.is_invalid() {
        return;
    }
    unsafe {
        SendMessageW(root, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    }
    let mut current = unsafe { GetWindow(root, GW_CHILD) };
    while current.0 != 0 {
        apply_recursive(current, font);
        current = unsafe { GetWindow(current, GW_HWNDNEXT) };
    }
}
