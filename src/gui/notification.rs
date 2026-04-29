// amwall — drop-packet toast notification window.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Pops a small floating window in the bottom-right corner of the
// primary monitor when a WFP `CLASSIFY_DROP` event fires (M6.1
// substrate). Shows the offending app, the connection 5-tuple, and
// the action ("Blocked"). Auto-dismisses after `AUTO_DISMISS_MS`,
// clicking the toast also dismisses it. New events replace any
// visible toast — no queue, by design (the Packets log tab is the
// scrollable history).
//
// Allow / Block action buttons are intentionally NOT here yet —
// they'd require synchronous profile-rule mutation + filter reload,
// which is a bigger M7 piece. For M6.2 the toast is informational.

#![cfg(windows)]

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, COLOR_3DDKSHADOW, COLOR_WINDOW, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER,
    DrawTextW, EndPaint, FrameRect, GetSysColorBrush, PAINTSTRUCT, SelectObject, SetBkMode,
    SetTextColor, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, GWLP_USERDATA, GetSystemMetrics,
    GetWindowLongPtrW, IDC_ARROW, KillTimer, LoadCursorW, RegisterClassExW, SM_CXSCREEN,
    SM_CYSCREEN, SetTimer, SetWindowLongPtrW, ShowWindow, SW_SHOWNA, WM_CREATE, WM_DESTROY,
    WM_LBUTTONDOWN, WM_NCCREATE, WM_NCDESTROY, WM_PAINT, WM_TIMER, WNDCLASSEXW, WS_BORDER,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};
use windows::core::{PCWSTR, w};

use std::net::IpAddr;

use crate::wfp::events::{NetDirection, NetEvent, NetEventDetails};

use super::wide;

// ---- Geometry / timing constants ----

const TOAST_W: i32 = 340;
const TOAST_H: i32 = 92;
const TOAST_MARGIN: i32 = 16;
const TOAST_INNER_PAD: i32 = 10;
const AUTO_DISMISS_MS: u32 = 5000;
const TIMER_DISMISS: usize = 8001;

const TOAST_CLASS: PCWSTR = w!("AmwallToast");

// ---- Process-wide singleton state ----

static CLASS_REGISTERED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// HWND of the currently visible toast, or `HWND::default()` if
    /// none. Set on `show_drop_notification`, cleared on
    /// `WM_NCDESTROY` from the toast's wndproc.
    static CURRENT_TOAST: Cell<HWND> = const { Cell::new(HWND(0)) };
}

/// Box stashed into the toast window's GWLP_USERDATA. Holds the
/// pre-formatted lines so WM_PAINT doesn't re-allocate per repaint.
struct ToastState {
    lines: Vec<String>,
}

/// Show (or replace) a drop-packet toast for the given event. Allow
/// / Other variants are ignored — toast is drop-only by design.
/// Caller is responsible for gating on the
/// `settings.enable_notifications` flag.
pub fn show_drop_notification(event: &NetEvent) {
    let details = match event {
        NetEvent::Drop(d) => d,
        _ => return,
    };

    if !ensure_class_registered() {
        return;
    }

    // Replace any existing toast.
    let existing = CURRENT_TOAST.with(|c| c.replace(HWND::default()));
    if existing.0 != 0 {
        unsafe {
            let _ = DestroyWindow(existing);
        }
    }

    let lines = format_lines(details);
    let state = Box::new(ToastState { lines });
    let state_ptr = Box::into_raw(state) as *const ToastState as *mut std::ffi::c_void;

    let hi = match unsafe { GetModuleHandleW(PCWSTR::null()) } {
        Ok(h) => h,
        Err(_) => {
            // Reclaim the box so we don't leak.
            unsafe {
                let _ = Box::from_raw(state_ptr as *mut ToastState);
            }
            return;
        }
    };

    let (x, y) = bottom_right_position();
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
            TOAST_CLASS,
            PCWSTR::null(),
            WS_POPUP | WS_BORDER | WS_VISIBLE,
            x,
            y,
            TOAST_W,
            TOAST_H,
            None,
            None,
            hi,
            Some(state_ptr),
        )
    };
    if hwnd.0 == 0 {
        // CreateWindowExW failed — reclaim the box.
        unsafe {
            let _ = Box::from_raw(state_ptr as *mut ToastState);
        }
        return;
    }
    CURRENT_TOAST.with(|c| c.set(hwnd));

    // Auto-dismiss timer. The wndproc clears the singleton on
    // WM_NCDESTROY, so KillTimer is implicit on destroy.
    unsafe {
        SetTimer(hwnd, TIMER_DISMISS, AUTO_DISMISS_MS, None);
    }
    // Stay non-activating so we don't steal focus from the user's
    // current window.
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOWNA);
    }
}

fn ensure_class_registered() -> bool {
    if CLASS_REGISTERED.load(Ordering::Acquire) {
        return true;
    }
    let hi = match unsafe { GetModuleHandleW(PCWSTR::null()) } {
        Ok(h) => h,
        Err(_) => return false,
    };
    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(toast_proc),
        hInstance: hi.into(),
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default(),
        lpszClassName: TOAST_CLASS,
        hbrBackground: unsafe { GetSysColorBrush(COLOR_WINDOW) },
        ..Default::default()
    };
    let atom = unsafe { RegisterClassExW(&wc) };
    if atom == 0 {
        return false;
    }
    CLASS_REGISTERED.store(true, Ordering::Release);
    true
}

/// Bottom-right corner of the primary monitor's work area minus the
/// toast size and a margin. Doesn't pick up multi-monitor layout —
/// good enough for M6.2; M6.4 covers position memory + multi-mon.
fn bottom_right_position() -> (i32, i32) {
    let sw = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let sh = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    let x = (sw - TOAST_W - TOAST_MARGIN).max(0);
    // Leave extra room for the taskbar; a fixed 56 px is a fair
    // default on Win10/11 with a bottom taskbar.
    let y = (sh - TOAST_H - TOAST_MARGIN - 56).max(0);
    (x, y)
}

fn format_lines(d: &NetEventDetails) -> Vec<String> {
    let app = d
        .app_path
        .as_deref()
        .map(|p| p.rsplit_once('\\').map(|(_, t)| t).unwrap_or(p))
        .unwrap_or("(system)");

    let proto = match d.protocol {
        Some(1) => "ICMPv4",
        Some(6) => "TCP",
        Some(17) => "UDP",
        Some(58) => "ICMPv6",
        Some(_) | None => "",
    };
    let dir = match d.direction {
        Some(NetDirection::Outbound) => "outbound",
        Some(NetDirection::Inbound) => "inbound",
        None => "",
    };

    let mut header = format!("Blocked: {app}");
    if !proto.is_empty() {
        if dir.is_empty() {
            header.push_str(&format!(" ({proto})"));
        } else {
            header.push_str(&format!(" ({proto} {dir})"));
        }
    }

    let conn = format_endpoint(d.local_addr, d.local_port, d.remote_addr, d.remote_port);

    if conn.is_empty() {
        vec![header]
    } else {
        vec![header, conn]
    }
}

fn format_endpoint(
    local: Option<IpAddr>,
    lport: Option<u16>,
    remote: Option<IpAddr>,
    rport: Option<u16>,
) -> String {
    let l = match (local, lport) {
        (Some(a), Some(p)) => format!("{a}:{p}"),
        (Some(a), None) => a.to_string(),
        _ => String::new(),
    };
    let r = match (remote, rport) {
        (Some(a), Some(p)) => format!("{a}:{p}"),
        (Some(a), None) => a.to_string(),
        _ => String::new(),
    };
    match (l.is_empty(), r.is_empty()) {
        (true, true) => String::new(),
        (false, true) => l,
        (true, false) => r,
        (false, false) => format!("{l} → {r}"),
    }
}

// =================================================================
// Window proc
// =================================================================

unsafe extern "system" fn toast_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_NCCREATE => {
            let cs = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, cs.lpCreateParams as isize);
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_CREATE => LRESULT(0),
        WM_PAINT => {
            paint_toast(hwnd);
            LRESULT(0)
        }
        WM_LBUTTONDOWN => {
            // Click anywhere to dismiss.
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_TIMER => {
            if wparam.0 == TIMER_DISMISS {
                unsafe {
                    let _ = KillTimer(hwnd, TIMER_DISMISS);
                    let _ = DestroyWindow(hwnd);
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => LRESULT(0),
        WM_NCDESTROY => {
            // Reclaim the boxed state and clear the singleton if
            // this is still the current toast.
            let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut ToastState;
            if !raw.is_null() {
                unsafe {
                    let _ = Box::from_raw(raw);
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
            }
            CURRENT_TOAST.with(|c| {
                if c.get() == hwnd {
                    c.set(HWND::default());
                }
            });
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn paint_toast(hwnd: HWND) {
    let state_ptr =
        unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const ToastState;
    if state_ptr.is_null() {
        return;
    }
    let state = unsafe { &*state_ptr };

    let mut ps = PAINTSTRUCT::default();
    let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
    if hdc.0 == 0 {
        return;
    }

    // Background: COLOR_WINDOW (already drawn by class brush).
    let mut rect = RECT::default();
    let _ = unsafe { windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rect) };

    // Inner border for visual separation.
    unsafe {
        let frame = GetSysColorBrush(COLOR_3DDKSHADOW);
        FrameRect(hdc, &rect, frame);
    }

    let font = super::font::load_message_font();
    let prev_font = unsafe { SelectObject(hdc, font) };
    unsafe {
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, windows::Win32::Foundation::COLORREF(0x00_22_22_22));
    }

    let mut y = TOAST_INNER_PAD;
    let line_h = 22;
    for line in &state.lines {
        let mut text_rect = RECT {
            left: TOAST_INNER_PAD,
            top: y,
            right: rect.right - TOAST_INNER_PAD,
            bottom: y + line_h,
        };
        let mut wide_buf = wide(line);
        unsafe {
            DrawTextW(
                hdc,
                &mut wide_buf,
                &mut text_rect,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
        }
        y += line_h;
    }

    unsafe {
        SelectObject(hdc, prev_font);
        let _ = EndPaint(hwnd, &ps);
    }
}
