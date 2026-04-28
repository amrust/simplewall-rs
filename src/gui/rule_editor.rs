// simplewall-rs — modal rule editor.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// 1:1 port of upstream simplewall's IDD_EDITOR dialog
// (resource.rc:250-319 + editor.c). Three property-page tabs:
//
//   General (IDD_EDITOR_GENERAL):
//     - Name (Edit)
//     - Comments (Edit)
//     - Protocol (Combo: Any / TCP / UDP / ICMP / ICMPv6) and
//       Family (ports only) (Combo: Any / IPv4 / IPv6) — side
//       by side, half-width each
//     - Direction (Combo: Outbound / Inbound / Both)
//     - Action (Combo: Allow / Block)
//
//   Rule (IDD_EDITOR_RULE):
//     - Remote group: ListView (no headers) + Add / Edit / Delete
//       buttons (each row = one ";"-separated rule fragment).
//     - Local group: same shape, mapped to `rule_local`.
//     - Hint text below.
//
//   Apps (IDD_EDITOR_APPS):
//     - Search edit (M5.6 will wire incremental filtering;
//       layout-only for now).
//     - ListView with checkboxes — every app from
//       `profile.apps` plus an extra row for any apps already
//       referenced in the rule's existing `apps` field.
//     - Hint text below.
//
// Bottom of the parent (IDD_EDITOR):
//     [x] Enable rule                      [Save] [Close]
//
// Each pane is a borderless WS_CHILD window that we show/hide
// on tab change — matches the same trick the main window uses
// for its 8 tab listviews. The tab control's TCM_ADJUSTRECT
// gives us the inset content rect; panes are sized to fill it.

#![cfg(windows)]

use std::cell::{Cell, RefCell};

use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT, LVCOLUMNW,
    LIST_VIEW_ITEM_STATE_FLAGS, LVIF_STATE, LVIF_TEXT, LVIS_STATEIMAGEMASK, LVITEMW,
    LVM_GETITEMSTATE, LVM_GETITEMTEXTW, LVM_GETNEXTITEM,
    LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMTEXTW,
    LVNI_SELECTED, LVS_EX_CHECKBOXES, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_NOCOLUMNHEADER,
    LVS_REPORT, LVS_SHOWSELALWAYS, NMHDR, TCIF_TEXT, TCITEMW, TCM_ADJUSTRECT, TCM_GETCURSEL,
    TCM_INSERTITEMW, TCN_SELCHANGE, WC_LISTVIEWW, WC_TABCONTROLW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_GROUPBOX, BS_PUSHBUTTON,
    CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL, CREATESTRUCTW, CW_USEDEFAULT, CreateWindowExW,
    DefWindowProcW, DestroyWindow, DispatchMessageW, ES_AUTOHSCROLL, ES_AUTOVSCROLL,
    ES_MULTILINE, ES_READONLY, GWLP_USERDATA, GetDlgItem, GetMessageW, GetWindowLongPtrW,
    GetWindowRect, GetWindowTextW, HMENU, IDCANCEL, IDC_ARROW, IDOK, IsDialogMessageW, IsWindow,
    LoadCursorW, MSG, MoveWindow, PostQuitMessage, RegisterClassExW, SW_HIDE, SW_SHOW,
    SendMessageW, SetWindowLongPtrW, ShowWindow, TranslateMessage,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_NCCREATE,
    WM_NCDESTROY, WM_NOTIFY, WM_SIZE, WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD,
    WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_EX_DLGMODALFRAME, WS_GROUP, WS_OVERLAPPED, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};
use windows::core::{PCWSTR, PWSTR, w};

use crate::profile::{Action, AddressFamily, App as ProfileApp, Direction, Rule};

use super::wide;

// ---- Control IDs (private to this module) ----

const ID_TAB: i32 = 100;
const ID_ENABLE_CHK: i32 = 101;
const ID_SAVE_BTN: i32 = IDOK.0;
const ID_CLOSE_BTN: i32 = IDCANCEL.0;

// General tab
const ID_NAME_EDIT: i32 = 200;
const ID_COMMENTS_EDIT: i32 = 201;
const ID_PROTOCOL_COMBO: i32 = 202;
const ID_FAMILY_COMBO: i32 = 203;
const ID_DIRECTION_COMBO: i32 = 204;
const ID_ACTION_COMBO: i32 = 205;

// Rule tab
const ID_REMOTE_LV: i32 = 300;
const ID_REMOTE_ADD: i32 = 301;
const ID_REMOTE_EDIT: i32 = 302;
const ID_REMOTE_DELETE: i32 = 303;
const ID_LOCAL_LV: i32 = 310;
const ID_LOCAL_ADD: i32 = 311;
const ID_LOCAL_EDIT: i32 = 312;
const ID_LOCAL_DELETE: i32 = 313;

// Apps tab
const ID_APPS_SEARCH: i32 = 400;
const ID_APPS_LV: i32 = 401;

// Add/edit-rule-fragment sub-dialog
const ID_ADDRULE_EDIT: i32 = 500;
const ID_ADDRULE_HINT: i32 = 501;

const CLASS_NAME: PCWSTR = w!("SimplewallRsRuleEditor");
const SUB_CLASS_NAME: PCWSTR = w!("SimplewallRsAddRuleEntry");

// Logical 96-DPI dimensions, roughly translated from upstream's
// dialog units (1 du ≈ 1.5 px for 8pt MS Shell Dlg).
const LOGICAL_W: i32 = 460;
const LOGICAL_H: i32 = 360;

/// Boxed dialog state. Pointer parked in the parent window's
/// GWLP_USERDATA, reclaimed in `open` after the modal pump exits.
struct DialogState {
    initial: RefCell<Rule>,
    result: RefCell<Option<Rule>>,
    finished: Cell<bool>,

    // Per-pane container HWNDs.
    page_general: Cell<HWND>,
    page_rule: Cell<HWND>,
    page_apps: Cell<HWND>,

    // Bottom-of-parent controls.
    enable_chk: Cell<HWND>,

    // The full app list (from caller's profile) so the Apps tab
    // can render every app with its check state. Display name is
    // the basename of the path; identity stored is the full path
    // so the rule's `apps` field round-trips losslessly.
    apps_paths: Vec<String>,
}

/// Show the modal rule-editor dialog.
///
/// `initial` = `None` opens an Add Rule dialog (blank); `Some(rule)`
/// opens an Edit Rule dialog prefilled from that rule.
///
/// `available_apps` is the caller's `profile.apps` slice — used
/// to populate the Apps tab. Pass an empty slice for "no apps to
/// pick from yet" (e.g. on a fresh profile); the rule's `apps`
/// field then stays as whatever was already in `initial`.
///
/// Returns `Some(rule)` on Save, `None` on Close / X / Esc.
pub fn open(parent: HWND, initial: Option<&Rule>, available_apps: &[ProfileApp]) -> Option<Rule> {
    let initial_rule = match initial {
        Some(r) => r.clone(),
        None => Rule {
            name: String::new(),
            remote: None,
            local: None,
            direction: Direction::Outbound,
            action: Action::Permit,
            protocol: None,
            address_family: None,
            apps: None,
            is_services: false,
            is_enabled: true,
            os_version: None,
            comment: None,
        },
    };

    unsafe {
        let hinstance = GetModuleHandleW(PCWSTR::null()).ok()?;

        // Register the parent + sub-dialog window classes once.
        // RegisterClassExW returning 0 on duplicate registration
        // is fine; the class stays usable.
        register_class(CLASS_NAME, Some(parent_proc), hinstance);
        register_class(SUB_CLASS_NAME, Some(addrule_proc), hinstance);

        let apps_paths: Vec<String> = available_apps
            .iter()
            .map(|a| a.path.display().to_string())
            .collect();

        let state = Box::new(DialogState {
            initial: RefCell::new(initial_rule),
            result: RefCell::new(None),
            finished: Cell::new(false),
            page_general: Cell::new(HWND::default()),
            page_rule: Cell::new(HWND::default()),
            page_apps: Cell::new(HWND::default()),
            enable_chk: Cell::new(HWND::default()),
            apps_paths,
        });
        let state_ptr = Box::into_raw(state) as *mut std::ffi::c_void;

        let title_text = if (*(state_ptr as *const DialogState))
            .initial
            .borrow()
            .name
            .is_empty()
        {
            "Add user rule"
        } else {
            "Edit user rule"
        };
        let title = wide(title_text);

        let (x, y) = center_over_parent(parent, LOGICAL_W, LOGICAL_H);

        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPSIBLINGS | WS_CLIPCHILDREN;
        let dlg = CreateWindowExW(
            WS_EX_DLGMODALFRAME,
            CLASS_NAME,
            PCWSTR(title.as_ptr()),
            style,
            x,
            y,
            LOGICAL_W,
            LOGICAL_H,
            parent,
            HMENU::default(),
            hinstance,
            Some(state_ptr),
        );
        if dlg.0 == 0 {
            let _ = Box::from_raw(state_ptr as *mut DialogState);
            return None;
        }

        let _ = EnableWindow(parent, false);
        let _ = ShowWindow(dlg, SW_SHOW);

        let mut msg = MSG::default();
        loop {
            let state_ref = &*(state_ptr as *const DialogState);
            if state_ref.finished.get() {
                break;
            }
            let got = GetMessageW(&mut msg, HWND::default(), 0, 0);
            if !got.as_bool() {
                PostQuitMessage(msg.wParam.0 as i32);
                break;
            }
            // IsDialogMessageW first — Tab/Enter/Esc routing.
            if !IsDialogMessageW(dlg, &msg).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        let _ = EnableWindow(parent, true);
        let _ = SetFocus(parent);
        if IsWindow(dlg).as_bool() {
            let _ = DestroyWindow(dlg);
        }

        let state = Box::from_raw(state_ptr as *mut DialogState);
        state.result.into_inner()
    }
}

unsafe fn register_class(name: PCWSTR, wnd_proc: windows::Win32::UI::WindowsAndMessaging::WNDPROC, hi: HMODULE) {
    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: wnd_proc,
        hInstance: hi.into(),
        lpszClassName: name,
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default(),
        hbrBackground: HBRUSH(6), // COLOR_WINDOW + 1
        ..Default::default()
    };
    unsafe {
        RegisterClassExW(&wc);
    }
}

// ===========================================================================
// Parent window proc — owns the tab control + Enable + Save/Close.
// ===========================================================================

unsafe extern "system" fn parent_proc(
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
        WM_CREATE => match on_parent_create(hwnd) {
            Ok(()) => LRESULT(0),
            Err(_) => LRESULT(-1),
        },
        WM_SIZE => {
            on_parent_size(hwnd);
            LRESULT(0)
        }
        WM_NOTIFY => {
            let nmhdr = unsafe { &*(lparam.0 as *const NMHDR) };
            if nmhdr.idFrom == ID_TAB as usize && nmhdr.code == TCN_SELCHANGE {
                on_tab_change(hwnd);
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            on_command(hwnd, (wparam.0 & 0xFFFF) as i32);
            LRESULT(0)
        }
        WM_CLOSE => {
            on_cancel(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => LRESULT(0),
        WM_NCDESTROY => {
            if let Some(s) = unsafe { state_ref(hwnd) } {
                s.finished.set(true);
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

unsafe fn state_ref<'a>(hwnd: HWND) -> Option<&'a DialogState> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const DialogState;
    if raw.is_null() { None } else { Some(unsafe { &*raw }) }
}

fn on_parent_create(hwnd: HWND) -> Result<(), String> {
    let state = unsafe { state_ref(hwnd) }.ok_or("DialogState missing")?;
    let hinstance = unsafe { GetModuleHandleW(PCWSTR::null()) }
        .map_err(|e| format!("GetModuleHandleW: {e}"))?;

    // ---- Tab control ----
    let tab = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            WC_TABCONTROLW,
            PCWSTR::null(),
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP,
            0,
            0,
            10,
            10, // resized in on_parent_size
            hwnd,
            HMENU(ID_TAB as isize),
            hinstance,
            None,
        )
    };
    if tab.0 == 0 {
        return Err("CreateWindowExW(WC_TABCONTROLW) failed".into());
    }

    // Tab labels — 1:1 with upstream (locale strings IDS_TITLE_GENERAL /
    // IDS_RULE / IDS_TAB_APPS).
    let labels: [&str; 3] = ["General", "Rule", "Apps (0)"];
    for (i, label) in labels.iter().enumerate() {
        let mut buf = wide(label);
        let item = TCITEMW {
            mask: TCIF_TEXT,
            pszText: PWSTR(buf.as_mut_ptr()),
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                tab,
                TCM_INSERTITEMW,
                WPARAM(i),
                LPARAM(&item as *const _ as isize),
            );
        }
    }

    // ---- Three child panes (one per tab) ----
    let pane_general = create_pane(hwnd, hinstance);
    let pane_rule = create_pane(hwnd, hinstance);
    let pane_apps = create_pane(hwnd, hinstance);
    state.page_general.set(pane_general);
    state.page_rule.set(pane_rule);
    state.page_apps.set(pane_apps);

    let initial = state.initial.borrow().clone();
    populate_general_pane(pane_general, hinstance, &initial)?;
    populate_rule_pane(pane_rule, hinstance, &initial)?;
    populate_apps_pane(pane_apps, hinstance, &initial, &state.apps_paths)?;

    // ---- Enable rule checkbox + Save / Close buttons ----
    let enable_buf = wide("Enable rule");
    let enable_chk = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Button"),
            PCWSTR(enable_buf.as_ptr()),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
            10,
            10,
            10,
            10,
            hwnd,
            HMENU(ID_ENABLE_CHK as isize),
            hinstance,
            None,
        )
    };
    state.enable_chk.set(enable_chk);
    let initial_check = if initial.is_enabled { BST_CHECKED.0 } else { BST_UNCHECKED.0 };
    unsafe {
        SendMessageW(
            enable_chk,
            BM_SETCHECK,
            WPARAM(initial_check as usize),
            LPARAM(0),
        );
    }

    let save_buf = wide("Save");
    let close_buf = wide("Close");
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Button"),
            PCWSTR(save_buf.as_ptr()),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
            10,
            10,
            10,
            10,
            hwnd,
            HMENU(ID_SAVE_BTN as isize),
            hinstance,
            None,
        );
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Button"),
            PCWSTR(close_buf.as_ptr()),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_PUSHBUTTON as u32),
            10,
            10,
            10,
            10,
            hwnd,
            HMENU(ID_CLOSE_BTN as isize),
            hinstance,
            None,
        );
    }

    // Initial layout + show first tab.
    on_parent_size(hwnd);
    on_tab_change(hwnd);

    // Focus the Name field on open.
    let name_edit = unsafe { GetDlgItem(pane_general, ID_NAME_EDIT) };
    unsafe {
        SetFocus(name_edit);
    }

    Ok(())
}

fn create_pane(parent: HWND, hi: HMODULE) -> HWND {
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Static"),
            PCWSTR::null(),
            WS_CHILD | WS_CLIPCHILDREN,
            0,
            0,
            10,
            10,
            parent,
            HMENU::default(),
            hi,
            None,
        )
    }
}

fn on_parent_size(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let mut client = RECT::default();
    if unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut client)
    }
    .is_err()
    {
        return;
    }
    let total_w = client.right - client.left;
    let total_h = client.bottom - client.top;

    // Bottom strip is 50px tall: Enable on left, Save+Close on right.
    let bottom_h = 50;
    let tab_h = (total_h - bottom_h).max(0);

    // Tab control fills the top.
    let tab = unsafe { GetDlgItem(hwnd, ID_TAB) };
    if tab.0 != 0 {
        unsafe {
            let _ = MoveWindow(tab, 0, 0, total_w, tab_h, true);
        }
    }

    // Panes fill the tab control's content rect.
    let mut content = RECT {
        left: 0,
        top: 0,
        right: total_w,
        bottom: tab_h,
    };
    if tab.0 != 0 {
        unsafe {
            SendMessageW(
                tab,
                TCM_ADJUSTRECT,
                WPARAM(0),
                LPARAM(&mut content as *mut _ as isize),
            );
        }
    }
    let cw = content.right - content.left;
    let ch = content.bottom - content.top;

    for &pane in &[
        state.page_general.get(),
        state.page_rule.get(),
        state.page_apps.get(),
    ] {
        if pane.0 != 0 {
            unsafe {
                let _ = MoveWindow(pane, content.left, content.top, cw, ch, true);
            }
        }
    }

    // Bottom strip: enable checkbox at x=12, Save at right-100,
    // Close at right-50.
    let by = tab_h + 14;
    let enable_chk = state.enable_chk.get();
    if enable_chk.0 != 0 {
        unsafe {
            let _ = MoveWindow(enable_chk, 12, by, 200, 22, true);
        }
    }
    let save_btn = unsafe { GetDlgItem(hwnd, ID_SAVE_BTN) };
    if save_btn.0 != 0 {
        unsafe {
            let _ = MoveWindow(save_btn, total_w - 180, by, 80, 26, true);
        }
    }
    let close_btn = unsafe { GetDlgItem(hwnd, ID_CLOSE_BTN) };
    if close_btn.0 != 0 {
        unsafe {
            let _ = MoveWindow(close_btn, total_w - 92, by, 80, 26, true);
        }
    }
}

fn on_tab_change(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let tab = unsafe { GetDlgItem(hwnd, ID_TAB) };
    if tab.0 == 0 {
        return;
    }
    let sel =
        unsafe { SendMessageW(tab, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) }.0 as isize;
    let sel_slot = if sel < 0 { 0 } else { sel as usize };
    let panes = [
        state.page_general.get(),
        state.page_rule.get(),
        state.page_apps.get(),
    ];
    for (i, &p) in panes.iter().enumerate() {
        if p.0 == 0 {
            continue;
        }
        unsafe {
            let _ = ShowWindow(p, if i == sel_slot { SW_SHOW } else { SW_HIDE });
        }
    }
}

fn on_command(hwnd: HWND, id: i32) {
    match id {
        ID_SAVE_BTN => on_save(hwnd),
        ID_CLOSE_BTN => on_cancel(hwnd),
        ID_REMOTE_ADD => on_rule_entry(hwnd, ID_REMOTE_LV, None),
        ID_REMOTE_EDIT => on_rule_entry_edit(hwnd, ID_REMOTE_LV),
        ID_REMOTE_DELETE => on_rule_entry_delete(hwnd, ID_REMOTE_LV),
        ID_LOCAL_ADD => on_rule_entry(hwnd, ID_LOCAL_LV, None),
        ID_LOCAL_EDIT => on_rule_entry_edit(hwnd, ID_LOCAL_LV),
        ID_LOCAL_DELETE => on_rule_entry_delete(hwnd, ID_LOCAL_LV),
        _ => {}
    }
}

fn on_cancel(hwnd: HWND) {
    if let Some(s) = unsafe { state_ref(hwnd) } {
        s.finished.set(true);
    }
}

fn on_save(hwnd: HWND) {
    let state = match unsafe { state_ref(hwnd) } {
        Some(s) => s,
        None => return,
    };
    let general = state.page_general.get();
    let rule_pane = state.page_rule.get();
    let apps_pane = state.page_apps.get();

    let name = read_edit(general, ID_NAME_EDIT);
    if name.trim().is_empty() {
        let name_edit = unsafe { GetDlgItem(general, ID_NAME_EDIT) };
        unsafe {
            SetFocus(name_edit);
        }
        return;
    }
    let comment = some_if_nonempty(read_edit(general, ID_COMMENTS_EDIT));
    let protocol = match read_combo_index(general, ID_PROTOCOL_COMBO) {
        1 => Some(6),
        2 => Some(17),
        3 => Some(1),
        4 => Some(58),
        _ => None,
    };
    let address_family = match read_combo_index(general, ID_FAMILY_COMBO) {
        1 => Some(AddressFamily::Ipv4),
        2 => Some(AddressFamily::Ipv6),
        _ => None,
    };
    let direction = match read_combo_index(general, ID_DIRECTION_COMBO) {
        1 => Direction::Inbound,
        2 => Direction::Any,
        _ => Direction::Outbound,
    };
    let action = match read_combo_index(general, ID_ACTION_COMBO) {
        1 => Action::Block,
        _ => Action::Permit,
    };
    let remote = some_if_nonempty(join_listview(rule_pane, ID_REMOTE_LV));
    let local = some_if_nonempty(join_listview(rule_pane, ID_LOCAL_LV));
    let apps = some_if_nonempty(collect_checked_apps(apps_pane, &state.apps_paths));
    let is_enabled = read_check(hwnd, ID_ENABLE_CHK);

    let initial = state.initial.borrow();
    let new_rule = Rule {
        name,
        remote,
        local,
        direction,
        action,
        protocol,
        address_family,
        apps,
        is_services: initial.is_services,
        is_enabled,
        os_version: initial.os_version.clone(),
        comment,
    };
    drop(initial);

    *state.result.borrow_mut() = Some(new_rule);
    state.finished.set(true);
}

// ===========================================================================
// General pane — Name / Comments / Protocol+Family / Direction / Action.
// ===========================================================================

fn populate_general_pane(pane: HWND, hi: HMODULE, initial: &Rule) -> Result<(), String> {
    let row_h = 38;
    let mut y = 8;
    let pane_w = 444; // approximate; pane is resized later

    // Name groupbox + edit
    add_groupbox(pane, hi, "Name:", 6, y, pane_w - 12, 32);
    add_edit(
        pane,
        hi,
        ID_NAME_EDIT,
        12,
        y + 14,
        pane_w - 24,
        16,
        &initial.name,
        false,
    );
    y += row_h;

    // Comments groupbox + edit
    add_groupbox(pane, hi, "Comments:", 6, y, pane_w - 12, 32);
    add_edit(
        pane,
        hi,
        ID_COMMENTS_EDIT,
        12,
        y + 14,
        pane_w - 24,
        16,
        initial.comment.as_deref().unwrap_or(""),
        false,
    );
    y += row_h;

    // Protocol + Family side-by-side
    let half_w = (pane_w - 18) / 2;
    add_groupbox(pane, hi, "Protocol:", 6, y, half_w, 36);
    let proto_combo = add_combo(
        pane,
        hi,
        ID_PROTOCOL_COMBO,
        12,
        y + 14,
        half_w - 12,
    );
    populate_combo(proto_combo, &["Any", "TCP", "UDP", "ICMP", "ICMPv6"]);
    let proto_idx = match initial.protocol {
        None => 0,
        Some(6) => 1,
        Some(17) => 2,
        Some(1) => 3,
        Some(58) => 4,
        Some(_) => 0,
    };
    unsafe {
        SendMessageW(proto_combo, CB_SETCURSEL, WPARAM(proto_idx), LPARAM(0));
    }

    add_groupbox(pane, hi, "Family (ports only):", 12 + half_w, y, half_w, 36);
    let family_combo = add_combo(
        pane,
        hi,
        ID_FAMILY_COMBO,
        18 + half_w,
        y + 14,
        half_w - 12,
    );
    populate_combo(family_combo, &["Any", "IPv4", "IPv6"]);
    let family_idx = match initial.address_family {
        None => 0,
        Some(AddressFamily::Ipv4) => 1,
        Some(AddressFamily::Ipv6) => 2,
        Some(AddressFamily::Other(_)) => 0,
    };
    unsafe {
        SendMessageW(family_combo, CB_SETCURSEL, WPARAM(family_idx), LPARAM(0));
    }
    y += 42;

    // Direction
    add_groupbox(pane, hi, "Direction:", 6, y, pane_w - 12, 36);
    let dir_combo = add_combo(pane, hi, ID_DIRECTION_COMBO, 12, y + 14, pane_w - 24);
    populate_combo(dir_combo, &["Outbound", "Inbound", "Both"]);
    let dir_idx = match initial.direction {
        Direction::Outbound => 0,
        Direction::Inbound => 1,
        Direction::Any => 2,
        Direction::Other(_) => 0,
    };
    unsafe {
        SendMessageW(dir_combo, CB_SETCURSEL, WPARAM(dir_idx), LPARAM(0));
    }
    y += 42;

    // Action
    add_groupbox(pane, hi, "Action:", 6, y, pane_w - 12, 36);
    let action_combo = add_combo(pane, hi, ID_ACTION_COMBO, 12, y + 14, pane_w - 24);
    populate_combo(action_combo, &["Allow", "Block"]);
    let action_idx = match initial.action {
        Action::Permit => 0,
        Action::Block => 1,
    };
    unsafe {
        SendMessageW(action_combo, CB_SETCURSEL, WPARAM(action_idx), LPARAM(0));
    }

    Ok(())
}

// ===========================================================================
// Rule pane — Remote and Local rule-entry listviews + Add/Edit/Delete.
// ===========================================================================

fn populate_rule_pane(pane: HWND, hi: HMODULE, initial: &Rule) -> Result<(), String> {
    let pane_w = 444;
    let mut y = 8;

    // Remote group
    add_groupbox(pane, hi, "Remote:", 6, y, pane_w - 12, 100);
    let remote_lv = add_rule_listview(pane, hi, ID_REMOTE_LV, 12, y + 14, pane_w - 100, 80);
    add_button(pane, hi, ID_REMOTE_ADD, "Add", pane_w - 80, y + 14, 70, 22);
    add_button(pane, hi, ID_REMOTE_EDIT, "Edit", pane_w - 80, y + 40, 70, 22);
    add_button(pane, hi, ID_REMOTE_DELETE, "Delete", pane_w - 80, y + 66, 70, 22);
    if let Some(s) = initial.remote.as_deref() {
        for entry in split_rule_entries(s) {
            insert_listview_row(remote_lv, &entry);
        }
    }
    y += 110;

    // Local group
    add_groupbox(pane, hi, "Local:", 6, y, pane_w - 12, 100);
    let local_lv = add_rule_listview(pane, hi, ID_LOCAL_LV, 12, y + 14, pane_w - 100, 80);
    add_button(pane, hi, ID_LOCAL_ADD, "Add", pane_w - 80, y + 14, 70, 22);
    add_button(pane, hi, ID_LOCAL_EDIT, "Edit", pane_w - 80, y + 40, 70, 22);
    add_button(pane, hi, ID_LOCAL_DELETE, "Delete", pane_w - 80, y + 66, 70, 22);
    if let Some(s) = initial.local.as_deref() {
        for entry in split_rule_entries(s) {
            insert_listview_row(local_lv, &entry);
        }
    }
    y += 110;

    // Hint
    let hint = "If you leave the lists blank, the rule applies to any address and port.";
    add_static(pane, hi, hint, 6, y, pane_w - 12, 30);

    Ok(())
}

fn add_rule_listview(parent: HWND, hi: HMODULE, id: i32, x: i32, y: i32, w: i32, h: i32) -> HWND {
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(WS_BORDER.0),
            WC_LISTVIEWW,
            PCWSTR::null(),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WS_VSCROLL
                | WINDOW_STYLE(LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SHOWSELALWAYS),
            x,
            y,
            w,
            h,
            parent,
            HMENU(id as isize),
            hi,
            None,
        )
    };
    unsafe {
        SendMessageW(
            hwnd,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(0),
            LPARAM((LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT) as isize),
        );
    }
    // One column spanning the full width — no header (LVS_NOCOLUMNHEADER).
    let mut buf = wide("Entry");
    let col = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH,
        fmt: LVCFMT_LEFT,
        cx: w - 24,
        pszText: PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            hwnd,
            LVM_INSERTCOLUMNW,
            WPARAM(0),
            LPARAM(&col as *const _ as isize),
        );
    }
    hwnd
}

fn split_rule_entries(s: &str) -> Vec<String> {
    s.split(';')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

fn insert_listview_row(lv: HWND, text: &str) {
    let mut buf = wide(text);
    let count =
        unsafe { SendMessageW(lv, windows_lvm_getitemcount(), WPARAM(0), LPARAM(0)) }.0
            as i32;
    let item = LVITEMW {
        mask: LVIF_TEXT,
        iItem: count,
        iSubItem: 0,
        pszText: PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_INSERTITEMW,
            WPARAM(0),
            LPARAM(&item as *const _ as isize),
        );
    }
}

#[inline]
const fn windows_lvm_getitemcount() -> u32 {
    0x1004 // LVM_GETITEMCOUNT — not re-exported by windows-rs 0.54.
}

fn join_listview(parent: HWND, lv_id: i32) -> String {
    let lv = unsafe { GetDlgItem(parent, lv_id) };
    if lv.0 == 0 {
        return String::new();
    }
    let count =
        unsafe { SendMessageW(lv, windows_lvm_getitemcount(), WPARAM(0), LPARAM(0)) }.0
            as i32;
    let mut parts = Vec::with_capacity(count as usize);
    for i in 0..count {
        parts.push(read_listview_row(lv, i));
    }
    parts.join("; ")
}

fn read_listview_row(lv: HWND, row: i32) -> String {
    let mut buf = [0u16; 512];
    let item = LVITEMW {
        iItem: row,
        iSubItem: 0,
        pszText: PWSTR(buf.as_mut_ptr()),
        cchTextMax: buf.len() as i32,
        ..Default::default()
    };
    let n = unsafe {
        SendMessageW(
            lv,
            LVM_GETITEMTEXTW,
            WPARAM(row as usize),
            LPARAM(&item as *const _ as isize),
        )
    }
    .0 as usize;
    String::from_utf16_lossy(&buf[..n.min(buf.len())])
}

// ===========================================================================
// Apps pane — search edit + checkbox listview.
// ===========================================================================

fn populate_apps_pane(
    pane: HWND,
    hi: HMODULE,
    initial: &Rule,
    paths: &[String],
) -> Result<(), String> {
    let pane_w = 444;
    add_edit(pane, hi, ID_APPS_SEARCH, 0, 0, pane_w, 18, "", false);

    let lv = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(WS_BORDER.0),
            WC_LISTVIEWW,
            PCWSTR::null(),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WS_VSCROLL
                | WINDOW_STYLE(LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SHOWSELALWAYS),
            0,
            22,
            pane_w,
            220,
            pane,
            HMENU(ID_APPS_LV as isize),
            hi,
            None,
        )
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(0),
            LPARAM(
                (LVS_EX_CHECKBOXES | LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT) as isize,
            ),
        );
    }
    let mut buf = wide("App");
    let col = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH,
        fmt: LVCFMT_LEFT,
        cx: pane_w - 24,
        pszText: PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_INSERTCOLUMNW,
            WPARAM(0),
            LPARAM(&col as *const _ as isize),
        );
    }

    let initial_apps: Vec<String> = match initial.apps.as_deref() {
        Some(s) => s.split('|').map(|p| p.trim().to_string()).collect(),
        None => Vec::new(),
    };

    for (idx, path) in paths.iter().enumerate() {
        let basename = std::path::Path::new(path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        let mut text = wide(&basename);
        let checked = initial_apps.iter().any(|a| a == path);
        let state_image = if checked { 2u32 } else { 1u32 };
        let item = LVITEMW {
            mask: LVIF_TEXT | LVIF_STATE,
            iItem: idx as i32,
            iSubItem: 0,
            pszText: PWSTR(text.as_mut_ptr()),
            stateMask: LVIS_STATEIMAGEMASK,
            state: LIST_VIEW_ITEM_STATE_FLAGS(state_image << 12),
            ..Default::default()
        };
        unsafe {
            SendMessageW(
                lv,
                LVM_INSERTITEMW,
                WPARAM(0),
                LPARAM(&item as *const _ as isize),
            );
        }
    }

    let hint = "If no apps are selected, the rule applies to all apps.";
    add_static(pane, hi, hint, 0, 250, pane_w, 30);

    Ok(())
}

fn collect_checked_apps(pane: HWND, paths: &[String]) -> String {
    let lv = unsafe { GetDlgItem(pane, ID_APPS_LV) };
    if lv.0 == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    for (idx, path) in paths.iter().enumerate() {
        // LVM_GETITEMSTATE with LVIS_STATEIMAGEMASK = the state image
        // index in the high nibble: 1 = unchecked, 2 = checked.
        let state = unsafe {
            SendMessageW(
                lv,
                LVM_GETITEMSTATE,
                WPARAM(idx),
                LPARAM(LVIS_STATEIMAGEMASK.0 as isize),
            )
        }
        .0 as u32;
        let checkbox_index = (state >> 12) & 0xF;
        if checkbox_index == 2 {
            out.push(path.clone());
        }
    }
    out.join("|")
}

// ===========================================================================
// Add/Edit-rule-fragment sub-dialog (IDD_EDITOR_ADDRULE).
// ===========================================================================

struct AddRuleState {
    initial: String,
    result: RefCell<Option<String>>,
    finished: Cell<bool>,
}

const ADDRULE_HINT_TEXT: &str = "Examples:\r\n\
    192.168.1.1                IP address\r\n\
    192.168.1.0/24             CIDR block\r\n\
    192.168.1.1-192.168.1.10   IP range\r\n\
    443                        port\r\n\
    [::1]:80                   IPv6 with port\r\n\
    443; 80; 8080              multiple entries (separator)";

fn open_addrule(parent: HWND, initial: &str) -> Option<String> {
    unsafe {
        let hi = GetModuleHandleW(PCWSTR::null()).ok()?;
        let state = Box::new(AddRuleState {
            initial: initial.to_string(),
            result: RefCell::new(None),
            finished: Cell::new(false),
        });
        let state_ptr = Box::into_raw(state) as *mut std::ffi::c_void;

        let title = wide(if initial.is_empty() {
            "Add rule entry"
        } else {
            "Edit rule entry"
        });
        let (x, y) = center_over_parent(parent, 420, 220);
        let dlg = CreateWindowExW(
            WS_EX_DLGMODALFRAME,
            SUB_CLASS_NAME,
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPSIBLINGS,
            x,
            y,
            420,
            220,
            parent,
            HMENU::default(),
            hi,
            Some(state_ptr),
        );
        if dlg.0 == 0 {
            let _ = Box::from_raw(state_ptr as *mut AddRuleState);
            return None;
        }
        let _ = EnableWindow(parent, false);
        let _ = ShowWindow(dlg, SW_SHOW);

        let mut msg = MSG::default();
        loop {
            let s = &*(state_ptr as *const AddRuleState);
            if s.finished.get() {
                break;
            }
            let got = GetMessageW(&mut msg, HWND::default(), 0, 0);
            if !got.as_bool() {
                PostQuitMessage(msg.wParam.0 as i32);
                break;
            }
            if !IsDialogMessageW(dlg, &msg).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        let _ = EnableWindow(parent, true);
        let _ = SetFocus(parent);
        if IsWindow(dlg).as_bool() {
            let _ = DestroyWindow(dlg);
        }

        let s = Box::from_raw(state_ptr as *mut AddRuleState);
        s.result.into_inner()
    }
}

unsafe extern "system" fn addrule_proc(
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
        WM_CREATE => {
            let _ = on_addrule_create(hwnd);
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            match id {
                IDOK_C => {
                    let text = read_edit(hwnd, ID_ADDRULE_EDIT);
                    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) }
                        as *const AddRuleState;
                    if !raw.is_null() {
                        let s = unsafe { &*raw };
                        if !text.trim().is_empty() {
                            *s.result.borrow_mut() = Some(text);
                        }
                        s.finished.set(true);
                    }
                }
                IDCANCEL_C => {
                    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) }
                        as *const AddRuleState;
                    if !raw.is_null() {
                        unsafe { (*raw).finished.set(true) };
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const AddRuleState;
            if !raw.is_null() {
                unsafe { (*raw).finished.set(true) };
            }
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

const IDOK_C: i32 = IDOK.0;
const IDCANCEL_C: i32 = IDCANCEL.0;

fn on_addrule_create(hwnd: HWND) -> Result<(), String> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const AddRuleState;
    if raw.is_null() {
        return Err("AddRuleState missing".into());
    }
    let s = unsafe { &*raw };
    let hi = unsafe { GetModuleHandleW(PCWSTR::null()) }.map_err(|e| e.to_string())?;

    add_edit(hwnd, hi, ID_ADDRULE_EDIT, 10, 10, 400, 22, &s.initial, false);
    add_edit(
        hwnd,
        hi,
        ID_ADDRULE_HINT,
        10,
        40,
        400,
        110,
        ADDRULE_HINT_TEXT,
        true,
    );
    add_button(hwnd, hi, IDOK_C, "Save", 240, 160, 80, 26);
    add_button(hwnd, hi, IDCANCEL_C, "Close", 326, 160, 80, 26);

    let edit = unsafe { GetDlgItem(hwnd, ID_ADDRULE_EDIT) };
    unsafe {
        SetFocus(edit);
    }
    Ok(())
}

// Add/edit/delete buttons on the Rule pane.

fn on_rule_entry(hwnd: HWND, lv_id: i32, prefill: Option<&str>) {
    let pane = match unsafe { state_ref(hwnd) } {
        Some(s) => s.page_rule.get(),
        None => return,
    };
    let lv = unsafe { GetDlgItem(pane, lv_id) };
    if lv.0 == 0 {
        return;
    }
    let new_entry = match open_addrule(hwnd, prefill.unwrap_or("")) {
        Some(t) => t,
        None => return,
    };
    insert_listview_row(lv, &new_entry);
}

fn on_rule_entry_edit(hwnd: HWND, lv_id: i32) {
    let pane = match unsafe { state_ref(hwnd) } {
        Some(s) => s.page_rule.get(),
        None => return,
    };
    let lv = unsafe { GetDlgItem(pane, lv_id) };
    if lv.0 == 0 {
        return;
    }
    let idx = unsafe {
        SendMessageW(
            lv,
            LVM_GETNEXTITEM,
            WPARAM(usize::MAX),
            LPARAM(LVNI_SELECTED as isize),
        )
    }
    .0;
    if idx < 0 {
        return;
    }
    let existing = read_listview_row(lv, idx as i32);
    let new_entry = match open_addrule(hwnd, &existing) {
        Some(t) => t,
        None => return,
    };
    // Rewrite that row in place.
    let mut buf = wide(&new_entry);
    let item = LVITEMW {
        mask: LVIF_TEXT,
        iItem: idx as i32,
        iSubItem: 0,
        pszText: PWSTR(buf.as_mut_ptr()),
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            lv,
            LVM_SETITEMTEXTW,
            WPARAM(idx as usize),
            LPARAM(&item as *const _ as isize),
        );
    }
}

fn on_rule_entry_delete(hwnd: HWND, lv_id: i32) {
    use windows::Win32::UI::Controls::LVM_DELETEITEM;
    let pane = match unsafe { state_ref(hwnd) } {
        Some(s) => s.page_rule.get(),
        None => return,
    };
    let lv = unsafe { GetDlgItem(pane, lv_id) };
    if lv.0 == 0 {
        return;
    }
    let idx = unsafe {
        SendMessageW(
            lv,
            LVM_GETNEXTITEM,
            WPARAM(usize::MAX),
            LPARAM(LVNI_SELECTED as isize),
        )
    }
    .0;
    if idx < 0 {
        return;
    }
    unsafe {
        SendMessageW(lv, LVM_DELETEITEM, WPARAM(idx as usize), LPARAM(0));
    }
}

// ===========================================================================
// Common control helpers.
// ===========================================================================

fn add_groupbox(parent: HWND, hi: HMODULE, label: &str, x: i32, y: i32, w: i32, h: i32) -> HWND {
    let buf = wide(label);
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Button"),
            PCWSTR(buf.as_ptr()),
            WS_CHILD | WS_VISIBLE | WS_GROUP | WINDOW_STYLE(BS_GROUPBOX as u32),
            x,
            y,
            w,
            h,
            parent,
            HMENU::default(),
            hi,
            None,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn add_edit(
    parent: HWND,
    hi: HMODULE,
    id: i32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    initial: &str,
    multiline_readonly: bool,
) -> HWND {
    let buf = wide(initial);
    let mut style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(ES_AUTOHSCROLL as u32);
    if multiline_readonly {
        style = WS_CHILD
            | WS_VISIBLE
            | WS_VSCROLL
            | WINDOW_STYLE(ES_MULTILINE as u32)
            | WINDOW_STYLE(ES_AUTOVSCROLL as u32)
            | WINDOW_STYLE(ES_READONLY as u32);
    }
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(WS_BORDER.0),
            w!("Edit"),
            PCWSTR(buf.as_ptr()),
            style,
            x,
            y,
            w,
            h,
            parent,
            HMENU(id as isize),
            hi,
            None,
        )
    }
}

fn add_combo(parent: HWND, hi: HMODULE, id: i32, x: i32, y: i32, w: i32) -> HWND {
    use windows::Win32::UI::Controls::WC_COMBOBOXW;
    const CBS_DROPDOWNLIST: u32 = 0x0003;
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            WC_COMBOBOXW,
            PCWSTR::null(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WINDOW_STYLE(CBS_DROPDOWNLIST),
            x,
            y,
            w,
            200,
            parent,
            HMENU(id as isize),
            hi,
            None,
        )
    }
}

fn populate_combo(combo: HWND, items: &[&str]) {
    for item in items {
        let buf = wide(item);
        unsafe {
            SendMessageW(combo, CB_ADDSTRING, WPARAM(0), LPARAM(buf.as_ptr() as isize));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_button(parent: HWND, hi: HMODULE, id: i32, label: &str, x: i32, y: i32, w: i32, h: i32) {
    let buf = wide(label);
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Button"),
            PCWSTR(buf.as_ptr()),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_PUSHBUTTON as u32),
            x,
            y,
            w,
            h,
            parent,
            HMENU(id as isize),
            hi,
            None,
        );
    }
}

fn add_static(parent: HWND, hi: HMODULE, label: &str, x: i32, y: i32, w: i32, h: i32) {
    let buf = wide(label);
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("Static"),
            PCWSTR(buf.as_ptr()),
            WS_CHILD | WS_VISIBLE,
            x,
            y,
            w,
            h,
            parent,
            HMENU::default(),
            hi,
            None,
        );
    }
}

fn read_edit(parent: HWND, id: i32) -> String {
    let edit = unsafe { GetDlgItem(parent, id) };
    if edit.0 == 0 {
        return String::new();
    }
    let mut buf = [0u16; 4096];
    let n = unsafe { GetWindowTextW(edit, &mut buf) } as usize;
    String::from_utf16_lossy(&buf[..n])
}

fn read_combo_index(parent: HWND, id: i32) -> usize {
    let combo = unsafe { GetDlgItem(parent, id) };
    if combo.0 == 0 {
        return 0;
    }
    let r = unsafe { SendMessageW(combo, CB_GETCURSEL, WPARAM(0), LPARAM(0)) };
    if r.0 < 0 { 0 } else { r.0 as usize }
}

fn read_check(parent: HWND, id: i32) -> bool {
    let btn = unsafe { GetDlgItem(parent, id) };
    if btn.0 == 0 {
        return false;
    }
    let r = unsafe { SendMessageW(btn, BM_GETCHECK, WPARAM(0), LPARAM(0)) };
    r.0 == BST_CHECKED.0 as isize
}

fn some_if_nonempty(s: String) -> Option<String> {
    if s.trim().is_empty() { None } else { Some(s) }
}

fn center_over_parent(parent: HWND, w: i32, h: i32) -> (i32, i32) {
    let mut rect = RECT::default();
    if parent.0 == 0 || unsafe { GetWindowRect(parent, &mut rect) }.is_err() {
        return (CW_USEDEFAULT, CW_USEDEFAULT);
    }
    let pw = rect.right - rect.left;
    let ph = rect.bottom - rect.top;
    (rect.left + (pw - w) / 2, rect.top + (ph - h) / 2)
}
