// amwall — IDS_* numeric string identifiers (M8).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Numeric IDs mirror upstream simplewall's `src/resource.h` so the
// bundled `simplewall.lng` (which uses three-digit numeric keys —
// `002=...`, `003=...`) drops in unchanged.
//
// Only the constants amwall actually surfaces today are listed
// here; the full upstream table has 277 entries. Each new GUI
// string we localize adds its constant. See upstream's resource.h
// for the canonical numeric assignment.

#![allow(dead_code)] // many entries listed for future M8.2 wiring

// ---- Top menu labels ----
pub const IDS_FILE: u32 = 2;
pub const IDS_SETTINGS: u32 = 3;
pub const IDS_EXIT: u32 = 4;
pub const IDS_EDIT: u32 = 5;
pub const IDS_VIEW: u32 = 12;
pub const IDS_HELP: u32 = 19;
pub const IDS_TRAY_BLOCKLIST_RULES: u32 = 29;

// ---- Common menu actions ----
pub const IDS_PURGE_UNUSED: u32 = 7;
pub const IDS_PURGE_TIMERS: u32 = 8;
pub const IDS_FIND: u32 = 9;
pub const IDS_REFRESH: u32 = 11;
pub const IDS_LANGUAGE: u32 = 17;
pub const IDS_FONT: u32 = 18;
pub const IDS_WEBSITE: u32 = 20;
pub const IDS_CHECKUPDATES: u32 = 21;
pub const IDS_ABOUT: u32 = 23;
