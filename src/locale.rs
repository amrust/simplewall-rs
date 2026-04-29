// amwall — locale string lookup (M8).
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// Reads upstream simplewall's `.lng` / `.ini` translation files
// (UTF-16 LE BOM, INI-shaped: `;` comments, `[Language]` section
// headers, `nnn=string` entries with three-digit numeric IDs that
// match upstream's `IDS_*` resource constants).
//
// Both file shapes are accepted by the same parser:
//   - Single-language `<Lang>.ini` (one `[Language]` section),
//   - Bundled multi-language `simplewall.lng` (every language
//     concatenated with `[Language]` dividers).
//
// At runtime, `Locale::lookup(id)` returns the localized string
// for the active language, or `None` if no entry exists. The GUI
// pairs every lookup with an English fallback baked into the
// source (`locale.lookup(IDS_FILE).unwrap_or("&File")`), so an
// unset language is harmless — the user sees English.
//
// IDS keys are u32 numerics (matching `crate::locale::ids` constants
// which mirror upstream's resource.h). Storing the raw numeric in
// the source avoids the symbol-to-numeric remap upstream's build
// pipeline does at compile time.

pub mod ids;

use std::collections::HashMap;
use std::path::Path;

/// Parsed string table for one specific language.
#[derive(Debug, Clone, Default)]
pub struct Locale {
    /// `IDS_*` numeric → translated string. Empty for the default-
    /// English path where no `.ini` was loaded.
    strings: HashMap<u32, String>,
    /// The `[Language]` section header that produced `strings`.
    /// Empty when constructed via `Locale::empty()` (no localization
    /// active — GUI falls through to baked-in English).
    language: String,
}

impl Locale {
    /// Empty locale — every `lookup` returns `None`. The default
    /// when no language is selected or the file failed to load.
    pub fn empty() -> Self {
        Self::default()
    }

    /// List every `[Language]` section header found in a file. Used
    /// to populate the Settings → General → Language dropdown
    /// without shipping a separate per-language metadata file. Empty
    /// vector on any I/O error or for files with no section headers.
    pub fn list_languages_in(path: &Path) -> Vec<String> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        let text = decode_utf16_lossy(&bytes);
        list_sections(&text)
    }

    /// Read a `.lng` / `.ini` file and pick out the section matching
    /// `language` (case-insensitive). Returns `Locale::empty()` on
    /// any I/O error or when the requested section isn't present —
    /// callers don't need to distinguish "no file" from "wrong
    /// language" because both fall back to English.
    pub fn load(path: &Path, language: &str) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let text = decode_utf16_lossy(&bytes);
        Ok(parse(&text, language))
    }

    /// Look up a string by its `IDS_*` numeric ID. Returns `None`
    /// when this locale has no entry for that ID — caller falls
    /// through to its English fallback.
    pub fn lookup(&self, id: u32) -> Option<&str> {
        self.strings.get(&id).map(String::as_str)
    }

    /// `[Language]` header this locale was loaded from. Empty when
    /// `Locale::empty()`.
    pub fn language(&self) -> &str {
        &self.language
    }

    /// Convenience: total entries this locale knows about. Useful
    /// for status-bar diagnostics ("loaded X strings for <lang>").
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// `true` if this locale carries no entries.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

/// Strip a UTF-16 BOM if present, decode the rest as UTF-16 LE.
/// Falls back to UTF-8 if the file isn't UTF-16 — no `.lng` ships
/// in UTF-8, but tolerating it makes hand-edited test fixtures
/// easier to write.
fn decode_utf16_lossy(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        // UTF-16 LE with BOM. Pair bytes into u16s.
        let words: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&words)
    } else if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        // UTF-16 BE with BOM — uncommon for upstream but cheap to
        // handle.
        let words: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&words)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Parse the INI-shaped text and pluck the section matching
/// `wanted_language` (case-insensitive).  Behaviour notes:
///
///   - Lines starting with `;` (after trimming) are comments.
///   - `[name]` starts a new section. Whitespace inside the
///     brackets is preserved, then case-insensitively matched
///     against `wanted_language`.
///   - Outside any section, lines are ignored — matches upstream
///     where the file's preamble carries author + URL comments
///     before the first section header.
///   - `key=value` lines: `key` parsed as decimal `u32` (the
///     three-digit ID, e.g. `002`); whitespace around key/value
///     is trimmed; the value is taken verbatim except for one
///     trailing CRLF, which `lines()` already strips.
///   - Unknown / non-numeric keys (e.g. upstream's symbolic
///     `IDS_FILE=` form in the per-language source `.ini`s) are
///     silently skipped — `Locale::lookup` doesn't index by
///     symbol so they're useless to us.  The GUI uses numeric
///     IDs from `locale::ids`.
fn parse(text: &str, wanted_language: &str) -> Locale {
    let mut strings = HashMap::new();
    let mut current_section: Option<String> = None;
    let mut found_section: Option<String> = None;
    let want_lc = wanted_language.to_lowercase();

    for line in text.lines() {
        let line = line.trim_start_matches('\u{FEFF}'); // stray inner BOM
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                current_section = Some(name.trim().to_string());
                continue;
            }
        }
        // Inside the wanted section?
        let in_wanted = match &current_section {
            Some(s) => s.to_lowercase() == want_lc,
            None => false,
        };
        if !in_wanted {
            continue;
        }
        if found_section.is_none() {
            found_section = current_section.clone();
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim_end_matches(['\r', '\n']);
        let Ok(id) = key.parse::<u32>() else {
            continue;
        };
        strings.insert(id, value.to_string());
    }

    Locale {
        strings,
        language: found_section.unwrap_or_default(),
    }
}

/// Walk the file once and collect every `[Section]` header in
/// order of first appearance. Skipping the second appearance keeps
/// hand-edited files with duplicate sections from showing the same
/// language twice.
fn list_sections(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim_start_matches('\u{FEFF}').trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                let name = name.trim().to_string();
                if !name.is_empty() && !out.contains(&name) {
                    out.push(name);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> &'static str {
        // Mimics the structure of upstream's `simplewall.lng`:
        // preamble comments, multiple [Language] sections, some
        // commented-out entries.
        "; preamble comment\n\
         ; URL\n\
         \n\
         [French]\n\
         002=Fichier\n\
         003=Paramètres\n\
         004=Quitter\n\
         \n\
         [German]\n\
         002=Datei\n\
         003=Einstellungen\n\
         004=Beenden\n"
    }

    #[test]
    fn picks_the_requested_section() {
        let loc = parse(fixture(), "French");
        assert_eq!(loc.language(), "French");
        assert_eq!(loc.lookup(2), Some("Fichier"));
        assert_eq!(loc.lookup(3), Some("Paramètres"));
        assert_eq!(loc.lookup(4), Some("Quitter"));
        // Other-language entries shouldn't bleed through.
        assert!(!loc.strings.values().any(|v| v == "Datei"));
    }

    #[test]
    fn case_insensitive_section_match() {
        let loc = parse(fixture(), "GERMAN");
        assert_eq!(loc.language(), "German");
        assert_eq!(loc.lookup(2), Some("Datei"));
    }

    #[test]
    fn unknown_section_yields_empty_locale() {
        let loc = parse(fixture(), "Klingon");
        assert!(loc.is_empty());
        assert_eq!(loc.language(), "");
        assert_eq!(loc.lookup(2), None);
    }

    #[test]
    fn comments_and_blank_lines_skipped() {
        let text = "[Test]\n; comment inside section\n\n002=hello\n";
        let loc = parse(text, "Test");
        assert_eq!(loc.lookup(2), Some("hello"));
        assert_eq!(loc.len(), 1);
    }

    #[test]
    fn non_numeric_keys_skipped() {
        // Upstream's per-language source `.ini`s use symbolic keys
        // (`IDS_FILE=...`); we accept the file silently but skip
        // those entries — only numeric keys reach `lookup`.
        let text = "[Test]\nIDS_FILE=File\n002=numeric works\n";
        let loc = parse(text, "Test");
        assert_eq!(loc.lookup(2), Some("numeric works"));
        assert_eq!(loc.len(), 1);
    }

    #[test]
    fn utf16_le_bom_decoded() {
        // Build a tiny UTF-16 LE BOM file in memory and verify
        // `decode_utf16_lossy` round-trips it.
        let s = "[T]\n002=ñ\n";
        let mut bytes = vec![0xFF, 0xFE];
        for ch in s.encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let text = decode_utf16_lossy(&bytes);
        let loc = parse(&text, "T");
        assert_eq!(loc.lookup(2), Some("ñ"));
    }

    #[test]
    fn list_sections_returns_each_header_once() {
        let text = "; preamble\n[French]\n002=Fichier\n[German]\n002=Datei\n[French]\n003=dup\n";
        let sections = list_sections(text);
        assert_eq!(sections, vec!["French".to_string(), "German".to_string()]);
    }

    #[test]
    fn no_bom_treated_as_utf8() {
        // Hand-edited fixtures may be UTF-8 — should still work.
        let bytes = "[T]\n002=hello\n".as_bytes();
        let text = decode_utf16_lossy(bytes);
        let loc = parse(&text, "T");
        assert_eq!(loc.lookup(2), Some("hello"));
    }
}
