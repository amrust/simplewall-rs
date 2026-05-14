// amwall — per-user override state for bundled internal rules.
// Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
//
// The System Rules and Blocklist tabs (plus the preset half of
// User Rules) display rules from `assets/profile_internal.xml`,
// which is `include_str!`'d into the binary and therefore immutable
// at runtime. Upstream simplewall lets users toggle each of those
// rules on/off through a checkbox; amwall pre-v1.1.7 didn't,
// because there was no place to persist a per-rule override.
//
// This module is that place. We track only DELTAS from each rule's
// bundled `is_enabled` default — a rule that the user hasn't
// touched has no entry. Toggling a rule back to its bundled state
// removes the entry, so the override file stays small.
//
// On-disk format (one line per override) under
// `<data_dir>\internal_rules_state.txt`:
//
//   <kind>:<rule-name>=<true|false>
//
// where <kind> is one of `system`, `custom`, `blocklist` —
// scoping by kind prevents collisions between e.g. a user-named
// custom rule and a system rule that happen to share a name.
// Rule names from `profile_internal.xml` contain spaces, brackets,
// and slashes (e.g. "Windows Update Delivery service",
// "RDP [inbound]", "IMAP/POP3/SMTP") but never `=` or `\n`, so a
// `split_once('=')` round-trip is safe.
//
// Lives at `src/internal_rules_state.rs` rather than under `gui/`
// because both the GUI (mutates via the rules-tab checkbox) and
// `install.rs` (consults via `effective_is_enabled` when deciding
// which rules to translate into WFP filters) need to share it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Which internal-profile rule list a name belongs to. Used as a
/// prefix in the override map's key so a custom-rule preset named
/// "DNS" and a system rule named "DNS" don't collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleKind {
    System,
    Custom,
    Blocklist,
}

impl RuleKind {
    fn as_str(self) -> &'static str {
        match self {
            RuleKind::System => "system",
            RuleKind::Custom => "custom",
            RuleKind::Blocklist => "blocklist",
        }
    }
}

/// User overrides for bundled internal-profile rules. Lives in
/// `App.internal_rules_state` under a `RefCell`; populated at
/// startup from `internal_rules_state.txt` and rewritten after
/// every checkbox toggle.
#[derive(Debug, Default, Clone)]
pub struct InternalRulesState {
    overrides: HashMap<String, bool>,
}

impl InternalRulesState {
    /// Read overrides from `path`. Missing file → empty (everyone
    /// at bundled defaults). Unreadable / malformed lines are
    /// skipped with a warning so a corrupt file never blocks
    /// startup — same forgiving-loader pattern as `Settings::load`.
    pub fn load(path: &Path) -> Self {
        let mut s = Self::default();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return s,
            Err(e) => {
                eprintln!(
                    "amwall: internal_rules_state: read failed for {}: {e}",
                    path.display()
                );
                return s;
            }
        };
        for (lineno, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                eprintln!(
                    "amwall: internal_rules_state: line {} ignored — no '=' separator",
                    lineno + 1
                );
                continue;
            };
            let value = match value.trim() {
                "true" | "1" | "on" | "yes" => true,
                "false" | "0" | "off" | "no" => false,
                other => {
                    eprintln!(
                        "amwall: internal_rules_state: line {} ignored — `{other}` not a bool",
                        lineno + 1
                    );
                    continue;
                }
            };
            // Keep the key verbatim (with the kind: prefix). The
            // public API does the prefix construction on the way in
            // and out so the on-disk representation never leaks.
            s.overrides.insert(key.trim().to_string(), value);
        }
        s
    }

    /// Write the current overrides to `path`. Creates parent dirs
    /// if needed. No-op when the override map is empty, except we
    /// still write an empty file so a manual `rm` cleanup is
    /// detectable on next load.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf = String::new();
        buf.push_str("# amwall internal-rules toggle overrides — \
                      edited by hand at your own risk\n");
        // Sort for deterministic output: easier to diff across
        // commits / sessions and avoids spurious file-change noise
        // when the HashMap rehashes.
        let mut keys: Vec<&String> = self.overrides.keys().collect();
        keys.sort();
        for k in keys {
            let v = self.overrides[k];
            use std::fmt::Write;
            let _ = writeln!(buf, "{k}={v}");
        }
        std::fs::write(path, buf)
    }

    /// True if the user has flipped this rule from its bundled
    /// default. Compute the effective enabled state with
    /// `effective_is_enabled`; this helper exists so callers
    /// rendering the row (e.g. a future "override" badge column)
    /// can show that the user has overridden the default without
    /// re-resolving the default themselves.
    #[allow(dead_code)]
    pub fn has_override(&self, kind: RuleKind, name: &str) -> bool {
        self.overrides.contains_key(&compose_key(kind, name))
    }

    /// Resolve the effective is_enabled for a bundled rule: the
    /// override if the user set one, otherwise the `default`
    /// from the bundled XML.
    pub fn effective_is_enabled(
        &self,
        kind: RuleKind,
        name: &str,
        default: bool,
    ) -> bool {
        self.overrides
            .get(&compose_key(kind, name))
            .copied()
            .unwrap_or(default)
    }

    /// Set the effective is_enabled for a bundled rule. When the
    /// new value matches `default` we drop the override entirely
    /// (keeps the file lean and makes "back to default" a real
    /// reset, not a sticky `=true` row).
    pub fn set(&mut self, kind: RuleKind, name: &str, enabled: bool, default: bool) {
        let key = compose_key(kind, name);
        if enabled == default {
            self.overrides.remove(&key);
        } else {
            self.overrides.insert(key, enabled);
        }
    }
}

fn compose_key(kind: RuleKind, name: &str) -> String {
    format!("{}:{name}", kind.as_str())
}

/// Standard location: `<data_dir>\internal_rules_state.txt`. Lives
/// alongside `settings.txt` and `profile.xml`. Lives in the same
/// directory in both portable and installed modes, courtesy of
/// `paths::data_dir`.
pub fn default_state_path() -> PathBuf {
    crate::paths::data_dir().join("internal_rules_state.txt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_default() {
        let s = InternalRulesState::default();
        assert!(s.effective_is_enabled(RuleKind::System, "DNS", true));
        assert!(!s.effective_is_enabled(RuleKind::System, "DNS", false));
    }

    #[test]
    fn override_takes_precedence_over_default() {
        let mut s = InternalRulesState::default();
        s.set(RuleKind::System, "DNS", false, true);
        assert!(!s.effective_is_enabled(RuleKind::System, "DNS", true));
        s.set(RuleKind::System, "DNS", true, false);
        assert!(s.effective_is_enabled(RuleKind::System, "DNS", false));
    }

    #[test]
    fn setting_to_default_clears_override() {
        let mut s = InternalRulesState::default();
        s.set(RuleKind::System, "DNS", false, true);
        assert!(s.has_override(RuleKind::System, "DNS"));
        s.set(RuleKind::System, "DNS", true, true);
        assert!(!s.has_override(RuleKind::System, "DNS"));
    }

    #[test]
    fn kind_scoping_prevents_collision() {
        let mut s = InternalRulesState::default();
        s.set(RuleKind::System, "DNS", false, true);
        // Same name under a different kind must not be affected.
        assert!(s.effective_is_enabled(RuleKind::Custom, "DNS", true));
        assert!(!s.has_override(RuleKind::Custom, "DNS"));
    }

    #[test]
    fn rule_names_with_special_chars_round_trip() {
        let dir = std::env::temp_dir().join("amwall-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("internal_rules_state_special.txt");
        let _ = std::fs::remove_file(&path);

        let mut s = InternalRulesState::default();
        // These three come straight from upstream simplewall's
        // bundled rules — spaces, brackets, slashes.
        s.set(RuleKind::System, "Windows Update Delivery service", false, true);
        s.set(RuleKind::System, "RDP [inbound]", true, false);
        s.set(RuleKind::Custom, "IMAP/POP3/SMTP", true, false);
        s.save(&path).expect("save should succeed");

        let loaded = InternalRulesState::load(&path);
        assert!(!loaded.effective_is_enabled(
            RuleKind::System, "Windows Update Delivery service", true,
        ));
        assert!(loaded.effective_is_enabled(RuleKind::System, "RDP [inbound]", false));
        assert!(loaded.effective_is_enabled(RuleKind::Custom, "IMAP/POP3/SMTP", false));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let dir = std::env::temp_dir().join("amwall-tests");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("internal_rules_state_malformed.txt");
        std::fs::write(
            &path,
            "# comment\n\
             system:DNS=true\n\
             no-equals-sign\n\
             system:NTP=not-a-bool\n\
             custom:HTTP=false\n",
        )
        .unwrap();
        let s = InternalRulesState::load(&path);
        assert!(s.effective_is_enabled(RuleKind::System, "DNS", false));
        // NTP line had a bad bool — falls back to default.
        assert!(s.effective_is_enabled(RuleKind::System, "NTP", true));
        assert!(!s.effective_is_enabled(RuleKind::System, "NTP", false));
        assert!(!s.effective_is_enabled(RuleKind::Custom, "HTTP", true));
        let _ = std::fs::remove_file(&path);
    }
}
