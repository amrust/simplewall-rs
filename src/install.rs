// simplewall-rs — high-level install / uninstall.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Bridges the parsed `Profile` (M2) and the rules engine (M3) to
// the kernel-side filter installation (M1). Used by the CLI binary
// (`-install` / `-uninstall`) and exposed publicly so embedders can
// call into the same flow.
//
// Stable provider + sublayer GUIDs let `-install` and `-uninstall`
// cooperate across process invocations: install creates persistent
// records under the well-known keys; uninstall finds them via
// `cleanup_provider(PROVIDER_KEY)` and removes everything tagged
// with that provider — filters, the sublayer, the provider itself.
//
// Windows-only because it sits on top of `wfp`.

#![cfg(windows)]

use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
use windows::core::GUID;

use crate::profile::{Action, Profile, Rule};
use crate::rules;
use crate::wfp::condition::{FilterCondition, IpProto};
use crate::wfp::filter::{self, FilterAction};
use crate::wfp::{CleanupReport, WfpEngine, WfpError, provider, sublayer};

/// Stable provider GUID — randomly generated, hardcoded so that
/// `-install` (which creates the provider) and `-uninstall` (which
/// finds it via enumeration) reach the same kernel object across
/// process invocations.
///
/// This GUID is unique to simplewall-rs and does NOT match upstream
/// simplewall's `GUID_WfpProvider` (`{ 0x4dbcf69d, ... }`); the two
/// projects can coexist on the same machine without colliding on
/// state.
pub const PROVIDER_KEY: GUID =
    GUID::from_u128(0xc6d7_462a_f26f_4f18_9f35_5ed4_42a6_d98e);

/// Stable sublayer GUID — same rationale as `PROVIDER_KEY`.
pub const SUBLAYER_KEY: GUID =
    GUID::from_u128(0xaf71_5b16_1777_40d4_a7ca_3ed3_88fa_5201);

const PROVIDER_NAME: &str = "simplewall-rs";
const PROVIDER_DESCRIPTION: &str =
    "Rust port of simplewall — Windows Filtering Platform firewall";
const SUBLAYER_NAME: &str = "simplewall-rs sublayer";
/// Sublayer weight — mid-range so we don't override system filters
/// at higher weights but rank above default ones. Matches the
/// upstream `FW_SUBLAYER_WEIGHT` default.
const SUBLAYER_WEIGHT: u16 = 0x4000;

/// Errors surfaced by `install_profile`.
#[derive(Debug)]
pub enum InstallError {
    /// A WFP-layer call (provider/sublayer/filter add) failed.
    Wfp(WfpError),
    /// A rule-string attribute (`rule` / `rule_local`) didn't parse.
    /// Rule name is preserved so the operator can identify which
    /// rule in the profile was malformed.
    RuleParse {
        rule_name: String,
        source: rules::ParseError,
    },
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wfp(e) => write!(f, "wfp: {e}"),
            Self::RuleParse { rule_name, source } => {
                write!(f, "rule `{rule_name}`: {source}")
            }
        }
    }
}

impl std::error::Error for InstallError {}

impl From<WfpError> for InstallError {
    fn from(e: WfpError) -> Self {
        Self::Wfp(e)
    }
}

/// Counts returned by `install_profile`.
#[derive(Debug, Clone, Copy)]
pub struct InstallReport {
    /// Number of filters successfully installed.
    pub filters_added: u32,
    /// Number of rules in the profile that produced zero filters
    /// (e.g. disabled, or only had `apps` / `direction` constraints
    /// the current MVP doesn't compile yet). Helpful for surfacing
    /// "your profile has 50 rules but only 30 filtered" feedback.
    pub rules_skipped: u32,
}

/// Install all enabled rules in `profile` into the kernel.
///
/// Idempotent in the provider/sublayer sense: re-running this
/// against an already-installed system tolerates the persistent
/// provider + sublayer that the previous run created
/// (`FWP_E_ALREADY_EXISTS` is treated as success). Filters are
/// always created fresh — running `install_profile` twice without
/// an intervening `uninstall` will accumulate duplicate filters.
///
/// `persistent = true` writes records that survive reboots
/// (upstream's default `-install` mode); `persistent = false`
/// writes session-scoped records that the kernel removes on
/// engine close (upstream's `-install -temp` mode).
///
/// MVP layer-selection note: every filter installs at
/// `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (outbound IPv4). This means
/// `direction = Inbound` rules and IPv6 traffic aren't filtered
/// yet. Layer selection per (direction × address-family) is a
/// follow-up.
///
/// Requires admin.
pub fn install_profile(
    engine: &WfpEngine,
    profile: &Profile,
    persistent: bool,
) -> Result<InstallReport, InstallError> {
    provider::add_with_key(
        engine,
        PROVIDER_NAME,
        PROVIDER_DESCRIPTION,
        persistent,
        &PROVIDER_KEY,
    )?;
    sublayer::add_with_key(
        engine,
        SUBLAYER_NAME,
        "",
        SUBLAYER_WEIGHT,
        Some(&PROVIDER_KEY),
        persistent,
        &SUBLAYER_KEY,
    )?;

    let mut filters_added = 0u32;
    let mut rules_skipped = 0u32;
    for rule in &profile.custom_rules {
        if !rule.is_enabled {
            rules_skipped += 1;
            continue;
        }
        let added = install_one_rule(engine, persistent, rule)?;
        if added == 0 {
            rules_skipped += 1;
        }
        filters_added += added;
    }

    Ok(InstallReport {
        filters_added,
        rules_skipped,
    })
}

/// Remove every filter, sublayer, and the provider itself
/// associated with `PROVIDER_KEY`. Idempotent — running twice
/// reports `provider_deleted = false` on the second call.
///
/// Requires admin.
pub fn uninstall(engine: &WfpEngine) -> Result<CleanupReport, WfpError> {
    engine.cleanup_provider(&PROVIDER_KEY)
}

/// Install all the filters that come out of one `Rule`.
///
/// Per upstream's semicolon-list semantics, each clause from
/// `rule.remote` × each clause from `rule.local` becomes its own
/// filter. With either side absent, that side contributes one
/// "no constraint" pseudo-clause so we always produce at least one
/// filter (modulo the empty-conditions skip below).
fn install_one_rule(
    engine: &WfpEngine,
    persistent: bool,
    rule: &Rule,
) -> Result<u32, InstallError> {
    let remotes = parse_rule_string(&rule.name, rule.remote.as_deref())?;
    let locals = parse_rule_string(&rule.name, rule.local.as_deref())?;

    let action = match rule.action {
        Action::Permit => FilterAction::Permit,
        Action::Block => FilterAction::Block,
    };

    let mut count = 0u32;
    for remote in &remotes {
        for local in &locals {
            let mut conds: Vec<FilterCondition> = Vec::new();
            if let Some(p) = rule.protocol {
                conds.push(FilterCondition::Protocol(IpProto::Other(p)));
            }
            if let Some(r) = remote {
                conds.extend(rules::compile(rules::Side::Remote, std::slice::from_ref(r)));
            }
            if let Some(l) = local {
                conds.extend(rules::compile(rules::Side::Local, std::slice::from_ref(l)));
            }
            // No conditions == match-all-traffic — too dangerous to
            // install silently. Skip; surfaces in `rules_skipped`.
            if conds.is_empty() {
                continue;
            }

            filter::add(
                engine,
                &rule.name,
                rule.comment.as_deref().unwrap_or(""),
                &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                &SUBLAYER_KEY,
                Some(&PROVIDER_KEY),
                &conds,
                action,
                persistent,
            )?;
            count += 1;
        }
    }
    Ok(count)
}

/// Parse a `rule` / `rule_local` string into a list of clauses,
/// each wrapped in `Some` so the cross-product loop can iterate
/// uniformly. An absent attribute yields a single `None` so the
/// other side still produces filters.
fn parse_rule_string(
    rule_name: &str,
    s: Option<&str>,
) -> Result<Vec<Option<rules::RuleClause>>, InstallError> {
    match s {
        None => Ok(vec![None]),
        Some(s) => {
            let clauses = rules::parse_str(s).map_err(|source| InstallError::RuleParse {
                rule_name: rule_name.to_string(),
                source,
            })?;
            Ok(clauses.into_iter().map(Some).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live admin-only smoke test for the install module's public
    /// API. Installs a tiny profile (one rule, two clauses → 2
    /// filters), asserts the report counts, then uninstalls and
    /// asserts the cleanup counts. Volatile (`persistent = false`)
    /// to avoid leaking persistent kernel state on test failure.
    #[test]
    #[ignore = "requires elevated shell"]
    fn install_profile_then_uninstall_admin_smoke() {
        let xml = r#"<?xml version="1.0" ?>
<root timestamp="0" type="4" version="5">
  <rules_custom>
    <item name="install-test" rule="65530;65531" protocol="6" is_enabled="true" />
  </rules_custom>
</root>"#;
        let profile = crate::profile::parse_str(xml).expect("profile parse failed");
        let engine = WfpEngine::open().expect("engine open failed");

        let report = install_profile(&engine, &profile, false).expect("install failed");
        assert_eq!(report.filters_added, 2);
        assert_eq!(report.rules_skipped, 0);

        let cleanup = uninstall(&engine).expect("uninstall failed");
        assert_eq!(cleanup.filters_deleted, 2);
        assert_eq!(cleanup.sublayers_deleted, 1);
        assert!(cleanup.provider_deleted);
    }
}
