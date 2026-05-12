//! Rule on-disk schema (TOML) and conversion to BPF-map keys/values.
//!
//! TOML schema:
//!
//!     [[rule]]
//!     comm   = "curl"      # process name (max 15 chars, matches BPF comm)
//!     ip     = "any"       # "any" or an IPv4 dotted-quad
//!     port   = 443         # 0 = any
//!     action = "allow"     # or "deny"

use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub comm: String,
    pub ip: String,
    pub port: u16,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RulesFile {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

impl Rule {
    pub fn comm_bytes(&self) -> [u8; 16] {
        let bytes = self.comm.as_bytes();
        let mut out = [0u8; 16];
        let n = bytes.len().min(15);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    pub fn ip4(&self) -> Result<u32> {
        let s = self.ip.trim();
        if s.eq_ignore_ascii_case("any") || s == "0.0.0.0" || s.is_empty() {
            return Ok(0);
        }
        let addr = Ipv4Addr::from_str(s)
            .with_context(|| format!("rule ip '{}' is not 'any' or a v4 address", s))?;
        Ok(u32::from(addr).to_be())
    }

    pub fn action_byte(&self) -> u8 {
        match self.action {
            Action::Allow => 1,
            Action::Deny => 0,
        }
    }
}

impl RulesFile {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir -p {}", parent.display()))?;
            }
        }
        let text = toml::to_string_pretty(self).context("serializing rules to TOML")?;
        std::fs::write(path, text)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}
