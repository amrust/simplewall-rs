// simplewall-rs — CLI entry point.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version. See LICENSE.
//
// Subcommands (matching upstream's flag style):
//   simplewall-rs.exe -install [profile.xml]   load + install rules
//   simplewall-rs.exe -uninstall               remove all our filters
//   simplewall-rs.exe -h | --help              print usage
//
// Both -install and -uninstall require Administrator privileges
// (filter management is admin-gated by WFP). When run unelevated
// the binary prints an error and exits 1; auto-relaunch via
// ShellExecuteW "runas" is a follow-up.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    cli::run()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("simplewall-rs is Windows-only (Windows Filtering Platform).");
    std::process::ExitCode::from(1)
}

#[cfg(windows)]
mod cli {
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use simplewall_rs::install;
    use simplewall_rs::profile;
    use simplewall_rs::wfp::WfpEngine;
    use windows::Win32::UI::Shell::IsUserAnAdmin;

    pub fn run() -> ExitCode {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            print_usage();
            return ExitCode::from(2);
        }
        match args[1].as_str() {
            "-h" | "--help" => {
                print_usage();
                ExitCode::from(0)
            }
            "-install" => {
                if !require_admin() {
                    return ExitCode::from(1);
                }
                let path = args
                    .get(2)
                    .map(PathBuf::from)
                    .unwrap_or_else(default_profile_path);
                handle_install(&path)
            }
            "-uninstall" => {
                if !require_admin() {
                    return ExitCode::from(1);
                }
                handle_uninstall()
            }
            other => {
                eprintln!("simplewall-rs: unknown command `{other}`");
                print_usage();
                ExitCode::from(2)
            }
        }
    }

    /// Returns true if the current process is elevated. Otherwise
    /// prints an error and returns false.
    fn require_admin() -> bool {
        let is_admin = unsafe { IsUserAnAdmin() }.as_bool();
        if !is_admin {
            eprintln!(
                "simplewall-rs: Administrator privileges required for filter management."
            );
            eprintln!("       Re-run from an elevated PowerShell or Command Prompt.");
        }
        is_admin
    }

    fn handle_install(path: &Path) -> ExitCode {
        let xml = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "simplewall-rs: failed to read profile at {}: {e}",
                    path.display()
                );
                return ExitCode::from(1);
            }
        };
        let profile = match profile::parse_str(&xml) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("simplewall-rs: profile parse failed: {e}");
                return ExitCode::from(1);
            }
        };
        let engine = match WfpEngine::open() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("simplewall-rs: WFP engine open failed: {e}");
                return ExitCode::from(1);
            }
        };
        match install::install_profile(&engine, &profile, true) {
            Ok(report) => {
                println!(
                    "simplewall-rs: installed {} filter(s); skipped {} rule(s).",
                    report.filters_added, report.rules_skipped,
                );
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("simplewall-rs: install failed: {e}");
                ExitCode::from(1)
            }
        }
    }

    fn handle_uninstall() -> ExitCode {
        let engine = match WfpEngine::open() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("simplewall-rs: WFP engine open failed: {e}");
                return ExitCode::from(1);
            }
        };
        match install::uninstall(&engine) {
            Ok(report) => {
                println!(
                    "simplewall-rs: removed {} filter(s), {} sublayer(s); provider {}.",
                    report.filters_deleted,
                    report.sublayers_deleted,
                    if report.provider_deleted {
                        "removed"
                    } else {
                        "not present"
                    },
                );
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("simplewall-rs: uninstall failed: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// Default profile-file location: `%APPDATA%\simplewall-rs\profile.xml`.
    /// Falls back to `profile.xml` in the current directory if
    /// `%APPDATA%` is unset (e.g. running as SYSTEM).
    fn default_profile_path() -> PathBuf {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            PathBuf::from(appdata)
                .join("simplewall-rs")
                .join("profile.xml")
        } else {
            PathBuf::from("profile.xml")
        }
    }

    fn print_usage() {
        println!("simplewall-rs — Rust port of simplewall (Windows Filtering Platform)");
        println!();
        println!("usage:");
        println!("    simplewall-rs.exe -install [profile.xml]");
        println!("        Load profile.xml (or %APPDATA%\\simplewall-rs\\profile.xml)");
        println!("        and install its rules into the kernel as persistent");
        println!("        filters. Requires Administrator.");
        println!();
        println!("    simplewall-rs.exe -uninstall");
        println!("        Remove every filter / sublayer / provider that");
        println!("        simplewall-rs has installed. Requires Administrator.");
        println!();
        println!("    simplewall-rs.exe -h | --help");
        println!("        Print this help.");
    }
}
