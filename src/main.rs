// simplewall-rs — a Rust port of simplewall (https://github.com/henrypp/simplewall)
// Copyright (C) 2026  simplewall-rs contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version. See LICENSE.

#[cfg(windows)]
mod wfp;

#[cfg(windows)]
fn main() -> Result<(), wfp::WfpError> {
    println!("simplewall-rs (pre-alpha) — see README.md");
    let engine = wfp::WfpEngine::open()?;
    println!("WFP engine handle acquired: {:?}", engine.raw());
    // engine drops here — FwpmEngineClose0 runs
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("simplewall-rs is Windows-only (Windows Filtering Platform).");
    std::process::exit(1);
}
