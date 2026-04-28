// simplewall-rs — build script.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// On Windows: compile `assets/simplewall-rs.rc` → `.res` and link
// it into the binary. The .rc references the application manifest
// (which opts us into ComCtl32 v6 for visual styles + themed
// controls) plus the app icon. On non-Windows hosts the script is
// a no-op so `cargo doc` / cross-target builds keep working.

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/simplewall-rs.rc");
        println!("cargo:rerun-if-changed=assets/manifest.xml");
        println!("cargo:rerun-if-changed=assets/icons/100.ico");
        embed_resource::compile("assets/simplewall-rs.rc", embed_resource::NONE);
    }
}
