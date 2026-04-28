// simplewall-rs — WFP engine bindings.
// Copyright (C) 2026  simplewall-rs contributors. Licensed GPL-3.0-or-later.
//
// Thin wrapper around the user-mode Windows Filtering Platform engine
// handle (`fwpuclnt.dll`). M1.1 binds the bare open/close pair with
// RAII; session config (display name, session-key GUID, transaction
// timeout) and the EPT_S_NOT_REGISTERED retry loop arrive in
// later commits.

#![cfg(windows)]

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

const ERROR_SUCCESS: u32 = 0;

#[derive(Debug)]
pub enum WfpError {
    /// `FwpmEngineOpen0` returned a non-zero Win32 error.
    Open(u32),
}

impl std::fmt::Display for WfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(s) => write!(f, "FwpmEngineOpen0 failed (Win32 error {s:#010x})"),
        }
    }
}

impl std::error::Error for WfpError {}

/// RAII wrapper around a WFP engine handle.
///
/// On drop the handle is closed via `FwpmEngineClose0`. Close failures
/// during drop are logged via `eprintln!` (the upstream C version
/// terminates the process on a failed close — we treat it as a soft
/// failure since the engine handle is process-scoped and BFE will
/// reclaim it when we exit).
pub struct WfpEngine {
    handle: HANDLE,
}

impl WfpEngine {
    /// Open a WFP engine handle bound to the local machine using the
    /// kernel-managed default session.
    ///
    /// Calls `FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &handle)`.
    /// Requires the Base Filtering Engine (BFE) service to be running;
    /// does NOT require administrator privileges (only filter mutations
    /// do). A custom `FWPM_SESSION0` with display data + session key
    /// will land in M1.2.
    pub fn open() -> Result<Self, WfpError> {
        let mut handle = HANDLE::default();
        let status = unsafe {
            FwpmEngineOpen0(
                windows::core::PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                None,
                &mut handle,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(WfpError::Open(status));
        }
        Ok(Self { handle })
    }

    /// Raw `HANDLE` for callers that need to pass it to other
    /// `Fwpm*` APIs. Lifetime is tied to `&self`.
    pub fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        let status = unsafe { FwpmEngineClose0(self.handle) };
        if status != ERROR_SUCCESS {
            eprintln!("simplewall-rs: FwpmEngineClose0 returned {status:#010x}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: open the engine with default session, verify the
    /// handle is non-null, drop it. Hits real Win32 — requires the
    /// BFE service to be running, which it always is on a default
    /// Windows install.
    #[test]
    fn open_and_drop_default_engine() {
        let engine = WfpEngine::open()
            .expect("FwpmEngineOpen0 failed - is the BFE service running?");
        assert!(
            !engine.raw().is_invalid(),
            "FwpmEngineOpen0 returned ERROR_SUCCESS but the handle is invalid"
        );
        // engine drops here, FwpmEngineClose0 runs
    }
}
