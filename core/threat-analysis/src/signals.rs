//! Heuristic signal vocabulary for explainable scoring.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    UnknownPublisher,
    TempDirectoryExecution,
    RecentlyDownloaded,
    SuspiciousPersistence,
    UnusualParentProcess,
    SuspiciousCommandLine,
    UnsignedExecutable,
    SuspiciousLocation,
    HighPrivilegeUnexpected,
    NetworkToUnusualPort,
    TrustedLocation,
    SignedByKnownPublisher,
    SystemProtectedPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub kind: SignalKind,
    /// Positive values increase risk; negative values decrease risk.
    pub weight: i32,
    pub reason: String,
}

impl Signal {
    pub fn new(kind: SignalKind, weight: i32, reason: impl Into<String>) -> Self {
        Self {
            kind,
            weight,
            reason: reason.into(),
        }
    }
}
