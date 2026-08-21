//! Shared types for SentinelAI.
//!
//! These types are the contract between collectors, the threat-analysis engine,
//! the Windows agent, and (later) cloud APIs and UI clients.

pub mod confidence;
pub mod findings;
pub mod posture;
pub mod scan;
pub mod version;

pub use confidence::Confidence;
pub use findings::{Finding, FindingCategory, Severity};
pub use posture::{
    AnalysisMode, ComponentStatus, ProtectionStatus, ScoreContext, SecurityPosture, SecurityScore,
};
pub use scan::{ScanKind, ScanReport, ScanStatus};
pub use version::SENTINEL_VERSION;
