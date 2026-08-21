//! Scan request/report types.

use crate::findings::Finding;
use crate::posture::{AnalysisMode, SecurityPosture};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    Quick,
    Smart,
    Full,
}

impl ScanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Smart => "smart",
            Self::Full => "full",
        }
    }

    pub fn user_label(self) -> &'static str {
        match self {
            Self::Quick => "Quick Scan",
            Self::Smart => "Smart Scan",
            Self::Full => "Full Scan",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Completed,
    CompletedWithWarnings,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub id: Uuid,
    pub kind: ScanKind,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub posture: SecurityPosture,
    pub findings: Vec<Finding>,
    pub collectors_run: Vec<String>,
    pub warnings: Vec<String>,
    pub analysis_mode: AnalysisMode,
    pub notes: Vec<String>,
}

impl ScanReport {
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}
