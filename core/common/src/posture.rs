//! Device security posture and score model.

use crate::Finding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionStatus {
    /// No elevated issues and core local checks completed successfully.
    Protected,
    /// Medium issues or incomplete security configuration.
    Attention,
    /// High/critical issues require user action.
    AtRisk,
    /// Scanner could not complete a trustworthy assessment.
    Unknown,
}

impl ProtectionStatus {
    pub fn user_label(self) -> &'static str {
        match self {
            Self::Protected => "Protected",
            Self::Attention => "Attention needed",
            Self::AtRisk => "At risk",
            Self::Unknown => "Status unknown",
        }
    }

    pub fn emoji(self) -> &'static str {
        match self {
            Self::Protected => "🟢",
            Self::Attention => "🟡",
            Self::AtRisk => "🔴",
            Self::Unknown => "⚪",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    /// 0–100 overall posture score (higher is better).
    pub value: u8,
    pub status: ProtectionStatus,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScoreContext {
    /// False when Defender/Firewall (or other core) signals were incomplete.
    pub assessment_complete: bool,
}

impl SecurityScore {
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self::from_findings_with_context(
            findings,
            ScoreContext {
                assessment_complete: true,
            },
        )
    }

    pub fn from_findings_with_context(findings: &[Finding], ctx: ScoreContext) -> Self {
        let mut score: i32 = 100;

        for finding in findings {
            let penalty = match finding.severity {
                crate::Severity::Info => 0,
                crate::Severity::Low => 2,
                crate::Severity::Medium => 6,
                crate::Severity::High => 12,
                crate::Severity::Critical => 20,
            };
            score -= penalty;
        }

        let value = score.clamp(0, 100) as u8;
        let mut status = if findings.iter().any(|f| {
            matches!(
                f.severity,
                crate::Severity::Critical | crate::Severity::High
            )
        }) {
            ProtectionStatus::AtRisk
        } else if findings
            .iter()
            .any(|f| f.severity == crate::Severity::Medium)
            || value < 85
        {
            ProtectionStatus::Attention
        } else {
            ProtectionStatus::Protected
        };

        // Never claim Protected when core assessment signals were incomplete.
        if !ctx.assessment_complete && status == ProtectionStatus::Protected {
            status = ProtectionStatus::Unknown;
        }

        let summary = match status {
            ProtectionStatus::Protected => {
                "Local analysis found no elevated issues. This is not a full antivirus scan."
                    .to_string()
            }
            ProtectionStatus::Attention => {
                "Some security settings or items need your attention.".to_string()
            }
            ProtectionStatus::AtRisk => {
                "SentinelAI found issues that need prompt attention.".to_string()
            }
            ProtectionStatus::Unknown => {
                "SentinelAI could not fully verify this device's security status.".to_string()
            }
        };

        Self {
            value,
            status,
            summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub score: SecurityScore,
    pub windows_defender: Option<ComponentStatus>,
    pub firewall: Option<ComponentStatus>,
    pub analysis_mode: AnalysisMode,
    pub assessed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub name: String,
    pub enabled: Option<bool>,
    pub healthy: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisMode {
    /// Only local heuristics / OS signals. No external TI provider queried.
    LocalOnly,
    /// At least one optional external provider was configured and used.
    LocalPlusThreatIntel,
}

impl AnalysisMode {
    pub fn user_label(self) -> &'static str {
        match self {
            Self::LocalOnly => "Local analysis only",
            Self::LocalPlusThreatIntel => "Local analysis + configured threat intelligence",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, Finding, FindingCategory, Severity};

    #[test]
    fn empty_findings_score_protected_when_complete() {
        let score = SecurityScore::from_findings(&[]);
        assert_eq!(score.value, 100);
        assert_eq!(score.status, ProtectionStatus::Protected);
        assert!(score.summary.contains("not a full antivirus scan"));
    }

    #[test]
    fn incomplete_assessment_never_claims_protected() {
        let score = SecurityScore::from_findings_with_context(
            &[],
            ScoreContext {
                assessment_complete: false,
            },
        );
        assert_eq!(score.status, ProtectionStatus::Unknown);
    }

    #[test]
    fn high_finding_marks_at_risk() {
        let finding = Finding::new(
            FindingCategory::Process,
            Severity::High,
            Confidence::Suspicious,
            "Unusual application",
            "An application is behaving unusually.",
        );
        let score = SecurityScore::from_findings(&[finding]);
        assert_eq!(score.status, ProtectionStatus::AtRisk);
        assert!(score.value < 100);
    }
}
