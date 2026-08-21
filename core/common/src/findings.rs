//! Security findings and severity model.

use crate::Confidence;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Process,
    Startup,
    File,
    Network,
    Configuration,
    Browser,
    Privacy,
    Defender,
    Firewall,
    Other,
}

/// A single explainable security observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub category: FindingCategory,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Plain-language summary for ordinary users.
    pub title: String,
    /// Plain-language explanation.
    pub summary: String,
    /// Technical detail (shown behind "Show technical details").
    pub technical_details: String,
    /// Why this finding was raised (explainable scoring inputs).
    pub reasons: Vec<String>,
    /// Recommended safe next step for the user.
    pub recommendation: String,
    /// Optional subject path / process name / URL, etc.
    pub subject: Option<String>,
    pub risk_score: u8,
    pub observed_at: DateTime<Utc>,
}

impl Finding {
    pub fn new(
        category: FindingCategory,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            category,
            severity,
            confidence,
            title: title.into(),
            summary: summary.into(),
            technical_details: String::new(),
            reasons: Vec::new(),
            recommendation: String::new(),
            subject: None,
            risk_score: 0,
            observed_at: Utc::now(),
        }
    }

    pub fn with_technical(mut self, details: impl Into<String>) -> Self {
        self.technical_details = details.into();
        self
    }

    pub fn with_reasons(mut self, reasons: Vec<String>) -> Self {
        self.reasons = reasons;
        self
    }

    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendation = recommendation.into();
        self
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_risk_score(mut self, score: u8) -> Self {
        self.risk_score = score.min(100);
        self
    }
}
