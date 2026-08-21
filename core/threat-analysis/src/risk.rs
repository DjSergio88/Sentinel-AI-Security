//! Risk scorer with explainable verdicts.

use crate::signals::Signal;
use sentinel_common::Confidence;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Trusted,
    LowRisk,
    Unknown,
    PotentiallyUnwanted,
    Suspicious,
    HighRisk,
    /// Reserved for verified TI hits only — never assigned by local heuristics alone.
    KnownMalicious,
}

impl Verdict {
    pub fn user_label(self) -> &'static str {
        match self {
            Self::Trusted => "Trusted",
            Self::LowRisk => "Low risk",
            Self::Unknown => "Unknown",
            Self::PotentiallyUnwanted => "Potentially unwanted",
            Self::Suspicious => "Suspicious",
            Self::HighRisk => "High risk",
            Self::KnownMalicious => "Known malicious",
        }
    }

    pub fn to_confidence(self) -> Confidence {
        match self {
            Self::Trusted => Confidence::Trusted,
            Self::LowRisk => Confidence::LowRisk,
            Self::Unknown => Confidence::Unknown,
            Self::PotentiallyUnwanted => Confidence::PotentiallyUnwanted,
            Self::Suspicious => Confidence::Suspicious,
            Self::HighRisk => Confidence::HighRisk,
            Self::KnownMalicious => Confidence::KnownMalicious,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// 0–100 risk score (higher = more concerning).
    pub risk_score: u8,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub recommendation: String,
    /// True only when an external/local verified malware indicator was used.
    pub malware_verified: bool,
}

#[derive(Debug, Default, Clone)]
pub struct RiskScorer {
    /// When false (default), KnownMalicious is never emitted.
    pub allow_verified_malware_label: bool,
}

impl RiskScorer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn assess(&self, signals: &[Signal]) -> RiskAssessment {
        let mut score: i32 = 20; // baseline "unknown"
        let mut reasons = Vec::new();
        for signal in signals {
            score += signal.weight;
            if !signal.reason.is_empty() {
                let prefix = if signal.weight >= 0 { "+" } else { "−" };
                reasons.push(format!("{prefix} {}", signal.reason));
            }
        }

        // Local heuristics cannot assert KnownMalicious.

        let risk_score = score.clamp(0, 100) as u8;
        let verdict = self.verdict_from_score(risk_score, false);
        let recommendation = recommendation_for(verdict);

        RiskAssessment {
            risk_score,
            verdict,
            reasons,
            recommendation,
            malware_verified: false,
        }
    }

    fn verdict_from_score(&self, score: u8, verified_malicious: bool) -> Verdict {
        if verified_malicious && self.allow_verified_malware_label {
            return Verdict::KnownMalicious;
        }
        match score {
            0..=15 => Verdict::Trusted,
            16..=35 => Verdict::LowRisk,
            36..=50 => Verdict::Unknown,
            51..=65 => Verdict::PotentiallyUnwanted,
            66..=80 => Verdict::Suspicious,
            _ => Verdict::HighRisk,
        }
    }
}

fn recommendation_for(verdict: Verdict) -> String {
    match verdict {
        Verdict::Trusted | Verdict::LowRisk => {
            "No action required. Keep monitoring with regular scans.".into()
        }
        Verdict::Unknown => {
            "Review this item. If you did not install it, investigate before trusting it.".into()
        }
        Verdict::PotentiallyUnwanted => {
            "Consider uninstalling if you do not recognize or need this software.".into()
        }
        Verdict::Suspicious => {
            "Quarantine is recommended after you confirm this is unexpected. Investigate before entering passwords or sensitive data.".into()
        }
        Verdict::HighRisk => {
            "Do not open related files. Disconnect from sensitive accounts if unsure, then investigate and remove if untrusted.".into()
        }
        Verdict::KnownMalicious => {
            "Verified malicious indicator. Isolate the file and remediate with your antivirus.".into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::{Signal, SignalKind};

    #[test]
    fn baseline_unknown_without_signals() {
        let assessment = RiskScorer::new().assess(&[]);
        assert_eq!(assessment.verdict, Verdict::LowRisk);
        assert!(!assessment.malware_verified);
    }

    #[test]
    fn temp_plus_unknown_publisher_raises_risk() {
        let signals = vec![
            Signal::new(SignalKind::UnknownPublisher, 25, "Unknown publisher"),
            Signal::new(
                SignalKind::TempDirectoryExecution,
                30,
                "Executed from temporary directory",
            ),
            Signal::new(SignalKind::RecentlyDownloaded, 15, "Recently downloaded"),
        ];
        let assessment = RiskScorer::new().assess(&signals);
        assert!(assessment.risk_score >= 66);
        assert!(matches!(
            assessment.verdict,
            Verdict::Suspicious | Verdict::HighRisk
        ));
        assert!(assessment
            .reasons
            .iter()
            .any(|r| r.contains("Unknown publisher")));
        assert!(!assessment.malware_verified);
    }

    #[test]
    fn local_heuristics_never_emit_known_malicious() {
        let signals = vec![Signal::new(
            SignalKind::SuspiciousPersistence,
            90,
            "Suspicious persistence indicator",
        )];
        let assessment = RiskScorer::new().assess(&signals);
        assert_ne!(assessment.verdict, Verdict::KnownMalicious);
    }

    #[test]
    fn trusted_signals_lower_score() {
        let signals = vec![
            Signal::new(
                SignalKind::SystemProtectedPath,
                -25,
                "Located in a system-protected path",
            ),
            Signal::new(
                SignalKind::SignedByKnownPublisher,
                -20,
                "Signed by a known publisher",
            ),
        ];
        let assessment = RiskScorer::new().assess(&signals);
        assert!(assessment.risk_score <= 15);
        assert_eq!(assessment.verdict, Verdict::Trusted);
    }
}
