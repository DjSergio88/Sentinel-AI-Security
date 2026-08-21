//! Confidence / verdict vocabulary used across scanners and UI.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Explainable confidence labels. Unknown is the default for unverified items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Confirmed against a verified local or configured TI source.
    KnownMalicious,
    HighRisk,
    Suspicious,
    PotentiallyUnwanted,
    Unknown,
    LowRisk,
    Trusted,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KnownMalicious => "known_malicious",
            Self::HighRisk => "high_risk",
            Self::Suspicious => "suspicious",
            Self::PotentiallyUnwanted => "potentially_unwanted",
            Self::Unknown => "unknown",
            Self::LowRisk => "low_risk",
            Self::Trusted => "trusted",
        }
    }

    /// Plain-language label for ordinary users.
    pub fn user_label(self) -> &'static str {
        match self {
            Self::KnownMalicious => "Known malicious",
            Self::HighRisk => "High risk",
            Self::Suspicious => "Suspicious",
            Self::PotentiallyUnwanted => "Potentially unwanted",
            Self::Unknown => "Unknown",
            Self::LowRisk => "Low risk",
            Self::Trusted => "Trusted",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.user_label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_default_vocabulary() {
        assert_eq!(Confidence::Unknown.as_str(), "unknown");
        assert_eq!(Confidence::Unknown.user_label(), "Unknown");
    }
}
