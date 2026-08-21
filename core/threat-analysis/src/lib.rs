//! Explainable threat analysis and risk scoring.
//!
//! SentinelAI never labels unknown software as malware by default.
//! Scores are built from additive signals with human-readable reasons.

pub mod risk;
pub mod signals;

pub use risk::{RiskAssessment, RiskScorer, Verdict};
pub use signals::{Signal, SignalKind};
