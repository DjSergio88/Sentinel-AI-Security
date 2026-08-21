//! Scan orchestration for Quick / Smart / Full scans.

use crate::collectors::{
    browser, downloads, network, process, security_config, startup, suspicious_paths,
};
use chrono::Utc;
use sentinel_common::posture::{AnalysisMode, ComponentStatus, SecurityPosture, SecurityScore};
use sentinel_common::{Finding, ScanKind, ScanReport, ScanStatus, Severity};
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub kind: ScanKind,
    /// Hash recent downloads during Smart/Full.
    pub hash_downloads: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            kind: ScanKind::Quick,
            hash_downloads: false,
        }
    }
}

pub struct ScanEngine;

impl ScanEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn run(&self, options: ScanOptions) -> ScanReport {
        let started = Instant::now();
        let started_at = Utc::now();
        let mut findings: Vec<Finding> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut collectors_run: Vec<String> = Vec::new();
        let mut notes = vec![
            "Analysis mode: Local analysis only.".to_string(),
            "No external threat-intelligence provider is configured.".to_string(),
            "SentinelAI does not claim malware detection without verification.".to_string(),
        ];

        let deep = matches!(options.kind, ScanKind::Smart | ScanKind::Full);
        let hash =
            options.hash_downloads || matches!(options.kind, ScanKind::Smart | ScanKind::Full);

        // Core collectors for all scan kinds
        for output in [
            process::collect_processes(deep),
            startup::collect_startup(),
            security_config::collect_security_config(),
            network::collect_network_indicators(),
            browser::collect_browser_extensions(),
            downloads::collect_downloads(hash),
            suspicious_paths::collect_suspicious_locations(),
        ] {
            collectors_run.push(output.name);
            findings.extend(output.findings);
            warnings.extend(output.warnings);
        }

        // Deduplicate findings by subject (same path reported by multiple collectors).
        findings = dedupe_findings(findings);

        if matches!(options.kind, ScanKind::Full) {
            notes.push(
                "Full Scan in Milestone 1 expands heuristics; exhaustive filesystem AV scanning is not yet implemented."
                    .into(),
            );
            warnings.push(
                "Full disk malware scanning is not available yet — results are heuristic posture checks only."
                    .into(),
            );
        }

        // Drop pure info findings from score calculation noise optionally —
        // SecurityScore already handles Info as 0 penalty.
        let score = SecurityScore::from_findings(
            &findings
                .iter()
                .filter(|f| f.severity != Severity::Info)
                .cloned()
                .collect::<Vec<_>>(),
        );

        let defender = findings
            .iter()
            .find(|f| f.category == sentinel_common::FindingCategory::Defender)
            .map(|f| ComponentStatus {
                name: "Windows Defender".into(),
                enabled: Some(!matches!(f.severity, Severity::High | Severity::Critical)),
                healthy: Some(!matches!(f.severity, Severity::High | Severity::Critical)),
                detail: f.summary.clone(),
            })
            .or_else(|| {
                Some(ComponentStatus {
                    name: "Windows Defender".into(),
                    enabled: None,
                    healthy: None,
                    detail: "Checked via local registry/service query.".into(),
                })
            });

        let firewall = findings
            .iter()
            .find(|f| f.category == sentinel_common::FindingCategory::Firewall)
            .map(|f| ComponentStatus {
                name: "Windows Firewall".into(),
                enabled: Some(false),
                healthy: Some(false),
                detail: f.summary.clone(),
            })
            .or_else(|| {
                Some(ComponentStatus {
                    name: "Windows Firewall".into(),
                    enabled: Some(true),
                    healthy: Some(true),
                    detail: "No disabled firewall profile detected by local checks.".into(),
                })
            });

        let posture = SecurityPosture {
            score,
            windows_defender: defender,
            firewall,
            analysis_mode: AnalysisMode::LocalOnly,
            assessed_at: Utc::now(),
        };

        let finished_at = Utc::now();
        let status = if warnings.is_empty() {
            ScanStatus::Completed
        } else {
            ScanStatus::CompletedWithWarnings
        };

        ScanReport {
            id: Uuid::new_v4(),
            kind: options.kind,
            status,
            started_at,
            finished_at,
            duration_ms: started.elapsed().as_millis() as u64,
            posture,
            findings,
            collectors_run,
            warnings,
            analysis_mode: AnalysisMode::LocalOnly,
            notes,
        }
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn dedupe_findings(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(findings.len());
    for finding in findings {
        let key = format!(
            "{:?}|{}|{}",
            finding.category,
            finding.title,
            finding.subject.as_deref().unwrap_or("")
        );
        if seen.insert(key) {
            out.push(finding);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_scan_produces_report() {
        let report = ScanEngine::new().run(ScanOptions {
            kind: ScanKind::Quick,
            hash_downloads: false,
        });
        assert!(!report.collectors_run.is_empty());
        assert_eq!(report.analysis_mode, AnalysisMode::LocalOnly);
        assert!(report.posture.score.value <= 100);
        assert!(report
            .notes
            .iter()
            .any(|n| n.contains("Local analysis only")));
    }
}
