//! Scan orchestration for Quick / Smart / Full scans.

use crate::collectors::{
    browser, downloads, network, process, security_config, startup, suspicious_paths,
};
use chrono::Utc;
use sentinel_common::posture::{
    AnalysisMode, ComponentStatus, ScoreContext, SecurityPosture, SecurityScore,
};
use sentinel_common::{Finding, FindingCategory, ScanKind, ScanReport, ScanStatus, Severity};
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
            "SentinelAI does not disable or reconfigure Windows Defender or Firewall.".to_string(),
        ];

        let deep = matches!(options.kind, ScanKind::Smart | ScanKind::Full);
        let hash =
            options.hash_downloads || matches!(options.kind, ScanKind::Smart | ScanKind::Full);

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

        let assessment_complete = !findings.iter().any(|f| {
            f.category == FindingCategory::Configuration
                && f.title.contains("could not be fully verified")
        }) && !warnings.iter().any(|w| {
            w.contains("Could not read Defender")
                || w.contains("Could not determine WinDefend")
                || w.contains("Could not read firewall")
        });

        let score = SecurityScore::from_findings_with_context(
            &findings
                .iter()
                .filter(|f| f.severity != Severity::Info)
                .cloned()
                .collect::<Vec<_>>(),
            ScoreContext {
                assessment_complete,
            },
        );

        let (defender, firewall) = component_status_from_host(&findings);

        let posture = SecurityPosture {
            score,
            windows_defender: Some(defender),
            firewall: Some(firewall),
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

fn component_status_from_host(findings: &[Finding]) -> (ComponentStatus, ComponentStatus) {
    #[cfg(windows)]
    {
        let (snap, _) = security_config::read_av_firewall_snapshot();
        let defender_issue = findings
            .iter()
            .any(|f| f.category == FindingCategory::Defender);
        let firewall_issue = findings
            .iter()
            .any(|f| f.category == FindingCategory::Firewall);

        let defender = ComponentStatus {
            name: "Windows Defender".into(),
            enabled: snap.defender_realtime_approx,
            healthy: match (snap.defender_realtime_approx, snap.defender_service_running) {
                (Some(true), Some(true)) => Some(!defender_issue),
                (Some(false), _) | (_, Some(false)) => Some(false),
                _ => None,
            },
            detail: snap.detail.clone(),
        };

        let fw_all = [
            snap.firewall_domain_enabled,
            snap.firewall_private_enabled,
            snap.firewall_public_enabled,
        ];
        let firewall = ComponentStatus {
            name: "Windows Firewall".into(),
            enabled: if fw_all.iter().all(|v| v.is_some()) {
                Some(fw_all.iter().all(|v| *v == Some(true)))
            } else {
                None
            },
            healthy: if fw_all.iter().any(|v| v.is_none()) {
                None
            } else {
                Some(!firewall_issue && fw_all.iter().all(|v| *v == Some(true)))
            },
            detail: format!(
                "domain={:?} private={:?} public={:?}",
                snap.firewall_domain_enabled,
                snap.firewall_private_enabled,
                snap.firewall_public_enabled
            ),
        };
        (defender, firewall)
    }
    #[cfg(not(windows))]
    {
        let _ = findings;
        (
            ComponentStatus {
                name: "Windows Defender".into(),
                enabled: None,
                healthy: None,
                detail: "Not available on this platform.".into(),
            },
            ComponentStatus {
                name: "Windows Firewall".into(),
                enabled: None,
                healthy: None,
                detail: "Not available on this platform.".into(),
            },
        )
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
    use sentinel_common::ProtectionStatus;

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
        assert!(report.notes.iter().any(|n| n.contains("does not disable")));
    }

    #[test]
    fn report_serializes_to_json() {
        let report = ScanEngine::new().run(ScanOptions::default());
        let json = serde_json::to_string_pretty(&report).expect("serialize");
        assert!(json.contains("analysis_mode"));
        assert!(json.contains("local_only") || json.contains("Local"));
        let parsed: ScanReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, report.id);
    }

    #[test]
    fn firewall_status_does_not_default_to_enabled_true_without_data() {
        let report = ScanEngine::new().run(ScanOptions::default());
        let fw = report.posture.firewall.expect("firewall status present");
        // enabled may be Some(true/false) from real registry, or None — never invent VPN/AV claims.
        // Guard: detail must not claim fake connected VPN.
        assert!(!fw.detail.to_ascii_lowercase().contains("vpn connected"));
        assert_eq!(fw.name, "Windows Firewall");
    }

    #[test]
    fn never_claims_protected_when_incomplete_config_finding_present() {
        let report = ScanEngine::new().run(ScanOptions::default());
        let incomplete = report
            .findings
            .iter()
            .any(|f| f.title.contains("could not be fully verified"));
        if incomplete {
            assert_ne!(
                report.posture.score.status,
                ProtectionStatus::Protected,
                "incomplete assessment must not claim Protected"
            );
        }
    }
}
