//! Integration-style tests that prove Milestone 1 collectors are functional.

use sentinel_common::{AnalysisMode, ProtectionStatus, ScanKind};
use sentinel_security_engine::collectors::{downloads, process, security_config, startup};
use sentinel_security_engine::{ScanEngine, ScanOptions};
use sentinel_threat_analysis::{RiskScorer, Signal, SignalKind};

#[test]
fn end_to_end_quick_scan_is_local_only() {
    let report = ScanEngine::new().run(ScanOptions {
        kind: ScanKind::Quick,
        hash_downloads: false,
    });
    assert_eq!(report.analysis_mode, AnalysisMode::LocalOnly);
    assert!(report
        .collectors_run
        .iter()
        .any(|c| c == "process_inventory"));
    assert!(report.collectors_run.iter().any(|c| c == "security_config"));
    assert!(!report
        .notes
        .iter()
        .any(|n| n.to_ascii_lowercase().contains("vpn connected")));
}

#[test]
fn smart_scan_enables_download_hashing_path() {
    let report = ScanEngine::new().run(ScanOptions {
        kind: ScanKind::Smart,
        hash_downloads: true,
    });
    assert!(report
        .collectors_run
        .iter()
        .any(|c| c == "downloads_inventory"));
    // JSON round-trip for agent --json / --output workflow
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("findings"));
}

#[test]
fn risk_scoring_is_explainable_and_non_malware_by_default() {
    let assessment = RiskScorer::new().assess(&[
        Signal::new(SignalKind::UnknownPublisher, 25, "Unknown publisher"),
        Signal::new(
            SignalKind::TempDirectoryExecution,
            30,
            "Executed from temporary directory",
        ),
    ]);
    assert!(!assessment.reasons.is_empty());
    assert!(!assessment.malware_verified);
    assert_ne!(
        assessment.verdict,
        sentinel_threat_analysis::Verdict::KnownMalicious
    );
}

#[test]
fn collectors_do_not_panic_on_permission_limited_paths() {
    // Missing downloads dir warning path
    let missing = std::path::PathBuf::from("Z:\\sentinel-missing-folder-xyz");
    let (inv, warnings) = downloads::inventory_directory(&missing, true, 5, 14);
    assert!(inv.is_empty());
    assert!(!warnings.is_empty());

    // Process enumeration should still return *something* for the current user session.
    let procs = process::enumerate_processes();
    assert!(!procs.is_empty());
}

#[cfg(windows)]
#[test]
fn windows_defenders_firewall_and_startup_are_real_reads() {
    let (snap, _) = security_config::read_av_firewall_snapshot();
    assert!(
        snap.defender_realtime_approx.is_some()
            || snap.defender_service_running.is_some()
            || snap.firewall_private_enabled.is_some(),
        "expected real Windows security signals"
    );

    let (items, warnings) = startup::list_startup_items();
    assert!(
        !items.is_empty() || !warnings.is_empty(),
        "startup collector must read registry or report access issues"
    );
}

#[cfg(windows)]
#[test]
fn protected_status_requires_complete_assessment() {
    let report = ScanEngine::new().run(ScanOptions::default());
    if report
        .findings
        .iter()
        .any(|f| f.title.contains("could not be fully verified"))
    {
        assert_ne!(report.posture.score.status, ProtectionStatus::Protected);
    }
    let fw = report.posture.firewall.expect("firewall component");
    // Never invent a "connected/enabled" claim when the signal is unknown.
    if fw.enabled.is_none() {
        assert_ne!(fw.healthy, Some(true));
    }
}
