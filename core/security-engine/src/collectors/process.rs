//! Running process inventory and heuristic checks.

use crate::collectors::CollectorOutput;
use crate::inventory::ProcessInfo;
use sentinel_common::{Confidence, Finding, FindingCategory, Severity};
use sentinel_threat_analysis::{RiskScorer, Signal, SignalKind};
use std::path::Path;
use sysinfo::System;

const SUSPICIOUS_TEMP_MARKERS: &[&str] = &[
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "/temp/",
    "/tmp/",
];

pub fn collect_processes(deep: bool) -> CollectorOutput {
    let mut out = CollectorOutput::new("process_inventory");
    let mut system = System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let scorer = RiskScorer::new();
    let mut reviewed = 0usize;

    for (pid, proc_) in system.processes() {
        reviewed += 1;
        let name = proc_.name().to_string_lossy().to_string();
        let exe = proc_.exe().map(|p| p.to_string_lossy().to_string());
        let cmd = {
            let args: Vec<String> = proc_
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            if args.is_empty() {
                None
            } else {
                Some(args.join(" "))
            }
        };

        let info = ProcessInfo {
            pid: pid.as_u32(),
            name: name.clone(),
            exe_path: exe.clone(),
            cmd: cmd.clone(),
            parent_pid: proc_.parent().map(|p| p.as_u32()),
            user: proc_.user_id().map(|u| u.to_string()),
        };

        if let Some(finding) = evaluate_process(&info, &scorer, deep) {
            out.findings.push(finding);
        }
    }

    if reviewed == 0 {
        out.warnings
            .push("Process inventory returned zero processes; permissions may be limited.".into());
    }

    out
}

fn evaluate_process(info: &ProcessInfo, scorer: &RiskScorer, deep: bool) -> Option<Finding> {
    let mut signals = Vec::new();
    let path_lower = info.exe_path.as_deref().unwrap_or("").to_ascii_lowercase();

    if path_lower.is_empty() {
        return None;
    }

    if SUSPICIOUS_TEMP_MARKERS
        .iter()
        .any(|m| path_lower.contains(m))
    {
        signals.push(Signal::new(
            SignalKind::TempDirectoryExecution,
            30,
            "Executed from a temporary directory",
        ));
    }

    if path_looks_user_download(&path_lower) {
        signals.push(Signal::new(
            SignalKind::RecentlyDownloaded,
            12,
            "Executable path suggests a downloads folder",
        ));
    }

    if path_looks_suspicious_location(&path_lower) {
        signals.push(Signal::new(
            SignalKind::SuspiciousLocation,
            20,
            "Running from an unusual location",
        ));
    }

    if is_system_protected_path(&path_lower) {
        signals.push(Signal::new(
            SignalKind::SystemProtectedPath,
            -25,
            "Located in a system-protected path",
        ));
    }

    if deep {
        if let Some(cmd) = &info.cmd {
            let cmd_l = cmd.to_ascii_lowercase();
            if cmd_l.contains("powershell")
                && (cmd_l.contains("-enc")
                    || cmd_l.contains("-e ")
                    || cmd_l.contains("frombase64")
                    || cmd_l.contains("downloadstring")
                    || cmd_l.contains("iex "))
            {
                signals.push(Signal::new(
                    SignalKind::SuspiciousCommandLine,
                    28,
                    "PowerShell command line contains suspicious encoded/download patterns",
                ));
            }
        }
    }

    // Only emit findings when there is at least one elevating signal.
    let elevating = signals.iter().any(|s| s.weight > 0);
    if !elevating {
        return None;
    }

    let assessment = scorer.assess(&signals);
    let severity = match assessment.verdict {
        sentinel_threat_analysis::Verdict::HighRisk => Severity::High,
        sentinel_threat_analysis::Verdict::Suspicious => Severity::Medium,
        sentinel_threat_analysis::Verdict::PotentiallyUnwanted => Severity::Low,
        _ => Severity::Info,
    };

    // Never claim malware from local heuristics.
    let confidence = assessment.verdict.to_confidence();
    if matches!(confidence, Confidence::KnownMalicious) {
        return None;
    }

    Some(
        Finding::new(
            FindingCategory::Process,
            severity,
            confidence,
            format!("Unusual application activity: {}", info.name),
            "SentinelAI found an application behaving unusually based on where and how it is running.",
        )
        .with_subject(info.exe_path.clone().unwrap_or_else(|| info.name.clone()))
        .with_reasons(assessment.reasons)
        .with_risk_score(assessment.risk_score)
        .with_recommendation(assessment.recommendation)
        .with_technical(format!(
            "pid={} name={} path={} parent={:?} verdict={}",
            info.pid,
            info.name,
            info.exe_path.as_deref().unwrap_or("(unknown)"),
            info.parent_pid,
            assessment.verdict.user_label()
        )),
    )
}

fn path_looks_user_download(path: &str) -> bool {
    path.contains("\\downloads\\") || path.contains("/downloads/")
}

fn path_looks_suspicious_location(path: &str) -> bool {
    let markers = [
        "\\appdata\\roaming\\",
        "\\appdata\\local\\",
        "\\public\\",
        "\\programdata\\",
    ];
    // AppData alone is common; only flag if also looks like a random single-folder drop.
    if !markers.iter().any(|m| path.contains(m)) {
        return false;
    }
    let p = Path::new(path);
    let parent = p.parent().map(|x| x.to_string_lossy().to_ascii_lowercase());
    match parent {
        Some(ref parent) if parent.ends_with("\\temp") || parent.contains("\\temp\\") => true,
        Some(ref parent) if parent.contains("\\downloads") => true,
        // Flag executables sitting directly under Roaming without a vendor folder depth heuristic:
        Some(ref parent)
            if parent.contains("\\appdata\\roaming")
                && parent.matches('\\').count() <= 5
                && !parent.contains("\\microsoft\\")
                && !parent.contains("\\sentinel") =>
        {
            true
        }
        _ => false,
    }
}

fn is_system_protected_path(path: &str) -> bool {
    path.contains("\\windows\\system32\\")
        || path.contains("\\windows\\syswow64\\")
        || path.contains("\\program files\\")
        || path.contains("\\program files (x86)\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_path_is_flagged() {
        let info = ProcessInfo {
            pid: 1,
            name: "weird.exe".into(),
            exe_path: Some(r"C:\Users\user\AppData\Local\Temp\weird.exe".into()),
            cmd: None,
            parent_pid: None,
            user: None,
        };
        let finding = evaluate_process(&info, &RiskScorer::new(), false);
        assert!(finding.is_some());
    }

    #[test]
    fn system32_alone_not_flagged() {
        let info = ProcessInfo {
            pid: 4,
            name: "svchost.exe".into(),
            exe_path: Some(r"C:\Windows\System32\svchost.exe".into()),
            cmd: None,
            parent_pid: None,
            user: None,
        };
        let finding = evaluate_process(&info, &RiskScorer::new(), false);
        assert!(finding.is_none());
    }
}
