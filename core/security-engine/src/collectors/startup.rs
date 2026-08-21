//! Startup application inventory (Windows Run keys + Startup folder).

use crate::collectors::CollectorOutput;
use crate::inventory::StartupItem;
use sentinel_common::{Finding, FindingCategory, Severity};
use sentinel_threat_analysis::{RiskScorer, Signal, SignalKind};

pub fn collect_startup() -> CollectorOutput {
    #[cfg(windows)]
    {
        collect_startup_windows()
    }
    #[cfg(not(windows))]
    {
        let mut out = CollectorOutput::new("startup_inventory");
        out.warnings
            .push("Startup inventory is only implemented for Windows in Milestone 1.".into());
        out
    }
}

#[cfg(windows)]
fn collect_startup_windows() -> CollectorOutput {
    let mut out = CollectorOutput::new("startup_inventory");
    let (items, warnings) = list_startup_items();
    out.warnings.extend(warnings);

    let scorer = RiskScorer::new();
    for item in &items {
        if let Some(finding) = evaluate_startup(item, &scorer) {
            out.findings.push(finding);
        }
    }

    if items.is_empty() {
        out.warnings
            .push("No startup entries discovered (or access was limited).".into());
    }

    out
}

/// List startup entries from Run keys and the user Startup folder (real registry/FS reads).
#[cfg(windows)]
pub fn list_startup_items() -> (Vec<StartupItem>, Vec<String>) {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut items = Vec::new();
    let mut warnings = Vec::new();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let paths = [
        (
            &hklm,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM Run",
        ),
        (
            &hklm,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM RunOnce",
        ),
        (
            &hkcu,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU Run",
        ),
        (
            &hkcu,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU RunOnce",
        ),
        (
            &hklm,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM WOW64 Run",
        ),
    ];

    for (root, subkey, label) in paths {
        match root.open_subkey(subkey) {
            Ok(key) => {
                for (name, value) in key.enum_values().filter_map(|v| v.ok()) {
                    items.push(StartupItem {
                        name,
                        command: value.to_string(),
                        location: label.to_string(),
                        enabled: true,
                    });
                }
            }
            Err(err) => {
                warnings.push(format!("Could not read {label}: {err}"));
            }
        }
    }

    if let Some(startup_dir) = user_startup_dir() {
        if let Ok(entries) = std::fs::read_dir(&startup_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    items.push(StartupItem {
                        name: path
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| "unknown".into()),
                        command: path.to_string_lossy().to_string(),
                        location: "Startup folder".into(),
                        enabled: true,
                    });
                }
            }
        }
    }

    (items, warnings)
}

#[cfg(windows)]
fn user_startup_dir() -> Option<std::path::PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    Some(
        std::path::PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup"),
    )
}

fn evaluate_startup(item: &StartupItem, scorer: &RiskScorer) -> Option<Finding> {
    let mut signals = Vec::new();
    let cmd_lower = item.command.to_ascii_lowercase();

    if cmd_lower.contains("\\temp\\") || cmd_lower.contains("\\tmp\\") {
        signals.push(Signal::new(
            SignalKind::SuspiciousPersistence,
            35,
            "Startup entry points at a temporary directory",
        ));
    }

    if cmd_lower.contains("powershell")
        && (cmd_lower.contains("-enc")
            || cmd_lower.contains("frombase64")
            || cmd_lower.contains("downloadstring")
            || cmd_lower.contains("iex"))
    {
        signals.push(Signal::new(
            SignalKind::SuspiciousCommandLine,
            30,
            "Startup entry uses suspicious PowerShell patterns",
        ));
    }

    if cmd_lower.contains("\\appdata\\roaming\\")
        && !cmd_lower.contains("\\microsoft\\")
        && (cmd_lower.ends_with(".exe") || cmd_lower.contains(".exe "))
        && (cmd_lower.contains("\\temp\\")
            || cmd_lower.contains("\\tmp\\")
            || looks_like_random_drop(&cmd_lower))
    {
        signals.push(Signal::new(
            SignalKind::SuspiciousPersistence,
            18,
            "Startup entry launches an executable from an unusual AppData location",
        ));
    }

    if signals.is_empty() {
        return None;
    }

    let assessment = scorer.assess(&signals);
    let severity = match assessment.verdict {
        sentinel_threat_analysis::Verdict::HighRisk => Severity::High,
        sentinel_threat_analysis::Verdict::Suspicious => Severity::Medium,
        _ => Severity::Low,
    };

    Some(
        Finding::new(
            FindingCategory::Startup,
            severity,
            assessment.verdict.to_confidence(),
            format!("Review startup item: {}", item.name),
            "A program is configured to start automatically and looks unusual.",
        )
        .with_subject(item.command.clone())
        .with_reasons(assessment.reasons)
        .with_risk_score(assessment.risk_score)
        .with_recommendation(assessment.recommendation)
        .with_technical(format!(
            "name={} location={} command={}",
            item.name, item.location, item.command
        )),
    )
}

/// Heuristic: Roaming drop without a recognizable vendor folder depth.
fn looks_like_random_drop(cmd_lower: &str) -> bool {
    if let Some(idx) = cmd_lower.find("\\appdata\\roaming\\") {
        let rest = &cmd_lower[idx + "\\appdata\\roaming\\".len()..];
        let slash_count = rest.matches('\\').count();
        return slash_count == 0;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_startup_flagged() {
        let item = StartupItem {
            name: "odd".into(),
            command: r"C:\Users\a\AppData\Local\Temp\odd.exe".into(),
            location: "HKCU Run".into(),
            enabled: true,
        };
        assert!(evaluate_startup(&item, &RiskScorer::new()).is_some());
    }

    #[test]
    fn normal_startup_not_flagged() {
        let item = StartupItem {
            name: "SecurityHealth".into(),
            command: r"C:\Windows\System32\SecurityHealthSystray.exe".into(),
            location: "HKLM Run".into(),
            enabled: true,
        };
        assert!(evaluate_startup(&item, &RiskScorer::new()).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn list_startup_items_reads_real_registry() {
        let (items, warnings) = list_startup_items();
        let _ = warnings.len();
        assert!(
            !items.is_empty() || warnings.iter().any(|w| w.contains("Could not read")),
            "expected startup inventory or permission warnings"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_startup_is_warning_only() {
        let out = collect_startup();
        assert!(out.warnings.iter().any(|w| w.contains("Windows")));
    }
}
