//! Windows Defender / Firewall posture via registry (least privilege).

use crate::collectors::CollectorOutput;
use crate::inventory::AvFirewallSnapshot;
use sentinel_common::{Confidence, Finding, FindingCategory, Severity};

pub fn collect_security_config() -> CollectorOutput {
    #[cfg(windows)]
    {
        collect_security_config_windows()
    }
    #[cfg(not(windows))]
    {
        let mut out = CollectorOutput::new("security_config");
        out.warnings
            .push("Security configuration checks are Windows-only in Milestone 1.".into());
        out
    }
}

#[cfg(windows)]
fn collect_security_config_windows() -> CollectorOutput {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut out = CollectorOutput::new("security_config");
    let mut snapshot = AvFirewallSnapshot {
        defender_service_running: None,
        defender_realtime_approx: None,
        firewall_domain_enabled: None,
        firewall_private_enabled: None,
        firewall_public_enabled: None,
        detail: String::new(),
        source: "windows_registry".into(),
    };

    // Defender disable flags (approximate). Prefer Security Center APIs in a later milestone.
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection") {
        Ok(key) => {
            let disabled: u32 = key.get_value("DisableRealtimeMonitoring").unwrap_or(0);
            snapshot.defender_realtime_approx = Some(disabled == 0);
        }
        Err(err) => {
            out.warnings.push(format!(
                "Could not read Defender real-time protection registry key: {err}"
            ));
        }
    }

    // Firewall profiles
    for (profile, field) in [
        (
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            &mut snapshot.firewall_domain_enabled,
        ),
        (
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            &mut snapshot.firewall_private_enabled,
        ),
        (
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            &mut snapshot.firewall_public_enabled,
        ),
    ] {
        match hklm.open_subkey(profile) {
            Ok(key) => {
                let enabled: u32 = key.get_value("EnableFirewall").unwrap_or(1);
                *field = Some(enabled != 0);
            }
            Err(err) => {
                out.warnings
                    .push(format!("Could not read firewall profile {profile}: {err}"));
            }
        }
    }

    // Service state for WinDefend — query via service manager would be better;
    // for Milestone 1 we use sc query via optional registry + note limitations.
    snapshot.defender_service_running = query_service_running("WinDefend");

    snapshot.detail = format!(
        "defender_realtime={:?} firewall_domain={:?} firewall_private={:?} firewall_public={:?} windefend_running={:?}",
        snapshot.defender_realtime_approx,
        snapshot.firewall_domain_enabled,
        snapshot.firewall_private_enabled,
        snapshot.firewall_public_enabled,
        snapshot.defender_service_running
    );

    if snapshot.defender_realtime_approx == Some(false) {
        out.findings.push(
            Finding::new(
                FindingCategory::Defender,
                Severity::High,
                Confidence::HighRisk,
                "Windows security real-time protection appears off",
                "Built-in Windows malware protection may be disabled. This reduces protection against malicious downloads and ransomware.",
            )
            .with_reasons(vec![
                "+ Defender real-time monitoring registry flag indicates disabled".into(),
            ])
            .with_recommendation(
                "Open Windows Security and turn on Real-time protection if it is off.",
            )
            .with_risk_score(78)
            .with_technical(snapshot.detail.clone()),
        );
    }

    if snapshot.defender_service_running == Some(false) {
        out.findings.push(
            Finding::new(
                FindingCategory::Defender,
                Severity::High,
                Confidence::HighRisk,
                "Windows Defender service does not appear to be running",
                "The core Windows antivirus service looks stopped. Your device may not be actively protected.",
            )
            .with_recommendation("Start the WinDefend service from Windows Security or Services.")
            .with_risk_score(82)
            .with_technical("service=WinDefend state=not_running (best-effort query)"),
        );
    }

    let any_fw_off = matches!(snapshot.firewall_domain_enabled, Some(false))
        || matches!(snapshot.firewall_private_enabled, Some(false))
        || matches!(snapshot.firewall_public_enabled, Some(false));

    if any_fw_off {
        out.findings.push(
            Finding::new(
                FindingCategory::Firewall,
                Severity::Medium,
                Confidence::Suspicious,
                "Windows Firewall may be disabled on a network profile",
                "At least one Windows Firewall profile looks turned off. Untrusted networks can reach your device more easily.",
            )
            .with_reasons(vec![
                format!(
                    "+ domain={:?} private={:?} public={:?}",
                    snapshot.firewall_domain_enabled,
                    snapshot.firewall_private_enabled,
                    snapshot.firewall_public_enabled
                ),
            ])
            .with_recommendation(
                "Turn on Windows Firewall for Domain, Private, and Public profiles.",
            )
            .with_risk_score(65)
            .with_technical(snapshot.detail.clone()),
        );
    }

    // Always add an informational posture note so UI can show truthful status.
    if out.findings.is_empty() {
        out.findings.push(
            Finding::new(
                FindingCategory::Configuration,
                Severity::Info,
                Confidence::LowRisk,
                "Windows security basics look enabled (local check)",
                "Local registry checks suggest Defender real-time protection and firewall profiles are on. This is not a full antivirus scan.",
            )
            .with_recommendation("Keep Windows Security up to date and run occasional full scans.")
            .with_risk_score(10)
            .with_technical(snapshot.detail),
        );
    }

    out
}

#[cfg(windows)]
fn query_service_running(name: &str) -> Option<bool> {
    // Best-effort: parse `sc query` without requiring admin for query.
    let output = std::process::Command::new("sc")
        .args(["query", name])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).to_ascii_uppercase();
    if text.contains("RUNNING") {
        Some(true)
    } else if text.contains("STOPPED") || text.contains("STOP_PENDING") {
        Some(false)
    } else {
        None
    }
}
