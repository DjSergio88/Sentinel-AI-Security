//! Windows Defender / Firewall posture via registry (least privilege).
//!
//! Read-only. Never disables, stops, or reconfigures Defender or Firewall.

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

/// Snapshot used by the engine for truthful component status (Windows).
#[cfg(windows)]
pub fn read_av_firewall_snapshot() -> (AvFirewallSnapshot, Vec<String>) {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut warnings = Vec::new();
    let mut snapshot = AvFirewallSnapshot {
        defender_service_running: None,
        defender_realtime_approx: None,
        firewall_domain_enabled: None,
        firewall_private_enabled: None,
        firewall_public_enabled: None,
        detail: String::new(),
        source: "windows_registry+sc_query".into(),
    };

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection") {
        Ok(key) => {
            // Missing value typically means real-time monitoring is NOT disabled.
            let disabled: u32 = key.get_value("DisableRealtimeMonitoring").unwrap_or(0);
            snapshot.defender_realtime_approx = Some(disabled == 0);
        }
        Err(err) => {
            warnings.push(format!(
                "Could not read Defender real-time protection registry key: {err}"
            ));
        }
    }

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
                warnings.push(format!("Could not read firewall profile {profile}: {err}"));
            }
        }
    }

    snapshot.defender_service_running = query_service_running("WinDefend");
    if snapshot.defender_service_running.is_none() {
        warnings.push(
            "Could not determine WinDefend service state (sc query unavailable or unexpected output)."
                .into(),
        );
    }

    snapshot.detail = format!(
        "defender_realtime={:?} firewall_domain={:?} firewall_private={:?} firewall_public={:?} windefend_running={:?}",
        snapshot.defender_realtime_approx,
        snapshot.firewall_domain_enabled,
        snapshot.firewall_private_enabled,
        snapshot.firewall_public_enabled,
        snapshot.defender_service_running
    );

    (snapshot, warnings)
}

#[cfg(windows)]
fn collect_security_config_windows() -> CollectorOutput {
    let mut out = CollectorOutput::new("security_config");
    let (snapshot, warnings) = read_av_firewall_snapshot();
    out.warnings.extend(warnings);

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
            .with_reasons(vec![format!(
                "+ domain={:?} private={:?} public={:?}",
                snapshot.firewall_domain_enabled,
                snapshot.firewall_private_enabled,
                snapshot.firewall_public_enabled
            )])
            .with_recommendation(
                "Turn on Windows Firewall for Domain, Private, and Public profiles.",
            )
            .with_risk_score(65)
            .with_technical(snapshot.detail.clone()),
        );
    }

    // Honesty gate: never claim OS protections "look enabled" unless positively confirmed.
    let core_confirmed_on = snapshot.defender_realtime_approx == Some(true)
        && snapshot.defender_service_running == Some(true)
        && snapshot.firewall_domain_enabled == Some(true)
        && snapshot.firewall_private_enabled == Some(true)
        && snapshot.firewall_public_enabled == Some(true);

    let core_incomplete = snapshot.defender_realtime_approx.is_none()
        || snapshot.defender_service_running.is_none()
        || snapshot.firewall_domain_enabled.is_none()
        || snapshot.firewall_private_enabled.is_none()
        || snapshot.firewall_public_enabled.is_none();

    if core_incomplete {
        out.findings.push(
            Finding::new(
                FindingCategory::Configuration,
                Severity::Low,
                Confidence::Unknown,
                "Windows security status could not be fully verified",
                "SentinelAI could not read every Defender/Firewall signal. The device is not marked Protected based on incomplete data.",
            )
            .with_reasons(vec![
                "+ One or more Defender/Firewall checks returned unknown".into(),
                format!("+ {}", snapshot.detail),
            ])
            .with_recommendation(
                "Re-run the scan. If this persists, check permissions or open Windows Security manually.",
            )
            .with_risk_score(35)
            .with_technical(snapshot.detail.clone()),
        );
    } else if core_confirmed_on && out.findings.is_empty() {
        out.findings.push(
            Finding::new(
                FindingCategory::Configuration,
                Severity::Info,
                Confidence::LowRisk,
                "Windows Defender and Firewall signals look enabled (local check)",
                "Local checks indicate real-time protection and firewall profiles are on. This is not a full antivirus scan and does not prove the device is malware-free.",
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

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_path_is_warning_only() {
        // Compiles on all targets; on Windows the real collector runs elsewhere.
        #[cfg(not(windows))]
        {
            let out = super::collect_security_config();
            assert!(out.warnings.iter().any(|w| w.contains("Windows-only")));
            assert!(out.findings.is_empty());
        }
        #[cfg(windows)]
        {
            let out = super::collect_security_config();
            assert_eq!(out.name, "security_config");
            // Must not panic; may produce findings or warnings depending on host.
            let _ = (out.findings.len(), out.warnings.len());
        }
    }

    #[cfg(windows)]
    #[test]
    fn snapshot_read_is_best_effort_not_placeholder() {
        let (snap, _warnings) = super::read_av_firewall_snapshot();
        assert_eq!(snap.source, "windows_registry+sc_query");
        // At least one signal should usually resolve on a real Windows host.
        let any = snap.defender_realtime_approx.is_some()
            || snap.defender_service_running.is_some()
            || snap.firewall_private_enabled.is_some();
        assert!(
            any,
            "expected at least one real Defender/Firewall signal on Windows"
        );
    }
}
