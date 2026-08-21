//! Suspicious listening ports / network indicators (local only).

use crate::collectors::CollectorOutput;
use sentinel_common::{Confidence, Finding, FindingCategory, Severity};

/// Ports commonly associated with remote access tools / unexpected listeners.
const INTERESTING_PORTS: &[u16] = &[1337, 4444, 5555, 6666, 6667, 31337, 12345, 20000, 33890];

pub fn collect_network_indicators() -> CollectorOutput {
    let mut out = CollectorOutput::new("network_indicators");

    #[cfg(windows)]
    {
        match collect_netstat_style() {
            Ok(findings) => out.findings.extend(findings),
            Err(err) => out
                .warnings
                .push(format!("Network indicator collection limited: {err}")),
        }
    }

    #[cfg(not(windows))]
    {
        out.warnings
            .push("Network indicators are Windows-focused in Milestone 1.".into());
    }

    out
}

#[cfg(windows)]
fn collect_netstat_style() -> Result<Vec<Finding>, String> {
    let output = std::process::Command::new("netstat")
        .args(["-ano"])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("netstat returned a non-zero status".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if !(line.starts_with("TCP") || line.starts_with("UDP")) {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let local = parts[1];
        let state = if parts[0] == "TCP" {
            parts.get(3).copied().unwrap_or("")
        } else {
            ""
        };
        if parts[0] == "TCP" && state != "LISTENING" {
            continue;
        }
        if let Some(port) = parse_port(local) {
            if INTERESTING_PORTS.contains(&port) {
                findings.push(
                    Finding::new(
                        FindingCategory::Network,
                        Severity::Medium,
                        Confidence::Suspicious,
                        format!("Unusual listening port detected: {port}"),
                        "A program is listening on a network port that is uncommon for everyday software.",
                    )
                    .with_subject(local.to_string())
                    .with_reasons(vec![
                        format!("+ Listening on uncommon port {port}"),
                        "+ Local netstat observation only (no external reputation lookup)".into(),
                    ])
                    .with_recommendation(
                        "Identify the process using this port. Close it if you do not recognize it.",
                    )
                    .with_risk_score(60)
                    .with_technical(line.to_string()),
                );
            }
        }
    }

    Ok(findings)
}

fn parse_port(local_addr: &str) -> Option<u16> {
    // Handles 0.0.0.0:4444 and [::]:4444
    if let Some(idx) = local_addr.rfind(':') {
        local_addr[idx + 1..].parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6() {
        assert_eq!(parse_port("0.0.0.0:4444"), Some(4444));
        assert_eq!(parse_port("[::]:3389"), Some(3389));
    }
}
