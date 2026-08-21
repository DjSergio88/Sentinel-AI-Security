//! Browser extension inventory (Chrome/Edge extension folders — local metadata only).

use crate::collectors::CollectorOutput;
use sentinel_common::{Confidence, Finding, FindingCategory, Severity};
use std::fs;
use std::path::PathBuf;

pub fn collect_browser_extensions() -> CollectorOutput {
    let mut out = CollectorOutput::new("browser_extensions");
    let mut count = 0usize;

    for (browser, base) in browser_extension_roots() {
        if !base.is_dir() {
            continue;
        }
        if let Ok(profiles) = fs::read_dir(&base) {
            for profile in profiles.flatten() {
                let ext_dir = profile.path().join("Extensions");
                if !ext_dir.is_dir() {
                    continue;
                }
                if let Ok(exts) = fs::read_dir(&ext_dir) {
                    for ext in exts.flatten() {
                        if !ext.path().is_dir() {
                            continue;
                        }
                        count += 1;
                        let id = ext.file_name().to_string_lossy().to_string();
                        // Flag only extremely short / suspicious-looking IDs is too noisy;
                        // Milestone 1 records inventory size and notes local-only analysis.
                        let _ = (browser, &id);
                    }
                }
            }
        }
    }

    if count == 0 {
        out.warnings.push(
            "No Chromium-based browser extensions discovered (or browsers not installed).".into(),
        );
    } else {
        out.findings.push(
            Finding::new(
                FindingCategory::Browser,
                Severity::Info,
                Confidence::Unknown,
                format!("Browser extensions inventoried: {count}"),
                "SentinelAI listed installed Chromium-based extensions. Extension risk scoring requires additional rules and is not claiming malware here.",
            )
            .with_recommendation(
                "Remove browser extensions you do not recognize or no longer use.",
            )
            .with_risk_score(15)
            .with_technical(format!(
                "extension_dirs_counted={count}; analysis_mode=local_only"
            )),
        );
    }

    out
}

fn browser_extension_roots() -> Vec<(&'static str, PathBuf)> {
    let mut roots = Vec::new();
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    if let Some(local) = local {
        roots.push((
            "Chrome",
            local.join("Google").join("Chrome").join("User Data"),
        ));
        roots.push((
            "Edge",
            local.join("Microsoft").join("Edge").join("User Data"),
        ));
        roots.push((
            "Brave",
            local
                .join("BraveSoftware")
                .join("Brave-Browser")
                .join("User Data"),
        ));
    }
    roots
}
