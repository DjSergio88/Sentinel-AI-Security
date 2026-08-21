//! Heuristic checks for common suspicious filesystem locations.

use crate::collectors::CollectorOutput;
use sentinel_common::{Confidence, Finding, FindingCategory, Severity};
use std::fs;
use std::path::PathBuf;

pub fn collect_suspicious_locations() -> CollectorOutput {
    let mut out = CollectorOutput::new("suspicious_locations");

    let candidates = suspicious_candidate_dirs();
    for dir in candidates {
        if !dir.is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let lower = name.to_ascii_lowercase();
            // TEMP often holds installer/updater EXEs worth reviewing.
            // Skip scripts (.ps1/.bat) here — they are extremely common for automation and too noisy.
            if !(lower.ends_with(".exe")
                || lower.ends_with(".dll")
                || lower.ends_with(".scr")
                || lower.ends_with(".hta"))
            {
                continue;
            }

            out.findings.push(
                Finding::new(
                    FindingCategory::File,
                    Severity::Medium,
                    Confidence::Suspicious,
                    format!("Executable in unusual folder: {name}"),
                    "SentinelAI found a program file in a location where everyday software is less commonly installed.",
                )
                .with_subject(path.to_string_lossy().to_string())
                .with_reasons(vec![
                    "+ Executable present in a high-risk staging location".into(),
                    "+ Local filesystem heuristic only".into(),
                ])
                .with_recommendation(
                    "If you did not place this file here, do not run it and consider removing it.",
                )
                .with_risk_score(62)
                .with_technical(format!("path={}", path.display())),
            );
        }
    }

    out
}

fn suspicious_candidate_dirs() -> Vec<PathBuf> {
    use std::collections::HashSet;
    let mut dirs = Vec::new();
    let mut seen = HashSet::new();
    for key in ["TEMP", "TMP"] {
        if let Ok(tmp) = std::env::var(key) {
            let path = PathBuf::from(tmp);
            if let Ok(canonical) = path.canonicalize() {
                if seen.insert(canonical) {
                    dirs.push(path);
                }
            } else if seen.insert(path.clone()) {
                dirs.push(path);
            }
        }
    }
    if let Ok(public) = std::env::var("PUBLIC") {
        let public_path = PathBuf::from(&public);
        dirs.push(public_path.clone());
        dirs.push(public_path.join("Downloads"));
    }
    dirs
}
