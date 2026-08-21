//! Recent downloads inventory with optional hashing.

use crate::collectors::CollectorOutput;
use crate::hash::sha256_file;
use crate::inventory::DownloadedFile;
use sentinel_common::{Confidence, Finding, FindingCategory, Severity};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const DEFAULT_MAX_FILES: usize = 40;
const DEFAULT_HASH_MAX_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB
const RECENT_DAYS: u64 = 14;

pub fn collect_downloads(hash_recent: bool) -> CollectorOutput {
    let mut out = CollectorOutput::new("downloads_inventory");
    let Some(dir) = downloads_dir() else {
        out.warnings
            .push("Could not resolve the user Downloads folder.".into());
        return out;
    };
    collect_downloads_from_dir(&dir, hash_recent, &mut out);
    out
}

/// Inventory a specific directory (used by tests and the Downloads collector).
pub fn inventory_directory(
    dir: &Path,
    hash_recent: bool,
    max_files: usize,
    recent_days: u64,
) -> (Vec<DownloadedFile>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut inventory = Vec::new();

    if !dir.is_dir() {
        warnings.push(format!(
            "Downloads folder does not exist: {}",
            dir.display()
        ));
        return (inventory, warnings);
    }

    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(recent_days * 24 * 3600))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let mut files: Vec<(PathBuf, SystemTime, u64)> = Vec::new();
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(err) => {
                        warnings.push(format!(
                            "Could not read metadata for {}: {err}",
                            path.display()
                        ));
                        continue;
                    }
                };
                let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                if modified < cutoff {
                    continue;
                }
                files.push((path, modified, meta.len()));
            }
        }
        Err(err) => {
            warnings.push(format!("Could not read Downloads folder: {err}"));
            return (inventory, warnings);
        }
    }

    files.sort_by_key(|a| std::cmp::Reverse(a.1));
    files.truncate(max_files);

    for (path, modified, size) in files {
        let mut sha = None;
        if hash_recent && size <= DEFAULT_HASH_MAX_BYTES {
            match sha256_file(&path) {
                Ok(h) => sha = Some(h),
                Err(err) => warnings.push(format!("Hash failed for {}: {err}", path.display())),
            }
        }

        let file_name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        inventory.push(DownloadedFile {
            path: path.to_string_lossy().to_string(),
            file_name,
            size_bytes: size,
            modified_unix: modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64),
            sha256: sha,
        });
    }

    (inventory, warnings)
}

fn collect_downloads_from_dir(dir: &Path, hash_recent: bool, out: &mut CollectorOutput) {
    let (inventory, warnings) =
        inventory_directory(dir, hash_recent, DEFAULT_MAX_FILES, RECENT_DAYS);
    out.warnings.extend(warnings);

    for item in &inventory {
        if looks_like_risky_download(&item.file_name) {
            out.findings.push(
                Finding::new(
                    FindingCategory::File,
                    Severity::Low,
                    Confidence::Unknown,
                    format!("Review recent download: {}", item.file_name),
                    "A recently downloaded file may be an installer or script. Confirm you trust the source before opening it.",
                )
                .with_subject(item.path.clone())
                .with_reasons(vec![
                    "+ Recently downloaded".into(),
                    "+ File type commonly used for software installers or scripts".into(),
                ])
                .with_recommendation(
                    "Open only if you requested this download from a trusted site.",
                )
                .with_risk_score(40)
                .with_technical(format!(
                    "path={} size={} sha256={}",
                    item.path,
                    item.size_bytes,
                    item.sha256.as_deref().unwrap_or("(not hashed)")
                )),
            );
        }
    }
}

fn downloads_dir() -> Option<PathBuf> {
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let p = PathBuf::from(userprofile).join("Downloads");
        if p.is_dir() {
            return Some(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join("Downloads");
        if p.is_dir() {
            return Some(p);
        }
    }
    None
}

fn looks_like_risky_download(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".exe")
        || lower.ends_with(".msi")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".ps1")
        || lower.ends_with(".js")
        || lower.ends_with(".vbs")
        || lower.ends_with(".scr")
        || lower.ends_with(".hta")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256_bytes;
    use std::io::Write;

    #[test]
    fn installer_extension_detected() {
        assert!(looks_like_risky_download("Setup.EXE"));
        assert!(looks_like_risky_download("payload.ps1"));
        assert!(!looks_like_risky_download("photo.jpg"));
    }

    #[test]
    fn inventory_hashes_recent_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("setup.exe");
        let payload = b"sentinel-test-download";
        {
            let mut f = fs::File::create(&file_path).expect("create");
            f.write_all(payload).expect("write");
        }

        let (inventory, warnings) = inventory_directory(dir.path(), true, 10, 14);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].file_name, "setup.exe");
        assert_eq!(
            inventory[0].sha256.as_deref(),
            Some(sha256_bytes(payload).as_str())
        );
    }

    #[test]
    fn missing_directory_produces_warning_not_panic() {
        let missing = PathBuf::from("C:\\sentinel-ai-does-not-exist-downloads");
        let (inventory, warnings) = inventory_directory(&missing, true, 10, 14);
        assert!(inventory.is_empty());
        assert!(!warnings.is_empty());
    }
}
