//! Inventory data structures collected from the host.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub cmd: Option<String>,
    pub parent_pid: Option<u32>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    pub name: String,
    pub command: String,
    pub location: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadedFile {
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub modified_unix: Option<i64>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkListener {
    pub local_addr: String,
    pub protocol: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserExtensionHint {
    pub browser: String,
    pub profile: String,
    pub extension_id: String,
    pub name: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvFirewallSnapshot {
    pub defender_service_running: Option<bool>,
    pub defender_realtime_approx: Option<bool>,
    pub firewall_domain_enabled: Option<bool>,
    pub firewall_private_enabled: Option<bool>,
    pub firewall_public_enabled: Option<bool>,
    pub detail: String,
    pub source: String,
}
