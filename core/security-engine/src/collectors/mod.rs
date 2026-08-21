//! Platform collectors for security posture signals.

pub mod browser;
pub mod downloads;
pub mod network;
pub mod process;
pub mod security_config;
pub mod startup;
pub mod suspicious_paths;

use sentinel_common::Finding;

/// Result of running a named collector.
#[derive(Debug, Default)]
pub struct CollectorOutput {
    pub name: String,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

impl CollectorOutput {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            findings: Vec::new(),
            warnings: Vec::new(),
        }
    }
}
