//! SentinelAgent — Windows security agent (Milestone 1).
//!
//! Runs defensive posture scans with least privilege. Does not disable OS
//! security controls, does not steal credentials, and does not claim unverified
//! malware detections or VPN protection.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sentinel_common::version::{CURRENT_MILESTONE, PRODUCT_NAME, SENTINEL_VERSION};
use sentinel_common::ScanKind;
use sentinel_security_engine::{ScanEngine, ScanOptions};
use std::fs;
use std::path::PathBuf;
use tracing::{info, Level};

#[derive(Debug, Parser)]
#[command(
    name = "SentinelAgent",
    about = "SentinelAI Windows security agent — local defensive scanning",
    version = SENTINEL_VERSION
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Increase log verbosity (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print agent and capability information (truthful)
    Info,
    /// Run a security posture scan
    Scan {
        /// Scan depth
        #[arg(long, value_enum, default_value_t = ScanKindArg::Quick)]
        kind: ScanKindArg,
        /// Write JSON report to this path
        #[arg(long)]
        output: Option<PathBuf>,
        /// Print JSON to stdout instead of a human summary
        #[arg(long)]
        json: bool,
    },
    /// Show a compact security posture summary (runs Quick Scan)
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ScanKindArg {
    Quick,
    Smart,
    Full,
}

impl From<ScanKindArg> for ScanKind {
    fn from(value: ScanKindArg) -> Self {
        match value {
            ScanKindArg::Quick => ScanKind::Quick,
            ScanKindArg::Smart => ScanKind::Smart,
            ScanKindArg::Full => ScanKind::Full,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Commands::Info => print_info(),
        Commands::Scan { kind, output, json } => run_scan(kind.into(), output, json)?,
        Commands::Status { json } => run_scan(ScanKind::Quick, None, json)?,
    }

    Ok(())
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .compact()
        .init();
}

fn print_info() {
    println!("{PRODUCT_NAME} Agent v{SENTINEL_VERSION}");
    println!("Milestone: {CURRENT_MILESTONE}");
    println!();
    println!("Capabilities (implemented):");
    println!("  • Local Quick / Smart / Full posture scans");
    println!("  • Process, startup, downloads, browser extension inventory");
    println!("  • Windows Defender / Firewall configuration checks (local)");
    println!("  • Explainable heuristic risk scoring");
    println!("  • SHA-256 hashing of recent downloads (Smart/Full)");
    println!();
    println!("Capabilities (NOT configured / NOT claimed):");
    println!("  • External threat intelligence providers — Local analysis only");
    println!("  • Cloud authentication / device registration — not implemented");
    println!("  • AI cloud assistant — not configured");
    println!("  • VPN — VPN infrastructure not configured");
    println!("  • Automatic quarantine / remediation — not implemented");
    println!();
    println!("Security model: defensive, least privilege, user-authorized scans.");
}

fn run_scan(kind: ScanKind, output: Option<PathBuf>, json: bool) -> Result<()> {
    info!(scan = kind.as_str(), "Starting local security scan");
    let engine = ScanEngine::new();
    let report = engine.run(ScanOptions {
        kind,
        hash_downloads: matches!(kind, ScanKind::Smart | ScanKind::Full),
    });

    if let Some(path) = output {
        let body = serde_json::to_string_pretty(&report)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, body)?;
        info!(path = %path.display(), "Wrote scan report");
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    print_human_summary(&report);
    Ok(())
}

fn print_human_summary(report: &sentinel_common::ScanReport) {
    let score = &report.posture.score;
    println!();
    println!("══════════════════════════════════════════════");
    println!("  {PRODUCT_NAME} — {}", report.kind.user_label());
    println!("══════════════════════════════════════════════");
    println!();
    println!(
        "  {} {}",
        score.status.emoji(),
        score.status.user_label().to_uppercase()
    );
    println!("  Security score: {}/100", score.value);
    println!("  {}", score.summary);
    println!();
    println!("  Analysis: {}", report.analysis_mode.user_label());
    println!("  Duration: {} ms", report.duration_ms);
    println!("  Findings: {}", report.findings.len());
    println!();

    let actionable: Vec<_> = report
        .findings
        .iter()
        .filter(|f| !matches!(f.severity, sentinel_common::Severity::Info))
        .collect();

    if actionable.is_empty() {
        println!("  No active threats requiring attention (local analysis).");
    } else {
        println!("  Items to review:");
        for finding in actionable.iter().take(15) {
            println!(
                "  • [{}] {} — {}",
                finding.confidence.user_label(),
                finding.title,
                finding.summary
            );
            if !finding.recommendation.is_empty() {
                println!("      → {}", finding.recommendation);
            }
        }
        if actionable.len() > 15 {
            println!("  … and {} more", actionable.len() - 15);
        }
    }

    if !report.warnings.is_empty() {
        println!();
        println!("  Warnings:");
        for w in &report.warnings {
            println!("  • {w}");
        }
    }

    println!();
    println!("  Notes:");
    for n in &report.notes {
        println!("  • {n}");
    }
    println!();
    println!("  VPN: VPN infrastructure not configured.");
    println!("  Threat intel: Local analysis only.");
    println!();
}
