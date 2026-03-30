use clap::Args;
use std::path::PathBuf;

/// Scan a Sparx Enterprise Architect .qeax file for secrets
#[derive(Args, Debug, Clone)]
pub struct QeaxScanArgs {
    /// Path to the .qeax file to scan
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
}
