use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum VaultCommand {
    /// Encrypt a file in place using Warp vault format.
    Encrypt(VaultFileArgs),
    /// Decrypt a vault file in place.
    Decrypt(VaultFileArgs),
    /// Decrypt a vault file to stdout without modifying it.
    View(VaultFileArgs),
}

#[derive(Debug, Clone, Args)]
pub struct VaultFileArgs {
    /// Path to the file to operate on.
    pub file_path: PathBuf,
}
