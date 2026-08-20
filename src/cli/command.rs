use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "proxyauth")]
#[command(about = "Manage proxyauth system", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Prepare {
        #[arg(long)]
        insecure: bool,
    },
    Stats,
    Sync {
        target: Option<String>,
    },
    /// Create or update a user directly in the configured database
    /// (requires `databases` to be set in config.json). If --password is
    /// omitted, you'll be prompted for it interactively (hidden input).
    DbAddUser {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Soft-delete a user in the configured database: the row is kept
    /// (marked deleted) rather than removed immediately, so every
    /// connected instance's incremental scan can pick it up and revoke
    /// it right away. Permanently purged later on its own
    /// (`databases.deleted_retention_secs`, default 24h).
    DbDeleteUser {
        #[arg(long)]
        username: String,
    },
}
