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
    /// Re-populate the configured database from this instance's local
    /// LMDB fallback cache (the last known-good snapshot, mirrored
    /// there on every successful full read of the database). Meant for
    /// after the database comes back empty (e.g. a botched restore, a
    /// fresh empty database swapped in by mistake) — never run
    /// automatically, since ProxyAuth can't tell an empty database
    /// apart from a deliberate one. Refuses if the database already has
    /// any users, unless --force is given — in which case every cached
    /// user is upserted, overwriting anything already there with the
    /// same username.
    DbRestoreFromCache {
        #[arg(long)]
        force: bool,
    },
    /// Clears this instance's local LMDB fallback cache. The next
    /// successful full database read repopulates it as usual — this
    /// doesn't disable caching going forward, it only wipes what's
    /// stored right now. Useful if the cache itself is suspected stale
    /// or wrong (e.g. before running db-restore-from-cache, if you'd
    /// rather force a fresh database read first) and you want to be
    /// certain a later fallback wouldn't reuse it. A no-op, not an
    /// error, if nothing was cached to begin with.
    DbClearCache,
    /// Forces an immediate sync of the local LMDB fallback cache from
    /// the configured database — a live full read, right now, instead
    /// of waiting for the next scheduled full scan
    /// (`databases.full_refresh_interval_secs`). Useful right after
    /// fixing a database connectivity issue, to get a fresh cache
    /// immediately.
    ///
    /// Refuses to overwrite a non-empty existing cache with an empty
    /// result (the database answered, but has zero users right now —
    /// could be genuine, could be a wrong database/permissions issue)
    /// unless --force is given, mirroring the same protection
    /// db-restore-from-cache has in the other direction.
    DbSyncCache {
        #[arg(long)]
        force: bool,
    },
}
