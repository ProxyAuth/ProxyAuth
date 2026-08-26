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
    /// Certificate management (native ACME/Let's Encrypt integration
    /// — see `certbot_renew` in routes.yml).
    Certbot {
        #[command(subcommand)]
        action: CertbotAction,
    },
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
        /// Email address to notify this user at — required for
        /// `proxyauth reset-password` to work for them. Repeat the
        /// flag to set more than one (e.g. --email a@x.com --email
        /// b@x.com). Omitting it entirely clears any email(s) already
        /// on file for this user (this command is authoritative, not a
        /// merge — same reasoning as --must-change-password below).
        #[arg(long)]
        email: Vec<String>,
        /// Which of the --email addresses is the primary one (used
        /// when sending a reset link). Must exactly match one of the
        /// --email values given. Defaults to the first --email given
        /// if omitted.
        #[arg(long)]
        primary_email: Option<String>,
        /// Marks the account as needing a real password before it can
        /// be used normally — their next successful login redirects to
        /// `page_change_password` instead of issuing a session. Use
        /// this when --password is a temporary one you're handing to
        /// someone directly, rather than a permanent password they
        /// chose themselves.
        #[arg(long)]
        must_change_password: bool,
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
    /// Resets a user's password: generates a single-use, time-limited
    /// link and emails it to them (requires both `smtp` and
    /// `page_change_password` to be configured, and the user to have
    /// an email on file). Their current password keeps working until
    /// they actually follow the link and set a new one — this doesn't
    /// lock them out immediately, it just gives them a way back in
    /// without needing their old password.
    ResetPassword {
        #[arg(long)]
        username: String,
    },
    /// Audits every route in routes.yml, showing exactly what secures
    /// it — an allow-listed username, groups, roles, "PUBLIC" (no
    /// login required at all), or "OPEN" (login required, but no
    /// username/groups/roles configured, so any authenticated account
    /// gets through). Meant to answer "where are we wide open?" at a
    /// glance across the whole route table. Reads routes.yml and
    /// config.json directly and uses the exact same access-decision
    /// logic the running proxy enforces
    /// (`AppConfig::route_access_decision`) — the running server
    /// doesn't need to be involved, and this can never silently
    /// disagree with what it actually does.
    RoutesAudit,
    /// Checks one account's access across every route in routes.yml —
    /// ✓/✗ per route and exactly why (matched username, a specific
    /// group, a specific role, an open/public route, or "denied" with
    /// what would need to change). Same underlying decision logic and
    /// same caveat as `routes-audit` above: this reflects real
    /// enforcement, not a re-implementation of it.
    CheckAccess {
        #[arg(long)]
        username: String,
    },
    /// The combined "everything at once" view: for every route,
    /// resolves the abstract username/groups/roles rule down to the
    /// concrete list of accounts that currently satisfy it — each
    /// tagged with why (listed by name, via a group, via a role) —
    /// by checking every known account against it. Also flags any
    /// route secured by something no current account actually
    /// matches (almost always a typo in a group/role name), which
    /// `routes-audit` alone can't surface since it only describes the
    /// rule, not who it currently resolves to.
    CheckRoutes,
    /// Lists every known account (file-based and database), each in
    /// its own small box: groups, roles, and every route it can
    /// currently reach (and via which mechanism). Uses the same
    /// `route_access_decision` logic as the other audit commands.
    Users {
        /// Just print each username, one per line — no per-account
        /// detail box. Script-friendly (pipe into `grep`, `xargs`,
        /// etc.), never colored regardless of `NO_COLOR`/TTY.
        #[arg(long)]
        list: bool,
    },
    /// Lists every group currently referenced by an account or a
    /// route, each in its own small box: current members, and which
    /// routes list it directly.
    Groups {
        /// Just print each group name, one per line — see `users
        /// --list`.
        #[arg(long)]
        list: bool,
    },
    /// Same as `groups`, for roles: current holders, and which routes
    /// list it directly. Roles are also still forwarded to the
    /// backend as `X-User-Roles` regardless of whether any route
    /// lists them.
    Roles {
        /// Just print each role name, one per line — see `users
        /// --list`.
        #[arg(long)]
        list: bool,
    },
}

#[derive(Subcommand)]
pub enum CertbotAction {
    /// Renews the certificate for a single vhost right now, via the
    /// same native ACME mechanism the periodic `certbot_renew: true`
    /// scan uses — see the "Automatic Certificate Renewal (ACME)"
    /// wiki page. `vhost` must already have `vhost_cert` (cert/key
    /// paths) configured for it in routes.yml; `certbot_renew: true`
    /// does *not* need to also be set — running this command by hand
    /// is itself sufficient intent to renew.
    Renew {
        /// The vhost to renew, exactly as it appears in that route's
        /// `vhost` list in routes.yml — or the literal value `all` to
        /// renew every vhost that has both `certbot_renew: true` and a
        /// usable `vhost_cert` (unlike a named single vhost, `all`
        /// only considers vhosts that opted into automatic renewal;
        /// a `vhost_cert`-only vhost without `certbot_renew: true`
        /// isn't touched by `all` — name it directly instead).
        vhost: String,

        /// Renew even if the current certificate isn't due yet
        /// (i.e. still has more than `renew_before_days` left).
        /// Without this, a certificate that's not yet due is left
        /// alone and the command exits without contacting Let's
        /// Encrypt at all. Applies to every vhost touched when
        /// `vhost` is `all`.
        #[arg(long)]
        force: bool,
    },

    /// Prints certificate details for a vhost — subject, issuer,
    /// validity window, days left, serial, and the hostnames it
    /// actually covers (SAN). Read-only; works for any vhost with a
    /// `vhost_cert` configured, whether it's ACME-managed
    /// (`certbot_renew: true`) or not.
    Check {
        /// The vhost to inspect, exactly as it appears in that
        /// route's `vhost` list in routes.yml — or `all` to check
        /// every vhost that has a `vhost_cert` configured (`certbot_renew`
        /// not required for `all` here, unlike `renew all`, since this
        /// is read-only and applies equally to a manually-managed
        /// certificate).
        vhost: String,
    },

    /// Issues a certificate for a vhost that doesn't have one yet —
    /// unconditionally, no `--force` needed (there's nothing to
    /// compare against a renewal threshold for). Uses the exact same
    /// mechanism as `renew`; the only difference is this always
    /// issues, and doesn't accept `all` (name the vhost you're
    /// setting up).
    ///
    /// If this vhost was *just* added to routes.yml (not already
    /// running with some placeholder certificate at its `vhost_cert`
    /// paths before this command), a restart is still needed
    /// afterwards — the TLS layer's file watcher for a given vhost is
    /// only ever set up once, at startup, from whatever `vhost_cert`
    /// paths existed at that time. This command issues the
    /// certificate; it can't retroactively make an already-running
    /// server start watching a path it didn't know about yet.
    New {
        /// The vhost to issue a certificate for, exactly as it
        /// appears in that route's `vhost` list in routes.yml.
        /// `vhost_cert` (cert/key paths) must already be set for it.
        vhost: String,
    },
}
