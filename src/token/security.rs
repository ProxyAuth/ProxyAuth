use crate::AppConfig;
use crate::AppState;
use crate::build::build_info::get;
use crate::config::config::RegexCond;
use crate::config::config::RouteRule;
use crate::network::canonical_url::canonicalize_path_for_match;
use crate::revoke::load::is_token_revoked;
use crate::token::vault::vault;
use actix_web::HttpRequest;
use actix_web::http::StatusCode;
use actix_web::http::header::HeaderMap;
use actix_web::web;
use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use regex::Regex;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use tracing::{error, info, warn};

// Build metadata accessors. All of them are folded into the vault's key
// at startup by `token::vault::build_key`, so a difference in any build
// constant yields a different key — see that function for why that
// binding is worth keeping now that the old shuffle no longer provides
// it.

pub fn get_build_time() -> u64 {
    let get_build = get();
    let data = get_build.build_time;
    data
}

pub fn get_build_rand() -> u64 {
    let get_build = get();
    let data = get_build.build_rand;
    data
}

pub fn get_build_seed2() -> u64 {
    let get_build = get();
    let data = get_build.build_seed2;
    data
}

pub fn get_build_epochdate() -> i64 {
    let get_build = get();
    let data = get_build.build_epoch;
    data
}

/// Convenience wrapper over [`get_build_epochdate`].
///
/// The vault folds the raw epoch in, not this; only the integration
/// tests call this one, and a library build cannot see those call sites.
#[allow(dead_code)]
pub fn get_build_datetime() -> chrono::DateTime<chrono::Utc> {
    let seconds = get_build_epochdate();
    let naive = Utc.timestamp_opt(seconds, 0).unwrap();
    naive
}

pub fn get_build_hk() -> String {
    let get_build = get();
    let data = get_build.build_hk;
    data
}

#[allow(dead_code)]
pub fn format_long_date(seconds: u128) -> String {
    let seconds_per_year = 31_557_600u128;
    let year = seconds / seconds_per_year;
    let remaining = seconds % seconds_per_year;

    let _days = remaining / 86400;
    let hours = (remaining % 86400) / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    format!(
        "+{:0>8}-01-01T{:02}:{:02}:{:02}Z",
        year, hours, minutes, seconds
    )
}

pub fn check_date_token(
    time_str: &str,
    username: &str,
    ip: &str,
    timezone: &str,
) -> Result<u64, ()> {
    let tz: Tz = timezone.parse().map_err(|_| {
        warn!("[{}] invalid timezone '{}'", ip, timezone);
        ()
    })?;

    let expire_time = time_str
        .parse::<DateTime<Utc>>()
        .or_else(|_| {
            time_str
                .parse::<i64>()
                .map(|ts| Utc.timestamp_opt(ts, 0).single().unwrap())
        })
        .map_err(|_| {
            warn!("[{}] failed to parse expiration time: {}", ip, time_str);
            ()
        })?;

    let expire_local = expire_time.with_timezone(&tz);
    let now_local = Utc::now().with_timezone(&tz);

    if now_local.timestamp() >= expire_local.timestamp() {
        warn!("[{}] token is expired for user {}", ip, username);
        return Err(());
    }

    let diff = expire_local.timestamp() - now_local.timestamp();
    diff.try_into().map_err(|_| ())
}

/// Mints a sealed session token.
///
/// The digest, the sealing and the optional obfuscation pass are all in
/// `zerocrypt` now; what remains here is ProxyAuth's own vocabulary —
/// the user's index, the expiry string, the token id.
///
/// `index_user` is genuinely read back by [`validate_token`] to resolve
/// which account a token belongs to. Passing the wrong one does not fail
/// loudly, it resolves a valid session to the wrong user.
pub fn issue_token(
    username: &str,
    index_user: usize,
    expiry_ts: &str,
    token_id: &str,
) -> Result<String, String> {
    let expires_at = expiry_ts
        .parse::<u64>()
        .map_err(|_| "invalid expiry timestamp".to_string())?;

    vault()
        .token(username)
        .expires_at(expires_at)
        .id(token_id)
        // The user index rides in the token's data field: the library
        // has no concept of an index, and does not need one.
        .data(&index_user.to_string())
        .issue()
        .map_err(|e| format!("token issue failed: {e}"))
}

/// Verifies a token and returns `(username, token_id, seconds_remaining)`.
///
/// Signature unchanged, so every existing call site keeps working. The
/// cryptography is delegated; everything below it — the expiry policy,
/// the user lookup, revocation, stats and logging — is application
/// behaviour and stays here.
///
/// # The order of the checks below is load-bearing
///
/// `vault().verify()` is **cached** (see `token::vault`), because for a
/// given key the answer to "is this token authentic" cannot change.
/// Everything after it reads live state and runs on every request:
/// the user lookup, the name/index agreement, the expiry policy against
/// the current config, and revocation.
///
/// That ordering is what makes the cache safe. Revoking a token, editing
/// or removing a user, or lowering `token_expiry_seconds` all take effect
/// immediately, because none of those answers is remembered.
///
/// Moving any of those checks above the `verify` call, or caching their
/// results, would break that guarantee — a revoked token would keep
/// working until its cache entry aged out, which is exactly the failure
/// this arrangement avoids. If you need to add a check that reads
/// mutable state, add it below, not above.
pub async fn validate_token(
    token: &str,
    data_app: &web::Data<AppState>,
    config: &AppConfig,
    ip: &str,
) -> Result<(String, String, u64), String> {
    // One call covers what used to be decrypt + split + digest recompute
    // + constant-time compare. `Expired` is separated from `Invalid`
    // because the two deserve different log lines: one is routine, the
    // other is worth noticing.
    let session = match vault().verify(token) {
        Ok(session) => session,
        Err(zerocrypt::Error::Expired) => {
            return Err("Your token is expired".to_string());
        }
        Err(_) => {
            warn!("[{}] Invalid token", ip);
            return Err("no valid token".to_string());
        }
    };

    // ── everything from here down reads live state, every request ──
    // Nothing below this line is cached. See the note on this function.
    let index_user = session
        .data()
        .parse::<usize>()
        .map_err(|_| "Index invalide")?;
    let user = config.user_by_index(index_user).ok_or("User not found")?;

    // The token carries the name it was issued to; the index must still
    // resolve to that same account. They can only disagree if the user
    // list changed under a live token, and silently serving the wrong
    // account is exactly the failure mode worth refusing.
    if user.username != session.user() {
        warn!(
            "[{}] token for {} resolved to index {} which is now {}",
            ip,
            session.user(),
            index_user,
            user.username
        );
        return Err("no valid token".to_string());
    }

    let time_expire = check_date_token(
        &session.expires_at().to_string(),
        &user.username,
        ip,
        &config.timezone,
    )
    .map_err(|_| "Your token is expired")?;

    if time_expire > config.token_expiry_seconds.max(0) as u64 {
        error!(
            "[{}] username {} try to access token limit config {} value request {}",
            ip, user.username, config.token_expiry_seconds, time_expire
        );
        return Err("Bad time token".to_string());
    }

    if is_token_revoked(session.id(), &data_app.revoked_tokens) {
        warn!(
            "[{}] token_id {} is revoked from user {}",
            ip,
            session.id(),
            user.username
        );
        return Err("revoked token".to_string());
    }

    if config.stats {
        let count = data_app.counter.record_and_get(
            &user.username,
            session.id(),
            &time_expire.to_string(),
        );

        info!(
            "[{}] user {} is logged token expire in {} seconds [token used: {}]",
            ip, user.username, time_expire, count
        );
    } else {
        info!(
            "[{}] user {} is logged token expire in {} seconds",
            ip, user.username, time_expire
        );
    }

    Ok((
        user.username.to_string(),
        session.id().to_string(),
        time_expire,
    ))
}

/// Resolves the username a token belongs to, without the full policy
/// checks [`validate_token`] applies.
///
/// Still authenticated: an unsealed or tampered token is rejected here
/// too. It is the revocation, expiry-policy and stats work that is
/// skipped, not the cryptography.
pub fn extract_token_user(token: &str, config: &AppConfig, ip: String) -> Result<String, String> {
    let session = match vault().verify(token) {
        Ok(session) => session,
        Err(zerocrypt::Error::Expired) => {
            warn!("[{}] Token is expired", ip);
            return Err("Your token is expired".into());
        }
        Err(_) => {
            warn!("[{}] Failed to open token (invalid format)", ip);
            return Err("Invalid token format".into());
        }
    };

    let index_user: usize = match session.data().parse() {
        Ok(i) => i,
        Err(_) => {
            warn!("[{}] Failed to parse user index from token", ip);
            return Err("Invalid user index".into());
        }
    };

    match config.user_by_index(index_user) {
        Some(user) if user.username == session.user() => Ok(user.username.clone()),
        Some(user) => {
            warn!(
                "[{}] token for {} resolved to index {} which is now {}",
                ip,
                session.user(),
                index_user,
                user.username
            );
            Err("User not found".into())
        }
        None => {
            warn!("[{}] User index out of bounds: {}", ip, index_user);
            Err("User not found".into())
        }
    }
}

pub fn all_values_match<'a, I>(vals: I, re: &Regex) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    vals.into_iter().all(|v| re.is_match(v))
}

pub fn parse_query_map(q: &str) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::<String, Vec<String>>::new();
    for pair in q.split('&').filter(|s| !s.is_empty()) {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("").to_string();
        let v = it.next().unwrap_or("").to_string();
        map.entry(k).or_default().push(v);
    }
    map
}

pub fn apply_filters_regex_allow_only(
    rule: &RouteRule,
    req: &HttpRequest,
    body: &[u8],
) -> Option<StatusCode> {
    let compiled = match &rule.filters_compiled {
        Some(c) => c,
        None => return None,
    };

    let method = req.method();
    let path_canon = canonicalize_path_for_match(req.uri().path());
    let query = parse_query_map(req.uri().query().unwrap_or("")); // HashMap<String, Vec<String>>

    let mut need_utf8 = false;
    let mut need_json = false;
    for c in &compiled.allow {
        match c {
            RegexCond::BodyRaw { .. } => need_utf8 = true,
            RegexCond::BodyJson { .. } => need_json = true,
            _ => {}
        }
    }

    let ct = req
        .headers()
        .get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let body_utf8 = if need_utf8 {
        std::str::from_utf8(body).ok()
    } else {
        None
    };

    let body_json = if need_json && ct.contains("application/json") {
        serde_json::from_slice::<JsonValue>(body).ok()
    } else {
        None
    };

    if compiled.allow.is_empty() {
        return if compiled.default_allow {
            None
        } else {
            Some(StatusCode::FORBIDDEN)
        };
    }

    let ok = compiled.allow.iter().all(|cond| {
        cond_matches_strict(
            cond,
            method,
            &path_canon,
            req.headers().clone(),
            &query,
            body_utf8,
            body_json.as_ref(),
            &ct,
        )
    });

    if ok {
        None
    } else {
        Some(StatusCode::FORBIDDEN)
    }
}

pub fn cond_matches_strict(
    cond: &RegexCond,
    method: &actix_web::http::Method,
    path: &str,
    headers: HeaderMap,
    query: &std::collections::HashMap<String, Vec<String>>,
    body_utf8: Option<&str>,
    body_json: Option<&JsonValue>,
    content_type_lower: &str,
) -> bool {
    match cond {
        RegexCond::Method { re } => re.is_match(method.as_str()),
        RegexCond::Path { re } => re.is_match(path),

        RegexCond::Header { name_re, re } => {
            let mut matched_any_name = false;
            let mut values_for_matched_names: Vec<String> = Vec::new();

            for (k, v) in headers.iter() {
                let name = k.as_str();
                if name_re.is_match(name) {
                    matched_any_name = true;
                    if let Ok(val) = v.to_str() {
                        values_for_matched_names.push(val.to_string());
                    } else {
                        return false;
                    }
                }
            }

            if !matched_any_name {
                return false;
            }

            all_values_match(values_for_matched_names.iter().map(|s| s.as_str()), re)
        }

        RegexCond::Query { name_re, re } => {
            let mut matched_any_name = false;

            for (k, vals) in query {
                if name_re.is_match(k) {
                    matched_any_name = true;

                    if !all_values_match(vals.iter().map(|s| s.as_str()), re) {
                        return false;
                    }
                }
            }

            matched_any_name
        }

        RegexCond::BodyRaw { re } => match body_utf8 {
            Some(s) => re.is_match(s),
            None => false,
        },

        RegexCond::BodyJson { key, re } => {
            if !content_type_lower.contains("application/json") {
                return false;
            }
            let Some(j) = body_json else {
                return false;
            };

            match j.get(key) {
                Some(JsonValue::String(s)) => re.is_match(s),
                Some(JsonValue::Number(n)) => re.is_match(&n.to_string()),
                Some(JsonValue::Bool(b)) => re.is_match(if *b { "true" } else { "false" }),
                Some(other) => re.is_match(&other.to_string()),
                None => false,
            }
        }
    }
}
