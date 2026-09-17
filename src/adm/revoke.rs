use actix_web::{HttpRequest, HttpResponse, Responder, web};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

use crate::AppState;
use crate::adm::stats::is_valid_admin_token;
use crate::revoke::load::{is_plain_token_id, revocation_record_until, revoke_token};

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token_id: String,
    /// Accepted for compatibility, ignored: the record is kept exactly as
    /// long as the token could still be valid (`now +
    /// token_expiry_seconds`), and the token is refused immediately.
    #[allow(dead_code)]
    pub exp: Option<u64>,
}

/// `POST /adm/revoke` — refuses a token from now on.
///
/// The token is refused immediately. The record is kept until every
/// token that exists now has expired (see `revocation_record_until`),
/// then purged from memory, LMDB and Redis.
pub async fn revoke_route(
    req: HttpRequest,
    data: web::Data<AppState>,
    body: web::Json<RevokeRequest>,
) -> impl Responder {
    // SECURITY: constant-time comparison (was a plain `==` on the raw
    // header, vulnerable to a timing side-channel on this very sensitive
    // admin token — same pattern already used correctly in adm/stats.rs).
    if !is_valid_admin_token(&req, &data) {
        return HttpResponse::Unauthorized().body("Invalid or missing token");
    }

    let token_id = body.token_id.trim();
    if !is_plain_token_id(token_id) {
        return HttpResponse::BadRequest().body("Invalid token_id.");
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let lifetime = data.config.token_expiry_seconds.max(0) as u64;
    let keep_until = revocation_record_until(now, lifetime);

    match revoke_token(token_id, Some(keep_until), &data.revoked_tokens).await {
        Ok(_) => {
            info!("token {token_id} revoked; record kept until {keep_until}");
            HttpResponse::Ok().body("Token revoked with expiration.")
        }
        Err(e) => {
            error!("[revoke_route] Failed to persist revocation of {token_id}: {e}");
            HttpResponse::InternalServerError().body("Failed to revoke token.")
        }
    }
}
