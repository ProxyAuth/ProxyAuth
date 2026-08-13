use actix_web::{HttpRequest, HttpResponse, Responder, web};
use serde::Deserialize;

use crate::AppState;
use crate::adm::stats::is_valid_admin_token;
use crate::revoke::load::revoke_token;

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token_id: String,
    pub exp: Option<u64>,
}

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

    let token_id = &body.token_id;
    let exp = body.exp;

    match revoke_token(token_id, exp, &data.revoked_tokens).await {
        Ok(_) => {
            if exp.is_some() {
                HttpResponse::Ok().body("Token revoked with expiration.")
            } else {
                HttpResponse::Ok().body("Token permanently revoked.")
            }
        }
        Err(e) => {
            eprintln!("[revoke_route] Failed to revoke token: {}", e);
            HttpResponse::InternalServerError().body("Failed to revoke token.")
        }
    }
}
