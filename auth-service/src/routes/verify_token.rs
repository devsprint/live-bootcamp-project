use crate::utils::auth::validate_token;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

#[derive(serde::Deserialize)]
pub struct TokenRequest {
    pub token: String,
}
pub async fn verify_token(Json(token): Json<TokenRequest>) -> impl IntoResponse {
    let validation = validate_token(&token.token).await;
    if validation.is_err() || !validation.unwrap() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    StatusCode::OK.into_response()
}
