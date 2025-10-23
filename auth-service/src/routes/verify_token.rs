use crate::utils::auth::validate_token;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

#[derive(serde::Deserialize)]
pub struct TokenRequest {
    pub token: String,
}
pub async fn verify_token(
    State(state): State<AppState>,
    Json(token): Json<TokenRequest>,
) -> impl IntoResponse {
    let banned_tokens_store = &state.banned_tokens.read().await;
    let is_banned = banned_tokens_store.is_token_banned(&token.token).await;
    if is_banned.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if is_banned.unwrap() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let validation = validate_token(&token.token).await;
    if validation.is_err() || !validation.unwrap() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    StatusCode::OK.into_response()
}
