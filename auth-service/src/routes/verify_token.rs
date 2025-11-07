use crate::AppState;
use crate::utils::auth::validate_token;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

#[derive(serde::Deserialize)]
pub struct TokenRequest {
    pub token: String,
}
pub async fn verify_token(
    State(state): State<AppState>,
    Json(token): Json<TokenRequest>,
) -> impl IntoResponse {
    let banned_tokens_store = state.banned_tokens.clone();
    let is_banned = banned_tokens_store
        .read()
        .await
        .is_token_banned(&token.token)
        .await;
    if is_banned.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if is_banned.unwrap() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let validation = validate_token(&token.token, banned_tokens_store).await;
    if validation.is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    StatusCode::OK.into_response()
}
