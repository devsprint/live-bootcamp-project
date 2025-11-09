use crate::AppState;
use crate::domain::AuthAPIError;
use crate::utils::JWT_COOKIE_NAME;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use color_eyre::eyre::eyre;

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = jar.get(JWT_COOKIE_NAME);
    let cookie = match cookie {
        Some(c) => c,
        None => return Err(AuthAPIError::MissingToken),
    };

    let token = cookie.value().to_owned();
    let banned_token_store = state.banned_tokens.clone();

    let result = crate::utils::auth::validate_token(&token, banned_token_store).await;

    match result {
        Ok(_claims) => {
            let jar = jar.clone().remove(cookie.clone());
            let result = state.banned_tokens.write().await.ban_token(&token).await;
            if result.is_err() {
                return Err(AuthAPIError::UnexpectedError(eyre!("Failed to ban token.")));
            }
            Ok((jar, StatusCode::OK.into_response()))
        }
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
