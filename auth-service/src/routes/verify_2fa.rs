use crate::AppState;
use crate::domain::AuthAPIError;
use crate::utils::auth::generate_auth_cookie;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use std::str::FromStr;

#[derive(serde::Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email = match crate::domain::Email::from_str(&request.email) {
        Ok(email) => email,
        Err(_) => return Err(AuthAPIError::InvalidCredentials),
    };

    let login_attempt_id_from_request =
        crate::domain::LoginAttemptId::new(request.login_attempt_id);
    let two_fa_code_from_request = match crate::domain::TwoFACode::parse(request.two_fa_code) {
        Ok(code) => code,
        Err(_) => return Err(AuthAPIError::InvalidCredentials),
    };

    let two_fa_code_store = state.two_fa_code_store.write().await;
    let (login_attempt_id, two_fa_code) = match two_fa_code_store.get_code(&email).await {
        Ok(code) => code,
        Err(_) => return Err(AuthAPIError::IncorrectCredentials),
    };

    if login_attempt_id != login_attempt_id_from_request || two_fa_code != two_fa_code_from_request
    {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    drop(two_fa_code_store);

    let auth_cookie =
        generate_auth_cookie(&email).map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    let updated_jar = jar.add(auth_cookie);
    state
        .two_fa_code_store
        .write()
        .await
        .remove_code(&email)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    Ok((updated_jar, StatusCode::OK.into_response()))
}
