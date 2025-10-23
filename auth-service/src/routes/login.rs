use crate::domain::{AuthAPIError, Email, Password, UserStoreError};
use crate::utils::auth::generate_auth_cookie;
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;
use std::str::FromStr;

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

impl LoginRequest {
    pub fn new(email: String, password: String) -> LoginRequest {
        LoginRequest { email, password }
    }

    pub fn email(&self) -> &str {
        &self.email
    }
    pub fn password(&self) -> &str {
        &self.password
    }
}
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(credentials): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email =
        Email::from_str(&credentials.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::from_str(&credentials.password).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let user_store = &state.user_store.read().await;
    user_store
        .validate_user(&email, &password)
        .await
        .map_err(|err| match err {
            UserStoreError::InvalidCredentials => AuthAPIError::IncorrectCredentials,
            _ => AuthAPIError::UnexpectedError,
        })?;

    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let auth_cookie = generate_auth_cookie("test")
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK.into_response()))
}
