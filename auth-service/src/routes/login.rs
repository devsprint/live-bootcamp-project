use std::str::FromStr;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use crate::AppState;
use crate::domain::{AuthAPIError, Email, Password, UserStoreError};

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
pub async fn login(State(state): State<AppState>,  Json(credentials): Json<LoginRequest>) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::from_str(&credentials.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::from_str(&credentials.password).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let user_store = &state.user_store.read().await;
    user_store.validate_user(&email, &password).await.map_err(|err| {
        match err {
            UserStoreError::InvalidCredentials => AuthAPIError::IncorrectCredentials,
            _ => AuthAPIError::UnexpectedError,
        }
    })?;


    Ok(StatusCode::OK.into_response())
}
