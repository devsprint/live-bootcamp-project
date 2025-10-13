use crate::domain::{AuthAPIError, Email, Password};
use crate::{domain, AppState};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SignupResponse {
    pub message: String,
}

#[axum::debug_handler]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email: Result<Email, String> = request.email.trim().try_into();
    if email.is_err() {
        return Err(AuthAPIError::InvalidCredentials);
    }
    let password: Result<Password, String> = request.password.trim().try_into();
    if password.is_err() {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user = domain::user::User::new(email.unwrap(), password.unwrap(), request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    if let Ok(_stored_user) = user_store.add_user(user).await {
        let response = Json(SignupResponse {
            message: "User created successfully!".to_string(),
        });

        Ok((StatusCode::CREATED, response))
    } else {
        Err(AuthAPIError::UserAlreadyExists)
    }
}
