use crate::domain::{AuthAPIError, Email, Password};
use crate::{AppState, domain};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use secrecy::Secret;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SignupResponse {
    pub message: String,
}

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email);
    if email.is_err() {
        return Err(AuthAPIError::InvalidCredentials);
    }
    let password = Password::parse(request.password);
    if password.is_err() {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user = domain::user::User::new(email.unwrap(), password.unwrap(), request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    match user_store.add_user(user).await {
        Err(domain::data_stores::UserStoreError::UserAlreadyExists) => {
            Err(AuthAPIError::UserAlreadyExists)
        }
        Err(e) => Err(AuthAPIError::UnexpectedError(e.into())),
        Ok(_) => {
            let response = SignupResponse {
                message: "User created successfully!".to_string(),
            };
            Ok((StatusCode::CREATED, Json(response)))
        }
    }
}
