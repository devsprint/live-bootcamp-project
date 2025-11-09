use crate::AppState;
use crate::domain::{AuthAPIError, Email, LoginAttemptId, Password, TwoFACode, UserStoreError};
use crate::utils::auth::generate_auth_cookie;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use color_eyre::eyre::eyre;
use secrecy::Secret;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct LoginRequest {
    email: Secret<String>,
    password: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

impl LoginRequest {
    pub fn new(email: String, password: String) -> LoginRequest {
        LoginRequest {
            email: Secret::new(email),
            password: Secret::new(password),
        }
    }

    pub fn email(&self) -> &Secret<String> {
        &self.email
    }
    pub fn password(&self) -> &Secret<String> {
        &self.password
    }
}

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(credentials): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email = Email::parse(credentials.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password =
        Password::parse(credentials.password).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let user_store = &state.user_store.read().await;
    user_store
        .validate_user(&email, &password)
        .await
        .map_err(|err| match err {
            UserStoreError::InvalidCredentials => AuthAPIError::IncorrectCredentials,
            err => AuthAPIError::UnexpectedError(err.into()),
        })?;

    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return Err(AuthAPIError::IncorrectCredentials),
    };

    match user.requires_2fa {
        true => handle_2fa(&email, &state, jar)
            .await
            .map(|(jar, resp)| (jar, (StatusCode::PARTIAL_CONTENT, resp))),
        false => handle_no_2fa(&user.email, jar)
            .await
            .map(|(jar, resp)| (jar, (StatusCode::OK, resp))),
    }
}

#[tracing::instrument(name = "HandleNo2FA", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> Result<(CookieJar, Json<LoginResponse>), AuthAPIError> {
    let auth_cookie = generate_auth_cookie(email).map_err(AuthAPIError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, Json(LoginResponse::RegularAuth)))
}

#[tracing::instrument(name = "Handle2FA", skip_all)]
async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> Result<(CookieJar, Json<LoginResponse>), AuthAPIError> {
    // TODO: Return a TwoFactorAuthResponse. The message should be "2FA required".
    // The login attempt ID should be "123456". We will replace this hard-coded login attempt ID soon!
    // First, we must generate a new random login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    // TODO: Store the ID and code in our 2FA code store. Return `AuthAPIError::UnexpectedError` if the operation fails
    state
        .two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    state
        .email_client
        .write()
        .await
        .send_email(email, "2FA code", two_fa_code.as_ref())
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(eyre!(e)))?;
    // Finally, we need to return the login attempt ID to the client
    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().to_string(), // Add the generated login attempt ID
    }));

    Ok((jar, response))
}
