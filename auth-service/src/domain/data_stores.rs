use crate::domain::{Email, Password, User};
use async_trait::async_trait;
use color_eyre::eyre::{Context, eyre};
use color_eyre::{Report, eyre};
use rand::random;
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password)
    -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
pub enum TokenStoreError {
    #[error("Token not found")]
    TokenNotFound,
    #[error("Token already banned")]
    TokenAlreadyBanned,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TokenStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::TokenNotFound, Self::TokenNotFound)
                | (Self::TokenAlreadyBanned, Self::TokenAlreadyBanned)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn ban_token(&mut self, token: Secret<String>) -> Result<(), TokenStoreError>;
    async fn is_token_banned(&self, token: Secret<String>) -> Result<bool, TokenStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(Secret<String>);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0.expose_secret()
    }
}

// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore: Send + Sync {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

impl LoginAttemptId {
    pub fn parse(id: String) -> eyre::Result<Self> {
        // Use the `parse_str` function from the `uuid` crate to ensure `id` is a valid UUID
        Uuid::parse_str(&id)
            .wrap_err("Invalid login attempt id")
            .map(|_| LoginAttemptId(Secret::new(id)))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Secret::new(Uuid::new_v4().to_string()))
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(Secret<String>);

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl TwoFACode {
    pub fn parse(code: String) -> eyre::Result<Self> {
        let code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?;

        if (000_000..=999_999).contains(&code_as_u32) {
            Ok(Self(Secret::new(code)))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        let code: String = (0..6)
            .map(|_| random::<u8>() % 10)
            .map(|digit| digit.to_string())
            .collect();
        TwoFACode(Secret::new(code))
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0.expose_secret()
    }
}
