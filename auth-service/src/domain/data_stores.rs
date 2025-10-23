use crate::domain::{Email, Password, User};
use async_trait::async_trait;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TokenStoreError {
    TokenNotFound,
    TokenAlreadyBanned,
    UnexpectedError,
}
#[async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn ban_token(&mut self, token: &str) -> Result<(), TokenStoreError>;
    async fn is_token_banned(&self, token: &str) -> Result<bool, TokenStoreError>;
}
