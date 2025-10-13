use crate::domain::User;
use std::pin::Pin;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

pub trait UserStore: Send + Sync {
    fn add_user<'a>(
        &'a mut self,
        user: User,
    ) -> Pin<Box<dyn Future<Output = Result<(), UserStoreError>> + Send + 'a>>;
    fn get_user<'a>(
        &'a self,
        email: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<User, UserStoreError>> + Send + 'a>>;
    fn validate_user<'a>(
        &'a self,
        email: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), UserStoreError>> + Send + 'a>>;
}
