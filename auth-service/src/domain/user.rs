use crate::domain::{Email, Password};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct User {
    pub email: Email,
    pub password: Password,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

impl User {
    /// Creates a new `User` instance.
    #[must_use]
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        Self {
            email,
            password,
            requires_2fa,
        }
    }
}
