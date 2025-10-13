use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    /// Creates a new `HashmapUserStore` instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// Adds a new user to the store.
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if Some(&user) == self.users.get(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        } else {
            self.users.insert(user.email.clone(), user);
        }

        Ok(())
    }

    /// Retrieves a user by email.
    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    /// Validates user credentials.
    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) => {
                if user.password == password {
                    Ok(())
                } else {
                    Err(UserStoreError::InvalidCredentials)
                }
            }
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::new();
        let user = User::new("test@test.com".to_string(), "password".to_string(), false);
        assert_eq!(store.add_user(user.clone()), Ok(()));
        assert_eq!(store.add_user(user), Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::new();
        let user = User::new("test@test.com".to_string(), "password".to_string(), false);
        store.add_user(user.clone()).unwrap();
        assert_eq!(store.get_user("test@test.com"), Ok(user));
        assert_eq!(
            store.get_user("t@test.com"),
            Err(UserStoreError::UserNotFound)
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::new();
        let user = User::new("test@test.com".to_string(), "password".to_string(), false);
        store.add_user(user).unwrap();
        assert_eq!(store.validate_user("test@test.com", "password"), Ok(()));
        assert_eq!(
            store.validate_user("test@test.com", "wrong"),
            Err(UserStoreError::InvalidCredentials)
        );
        assert_eq!(
            store.validate_user("t@test.com", "password"),
            Err(UserStoreError::UserNotFound)
        );
    }
}
