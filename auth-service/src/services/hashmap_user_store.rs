use crate::domain::{User, UserStore, UserStoreError};
use async_trait::async_trait;
use std::collections::HashMap;

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
}

#[async_trait]
impl UserStore for HashmapUserStore {
    /// Adds a new user to the store.
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if Some(&user) == self.users.get(&user.email.value) {
            return Err(UserStoreError::UserAlreadyExists);
        } else {
            self.users.insert(user.email.value.clone(), user);
        }

        Ok(())
    }

    /// Retrieves a user by email.
    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    /// Validates user credentials.
    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) => {
                if user.password.hash == password {
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
        let email = "test@test.com".try_into().unwrap();
        let password = "password".try_into().unwrap();
        let user = User::new(email, password, false);
        assert_eq!(store.add_user(user.clone()).await, Ok(()));
        assert_eq!(
            store.add_user(user).await,
            Err(UserStoreError::UserAlreadyExists)
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::new();
        let email = "test@test.com".try_into().unwrap();
        let password = "password".try_into().unwrap();
        let user = User::new(email, password, false);
        store.add_user(user.clone()).await.unwrap();
        assert_eq!(store.get_user("test@test.com").await, Ok(user));
        assert_eq!(
            store.get_user("t@test.com").await,
            Err(UserStoreError::UserNotFound)
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::new();
        let email = "test@test.com".try_into().unwrap();
        let password = "password".try_into().unwrap();

        let user = User::new(email, password, false);
        store.add_user(user).await.unwrap();
        assert_eq!(
            store.validate_user("test@test.com", "password").await,
            Ok(())
        );
        assert_eq!(
            store.validate_user("test@test.com", "wrong").await,
            Err(UserStoreError::InvalidCredentials)
        );
        assert_eq!(
            store.validate_user("t@test.com", "password").await,
            Err(UserStoreError::UserNotFound)
        );
    }
}
