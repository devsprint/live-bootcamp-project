use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore};
use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

impl HashmapTwoFACodeStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }
}

#[async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), crate::domain::TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(
        &mut self,
        email: &Email,
    ) -> Result<(), crate::domain::TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), crate::domain::TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some((login_attempt_id, code)) => Ok((login_attempt_id.clone(), code.clone())),
            None => Err(crate::domain::TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HashmapTwoFACodeStore;
    use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore};

    use secrecy::Secret;

    #[tokio::test]
    async fn test_hashmap_two_fa_code_store() {
        let mut store = HashmapTwoFACodeStore::new();

        let email = Email::parse(Secret::new("test@test.com".to_string())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        // Add code
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        // Get code
        let (retrieved_login_attempt_id, retrieved_code) = store.get_code(&email).await.unwrap();
        assert_eq!(retrieved_login_attempt_id, login_attempt_id);
        assert_eq!(retrieved_code, code);
        // Remove code
        store.remove_code(&email).await.unwrap();
        let result = store.get_code(&email).await;
        assert!(matches!(
            result,
            Err(crate::domain::TwoFACodeStoreError::LoginAttemptIdNotFound)
        ));
    }
}
