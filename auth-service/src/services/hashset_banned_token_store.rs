use crate::domain::BannedTokenStore;
use async_trait::async_trait;
use std::collections::HashSet;

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct HashSetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

impl HashSetBannedTokenStore {
    /// Creates a new `HashSetBannedTokenStore` instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            banned_tokens: HashSet::new(),
        }
    }
}

#[async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    /// Bans a token by adding it to the store.
    async fn ban_token(&mut self, token: &str) -> Result<(), crate::domain::TokenStoreError> {
        if self.banned_tokens.contains(token) {
            return Err(crate::domain::TokenStoreError::TokenAlreadyBanned);
        }
        self.banned_tokens.insert(token.to_string());
        Ok(())
    }

    /// Checks if a token is banned.
    async fn is_token_banned(&self, token: &str) -> Result<bool, crate::domain::TokenStoreError> {
        Ok(self.banned_tokens.contains(token))
    }
}
