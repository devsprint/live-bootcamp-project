use async_trait::async_trait;
use redis::{Commands, Connection};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::TokenStoreError;
use crate::{domain::data_stores::BannedTokenStore, utils::auth::TOKEN_TTL_SECONDS};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn ban_token(&mut self, token: &str) -> Result<(), TokenStoreError> {
        let key = get_key(token);
        let value = true;
        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .map_err(|_| TokenStoreError::UnexpectedError)?;
        let mut conn = self.conn.write().await;
        let _: () = conn
            .set_ex(&key, value, ttl)
            .map_err(|_| TokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn is_token_banned(&self, token: &str) -> Result<bool, TokenStoreError> {
        let key = get_key(token);
        let mut conn = self.conn.write().await;
        let exists: bool = conn
            .exists(key)
            .map_err(|_| TokenStoreError::UnexpectedError)?;
        Ok(exists)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
