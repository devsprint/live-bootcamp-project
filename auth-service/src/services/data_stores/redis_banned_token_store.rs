use async_trait::async_trait;
use color_eyre::eyre::Context;
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
    #[tracing::instrument(name = "BanToken", skip_all)]

    async fn ban_token(&mut self, token: &str) -> Result<(), TokenStoreError> {
        let key = get_key(token);
        let value = true;
        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .wrap_err("failed to cast TOKEN_TTL_SECONDS to u64")
            .map_err(TokenStoreError::UnexpectedError)?;
        let mut conn = self.conn.write().await;
        let _: () = conn
            .set_ex(&key, value, ttl)
            .wrap_err("failed to set banned token in Redis")
            .map_err(TokenStoreError::UnexpectedError)?;

        Ok(())
    }

    #[tracing::instrument(name = "IsTokenBanned", skip_all)]
    async fn is_token_banned(&self, token: &str) -> Result<bool, TokenStoreError> {
        let key = get_key(token);
        let mut conn = self.conn.write().await;
        let exists: bool = conn
            .exists(key)
            .wrap_err("failed to check if token exists in Redis")
            .map_err(TokenStoreError::UnexpectedError)?;
        Ok(exists)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
