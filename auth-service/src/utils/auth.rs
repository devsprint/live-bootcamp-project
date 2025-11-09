use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};
use crate::app_state::BannedTokenStoreType;
use crate::domain::Email;
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use color_eyre::eyre::{Context, eyre};
use color_eyre::{Report, eyre};
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, decode, encode};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GenerateTokenError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

pub const TOKEN_TTL_SECONDS: i64 = 600;

#[tracing::instrument(name = "GenerateAuthCookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> eyre::Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

#[tracing::instrument(name = "CreateAuthCookie", skip_all)]
fn create_auth_cookie(token: String) -> Cookie<'static> {
    Cookie::build((JWT_COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[tracing::instrument(name = "GenerateAuthToken", skip_all)]
fn generate_auth_token(email: &Email) -> eyre::Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS).ok_or(
        GenerateTokenError::UnexpectedError(eyre!("Failed to convert to seconds.")),
    )?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(GenerateTokenError::UnexpectedError(eyre!(
            "Failed to get curren time"
        )))?
        .timestamp();

    let exp: usize = exp
        .try_into()
        .map_err(|_| GenerateTokenError::UnexpectedError(eyre!("Failed to convert to usize.")))?;

    let sub = email.as_ref().to_owned();

    let claims = Claims {
        sub: sub.expose_secret().to_string(),
        exp,
    };

    create_token(&claims)
}

#[tracing::instrument(name = "ValidateToken", skip_all)]
pub async fn validate_token(
    token: Secret<String>,
    banned_token_store: BannedTokenStoreType,
) -> eyre::Result<Claims> {
    match banned_token_store
        .read()
        .await
        .is_token_banned(token.clone())
        .await
    {
        Ok(value) => {
            if value {
                return Err(eyre!("Token is banned"));
            }
        }
        Err(e) => {
            return Err(e.into());
        }
    }

    decode::<Claims>(
        token.expose_secret().as_str(),
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("Failed to decode token")
}

#[tracing::instrument(name = "CreateToken", skip_all)]
fn create_token(claims: &Claims) -> eyre::Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
    .wrap_err("failed to create token")
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use crate::{
        domain::BannedTokenStore, services::hashset_banned_token_store::HashSetBannedTokenStore,
    };

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let token = Secret::new(generate_auth_token(&email).unwrap());
        let banned_token_store: BannedTokenStoreType =
            Arc::new(RwLock::new(Box::new(HashSetBannedTokenStore::default())));
        let result = validate_token(token, banned_token_store).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = Secret::new("invalid_token".to_owned());
        let banned_token_store: BannedTokenStoreType =
            Arc::new(RwLock::new(Box::new(HashSetBannedTokenStore::default())));
        let result = validate_token(token, banned_token_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let token = Secret::new(generate_auth_token(&email).unwrap());
        let mut hs = HashSetBannedTokenStore::default();
        hs.ban_token(token.clone()).await.unwrap();
        let banned_token_store: BannedTokenStoreType = Arc::new(RwLock::new(Box::new(hs)));
        let result = validate_token(token, banned_token_store.clone()).await;
        assert!(result.is_err());
    }
}
