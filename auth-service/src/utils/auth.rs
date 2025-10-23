use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};
use axum_extra::extract::cookie::Cookie;

pub async fn generate_auth_cookie<'a>(token: &'a str) -> Result<Cookie<'a>, String> {
    Ok(Cookie::new(JWT_COOKIE_NAME, token.to_owned()))
}
