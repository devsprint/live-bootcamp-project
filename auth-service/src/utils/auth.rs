use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};
use axum_extra::extract::cookie::Cookie;

pub async fn generate_auth_cookie<'a>(token: &'a str) -> Result<Cookie<'a>, String> {
    Ok(Cookie::new(JWT_COOKIE_NAME, token.to_owned()))
}

pub async fn validate_token(token: &str) -> Result<bool, String> {
    // In a real implementation, you would decode and validate the JWT token here.
    // For simplicity, we will just check if the token matches a predefined secret.
    if token.to_owned().eq_ignore_ascii_case("test") {
        Ok(true)
    } else {
        Ok(false)
    }
}
