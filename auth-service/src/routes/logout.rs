use crate::domain::AuthAPIError;
use crate::utils::JWT_COOKIE_NAME;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;

pub async fn logout(jar: CookieJar) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = jar.get(JWT_COOKIE_NAME);
    let cookie = match cookie {
        Some(c) => c,
        None => return Err(AuthAPIError::MissingToken),
    };

    let token = cookie.value().to_owned();

    let result = crate::utils::auth::validate_token(&token).await;

    match result {
        Ok(valid) => {
            if !valid {
                Err(AuthAPIError::InvalidToken)
            } else {
                let jar = jar.clone().remove(cookie.clone());
                Ok((jar, StatusCode::OK.into_response()))
            }
        }
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
