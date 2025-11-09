use crate::helpers::{TestApp, get_random_email};
use auth_service::domain::Email;
use auth_service::routes::TwoFactorAuthResponse;
use auth_service::utils::JWT_COOKIE_NAME;
use cleanup_db_macro::api_test;
use secrecy::Secret;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[api_test]
async fn should_return_422_if_malformed_credentials() {
    let response = app
        .post_login(&serde_json::json!({
            "username": "testuser"
        }))
        .await;
    assert_eq!(response.status().as_u16(), 422);
}

#[api_test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message.
    let response = app
        .post_login(&serde_json::json!({
            "email": "invalid-email",
            "password": "short"
        }))
        .await;
    assert_eq!(response.status().as_u16(), 400);
}

#[api_test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message
    let test_email = "test_2@test.com";

    let test_case = serde_json::json!({
        "password": "password123",
        "email": test_email,
        "requires2FA": true
    });

    let response = app.post_signup(&test_case).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app
        .post_login(&serde_json::json!({
            "email": test_email,
            "password": "wrongpassword"
        }))
        .await;
    assert_eq!(response.status().as_u16(), 401);
}

#[api_test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[api_test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email")) // Expect an HTTP request to the "/email" path
        .and(method("POST")) // Expect the HTTP method to be POST
        .respond_with(ResponseTemplate::new(200)) // Respond with an HTTP 200 OK status
        .expect(1) // Expect this request to be made exactly once
        .mount(&app.email_server) // Mount this expectation on the mock email server
        .await; // Await the asynchronous operation to ensure the mock server is set up before proceeding

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Unexpected response");
    assert_eq!(two_fa_response.message, "2FA required".to_owned());

    let (attempt_id, _) = app
        .state
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.to_string())).unwrap())
        .await
        .expect("2FA code should be stored");
    assert_eq!(two_fa_response.login_attempt_id, attempt_id.as_ref());
}
