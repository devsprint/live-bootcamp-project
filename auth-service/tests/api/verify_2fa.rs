use crate::helpers::TestApp;
use auth_service::domain::Email;
use axum::http::StatusCode;
use cleanup_db_macro::api_test;
use secrecy::Secret;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[api_test]
async fn should_return_422_if_malformed_input() {
    let response = app
        .post_verify_2fa(&json!({ "message": "malformed input" }))
        .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[api_test]
async fn should_return_400_if_invalid_input() {
    let response = app
        .post_verify_2fa(&json!({
            "email": "invalid-email",
            "loginAttemptId": "some-id",
            "2FACode": "123456"
        }))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[api_test]
async fn should_return_401_if_incorrect_credentials() {
    let email = "test@tes.com";

    // First, sign up a user who requires 2FA
    let signup_response = app
        .post_signup(&json!({
            "email": email,
            "password": "StrongPassword123!",
            "requires2FA": true
        }))
        .await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    // Next, attempt to log in to get a loginAttemptId
    let login_response = app
        .post_login(&json!({
            "email": email,
            "password": "StrongPassword123!"
        }))
        .await;
    assert_eq!(login_response.status(), StatusCode::PARTIAL_CONTENT);
    let login_body: serde_json::Value = login_response.json().await.unwrap();
    let login_attempt_id = login_body["loginAttemptId"].as_str().unwrap();
    // Now, attempt to verify 2FA with an incorrect code
    let verify_response = app
        .post_verify_2fa(&json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": "000000"  // Assuming this is an incorrect code
        }))
        .await;
    assert_eq!(verify_response.status(), StatusCode::UNAUTHORIZED);
}

#[api_test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login request. This should fail.
    let email = "test@test.com";
    // First, sign up a user who requires 2FA
    let signup_response = app
        .post_signup(&json!({
            "email": email,
            "password": "StrongPassword123!",
            "requires2FA": true
        }))
        .await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;
    // Next, attempt to log in to get the first loginAttemptId
    let first_login_response = app
        .post_login(&json!({
            "email": email,
            "password": "StrongPassword123!"
        }))
        .await;
    assert_eq!(first_login_response.status(), StatusCode::PARTIAL_CONTENT);
    let first_login_body: serde_json::Value = first_login_response.json().await.unwrap();
    let first_login_attempt_id = first_login_body["loginAttemptId"].as_str().unwrap();
    // Log in a second time to get a new loginAttemptId
    let second_login_response = app
        .post_login(&json!({
            "email": email,
            "password": "StrongPassword123!"
        }))
        .await;
    assert_eq!(second_login_response.status(), StatusCode::PARTIAL_CONTENT);
    let second_login_body: serde_json::Value = second_login_response.json().await.unwrap();
    let _second_login_attempt_id = second_login_body["loginAttemptId"].as_str().unwrap();
    // Now, attempt to verify 2FA with the old code from the first login
    let verify_response = app
        .post_verify_2fa(&json!({
            "email": email,
            "loginAttemptId": first_login_attempt_id,
            "2FACode": "123456"  // Assuming this is the code from the first login
        }))
        .await;
    assert_eq!(verify_response.status(), StatusCode::UNAUTHORIZED);
}

#[api_test]
async fn should_return_200_if_correct_code() {
    let email = "test@test.com";
    // First, sign up a user who requires 2FA
    let signup_response = app
        .post_signup(&json!({
            "email": email,
            "password": "StrongPassword123!",
            "requires2FA": true
        }))
        .await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    // Next, attempt to log in to get a loginAttemptId
    let login_response = app
        .post_login(&json!({
            "email": email,
            "password": "StrongPassword123!"
        }))
        .await;
    assert_eq!(login_response.status(), StatusCode::PARTIAL_CONTENT);
    let login_body: serde_json::Value = login_response.json().await.unwrap();
    let login_attempt_id = login_body["loginAttemptId"].as_str().unwrap();

    let two_fa_code_store = app.state().two_fa_code_store.write().await;
    let (_stored_login_attempt_id, stored_code) = two_fa_code_store
        .get_code(&Email::parse(Secret::new(email.to_string())).unwrap())
        .await
        .unwrap();
    drop(two_fa_code_store); // Release the write lock
    // Now, attempt to verify 2FA with the correct code
    let verify_response = app
        .post_verify_2fa(&json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": stored_code.as_ref()  // Assuming this is the correct code
        }))
        .await;
    assert_eq!(verify_response.status(), StatusCode::OK);
}

#[api_test]
async fn should_return_401_if_same_code_twice() {
    let email = "test@test.com";
    // First, sign up a user who requires 2FA
    let signup_response = app
        .post_signup(&json!({
            "email": email,
            "password": "StrongPassword123!",
            "requires2FA": true
        }))
        .await;
    assert_eq!(signup_response.status(), StatusCode::CREATED);
    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;
    // Next, attempt to log in to get a loginAttemptId
    let login_response = app
        .post_login(&json!({
            "email": email,
            "password": "StrongPassword123!"
        }))
        .await;
    assert_eq!(login_response.status(), StatusCode::PARTIAL_CONTENT);
    let login_body: serde_json::Value = login_response.json().await.unwrap();
    let login_attempt_id = login_body["loginAttemptId"].as_str().unwrap();
    let two_fa_code_store = app.state().two_fa_code_store.write().await;
    let (_stored_login_attempt_id, stored_code) = two_fa_code_store
        .get_code(&Email::parse(Secret::new(email.to_string())).unwrap())
        .await
        .unwrap();
    drop(two_fa_code_store); // Release the write lock
    // Now, attempt to verify 2FA with the correct code
    let verify_response = app
        .post_verify_2fa(&json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": stored_code.as_ref()  // Assuming this is the correct code
        }))
        .await;
    assert_eq!(verify_response.status(), StatusCode::OK);
    // Attempt to verify 2FA again with the same code
    let second_verify_response = app
        .post_verify_2fa(&json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": stored_code.as_ref()  // Same code as before
        }))
        .await;
    assert_eq!(second_verify_response.status(), StatusCode::UNAUTHORIZED);
}
