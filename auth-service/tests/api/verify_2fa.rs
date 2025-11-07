use crate::helpers::TestApp;
use auth_service::domain::Email;
use axum::http::StatusCode;
use cleanup_db_macro::with_cleanup;
use serde_json::json;
use std::str::FromStr;

#[with_cleanup(app)]
#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let response = app
        .post_verify_2fa(&json!({ "message": "malformed input" }))
        .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[with_cleanup(app)]
#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let response = app
        .post_verify_2fa(&json!({
            "email": "invalid-email",
            "loginAttemptId": "some-id",
            "2FACode": "123456"
        }))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[with_cleanup(app)]
#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
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

#[with_cleanup(app)]
#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login request. This should fail.
    let app = TestApp::new().await;
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

#[with_cleanup(app)]
#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
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
        .get_code(&Email::from_str(email).unwrap())
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

#[with_cleanup(app)]
#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;
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
        .get_code(&Email::from_str(email).unwrap())
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
