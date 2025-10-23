use crate::helpers::TestApp;
use auth_service::utils::JWT_COOKIE_NAME;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_token(&serde_json::json!({
            "token": 12345
        }))
        .await;
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;
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
            "password": "password123"
        }))
        .await;
    assert_eq!(response.status().as_u16(), 200);

    // First, we need to obtain a valid token. This usually involves logging in.
    let token = response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("Auth token cookie not found")
        .value()
        .to_string();

    let response = app
        .post_verify_token(&serde_json::json!({
            "token": token
        }))
        .await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_token(&serde_json::json!({
            "token": "invalid_token_example"
        }))
        .await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

    let test_email = "test@test.com";
    let test_case = serde_json::json!({
        "password": "password123",
        "email": test_email,
        "requires2FA": true
    });
    let response = app.post_signup(&test_case).await;
    assert_eq!(response.status().as_u16(), 201);
    // login to get valid cookie
    let login_response = app
        .post_login(&serde_json::json!({
            "email": test_email,
            "password": "password123"
        }))
        .await;
    assert_eq!(login_response.status().as_u16(), 200);

    let token = login_response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("Auth token cookie not found")
        .value()
        .to_string();
    // logout to ban the token
    let logout_response = app.logout().await;
    assert_eq!(logout_response.status().as_u16(), 200);
    let response = app
        .post_verify_token(&serde_json::json!({
            "token": token
        }))
        .await;
    assert_eq!(response.status().as_u16(), 401);
}
