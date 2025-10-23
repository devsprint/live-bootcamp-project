use crate::helpers::TestApp;
use auth_service::utils::JWT_COOKIE_NAME;
use reqwest::Url;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;
    let response = app.logout().await;
    let cookies = response.cookies();
    if cookies
        .filter(|c| c.name() == JWT_COOKIE_NAME)
        .any(|_| true)
    {
        panic!("JWT cookie should not be present");
    };
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.logout().await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;

    let test_email = "test_2@test.com";

    let test_case = serde_json::json!({
        "password": "password123",
        "email": test_email,
        "requires2FA": true
    });

    let response = app.post_signup(&test_case).await;
    assert_eq!(response.status().as_u16(), 201);


    // login to get valid cookie
    let login_response = app
        .post_login(
            &serde_json::json!({
                "email": test_email,
                "password": "password123"
            }),
        )
        .await;
    assert_eq!(login_response.status().as_u16(), 200);
    let response = app.logout().await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;

    let test_email = "test_2@test.com";

    let test_case = serde_json::json!({
        "password": "password123",
        "email": test_email,
        "requires2FA": true
    });

    let response = app.post_signup(&test_case).await;
    assert_eq!(response.status().as_u16(), 201);


    // login to get valid cookie
    let login_response = app
        .post_login(
            &serde_json::json!({
                "email": test_email,
                "password": "password123"
            }),
        )
        .await;
    assert_eq!(login_response.status().as_u16(), 200);
    let first_logout_response = app.logout().await;
    assert_eq!(first_logout_response.status().as_u16(), 200);
    let second_logout_response = app.logout().await;
    assert_eq!(second_logout_response.status().as_u16(), 400);
}