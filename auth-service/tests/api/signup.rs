use crate::helpers::{TestApp, get_random_email};
use auth_service::ErrorResponse;
use auth_service::routes::SignupResponse;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "password": "",
            "requires2FA": true
        }),
        serde_json::json!({
            "password": "password123",
            "email": random_email,
        }),
        serde_json::json!({
            "password": "password123",
            "email": random_email,
            "requires2FA": "not_a_boolean"
        }),
        serde_json::json!({
            "password": "password123",
            "email": random_email,
            "requires2FA": null
        }),
        serde_json::json!({}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await; // call `post_signup`
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let test_case = serde_json::json!({
        "password": "password123",
        "email": "test_2@test.com",
        "requires2FA": true
    });

    let response = app.post_signup(&test_case).await;
    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "password": "",
            "email": "test@test.com",
            "requires2FA": true
        }),
        serde_json::json!({
            "password": "password123",
            "email": "",
            "requires2FA": false
        }),
        serde_json::json!({
            "password": "password123",
            "email": "test",
            "requires2FA": true
        }),
        serde_json::json!({
            "password": "passwor",
            "email": "test2@test.com",
            "requires2FA": false
        }),
    ];

    for i in test_cases.iter() {
        let response = app.post_signup(i).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", i);

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let test_case = serde_json::json!({
        "password": "password123",
        "email": "test_mail@test.com",
        "requires2FA": true
    });
    let response = app.post_signup(&test_case).await;
    assert_eq!(response.status().as_u16(), 201);
    let response = app.post_signup(&test_case).await;

    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}
