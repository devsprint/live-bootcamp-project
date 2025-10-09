use crate::helpers::TestApp;

#[tokio::test]
async fn signup_returns_200() {
    let app = TestApp::new().await;

    let response = app.signup("testuser", "password").await;

    assert_eq!(response.status().as_u16(), 200);
}
