use auth_service::services::HashmapUserStore;
use auth_service::Application;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store = HashmapUserStore::new();
        let app_state = auth_service::AppState {
            user_store: Arc::new(RwLock::new(user_store)),
        };

        let app = Application::build(app_state, "127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::new(); // Create a Reqwest http client instance

        // Create new `TestApp` instance and return it
        TestApp {
            address,
            http_client,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn login(&self, username: &str, password: &str) -> reqwest::Response {
        let login_body = serde_json::json!({
            "username": username,
            "password": password,
        });

        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(&login_body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn verify_2fa(&self, token: &str) -> reqwest::Response {
        let verify_2fa_body = serde_json::json!({
            "token": token,
        });

        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(&verify_2fa_body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
    pub async fn verify_token(&self, token: &str) -> reqwest::Response {
        let verify_token_body = serde_json::json!({
            "token": token,
        });

        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .json(&verify_token_body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
