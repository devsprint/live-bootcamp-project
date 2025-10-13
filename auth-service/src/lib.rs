use std::error::Error;

pub use crate::app_state::AppState;
use crate::domain::AuthAPIError;
use crate::routes::{login, logout, signup, verify_2fa, verify_token};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, serve::Serve};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

mod domain;
pub mod routes;

mod app_state;
pub mod services;

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub fn new(server: Serve<TcpListener, Router, Router>, address: String) -> Self {
        Self { server, address }
    }

    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        let router = Router::new()
            .fallback_service(ServeDir::new("assets"))
            .route("/signup", axum::routing::post(signup))
            .route("/login", axum::routing::post(login))
            .route("/logout", axum::routing::post(logout))
            .route("/verify-2fa", axum::routing::post(verify_2fa))
            .route("/verify-token", axum::routing::post(verify_token))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Self::new(server, address))
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
