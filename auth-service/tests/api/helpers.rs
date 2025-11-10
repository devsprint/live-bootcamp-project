use auth_service::domain::{Email, EmailClient, UserStore};
use auth_service::services::PostmarkEmailClient;
use auth_service::services::data_stores::postgres_user_store::PostgresUserStore;
use auth_service::utils::{DATABASE_URL, REDIS_HOST_NAME, test};
use auth_service::{Application, get_postgres_pool};
use redis::ConnectionLike;
use reqwest::Client;
use reqwest::cookie::Jar;
use secrecy::{ExposeSecret, Secret};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::cell::Cell;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;
use wiremock::MockServer;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub state: auth_service::AppState,
    pub email_server: MockServer,
    pub database_name: String,
    pub clean_up_called: Cell<bool>,
}

impl TestApp {
    pub async fn new() -> Self {
        let cookie_jar = Arc::new(Jar::default());
        let pg_pool = configure_postgresql().await;
        let database_name = pg_pool
            .connect_options()
            .get_database()
            .unwrap()
            .to_string();
        let redis = auth_service::get_redis_client(REDIS_HOST_NAME.to_owned())
            .expect("Failed to get Redis client")
            .get_connection()
            .expect("Failed to get Redis connection");
        debug!("Using Redis at: {:?}", redis.is_open());

        let email_server = MockServer::start().await; // New!
        let base_url = email_server.uri(); // New!
        let email_client: Arc<RwLock<Box<dyn EmailClient>>> = Arc::new(RwLock::new(Box::new(
            configure_postmark_email_client(base_url),
        ))); // Updated!

        let redis = Arc::new(RwLock::new(redis));

        let user_store: Arc<RwLock<Box<dyn UserStore>>> =
            Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool))));
        let app_state = auth_service::AppState {
            user_store,
            banned_tokens: Arc::new(RwLock::new(Box::new(
                auth_service::services::RedisBannedTokenStore::new(redis.clone()),
            ))),
            two_fa_code_store: Arc::new(RwLock::new(Box::new(
                auth_service::services::RedisTwoFACodeStore::new(redis),
            ))),
            email_client,
        };

        let app = Application::build(app_state.clone(), test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap(); // Create a Reqwest http client instance

        // Create new `TestApp` instance and return it
        TestApp {
            address,
            cookie_jar,
            http_client,
            state: app_state,
            email_server,
            database_name,
            clean_up_called: Cell::new(false),
        }
    }

    pub fn state(&self) -> &auth_service::AppState {
        &self.state
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

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
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

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn cleanup(&self) {
        self.clean_up_called.set(true);
        delete_database(&self.database_name).await;
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called.get() {
            panic!(
                "TestApp cleanup() was not called before dropping the instance. \
                Please ensure to call cleanup() to avoid leaking test databases."
            );
        }
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql() -> PgPool {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    // We are creating a new database for each test case, and we need to ensure each database has a unique name!
    let db_name = Uuid::new_v4().to_string();

    configure_database(&postgresql_conn_url.expose_secret().as_ref(), &db_name).await;

    let postgresql_conn_url_with_db = format!(
        "{}/{}",
        postgresql_conn_url.expose_secret().as_str(),
        db_name
    );

    // Create a new connection pool and return it
    get_postgres_pool(&Secret::new(postgresql_conn_url_with_db))
        .await
        .expect("Failed to create Postgres connection pool!")
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    info!("Connecting to {}", db_conn_string);
    // Create database connection
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");

    // Connect to new database
    let db_conn_string = format!("{}/{}", db_conn_string, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url: String = DATABASE_URL.to_owned().expose_secret().to_string();

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill any active connections to the database
    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
        "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    // Drop the database
    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}

fn configure_postmark_email_client(base_url: String) -> PostmarkEmailClient {
    let postmark_auth_token = Secret::new("auth_token".to_owned());

    let sender = Email::parse(Secret::new(test::email_client::SENDER.to_owned())).unwrap();

    let http_client = Client::builder()
        .timeout(test::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(base_url, sender, postmark_auth_token, http_client)
}
