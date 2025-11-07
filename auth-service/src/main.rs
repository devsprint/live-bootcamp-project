use auth_service::services::data_stores::postgres_user_store::PostgresUserStore;
use auth_service::services::data_stores::redis_banned_token_store::RedisBannedTokenStore;
use auth_service::services::{HashmapTwoFACodeStore, MockEmailClient};
use auth_service::utils::{DATABASE_URL, REDIS_HOST_NAME, prod};
use auth_service::{Application, get_postgres_pool, get_redis_client};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;
    let user_store = PostgresUserStore::new(pg_pool);
    let redis = Arc::new(RwLock::new(configure_redis()));
    let app_state = auth_service::AppState {
        user_store: Arc::new(RwLock::new(Box::new(user_store))),
        banned_tokens: Arc::new(RwLock::new(Box::new(RedisBannedTokenStore::new(redis)))),
        two_fa_code_store: Arc::new(RwLock::new(Box::new(HashmapTwoFACodeStore::new()))),
        email_client: Arc::new(RwLock::new(Box::new(MockEmailClient))),
    };

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
