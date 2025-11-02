use auth_service::services::data_stores::postgres_user_store::PostgresUserStore;
use auth_service::services::{HashSetBannedTokenStore, HashmapTwoFACodeStore, MockEmailClient};
use auth_service::utils::{prod, DATABASE_URL};
use auth_service::{get_postgres_pool, Application};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;
    let user_store = PostgresUserStore::new(pg_pool);
    let app_state = auth_service::AppState {
        user_store: Arc::new(RwLock::new(Box::new(user_store))),
        banned_tokens: Arc::new(RwLock::new(Box::new(HashSetBannedTokenStore::default()))),
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
