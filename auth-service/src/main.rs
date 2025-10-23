use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::utils::prod;
use auth_service::Application;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = HashmapUserStore::new();
    let app_state = auth_service::AppState {
        user_store: Arc::new(RwLock::new(Box::new(user_store))),
    };

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
