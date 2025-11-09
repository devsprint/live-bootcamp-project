use crate::domain::Email;
use async_trait::async_trait;
use color_eyre::eyre;

#[async_trait]
pub trait EmailClient: Send + Sync {
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str)
    -> eyre::Result<()>;
}
