use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Email {
    pub value: String,
}

impl TryFrom<&str> for Email {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.contains('@') {
            Ok(Self {
                value: value.to_string(),
            })
        } else if value.trim().is_empty() {
            Err("Email is empty".to_string())
        } else {
            Err("Invalid email format".to_string())
        }
    }
}
