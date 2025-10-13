use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Password {
    pub hash: String,
}

impl TryFrom<&str> for Password {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }

        Ok(Self {
            hash: value.to_string(),
        })
    }
}
