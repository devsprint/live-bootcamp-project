use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Password(String);

impl FromStr for Password {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }

        Ok(Self(value.to_string()))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::quickcheck;
    use quickcheck::Arbitrary;

    #[test]
    fn test_password_valid() {
        let val: String = FakePassword(8..20).fake();
        let password: Result<Password, String> = Password::from_str(val.as_str());
        assert!(password.is_ok());
    }

    #[test]
    fn test_password_too_short() {
        let val = "short";
        let password: Result<Password, String> = Password::from_str(val);
        assert!(password.is_err());
    }

    impl Arbitrary for Password {
        fn arbitrary(_g: &mut quickcheck::Gen) -> Self {
            let password_string: String = FakePassword(8..20).fake();
            Password::from_str(password_string.as_str()).unwrap()
        }
    }

    quickcheck! {
        fn prop_password(password: Password) -> bool {
            let password_str = password.as_ref();
            password_str.len() >= 8
        }
    }
}
