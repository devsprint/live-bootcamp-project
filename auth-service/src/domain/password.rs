use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Password(String);

impl TryFrom<&str> for Password {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
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
        let password: Result<Password, String> = val.as_str().try_into();
        assert!(password.is_ok());
    }

    #[test]
    fn test_password_too_short() {
        let val = "short";
        let password: Result<Password, String> = val.try_into();
        assert!(password.is_err());
    }

    impl Arbitrary for Password {
        fn arbitrary(_g: &mut quickcheck::Gen) -> Self {
            let password_string: String = FakePassword(8..20).fake();
            password_string.as_str().try_into().unwrap()
        }
    }

    quickcheck! {
        fn prop_password(password: Password) -> bool {
            let password_str = password.as_ref();
            password_str.len() >= 8
        }
    }
}
