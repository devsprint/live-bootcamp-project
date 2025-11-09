use color_eyre::eyre;
use color_eyre::eyre::eyre;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Password(Secret<String>);

impl Password {
    pub fn parse(s: Secret<String>) -> eyre::Result<Password> {
        if validate_password(&s) {
            Ok(Self(s))
        } else {
            Err(eyre!("Failed to parse string to a Password type"))
        }
    }
}

fn validate_password(s: &Secret<String>) -> bool {
    // Updated!
    s.expose_secret().len() >= 8
}

impl PartialEq for Password {
    // New!
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the secret in a
        // controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::Fake;
    use fake::faker::internet::en::Password as FakePassword;
    use quickcheck::Arbitrary;
    use quickcheck::quickcheck;

    #[test]
    fn test_password_valid() {
        let val: String = FakePassword(8..20).fake();
        let password = Password::parse(Secret::new(val));
        assert!(password.is_ok());
    }

    #[test]
    fn test_password_too_short() {
        let val = Secret::new("short".to_string());
        let password = Password::parse(val);
        assert!(password.is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub Secret<String>);

    impl Arbitrary for ValidPasswordFixture {
        fn arbitrary(_g: &mut quickcheck::Gen) -> Self {
            let password_string: String = FakePassword(8..20).fake();
            Self(Secret::new(password_string))
        }
    }

    quickcheck! {
        fn prop_password(valid_password: ValidPasswordFixture) -> bool {
            Password::parse(valid_password.0).is_ok()
        }
    }
}
