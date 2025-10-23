use serde::{Deserialize, Serialize};
use std::str::FromStr;
use validator::Validate;

#[derive(Debug, Clone, PartialEq, Hash, Eq, Validate, Serialize, Deserialize)]
pub struct Email {
    #[validate(email)]
    value: String,
}

impl FromStr for Email {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let email = Self {
            value: value.to_string(),
        };
        match email.validate() {
            Ok(_) => Ok(email),
            Err(e) => Err(format!("Invalid email format: {}", e)),
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.value
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::{FreeEmail, SafeEmail};
    use fake::Fake;
    use quickcheck::quickcheck;
    use quickcheck::{Arbitrary, TestResult};

    #[test]
    fn test_email_valid() {
        let val: String = FreeEmail().fake();
        let email: Result<Email, String> = Email::from_str(val.as_str());
        assert!(email.is_ok());
    }

    #[test]
    fn test_safe_email_valid() {
        let val: String = SafeEmail().fake();
        let email: Result<Email, String> = Email::from_str(val.as_str());
        assert!(email.is_ok());
    }

    impl Arbitrary for Email {
        fn arbitrary(_g: &mut quickcheck::Gen) -> Self {
            let email_string: String = SafeEmail().fake();
            Email::from_str(email_string.as_str()).unwrap()
        }
    }

    quickcheck! {
    fn prop_email(email: Email) -> bool {
        // If we have a valid Email instance, converting it back should work
        Email::from_str(email.as_ref()).is_ok()
    }
        }

    quickcheck! {
        fn prop(s: String) -> TestResult {
            // Filter out strings that happen to be valid emails
            if s.contains('@') && s.split('@').count() == 2 {
                return TestResult::discard();
            }

            // These should fail validation
            TestResult::from_bool(Email::from_str(s.as_str()).is_err())
        }

    }

    quickcheck! {
        fn roundtrip(email: Email) -> bool {
            let original = email.as_ref();
            match Email::from_str(original) {
                Ok(parsed) => parsed.as_ref() == original,
                Err(_) => false,
            }
        }
    }

    #[test]
    fn test_specific_invalid_cases() {
        let invalid_cases = vec![
            "plaintext",
            "@example.com",
            "user@",
            "user @example.com",
            "user@.com",
            "",
        ];

        for case in invalid_cases {
            assert!(
                Email::from_str(case).is_err(),
                "Expected '{}' to be invalid",
                case
            );
        }
    }

    #[test]
    fn test_specific_valid_cases() {
        let valid_cases = vec![
            "user@example.com",
            "test.email@domain.co.uk",
            "first+last@company.com",
        ];

        for case in valid_cases {
            assert!(
                Email::from_str(case).is_ok(),
                "Expected '{}' to be valid",
                case
            );
        }
    }

    //    let val: String = Password(EN, 8..20).fake();
}
