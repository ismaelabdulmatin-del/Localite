//! STS handler: GetCallerIdentity + AssumeRole stub.

pub mod handler {
    pub struct CallerIdentity {
        pub user_id: String,
        pub account: String,
        pub arn: String,
    }

    impl Default for CallerIdentity {
        fn default() -> Self {
            Self {
                user_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
                account: "123456789012".to_string(),
                arn: "arn:aws:iam::123456789012:user/test".to_string(),
            }
        }
    }

    pub fn get_caller_identity_xml(id: &CallerIdentity) -> String {
        proto::query_xml::caller_identity_envelope(&id.user_id, &id.account, &id.arn)
    }

    pub fn dispatch(action: &str, _params: &std::collections::HashMap<String, String>) -> Result<String, (String, String)> {
        match action {
            "GetCallerIdentity" => Ok(get_caller_identity_xml(&CallerIdentity::default())),
            _ => Err((
                "InvalidAction".to_string(),
                format!("STS action not implemented: {action}"),
            )),
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn caller_identity_envelope() {
            let xml = get_caller_identity_xml(&CallerIdentity::default());
            assert!(xml.contains("<GetCallerIdentityResult>"), "xml:\n{xml}");
            assert!(xml.contains("<Account>123456789012</Account>"));
            assert!(xml.contains("<Arn>arn:aws:iam::123456789012:user/test</Arn>"));
            assert!(xml.contains("xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\""));
            // Dispatch path renders the same envelope.
            let body = dispatch("GetCallerIdentity", &Default::default()).unwrap();
            assert!(body.contains("GetCallerIdentityResponse"));
            assert!(dispatch("Nope", &Default::default()).is_err());
        }
    }
}
