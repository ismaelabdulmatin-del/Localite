//! Minimal IAM: CreateUser / GetUser / ListUsers over the scoped store.
//! UIDs are deterministic (`AIDA` + 16 hex of a counter) so tests are stable.

pub mod handler {
    const NS: &str = "https://iam.amazonaws.com/doc/2010-05-08/";

    pub struct Iam {
        store: store::Store,
    }

    impl Iam {
        pub fn new(clock: store::Clock) -> Self {
            Self { store: store::Store::new(clock) }
        }

        fn user_key(name: &str) -> String {
            format!("user/{name}")
        }

        pub fn create_user(&self, name: &str) -> Result<(String, String), (String, String)> {
            if name.is_empty() || name.len() > 64 {
                return Err((
                    "ValidationError".to_string(),
                    "UserName must be 1-64 characters".to_string(),
                ));
            }
            if self.store.get("iam", &Self::user_key(name)).is_some() {
                return Err(("EntityAlreadyExists".to_string(), format!("User {name} already exists")));
            }
            let n = self.store.list("iam", "user/").len() as u64 + 1;
            let uid = format!("AIDA{n:016X}");
            let arn = format!("arn:aws:iam::123456789012:user/{name}");
            let val = format!("{uid}\n{arn}");
            self.store.put("iam", &Self::user_key(name), val.into_bytes());
            Ok((uid, arn))
        }

        pub fn get_user(&self, name: &str) -> Option<(String, String)> {
            let raw = self.store.get("iam", &Self::user_key(name))?;
            let text = String::from_utf8_lossy(&raw).into_owned();
            let (uid, arn) = text.split_once('\n')?;
            Some((uid.to_string(), arn.to_string()))
        }

        pub fn list_users(&self) -> Vec<(String, String, String)> {
            let mut out = Vec::new();
            for k in self.store.list("iam", "user/") {
                let name = k.strip_prefix("user/").unwrap_or(&k).to_string();
                if let Some((uid, arn)) = self.get_user(&name) {
                    out.push((name, uid, arn));
                }
            }
            out
        }

        fn user_xml(name: &str, uid: &str, arn: &str) -> String {
            format!(
                "<User><UserName>{}</UserName><UserId>{uid}</UserId><Arn>{arn}</Arn></User>",
                proto::query_xml::xml_escape(name)
            )
        }

        pub fn dispatch(
            &self,
            action: &str,
            p: &std::collections::HashMap<String, String>,
        ) -> Result<String, (String, String)> {
            let req_id = "01234567-89ab-cdef-0123-456789abcdef";
            match action {
                "CreateUser" => {
                    let name = p.get("UserName").cloned().unwrap_or_default();
                    match self.create_user(&name) {
                        Ok((uid, arn)) => Ok(format!(
                            "<CreateUserResponse xmlns=\"{NS}\"><CreateUserResult>{}</CreateUserResult><ResponseMetadata><RequestId>{req_id}</RequestId></ResponseMetadata></CreateUserResponse>",
                            Self::user_xml(&name, &uid, &arn)
                        )),
                        Err(e) => Err(e),
                    }
                }
                "GetUser" => {
                    let name = p.get("UserName").cloned().unwrap_or_default();
                    match self.get_user(&name) {
                        Some((uid, arn)) => Ok(format!(
                            "<GetUserResponse xmlns=\"{NS}\"><GetUserResult>{}</GetUserResult><ResponseMetadata><RequestId>{req_id}</RequestId></ResponseMetadata></GetUserResponse>",
                            Self::user_xml(&name, &uid, &arn)
                        )),
                        None => Err(("NoSuchEntity".to_string(), format!("User {name} not found"))),
                    }
                }
                "ListUsers" => {
                    let mut xml = format!("<ListUsersResponse xmlns=\"{NS}\"><ListUsersResult><Users>");
                    for (name, uid, arn) in self.list_users() {
                        let inner = Self::user_xml(&name, &uid, &arn);
                        let inner = inner.strip_prefix("<User>").and_then(|x| x.strip_suffix("</User>")).unwrap_or(&inner);
                        xml.push_str(&format!("<member>{inner}</member>"));
                    }
                    xml.push_str(&format!("</Users></ListUsersResult><ResponseMetadata><RequestId>{req_id}</RequestId></ResponseMetadata></ListUsersResponse>"));
                    Ok(xml)
                }
                _ => Err(("InvalidAction".to_string(), format!("iam {action} not implemented"))),
            }
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn create_get_list() {
            let iam = Iam::new(store::Clock::frozen_at(1));
            let (uid, arn) = iam.create_user("alice").unwrap();
            assert!(uid.starts_with("AIDA"));
            assert!(arn.ends_with(":user/alice"));
            assert!(iam.create_user("alice").is_err());
            let (u2, _) = iam.get_user("alice").unwrap();
            assert_eq!(uid, u2);
            assert!(iam.get_user("nobody").is_none());
            iam.create_user("bob").unwrap();
            let users = iam.list_users();
            assert_eq!(users.len(), 2);
            let xml = iam.dispatch("ListUsers", &Default::default()).unwrap();
            assert!(xml.contains("<UserName>alice</UserName>"), "xml:\n{xml}");
            assert!(xml.contains("<UserName>bob</UserName>"));
        }
    }
}
