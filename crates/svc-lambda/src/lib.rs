//! Minimal Lambda: CreateFunction / GetFunction / DeleteFunction / Invoke.
//!
//! Invoke runs in **echo mode**: the stored function must exist, and the
//! request payload is returned verbatim as the result payload with
//! StatusCode 200. Real execution (Firecracker/microVM) is the M-future
//! track; this layer proves routing, function-exists checks, payload
//! round-trip and error shapes over real HTTP.

pub mod handler {
    pub struct Lambda {
        store: store::Store,
    }

    impl Lambda {
        pub fn new(clock: store::Clock) -> Self {
            Self { store: store::Store::new(clock) }
        }

        fn fn_key(name: &str) -> String {
            format!("function/{name}")
        }

        pub fn create(&self, name: &str, config_json: &str, code_len: usize) -> Result<String, (String, u16)> {
            if name.is_empty() || name.len() > 64 {
                return Err((json_err("ValidationException", "FunctionName must be 1-64 characters"), 400));
            }
            if self.store.get("lambda", &Self::fn_key(name)).is_some() {
                return Err((json_err("ResourceConflictException", &format!("Function {name} already exists")), 409));
            }
            let arn = format!("arn:aws:lambda:us-east-1:123456789012:function:{name}");
            let val = format!("{arn}\n{config_json}\n{code_len}");
            self.store.put("lambda", &Self::fn_key(name), val.into_bytes());
            Ok(format!("{{\"FunctionName\":\"{}\",\"FunctionArn\":\"{arn}\",\"Runtime\":\"python3.12\",\"State\":\"Active\"}}", proto::json_codec::esc(name)))
        }

        pub fn get(&self, name: &str) -> Option<String> {
            let raw = self.store.get("lambda", &Self::fn_key(name))?;
            let text = String::from_utf8_lossy(&raw).into_owned();
            let (arn, _) = text.split_once('\n')?;
            Some(format!("{{\"FunctionName\":\"{}\",\"FunctionArn\":\"{arn}\",\"Runtime\":\"python3.12\",\"State\":\"Active\"}}", proto::json_codec::esc(name)))
        }

        pub fn delete(&self, name: &str) -> bool {
            self.store.delete("lambda", &Self::fn_key(name))
        }

        /// Echo-mode invoke: 200 + request payload iff the function exists.
        pub fn invoke(&self, name: &str, payload: &[u8]) -> Result<Vec<u8>, (String, u16)> {
            if self.store.get("lambda", &Self::fn_key(name)).is_none() {
                return Err((json_err("ResourceNotFoundException", &format!("Function not found: {name}")), 404));
            }
            Ok(payload.to_vec())
        }
    }

    fn json_err(code: &str, msg: &str) -> String {
        format!("{{\"__type\":\"{code}\",\"message\":\"{}\"}}", proto::json_codec::esc(msg))
    }

    pub fn not_found(name: &str) -> (String, u16) {
        (json_err("ResourceNotFoundException", &format!("Function not found: {name}")), 404)
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn create_get_invoke_delete() {
            let l = Lambda::new(store::Clock::frozen_at(1));
            let cfg = l.create("f", "{\"Runtime\":\"python3.12\"}", 3).unwrap();
            assert!(cfg.contains("\"State\":\"Active\""), "cfg:\n{cfg}");
            assert!(l.create("f", "{}", 0).is_err());
            let g = l.get("f").unwrap();
            assert!(g.contains("arn:aws:lambda"), "get:\n{g}");
            let out = l.invoke("f", b"{\"k\":1}").unwrap();
            assert_eq!(out, b"{\"k\":1}");
            assert!(l.invoke("nope", b"{}").is_err());
            assert!(l.delete("f"));
            assert!(!l.delete("f"));
            assert!(l.get("f").is_none());
        }
    }
}
