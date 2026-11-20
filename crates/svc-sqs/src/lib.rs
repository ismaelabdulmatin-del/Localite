//! SQS handler over scoped store: SendMessage / ReceiveMessage / DeleteMessage.
//! Supports both Query and JSON input shapes.

use std::sync::atomic::{AtomicU64, Ordering};

pub mod handler {
    use super::*;

    pub struct Queue {
        store: store::Store,
        seq: AtomicU64,
        /// message key -> epoch seconds until which it is invisible (in flight)
        inflight: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    }

    impl Queue {
        pub fn new(clock: store::Clock) -> Self {
            Self { store: store::Store::new(clock), seq: AtomicU64::new(1), inflight: Default::default() }
        }
        fn msg_key(&self, queue: &str, id: u64) -> String {
            format!("msg/{queue}/{id:020}")
        }
        pub fn send(&self, queue: &str, body: &str) -> (String, String) {
            let id = self.seq.fetch_add(1, Ordering::SeqCst);
            let mid = format!("msg-{id:08x}-0000-4000-8000-{id:012x}");
            let md5 = proto::md5::hex(body.as_bytes());
            self.store.put("sqs", &self.msg_key(queue, id), body.as_bytes().to_vec());
            self.store.put("sqs", &format!("id/{mid}"), self.msg_key(queue, id).into_bytes());
            (mid, md5)
        }
        pub fn create_queue(&self, name: &str) {
            self.store.put("sqs-queues", name, b"1".to_vec());
        }
        pub fn queue_exists(&self, name: &str) -> bool {
            self.store.get("sqs-queues", name).is_some()
        }
        pub fn list_queues(&self, prefix: &str) -> Vec<String> {
            self.store.list("sqs-queues", prefix)
        }
        pub fn delete_queue(&self, name: &str) -> bool {
            self.purge(name);
            self.store.delete("sqs-queues", name)
        }
        pub fn purge(&self, name: &str) {
            for k in self.store.list("sqs", &format!("msg/{name}/")) {
                self.store.delete("sqs", &k);
            }
        }
        /// Up to 10 visible messages; each returned message is hidden for
        /// 30s (default visibility timeout) until deleted.
        pub fn receive(&self, queue: &str) -> Vec<(String, String)> {
            let now = self.store.clock.service_now();
            let keys = self.store.list("sqs", &format!("msg/{queue}/"));
            let mut inflight = self.inflight.lock().unwrap();
            let visible: Vec<String> = keys
                .into_iter()
                .filter(|k| inflight.get(k).map(|&until| until <= now).unwrap_or(true))
                .take(10)
                .collect();
            for k in &visible {
                inflight.insert(k.clone(), now + 30);
            }
            drop(inflight);
            visible.into_iter().filter_map(|k| {
                let body = self.store.get("sqs", &k)?;
                // Derive receipt from key suffix.
                let receipt = format!("rh-{}", k.rsplit('/').next().unwrap_or("0"));
                Some((receipt, String::from_utf8_lossy(&body).into_owned()))
            }).collect()
        }
        pub fn delete_by_receipt(&self, receipt: &str) -> bool {
            let id = receipt.strip_prefix("rh-").unwrap_or(receipt);
            // Find key ending with id across queues (single-scope test helper).
            let keys = self.store.list("sqs", "msg/");
            for k in keys {
                if k.ends_with(id) {
                    return self.store.delete("sqs", &k);
                }
            }
            false
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn send_receive_delete() {
            let q = Queue::new(store::Clock::frozen_at(1));
            // JSON shape (real SQS-json) and Query shape share the handler.
            let body = proto::json_codec::get_str_field(
                r#"{"QueueUrl":"http://127.0.0.1:4566/000000000000/q","MessageBody":"hello"}"#,
                "MessageBody",
            ).unwrap();
            let (mid, _md5) = q.send("q", &body);
            assert!(mid.starts_with("msg-"));
            let msgs = q.receive("q");
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].1, "hello");
            assert!(q.delete_by_receipt(&msgs[0].0));
            assert!(q.receive("q").is_empty());
        }
    }
}
