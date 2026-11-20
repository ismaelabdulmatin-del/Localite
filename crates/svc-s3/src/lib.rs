//! Minimal fake S3: bucket/key put/get, ListObjectsV2 XML.

pub mod handler {
    pub struct S3 {
        store: store::Store,
    }

    impl S3 {
        pub fn new(clock: store::Clock) -> Self {
            Self { store: store::Store::new(clock) }
        }
        fn key(&self, bucket: &str, key: &str) -> String {
            format!("{bucket}/{key}")
        }
        pub fn put(&self, bucket: &str, key: &str, body: Vec<u8>) {
            // PUT auto-creates buckets (documented fidelity deviation).
            self.store.put("s3", &self.key(bucket, key), body);
            self.store.put("s3-buckets", bucket, b"1".to_vec());
        }
        pub fn get(&self, bucket: &str, key: &str) -> Option<Vec<u8>> {
            self.store.get("s3", &self.key(bucket, key))
        }
        pub fn remove(&self, bucket: &str, key: &str) -> bool {
            self.store.delete("s3", &self.key(bucket, key))
        }
        pub fn list_v2(&self, bucket: &str, prefix: &str) -> String {
            let keys = self.store.list("s3", &format!("{bucket}/{prefix}"));
            let mut xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{bucket}</Name><KeyCount>{}</KeyCount>",
                keys.len()
            );
            for k in keys {
                let name = k.strip_prefix(&format!("{bucket}/")).unwrap_or(&k);
                let size = self.store.get("s3", &k).map(|v| v.len()).unwrap_or(0);
                xml.push_str(&format!("<Contents><Key>{name}</Key><Size>{size}</Size></Contents>"));
            }
            xml.push_str("</ListBucketResult>");
            xml
        }
        pub fn create_bucket(&self, bucket: &str) -> bool {
            if self.store.get("s3-buckets", bucket).is_some() {
                return false;
            }
            self.store.put("s3-buckets", bucket, b"1".to_vec());
            true
        }
        pub fn bucket_exists(&self, bucket: &str) -> bool {
            self.store.get("s3-buckets", bucket).is_some()
        }
        /// Err("BucketNotEmpty") / Err("NoSuchBucket") like real S3.
        pub fn delete_bucket(&self, bucket: &str) -> Result<(), &'static str> {
            if !self.bucket_exists(bucket) {
                return Err("NoSuchBucket");
            }
            if !self.store.list("s3", &format!("{bucket}/")).is_empty() {
                return Err("BucketNotEmpty");
            }
            self.store.delete("s3-buckets", bucket);
            Ok(())
        }
        pub fn list_buckets_xml(&self) -> String {
            let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>localite</ID><DisplayName>localite</DisplayName></Owner><Buckets>");
            for b in self.store.list("s3-buckets", "") {
                xml.push_str(&format!("<Bucket><Name>{b}</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket>"));
            }
            xml.push_str("</Buckets></ListAllMyBucketsResult>");
            xml
        }
        pub fn error_no_such_key(key: &str) -> String {
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist: {key}</Message></Error>"
            )
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn put_get_object() {
            let s = S3::new(store::Clock::frozen_at(1));
            s.put("b", "k.txt", b"hello".to_vec());
            assert_eq!(s.get("b", "k.txt").unwrap(), b"hello");
            assert_eq!(s.get("b", "missing"), None);
            let err = S3::error_no_such_key("missing");
            assert!(err.contains("NoSuchKey"));
        }

        #[test]
        fn list_objects_v2() {
            let s = S3::new(store::Clock::frozen_at(1));
            s.put("b", "a/1", b"one".to_vec());
            s.put("b", "a/2", b"two!".to_vec());
            let xml = s.list_v2("b", "a/");
            assert!(xml.contains("<Key>a/1</Key>"), "xml:\n{xml}");
            assert!(xml.contains("<Size>3</Size>"));
            assert!(xml.contains("<KeyCount>2</KeyCount>"));
        }
    }
}
