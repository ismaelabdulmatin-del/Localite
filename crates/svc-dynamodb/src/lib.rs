//! DynamoDB core: PutItem / GetItem over scoped store (JSON attribute maps as opaque bodies).

pub mod handler {
    pub struct Db {
        store: store::Store,
    }

    impl Db {
        pub fn new(clock: store::Clock) -> Self {
            Self { store: store::Store::new(clock) }
        }
        pub fn put_item(&self, table: &str, key_json: &str, item_json: &str) {
            // key_json is the canonical key projection supplied by caller.
            self.store.put("ddb", &format!("{table}#{key_json}"), item_json.as_bytes().to_vec());
        }
        pub fn create_table(&self, table: &str, key_attrs: &[String]) -> bool {
            if self.store.get("ddb-tables", table).is_some() {
                return false;
            }
            self.store.put("ddb-tables", table, key_attrs.join(",").into_bytes());
            true
        }
        /// Key attribute names (hash first, then range) if the table exists.
        pub fn table_keys(&self, table: &str) -> Option<Vec<String>> {
            let v = self.store.get("ddb-tables", table)?;
            Some(String::from_utf8_lossy(&v).split(',').filter(|s| !s.is_empty()).map(String::from).collect())
        }
        pub fn list_tables(&self) -> Vec<String> {
            self.store.list("ddb-tables", "")
        }
        pub fn delete_table(&self, table: &str) -> bool {
            for k in self.store.list("ddb", &format!("{table}#")) {
                self.store.delete("ddb", &k);
            }
            self.store.delete("ddb-tables", table)
        }
        pub fn delete_item(&self, table: &str, key_json: &str) -> bool {
            self.store.delete("ddb", &format!("{table}#{key_json}"))
        }
        pub fn scan(&self, table: &str) -> Vec<String> {
            self.store.list("ddb", &format!("{table}#")).into_iter()
                .filter_map(|k| self.store.get("ddb", &k))
                .map(|v| String::from_utf8_lossy(&v).into_owned())
                .collect()
        }
        pub fn get_item(&self, table: &str, key_json: &str) -> Option<String> {
            self.store.get("ddb", &format!("{table}#{key_json}"))
                .map(|v| String::from_utf8_lossy(&v).into_owned())
        }
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn put_get_item() {
            let db = Db::new(store::Clock::frozen_at(7));
            let item = r#"{"pk":{"S":"a"},"v":{"N":"1"}}"#;
            db.put_item("t", r#"{"pk":{"S":"a"}}"#, item);
            assert_eq!(db.get_item("t", r#"{"pk":{"S":"a"}}"#).as_deref(), Some(item));
            assert_eq!(db.get_item("t", r#"{"pk":{"S":"b"}}"#), None);
            // Cross-table isolation.
            assert_eq!(db.get_item("other", r#"{"pk":{"S":"a"}}"#), None);
        }
    }
}
