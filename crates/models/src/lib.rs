//! Generated operation registry (checked in; produced by `cargo run -p xtask`).
//!
//! v1: static table of (service, op, protocol). The codegen (`xtask`) reads
//! `vendor/botocore/services/*/service-2.json` and rewrites `generated.rs`.
//! Hand edits go here only, never in `generated.rs`.

pub mod generated {
    include!("generated.rs");
}

pub fn ops_for(service: &str) -> Vec<&'static str> {
    generated::OPS.iter().filter(|(s, _, _)| *s == service).map(|(_, op, _)| *op).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_has_sts_caller_identity() {
        let ops = ops_for("sts");
        assert!(ops.contains(&"GetCallerIdentity"), "sts ops: {ops:?}");
    }
}
