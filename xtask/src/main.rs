//! xtask codegen: reads vendored botocore models, regenerates `crates/models/src/generated.rs`.
//!
//! Allowed network: none at runtime. Reads only checked-in `vendor/botocore`.

use std::collections::BTreeMap;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    let mut d = std::env::current_dir().expect("cwd");
    loop {
        if d.join("vendor/botocore/services").is_dir() {
            return d;
        }
        if !d.pop() {
            panic!("vendor/botocore/services not found above cwd");
        }
    }
}

/// Minimal JSON string-value extractor for top-level `metadata.protocol`
/// and operation names, without a JSON dependency (offline-safe).
/// We only need: metadata.protocol, operations keys, apiVersion.
fn extract_protocol_and_ops(text: &str) -> (String, Vec<String>, String) {
    // apiVersion: first occurrence of `"apiVersion": "..."`.
    let api = extract_str_field(text, "\"apiVersion\"").unwrap_or_default();
    let proto = {
        // Prefer `"protocol":"x"` inside metadata; fall back to protocols[0].
        extract_str_field(text, "\"protocol\"").unwrap_or_default()
    };
    // Operations: parse the `"operations": { "Name": {...}, ... }` map at depth 1.
    let mut ops = Vec::new();
    if let Some(start) = text.find("\"operations\"") {
        let rest = &text[start..];
        if let Some(brace) = rest.find('{') {
            let body = &rest[brace..];
            // Walk brace depth; depth 1 keys are op names.
            let mut depth = 0i32;
            let mut in_str = false;
            let mut esc = false;
            let mut cur = String::new();
            let mut chars = body.char_indices().peekable();
            // Skip the opening brace itself.
            let mut first = true;
            while let Some((_, c)) = chars.next() {
                if first {
                    first = false;
                    depth = 1;
                    continue;
                }
                if in_str {
                    if esc {
                        esc = false;
                        cur.push(c);
                    } else if c == '\\' {
                        esc = true;
                        cur.push(c);
                    } else if c == '"' {
                        in_str = false;
                        if depth == 1 {
                            // Potential key; check next non-space char is ':'.
                            let look = chars.clone();
                            let mut is_key = false;
                            for (_, lc) in look {
                                if lc == ' ' || lc == '\n' || lc == '\r' || lc == '\t' {
                                    continue;
                                }
                                is_key = lc == ':';
                                break;
                            }
                            if is_key && !cur.is_empty() {
                                ops.push(cur.clone());
                            }
                        }
                        cur.clear();
                    } else {
                        cur.push(c);
                    }
                    continue;
                }
                match c {
                    '"' => {
                        in_str = true;
                        cur.clear();
                    }
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    (proto, ops, api)
}

fn extract_str_field(text: &str, field: &str) -> Option<String> {
    let i = text.find(field)?;
    let rest = &text[i + field.len()..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(e) = chars.next() {
                    out.push(e);
                }
            }
            '"' => return Some(out),
            c => out.push(c),
        }
    }
    None
}

fn service_models(root: &PathBuf) -> BTreeMap<String, (String, Vec<String>, String)> {
    let mut m = BTreeMap::new();
    let dir = root.join("vendor/botocore/services");
    let entries = std::fs::read_dir(&dir).expect("read services dir");
    for e in entries {
        let e = e.unwrap();
        let svc = e.file_name().to_string_lossy().into_owned();
        let f = e.path().join("service-2.json");
        if !f.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap_or_else(|_| panic!("read {f:?}"));
        let (proto, ops, api) = extract_protocol_and_ops(&text);
        m.insert(svc, (proto, ops, api));
    }
    m
}

fn run_codegen() {
    let root = workspace_root();
    let models = service_models(&root);
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for (svc, (proto, ops, _)) in &models {
        for op in ops {
            rows.push((svc.clone(), op.clone(), proto.clone()));
        }
    }
    rows.sort();
    let mut out = String::from(
        "// GENERATED by xtask codegen from vendor/botocore 1.42.97. Do not hand-edit.\n// Regenerate: `cargo run -p xtask`.\n\n/// (service, operation, protocol)\npub const OPS: &[(&str, &str, &str)] = &[\n",
    );
    for (s, o, p) in &rows {
        out.push_str(&format!("    (\"{s}\", \"{o}\", \"{p}\"),\n"));
    }
    out.push_str("];\n");
    let dst = root.join("crates/models/src/generated.rs");
    std::fs::write(&dst, out).expect("write generated.rs");
    println!("codegen: {} ops across {} services", rows.len(), models.len());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = if args.len() < 2 { "codegen" } else { args[1].as_str() };
    match cmd {
        "codegen" => run_codegen(),
        "lint" => run_lint(),
        _ => {
            eprintln!("usage: xtask [codegen|lint]");
            std::process::exit(2);
        }
    }
}

/// Fail on any compiler warning: warnings are how dead code and unused
/// security checks hide. Runs `cargo build --workspace --tests` and rejects
/// the tree if `warning` appears in the compiler output.
fn run_lint() {
    let out = std::process::Command::new("cargo")
        .args(["build", "--workspace", "--tests"])
        .output()
        .expect("cargo build");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let warns: Vec<&str> = stderr.lines().filter(|l| l.contains("warning")).collect();
    if !out.status.success() {
        eprintln!("{stderr}");
        eprintln!("lint: build failed");
        std::process::exit(1);
    }
    if !warns.is_empty() {
        for w in &warns {
            eprintln!("{w}");
        }
        eprintln!("lint: {} warning(s) — fix them, do not allow them", warns.len());
        std::process::exit(1);
    }
    println!("lint: clean (no warnings, workspace builds)");
}

pub mod codegen {
    #[cfg(test)]
    pub mod tests {
        use super::super::*;

        #[test]
        fn six_services_pinned() {
            let root = workspace_root();
            let models = service_models(&root);
            for svc in ["sts", "sqs", "dynamodb", "s3", "iam", "lambda"] {
                assert!(models.contains_key(svc), "missing vendored {svc}");
            }
            assert_eq!(models.len(), 6, "expected exactly 6 tier-1 services");
            // Pinned apiVersions (botocore 1.42.97).
            let expect_api = [
                ("sts", "2011-06-15"),
                ("sqs", "2012-11-05"),
                ("dynamodb", "2012-08-10"),
                ("s3", "2006-03-01"),
                ("iam", "2010-05-08"),
                ("lambda", "2015-03-31"),
            ];
            for (svc, api) in expect_api {
                assert_eq!(models[svc].2, api, "apiVersion drift for {svc}");
            }
            // Tier-1 op totals from the plan (the coverage denominator).
            let expect_ops = [
                ("sts", 11),
                ("sqs", 23),
                ("dynamodb", 57),
                ("s3", 111),
                ("iam", 176),
                ("lambda", 85),
            ];
            let mut total = 0;
            for (svc, n) in expect_ops {
                assert_eq!(models[svc].1.len(), n, "op count drift for {svc}");
                total += n;
            }
            assert_eq!(total, 463, "tier-1 total");
        }
    }
}
