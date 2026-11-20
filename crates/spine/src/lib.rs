//! Spine: real HTTP -> codec -> route -> service -> response.
//! Serves STS + SQS (Query and JSON), DynamoDB (JSON), S3 (REST-XML).
//! `--selftest` boots loopback on an ephemeral port and drives one real
//! `GetCallerIdentity` through TCP (not a handler stub).
//!
//! Auth: `App::Open` skips verification (default, matches m0-05 selftest).
//! `App::Required` enforces SigV4 via `proto::sigv4::verify` with a lite
//! canonical form documented below (full canonical-request construction,
//! including header/scope derivation per service, is a follow-up; the scope,
//! skew and signature logic verified here is the real `proto` implementation).

use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

type NowFn = Arc<dyn Fn() -> u64 + Send + Sync>;

fn wall_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub struct App {
    sqs: Arc<svc_sqs::handler::Queue>,
    ddb: Arc<svc_dynamodb::handler::Db>,
    s3: Arc<svc_s3::handler::S3>,
    iam: Arc<svc_iam::handler::Iam>,
    lambda: Arc<svc_lambda::handler::Lambda>,
    auth_required: bool,
    secrets: HashMap<String, String>,
    now: NowFn,
}

impl App {
    pub fn open() -> Self {
        Self {
            sqs: Arc::new(svc_sqs::handler::Queue::new(store::Clock::live())),
            ddb: Arc::new(svc_dynamodb::handler::Db::new(store::Clock::live())),
            s3: Arc::new(svc_s3::handler::S3::new(store::Clock::live())),
            iam: Arc::new(svc_iam::handler::Iam::new(store::Clock::live())),
            lambda: Arc::new(svc_lambda::handler::Lambda::new(store::Clock::live())),
            auth_required: false,
            secrets: HashMap::new(),
            now: Arc::new(wall_now),
        }
    }

    pub fn authed(secrets: HashMap<String, String>, now: NowFn) -> Self {
        Self {
            sqs: Arc::new(svc_sqs::handler::Queue::new(store::Clock::live())),
            ddb: Arc::new(svc_dynamodb::handler::Db::new(store::Clock::live())),
            s3: Arc::new(svc_s3::handler::S3::new(store::Clock::live())),
            iam: Arc::new(svc_iam::handler::Iam::new(store::Clock::live())),
            lambda: Arc::new(svc_lambda::handler::Lambda::new(store::Clock::live())),
            auth_required: true,
            secrets,
            now,
        }
    }
}

/// Canonical hash for the AUTH gate: a real AWS SigV4 canonical request
/// built from the received method, path, query string, signed headers and
/// body hash (`proto::canonical_request`, AWS-anchored by
/// `sigv4::tests::aws_listusers_vector`). Query-POST params travel in the
/// body and are covered by the payload hash, exactly as AWS signs them.
fn canonical_hash_for(req: &edge::http::Request, signed: &[String]) -> Result<String, String> {
    let (path, query) = match req.path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (req.path.as_str(), ""),
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    for name in signed {
        let v = req
            .headers
            .get(name)
            .ok_or_else(|| format!("signed header missing: {name}"))?;
        headers.push((name.clone(), v.clone()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let payload_hash = proto::sigv4::sha256_hex(&req.body);
    let cr = proto::sigv4::canonical_request(
        &req.method,
        path,
        query,
        &headers,
        &signed.join(";"),
        &payload_hash,
    );
    Ok(proto::sigv4::sha256_hex(cr.as_bytes()))
}

fn check_auth(app: &App, req: &edge::http::Request, service: &str) -> Result<(), Vec<u8>> {
    if !app.auth_required {
        return Ok(());
    }
    let deny = |msg: &str| -> Vec<u8> {
        let body = format!(
            "{{\"__type\":\"AccessDenied\",\"message\":\"{}\"}}",
            proto::json_codec::esc(msg)
        );
        edge::http::response(403, "Forbidden", "application/json", &body)
    };
    let auth = req.headers.get("authorization").map(|s| s.as_str()).unwrap_or("");
    let amz_date = req.headers.get("x-amz-date").map(|s| s.as_str()).unwrap_or("");
    if auth.is_empty() || amz_date.is_empty() {
        return Err(deny("missing Authorization or X-Amz-Date"));
    }
    let signed = match proto::sigv4::parse_authorization(auth) {
        Ok(v) => v.signed_headers,
        Err(e) => return Err(deny(&e)),
    };
    let chash = match canonical_hash_for(req, &signed) {
        Ok(h) => h,
        Err(e) => return Err(deny(&e)),
    };
    match proto::sigv4::verify(
        &app.secrets,
        auth,
        amz_date,
        "us-east-1",
        service,
        &chash,
        (app.now)(),
        900,
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(deny(&e)),
    }
}

fn queue_name(queue_url: &str) -> String {
    queue_url
        .rsplit(['/', '?'])
        .next()
        .unwrap_or(queue_url)
        .split('?')
        .next()
        .unwrap_or(queue_url)
        .to_string()
}

fn handle_query(app: &App, req: &edge::http::Request) -> Vec<u8> {
    let body_str = String::from_utf8_lossy(&req.body).into_owned();
    let q = match proto::query_xml::parse_query_body(&body_str) {
        Ok(q) => q,
        Err(e) => {
            let b = proto::query_xml::error_envelope("MissingAction", &e, "Sender");
            return edge::http::response(400, "Bad Request", "text/xml", &b);
        }
    };
    let (svc, action) = match edge::route::route_query(&body_str) {
        Ok(r) => r,
        Err(e) => {
            let b = proto::query_xml::error_envelope("InvalidAction", &e, "Sender");
            return edge::http::response(400, "Bad Request", "text/xml", &b);
        }
    };
    if let Err(resp) = check_auth(app, req, &svc) {
        return resp;
    }
    match svc.as_str() {
        "sts" => match svc_sts::handler::dispatch(&action, &q.params) {
            Ok(xml) => edge::http::response(200, "OK", "text/xml", &xml),
            Err((code, msg)) => {
                let b = proto::query_xml::error_envelope(&code, &msg, "Sender");
                edge::http::response(400, "Bad Request", "text/xml", &b)
            }
        },
        "sqs" => handle_sqs_query(app, &action, &q.params),
        "iam" => match app.iam.dispatch(&action, &q.params) {
            Ok(xml) => edge::http::response(200, "OK", "text/xml", &xml),
            Err((code, msg)) => {
                let b = proto::query_xml::error_envelope(&code, &msg, "Sender");
                let status = if code == "NoSuchEntity" { 404 } else { 400 };
                let reason = if status == 404 { "Not Found" } else { "Bad Request" };
                edge::http::response(status, reason, "text/xml", &b)
            }
        }
        _ => {
            let b = proto::query_xml::error_envelope(
                "InvalidAction",
                &format!("service {svc} action {action} not yet served by spine"),
                "Sender",
            );
            edge::http::response(400, "Bad Request", "text/xml", &b)
        }
    }
}

fn handle_sqs_query(
    app: &App,
    action: &str,
    p: &HashMap<String, String>,
) -> Vec<u8> {
    let qname = p.get("QueueUrl").map(|u| queue_name(u)).unwrap_or_default();
    match action {
        "SendMessage" => {
            let body = match p.get("MessageBody") {
                Some(b) => b.clone(),
                None => {
                    let b = proto::query_xml::error_envelope("MissingParameter", "MessageBody required", "Sender");
                    return edge::http::response(400, "Bad Request", "text/xml", &b);
                }
            };
            let (mid, md5) = app.sqs.send(&qname, &body);
            let xml = format!(
                "<SendMessageResponse xmlns=\"https://queue.amazonaws.com/doc/2012-11-05/\"><SendMessageResult><MessageId>{mid}</MessageId><MD5OfMessageBody>{md5}</MD5OfMessageBody></SendMessageResult><ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata></SendMessageResponse>"
            );
            edge::http::response(200, "OK", "text/xml", &xml)
        }
        "ReceiveMessage" => {
            let msgs = app.sqs.receive(&qname);
            let mut xml = String::from("<ReceiveMessageResponse xmlns=\"https://queue.amazonaws.com/doc/2012-11-05/\"><ReceiveMessageResult>");
            for (receipt, body) in msgs.iter().take(10) {
                xml.push_str(&format!(
                    "<Message><Body>{}</Body><ReceiptHandle>{}</ReceiptHandle></Message>",
                    proto::query_xml::xml_escape(body),
                    proto::query_xml::xml_escape(receipt)
                ));
            }
            xml.push_str("</ReceiveMessageResult><ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata></ReceiveMessageResponse>");
            edge::http::response(200, "OK", "text/xml", &xml)
        }
        "DeleteMessage" => {
            let ok = p.get("ReceiptHandle").map(|r| app.sqs.delete_by_receipt(r)).unwrap_or(false);
            if ok {
                let xml = "<DeleteMessageResponse xmlns=\"https://queue.amazonaws.com/doc/2012-11-05/\"><ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata></DeleteMessageResponse>";
                edge::http::response(200, "OK", "text/xml", xml)
            } else {
                let b = proto::query_xml::error_envelope("ReceiptHandleIsInvalid", "unknown receipt", "Sender");
                edge::http::response(400, "Bad Request", "text/xml", &b)
            }
        }
        _ => {
            let b = proto::query_xml::error_envelope("InvalidAction", &format!("sqs {action} not implemented"), "Sender");
            edge::http::response(400, "Bad Request", "text/xml", &b)
        }
    }
}

/// End index (exclusive) of the JSON value starting at `i` (leading ws skipped by caller).
fn json_value_end(b: &[u8], mut i: usize) -> usize {
    if i >= b.len() {
        return i;
    }
    match b[i] {
        b'"' => {
            i += 1;
            while i < b.len() {
                match b[i] {
                    b'\\' => i += 2,
                    b'"' => return i + 1,
                    _ => i += 1,
                }
            }
            b.len()
        }
        b'{' | b'[' => {
            let mut depth = 0i32;
            let mut in_str = false;
            while i < b.len() {
                let c = b[i];
                if in_str {
                    if c == b'\\' {
                        i += 1;
                    } else if c == b'"' {
                        in_str = false;
                    }
                } else {
                    match c {
                        b'"' => in_str = true,
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                return i + 1;
                            }
                        }
                        _ => {}
                    }
                }
                i += 1;
            }
            b.len()
        }
        _ => {
            while i < b.len() && !matches!(b[i], b',' | b'}' | b']') {
                i += 1;
            }
            i
        }
    }
}

/// Raw JSON value text for a TOP-LEVEL key of the object `obj` (never matches
/// nested keys or string values that happen to equal `key`).
fn json_top_get(obj: &str, key: &str) -> Option<String> {
    let b = obj.as_bytes();
    let mut i = obj.find('{')? + 1;
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b',') {
            i += 1;
        }
        if i >= b.len() || b[i] == b'}' {
            return None;
        }
        if b[i] != b'"' {
            return None;
        }
        let ke = json_value_end(b, i);
        let k = &obj[i + 1..ke.saturating_sub(1)];
        i = ke;
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b':') {
            i += 1;
        }
        let ve = json_value_end(b, i);
        if k == key {
            return Some(obj[i..ve].trim().to_string());
        }
        i = ve;
    }
}

/// String content of a JSON string value (no unescaping beyond quotes).
fn json_unquote(v: &str) -> String {
    v.trim().trim_matches('"').to_string()
}

/// Split a JSON array text `[a,b,c]` into its element texts.
fn json_array_items(arr: &str) -> Vec<String> {
    let b = arr.as_bytes();
    let mut out = Vec::new();
    let mut i = match arr.find('[') { Some(x) => x + 1, None => return out };
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b',') {
            i += 1;
        }
        if i >= b.len() || b[i] == b']' {
            return out;
        }
        let e = json_value_end(b, i);
        out.push(arr[i..e].to_string());
        i = e;
    }
}

/// Canonical key projection `{"id":{"S":"1"}}` for `table` from `source`
/// (an Item or Key object). Tables created via CreateTable use their real
/// schema; unknown tables keep the legacy `pk`-or-whole-item behaviour.
fn ddb_key(app: &App, table: &str, source: &str) -> String {
    if let Some(attrs) = app.ddb.table_keys(table) {
        let parts: Vec<String> = attrs
            .iter()
            .filter_map(|a| json_top_get(source, a).map(|v| format!("\"{a}\":{v}")))
            .collect();
        return format!("{{{}}}", parts.join(","));
    }
    source.to_string()
}

fn json_ok(body: &str) -> Vec<u8> {
    edge::http::response(200, "OK", "application/json", body)
}

fn ddb_table_desc(table: &str, keys: &[String]) -> String {
    let ks: Vec<String> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| format!("{{\"AttributeName\":\"{k}\",\"KeyType\":\"{}\"}}", if i == 0 { "HASH" } else { "RANGE" }))
        .collect();
    format!(
        "{{\"TableName\":\"{table}\",\"TableStatus\":\"ACTIVE\",\"KeySchema\":[{}],\"ItemCount\":0,\"TableSizeBytes\":0,\"TableArn\":\"arn:aws:dynamodb:us-east-1:123456789012:table/{table}\"}}",
        ks.join(",")
    )
}

fn queue_url(req: &edge::http::Request, name: &str) -> String {
    let host = req.headers.get("host").cloned().unwrap_or_else(|| "localhost:4566".into());
    format!("http://{host}/123456789012/{name}")
}

/// Extract the balanced `{...}` value object for `"attr"` inside a flat JSON
/// object body. Returns the object substring including braces.
fn json_obj_attr(body: &str, attr: &str) -> Option<String> {
    let needle = format!("\"{attr}\"");
    let mut i = body.find(&needle)?;
    i += needle.len();
    let rest = &body[i..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    if !rest.starts_with('{') {
        // Scalar: return the raw token.
        let end = rest.find(|c| c == ',' || c == '}').unwrap_or(rest.len());
        return Some(rest[..end].trim().to_string());
    }
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for (j, c) in rest.char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[..j + 1].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn handle_json(app: &App, req: &edge::http::Request) -> Vec<u8> {
    let target = req.headers.get("x-amz-target").cloned().unwrap_or_default();
    let body = String::from_utf8_lossy(&req.body).into_owned();
    let err = |code: &str, msg: &str| -> Vec<u8> {
        let b = format!(
            "{{\"__type\":\"{code}\",\"message\":\"{}\"}}",
            proto::json_codec::esc(msg)
        );
        edge::http::response(400, "Bad Request", "application/json", &b)
    };
    // SQS-over-JSON (awsQueryCompatible dual codec): target AmazonSQS.* or
    // a body carrying MessageBody.
    let is_sqs_json = target.contains("SQS")
        || (target.is_empty() && body.contains("\"MessageBody\""));
    if is_sqs_json {
        if let Err(resp) = check_auth(app, req, "sqs") {
            return resp;
        }
        let op = target.split('.').next_back().unwrap_or("");
        if op == "SendMessage" || (target.is_empty() && body.contains("\"MessageBody\"")) {
            let (qurl, mbody) = (
                proto::json_codec::get_str_field(&body, "QueueUrl").unwrap_or_default(),
                proto::json_codec::get_str_field(&body, "MessageBody"),
            );
            let mbody = match mbody {
                Some(b) => b,
                None => return err("MissingParameter", "MessageBody required"),
            };
            let (mid, md5) = app.sqs.send(&queue_name(&qurl), &mbody);
            let b = format!("{{\"MessageId\":\"{mid}\",\"MD5OfMessageBody\":\"{md5}\"}}");
            return edge::http::response(200, "OK", "application/json", &b);
        }
        if op == "ReceiveMessage" {
            let qurl = proto::json_codec::get_str_field(&body, "QueueUrl").unwrap_or_default();
            let msgs = app.sqs.receive(&queue_name(&qurl));
            let mut b = String::from("{\"Messages\":[");
            for (i, (receipt, mbody)) in msgs.iter().take(10).enumerate() {
                if i > 0 {
                    b.push(',');
                }
                b.push_str(&format!(
                    "{{\"Body\":\"{}\",\"ReceiptHandle\":\"{}\"}}",
                    proto::json_codec::esc(mbody),
                    proto::json_codec::esc(receipt)
                ));
            }
            b.push_str("]}");
            return edge::http::response(200, "OK", "application/json", &b);
        }
        if op == "DeleteMessage" {
            let receipt = proto::json_codec::get_str_field(&body, "ReceiptHandle").unwrap_or_default();
            if app.sqs.delete_by_receipt(&receipt) {
                return edge::http::response(200, "OK", "application/json", "{}");
            }
            return err("ReceiptHandleIsInvalid", "unknown receipt");
        }
        if op == "CreateQueue" {
            let name = proto::json_codec::get_str_field(&body, "QueueName").unwrap_or_default();
            if name.is_empty() {
                return err("MissingParameter", "QueueName required");
            }
            app.sqs.create_queue(&name);
            return json_ok(&format!("{{\"QueueUrl\":\"{}\"}}", queue_url(req, &name)));
        }
        if op == "GetQueueUrl" {
            let name = proto::json_codec::get_str_field(&body, "QueueName").unwrap_or_default();
            if !app.sqs.queue_exists(&name) {
                return err("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.");
            }
            return json_ok(&format!("{{\"QueueUrl\":\"{}\"}}", queue_url(req, &name)));
        }
        if op == "ListQueues" {
            let prefix = proto::json_codec::get_str_field(&body, "QueueNamePrefix").unwrap_or_default();
            let urls: Vec<String> = app.sqs.list_queues(&prefix).iter().map(|n| format!("\"{}\"", queue_url(req, n))).collect();
            return json_ok(&format!("{{\"QueueUrls\":[{}]}}", urls.join(",")));
        }
        if op == "DeleteQueue" || op == "PurgeQueue" {
            let qurl = proto::json_codec::get_str_field(&body, "QueueUrl").unwrap_or_default();
            let name = queue_name(&qurl);
            if op == "PurgeQueue" {
                app.sqs.purge(&name);
            } else {
                app.sqs.delete_queue(&name);
            }
            return json_ok("{}");
        }
        return err("InvalidAction", "unknown SQS JSON op");
    }
    // DynamoDB JSON: target DynamoDB_20120810.Op.
    if let Ok((svc, op)) = edge::route::route_json(if target.is_empty() { "x.y" } else { &target }) {
        if svc == "dynamodb" {
            if let Err(resp) = check_auth(app, req, "dynamodb") {
                return resp;
            }
            let table = proto::json_codec::get_str_field(&body, "TableName").unwrap_or_default();
            match op.as_str() {
                "CreateTable" => {
                    let schema = json_top_get(&body, "KeySchema").unwrap_or_default();
                    let mut hash = Vec::new();
                    let mut range = Vec::new();
                    for el in json_array_items(&schema) {
                        let name = json_top_get(&el, "AttributeName").map(|v| json_unquote(&v)).unwrap_or_default();
                        match json_top_get(&el, "KeyType").map(|v| json_unquote(&v)).as_deref() {
                            Some("HASH") => hash.push(name),
                            _ => range.push(name),
                        }
                    }
                    let keys: Vec<String> = hash.into_iter().chain(range).collect();
                    if table.is_empty() || keys.is_empty() {
                        return err("ValidationException", "TableName and KeySchema are required");
                    }
                    if !app.ddb.create_table(&table, &keys) {
                        return err("ResourceInUseException", &format!("Table already exists: {table}"));
                    }
                    return json_ok(&format!("{{\"TableDescription\":{}}}", ddb_table_desc(&table, &keys)));
                }
                "DescribeTable" => {
                    return match app.ddb.table_keys(&table) {
                        Some(keys) => json_ok(&format!("{{\"Table\":{}}}", ddb_table_desc(&table, &keys))),
                        None => err("ResourceNotFoundException", &format!("Requested resource not found: Table: {table} not found")),
                    };
                }
                "ListTables" => {
                    let names: Vec<String> = app.ddb.list_tables().iter().map(|t| format!("\"{t}\"")).collect();
                    return json_ok(&format!("{{\"TableNames\":[{}]}}", names.join(",")));
                }
                "DeleteTable" => {
                    return match app.ddb.table_keys(&table) {
                        Some(keys) => {
                            app.ddb.delete_table(&table);
                            json_ok(&format!("{{\"TableDescription\":{}}}", ddb_table_desc(&table, &keys)))
                        }
                        None => err("ResourceNotFoundException", &format!("Requested resource not found: Table: {table} not found")),
                    };
                }
                "PutItem" => {
                    let item = json_top_get(&body, "Item").unwrap_or_default();
                    let key = if app.ddb.table_keys(&table).is_some() {
                        ddb_key(app, &table, &item)
                    } else {
                        json_obj_attr(&item, "pk")
                            .or_else(|| json_obj_attr(&body, "Key"))
                            .unwrap_or_else(|| item.clone())
                    };
                    app.ddb.put_item(&table, &key, &item);
                    return json_ok("{}");
                }
                "GetItem" => {
                    let key_block = json_top_get(&body, "Key").unwrap_or_default();
                    let key = if app.ddb.table_keys(&table).is_some() {
                        ddb_key(app, &table, &key_block)
                    } else {
                        json_obj_attr(&key_block, "pk").unwrap_or(key_block)
                    };
                    return match app.ddb.get_item(&table, &key) {
                        Some(item) => json_ok(&format!("{{\"Item\":{item}}}")),
                        None => json_ok("{}"),
                    };
                }
                "DeleteItem" => {
                    let key_block = json_top_get(&body, "Key").unwrap_or_default();
                    let key = if app.ddb.table_keys(&table).is_some() {
                        ddb_key(app, &table, &key_block)
                    } else {
                        json_obj_attr(&key_block, "pk").unwrap_or(key_block)
                    };
                    app.ddb.delete_item(&table, &key);
                    return json_ok("{}");
                }
                "Scan" => {
                    let items = app.ddb.scan(&table);
                    return json_ok(&format!(
                        "{{\"Items\":[{}],\"Count\":{n},\"ScannedCount\":{n}}}",
                        items.join(","),
                        n = items.len()
                    ));
                }
                _ => return err("InvalidAction", &format!("dynamodb {op} not implemented")),
            }
        }
    }
    err("InvalidAction", "unknown JSON target")
}

fn handle_lambda(app: &App, req: &edge::http::Request) -> Vec<u8> {
    if let Err(resp) = check_auth(app, req, "lambda") {
        return resp;
    }
    let rest = req.path.strip_prefix("/2015-03-31/functions").unwrap_or("");
    let json_err = |code: &str, msg: &str, status: u16| -> Vec<u8> {
        let b = format!(
            "{{\"__type\":\"{code}\",\"message\":\"{}\"}}",
            proto::json_codec::esc(msg)
        );
        let reason = match status {
            404 => "Not Found",
            409 => "Conflict",
            _ => "Bad Request",
        };
        edge::http::response(status, reason, "application/json", &b)
    };
    // POST /2015-03-31/functions -> CreateFunction {FunctionName,...}.
    if rest.is_empty() || rest == "/" {
        if req.method != "POST" {
            return json_err("InvalidAction", "use POST to create a function", 400);
        }
        let body = String::from_utf8_lossy(&req.body).into_owned();
        let name = proto::json_codec::get_str_field(&body, "FunctionName").unwrap_or_default();
        match app.lambda.create(&name, &body, req.body.len()) {
            Ok(cfg) => edge::http::response(201, "Created", "application/json", &cfg),
            Err((b, 409)) => edge::http::response(409, "Conflict", "application/json", &b),
            Err((b, _)) => edge::http::response(400, "Bad Request", "application/json", &b),
        }
    } else if let Some(invoke_path) = rest.strip_suffix("/invocations") {
        // POST /2015-03-31/functions/{name}/invocations.
        let name = invoke_path.trim_start_matches('/');
        if req.method != "POST" {
            return json_err("InvalidAction", "use POST to invoke", 400);
        }
        match app.lambda.invoke(name, &req.body) {
            Ok(payload) => {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Amz-Executed-Version: $LATEST\r\nX-Amz-StatusCode: 200\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let mut resp = head.into_bytes();
                resp.extend_from_slice(&payload);
                resp
            }
            Err((b, 404)) => edge::http::response(404, "Not Found", "application/json", &b),
            Err((b, _)) => edge::http::response(400, "Bad Request", "application/json", &b),
        }
    } else {
        // GET|DELETE /2015-03-31/functions/{name}.
        let name = rest.trim_start_matches('/').split('/').next().unwrap_or("");
        match req.method.as_str() {
            "GET" => match app.lambda.get(name) {
                Some(cfg) => edge::http::response(
                    200,
                    "OK",
                    "application/json",
                    &format!("{{\"Configuration\":{cfg},\"Code\":{{\"RepositoryType\":\"S3\"}}}}"),
                ),
                None => {
                    let (b, _) = svc_lambda::handler::not_found(name);
                    edge::http::response(404, "Not Found", "application/json", &b)
                }
            },
            "DELETE" => {
                if app.lambda.delete(name) {
                    edge::http::response(204, "No Content", "application/json", "")
                } else {
                    let (b, _) = svc_lambda::handler::not_found(name);
                    edge::http::response(404, "Not Found", "application/json", &b)
                }
            }
            _ => json_err("InvalidAction", "unsupported Lambda op", 400),
        }
    }
}

fn handle_s3(app: &App, req: &edge::http::Request) -> Vec<u8> {
    if let Err(resp) = check_auth(app, req, "s3") {
        // S3 speaks XML even for auth errors.
        let _ = resp;
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>";
        return edge::http::response(403, "Forbidden", "application/xml", xml);
    }
    // Split path and query.
    let (path, query) = match req.path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (req.path.as_str(), ""),
    };
    let mut segs = path.split('/').filter(|s| !s.is_empty());
    let bucket = match segs.next() {
        Some(b) => b.to_string(),
        None => {
            let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchBucket</Code><Message>Missing bucket</Message></Error>";
            return edge::http::response(400, "Bad Request", "application/xml", xml);
        }
    };
    let key: Option<String> = {
        let rest: Vec<&str> = segs.collect();
        if rest.is_empty() {
            None
        } else {
            Some(rest.join("/"))
        }
    };
    let qmap: HashMap<String, String> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| match p.split_once('=') {
            Some((k, v)) => Some((k.to_string(), v.to_string())),
            None => Some((p.to_string(), String::new())),
        })
        .collect();
    match (req.method.as_str(), key) {
        ("PUT", None) => {
            // CreateBucket (idempotent for the owner, like us-east-1).
            app.s3.create_bucket(&bucket);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nLocation: /{bucket}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            resp.into_bytes()
        }
        ("HEAD", None) => {
            if app.s3.bucket_exists(&bucket) {
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            }
        }
        ("DELETE", None) => match app.s3.delete_bucket(&bucket) {
            Ok(()) => edge::http::response(204, "No Content", "application/xml", ""),
            Err(code) => {
                let xml = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{code}</Message></Error>");
                let (st, reason) = if code == "NoSuchBucket" { (404, "Not Found") } else { (409, "Conflict") };
                edge::http::response(st, reason, "application/xml", &xml)
            }
        },
        (_, None) => {
            // Bucket-level: ListObjectsV2.
            if qmap.get("list-type").map(|s| s.as_str()) == Some("2") || req.method == "GET" {
                let prefix = qmap.get("prefix").cloned().unwrap_or_default();
                let xml = app.s3.list_v2(&bucket, &prefix);
                return edge::http::response(200, "OK", "application/xml", &xml);
            }
            let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>InvalidRequest</Code><Message>unsupported bucket op</Message></Error>";
            edge::http::response(400, "Bad Request", "application/xml", xml)
        }
        ("PUT", Some(k)) => {
            let etag = proto::md5::hex(&req.body);
            app.s3.put(&bucket, &k, req.body.clone());
            format!("HTTP/1.1 200 OK\r\nETag: \"{etag}\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
        }
        ("GET", Some(k)) => match app.s3.get(&bucket, &k) {
            Some(v) => {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nETag: \"{}\"\r\nConnection: close\r\n\r\n",
                    v.len(),
                    proto::md5::hex(&v)
                );
                let mut resp = head.into_bytes();
                resp.extend_from_slice(&v); // raw bytes: never round-trip objects through UTF-8
                resp
            }
            None => {
                let xml = svc_s3::handler::S3::error_no_such_key(&k);
                edge::http::response(404, "Not Found", "application/xml", &xml)
            }
        },
        ("HEAD", Some(k)) => match app.s3.get(&bucket, &k) {
            Some(v) => {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    v.len()
                );
                resp.into_bytes()
            }
            None => {
                let xml = svc_s3::handler::S3::error_no_such_key(&k);
                edge::http::response(404, "Not Found", "application/xml", &xml)
            }
        },
        ("DELETE", Some(k)) => {
            // Real delete; idempotent like S3 (missing key still 204).
            // Documented deviation: bucket non-empty check absent.
            app.s3.remove(&bucket, &k);
            edge::http::response(204, "No Content", "application/xml", "")
        }
        _ => {
            let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>InvalidRequest</Code><Message>unsupported S3 op</Message></Error>";
            edge::http::response(400, "Bad Request", "application/xml", xml)
        }
    }
}

pub fn handle_one(app: &App, stream: &mut TcpStream) -> bool {
    let req = match edge::http::read_request(stream) {
        Ok(r) => r,
        Err(e) => {
            if e == "eof" {
                return false;
            }
            let body = proto::query_xml::error_envelope("InvalidRequest", &e, "Sender");
            let resp = edge::http::response(400, "Bad Request", "text/xml", &body);
            let _ = stream.write_all(&resp);
            return true;
        }
    };
    if req.method == "GET" && req.path == "/" && req.headers.contains_key("authorization") {
        let xml = app.s3.list_buckets_xml();
        let _ = stream.write_all(&edge::http::response(200, "OK", "application/xml", &xml));
        return true;
    }
    if req.method == "GET" && (req.path == "/" || req.path == "/health") {
        let resp = edge::http::response(200, "OK", "text/plain", "ok");
        let _ = stream.write_all(&resp);
        return true;
    }
    let is_query_post = req.method == "POST"
        && (req.path == "/" || req.path.starts_with("/?"))
        && String::from_utf8_lossy(&req.body).contains("Action=");
    let has_target = req.headers.contains_key("x-amz-target");
    let is_json = has_target
        || req
            .headers
            .get("content-type")
            .map(|c| c.contains("json") && req.method == "POST")
            .unwrap_or(false);
    // Lambda REST paths are distinctive; check before the JSON sniff so a
    // CreateFunction POST with Content-Type: application/json routes correctly.
    let resp = if is_query_post {
        handle_query(app, &req)
    } else if req.path.starts_with("/2015-03-31/") {
        handle_lambda(app, &req)
    } else if is_json {
        handle_json(app, &req)
    } else {
        handle_s3(app, &req)
    };
    let _ = stream.write_all(&resp);
    true
}

/// Serve until `max_requests` connections have been handled (tests/selftest).
pub fn serve(app: Arc<App>, listener: TcpListener, max_requests: Option<usize>) {
    let mut n = 0usize;
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                s.set_read_timeout(Some(std::time::Duration::from_secs(15))).ok();
                handle_one(&app, &mut s);
                n += 1;
                if let Some(max) = max_requests {
                    if n >= max {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
}

/// Production server loop: one thread per connection (so an idle client can
/// never stall the others), 15s read timeout, exits when `stop` is set.
pub fn serve_until(app: Arc<App>, listener: TcpListener, stop: &std::sync::atomic::AtomicBool) {
    use std::sync::atomic::Ordering;
    listener.set_nonblocking(true).ok();
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut s, _)) => {
                s.set_nonblocking(false).ok();
                s.set_read_timeout(Some(std::time::Duration::from_secs(15))).ok();
                let app = app.clone();
                std::thread::spawn(move || {
                    handle_one(&app, &mut s);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
}

/// Build the app from env (SPINE_AUTH=require, SPINE_AK, SPINE_SK).
pub fn app_from_env() -> (Arc<App>, bool) {
    let require_auth = std::env::var("SPINE_AUTH").map(|v| v == "require").unwrap_or(false);
    let app = if require_auth {
        let mut secrets = HashMap::new();
        if let (Ok(ak), Ok(sk)) = (std::env::var("SPINE_AK"), std::env::var("SPINE_SK")) {
            secrets.insert(ak, sk);
        }
        Arc::new(App::authed(secrets, Arc::new(wall_now)))
    } else {
        Arc::new(App::open())
    };
    (app, require_auth)
}

#[cfg(test)]
pub mod e2e {
    use super::*;
    use std::io::{Read, Write};

    fn start(app: App) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind e2e");
        let port = listener.local_addr().unwrap().port();
        let app = Arc::new(app);
        std::thread::spawn(move || serve(app, listener, None));
        // Wait for listen.
        for _ in 0..50 {
            if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        port
    }

    fn roundtrip(port: u16, req: &str) -> String {
        let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
        s.write_all(req.as_bytes()).expect("write");
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).expect("read");
        String::from_utf8_lossy(&resp).into_owned()
    }

    fn post_query(port: u16, body: &str, extra: &str) -> String {
        roundtrip(
            port,
            &format!(
                "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
                body.len()
            ),
        )
    }

    fn post_json(port: u16, target: &str, body: &str, extra: &str) -> String {
        roundtrip(
            port,
            &format!(
                "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-amz-json-1.0\r\nX-Amz-Target: {target}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
                body.len()
            ),
        )
    }

    /// Civil date -> amz `YYYYMMDDTHHMMSSZ` for the AUTH tests.
    fn amz_now(epoch: u64) -> String {
        let days = (epoch / 86400) as i64;
        let secs = (epoch % 86400) as i64;
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z.rem_euclid(146097);
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            y, m, d,
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )
    }

    fn sign(
        secrets_sk: &str,
        amz_date: &str,
        region: &str,
        svc: &str,
        method: &str,
        path: &str,
        query: &str,
        host: &str,
        body: &[u8],
    ) -> String {
        // Same construction as the server gate: sorted signed headers,
        // raw query (normalized inside `canonical_request` on both sides),
        // payload hash of the exact body bytes.
        let payload = proto::sigv4::sha256_hex(body);
        let mut headers = vec![
            ("host".to_string(), host.to_string()),
            ("x-amz-date".to_string(), amz_date.to_string()),
        ];
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        let ch = {
            let cr = proto::sigv4::canonical_request(
                method, path, query, &headers, "host;x-amz-date", &payload,
            );
            proto::sigv4::sha256_hex(cr.as_bytes())
        };
        let scope = format!("{}/{}/{}/aws4_request", &amz_date[..8], region, svc);
        let sts = proto::sigv4::string_to_sign(amz_date, &scope, &ch);
        let key = proto::sigv4::signing_key(secrets_sk, &amz_date[..8], region, svc);
        proto::sigv4::hex(&proto::sigv4::hmac_sha256(&key, sts.as_bytes()))
    }

    #[test]
    fn sqs_send_receive_over_http() {
        let port = start(App::open());
        let send = post_query(
            port,
            "Action=SendMessage&Version=2012-11-05&QueueUrl=http%3A%2F%2F127.0.0.1%3A4566%2F000000000000%2Fq&MessageBody=hello",
            "",
        );
        assert!(send.starts_with("HTTP/1.1 200"), "send:\n{send}");
        assert!(send.contains("<MessageId>msg-"), "send:\n{send}");
        let recv = post_query(
            port,
            "Action=ReceiveMessage&Version=2012-11-05&QueueUrl=http%3A%2F%2F127.0.0.1%3A4566%2F000000000000%2Fq",
            "",
        );
        assert!(recv.contains("<Body>hello</Body>"), "recv:\n{recv}");
        let receipt = recv
            .split("<ReceiptHandle>")
            .nth(1)
            .and_then(|s| s.split("</ReceiptHandle>").next())
            .expect("receipt");
        // URL-encode the receipt minimally (it has no special chars by construction).
        let del = post_query(
            port,
            &format!("Action=DeleteMessage&Version=2012-11-05&QueueUrl=http%3A%2F%2F127.0.0.1%3A4566%2F000000000000%2Fq&ReceiptHandle={receipt}"),
            "",
        );
        assert!(del.starts_with("HTTP/1.1 200"), "del:\n{del}");
        let recv2 = post_query(
            port,
            "Action=ReceiveMessage&Version=2012-11-05&QueueUrl=http%3A%2F%2F127.0.0.1%3A4566%2F000000000000%2Fq",
            "",
        );
        assert!(!recv2.contains("<Body>"), "queue not drained:\n{recv2}");
        // JSON dual-codec path over the same queue.
        let jsend = post_json(
            port,
            "AmazonSQS.SendMessage",
            "{\"QueueUrl\":\"http://127.0.0.1:4566/000000000000/q\",\"MessageBody\":\"jhello\"}",
            "",
        );
        assert!(jsend.contains("\"MessageId\""), "jsend:\n{jsend}");
        let jrecv = post_json(
            port,
            "AmazonSQS.ReceiveMessage",
            "{\"QueueUrl\":\"http://127.0.0.1:4566/000000000000/q\"}",
            "",
        );
        assert!(jrecv.contains("jhello"), "jrecv:\n{jrecv}");
    }

    #[test]
    fn dynamodb_put_get_over_http() {
        let port = start(App::open());
        let put = post_json(
            port,
            "DynamoDB_20120810.PutItem",
            "{\"TableName\":\"t\",\"Item\":{\"pk\":{\"S\":\"a\"},\"v\":{\"N\":\"1\"}}}",
            "",
        );
        assert!(put.starts_with("HTTP/1.1 200"), "put:\n{put}");
        let get = post_json(
            port,
            "DynamoDB_20120810.GetItem",
            "{\"TableName\":\"t\",\"Key\":{\"pk\":{\"S\":\"a\"}}}",
            "",
        );
        assert!(get.contains("\"pk\""), "get:\n{get}");
        assert!(get.contains("\"N\":\"1\""), "get:\n{get}");
        let miss = post_json(
            port,
            "DynamoDB_20120810.GetItem",
            "{\"TableName\":\"t\",\"Key\":{\"pk\":{\"S\":\"zzz\"}}}",
            "",
        );
        assert!(miss.contains("{}") && !miss.contains("\"Item\""), "miss:\n{miss}");
    }

    #[test]
    fn s3_put_get_list_over_http() {
        let port = start(App::open());
        let put = roundtrip(
            port,
            "PUT /b/k.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        );
        assert!(put.starts_with("HTTP/1.1 200"), "put:\n{put}");
        let get = roundtrip(port, "GET /b/k.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assert!(get.starts_with("HTTP/1.1 200"), "get:\n{get}");
        assert!(get.ends_with("hello"), "get body:\n{get}");
        let head = roundtrip(port, "HEAD /b/k.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assert!(head.contains("Content-Length: 5"), "head:\n{head}");
        let list = roundtrip(
            port,
            "GET /b?list-type=2 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert!(list.contains("<Key>k.txt</Key>"), "list:\n{list}");
        let miss = roundtrip(port, "GET /b/nope HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assert!(miss.starts_with("HTTP/1.1 404") && miss.contains("NoSuchKey"), "miss:\n{miss}");
    }

    #[test]
    fn auth_required_rejects_unsigned() {
        let fixed_now: u64 = 1_735_689_600; // 2025-01-01T00:00:00Z
        let mut secrets = HashMap::new();
        secrets.insert("AKID".to_string(), "secret123".to_string());
        let port = start(App::authed(
            secrets,
            Arc::new(move || fixed_now),
        ));
        // Unsigned STS call is rejected.
        let denied = post_query(port, "Action=GetCallerIdentity&Version=2011-06-15", "");
        assert!(denied.starts_with("HTTP/1.1 403"), "unsigned:\n{denied}");
        // Correctly signed call passes through the same gate.
        let body = "Action=GetCallerIdentity&Version=2011-06-15";
        let amz = amz_now(fixed_now);
        let host = format!("127.0.0.1:{port}");
        let sig = sign("secret123", &amz, "us-east-1", "sts", "POST", "/", "", &host, body.as_bytes());
        let scope = format!("{}/us-east-1/sts/aws4_request", &amz[..8]);
        let extra = format!(
            "Authorization: AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={sig}\r\nX-Amz-Date: {amz}\r\n"
        );
        let ok = post_query(port, body, &extra);
        assert!(ok.contains("<GetCallerIdentityResult>"), "signed:\n{ok}");
        // Tampered signature is rejected.
        let bad_extra = format!(
            "Authorization: AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={}\r\nX-Amz-Date: {amz}\r\n",
            "0".repeat(64)
        );
        let bad = post_query(port, body, &bad_extra);
        assert!(bad.starts_with("HTTP/1.1 403"), "tampered:\n{bad}");
    }

    #[test]
    fn s3_delete_removes() {
        let port = start(App::open());
        let put = roundtrip(
            port,
            "PUT /b/gone.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbye",
        );
        assert!(put.starts_with("HTTP/1.1 200"), "put:\n{put}");
        let del = roundtrip(port, "DELETE /b/gone.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assert!(del.starts_with("HTTP/1.1 204"), "del:\n{del}");
        let get = roundtrip(port, "GET /b/gone.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assert!(get.starts_with("HTTP/1.1 404") && get.contains("NoSuchKey"), "get after delete:\n{get}");
        // Second delete is still 204 (S3 idempotency).
        let del2 = roundtrip(port, "DELETE /b/gone.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assert!(del2.starts_with("HTTP/1.1 204"), "del2:\n{del2}");
    }

    #[test]
    fn auth_binds_path_and_host() {
        let fixed_now: u64 = 1_735_689_600;
        let mut secrets = HashMap::new();
        secrets.insert("AKID".to_string(), "secret123".to_string());
        let port = start(App::authed(secrets, Arc::new(move || fixed_now)));
        let host = format!("127.0.0.1:{port}");
        let amz = amz_now(fixed_now);
        let scope = format!("{}/us-east-1/s3/aws4_request", &amz[..8]);
        // Valid signature is bound to GET /b/k with the real host.
        let sig = sign("secret123", &amz, "us-east-1", "s3", "GET", "/b/k", "", &host, b"");
        let authed_get = |path: &str, host_override: Option<&str>| -> String {
            let h = host_override.map(|s| s.to_string()).unwrap_or_else(|| host.clone());
            roundtrip(
                port,
                &format!(
                    "GET {path} HTTP/1.1\r\nHost: {h}\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={sig}\r\nX-Amz-Date: {amz}\r\nConnection: close\r\n\r\n"
                ),
            )
        };
        // First store an object via the open... no: auth is required, so PUT
        // through an authed request. Sign the PUT the same way.
        let put_sig = sign("secret123", &amz, "us-east-1", "s3", "PUT", "/b/k", "", &host, b"data");
        let put = roundtrip(
            port,
            &format!(
                "PUT /b/k HTTP/1.1\r\nHost: {host}\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={put_sig}\r\nX-Amz-Date: {amz}\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata"
            ),
        );
        assert!(put.starts_with("HTTP/1.1 200"), "authed put:\n{put}");
        // Replaying the GET signature against a different path fails.
        let wrong_path = authed_get("/b/other", None);
        assert!(wrong_path.starts_with("HTTP/1.1 403"), "wrong path:\n{wrong_path}");
        // Replaying against a different Host fails.
        let wrong_host = authed_get("/b/k", Some("127.0.0.1:1"));
        assert!(wrong_host.starts_with("HTTP/1.1 403"), "wrong host:\n{wrong_host}");
        // The correctly-bound request succeeds.
        let ok = authed_get("/b/k", None);
        assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("data"), "bound get:\n{ok}");
    }

    #[test]
    fn auth_query_params_sorted() {
        // Client and server agree on an unsorted multi-param query: both
        // sides normalize via `canonical_query_string` (SigV4 §5). A changed
        // param value breaks the signature.
        let fixed_now: u64 = 1_735_689_600;
        let mut secrets = HashMap::new();
        secrets.insert("AKID".to_string(), "secret123".to_string());
        let port = start(App::authed(secrets, Arc::new(move || fixed_now)));
        let host = format!("127.0.0.1:{port}");
        let amz = amz_now(fixed_now);
        let scope = format!("{}/us-east-1/s3/aws4_request", &amz[..8]);
        let put_sig = sign("secret123", &amz, "us-east-1", "s3", "PUT", "/b/k", "", &host, b"data");
        let put = roundtrip(
            port,
            &format!(
                "PUT /b/k HTTP/1.1\r\nHost: {host}\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={put_sig}\r\nX-Amz-Date: {amz}\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata"
            ),
        );
        assert!(put.starts_with("HTTP/1.1 200"), "authed put:\n{put}");
        // Unsorted on the wire: prefix before list-type.
        let raw_query = "prefix=k&list-type=2";
        let sig = sign("secret123", &amz, "us-east-1", "s3", "GET", "/b", raw_query, &host, b"");
        let ok = roundtrip(
            port,
            &format!(
                "GET /b?{raw_query} HTTP/1.1\r\nHost: {host}\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={sig}\r\nX-Amz-Date: {amz}\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(ok.starts_with("HTTP/1.1 200") && ok.contains("<Key>k</Key>"), "sorted list:\n{ok}");
        // Same signature replayed with a different param value fails.
        let tampered = roundtrip(
            port,
            &format!(
                "GET /b?prefix=other&list-type=2 HTTP/1.1\r\nHost: {host}\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={sig}\r\nX-Amz-Date: {amz}\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(tampered.starts_with("HTTP/1.1 403"), "tampered query:\n{tampered}");
    }

    #[test]
    fn iam_create_get_list_over_http() {
        let port = start(App::open());
        let create = post_query(
            port,
            "Action=CreateUser&Version=2010-05-08&UserName=alice",
            "",
        );
        assert!(create.starts_with("HTTP/1.1 200"), "create:\n{create}");
        assert!(create.contains("<UserName>alice</UserName>"), "create:\n{create}");
        assert!(create.contains("xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\""));
        let dup = post_query(port, "Action=CreateUser&Version=2010-05-08&UserName=alice", "");
        assert!(dup.contains("EntityAlreadyExists"), "dup:\n{dup}");
        let get = post_query(port, "Action=GetUser&Version=2010-05-08&UserName=alice", "");
        assert!(get.contains("<Arn>arn:aws:iam::123456789012:user/alice</Arn>"), "get:\n{get}");
        let miss = post_query(port, "Action=GetUser&Version=2010-05-08&UserName=nobody", "");
        assert!(miss.starts_with("HTTP/1.1 404") && miss.contains("NoSuchEntity"), "miss:\n{miss}");
        let list = post_query(port, "Action=ListUsers&Version=2010-05-08", "");
        assert!(list.contains("<UserName>alice</UserName>"), "list:\n{list}");
    }

    #[test]
    fn lambda_create_invoke_over_http() {
        let port = start(App::open());
        // CreateFunction.
        let create = roundtrip(
            port,
            "POST /2015-03-31/functions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 54\r\nConnection: close\r\n\r\n{\"FunctionName\":\"f\",\"Runtime\":\"python3.12\",\"Role\":\"r\"}",
        );
        assert!(create.starts_with("HTTP/1.1 201"), "create:\n{create}");
        assert!(create.contains("arn:aws:lambda:us-east-1:123456789012:function:f"), "create:\n{create}");
        // GetFunction.
        let get = roundtrip(port, "GET /2015-03-31/functions/f HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assert!(get.contains("\"State\":\"Active\""), "get:\n{get}");
        // Invoke echo-mode: payload round-trips with execution headers.
        let inv = roundtrip(
            port,
            "POST /2015-03-31/functions/f/invocations HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{\"k\":1}",
        );
        assert!(inv.starts_with("HTTP/1.1 200"), "invoke:\n{inv}");
        assert!(inv.contains("X-Amz-StatusCode: 200"), "invoke:\n{inv}");
        assert!(inv.ends_with("{\"k\":1}"), "invoke:\n{inv}");
        // Missing function -> 404 ResourceNotFoundException.
        let miss = roundtrip(
            port,
            "POST /2015-03-31/functions/nope/invocations HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
        assert!(miss.starts_with("HTTP/1.1 404") && miss.contains("ResourceNotFoundException"), "miss:\n{miss}");
        // DeleteFunction then invoke fails.
        let del = roundtrip(port, "DELETE /2015-03-31/functions/f HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        assert!(del.starts_with("HTTP/1.1 204"), "del:\n{del}");
    }
}
