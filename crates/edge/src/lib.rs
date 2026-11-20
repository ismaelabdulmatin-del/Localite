//! HTTP edge: minimal HTTP/1.1 parsing, Query Action routing, Host preservation.

pub mod route {
    /// Route a Query body to (service, action).
    /// STS/IAM share Query+XML; SQS is Query-compatible; DynamoDB/Lambda are JSON (X-Amz-Target).
    pub fn route_query(body: &str) -> Result<(String, String), String> {
        let q = proto::query_xml::parse_query_body(body)?;
        let svc = match q.action.as_str() {
            "GetCallerIdentity" | "AssumeRole" | "GetSessionToken" => "sts",
            "SendMessage" | "ReceiveMessage" | "DeleteMessage" | "GetQueueUrl"
            | "CreateQueue" | "ListQueues" => "sqs",
            _ if q.version.starts_with("2010") => "iam",
            _ => "unknown",
        };
        Ok((svc.to_string(), q.action))
    }

    /// Route a JSON request via X-Amz-Target header: `DynamoDB_20120810.PutItem`.
    pub fn route_json(target: &str) -> Result<(String, String), String> {
        let (svc_prefix, op) = target
            .split_once('.')
            .ok_or_else(|| format!("bad X-Amz-Target: {target}"))?;
        let svc = if svc_prefix.starts_with("DynamoDB") {
            "dynamodb"
        } else if svc_prefix.starts_with("TrentService") || svc_prefix == "Lambda" {
            "lambda"
        } else {
            svc_prefix
        };
        Ok((svc.to_string(), op.to_string()))
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn query_action() {
            let (svc, action) = route_query("Action=GetCallerIdentity&Version=2011-06-15").unwrap();
            assert_eq!((svc.as_str(), action.as_str()), ("sts", "GetCallerIdentity"));
            let (svc, _) =
                route_json("DynamoDB_20120810.PutItem").unwrap();
            assert_eq!(svc, "dynamodb");
            assert!(route_query("Version=2011-06-15").is_err());
        }
    }
}

pub mod auth {
    use std::collections::HashMap;
    /// Parsed auth context. `host_raw` is the byte-exact Host header value —
    /// routing must never normalize it because Host is inside the SigV4
    /// canonical request (plan trap).
    #[derive(Debug, Clone)]
    pub struct AuthCtx {
        pub host_raw: String,
        pub access_key: Option<String>,
        pub verified: bool,
    }

    pub fn parse_headers(raw_headers: &[(String, String)]) -> HashMap<String, String> {
        let mut m = HashMap::new();
        for (k, v) in raw_headers {
            m.insert(k.to_ascii_lowercase(), v.clone());
        }
        m
    }

    pub fn host_raw(headers: &HashMap<String, String>) -> String {
        headers.get("host").cloned().unwrap_or_default()
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn host_preserved() {
            let raw = vec![
                ("Host".to_string(), "127.0.0.1:4566".to_string()),
                ("Authorization".to_string(), "AWS4-HMAC-SHA256 Credential=AK/20250101/us-east-1/sts/aws4_request".to_string()),
            ];
            let h = parse_headers(&raw);
            assert_eq!(host_raw(&h), "127.0.0.1:4566");
            // Case-insensitive lookup but value byte-preserved.
            let raw2 = vec![("HOST".to_string(), " 127.0.0.1:4566 ".to_string())];
            let h2 = parse_headers(&raw2);
            assert_eq!(host_raw(&h2), " 127.0.0.1:4566 ");
        }
    }
}

pub mod http {
    use std::collections::HashMap;

    #[derive(Debug)]
    pub struct Request {
        pub method: String,
        pub path: String,
        pub headers: HashMap<String, String>,
        pub host_raw: String,
        pub body: Vec<u8>,
    }

    /// Minimal HTTP/1.1 request parser over a buffered stream reader.
    /// Reads headers + exact Content-Length body. No pipelining.
    pub fn read_request(
        stream: &mut impl std::io::Read,
    ) -> Result<Request, String> {
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 4096];
        // Read until end of headers.
        loop {
            let n = stream.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                if buf.is_empty() {
                    return Err("eof".to_string());
                }
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 1_048_576 {
                return Err("headers too large".to_string());
            }
        }
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "bad headers".to_string())?;
        let header_str =
            String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let mut lines = header_str.lines();
        let request_line = lines.next().ok_or_else(|| "empty request".to_string())?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_string();
        let path = parts.next().unwrap_or("/").to_string();
        let mut headers = HashMap::new();
        let mut host_raw = String::new();
        for line in lines {
            if let Some(i) = line.find(':') {
                let name = line[..i].trim().to_string();
                let value = line[i + 1..].trim().to_string();
                if name.eq_ignore_ascii_case("host") && host_raw.is_empty() {
                    host_raw = value.clone();
                }
                headers.insert(name.to_ascii_lowercase(), value);
            }
        }
        let content_len: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = buf[header_end + 4..].to_vec();
        while body.len() < content_len {
            let n = stream.read(&mut tmp).map_err(|e| format!("read body: {e}"))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_len);
        Ok(Request { method, path, headers, host_raw, body })
    }

    pub fn response(
        status: u16,
        reason: &str,
        content_type: &str,
        body: &str,
    ) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }
}
