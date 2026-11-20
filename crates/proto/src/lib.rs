//! Protocol codecs: Query+XML (STS/IAM/SQS-query-compat), JSON (DynamoDB/Lambda/SQS-json), SigV4.
//!
//! No external dependencies: percent-decoding, XML escaping and envelope
//! rendering are hand-rolled so the runtime crates build offline.

pub mod query_xml {
    use std::collections::HashMap;

    /// Parsed Query-protocol action call: `Action=Foo&Version=...&<params>`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct QueryAction {
        pub action: String,
        pub version: String,
        pub params: HashMap<String, String>,
    }

    pub fn percent_decode(s: &str) -> String {
        let mut out = Vec::with_capacity(s.len());
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b'%' if i + 2 < b.len() => {
                    let h = |c: u8| match c {
                        b'0'..=b'9' => Some(c - b'0'),
                        b'a'..=b'f' => Some(c - b'a' + 10),
                        b'A'..=b'F' => Some(c - b'A' + 10),
                        _ => None,
                    };
                    match (h(b[i + 1]), h(b[i + 2])) {
                        (Some(hi), Some(lo)) => {
                            out.push(hi * 16 + lo);
                            i += 3;
                        }
                        _ => {
                            out.push(b'%');
                            i += 1;
                        }
                    }
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Parse an `application/x-www-form-urlencoded` Query body.
    pub fn parse_query_body(body: &str) -> Result<QueryAction, String> {
        let mut action: Option<String> = None;
        let mut version: Option<String> = None;
        let mut params = HashMap::new();
        for pair in body.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.find('=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, ""),
            };
            let k = percent_decode(k);
            let v = percent_decode(v);
            match k.as_str() {
                "Action" => action = Some(v),
                "Version" => version = Some(v),
                _ => {
                    params.insert(k, v);
                }
            }
        }
        Ok(QueryAction {
            action: action.ok_or_else(|| "missing Action".to_string())?,
            version: version.ok_or_else(|| "missing Version".to_string())?,
            params,
        })
    }

    pub fn xml_escape(s: &str) -> String {
        let mut o = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => o.push_str("&amp;"),
                '<' => o.push_str("&lt;"),
                '>' => o.push_str("&gt;"),
                '"' => o.push_str("&quot;"),
                '\'' => o.push_str("&apos;"),
                c => o.push(c),
            }
        }
        o
    }

    /// Render `GetCallerIdentity` XML envelope (STS 2011-06-15 namespace).
    pub fn caller_identity_envelope(user_id: &str, account: &str, arn: &str) -> String {
        format!(
            "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><UserId>{}</UserId><Account>{}</Account><Arn>{}</Arn></GetCallerIdentityResult><ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></GetCallerIdentityResponse>",
            xml_escape(user_id),
            xml_escape(account),
            xml_escape(arn),
            "01234567-89ab-cdef-0123-456789abcdef"
        )
    }

    /// Generic Query error envelope.
    pub fn error_envelope(code: &str, message: &str, type_: &str) -> String {
        format!(
            "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error><Type>{}</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>{}</RequestId></ErrorResponse>",
            xml_escape(type_),
            xml_escape(code),
            xml_escape(message),
            "01234567-89ab-cdef-0123-456789abcdef"
        )
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn get_caller_identity() {
            // Exact body shape the AWS CLI sends for sts get-caller-identity.
            let body = "Action=GetCallerIdentity&Version=2011-06-15";
            let q = parse_query_body(body).expect("parse");
            assert_eq!(q.action, "GetCallerIdentity");
            assert_eq!(q.version, "2011-06-15");

            let xml = caller_identity_envelope(
                "AKIAIOSFODNN7EXAMPLE",
                "123456789012",
                "arn:aws:iam::123456789012:user/test",
            );
            assert!(xml.contains("<GetCallerIdentityResult>"), "envelope:\n{xml}");
            assert!(xml.contains("<Arn>arn:aws:iam::123456789012:user/test</Arn>"));
            assert!(xml.contains("xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\""));
        }
    }
}

pub mod json_codec {
    /// Minimal JSON string escaper (no serde dependency).
    pub fn esc(s: &str) -> String {
        let mut o = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                '\r' => o.push_str("\\r"),
                '\t' => o.push_str("\\t"),
                c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
                c => o.push(c),
            }
        }
        o
    }

    /// Extract a top-level string field `"key":"value"` from flat JSON.
    /// Sufficient for SQS SendMessage / DynamoDB smoke shapes; not a parser.
    pub fn get_str_field(body: &str, key: &str) -> Option<String> {
        let needle = format!("\"{key}\"");
        let mut i = body.find(&needle)?;
        i += needle.len();
        let rest = &body[i..];
        let rest = rest.trim_start();
        if !rest.starts_with(':') {
            return None;
        }
        let mut rest = rest[1..].trim_start();
        if !rest.starts_with('"') {
            return None;
        }
        rest = &rest[1..];
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(e) = chars.next() {
                        match e {
                            '"' => out.push('"'),
                            '\\' => out.push('\\'),
                            'n' => out.push('\n'),
                            'r' => out.push('\r'),
                            't' => out.push('\t'),
                            c => {
                                out.push('\\');
                                out.push(c);
                            }
                        }
                    }
                }
                '"' => return Some(out),
                c => out.push(c),
            }
        }
        None
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn sqs_send_message() {
            let body = r#"{"QueueUrl":"http://127.0.0.1:4566/000000000000/q","MessageBody":"hello"}"#;
            assert_eq!(
                get_str_field(body, "MessageBody").as_deref(),
                Some("hello")
            );
            assert!(get_str_field(body, "QueueUrl").unwrap().contains("/q"));
            assert_eq!(get_str_field(body, "Missing"), None);
            let resp = format!(
                "{{\"MD5OfMessageBody\":\"{}\",\"MessageId\":\"{}\"}}",
                "5d41402abc4b2a76b9719d911017c592",
                "00000000-0000-0000-0000-000000000000"
            );
            assert!(resp.contains("MD5OfMessageBody"));
        }
    }
}

pub mod sigv4 {
    /// Canonical-header helper: lowercase name, trim+collapse spaces.
    pub fn canonical_header(name: &str, value: &str) -> String {
        let mut v = String::new();
        let mut last_space = true;
        for c in value.trim().chars() {
            if c == ' ' || c == '\t' {
                if !last_space {
                    v.push(' ');
                    last_space = true;
                }
            } else {
                v.push(c);
                last_space = false;
            }
        }
        format!("{}:{}\n", name.to_ascii_lowercase(), v)
    }

    /// SHA-256 over bytes (self-contained; no crypto dep).
    /// Compact implementation for test-vector verification.
    pub fn sha256_hex(data: &[u8]) -> String {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64).wrapping_mul(8);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());
        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }
        let mut s = String::with_capacity(64);
        for v in h {
            s.push_str(&format!("{v:08x}"));
        }
        s
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let hex = sha256_hex(data);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
        const B: usize = 64;
        let mut k = [0u8; B];
        if key.len() > B {
            k[..32].copy_from_slice(&sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; B];
        let mut opad = [0x5cu8; B];
        for i in 0..B {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Vec::with_capacity(B + msg.len());
        inner.extend_from_slice(&ipad);
        inner.extend_from_slice(msg);
        let ih = sha256(&inner);
        let mut outer = Vec::with_capacity(B + 32);
        outer.extend_from_slice(&opad);
        outer.extend_from_slice(&ih);
        sha256(&outer)
    }

    pub fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Derive SigV4 signing key: kDate/kRegion/kService/aws4_request.
    pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
        let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }

    /// Build the SigV4 string-to-sign for a pre-hashed canonical request.
    pub fn string_to_sign(amz_date: &str, scope: &str, canonical_hash: &str) -> String {
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}")
    }

    /// Percent-encode one query name/value per SigV4: unreserved
    /// `A-Z a-z 0-9 - _ . ~` pass through, everything else (including a
    /// literal `%` from an already-encoded client value) becomes `%XX`.
    /// SDKs pre-encode, so the server must encode the raw bytes as received
    /// — never decode first.
    pub fn encode_query_component(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    /// Canonical query string per SigV4 §5: split on `&`, encode each name
    /// and value, sort by (encoded name, encoded value), rejoin.
    /// Cross-checked against an independent Python (urllib) reference.
    pub fn canonical_query_string(raw: &str) -> String {
        if raw.is_empty() {
            return String::new();
        }
        let mut pairs: Vec<(String, String)> = Vec::new();
        for p in raw.split('&') {
            let (n, v) = match p.split_once('=') {
                Some((n, v)) => (n, v),
                None => (p, ""),
            };
            pairs.push((encode_query_component(n), encode_query_component(v)));
        }
        pairs.sort();
        pairs.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("&")
    }

    /// Build an AWS SigV4 canonical request from its parts.
    /// `headers` MUST already be sorted by lowercase name; `signed` is the
    /// `;`-joined signed-headers list; `payload_hash` is hex SHA-256 of the body
    /// (or `UNSIGNED-PAYLOAD`/`STREAMING-...` where the service allows it).
    /// `query_string` is the raw query as received; it is normalized via
    /// `canonical_query_string` (path and Host are never normalized).
    pub fn canonical_request(
        method: &str,
        path: &str,
        query_string: &str,
        headers: &[(String, String)],
        signed: &str,
        payload_hash: &str,
    ) -> String {
        let mut cr = format!("{method}\n{path}\n{}\n", canonical_query_string(query_string));
        for (name, value) in headers {
            cr.push_str(&canonical_header(name, value));
        }
        cr.push('\n');
        cr.push_str(signed);
        cr.push('\n');
        cr.push_str(payload_hash);
        cr
    }

    /// One-shot AWS SigV4 signature over canonical parts (used by tests and
    /// the spine gate; mirrors the documented signing flow).
    pub fn sign_canonical(
        secret: &str,
        amz_date: &str,
        region: &str,
        service: &str,
        method: &str,
        path: &str,
        query_string: &str,
        headers: &[(String, String)],
        signed: &str,
        payload_hash: &str,
    ) -> (String, String) {
        let cr = canonical_request(method, path, query_string, headers, signed, payload_hash);
        let cr_hash = sha256_hex(cr.as_bytes());
        let scope = format!("{}/{}/{}/aws4_request", &amz_date[..8], region, service);
        let sts = string_to_sign(amz_date, &scope, &cr_hash);
        let key = signing_key(secret, &amz_date[..8], region, service);
        (cr_hash, hex(&hmac_sha256(&key, sts.as_bytes())))
    }

    #[derive(Debug, Clone)]
    pub struct Verification {
        pub access_key: String,
        pub scope: String,
        pub signed_headers: Vec<String>,
        pub signature: String,
    }

    /// Parse `Authorization: AWS4-HMAC-SHA256 Credential=AK/DATE/REGION/SVC/aws4_request, SignedHeaders=..., Signature=...`.
    pub fn parse_authorization(v: &str) -> Result<Verification, String> {
        let v = v.trim();
        let rest = v.strip_prefix("AWS4-HMAC-SHA256").ok_or_else(|| "not SigV4".to_string())?;
        let rest = rest.trim();
        let mut cred = None;
        let mut signed = None;
        let mut sig = None;
        for part in rest.split(',') {
            let part = part.trim();
            if let Some(r) = part.strip_prefix("Credential=") {
                cred = Some(r.trim().to_string());
            } else if let Some(r) = part.strip_prefix("SignedHeaders=") {
                signed = Some(r.trim().to_string());
            } else if let Some(r) = part.strip_prefix("Signature=") {
                sig = Some(r.trim().to_string());
            }
        }
        let cred = cred.ok_or_else(|| "missing Credential".to_string())?;
        let mut it = cred.splitn(2, '/');
        let ak = it.next().unwrap_or("").to_string();
        let scope = it.next().unwrap_or("").to_string();
        if ak.is_empty() || scope.is_empty() {
            return Err("bad Credential".to_string());
        }
        // Scope must be DATE/REGION/SERVICE/aws4_request (SigV4 §3).
        let segs: Vec<&str> = scope.split('/').collect();
        if segs.len() != 4 || segs[3] != "aws4_request" {
            return Err(format!("bad scope: {scope}"));
        }
        if segs[0].len() != 8 || !segs[0].bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("bad scope date: {scope}"));
        }
        Ok(Verification {
            access_key: ak,
            scope,
            signed_headers: signed
                .ok_or_else(|| "missing SignedHeaders".to_string())?
                .split(';')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect(),
            signature: sig.ok_or_else(|| "missing Signature".to_string())?,
        })
    }

    /// Verify a signature against the secrets map and a skew window.
    /// `now_epoch` and `amz_date` (`YYYYMMDDTHHMMSSZ`) bound the skew;
    /// `clock_skew_secs` default 900 (15 min, SigV4 §5).
    pub fn verify(
        secrets: &std::collections::HashMap<String, String>,
        auth_header: &str,
        amz_date: &str,
        region: &str,
        service: &str,
        canonical_hash: &str,
        now_epoch: u64,
        clock_skew_secs: u64,
    ) -> Result<String, String> {
        let p = parse_authorization(auth_header)?;
        // host must be signed ( SigV4 requires it; our trap test asserts it).
        if !p.signed_headers.iter().any(|h| h == "host") {
            return Err("host must be a SignedHeader".to_string());
        }
        let req_epoch = parse_amz_date(amz_date)?;
        let skew = req_epoch.abs_diff(now_epoch);
        if skew > clock_skew_secs {
            return Err(format!("clock skew too large: {skew}s"));
        }
        // Scope date must match the request date.
        let scope_date = p.scope.split('/').next().unwrap_or("");
        if &amz_date[..8] != scope_date {
            return Err("scope date != request date".to_string());
        }
        let secret = secrets.get(&p.access_key).ok_or_else(|| "unknown access key".to_string())?;
        let scope = format!("{}/{}/{}/aws4_request", &amz_date[..8], region, service);
        if scope != p.scope {
            return Err(format!("scope mismatch: {} != {}", p.scope, scope));
        }
        let sts = string_to_sign(amz_date, &scope, canonical_hash);
        let key = signing_key(secret, &amz_date[..8], region, service);
        let expect = hex(&hmac_sha256(&key, sts.as_bytes()));
        if expect != p.signature.to_ascii_lowercase() {
            return Err("signature mismatch".to_string());
        }
        Ok(p.access_key)
    }

    fn parse_amz_date(s: &str) -> Result<u64, String> {
        // YYYYMMDDTHHMMSSZ -> epoch via civil-date math (no chrono dep).
        if s.len() != 16 || !s.ends_with('Z') || s.as_bytes()[8] != b'T' {
            return Err(format!("bad amz date: {s}"));
        }
        let num = |a: usize, b: usize| s[a..b].parse::<i64>().map_err(|_| format!("bad amz date: {s}"));
        let (y, mo, d, h, mi, se) = (num(0, 4)?, num(4, 6)?, num(6, 8)?, num(9, 11)?, num(11, 13)?, num(13, 15)?);
        let days = days_from_civil(y, mo, d)?;
        Ok((days * 86400 + h * 3600 + mi * 60 + se) as u64)
    }

    fn days_from_civil(y: i64, m: i64, d: i64) -> Result<i64, String> {
        if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
            return Err("bad date".to_string());
        }
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y.rem_euclid(400);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        Ok(era * 146097 + doe - 719468)
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn aws_vector() {
            // AWS SigV4 test-suite vector: empty string digest.
            assert_eq!(
                sha256_hex(b""),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
            assert_eq!(
                sha256_hex(b"abc"),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            // Header canonicalization preserves Host byte-for-byte (D-plan trap:
            // routing must never normalize the bytes being hashed).
            let h = canonical_header("Host", "  127.0.0.1:4566  ");
            assert_eq!(h, "host:127.0.0.1:4566\n");
        }

        #[test]
        fn hmac_rfc4231() {
            // RFC 4231 Test Cases 1-2: proves the primitive against an
            // external anchor (cross-checked with Python hmac/HMAC-SHA256).
            assert_eq!(
                hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            );
            // TC2 tail cross-checked against Python hmac (stdlib, authoritative);
            // an earlier draft carried a misremembered tail here — the machine wins.
            assert_eq!(
                hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
            );
        }

        #[test]
        fn aws_listusers_vector() {
            // Full AWS SigV4 worked example (IAM ListUsers, 20150830) — proves
            // the whole chain (canonical text, SHA-256, KDF, HMAC) is
            // AWS-compatible, not merely self-consistent.
            // Canonical text per the AWS signing docs; the expected hash and
            // signature were cross-checked with an independent Python
            // (hmac/hashlib) re-implementation before being pinned here.
            let headers = vec![
                ("content-type".to_string(), "application/x-www-form-urlencoded; charset=utf-8".to_string()),
                ("host".to_string(), "iam.amazonaws.com".to_string()),
                ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
            ];
            let cr = canonical_request(
                "GET",
                "/",
                "Action=ListUsers&Version=2010-05-08",
                &headers,
                "content-type;host;x-amz-date",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            );
            assert_eq!(
                cr,
                "GET\n/\nAction=ListUsers&Version=2010-05-08\ncontent-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\nx-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
            let (cr_hash, sig) = sign_canonical(
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                "20150830T123600Z",
                "us-east-1",
                "iam",
                "GET",
                "/",
                "Action=ListUsers&Version=2010-05-08",
                &headers,
                "content-type;host;x-amz-date",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            );
            assert_eq!(cr_hash, "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59");
            assert_eq!(sig, "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
        }

        #[test]
        fn canonical_query() {
            // Expectations produced by the independent Python reference
            // (urllib.quote, safe='-_.~', sort by name then value).
            assert_eq!(canonical_query_string(""), "");
            assert_eq!(
                canonical_query_string("Action=ListUsers&Version=2010-05-08"),
                "Action=ListUsers&Version=2010-05-08"
            );
            assert_eq!(canonical_query_string("b=2&a=1"), "a=1&b=2");
            assert_eq!(canonical_query_string("a=2&a=1&b="), "a=1&a=2&b=");
            // Already-encoded input is NOT decoded: `%` encodes to `%25`.
            assert_eq!(canonical_query_string("x=%2Fy&x=%2Fz"), "x=%252Fy&x=%252Fz");
            assert_eq!(canonical_query_string("q=hello world"), "q=hello%20world");
            assert_eq!(canonical_query_string("plus=a+b"), "plus=a%2Bb");
            assert_eq!(canonical_query_string("enc=%41%42"), "enc=%2541%2542");
            assert_eq!(canonical_query_string("flag"), "flag=");
            assert_eq!(
                canonical_query_string("prefix=my dir/list-type&list-type=2"),
                "list-type=2&prefix=my%20dir%2Flist-type"
            );
            assert_eq!(canonical_query_string("A=1&a=2"), "A=1&a=2");
        }

        #[test]
        fn verify_roundtrip() {
            // Sign-then-verify with a known secret; no network, no clock.
            let mut secrets = std::collections::HashMap::new();
            secrets.insert("AKID".to_string(), "secret123".to_string());
            let amz_date = "20250101T000000Z";
            let (region, service) = ("us-east-1", "sts");
            let canonical_hash = sha256_hex(b"canonical-request-bytes");
            let scope = format!("20250101/{region}/{service}/aws4_request");
            let sts = string_to_sign(amz_date, &scope, &canonical_hash);
            let key = signing_key("secret123", "20250101", region, service);
            let sig = hex(&hmac_sha256(&key, sts.as_bytes()));
            let auth = format!(
                "AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={sig}"
            );
            // now = request time -> skew 0.
            let now = parse_amz_date(amz_date).unwrap();
            assert_eq!(
                verify(&secrets, &auth, amz_date, region, service, &canonical_hash, now, 900).unwrap(),
                "AKID"
            );
            // Tampered signature fails.
            let bad = auth.replace(&sig, &"0".repeat(64));
            assert!(verify(&secrets, &bad, amz_date, region, service, &canonical_hash, now, 900).is_err());
            // Skewed clock fails (2h later).
            assert!(verify(&secrets, &auth, amz_date, region, service, &canonical_hash, now + 7200, 900).is_err());
            // Missing host in SignedHeaders fails.
            let nohost = format!(
                "AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=x-amz-date, Signature={sig}"
            );
            assert!(verify(&secrets, &nohost, amz_date, region, service, &canonical_hash, now, 900).is_err());
            // Unknown key fails.
            let mut empty = std::collections::HashMap::new();
            empty.insert("OTHER".to_string(), "x".to_string());
            assert!(verify(&empty, &auth, amz_date, region, service, &canonical_hash, now, 900).is_err());
        }
    }
}

/// MD5 (RFC 1321), self-contained. Used for SQS `MD5OfMessageBody`, which
/// real SDKs verify against the received body.
pub mod md5 {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64).wrapping_mul(8);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_le_bytes());
        for chunk in msg.chunks_exact(64) {
            let mut m = [0u32; 16];
            for i in 0..16 {
                m[i] = u32::from_le_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
            }
            let (mut a0, mut b0, mut c0, mut d0) = (state[0], state[1], state[2], state[3]);
            for i in 0..64 {
                let (f, g) = if i < 16 {
                    ((b0 & c0) | ((!b0) & d0), i)
                } else if i < 32 {
                    ((d0 & b0) | ((!d0) & c0), (5 * i + 1) % 16)
                } else if i < 48 {
                    (b0 ^ c0 ^ d0, (3 * i + 5) % 16)
                } else {
                    (c0 ^ (b0 | (!d0)), (7 * i) % 16)
                };
                let tmp = d0;
                d0 = c0;
                c0 = b0;
                b0 = b0.wrapping_add(
                    a0.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]).rotate_left(S[i]),
                );
                a0 = tmp;
            }
            state[0] = state[0].wrapping_add(a0);
            state[1] = state[1].wrapping_add(b0);
            state[2] = state[2].wrapping_add(c0);
            state[3] = state[3].wrapping_add(d0);
        }
        let mut out = [0u8; 16];
        for (i, s) in state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&s.to_le_bytes());
        }
        out
    }

    pub fn hex(data: &[u8]) -> String {
        digest(data).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn vectors() {
            // RFC 1321 test suite.
            assert_eq!(hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
            assert_eq!(hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
            assert_eq!(hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
            // Value cross-checked against Python hashlib (which agrees
            // byte-for-byte with this implementation on all six inputs).
            assert_eq!(hex(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
            assert_eq!(
                hex(b"abcdefghijklmnopqrstuvwxyz"),
                "c3fcd3d76192e4007dfb496cca67e13b"
            );
            // The SQS body every SDK test uses.
            assert_eq!(hex(b"hello"), "5d41402abc4b2a76b9719d911017c592");
        }
    }
}
