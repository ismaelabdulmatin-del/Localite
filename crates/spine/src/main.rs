use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use spine::{app_from_env, serve, App};

fn selftest() -> Result<(), String> {
    let app = Arc::new(App::open());
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let port = listener.local_addr().map_err(|e| format!("addr: {e}"))?.port();
    let server = std::thread::spawn(move || serve(app, listener, Some(1)));
    let body = "Action=GetCallerIdentity&Version=2011-06-15";
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| format!("connect: {e}"))?;
    stream.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).map_err(|e| format!("read: {e}"))?;
    server.join().map_err(|_| "server panicked".to_string())?;
    let text = String::from_utf8_lossy(&resp).into_owned();
    if !text.starts_with("HTTP/1.1 200") {
        return Err(format!("expected 200, got:\n{text}"));
    }
    for needle in [
        "<GetCallerIdentityResponse",
        "xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"",
        "<GetCallerIdentityResult>",
        "<Account>123456789012</Account>",
        "arn:aws:iam::123456789012:user/test",
    ] {
        if !text.contains(needle) {
            return Err(format!("missing {needle:?} in:\n{text}"));
        }
    }
    println!("SELFTEST PASS port={port} bytes={}", resp.len());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--selftest") {
        if let Err(e) = selftest() {
            eprintln!("SELFTEST FAIL: {e}");
            std::process::exit(1);
        }
        return;
    }
    let port: u16 = args
        .windows(2)
        .find(|w| w[0] == "--port")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(4566);
    let (app, require_auth) = app_from_env();
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).expect("bind spine");
    println!("spine on 127.0.0.1:{port} auth={}", if require_auth { "required" } else { "open" });
    let stop = std::sync::atomic::AtomicBool::new(false);
    spine::serve_until(app, listener, &stop);
}
