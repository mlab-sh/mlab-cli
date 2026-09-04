//! Test scaffolding: a throwaway HTTP server plus a runner for the `mlab`
//! binary. Both are deliberately dependency-free — a test suite that needs a
//! mock-server crate to check which URL we call is a test suite nobody runs.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

static COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    /// Full request target, query string included.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl RecordedRequest {
    pub fn route(&self) -> String {
        format!("{} {}", self.method, self.path)
    }

    /// Path with the query string stripped.
    pub fn route_path(&self) -> &str {
        self.path.split('?').next().unwrap_or(&self.path)
    }
}

/// A canned answer. Headers matter for the rate-limit path, where the client is
/// supposed to obey `Retry-After`.
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }
}

pub struct TestServer {
    pub url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl TestServer {
    /// Start a server on an ephemeral port. `handler` maps a request to a
    /// `(status, json body)` pair and runs on the server thread.
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(&RecordedRequest) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);

        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&mut stream) else { continue };
                recorded.lock().unwrap().push(request.clone());
                let reply = handler(&request);
                let _ = write_response(&mut stream, &reply);
            }
        });

        Self {
            url: format!("http://127.0.0.1:{port}"),
            requests,
        }
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn routes(&self) -> Vec<String> {
        self.requests().iter().map(RecordedRequest::route).collect()
    }

    pub fn first_matching(&self, needle: &str) -> Option<RecordedRequest> {
        self.requests().into_iter().find(|r| r.path.contains(needle))
    }
}

fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    // A body we never finish reading would break the client's write before it
    // can read our answer, so unbounded bodies are drained on a short timeout.
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body = Vec::new();
    match headers.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        Some(len) if len > 0 => {
            body.resize(len, 0);
            reader.read_exact(&mut body).ok()?;
        }
        _ if method != "GET" => {
            let _ = reader.read_to_end(&mut body);
        }
        _ => {}
    }

    Some(RecordedRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn write_response(stream: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
    let code = reply.status;
    let body = &reply.body;
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let extra: String = reply
        .headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

pub fn json(body: &str) -> Reply {
    Reply { status: 200, body: body.to_string(), headers: Vec::new() }
}

pub fn status_json(code: u16, body: &str) -> Reply {
    Reply { status: code, body: body.to_string(), headers: Vec::new() }
}

pub fn error(code: u16, message: &str) -> Reply {
    status_json(code, &format!(r#"{{"error":"{message}"}}"#))
}

pub fn not_found() -> Reply {
    error(404, "Not found")
}

/// An isolated `$HOME` holding a `.mlab/conf.yml` pointed at the test server, so
/// no test can read or clobber the developer's real credentials.
pub struct TempHome {
    pub path: PathBuf,
}

impl TempHome {
    pub fn new(hostname: &str) -> Self {
        Self::with_key(hostname, "mlab_testkey")
    }

    pub fn with_key(hostname: &str, api_key: &str) -> Self {
        let unique = format!(
            "mlab-cli-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(path.join(".mlab")).expect("create temp home");
        fs::write(
            path.join(".mlab").join("conf.yml"),
            format!("hostname: {hostname}\napi_key: {api_key}\n"),
        )
        .expect("write conf.yml");
        Self { path }
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn mlab(home: &TempHome, args: &[&str]) -> Output {
    mlab_env(home, args, &[])
}

pub fn mlab_env(home: &TempHome, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mlab"));
    cmd.args(args)
        .env_remove("MLAB_API_KEY")
        .env_remove("MLAB_HOSTNAME")
        .env_remove("MLAB_CVE_HOSTNAME")
        .env("HOME", &home.path)
        .env("NO_COLOR", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run the mlab binary")
}

/// Exit codes the CLI promises; asserted rather than hardcoded per test so the
/// contract lives in one place.
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_AUTH: i32 = 2;
pub const EXIT_QUOTA: i32 = 3;
pub const EXIT_INPUT: i32 = 4;
pub const EXIT_MAINTENANCE: i32 = 5;
pub const EXIT_NOT_FOUND: i32 = 6;

pub fn read_config(home: &TempHome) -> String {
    fs::read_to_string(home.path.join(".mlab").join("conf.yml")).unwrap_or_default()
}

/// Run the CLI with something on stdin — the pipe case `mlab ioc` exists for.
pub fn mlab_stdin(home: &TempHome, args: &[&str], input: &str) -> Output {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = Command::new(env!("CARGO_BIN_EXE_mlab"))
        .args(args)
        .env_remove("MLAB_API_KEY")
        .env("HOME", &home.path)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the mlab binary");

    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("write stdin");

    child.wait_with_output().expect("collect output")
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}
