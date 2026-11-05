//! Hermetic tests. They use loopback servers and a mock phone. No route changes.
use super::*;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

const TOKEN: &str = "speed-token-canary";

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

fn loopback_index() -> u32 {
    let name = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    normalization::interface_index(name).unwrap()
}

fn secrets() -> Secrets {
    udp_diag::parse_secrets(&format!(r#"{{"token":"{TOKEN}"}}"#)).unwrap()
}

/// Loopback HTTP server. GET on /down streams bytes until the client closes.
/// GET on /small returns a short body. POST on /up reads the body and answers 200.
/// Any other path answers 404. It counts requests by kind.
#[derive(Default)]
struct HttpCounts {
    down: AtomicU64,
    up: AtomicU64,
    up_bytes: AtomicU64,
    small: AtomicU64,
    not_found: AtomicU64,
    hosts_ok: AtomicU64,
}

fn http_server(counts: Arc<HttpCounts>, expect_host: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let counts = counts.clone();
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).is_err() || head.len() > 8192 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&head).to_string();
                if text.contains(&format!("\r\nHost: {expect_host}")) {
                    counts.hosts_ok.fetch_add(1, Ordering::Relaxed);
                }
                let line = text.lines().next().unwrap_or("").to_owned();
                if line.starts_with("GET /down ") {
                    counts.down.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                    let block = vec![0x55u8; 64 * 1024];
                    // About 32 MB/s for each flow, so that a test does not reach the byte cap.
                    while stream.write_all(&block).is_ok() {
                        thread::sleep(Duration::from_millis(2));
                    }
                } else if line.starts_with("GET /small ") {
                    counts.small.fetch_add(1, Ordering::Relaxed);
                    let _ =
                        stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
                } else if line.starts_with("POST /up ") {
                    counts.up.fetch_add(1, Ordering::Relaxed);
                    let length: u64 = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    let mut left = length;
                    let mut buffer = vec![0u8; 64 * 1024];
                    while left > 0 {
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                thread::sleep(Duration::from_millis(1));
                                left = left.saturating_sub(n as u64);
                                counts.up_bytes.fetch_add(n as u64, Ordering::Relaxed);
                            }
                        }
                    }
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                } else {
                    // Other local programs can reach a loopback listener. Count only our path.
                    if line.starts_with("GET /missing ") {
                        counts.not_found.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ =
                        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                }
            });
        }
    });
    address
}

/// Mock phone proxy. It checks the token, records the requested domain, and
/// forwards CONNECT to `upstream`. An auth-only session ends after the token.
#[derive(Default)]
struct PhoneCounts {
    auth_ok: AtomicU64,
    auth_bad: AtomicU64,
    connects: AtomicU64,
    domain_ok: AtomicU64,
}

fn mock_phone(upstream: SocketAddr, counts: Arc<PhoneCounts>, domain: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let counts = counts.clone();
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let mut hello = [0; 3];
                // Other local programs can reach a loopback listener. Ignore non-SOCKS5 input.
                if s.read_exact(&mut hello).is_err() || hello[0] != 5 {
                    return;
                }
                let _ = s.write_all(&[5, 2]);
                let mut head = [0; 2];
                if s.read_exact(&mut head).is_err() {
                    return;
                }
                let mut user = vec![0; head[1] as usize];
                let mut plen = [0; 1];
                if s.read_exact(&mut user).is_err() || s.read_exact(&mut plen).is_err() {
                    return;
                }
                let mut pass = vec![0; plen[0] as usize];
                if s.read_exact(&mut pass).is_err() {
                    return;
                }
                if pass != TOKEN.as_bytes() {
                    counts.auth_bad.fetch_add(1, Ordering::Relaxed);
                    let _ = s.write_all(&[1, 1]);
                    return;
                }
                counts.auth_ok.fetch_add(1, Ordering::Relaxed);
                let _ = s.write_all(&[1, 0]);
                let mut req = [0; 4];
                if s.read_exact(&mut req).is_err() {
                    return; // auth-only probe
                }
                assert_eq!(req[1], 1, "CONNECT only");
                match req[3] {
                    3 => {
                        let mut len = [0; 1];
                        s.read_exact(&mut len).unwrap();
                        let mut name = vec![0; len[0] as usize];
                        s.read_exact(&mut name).unwrap();
                        if name == domain.as_bytes() {
                            counts.domain_ok.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    1 => {
                        let mut ip = [0; 4];
                        s.read_exact(&mut ip).unwrap();
                    }
                    _ => {
                        let mut ip = [0; 16];
                        s.read_exact(&mut ip).unwrap();
                    }
                }
                let mut port = [0; 2];
                s.read_exact(&mut port).unwrap();
                counts.connects.fetch_add(1, Ordering::Relaxed);
                let Ok(up) = TcpStream::connect(upstream) else {
                    let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
                    return;
                };
                let _ = s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                let _ = s.set_read_timeout(None);
                let mut a_read = s.try_clone().unwrap();
                let mut a_write = s;
                let mut b_read = up.try_clone().unwrap();
                let mut b_write = up;
                let t = thread::spawn(move || {
                    let _ = io::copy(&mut a_read, &mut b_write);
                    let _ = b_write.shutdown(std::net::Shutdown::Write);
                });
                let _ = io::copy(&mut b_read, &mut a_write);
                let _ = a_write.shutdown(std::net::Shutdown::Both);
                let _ = t.join();
            });
        }
    });
    address
}

fn base_config(phone: SocketAddr, port: u16) -> SpeedConfig {
    SpeedConfig {
        phone,
        iface: loopback_index(),
        host: "speed.example.test".into(),
        address: None,
        port,
        download_path: Some("/down".into()),
        upload_path: Some("/up".into()),
        probe_path: Some("/small".into()),
        streams: 2,
        seconds: 1.5,
        idle_seconds: 0.6,
        warmup: 0.5,
        probe_interval: Duration::from_millis(200),
        max_bytes: 2_000_000_000,
        connect_timeout: Duration::from_secs(3),
        udp_target: None,
    }
}

#[test]
fn phone_path_measures_load_and_probes_with_audited_sockets() {
    let http = Arc::new(HttpCounts::default());
    let upstream = http_server(http.clone(), "speed.example.test:");
    let phone_counts = Arc::new(PhoneCounts::default());
    let phone = mock_phone(upstream, phone_counts.clone(), "speed.example.test");
    let config = base_config(phone, upstream.port());
    let report = run_path(
        PathKind::Phone,
        &config,
        Some(&secrets()),
        None,
        &AtomicBool::new(false),
    );
    let phases = report["phases"].as_array().unwrap();
    assert_eq!(phases.len(), 3);
    assert_eq!(phases[0]["phase"], "idle");
    assert!(phases[0].get("throughput").is_none());
    assert!(
        phases[0]["latency"]["connect_ms"]["count"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert!(phases[0]["latency"]["ttfb_ms"]["count"].as_u64().unwrap() >= 2);
    assert!(
        phases[0]["latency"]["phone_auth_ms"]["count"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert_eq!(phases[0]["latency"]["success_percent"], 100.0);
    let down = &phases[1];
    assert_eq!(down["phase"], "download");
    assert!(down["throughput"]["bytes_counted"].as_u64().unwrap() > 1_000_000);
    assert!(down["throughput"]["mbps_after_warmup"].as_f64().unwrap() > 0.0);
    assert!(down["latency"]["connect_ms"]["count"].as_u64().unwrap() >= 1);
    let up = &phases[2];
    assert_eq!(up["phase"], "upload");
    assert!(up["throughput"]["bytes_counted"].as_u64().unwrap() > 100_000);
    assert!(http.up_bytes.load(Ordering::Relaxed) > 0);
    // The target device never resolved the name. The phone saw the domain each time.
    assert_eq!(
        phone_counts.domain_ok.load(Ordering::Relaxed),
        phone_counts.connects.load(Ordering::Relaxed)
    );
    assert!(http.hosts_ok.load(Ordering::Relaxed) > 0);
    // One outer socket per load request and per probe. Every socket has TTL 65.
    assert_eq!(report["ttl_bad"], 0);
    let outer = report["outer_sockets"].as_u64().unwrap();
    let opened = phone_counts.auth_ok.load(Ordering::Relaxed);
    assert_eq!(outer, opened, "each phone session is its own outer socket");
    assert_eq!(phone_counts.auth_bad.load(Ordering::Relaxed), 0);
    assert!(!report.to_string().contains(TOKEN));
}

#[test]
fn direct_path_uses_numeric_address_and_no_phone() {
    let http = Arc::new(HttpCounts::default());
    let upstream = http_server(http.clone(), "127.0.0.1:");
    let mut config = base_config("127.0.0.1:9".parse().unwrap(), upstream.port());
    config.host = "127.0.0.1".into();
    config.address = Some(upstream.ip());
    config.upload_path = None;
    let report = run_path(
        PathKind::Direct,
        &config,
        None,
        None,
        &AtomicBool::new(false),
    );
    let phases = report["phases"].as_array().unwrap();
    assert_eq!(phases.len(), 2);
    assert_eq!(phases[0]["latency"]["phone_auth_ms"], Value::Null);
    assert!(phases[1]["throughput"]["bytes_counted"].as_u64().unwrap() > 0);
    assert_eq!(report["ttl_bad"], 0);
    assert!(http.down.load(Ordering::Relaxed) >= 2);
}

#[test]
fn byte_cap_ends_the_phase_early() {
    let http = Arc::new(HttpCounts::default());
    let upstream = http_server(http, "speed.example.test:");
    let phone = mock_phone(
        upstream,
        Arc::new(PhoneCounts::default()),
        "speed.example.test",
    );
    let mut config = base_config(phone, upstream.port());
    config.upload_path = None;
    config.idle_seconds = 0.0;
    config.seconds = 10.0;
    config.max_bytes = 3_000_000;
    let started = Instant::now();
    let report = run_path(
        PathKind::Phone,
        &config,
        Some(&secrets()),
        None,
        &AtomicBool::new(false),
    );
    assert!(started.elapsed() < Duration::from_secs(6));
    let down = &report["phases"][0];
    assert_eq!(down["throughput"]["reached_byte_cap"], true);
    assert_eq!(down["throughput"]["ended_early"], true);
}

#[test]
fn http_errors_stop_the_workers_without_hammering() {
    let http = Arc::new(HttpCounts::default());
    let upstream = http_server(http.clone(), "speed.example.test:");
    let phone = mock_phone(
        upstream,
        Arc::new(PhoneCounts::default()),
        "speed.example.test",
    );
    let mut config = base_config(phone, upstream.port());
    config.download_path = Some("/missing".into());
    config.upload_path = None;
    config.probe_path = None;
    config.idle_seconds = 0.0;
    config.seconds = 5.0;
    config.streams = 2;
    let report = run_path(
        PathKind::Phone,
        &config,
        Some(&secrets()),
        None,
        &AtomicBool::new(false),
    );
    let down = &report["phases"][0]["throughput"];
    assert_eq!(down["http_errors"], 6, "3 consecutive failures per stream");
    assert_eq!(down["bytes_counted"], 0);
    assert_eq!(http.not_found.load(Ordering::Relaxed), 6);
}

#[test]
fn wrong_token_counts_probe_and_open_failures() {
    let http = Arc::new(HttpCounts::default());
    let upstream = http_server(http.clone(), "x");
    let counts = Arc::new(PhoneCounts::default());
    let phone = mock_phone(upstream, counts.clone(), "speed.example.test");
    let mut config = base_config(phone, upstream.port());
    config.upload_path = None;
    config.idle_seconds = 0.5;
    config.seconds = 2.0;
    config.streams = 1;
    let wrong = udp_diag::parse_secrets(r#"{"token":"wrong-token"}"#).unwrap();
    let report = run_path(
        PathKind::Phone,
        &config,
        Some(&wrong),
        None,
        &AtomicBool::new(false),
    );
    assert_eq!(report["phases"][0]["latency"]["success_percent"], 0.0);
    assert_eq!(report["phases"][1]["throughput"]["open_errors"], 3);
    assert_eq!(counts.auth_ok.load(Ordering::Relaxed), 0);
    assert_eq!(http.down.load(Ordering::Relaxed), 0);
    assert!(!report.to_string().contains("wrong-token"));
}

#[test]
fn stop_flag_ends_quickly() {
    let http = Arc::new(HttpCounts::default());
    let upstream = http_server(http, "speed.example.test:");
    let phone = mock_phone(
        upstream,
        Arc::new(PhoneCounts::default()),
        "speed.example.test",
    );
    let mut config = base_config(phone, upstream.port());
    config.seconds = 20.0;
    config.idle_seconds = 20.0;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let stopper = thread::spawn(move || {
        thread::sleep(Duration::from_millis(500));
        flag.store(true, Ordering::Release);
    });
    let started = Instant::now();
    let runs = run_all(
        &[PathKind::Phone],
        3,
        &config,
        Some(&secrets()),
        None,
        &stop,
    );
    stopper.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(runs.len(), 1);
}

#[test]
fn run_all_alternates_order_and_summary_uses_medians() {
    let http = Arc::new(HttpCounts::default());
    let upstream = http_server(http, "127.0.0.1:");
    let phone = mock_phone(upstream, Arc::new(PhoneCounts::default()), "unused");
    let mut config = base_config(phone, upstream.port());
    config.host = "127.0.0.1".into();
    config.address = Some(upstream.ip());
    config.upload_path = None;
    config.probe_path = None;
    config.idle_seconds = 0.4;
    config.seconds = 1.2;
    config.warmup = 0.2;
    let kinds = [PathKind::Phone, PathKind::Direct];
    let runs = run_all(
        &kinds,
        2,
        &config,
        Some(&secrets()),
        None,
        &AtomicBool::new(false),
    );
    let order: Vec<_> = runs
        .iter()
        .map(|r| r["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        order,
        [
            "phone_proxy",
            "laptop_direct",
            "laptop_direct",
            "phone_proxy"
        ]
    );
    let summary = summarize(&runs, &kinds);
    assert_eq!(summary["phone_proxy"]["repetitions"], 2);
    assert!(
        summary["laptop_direct"]["download_mbps_median"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    assert_eq!(summary["laptop_direct"]["upload_mbps_median"], Value::Null);
}

#[test]
fn percentiles_use_nearest_rank() {
    let values: Vec<f64> = (1..=100).map(f64::from).collect();
    let p = percentiles(&values);
    assert_eq!(p["p50"], 50.0);
    assert_eq!(p["p95"], 95.0);
    assert_eq!(p["p99"], 99.0);
    assert_eq!(p["max"], 100.0);
    assert_eq!(percentiles(&[])["p50"], Value::Null);
    assert_eq!(percentiles(&[7.0])["p99"], 7.0);
}

#[test]
fn status_parser_and_request_head() {
    assert_eq!(
        parse_status(b"HTTP/1.1 200 OK\r\n\r\nbody"),
        Some(Ok((200, 19)))
    );
    assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), None);
    assert_eq!(parse_status(b"SSH-2.0\r\n\r\n"), Some(Err(())));
    let head = request_head("POST", "/up", "h.test", 8080, Some(10));
    assert!(head.starts_with("POST /up HTTP/1.1\r\nHost: h.test:8080\r\n"));
    assert!(head.contains("Content-Length: 10\r\n") && head.ends_with("\r\n\r\n"));
    assert!(
        request_head("GET", "/", "2001:db8::1", 8080, None).contains("Host: [2001:db8::1]:8080")
    );
    assert!(request_head("GET", "/", "h.test", 80, None).contains("Host: h.test\r\n"));
}

#[test]
fn options_are_scoped_bounded_and_secret_free() {
    let base = [
        "--phone",
        "172.20.10.1:1080",
        "--iface",
        "en6",
        "--host",
        "speed.example.net",
        "--download-path",
        "/down",
    ];
    let ok = parse_options(&args(&base)).unwrap();
    assert_eq!(ok.paths, vec![PathKind::Phone]);
    assert_eq!(
        (ok.streams, ok.seconds, ok.warmup, ok.probe_interval_ms),
        (4, 20.0, 3.0, 1000)
    );
    assert_eq!(ok.address, None);
    assert_eq!(ok.planned_max_bytes(), 200_000_000);
    let numeric = parse_options(&args(&[
        "--phone",
        "172.20.10.1:1080",
        "--iface",
        "en6",
        "--host",
        "93.184.215.14",
        "--download-path",
        "/d",
        "--upload-path",
        "/u",
        "--paths",
        "phone,direct",
        "--repeat",
        "3",
    ]))
    .unwrap();
    assert_eq!(numeric.address, Some("93.184.215.14".parse().unwrap()));
    assert_eq!(numeric.planned_max_bytes(), 200_000_000 * 2 * 2 * 3);
    let with = |extra: &[&str]| {
        let mut all: Vec<&str> = base.to_vec();
        all.extend_from_slice(extra);
        parse_options(&args(&all))
    };
    for bad in [
        vec!["--paths", "direct"],
        vec!["--streams", "17"],
        vec!["--streams", "0"],
        vec!["--seconds", "31"],
        vec!["--warmup", "20"],
        vec!["--repeat", "6"],
        vec!["--max-mb", "2001"],
        vec!["--probe-interval-ms", "50"],
        vec!["--port", "443"],
        vec!["--address", "192.168.1.5"],
        vec!["--address", "100.64.0.1"],
        vec!["--probe-path", "relative"],
        vec!["--udp-target", "10.0.0.1:19302"],
        vec!["--udp-target", "74.125.250.129:0"],
    ] {
        assert!(with(&bad).is_err(), "accepted {bad:?}");
    }
    for bad_host in ["https://speed.example.net", "bad host", "-x.example", ""] {
        let mut all = base.to_vec();
        all[5] = bad_host;
        assert!(parse_options(&args(&all)).is_err(), "accepted {bad_host}");
    }
    let mut no_load = base.to_vec();
    no_load.truncate(6);
    assert!(parse_options(&args(&no_load)).is_err());
    assert!(with(&["--udp-target", "74.125.250.129:19302"]).is_ok());
    assert!(!VALUE_FLAGS
        .iter()
        .any(|f| f.contains("token") || f.contains("secret=")));
}
