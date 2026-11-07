//! Linux tunnel start tests inside a disposable VM.
//!
//! These tests create a TUN device, a network namespace, a veth pair, and
//! policy routes. They are ignored by default. CI must not run them. Run them
//! as root on a disposable Linux host. See `docs/LINUX_TEST_VM.md`.
//!
//! The source device mock runs in a network namespace at `10.213.0.2`. The
//! engine pins its outer sockets to `hs-host0` at `10.213.0.1`. The source
//! device address is not local, so a broken outer policy rule cannot hide
//! behind the local table.
#![cfg(target_os = "linux")]

mod support;

use hotspotshade::phone::PhoneProxy;
use hotspotshade::platform_linux::{OUTER_RULE_PRIORITY, TUNNEL_RULE_PRIORITY, TUNNEL_TABLE};
use hotspotshade::service::{Ipv6Policy, Service, TunOptions};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use support::socks::{MockSocksSource, SocksAddress, SocksConfig, SocksObservation};
use support::{TEST_TOKEN, TEST_USER};

/// The physical test interface. It is a veth link, so the link type check must
/// accept it and the outer rule must name it.
const HOST_IF: &str = "hs-host0";
/// The veth end in the source device namespace.
const SOURCE_IF: &str = "hs-src0";
/// The source device namespace.
const SOURCE_NS: &str = "hs-vm-net";
/// The host address of the veth pair.
const HOST_ADDR: &str = "10.213.0.1";
/// The source device address of the veth pair.
const SOURCE_ADDR: Ipv4Addr = Ipv4Addr::new(10, 213, 0, 2);
/// The first inner destination. It is in `0.0.0.0/1`.
const FLOW_ONE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
/// The second inner destination. It is in `128.0.0.0/1`.
const FLOW_TWO: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 11);
/// The inner IPv6 destination. It is in `2000::/3`.
const FLOW_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10);
/// The environment variable that marks the mock child process.
const MOCK_ENV: &str = "HS_LINUX_VM_MOCK";
/// The environment variable that names the mock report file.
const MOCK_FILE_ENV: &str = "HS_LINUX_VM_MOCK_FILE";
/// The environment variable that marks the direct echo child process.
const ECHO_ENV: &str = "HS_LINUX_VM_ECHO";
/// The environment variable that names the echo ready file.
const ECHO_FILE_ENV: &str = "HS_LINUX_VM_ECHO_FILE";

/// The tests change global routing state. Run them one at a time.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
    SERIAL
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn require_root() {
    assert_eq!(
        std::env::var("HS_DISPOSABLE_LINUX_VM").as_deref(),
        Ok("1"),
        "set HS_DISPOSABLE_LINUX_VM=1 only inside a disposable Linux VM"
    );
    let uid = unsafe { libc::geteuid() };
    assert_eq!(
        uid, 0,
        "the Linux tunnel test needs root. Run it with sudo on a disposable VM."
    );
}

fn ip_path() -> PathBuf {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if Path::new(candidate).is_file() {
            return PathBuf::from(candidate);
        }
    }
    panic!("the ip tool is not installed");
}

fn ip_output(args: &[&str]) -> std::process::Output {
    Command::new(ip_path())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("cannot run ip {args:?}: {error}"))
}

fn ip_run(args: &[&str]) -> String {
    let output = ip_output(args);
    assert!(
        output.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8_lossy(&output.stdout).replace('\r', "")
}

fn ip_quiet(args: &[&str]) {
    let _ = ip_output(args);
}

/// The routing state that the tunnel must restore.
///
/// The snapshot holds IPv4 addresses only. An IPv6 link-local address on the
/// test link can move from tentative to preferred while the test runs. That
/// change is not tunnel state.
#[derive(Debug, PartialEq, Eq)]
struct NetState {
    v4_routes: String,
    v6_routes: String,
    v4_rules: String,
    v6_rules: String,
    links: String,
    v4_addrs: String,
}

fn table_text() -> String {
    TUNNEL_TABLE.to_string()
}

/// Read one route table. A family without that FIB table is empty.
fn table_routes(family: &str) -> String {
    let table = table_text();
    let output = ip_output(&[family, "route", "show", "table", &table]);
    if output.status.success() {
        return String::from_utf8_lossy(&output.stdout).replace('\r', "");
    }
    let error = String::from_utf8_lossy(&output.stderr);
    if error.contains("FIB table does not exist") {
        return String::new();
    }
    panic!(
        "ip {family} route show table {table} failed: {}",
        error.trim()
    );
}

fn snapshot() -> NetState {
    NetState {
        v4_routes: table_routes("-4"),
        v6_routes: table_routes("-6"),
        v4_rules: ip_run(&["-4", "rule", "show"]),
        v6_rules: ip_run(&["-6", "rule", "show"]),
        links: ip_run(&["-o", "link", "show"]),
        v4_addrs: ip_run(&["-4", "-o", "addr", "show"]),
    }
}

fn has_tun(ifname: &str) -> bool {
    ip_run(&["-o", "link", "show"])
        .lines()
        .any(|line| line.contains(&format!(": {ifname}:")))
}

fn has_rule(text: &str) -> bool {
    let v4 = ip_run(&["-4", "rule", "show"]);
    let v6 = ip_run(&["-6", "rule", "show"]);
    v4.contains(text) || v6.contains(text)
}

/// The veth pair and the source device namespace.
struct TestNet {
    host: String,
}

impl TestNet {
    fn create() -> Self {
        Self::create_with_direct(false)
    }

    /// Create the test network for direct mode. The source device namespace
    /// owns the inner destination, and a main-table host route sends the outer
    /// socket to the namespace over the veth pair.
    fn create_direct() -> Self {
        Self::create_with_direct(true)
    }

    fn create_with_direct(direct: bool) -> Self {
        require_root();
        // The VM is disposable. Remove objects from an earlier failed run with
        // the same fixed names before a new run.
        ip_quiet(&["netns", "delete", SOURCE_NS]);
        ip_quiet(&["link", "delete", HOST_IF]);
        ip_run(&["netns", "add", SOURCE_NS]);
        // Own the namespace before the remaining setup commands can fail.
        // Drop then removes both it and any partially created host link.
        let net = Self {
            host: HOST_IF.to_owned(),
        };
        ip_run(&[
            "link", "add", HOST_IF, "type", "veth", "peer", "name", SOURCE_IF,
        ]);
        ip_run(&["link", "set", SOURCE_IF, "netns", SOURCE_NS]);
        ip_run(&["addr", "add", &format!("{HOST_ADDR}/24"), "dev", HOST_IF]);
        ip_run(&["link", "set", HOST_IF, "up"]);
        ip_run(&["netns", "exec", SOURCE_NS, "ip", "link", "set", "lo", "up"]);
        ip_run(&[
            "netns",
            "exec",
            SOURCE_NS,
            "ip",
            "addr",
            "add",
            &format!("{SOURCE_ADDR}/24"),
            "dev",
            SOURCE_IF,
        ]);
        ip_run(&[
            "netns", "exec", SOURCE_NS, "ip", "link", "set", SOURCE_IF, "up",
        ]);
        if direct {
            // The echo server in the namespace owns the inner destination.
            ip_run(&[
                "netns",
                "exec",
                SOURCE_NS,
                "ip",
                "addr",
                "add",
                &format!("{FLOW_ONE}/32"),
                "dev",
                SOURCE_IF,
            ]);
            // An outer socket that is pinned to the veth uses this route.
            ip_run(&["route", "add", &format!("{FLOW_ONE}/32"), "dev", HOST_IF]);
        }
        // Let the link flags settle before the pre-test snapshot.
        thread::sleep(Duration::from_millis(200));
        net
    }
}

impl Drop for TestNet {
    fn drop(&mut self) {
        ip_quiet(&["link", "delete", &self.host]);
        ip_quiet(&["netns", "delete", SOURCE_NS]);
    }
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hs-linux-vm-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test directory");
    dir
}

fn wait_for_file(path: &Path, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if path.is_file() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    path.is_file()
}

fn address_text(address: &SocksAddress) -> String {
    match address {
        SocksAddress::V4(octets) => Ipv4Addr::from(*octets).to_string(),
        SocksAddress::V6(octets) => std::net::Ipv6Addr::from(*octets).to_string(),
        SocksAddress::Domain(name) => name.clone(),
    }
}

/// The mock source device runs in its own process inside the namespace.
struct MockChild {
    child: Child,
    dir: PathBuf,
}

impl MockChild {
    fn start() -> Self {
        let dir = temp_dir("mock");
        let port_file = dir.join("mock-port");
        let log_path = dir.join("mock.log");
        let log = std::fs::File::create(&log_path).expect("create mock log");
        let exe = std::env::current_exe().expect("test binary path");
        let child = Command::new(ip_path())
            .args([
                "netns",
                "exec",
                SOURCE_NS,
                exe.to_str().expect("test binary path"),
                "--exact",
                "linux_vm_mock_source",
                "--ignored",
                "--nocapture",
            ])
            .env(MOCK_ENV, "1")
            .env(MOCK_FILE_ENV, &port_file)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start the mock source device");
        assert!(
            wait_for_file(&port_file, Duration::from_secs(10)),
            "the mock source device did not report its port. See {}",
            log_path.display()
        );
        Self { child, dir }
    }

    fn port(&self) -> u16 {
        std::fs::read_to_string(self.dir.join("mock-port"))
            .expect("read mock port")
            .trim()
            .parse()
            .expect("mock port is a number")
    }

    fn phone(&self) -> SocketAddr {
        SocketAddr::new(SOURCE_ADDR.into(), self.port())
    }

    fn stop(mut self) -> Value {
        let done = self.dir.join("mock-port.done");
        std::fs::write(self.dir.join("mock-port.stop"), b"stop").expect("stop the mock");
        assert!(
            wait_for_file(&done, Duration::from_secs(10)),
            "the mock source device did not write a report"
        );
        let text = std::fs::read_to_string(&done).expect("read mock report");
        let value: Value = serde_json::from_str(&text).expect("parse mock report");
        let status = self.child.wait().expect("wait for the mock");
        assert!(status.success(), "the mock source device failed");
        value
    }
}

impl Drop for MockChild {
    fn drop(&mut self) {
        let _ = std::fs::write(self.dir.join("mock-port.stop"), b"stop");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The direct-mode echo server runs in the source device namespace.
struct DirectEchoChild {
    child: Child,
    dir: PathBuf,
}

impl DirectEchoChild {
    fn start() -> Self {
        let dir = temp_dir("echo");
        let ready = dir.join("echo-ready");
        let log_path = dir.join("echo.log");
        let log = std::fs::File::create(&log_path).expect("create echo log");
        let exe = std::env::current_exe().expect("test binary path");
        let child = Command::new(ip_path())
            .args([
                "netns",
                "exec",
                SOURCE_NS,
                exe.to_str().expect("test binary path"),
                "--exact",
                "linux_vm_direct_echo",
                "--ignored",
                "--nocapture",
            ])
            .env(ECHO_ENV, "1")
            .env(ECHO_FILE_ENV, &ready)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start the direct echo server");
        assert!(
            wait_for_file(&ready, Duration::from_secs(10)),
            "the direct echo server did not report readiness. See {}",
            log_path.display()
        );
        Self { child, dir }
    }

    fn stop(mut self) -> Value {
        let ready = self.dir.join("echo-ready");
        let done = self.dir.join("echo-ready.done");
        std::fs::write(self.dir.join("echo-ready.stop"), b"stop").expect("stop the echo server");
        assert!(
            wait_for_file(&done, Duration::from_secs(10)),
            "the direct echo server did not write a report"
        );
        let text = std::fs::read_to_string(&done).expect("read echo report");
        let value: Value = serde_json::from_str(&text).expect("parse echo report");
        assert!(
            ready.is_file(),
            "the echo server readiness file disappeared"
        );
        let status = self.child.wait().expect("wait for the echo server");
        assert!(status.success(), "the direct echo server failed");
        value
    }
}

impl Drop for DirectEchoChild {
    fn drop(&mut self) {
        let _ = std::fs::write(self.dir.join("echo-ready.stop"), b"stop");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_engine(phone: SocketAddr) -> Service {
    let service = Service::new();
    let options = TunOptions {
        iface: Some(HOST_IF.to_owned()),
        ipv6: Ipv6Policy::Forward,
        ..TunOptions::default()
    };
    let proxy = PhoneProxy {
        address: phone,
        username: TEST_USER.into(),
        token: TEST_TOKEN.into(),
        iface: None,
        timeout: Duration::from_secs(5),
    };
    service
        .start_tun_options_cancellable(options, Some(proxy), 2, &AtomicBool::new(false))
        .expect("start the Linux tunnel");
    service
}

fn start_direct_engine(ipv6: Ipv6Policy) -> Service {
    let service = Service::new();
    let options = TunOptions {
        iface: Some(HOST_IF.to_owned()),
        ipv6,
        ..TunOptions::default()
    };
    service
        .start_tun_options_cancellable(options, None, 2, &AtomicBool::new(false))
        .expect("start the Linux direct tunnel");
    service
}

fn tcp_flow(destination: Ipv4Addr) -> io::Result<()> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::new(destination.into(), 80),
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"flow")?;
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo)?;
    if &echo != b"flow" {
        return Err(io::Error::other("the echo bytes do not match"));
    }
    Ok(())
}

fn flow_with_retry(destination: Ipv4Addr, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if tcp_flow(destination).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

fn tcp_flow_v6(destination: Ipv6Addr) -> io::Result<()> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::new(destination.into(), 80),
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"flow6")?;
    let mut echo = [0u8; 5];
    stream.read_exact(&mut echo)?;
    if &echo != b"flow6" {
        return Err(io::Error::other("the IPv6 echo bytes do not match"));
    }
    Ok(())
}

fn v6_flow_with_retry(destination: Ipv6Addr, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if tcp_flow_v6(destination).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

fn wait_for_tunnel(ifname: &str, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if has_tun(ifname) && has_rule(&format!("{TUNNEL_RULE_PRIORITY}:")) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn requests(report: &Value) -> Vec<Value> {
    report["observations"]
        .as_array()
        .expect("mock observations")
        .iter()
        .filter_map(|item| item["request"].as_object().map(|_| item.clone()))
        .collect()
}

fn assert_clean_report(report: &Value, minimum_connections: usize) {
    assert_eq!(
        report["failures"],
        json!([]),
        "the mock source device reported failures"
    );
    assert!(
        report["connections"].as_u64().unwrap_or(0) >= minimum_connections as u64,
        "the mock source device accepted too few connections"
    );
    let observations = report["observations"]
        .as_array()
        .expect("mock observations");
    assert!(observations
        .iter()
        .all(|item| item["auth_ok"].as_bool() == Some(true)));
}

#[test]
#[ignore = "child process for the Linux direct tunnel VM test"]
fn linux_vm_direct_echo() {
    if std::env::var(ECHO_ENV).as_deref() != Ok("1") {
        return;
    }
    let file = PathBuf::from(std::env::var(ECHO_FILE_ENV).expect("echo file path"));
    let listener = TcpListener::bind(SocketAddr::new(FLOW_ONE.into(), 80))
        .expect("bind the direct echo server");
    listener
        .set_nonblocking(true)
        .expect("set the echo listener nonblocking");
    std::fs::write(&file, b"ready").expect("write the echo ready file");
    let stop = PathBuf::from(format!("{}.stop", file.display()));
    let mut connections = 0u64;
    let mut failures = Vec::new();
    while !stop.is_file() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                connections += 1;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buffer = [0u8; 16];
                match stream.read(&mut buffer) {
                    Ok(0) => failures.push("empty connection".to_string()),
                    Ok(count) => {
                        if let Err(error) = stream.write_all(&buffer[..count]) {
                            failures.push(error.to_string());
                        }
                    }
                    Err(error) => failures.push(error.to_string()),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                failures.push(error.to_string());
                break;
            }
        }
    }
    let summary = json!({"connections": connections, "failures": failures});
    std::fs::write(
        format!("{}.done", file.display()),
        serde_json::to_string(&summary).expect("serialize the echo report"),
    )
    .expect("write the echo report");
}

#[test]
#[ignore = "child process for the Linux tunnel VM test"]
fn linux_vm_mock_source() {
    if std::env::var(MOCK_ENV).as_deref() != Ok("1") {
        return;
    }
    let file = std::env::var(MOCK_FILE_ENV).expect("mock file path");
    let address = SocketAddr::new(SOURCE_ADDR.into(), 0);
    let mut mock = MockSocksSource::start_on(address, SocksConfig::default())
        .expect("start the mock source device");
    let port = mock.address().port();
    std::fs::write(&file, port.to_string()).expect("write the mock port");
    let stop = format!("{file}.stop");
    let deadline = Instant::now() + Duration::from_secs(120);
    while !Path::new(&stop).is_file() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    let report = mock.stop();
    let observations: Vec<Value> = report
        .observations
        .iter()
        .map(|item: &SocksObservation| {
            json!({
                "connection": item.connection,
                "auth_ok": item.auth_ok,
                "request": item.request.as_ref().map(|request| json!({
                    "command": request.command,
                    "address": address_text(&request.address),
                    "port": request.port,
                })),
            })
        })
        .collect();
    let summary = json!({
        "connections": report.connections,
        "failures": report.failures,
        "observations": observations,
    });
    std::fs::write(
        format!("{file}.done"),
        serde_json::to_string(&summary).expect("serialize the mock report"),
    )
    .expect("write the mock report");
}

#[test]
#[ignore = "needs a disposable Linux VM with root, a TUN device, and routes"]
fn tcp_flow_uses_one_outer_socket_with_ttl_65() {
    let _serial = serial();
    let _net = TestNet::create();
    let mock = MockChild::start();
    let before = snapshot();
    let service = start_engine(mock.phone());
    assert_eq!(service.status()["running"], true);
    assert_eq!(service.status()["mode"], "phone");
    assert_eq!(service.status()["iface"], HOST_IF);

    assert!(
        tcp_flow(FLOW_ONE).is_ok(),
        "the first inner TCP flow did not complete"
    );
    assert!(
        tcp_flow(FLOW_TWO).is_ok(),
        "the second inner TCP flow did not complete"
    );

    // The worker publishes its counters every 100 ms. Wait for the two flows
    // and the TTL audit instead of reading one early snapshot.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = service.status();
        let tcp_flows = status["stats"]["tcp_flows"].as_u64().unwrap_or(0);
        let ttl_bad = status["stats"]["ttl_bad"].as_u64().unwrap_or(0);
        if tcp_flows >= 2 && ttl_bad == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the relay did not record two inner TCP flows with a clean TTL audit: {}",
            status["stats"]
        );
        thread::sleep(Duration::from_millis(100));
    }
    let status = service.status();
    assert_eq!(status["stats"]["ttl_bad"], 0, "the TTL audit failed");
    assert_eq!(status["stats"]["ipv6_dropped"], 0);

    service.stop();
    assert!(!service.is_running());
    let after = snapshot();
    assert_eq!(
        before, after,
        "the tunnel did not restore the routing state"
    );
    assert!(!has_tun("hs-tun0"), "the TUN device remained");

    let report = mock.stop();
    assert_clean_report(&report, 3);
    assert_eq!(
        report["connections"].as_u64(),
        Some(3),
        "the check and two flows must use three outer sockets"
    );
    let connected = requests(&report);
    assert_eq!(connected.len(), 2, "each inner flow opens one outer socket");
    let addresses: HashSet<String> = connected
        .iter()
        .map(|item| item["request"]["address"].as_str().unwrap_or("").to_owned())
        .collect();
    assert!(addresses.contains(&FLOW_ONE.to_string()));
    assert!(addresses.contains(&FLOW_TWO.to_string()));
    let ports: HashSet<u64> = connected
        .iter()
        .map(|item| item["request"]["port"].as_u64().unwrap_or(0))
        .collect();
    assert_eq!(ports, HashSet::from([80]));
    assert!(connected.iter().all(|item| item["request"]["command"] == 1));
}

/// The kernel selects an IPv6 source address for the inner flow. The test
/// needs a host with an IPv6 source address. It does not add one to the TUN.
#[test]
#[ignore = "needs a disposable Linux VM with root, a TUN device, and routes"]
fn ipv6_tcp_flow_uses_the_tunnel() {
    let _serial = serial();
    let _net = TestNet::create();
    let mock = MockChild::start();
    let before = snapshot();
    let service = start_engine(mock.phone());
    assert_eq!(service.status()["running"], true);

    assert!(
        v6_flow_with_retry(FLOW_V6, Duration::from_secs(10)),
        "the inner IPv6 TCP flow did not complete"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = service.status();
        let tcp_flows = status["stats"]["tcp_flows"].as_u64().unwrap_or(0);
        let ttl_bad = status["stats"]["ttl_bad"].as_u64().unwrap_or(0);
        let ipv6_dropped = status["stats"]["ipv6_dropped"].as_u64().unwrap_or(0);
        if tcp_flows >= 1 && ttl_bad == 0 && ipv6_dropped == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the relay did not record the IPv6 flow with a clean audit: {}",
            status["stats"]
        );
        thread::sleep(Duration::from_millis(100));
    }

    service.stop();
    assert!(!service.is_running());
    let after = snapshot();
    assert_eq!(
        before, after,
        "the tunnel did not restore the routing state"
    );
    assert!(!has_tun("hs-tun0"), "the TUN device remained");

    let report = mock.stop();
    assert_clean_report(&report, 2);
    assert_eq!(
        report["connections"].as_u64(),
        Some(2),
        "the check and the IPv6 flow must use two outer sockets"
    );
    let connected = requests(&report);
    assert_eq!(connected.len(), 1, "the IPv6 flow opens one outer socket");
    assert_eq!(
        connected[0]["request"]["address"].as_str(),
        Some("2001:db8::10")
    );
    assert_eq!(connected[0]["request"]["port"].as_u64(), Some(80));
    assert_eq!(connected[0]["request"]["command"], 1);
}

/// A direct-mode flow uses the TUN and opens one outer socket. The source
/// device namespace owns the destination and echoes the payload. No source
/// device app runs.
#[test]
#[ignore = "needs a disposable Linux VM with root, a TUN device, and routes"]
fn direct_tcp_flow_uses_one_outer_socket_with_ttl_65() {
    let _serial = serial();
    let _net = TestNet::create_direct();
    let echo = DirectEchoChild::start();
    let before = snapshot();
    let service = start_direct_engine(Ipv6Policy::Block);
    assert_eq!(service.status()["running"], true);
    assert_eq!(service.status()["mode"], "tun");
    assert_eq!(service.status()["iface"], HOST_IF);

    assert!(
        tcp_flow(FLOW_ONE).is_ok(),
        "the direct inner TCP flow did not complete"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = service.status();
        let tcp_flows = status["stats"]["tcp_flows"].as_u64().unwrap_or(0);
        let ttl_bad = status["stats"]["ttl_bad"].as_u64().unwrap_or(0);
        if tcp_flows >= 1 && ttl_bad == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the direct relay did not record the flow with a clean TTL audit: {}",
            status["stats"]
        );
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(service.status()["stats"]["ttl_bad"], 0);

    service.stop();
    assert!(!service.is_running());
    let after = snapshot();
    assert_eq!(
        before, after,
        "the direct tunnel did not restore the routing state"
    );
    assert!(!has_tun("hs-tun0"), "the TUN device remained");

    let report = echo.stop();
    assert_eq!(report["failures"], json!([]));
    assert!(
        report["connections"].as_u64().unwrap_or(0) >= 1,
        "the direct echo server accepted no connection"
    );
}

/// Direct mode installs the blackhole in table 700 and the start gate proves
/// that every global unicast probe is blocked.
#[test]
#[ignore = "needs a disposable Linux VM with root, a TUN device, and routes"]
fn direct_ipv6_block_installs_and_verifies_the_blackhole() {
    let _serial = serial();
    let _net = TestNet::create();
    let before = snapshot();
    let service = start_direct_engine(Ipv6Policy::Block);
    assert_eq!(service.status()["running"], true);
    assert_eq!(service.status()["mode"], "tun");
    let table = table_routes("-6");
    assert!(
        table.contains("blackhole 2000::/3"),
        "the IPv6 block route is missing: {table}"
    );
    assert!(
        table.contains("proto 196"),
        "the IPv6 block route has the wrong protocol: {table}"
    );
    let probe = ip_output(&["-6", "route", "get", "2606:4700:4700::1111"]);
    assert!(
        !probe.status.success(),
        "an IPv6 probe was not blocked: {}",
        String::from_utf8_lossy(&probe.stdout)
    );

    service.stop();
    assert!(!service.is_running());
    assert_eq!(
        before,
        snapshot(),
        "the block run did not restore the state"
    );
    assert!(!has_tun("hs-tun0"));
}

/// Direct forward mode is explicit and installs the tunnel route instead of the
/// blackhole. No IPv6 flow runs, so the test host does not need an IPv6 source.
#[test]
#[ignore = "needs a disposable Linux VM with root, a TUN device, and routes"]
fn direct_ipv6_forward_installs_the_tunnel_route() {
    let _serial = serial();
    let _net = TestNet::create();
    let before = snapshot();
    let service = start_direct_engine(Ipv6Policy::Forward);
    assert_eq!(service.status()["running"], true);
    let table = table_routes("-6");
    assert!(
        table.contains("2000::/3 dev hs-tun0"),
        "the IPv6 forward route is missing: {table}"
    );
    assert!(
        !table.contains("blackhole"),
        "the forward run installed a blackhole: {table}"
    );
    service.stop();
    assert!(!service.is_running());
    assert_eq!(
        before,
        snapshot(),
        "the forward run did not restore the state"
    );
    assert!(!has_tun("hs-tun0"));
}

/// The worker stops after 20 seconds without the physical link. It removes the
/// routes, rules, address, and TUN device.
#[test]
#[ignore = "needs a disposable Linux VM with root, a TUN device, and routes"]
fn direct_link_loss_stops_the_tunnel() {
    let _serial = serial();
    let _net = TestNet::create();
    let before = snapshot();
    let service = start_direct_engine(Ipv6Policy::Block);
    assert_eq!(service.status()["running"], true);

    ip_run(&["link", "set", HOST_IF, "down"]);
    let deadline = Instant::now() + Duration::from_secs(40);
    while service.is_running() {
        assert!(
            Instant::now() < deadline,
            "the tunnel did not stop after the link went down"
        );
        thread::sleep(Duration::from_millis(200));
    }
    let status = service.status();
    assert_eq!(status["last_stop"]["reason"], "hotspot_lost");
    assert!(status["last_stop"]["at"].as_u64().is_some());
    assert_eq!(status["error"], Value::Null);
    assert!(!has_tun("hs-tun0"), "the TUN device remained");
    assert!(!has_rule(&format!("{OUTER_RULE_PRIORITY}:")));
    assert!(!has_rule(&format!("{TUNNEL_RULE_PRIORITY}:")));
    assert_eq!(table_routes("-4").trim(), "");
    assert_eq!(table_routes("-6").trim(), "");

    ip_run(&["link", "set", HOST_IF, "up"]);
    thread::sleep(Duration::from_millis(200));
    let after = snapshot();
    assert_eq!(after.v4_routes, before.v4_routes);
    assert_eq!(after.v6_routes, before.v6_routes);
    assert_eq!(after.v4_rules, before.v4_rules);
    assert_eq!(after.v6_rules, before.v6_rules);
    assert_eq!(after.v4_addrs, before.v4_addrs);
}

fn cli_command(phone: SocketAddr, unit: u32, log: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hotspotshade"));
    command
        .args([
            "tun",
            "--iface",
            HOST_IF,
            "--phone",
            &phone.to_string(),
            "--ipv6",
            "forward",
            "--unit",
            &unit.to_string(),
        ])
        .env("HOTSPOTSHADE_PHONE_TOKEN", TEST_TOKEN)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            std::fs::File::create(log.with_extension("out")).expect("create CLI output"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(log.with_extension("err")).expect("create CLI error output"),
        ));
    command
}

fn stop_child(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the engine process did not stop within {limit:?}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// One engine child process. A failed test must not leave it running with the
/// test routes installed.
struct EngineProcess {
    child: Child,
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "needs a disposable Linux VM with root, a TUN device, and routes"]
fn sigterm_stop_restores_the_pre_test_state() {
    let _serial = serial();
    let _net = TestNet::create();
    let mock = MockChild::start();
    let before = snapshot();
    let dir = temp_dir("sigterm");
    let log = dir.join("engine.log");
    let mut engine = EngineProcess {
        child: cli_command(mock.phone(), 1, &log)
            .spawn()
            .expect("start the engine"),
    };
    assert!(
        wait_for_tunnel("hs-tun1", Duration::from_secs(20)),
        "the engine did not create its table and rules. See {}",
        log.with_extension("err").display()
    );
    assert!(
        flow_with_retry(FLOW_ONE, Duration::from_secs(10)),
        "the inner flow did not complete"
    );

    let pid = engine.child.id() as i32;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = stop_child(&mut engine.child, Duration::from_secs(15));
    assert!(status.success(), "the engine exited with {status:?}");

    let after = snapshot();
    assert_eq!(before, after, "SIGTERM did not restore the routing state");
    assert!(!has_tun("hs-tun1"));

    let report = mock.stop();
    assert_eq!(report["failures"], json!([]));
    assert!(report["connections"].as_u64().unwrap_or(0) >= 2);
    assert!(requests(&report)
        .iter()
        .any(|item| item["request"]["address"] == FLOW_ONE.to_string()));
}

#[test]
#[ignore = "needs a disposable Linux VM with root, a TUN device, and routes"]
fn sigkill_leaves_the_tun_gone_and_reports_the_rules() {
    let _serial = serial();
    let _net = TestNet::create();
    let mock = MockChild::start();
    let before = snapshot();
    let dir = temp_dir("sigkill");
    let log = dir.join("engine.log");
    let mut engine = EngineProcess {
        child: cli_command(mock.phone(), 2, &log)
            .spawn()
            .expect("start the engine"),
    };
    assert!(
        wait_for_tunnel("hs-tun2", Duration::from_secs(20)),
        "the engine did not create its table and rules. See {}",
        log.with_extension("err").display()
    );
    assert!(
        flow_with_retry(FLOW_ONE, Duration::from_secs(10)),
        "the inner flow did not complete"
    );
    let pid = engine.child.id() as i32;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    let _ = engine.child.wait();
    thread::sleep(Duration::from_millis(500));

    assert!(!has_tun("hs-tun2"), "the kernel did not remove the TUN");
    assert!(
        ip_run(&["-4", "-o", "addr", "show", "dev", HOST_IF]).contains(HOST_ADDR),
        "the physical address was removed"
    );
    let table = table_text();
    assert_eq!(
        table_routes("-4").trim(),
        "",
        "a device-bound route remained"
    );
    assert_eq!(
        table_routes("-6").trim(),
        "",
        "a device-bound route remained"
    );
    // The policy rules are not bound to the device. The crash leaves them.
    let leftover_v4 = ip_run(&["-4", "rule", "show"]);
    let leftover_v6 = ip_run(&["-6", "rule", "show"]);
    assert!(leftover_v4.contains(&format!("{OUTER_RULE_PRIORITY}:")));
    assert!(leftover_v4.contains(&format!("{TUNNEL_RULE_PRIORITY}:")));
    assert!(leftover_v6.contains(&format!("{OUTER_RULE_PRIORITY}:")));
    assert!(leftover_v6.contains(&format!("{TUNNEL_RULE_PRIORITY}:")));
    println!("leftover IPv4 rules:\n{leftover_v4}");
    println!("leftover IPv6 rules:\n{leftover_v6}");

    // The test removes the rules that the killed run created. The fixed
    // priorities and the table name the objects. This cleanup belongs to the
    // disposable VM only.
    ip_quiet(&[
        "-4",
        "rule",
        "del",
        "priority",
        &TUNNEL_RULE_PRIORITY.to_string(),
        "table",
        &table,
    ]);
    ip_quiet(&[
        "-4",
        "rule",
        "del",
        "priority",
        &OUTER_RULE_PRIORITY.to_string(),
        "table",
        "main",
    ]);
    ip_quiet(&[
        "-6",
        "rule",
        "del",
        "priority",
        &TUNNEL_RULE_PRIORITY.to_string(),
        "table",
        &table,
    ]);
    ip_quiet(&[
        "-6",
        "rule",
        "del",
        "priority",
        &OUTER_RULE_PRIORITY.to_string(),
        "table",
        "main",
    ]);
    assert_eq!(
        snapshot(),
        before,
        "the manual cleanup did not restore the state"
    );

    let report = mock.stop();
    assert!(report["connections"].as_u64().unwrap_or(0) >= 2);
}
