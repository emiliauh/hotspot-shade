//! IPv6 address and route lifecycle for a macOS utun.
//!
//! The caller enables this only for explicit IPv6 forwarding. The caller
//! owns the utun and closes it after this guard removes the route and address.
use crate::platform::CommandRunner;
use std::io;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Check the selected route for a public IPv6 address. `Some(ifname)` requires
/// that utun. `None` requires a blackhole route. This checks one destination;
/// more-specific routes for other destinations can still bypass the policy.
/// The timeout is capped at two seconds.
pub fn verify_ipv6_route(expected_interface: Option<&str>, timeout: Duration) -> io::Result<()> {
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "route check timeout must be positive",
        ));
    }
    if let Some(name) = expected_interface {
        if !name
            .strip_prefix("utun")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid tunnel interface",
            ));
        }
    }
    let mut command = Command::new("/sbin/route");
    command.args(["-n", "get", "-inet6", "2606:4700:4700::1111"]);
    let output = bounded_output(&mut command, timeout.min(Duration::from_secs(2)))?;
    if !output.status.success()
        || !route_matches(&String::from_utf8_lossy(&output.stdout), expected_interface)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "IPv6 route does not match the selected policy",
        ));
    }
    Ok(())
}

fn bounded_output(command: &mut Command, timeout: Duration) -> io::Result<std::process::Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < timeout => {
                thread::sleep(
                    Duration::from_millis(10).min(timeout.saturating_sub(started.elapsed())),
                );
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "IPv6 route check timed out",
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    }
    child.wait_with_output()
}

fn route_matches(output: &str, expected_interface: Option<&str>) -> bool {
    let (mut interface, mut flags) = (None, None);
    for line in output.lines() {
        if let Some((key, value)) = line.trim().split_once(':') {
            match key {
                "interface" if interface.is_none() => interface = Some(value.trim()),
                "flags" if flags.is_none() => flags = Some(value.trim()),
                "interface" | "flags" => return false,
                _ => (),
            }
        }
    }
    let flags = match flags {
        Some(flags) => flags,
        None => return false,
    };
    let flag = |name| {
        flags
            .split(|c: char| c == '<' || c == '>' || c == ',' || c.is_ascii_whitespace())
            .any(|part| part == name)
    };
    if !flag("UP") || flag("REJECT") {
        return false;
    }
    match expected_interface {
        Some(name) => interface == Some(name) && !flag("BLACKHOLE"),
        None => flag("BLACKHOLE"),
    }
}

struct SystemRunner;
impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String]) -> io::Result<()> {
        let result = Command::new(program).args(args).output()?;
        if result.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "{} failed: {}",
                program,
                String::from_utf8_lossy(&result.stderr).trim()
            )))
        }
    }
}

/// Owns only the address and route successfully added by this instance.
pub struct Ipv6Tunnel {
    ifname: String,
    address: String,
    peer: String,
    runner: Arc<dyn CommandRunner>,
    has_address: bool,
    has_route: bool,
}
impl Ipv6Tunnel {
    pub fn new(ifname: &str) -> io::Result<Self> {
        Self::with_runner(ifname, Arc::new(SystemRunner))
    }
    pub fn with_runner(ifname: &str, runner: Arc<dyn CommandRunner>) -> io::Result<Self> {
        let unit: u16 = ifname
            .strip_prefix("utun")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid tunnel name"))?;
        let prefix = format!("fd42:6873:6861:{unit:x}::");
        Ok(Self {
            ifname: ifname.into(),
            address: format!("{prefix}1"),
            peer: format!("{prefix}2"),
            runner,
            has_address: false,
            has_route: false,
        })
    }
    pub fn install(&mut self) -> io::Result<()> {
        if self.has_address || self.has_route {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "IPv6 tunnel already installed",
            ));
        }
        self.runner.run(
            "/sbin/ifconfig",
            &[
                self.ifname.clone(),
                "inet6".into(),
                self.address.clone(),
                self.peer.clone(),
                "prefixlen".into(),
                "128".into(),
                "alias".into(),
            ],
        )?;
        self.has_address = true;
        let result = self.runner.run(
            "/sbin/route",
            &[
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "2000::/3".into(),
                "-interface".into(),
                self.ifname.clone(),
            ],
        );
        match result {
            Ok(()) => {
                self.has_route = true;
                Ok(())
            }
            Err(error) => match self.remove() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::new(
                    error.kind(),
                    format!("{error}; IPv6 cleanup failed: {cleanup}"),
                )),
            },
        }
    }
    pub fn has_changes(&self) -> bool {
        self.has_address || self.has_route
    }
    /// Check that a public IPv6 destination uses the tunnel route.
    pub fn verify(&self) -> io::Result<()> {
        verify_ipv6_route(Some(&self.ifname), Duration::from_secs(2))
    }
    pub fn remove(&mut self) -> io::Result<()> {
        let mut error = None;
        if self.has_route {
            match self.runner.run(
                "/sbin/route",
                &[
                    "-n".into(),
                    "delete".into(),
                    "-inet6".into(),
                    "2000::/3".into(),
                    "-interface".into(),
                    self.ifname.clone(),
                ],
            ) {
                Ok(()) => self.has_route = false,
                Err(e) => error = Some(e),
            }
        }
        if self.has_address && !self.has_route {
            match self.runner.run(
                "/sbin/ifconfig",
                &[
                    self.ifname.clone(),
                    "inet6".into(),
                    self.address.clone(),
                    "-alias".into(),
                ],
            ) {
                Ok(()) => self.has_address = false,
                Err(e) => error = Some(e),
            }
        }
        match error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
impl Drop for Ipv6Tunnel {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            eprintln!("[route] IPv6 cleanup failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<Vec<String>>>,
        fail_add: bool,
    }
    impl CommandRunner for Fake {
        fn run(&self, program: &str, args: &[String]) -> io::Result<()> {
            let mut call = vec![program.to_string()];
            call.extend_from_slice(args);
            self.calls.lock().unwrap().push(call);
            if self.fail_add && program.ends_with("route") && args.iter().any(|v| v == "add") {
                return Err(io::Error::other("route failure"));
            }
            Ok(())
        }
    }
    #[test]
    fn rollback_address_if_route_install_fails() {
        let runner = Arc::new(Fake {
            fail_add: true,
            ..Default::default()
        });
        let mut tunnel = Ipv6Tunnel::with_runner("utun6", runner.clone()).unwrap();
        assert!(tunnel.install().is_err());
        let calls = runner.calls.lock().unwrap();
        assert!(calls.last().unwrap().contains(&"-alias".to_string()));
    }
    #[test]
    fn cleanup_removes_route_before_address() {
        let runner = Arc::new(Fake::default());
        let mut tunnel = Ipv6Tunnel::with_runner("utun6", runner.clone()).unwrap();
        tunnel.install().unwrap();
        tunnel.remove().unwrap();
        let calls = runner.calls.lock().unwrap();
        assert!(calls[2].contains(&"delete".to_string()));
        assert!(calls[3].contains(&"-alias".to_string()));
    }
    #[test]
    fn route_check_rejects_bypass_and_blackhole() {
        assert!(route_matches(
            "interface: utun6\nflags: <UP,DONE>",
            Some("utun6")
        ));
        assert!(!route_matches(
            "interface: en5\nflags: <UP,DONE>",
            Some("utun6")
        ));
        assert!(!route_matches(
            "interface: utun6\nflags: <UP,BLACKHOLE>",
            Some("utun6")
        ));
        assert!(!route_matches(
            "interface: utun60\nflags: <UP,DONE>",
            Some("utun6")
        ));
        assert!(!route_matches(
            "interface: utun6\nflags: <UP,REJECT>",
            Some("utun6")
        ));
        assert!(!route_matches(
            "interface: utun6\nflags: <DONE>",
            Some("utun6")
        ));
        assert!(!route_matches(
            "interface: utun6\ninterface: en5\nflags: <UP,DONE>",
            Some("utun6")
        ));
    }
    #[test]
    fn route_check_requires_blackhole_for_block() {
        assert!(route_matches(
            "interface: lo0\nflags: <UP,GATEWAY,BLACKHOLE>",
            None
        ));
        assert!(!route_matches("interface: en5\nflags: <UP,GATEWAY>", None));
        assert!(!route_matches(
            "interface: lo0\nflags: <UP,NOTBLACKHOLE>",
            None
        ));
        assert!(!route_matches(
            "interface: lo0\nflags: <UP,BLACKHOLE,REJECT>",
            None
        ));
        assert!(!route_matches("interface: lo0", None));
    }
    #[test]
    fn route_check_timeout_kills_the_child() {
        let started = Instant::now();
        let mut command = Command::new("/bin/sleep");
        command.arg("5");
        let error = bounded_output(&mut command, Duration::from_millis(60)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
