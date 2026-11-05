//! Inspect local routing and DNS configuration without resolving hostnames.
//!
//! Discovery is read-only. On macOS the module runs `/sbin/route` and
//! `/usr/sbin/scutil`. On Linux it reads `/proc/net/route` and the resolver
//! files through the `environment_linux` module. No call uses `getaddrinfo`.
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(target_os = "macos")]
use std::process::Command;

/// One IPv4 default route from local configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    /// The selected interface name.
    pub interface: String,
    /// The IPv4 next hop, when the route has one.
    pub gateway: Option<Ipv4Addr>,
}

#[cfg(any(target_os = "macos", test))]
fn parse_route(text: &str) -> io::Result<DefaultRoute> {
    let mut interface = None;
    let mut gateway = None;
    for line in text.lines() {
        if let Some((key, value)) = line.trim().split_once(':') {
            match key {
                "interface" => interface = Some(value.trim().to_owned()),
                "gateway" => gateway = value.trim().parse().ok(),
                _ => (),
            }
        }
    }
    let interface = interface
        .filter(|name| !name.is_empty() && !name.starts_with("utun") && !name.starts_with("lo"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no physical default interface"))?;
    Ok(DefaultRoute { interface, gateway })
}

/// Read the macOS IPv4 default route. It runs `/sbin/route -n get default`
/// and changes nothing.
#[cfg(target_os = "macos")]
pub fn default_route() -> io::Result<DefaultRoute> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("default route lookup failed"));
    }
    parse_route(&String::from_utf8_lossy(&output.stdout))
}

/// Read the Linux IPv4 default route.
///
/// The call reads `/proc/net/route` through `environment_linux`. It does not
/// run a command or change a route. The lowest metric wins. A tie is an error.
/// The route-up flag does not prove that the link is operational.
#[cfg(target_os = "linux")]
pub fn default_route() -> io::Result<DefaultRoute> {
    Ok(linux_route(crate::environment_linux::default_route()?))
}

#[cfg(target_os = "linux")]
fn linux_route(route: crate::environment_linux::LinuxDefaultRoute) -> DefaultRoute {
    DefaultRoute {
        interface: route.interface,
        gateway: route.gateway,
    }
}

/// Return an error on a platform without default route discovery.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn default_route() -> io::Result<DefaultRoute> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "default route discovery is not implemented on this platform",
    ))
}

/// One `route -n get` result. Read-only. The gateway is kept as text, so an
/// IPv6 or link gateway is also recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteLookup {
    pub interface: Option<String>,
    pub gateway: Option<String>,
}

pub fn parse_route_lookup(text: &str) -> RouteLookup {
    let mut lookup = RouteLookup {
        interface: None,
        gateway: None,
    };
    for line in text.lines() {
        if let Some((key, value)) = line.trim().split_once(':') {
            let value = value.trim();
            match key.trim() {
                "interface" if !value.is_empty() => lookup.interface = Some(value.to_owned()),
                "gateway" if !value.is_empty() => lookup.gateway = Some(value.to_owned()),
                _ => (),
            }
        }
    }
    lookup
}

/// Look up the route to a numeric address, or to `default`, optionally in
/// the scope of one interface. It runs `/sbin/route -n get` and changes nothing.
/// The arguments are numeric or a validated interface name. No name is resolved.
#[cfg(target_os = "macos")]
pub fn route_lookup(destination: Option<IpAddr>, scope: Option<&str>) -> Option<RouteLookup> {
    let mut command = Command::new("/sbin/route");
    command.args(["-n", "get"]);
    if matches!(destination, Some(IpAddr::V6(_))) {
        command.arg("-inet6");
    }
    if let Some(name) = scope {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        command.args(["-ifscope", name]);
    }
    match destination {
        Some(ip) => command.arg(ip.to_string()),
        None => command.arg("default"),
    };
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_route_lookup(&String::from_utf8_lossy(&output.stdout)))
}

/// Return `None` on a platform without a read-only route lookup.
///
/// The Linux main route table does not prove the route that a socket uses,
/// because a policy rule can select another table. This function does not
/// guess.
#[cfg(not(target_os = "macos"))]
pub fn route_lookup(_destination: Option<IpAddr>, _scope: Option<&str>) -> Option<RouteLookup> {
    None
}

#[cfg(any(target_os = "macos", test))]
fn parse_dns(text: &str) -> Vec<SocketAddr> {
    let mut result = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with("nameserver[") {
            if let Some((_, value)) = line.split_once(':') {
                if let Ok(ip) = value.trim().parse::<Ipv4Addr>() {
                    let address = SocketAddr::from((ip, 53));
                    if !result.contains(&address) {
                        result.push(address);
                    }
                }
            }
        }
    }
    result
}

/// Read the macOS DNS servers. It runs `/usr/sbin/scutil --dns` and changes
/// nothing. The parser keeps numeric IPv4 nameservers and removes duplicates.
#[cfg(target_os = "macos")]
pub fn system_dns() -> io::Result<Vec<SocketAddr>> {
    let output = Command::new("/usr/sbin/scutil").arg("--dns").output()?;
    if !output.status.success() {
        return Err(io::Error::other("DNS configuration lookup failed"));
    }
    Ok(parse_dns(&String::from_utf8_lossy(&output.stdout)))
}

/// Read the usable non-local Linux DNS servers.
///
/// The call reads the resolver files through `environment_linux`. It rejects
/// a loopback or link-local stub. When the main resolver file holds only a
/// stub, it reads the systemd-resolved upstream file. It returns an error
/// when no usable upstream exists. It does not fall back to a local stub.
#[cfg(target_os = "linux")]
pub fn system_dns() -> io::Result<Vec<SocketAddr>> {
    crate::environment_linux::system_dns()
}

/// Return an error on a platform without DNS configuration discovery.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn system_dns() -> io::Result<Vec<SocketAddr>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "DNS configuration discovery is not implemented on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_tunnel_default_route() {
        assert!(parse_route("interface: utun2\ngateway: 1.2.3.4").is_err());
        let route = parse_route("interface: en5\ngateway: 172.20.10.1").unwrap();
        assert_eq!(route.gateway, Some(Ipv4Addr::new(172, 20, 10, 1)));
    }
    #[test]
    fn route_lookup_keeps_text_gateway() {
        let lookup = parse_route_lookup(
            "   route to: default\ndestination: default\n    gateway: fe80::1%en6\n  interface: en6\n",
        );
        assert_eq!(lookup.interface.as_deref(), Some("en6"));
        assert_eq!(lookup.gateway.as_deref(), Some("fe80::1%en6"));
        assert_eq!(parse_route_lookup("nothing").interface, None);
    }
    #[test]
    fn dns_is_numeric_and_deduplicated() {
        let servers = parse_dns("nameserver[0] : 1.1.1.1\nnameserver[1] : example.com\nnameserver[2] : 1.1.1.1\nnameserver[3] : 2606::1");
        assert_eq!(servers, vec!["1.1.1.1:53".parse().unwrap()]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_route_keeps_the_shared_fields() {
        let route = crate::environment_linux::LinuxDefaultRoute {
            interface: "wlan0".to_owned(),
            gateway: Some(Ipv4Addr::new(172, 20, 10, 1)),
            metric: 600,
        };
        assert_eq!(
            linux_route(route),
            DefaultRoute {
                interface: "wlan0".to_owned(),
                gateway: Some(Ipv4Addr::new(172, 20, 10, 1)),
            }
        );
        let on_link = crate::environment_linux::LinuxDefaultRoute {
            interface: "usb0".to_owned(),
            gateway: None,
            metric: 100,
        };
        assert_eq!(linux_route(on_link).gateway, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_route_lookup_returns_no_guess() {
        assert_eq!(route_lookup(None, None), None);
        assert_eq!(
            route_lookup(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), None),
            None
        );
        assert_eq!(route_lookup(None, Some("eth0")), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_dns_discovery_rejects_a_local_stub() {
        let servers = crate::environment_linux::parse_resolv_conf(
            "nameserver 127.0.0.53\nnameserver fe80::1\nnameserver 8.8.8.8\n",
        );
        assert_eq!(servers, vec!["8.8.8.8:53".parse().unwrap()]);
    }
}
