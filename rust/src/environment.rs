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
        .env_remove(crate::secret_env::PHONE_TOKEN_ENV)
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
    command.env_remove(crate::secret_env::PHONE_TOKEN_ENV);
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

/// One resolver block from `scutil --dns`.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ResolverBlock {
    interface: Option<String>,
    /// The block is limited to one suffix. A split-DNS or VPN resolver.
    split_domain: bool,
    /// The block answers multicast DNS, not unicast queries.
    mdns: bool,
    /// The block belongs to the scoped-query section.
    scoped: bool,
    servers: Vec<Ipv4Addr>,
}

/// A usable upstream IPv4 nameserver. A loopback stub, a link-local address,
/// and an address that cannot be a unicast destination are not usable.
#[cfg(any(target_os = "macos", test))]
fn usable_dns_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] != 0
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}

/// Return true for a name that can identify a physical link. A tunnel, VPN,
/// container, bridge, or loopback name is not a physical link. The platform
/// resolved the name already, so this check is a second guard, not a discovery
/// step.
///
/// The list is a heuristic. A renamed tunnel can still pass. A caller that
/// needs proof must also check the live link, as the Linux route manager does
/// before any source device token leaves the process.
pub(crate) fn physical_interface_name(name: &str) -> bool {
    const VIRTUAL: &[&str] = &[
        "utun",
        "ipsec",
        "gif",
        "stf",
        "ppp",
        "tun",
        "tap",
        "wg",
        "lo",
        "hs-tun",
        "tailscale",
        "zt",
        "docker",
        "veth",
        "virbr",
        "vmnet",
        "ifb",
        "dummy",
        "vxlan",
        "geneve",
        "gretap",
        "gre",
        "erspan",
        "ip6tnl",
        "ipip",
        "sit",
        "xfrm",
        "nlmon",
    ];
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
        && !VIRTUAL.iter().any(|prefix| name.starts_with(prefix))
}

/// Parse the resolver blocks in `scutil --dns` output.
///
/// The parser records every block from both sections. It keeps the interface
/// name, the scoped-section marker, and whether the block is limited to one
/// suffix or answers multicast DNS. The scoped section is kept because it is
/// the only per-interface resolver statement on macOS.
#[cfg(any(target_os = "macos", test))]
fn parse_scutil_dns(text: &str) -> Vec<ResolverBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<ResolverBlock> = None;
    let mut scoped_section = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("DNS configuration") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            scoped_section = line.contains("scoped queries");
            continue;
        }
        if line.starts_with("resolver #") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(ResolverBlock {
                scoped: scoped_section,
                ..ResolverBlock::default()
            });
            continue;
        }
        let Some(block) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.starts_with("nameserver[") {
            if let Ok(ip) = value.parse::<Ipv4Addr>() {
                block.servers.push(ip);
            }
        } else if key == "domain" {
            block.split_domain = true;
        } else if key == "options" {
            block.mdns |= value.split(',').any(|item| item.trim() == "mdns");
        } else if key == "flags" {
            block.scoped |= value.split(',').any(|item| item.trim() == "Scoped");
        } else if key == "if_index" {
            block.interface = value
                .split_once('(')
                .and_then(|(_, rest)| rest.split_once(')'))
                .map(|(name, _)| name.trim().to_owned())
                .filter(|name| !name.is_empty());
        }
    }
    if let Some(block) = current {
        blocks.push(block);
    }
    blocks
}

/// Return the usable upstream servers that one resolver block names.
#[cfg(any(target_os = "macos", test))]
fn block_servers(block: &ResolverBlock) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for ip in &block.servers {
        if !usable_dns_ipv4(*ip) {
            continue;
        }
        let address = SocketAddr::from((*ip, 53));
        if !servers.contains(&address) {
            servers.push(address);
        }
    }
    servers
}

/// Select the upstream nameservers that provably belong to one explicit
/// physical interface.
///
/// Only a block whose `if_index` names the interface is a candidate. A scoped
/// block for that interface is the per-interface resolver and wins over the
/// general section when only one section names the interface. A block that is
/// limited to one suffix, answers multicast DNS, or names another interface is
/// not a candidate, so a full VPN resolver that has no interface, or that
/// names a tunnel, stays out. When the two sections name different servers for
/// the same interface, or when one section holds two different server sets,
/// the association is ambiguous and the call fails instead of guessing. An
/// empty result is an error, not an invitation to use a public resolver.
#[cfg(any(target_os = "macos", test))]
fn select_dns_for_interface(
    blocks: &[ResolverBlock],
    interface: &str,
) -> io::Result<Vec<SocketAddr>> {
    if !physical_interface_name(interface) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a physical interface is required",
        ));
    }
    let matching = |scoped: bool| -> Vec<Vec<SocketAddr>> {
        blocks
            .iter()
            .filter(|block| block.scoped == scoped && !block.mdns && !block.split_domain)
            .filter(|block| block.interface.as_deref() == Some(interface))
            .map(block_servers)
            .filter(|servers| !servers.is_empty())
            .collect()
    };
    let mut scoped_sets = matching(true);
    let mut general_sets = matching(false);
    for sets in [&mut scoped_sets, &mut general_sets] {
        sets.sort();
        sets.dedup();
    }
    let chosen = match (scoped_sets.len(), general_sets.len()) {
        (1, 0) => scoped_sets.pop().unwrap(),
        (0, 1) => general_sets.pop().unwrap(),
        (1, 1) if scoped_sets[0] == general_sets[0] => scoped_sets.pop().unwrap(),
        (0, 0) => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no usable resolver is associated with the pinned interface",
            ))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resolvers associated with the pinned interface disagree",
            ))
        }
    };
    Ok(chosen)
}

/// Select the servers for one interface from `scutil --dns` text.
#[cfg(any(target_os = "macos", test))]
fn dns_for_interface_from_scutil(text: &str, interface: &str) -> io::Result<Vec<SocketAddr>> {
    select_dns_for_interface(&parse_scutil_dns(text), interface)
}

/// Read the macOS DNS servers for one explicitly pinned physical interface.
/// It runs `/usr/sbin/scutil --dns` and changes nothing.
///
/// The selected servers must name that interface in `scutil` output. A
/// scoped block for the interface, a general block for the interface, or both
/// when they agree is accepted. A tunnel or VPN block, a resolver without an
/// interface, a split-DNS resolver, an mDNS resolver, a loopback stub, and a
/// link-local address are not used. The call fails when the association is
/// absent or ambiguous. It never substitutes a public resolver, because that
/// would change the DNS policy without telling the person who runs the tunnel.
#[cfg(target_os = "macos")]
pub fn system_dns_for_interface(interface: &str) -> io::Result<Vec<SocketAddr>> {
    if !physical_interface_name(interface) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a physical interface is required",
        ));
    }
    let output = Command::new("/usr/sbin/scutil")
        .arg("--dns")
        .env_remove(crate::secret_env::PHONE_TOKEN_ENV)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("DNS configuration lookup failed"));
    }
    dns_for_interface_from_scutil(&String::from_utf8_lossy(&output.stdout), interface)
}

/// Read the macOS DNS servers for the physical default interface. It runs
/// `/sbin/route -n get default` to learn the interface and then calls
/// [`system_dns_for_interface`]. It changes nothing.
#[cfg(target_os = "macos")]
pub fn system_dns() -> io::Result<Vec<SocketAddr>> {
    let route = default_route()?;
    system_dns_for_interface(&route.interface)
}

/// Read the usable non-local Linux DNS servers for one explicit interface.
///
/// Linux resolver files are not gathered per interface. `/etc/resolv.conf` and
/// the systemd-resolved upstream file hold one aggregate list, and a server in
/// that list can belong to a VPN, a container, or another link. The files do
/// not prove that a server belongs to the pinned interface, even when the
/// pinned interface is the default route. This call therefore fails closed. It
/// does not use the aggregate list as though it belonged to the interface, and
/// it never falls back to a public resolver.
///
/// A caller that needs a resolver on Linux must name one explicitly. The
/// explicit server is still queried through the normalized, interface-pinned
/// socket, so it does not create a raw egress path.
#[cfg(target_os = "linux")]
pub fn system_dns_for_interface(interface: &str) -> io::Result<Vec<SocketAddr>> {
    if !physical_interface_name(interface) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a physical interface is required",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the Linux system resolver list is not tied to one interface; pass an explicit DNS server",
    ))
}

/// Read the usable non-local Linux DNS servers.
///
/// The call reads the resolver files through `environment_linux`. It rejects
/// a loopback or link-local stub. When the main resolver file holds only a
/// stub, it reads the systemd-resolved upstream file. It returns an error
/// when no usable upstream exists. It does not fall back to a local stub.
///
/// This aggregate list is for diagnostics only, such as the `probe` command.
/// It is not tied to one interface, so an egress path must not use it as the
/// resolver for a pinned interface. Use [`system_dns_for_interface`] or an
/// explicit server for that purpose.
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

/// Return an error on a platform without per-interface DNS discovery.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn system_dns_for_interface(interface: &str) -> io::Result<Vec<SocketAddr>> {
    if !physical_interface_name(interface) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a physical interface is required",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "per-interface DNS configuration discovery is not implemented on this platform",
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
    const SCUTIL_DNS: &str = "\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.0.2.53
  nameserver[1] : 2001:db8::53
  if_index : 11 (en5)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #3
  domain   : corp.example
  nameserver[0] : 198.51.100.53
  if_index : 20 (utun4)
  flags    : Request A records
  order    : 100000

resolver #4
  nameserver[0] : 127.0.0.1
  if_index : 5 (en0)
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.0.2.53
  if_index : 11 (en5)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
";

    #[test]
    fn scutil_dns_selects_only_the_pinned_interface() {
        let blocks = parse_scutil_dns(SCUTIL_DNS);
        // Both sections are parsed now.
        assert_eq!(blocks.len(), 5);
        let expected = vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap()];
        // The scoped en5 block repeats the general en5 block, so it agrees.
        assert_eq!(
            dns_for_interface_from_scutil(SCUTIL_DNS, "en5").unwrap(),
            expected
        );
        // The IPv6 nameserver in the same block is not usable in this mode.
        assert!(!expected[0].is_ipv6());
        // en0 has only a loopback stub.
        let error = dns_for_interface_from_scutil(SCUTIL_DNS, "en0").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        // A tunnel name is never a physical pin.
        let error = dns_for_interface_from_scutil(SCUTIL_DNS, "utun4").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        // An absent interface fails closed instead of taking another link.
        let error = dns_for_interface_from_scutil(SCUTIL_DNS, "en9").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("no usable resolver"));
    }

    #[test]
    fn scutil_dns_allows_an_explicit_interface_that_differs_from_the_default_route() {
        let text = "\
DNS configuration

resolver #1
  nameserver[0] : 192.0.2.53
  if_index : 5 (en0)
  flags    : Request A records

resolver #2
  nameserver[0] : 198.51.100.53
  if_index : 11 (en5)
  flags    : Request A records
";
        // en0 is the ordinary default route. The pinned hotspot interface is
        // en5, and its own resolver must be used.
        assert_eq!(
            dns_for_interface_from_scutil(text, "en5").unwrap(),
            vec!["198.51.100.53:53".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn scutil_dns_rejects_a_full_vpn_resolver_for_another_interface() {
        let text = "\
DNS configuration

resolver #1
  nameserver[0] : 203.0.113.9
  flags    : Request A records

resolver #2
  nameserver[0] : 198.51.100.53
  if_index : 5 (en0)
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 203.0.113.9
  if_index : 20 (utun4)
  flags    : Scoped, Request A records

resolver #2
  nameserver[0] : 192.0.2.53
  if_index : 11 (en5)
  flags    : Scoped, Request A records
";
        // The pinned hotspot interface gets its scoped resolver.
        assert_eq!(
            dns_for_interface_from_scutil(text, "en5").unwrap(),
            vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap()]
        );
        // The default-route interface gets its own resolver, not the VPN one.
        assert_eq!(
            dns_for_interface_from_scutil(text, "en0").unwrap(),
            vec!["198.51.100.53:53".parse::<SocketAddr>().unwrap()]
        );
        // A pinned interface with no block never borrows the VPN or en0.
        assert_eq!(
            dns_for_interface_from_scutil(text, "en7")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn scutil_dns_uses_a_matching_scoped_resolver_without_a_general_block() {
        let text = "\
DNS configuration

resolver #1
  nameserver[0] : 203.0.113.9
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 203.0.113.9
  if_index : 20 (utun4)
  flags    : Scoped, Request A records

resolver #2
  nameserver[0] : 198.51.100.53
  if_index : 11 (en5)
  flags    : Scoped, Request A records
";
        let servers = dns_for_interface_from_scutil(text, "en5").unwrap();
        assert_eq!(
            servers,
            vec!["198.51.100.53:53".parse::<SocketAddr>().unwrap()]
        );
        let vpn: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(!servers.iter().any(|server| server.ip() == vpn));
    }

    #[test]
    fn scutil_dns_fails_when_the_interface_resolver_is_ambiguous() {
        let text = "\
DNS configuration

resolver #1
  nameserver[0] : 192.0.2.53
  if_index : 11 (en5)
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 198.51.100.53
  if_index : 11 (en5)
  flags    : Scoped, Request A records
";
        let error = dns_for_interface_from_scutil(text, "en5").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("disagree"));
        // Identical blocks in both sections and the same section are not an
        // ambiguity.
        let duplicated = "\
DNS configuration

resolver #1
  nameserver[0] : 198.51.100.53
  if_index : 11 (en5)
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 198.51.100.53
  if_index : 11 (en5)
  flags    : Scoped, Request A records

resolver #2
  nameserver[0] : 198.51.100.53
  if_index : 11 (en5)
  flags    : Scoped, Request A records
";
        assert_eq!(
            dns_for_interface_from_scutil(duplicated, "en5").unwrap(),
            vec!["198.51.100.53:53".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn scutil_dns_ignores_split_mdns_and_other_scoped_blocks() {
        let text = "\
DNS configuration

resolver #1
  domain   : corp.example
  nameserver[0] : 192.0.2.53
  if_index : 11 (en5)
  flags    : Request A records

resolver #2
  options  : mdns
  nameserver[0] : 198.51.100.53
  if_index : 11 (en5)

resolver #3
  nameserver[0] : 203.0.113.9
  if_index : 5 (en0)
";
        assert_eq!(
            dns_for_interface_from_scutil(text, "en5")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn scutil_dns_rejects_a_local_stub_on_the_pinned_interface() {
        let text = "\
DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 127.0.0.1
  if_index : 11 (en5)
  flags    : Scoped, Request A records

resolver #2
  nameserver[0] : 169.254.1.1
  if_index : 11 (en5)
  flags    : Scoped, Request A records
";
        assert_eq!(
            dns_for_interface_from_scutil(text, "en5")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn physical_interface_names_exclude_tunnels_vpn_and_loopback() {
        for name in ["en5", "en0", "bridge0", "pdp_ip0", "eth0", "wlan0", "usb0"] {
            assert!(physical_interface_name(name), "{name}");
        }
        for name in [
            "",
            "utun4",
            "ipsec0",
            "gif0",
            "stf0",
            "ppp0",
            "tun0",
            "tap0",
            "wg0",
            "lo",
            "lo0",
            "hs-tun0",
            "tailscale0",
            "zt0",
            "docker0",
            "veth12",
            "virbr0",
            "vmnet8",
            "ifb0",
            "dummy0",
            "vxlan0",
            "geneve0",
            "gretap0",
            "gre0",
            "erspan0",
            "ip6tnl0",
            "ipip0",
            "sit0",
            "xfrm0",
            "nlmon0",
            "en 5",
        ] {
            assert!(!physical_interface_name(name), "{name}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_per_interface_dns_requires_an_explicit_server() {
        // The aggregate resolver files do not prove that a server belongs to
        // the pinned interface. The call fails closed even for the default
        // route interface instead of borrowing another link's resolver.
        let error = system_dns_for_interface("eth0").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("explicit DNS server"));
        let error = system_dns_for_interface("lo").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn scutil_dns_reads_both_sections() {
        let blocks = parse_scutil_dns(SCUTIL_DNS);
        assert_eq!(blocks[0].interface.as_deref(), Some("en5"));
        assert!(!blocks[0].scoped);
        assert!(blocks[1].mdns);
        assert!(blocks[2].split_domain);
        assert_eq!(blocks[2].interface.as_deref(), Some("utun4"));
        assert!(blocks[4].scoped);
        assert_eq!(blocks[4].interface.as_deref(), Some("en5"));
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
