//! Read the Linux IPv4 route table and DNS configuration.
//!
//! The shared environment module uses this discovery on Linux. It supports
//! read-only diagnostics and existing service paths. The Linux tunnel is not
//! implemented.
//!
//! Discovery is read-only. The module reads `/proc/net/route` and resolver
//! files. It never calls `getaddrinfo`, changes a route, runs a command, or
//! opens a tunnel device. The pure parsers are separate from the file reads.
//! Tests use fixed text and temporary files.
//!
//! # Route fields
//!
//! The kernel prints IPv4 values in hexadecimal in native byte order. This
//! module converts that order. A line holds the interface, the
//! destination, the gateway, the flags, the metric, and the mask. A zero
//! gateway means that the route has no next hop.
//!
//! # Selection
//!
//! A usable default route has the kernel's route-up flag, is not a reject route, has the zero
//! destination and the zero mask, and uses a physical interface name. A route
//! with a next hop must carry the gateway flag. The route with the lowest
//! metric wins. A tie at the lowest metric is an ambiguity. The selector fails
//! instead of choosing an arbitrary link. The flag does not prove the link is
//! operational. The `*` device placeholder is not a usable interface.
//!
//! # DNS
//!
//! A loopback or link-local nameserver is a local stub. This module rejects
//! it. It reads the systemd-resolved upstream file when the main resolver file
//! holds only a local stub. It fails when no usable non-local upstream exists.
//! A local stub on a non-loopback address is not detectable without a probe.
//! This module does not probe.
//!
//! # Limits
//!
//! `/proc/net/route` shows the main table. A policy rule can select another
//! table. A pair of `/1` routes without a default is not detected. The
//! interface name filter is a heuristic. It
//! cannot prove that a renamed tunnel is not a tunnel. The DNS fallback reads
//! the systemd-resolved upstream file. It does not query the systemd-resolved
//! D-Bus API.

use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// The kernel IPv4 route table.
pub const ROUTE_FILE: &str = "/proc/net/route";

/// The system resolver configuration.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The systemd-resolved upstream resolver file.
pub const SYSTEMD_UPSTREAM_RESOLV_CONF: &str = "/run/systemd/resolve/resolv.conf";

/// The most DNS servers that one parse returns.
pub const MAX_DNS_SERVERS: usize = 16;

/// The kernel route-up flag. It does not prove interface liveness.
pub const RTF_UP: u16 = 0x0001;

/// The route flag for a route with a next hop.
pub const RTF_GATEWAY: u16 = 0x0002;

/// The route flag for a reject route.
pub const RTF_REJECT: u16 = 0x0200;

/// The maximum size of the route file that this module reads.
pub const MAX_ROUTE_BYTES: u64 = 1 << 20;

/// The maximum number of route lines that this module reads.
pub const MAX_ROUTE_LINES: usize = 4096;

/// The maximum length of one route line.
pub const MAX_ROUTE_LINE: usize = 512;

/// The maximum size of one resolver file that this module reads.
pub const MAX_RESOLV_BYTES: u64 = 64 * 1024;

/// The maximum number of resolver lines that this module reads.
pub const MAX_RESOLV_LINES: usize = 512;

/// The maximum length of one resolver line.
pub const MAX_RESOLV_LINE: usize = 512;

/// The kernel interface name limit, without the terminating zero.
const MAX_INTERFACE_NAME: usize = 15;

/// The interface name prefixes that are not physical links.
///
/// This list is a heuristic. It catches the common tunnel, container, and
/// bridge helper names. A renamed tunnel can still pass.
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "tun",
    "tap",
    "utun",
    "wg",
    "docker",
    "veth",
    "virbr",
    "vmnet",
    "tailscale",
    "zt",
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

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// One IPv4 route entry from `/proc/net/route`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// The interface name.
    pub interface: String,
    /// The destination address.
    pub destination: Ipv4Addr,
    /// The next hop, or `None` for an on-link route.
    pub gateway: Option<Ipv4Addr>,
    /// The raw kernel route flags.
    pub flags: u16,
    /// The route metric. A lower value wins.
    pub metric: u32,
    /// The destination mask.
    pub mask: Ipv4Addr,
}

impl RouteEntry {
    /// Return the kernel route-up flag. It does not prove interface liveness.
    pub fn is_up(&self) -> bool {
        self.flags & RTF_UP != 0
    }

    /// Return true when the route is a reject route.
    pub fn is_reject(&self) -> bool {
        self.flags & RTF_REJECT != 0
    }

    /// Return true when the route has the default destination and mask.
    pub fn is_default(&self) -> bool {
        self.destination.is_unspecified() && self.mask.is_unspecified()
    }

    /// Return true when the route is a usable physical default route.
    fn is_usable_default(&self) -> bool {
        self.is_default()
            && self.is_up()
            && !self.is_reject()
            && (self.gateway.is_none() || self.flags & RTF_GATEWAY != 0)
            && is_physical_interface(&self.interface)
    }
}

/// One usable IPv4 default route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxDefaultRoute {
    /// The physical interface name.
    pub interface: String,
    /// The next hop, or `None` for an on-link route.
    pub gateway: Option<Ipv4Addr>,
    /// The metric of the selected route.
    pub metric: u32,
}

/// Return true when the name can be one Linux interface name.
fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_INTERFACE_NAME
        && name.bytes().all(|byte| byte.is_ascii_graphic())
        && !name.bytes().any(|byte| matches!(byte, b'/' | b':'))
}

/// Return true when the name is not loopback or a common tunnel name.
///
/// This check uses the name only. It cannot prove the link type. See the
/// module limits.
pub fn is_physical_interface(name: &str) -> bool {
    if !valid_interface_name(name) || name == "lo" || name == "*" {
        return false;
    }
    !VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn parse_hex_u32(field: &str) -> io::Result<u32> {
    if field.is_empty() || field.len() > 8 || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(bad("route field is not 32-bit hexadecimal"));
    }
    u32::from_str_radix(field, 16).map_err(|_| bad("route field is not 32-bit hexadecimal"))
}

fn parse_hex_u16(field: &str) -> io::Result<u16> {
    if field.is_empty() || field.len() > 4 || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(bad("route flag is not 16-bit hexadecimal"));
    }
    u16::from_str_radix(field, 16).map_err(|_| bad("route flag is not 16-bit hexadecimal"))
}

fn parse_decimal_u32(field: &str) -> io::Result<u32> {
    if field.is_empty() || field.len() > 10 || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(bad("route metric is not a decimal number"));
    }
    field
        .parse()
        .map_err(|_| bad("route metric is not a decimal number"))
}

/// Convert one native-endian hexadecimal IPv4 field.
fn ipv4_from_hex(field: &str) -> io::Result<Ipv4Addr> {
    Ok(Ipv4Addr::from(parse_hex_u32(field)?.to_ne_bytes()))
}

/// Parse the kernel IPv4 route table.
///
/// The function accepts the header line and blank lines. It rejects a line
/// with too few fields, a bad hexadecimal value, a bad metric, or an invalid
/// interface name. Errors identify the line and field without including their
/// contents. The input is bounded by [`MAX_ROUTE_LINES`] and [`MAX_ROUTE_LINE`].
pub fn parse_route_table(text: &str) -> io::Result<Vec<RouteEntry>> {
    if text.len() as u64 > MAX_ROUTE_BYTES {
        return Err(bad("route table is too large"));
    }
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_ROUTE_LINES {
            return Err(bad("route table has too many lines"));
        }
        let invalid = |field: &str| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid route {field} on line {}", index + 1),
            )
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_ROUTE_LINE {
            return Err(invalid("line length"));
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields
            .first()
            .is_some_and(|field| field.eq_ignore_ascii_case("Iface"))
        {
            continue;
        }
        if fields.len() < 8 {
            return Err(invalid("line length"));
        }
        if !valid_interface_name(fields[0]) {
            return Err(invalid("interface"));
        }
        let destination = ipv4_from_hex(fields[1]).map_err(|_| invalid("destination"))?;
        let gateway = ipv4_from_hex(fields[2]).map_err(|_| invalid("gateway"))?;
        let flags = parse_hex_u16(fields[3]).map_err(|_| invalid("flags"))?;
        let metric = parse_decimal_u32(fields[6]).map_err(|_| invalid("metric"))?;
        let mask = ipv4_from_hex(fields[7]).map_err(|_| invalid("mask"))?;
        entries.push(RouteEntry {
            interface: fields[0].to_owned(),
            destination,
            gateway: (!gateway.is_unspecified()).then_some(gateway),
            flags,
            metric,
            mask,
        });
    }
    Ok(entries)
}

/// Select the usable default route with the lowest metric.
///
/// A tie at the lowest metric between different interfaces or gateways is
/// ambiguous. The function returns an error and does not guess.
pub fn select_default_route(entries: &[RouteEntry]) -> io::Result<LinuxDefaultRoute> {
    let mut candidates = entries.iter().filter(|entry| entry.is_usable_default());
    let Some(first) = candidates.next() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no usable IPv4 default route",
        ));
    };
    let mut best = first;
    let mut ambiguous = false;
    for entry in candidates {
        if entry.metric < best.metric {
            best = entry;
            ambiguous = false;
        } else if entry.metric == best.metric
            && (entry.interface != best.interface || entry.gateway != best.gateway)
        {
            ambiguous = true;
        }
    }
    if ambiguous {
        return Err(bad("IPv4 default route is ambiguous"));
    }
    Ok(LinuxDefaultRoute {
        interface: best.interface.clone(),
        gateway: best.gateway,
        metric: best.metric,
    })
}

/// Return true when the address is a usable non-local DNS upstream.
pub fn is_usable_dns_server(address: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => is_usable_ipv4(ip),
        IpAddr::V6(ip) => is_usable_ipv6(ip),
    }
}

fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] != 0
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}

fn is_usable_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ip) = ip.to_ipv4_mapped() {
        return is_usable_ipv4(ip);
    }
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    // Reject the IPv6 link-local prefix fe80::/10.
    ip.segments()[0] & 0xffc0 != 0xfe80
}

/// Return the usable non-local nameservers in resolver text.
///
/// A hostname, a malformed line, and a local stub are skipped. The function
/// reads at most [`MAX_RESOLV_LINES`] lines and returns at most
/// [`MAX_DNS_SERVERS`] entries. A text larger than the read bound returns an
/// empty list.
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    if text.len() as u64 > MAX_RESOLV_BYTES {
        return Vec::new();
    }
    let mut servers = Vec::new();
    for line in text.lines().take(MAX_RESOLV_LINES) {
        if servers.len() >= MAX_DNS_SERVERS {
            break;
        }
        if line.len() > MAX_RESOLV_LINE {
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(keyword) = fields.next() else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("nameserver") {
            continue;
        }
        let Some(value) = fields.next() else {
            continue;
        };
        let Ok(ip) = value.parse::<IpAddr>() else {
            continue;
        };
        let address = SocketAddr::new(ip, 53);
        if is_usable_dns_server(address) && !servers.contains(&address) {
            servers.push(address);
        }
    }
    servers
}

fn read_bounded(path: &Path, limit: u64) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = file.take(limit + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(bad("configuration file is too large"));
    }
    String::from_utf8(bytes).map_err(|_| bad("configuration file is not UTF-8"))
}

fn default_route_from(path: &Path) -> io::Result<LinuxDefaultRoute> {
    let text = read_bounded(path, MAX_ROUTE_BYTES)?;
    select_default_route(&parse_route_table(&text)?)
}

/// Read the Linux IPv4 default route.
///
/// This call reads [`ROUTE_FILE`] only. It does not change a route.
pub fn default_route() -> io::Result<LinuxDefaultRoute> {
    default_route_from(Path::new(ROUTE_FILE))
}

fn system_dns_from(paths: &[&Path]) -> io::Result<Vec<SocketAddr>> {
    let mut last_error = None;
    for path in paths {
        match read_bounded(path, MAX_RESOLV_BYTES) {
            Ok(text) => {
                let servers = parse_resolv_conf(&text);
                if !servers.is_empty() {
                    return Ok(servers);
                }
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(match last_error {
        Some(error) => io::Error::new(
            io::ErrorKind::NotFound,
            format!("no usable non-local DNS upstream: {error}"),
        ),
        None => io::Error::new(io::ErrorKind::NotFound, "no usable non-local DNS upstream"),
    })
}

/// Read the usable non-local DNS servers.
///
/// The function reads [`RESOLV_CONF`]. When that file holds no usable
/// nameserver, it reads [`SYSTEMD_UPSTREAM_RESOLV_CONF`]. It never returns a
/// loopback or link-local stub. It fails when no usable upstream exists.
pub fn system_dns() -> io::Result<Vec<SocketAddr>> {
    system_dns_from(&[
        Path::new(RESOLV_CONF),
        Path::new(SYSTEMD_UPSTREAM_RESOLV_CONF),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const DEFAULT_ROUTE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
";

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            loop {
                let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "hotspotshade-environment-linux-{}-{unique}",
                    std::process::id()
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn route(interface: &str, gateway: Option<Ipv4Addr>, flags: u16, metric: u32) -> RouteEntry {
        RouteEntry {
            interface: interface.to_owned(),
            destination: Ipv4Addr::UNSPECIFIED,
            gateway,
            flags,
            metric,
            mask: Ipv4Addr::UNSPECIFIED,
        }
    }

    #[test]
    fn route_fields_use_little_endian_order() {
        let entries = parse_route_table(DEFAULT_ROUTE).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].interface, "eth0");
        assert_eq!(entries[0].destination, Ipv4Addr::UNSPECIFIED);
        assert_eq!(entries[0].gateway, Some(Ipv4Addr::new(192, 168, 2, 1)));
        assert_eq!(entries[0].flags, 3);
        assert_eq!(entries[0].metric, 0);
        assert_eq!(entries[0].mask, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn route_fields_read_a_subnet_and_a_zero_gateway() {
        let text = "wlan0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let entries = parse_route_table(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].destination, Ipv4Addr::new(192, 168, 2, 0));
        assert_eq!(entries[0].gateway, None);
        assert_eq!(entries[0].mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(entries[0].metric, 100);
    }

    #[test]
    fn route_parser_rejects_malformed_data() {
        for text in [
            "eth0 00000000\n",
            "eth0 ZZZZZZZZ 00000000 0001 0 0 0 00000000\n",
            "eth0 00000000 00000000 000Z 0 0 0 00000000\n",
            "eth0 00000000 00000000 0001 0 0 x 00000000\n",
            "this-name-is-too-long\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n",
            "bad/name\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n",
        ] {
            assert!(parse_route_table(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn route_parser_is_bounded() {
        let long_line = "x".repeat(MAX_ROUTE_LINE + 1);
        assert!(parse_route_table(&long_line).is_err());

        let mut many_lines = String::new();
        for _ in 0..=MAX_ROUTE_LINES {
            many_lines.push('\n');
        }
        many_lines.push_str(DEFAULT_ROUTE);
        assert!(parse_route_table(&many_lines).is_err());
    }

    #[test]
    fn route_parse_errors_name_the_field_and_line_without_values() {
        let input = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n\
wlan0 00000000 00000000 0001 0 0 badmetric 00000000\n";
        let error = parse_route_table(input).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "invalid route metric on line 2");
        assert!(!error.to_string().contains("wlan0"));
        assert!(!error.to_string().contains("badmetric"));
    }

    #[test]
    fn route_parser_accepts_a_missing_header_and_blank_lines() {
        let text = "\n\neth0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\n";
        let entries = parse_route_table(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].interface, "eth0");
    }

    #[test]
    fn selector_uses_the_lowest_metric() {
        let entries = vec![
            route("eth0", Some(Ipv4Addr::new(192, 168, 1, 1)), 3, 100),
            route("wlan0", Some(Ipv4Addr::new(172, 20, 10, 1)), 3, 50),
        ];
        let selected = select_default_route(&entries).unwrap();
        assert_eq!(selected.interface, "wlan0");
        assert_eq!(selected.gateway, Some(Ipv4Addr::new(172, 20, 10, 1)));
        assert_eq!(selected.metric, 50);
    }

    #[test]
    fn selector_ignores_a_blackhole_device_placeholder() {
        let text = "*\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
                    wlan0\t00000000\t00000000\t0001\t0\t0\t600\t00000000\t0\t0\t0\n";
        let entries = parse_route_table(text).unwrap();
        assert_eq!(select_default_route(&entries).unwrap().interface, "wlan0");
        assert!(!is_physical_interface("*"));
    }

    #[test]
    fn selector_rejects_down_reject_tunnel_loopback_and_foreign_routes() {
        let mut foreign = route("eth2", None, RTF_UP, 1);
        foreign.destination = Ipv4Addr::new(192, 168, 2, 0);
        foreign.mask = Ipv4Addr::new(255, 255, 255, 0);
        let entries = vec![
            route("tun0", None, RTF_UP, 1),
            route("lo", None, RTF_UP, 1),
            route("eth0", None, 0, 2),
            route("eth1", None, RTF_UP | RTF_REJECT, 3),
            foreign,
            route("wlan0", None, RTF_UP, 5),
        ];
        let selected = select_default_route(&entries).unwrap();
        assert_eq!(selected.interface, "wlan0");
        assert_eq!(selected.gateway, None);
        assert_eq!(selected.metric, 5);
    }

    #[test]
    fn selector_rejects_a_gateway_without_the_gateway_flag() {
        let entries = vec![route(
            "eth0",
            Some(Ipv4Addr::new(192, 168, 1, 1)),
            RTF_UP,
            0,
        )];
        let error = select_default_route(&entries).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn selector_fails_when_no_default_route_is_usable() {
        let entries = vec![route("tun0", None, RTF_UP, 0), route("lo", None, RTF_UP, 0)];
        let error = select_default_route(&entries).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(select_default_route(&[]).is_err());
    }

    #[test]
    fn selector_fails_on_an_equal_metric_tie() {
        let entries = vec![
            route("eth0", Some(Ipv4Addr::new(192, 168, 1, 1)), 3, 100),
            route("wlan0", Some(Ipv4Addr::new(172, 20, 10, 1)), 3, 100),
        ];
        let error = select_default_route(&entries).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let duplicate = vec![
            route("eth0", Some(Ipv4Addr::new(192, 168, 1, 1)), 3, 100),
            route("eth0", Some(Ipv4Addr::new(192, 168, 1, 1)), 3, 100),
        ];
        assert_eq!(select_default_route(&duplicate).unwrap().interface, "eth0");
    }

    #[test]
    fn interface_name_filter_rejects_common_virtual_links() {
        assert!(is_physical_interface("eth0"));
        assert!(is_physical_interface("wlan0"));
        assert!(is_physical_interface("usb0"));
        assert!(is_physical_interface("enx001122334455"));
        assert!(!is_physical_interface("lo"));
        assert!(!is_physical_interface("tun0"));
        assert!(!is_physical_interface("tap0"));
        assert!(!is_physical_interface("wg0"));
        assert!(!is_physical_interface("docker0"));
        assert!(!is_physical_interface("veth1234"));
        assert!(!is_physical_interface("tailscale0"));
        assert!(!is_physical_interface(""));
        assert!(!is_physical_interface("bad/name"));
        assert!(!is_physical_interface("this-name-is-too-long"));
    }

    #[test]
    fn resolver_parser_rejects_local_stubs_and_non_numeric_values() {
        let text = "\
# comment
; comment
nameserver 127.0.0.53
nameserver 169.254.1.1
nameserver 0.0.0.0
nameserver 224.0.0.1
nameserver 255.255.255.255
nameserver ::1
nameserver fe80::1
nameserver ::
nameserver ::ffff:127.0.0.1
nameserver dns.example
nameserver 1.1.1.1 # inline comment
nameserver 1.1.1.1
nameserver 192.168.1.1
nameserver 2001:db8::1
search example.test
options edns0
";
        let servers = parse_resolv_conf(text);
        assert_eq!(
            servers,
            vec![
                "1.1.1.1:53".parse().unwrap(),
                "192.168.1.1:53".parse().unwrap(),
                "[2001:db8::1]:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn resolver_parser_is_bounded_and_deduplicated() {
        let mut text = String::new();
        for index in 1..=20 {
            text.push_str(&format!("nameserver 8.8.0.{index}\n"));
        }
        let servers = parse_resolv_conf(&text);
        assert_eq!(servers.len(), MAX_DNS_SERVERS);
        assert_eq!(servers[0], "8.8.0.1:53".parse().unwrap());
        assert_eq!(servers[MAX_DNS_SERVERS - 1], "8.8.0.16:53".parse().unwrap());

        let oversized = "#".repeat(MAX_RESOLV_BYTES as usize + 1);
        assert!(parse_resolv_conf(&oversized).is_empty());
    }

    #[test]
    fn dns_server_check_keeps_public_and_private_addresses() {
        for address in ["8.8.8.8:53", "192.168.1.1:53", "[2001:db8::1]:53"] {
            assert!(is_usable_dns_server(address.parse().unwrap()));
        }
        for address in [
            "127.0.0.1:53",
            "127.0.0.53:53",
            "169.254.1.1:53",
            "0.0.0.0:53",
            "224.0.0.1:53",
            "255.255.255.255:53",
            "[::1]:53",
            "[fe80::1]:53",
            "[::]:53",
            "[::ffff:127.0.0.1]:53",
            "8.8.8.8:0",
        ] {
            assert!(!is_usable_dns_server(address.parse().unwrap()));
        }
    }

    #[test]
    fn discovery_reads_only_temporary_files() {
        let dir = TempDir::new();
        let route_file = dir.path().join("route");
        std::fs::write(&route_file, DEFAULT_ROUTE).unwrap();
        let selected = default_route_from(&route_file).unwrap();
        assert_eq!(selected.interface, "eth0");
        assert_eq!(selected.metric, 0);

        let missing = dir.path().join("missing");
        assert_eq!(
            default_route_from(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        let malformed = dir.path().join("malformed");
        std::fs::write(&malformed, "eth0 00000000\n").unwrap();
        assert_eq!(
            default_route_from(&malformed).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn dns_discovery_skips_a_stub_and_uses_the_systemd_upstream() {
        let dir = TempDir::new();
        let main = dir.path().join("resolv.conf");
        let upstream = dir.path().join("systemd-resolv.conf");
        std::fs::write(&main, "nameserver 127.0.0.53\n").unwrap();
        std::fs::write(&upstream, "nameserver 9.9.9.9\n").unwrap();
        let servers = system_dns_from(&[main.as_path(), upstream.as_path()]).unwrap();
        assert_eq!(servers, vec!["9.9.9.9:53".parse().unwrap()]);
    }

    #[test]
    fn dns_discovery_uses_the_first_file_with_a_usable_server() {
        let dir = TempDir::new();
        let main = dir.path().join("resolv.conf");
        let upstream = dir.path().join("systemd-resolv.conf");
        std::fs::write(&main, "nameserver 1.1.1.1\n").unwrap();
        std::fs::write(&upstream, "nameserver 9.9.9.9\n").unwrap();
        let servers = system_dns_from(&[main.as_path(), upstream.as_path()]).unwrap();
        assert_eq!(servers, vec!["1.1.1.1:53".parse().unwrap()]);
    }

    #[test]
    fn dns_discovery_skips_an_unreadable_file() {
        let dir = TempDir::new();
        let missing = dir.path().join("missing");
        let upstream = dir.path().join("systemd-resolv.conf");
        std::fs::write(&upstream, "nameserver 9.9.9.9\n").unwrap();
        let servers = system_dns_from(&[missing.as_path(), upstream.as_path()]).unwrap();
        assert_eq!(servers, vec!["9.9.9.9:53".parse().unwrap()]);
    }

    #[test]
    fn dns_discovery_fails_without_a_usable_upstream() {
        let dir = TempDir::new();
        let main = dir.path().join("resolv.conf");
        let upstream = dir.path().join("systemd-resolv.conf");
        std::fs::write(&main, "nameserver 127.0.0.53\n").unwrap();
        std::fs::write(&upstream, "nameserver 127.0.0.53\n").unwrap();
        let error = system_dns_from(&[main.as_path(), upstream.as_path()]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);

        let missing = dir.path().join("missing");
        let error = system_dns_from(&[missing.as_path()]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn bounded_read_rejects_oversize_and_non_utf8_files() {
        let dir = TempDir::new();
        let exact = dir.path().join("exact");
        std::fs::write(&exact, b"12345678").unwrap();
        assert_eq!(read_bounded(&exact, 8).unwrap(), "12345678");

        let oversized = dir.path().join("oversized");
        std::fs::write(&oversized, b"123456789").unwrap();
        assert_eq!(
            read_bounded(&oversized, 8).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let binary = dir.path().join("binary");
        std::fs::write(&binary, [0xff]).unwrap();
        assert_eq!(
            read_bounded(&binary, 8).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
