//! Read-only Windows route verification foundation.
//!
//! This module checks the Windows route table for the routes that the tunnel
//! installs. It proves four facts from observed route data:
//!
//! 1. The table has the exact `0.0.0.0/1` and `128.0.0.0/1` routes.
//! 2. The tunnel adapter owns both routes. Ownership means the interface index
//!    and the interface LUID match the tunnel adapter.
//! 3. The route for the selected IPv6 policy is present and owned.
//! 4. Windows selects the tunnel route for a fixed set of probe destinations.
//!
//! The module changes no route and creates no device. It reads the route table
//! with `GetIpForwardTable2`, `GetBestInterfaceEx`, and `GetBestRoute2` only.
//!
//! # The tunnel is not fail-closed
//!
//! A successful result does not prove that no traffic can bypass the tunnel.
//! Windows uses the longest matching prefix. A more-specific route on another
//! interface bypasses the tunnel. A local DNS answer bypasses the tunnel. This
//! module checks only the exact prefixes that the tunnel manages and only the
//! probe destinations in the policy. Do not describe the tunnel as fail-closed.
//!
//! The IPv6 block route sends `2000::/3` to the tunnel adapter. It does not
//! cover IPv6 addresses outside `2000::/3`. It does not cover link-local,
//! multicast, or NAT64 addresses. The IPv6 block policy is a reduction of the
//! IPv6 path, not a complete block.
//!
//! # Layers
//!
//! [`verify`] is a pure function. It reads a [`RouteObservation`] and returns a
//! [`RouteProof`] or an error. Tests cover this layer without a Windows host.
//!
//! `observe` and `verify_live` are Windows only. They call `iphlpapi.dll` and
//! convert the ABI rows into [`ObservedRoute`] values. `observe` never treats an
//! API error as an empty table. `verify_live` returns an error for every
//! inconclusive state.
//!
//! # Microsoft references
//!
//! - `GetIpForwardTable2`: <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2>
//! - `GetBestRoute2`: <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getbestroute2>
//! - `GetBestInterfaceEx`: <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getbestinterfaceex>
//! - `MIB_IPFORWARD_ROW2`: <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2>
//! - `MIB_IPFORWARD_TABLE2`: <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_table2>
//! - `IP_ADDRESS_PREFIX`: <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix>
//! - `SOCKADDR_INET`: <https://learn.microsoft.com/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet>
//!
//! # Limits that need a live Windows host
//!
//! The ABI layout is asserted at compile time for `x86_64-pc-windows-msvc` and
//! `i686-pc-windows-msvc`. The behavior of the APIs on a live Windows host is
//! not verified here. In particular, these points need a measurement:
//!
//! - Windows must return the installed `/1` routes with next hop `0.0.0.0` and
//!   the installed `2000::/3` route with next hop `::`.
//! - Windows must report on-link tunnel routes with `Loopback` clear.
//! - Block mode needs a best-route result on an adapter without a configured
//!   IPv6 address. The lookup may fail when it cannot select a source address.
//! - The selected routes may need time to converge after installation.
//! - `GetBestRoute2` with a zero LUID and a nonzero interface index must
//!   return the route that the IP stack selects.
//! - The route table stride must equal `size_of::<MIB_IPFORWARD_ROW2>()`. The
//!   C array rule gives this stride. Microsoft warns that alignment padding may
//!   exist between rows, so confirm the stride on the target host.
//! - The interface metric is not read. A competing exact prefix on another
//!   interface is therefore an error, because this module cannot compare the
//!   total metrics.
//!
//! # Integration prerequisites
//!
//! 1. Keep the pure layer available on every platform. The FFI layer is behind
//!    `cfg(windows)`.
//! 2. Call `verify_live` for a managed IPv6 policy only, after `RouteManager`
//!    installs the routes and after the adapter has an interface index.
//! 3. Pass the exact LUID and index of the tunnel adapter. Do not persist the
//!    index across a link change.
//! 4. Treat `Ipv6InheritNotVerifiable` as "not verified". Do not show a
//!    success state for the inherit policy.
//! 5. Run the checks only for block or forward. On a host without an IPv6
//!    stack, the IPv6 snapshot returns an API error. Do not convert that error
//!    into a success.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The Windows `AF_INET` value.
#[cfg(windows)]
const AF_INET: u16 = 2;
/// The Windows `AF_INET6` value.
#[cfg(windows)]
const AF_INET6: u16 = 23;

/// The largest valid interface index. `NET_IFINDEX` uses 24 bits.
const MAX_INTERFACE_INDEX: u32 = 0x00ff_ffff;

/// The two IPv4 prefixes that the tunnel manages.
pub const IPV4_ROUTES: [RoutePrefix; 2] = [
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        length: 1,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        length: 1,
    },
];

/// The IPv6 prefix that the tunnel manages for block and forward.
pub const IPV6_TUNNEL_ROUTE: RoutePrefix = RoutePrefix {
    address: IpAddr::V6(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)),
    length: 3,
};

/// Default IPv4 best-route probes. Three are in `0.0.0.0/1` and two are in
/// `128.0.0.0/1`.
///
/// The probes check the selected route. They send no packet.
pub const DEFAULT_IPV4_PROBES: [Ipv4Addr; 5] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(200, 1, 1, 1),
    Ipv4Addr::new(208, 67, 222, 222),
];

/// Default IPv6 best-route probes. Both are inside `2000::/3`.
pub const DEFAULT_IPV6_PROBES: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressFamily {
    V4,
    V6,
}

/// An IP prefix with an address and a prefix length.
///
/// The prefix must not have host bits set. Use [`RoutePrefix::new`] to build a
/// valid prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RoutePrefix {
    /// The network address.
    pub address: IpAddr,
    /// The prefix length in bits.
    pub length: u8,
}

impl RoutePrefix {
    /// Build a prefix. Return `None` for a length that is too large or for an
    /// address that has host bits set.
    pub fn new(address: IpAddr, length: u8) -> Option<Self> {
        let prefix = Self { address, length };
        prefix.is_valid().then_some(prefix)
    }

    /// Return true for a family-correct length and a network address with no
    /// host bits set.
    pub fn is_valid(&self) -> bool {
        match self.address {
            IpAddr::V4(address) => self.length <= 32 && mask_v4(address, self.length) == address,
            IpAddr::V6(address) => self.length <= 128 && mask_v6(address, self.length) == address,
        }
    }

    /// Return true when this prefix contains the destination.
    pub fn contains(&self, destination: IpAddr) -> bool {
        match (self.address, destination) {
            (IpAddr::V4(network), IpAddr::V4(destination)) if self.length <= 32 => {
                mask_v4(destination, self.length) == network
            }
            (IpAddr::V6(network), IpAddr::V6(destination)) if self.length <= 128 => {
                mask_v6(destination, self.length) == network
            }
            _ => false,
        }
    }

    fn family(&self) -> AddressFamily {
        match self.address {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        }
    }
}

impl fmt::Display for RoutePrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.length)
    }
}

fn mask_v4(address: Ipv4Addr, length: u8) -> Ipv4Addr {
    if length == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mask = u32::MAX << (32 - u32::from(length));
    Ipv4Addr::from(u32::from(address) & mask)
}

fn mask_v6(address: Ipv6Addr, length: u8) -> Ipv6Addr {
    if length == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mask = u128::MAX << (128 - u32::from(length));
    Ipv6Addr::from(u128::from(address) & mask)
}

/// The interface identity of the tunnel adapter.
///
/// The index alone is not stable. Windows can reuse an index after an adapter
/// is disabled. The LUID identifies the adapter. Both values must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelIdentity {
    /// The `NET_IFINDEX` of the tunnel adapter.
    pub interface_index: u32,
    /// The `NET_LUID` value of the tunnel adapter.
    pub interface_luid: u64,
}

impl TunnelIdentity {
    /// Build a tunnel identity. Reject a zero index, an index above 24 bits,
    /// and a zero LUID.
    pub fn new(interface_index: u32, interface_luid: u64) -> Result<Self, RouteVerifyError> {
        if !valid_interface_index(interface_index) {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface index must be a nonzero 24-bit number",
            ));
        }
        if interface_luid == 0 {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface LUID must be nonzero",
            ));
        }
        Ok(Self {
            interface_index,
            interface_luid,
        })
    }
}

/// The IPv6 route policy that the tunnel requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6RoutePolicy {
    /// Install `2000::/3` on the tunnel and drop the packets in the relay.
    Block,
    /// Install `2000::/3` on the tunnel and forward the packets.
    Forward,
    /// Do not manage IPv6 routes. This module cannot verify this policy.
    Inherit,
}

impl Ipv6RoutePolicy {
    /// Return true for a policy that installs the tunnel route.
    pub fn is_managed(self) -> bool {
        matches!(self, Self::Block | Self::Forward)
    }
}

/// One route row from the Windows route table, converted to native values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedRoute {
    /// The destination prefix.
    pub prefix: RoutePrefix,
    /// The `NET_IFINDEX` from the row.
    pub interface_index: u32,
    /// The `NET_LUID` from the row.
    pub interface_luid: u64,
    /// The next hop. An on-link route uses the unspecified address.
    pub next_hop: IpAddr,
    /// The route metric offset. This is not the total metric.
    pub metric: u32,
    /// The `NL_ROUTE_PROTOCOL` value. This value is for diagnostics only.
    pub protocol: u32,
    /// True when Windows marks the row as a loopback route.
    pub loopback: bool,
}

/// One best-route probe.
///
/// `best_interface_index` comes from `GetBestInterfaceEx`. `route` comes from
/// `GetBestRoute2` for that interface. The two calls together show which
/// interface Windows selects and which route it selects on that interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BestRouteProbe {
    /// The destination address.
    pub destination: IpAddr,
    /// The interface that Windows selects for the destination.
    pub best_interface_index: u32,
    /// The route that Windows selects on that interface.
    pub route: ObservedRoute,
}

/// The route data that a read-only check collected.
///
/// Build this value from Windows API calls, or from fixed test data. `verify`
/// does not call the operating system.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteObservation {
    /// Rows from `GetIpForwardTable2(AF_INET)`.
    pub ipv4_routes: Vec<ObservedRoute>,
    /// Rows from `GetIpForwardTable2(AF_INET6)`.
    pub ipv6_routes: Vec<ObservedRoute>,
    /// Best-route probes.
    pub probes: Vec<BestRouteProbe>,
}

impl RouteObservation {
    fn routes_for(&self, family: AddressFamily) -> &[ObservedRoute] {
        match family {
            AddressFamily::V4 => &self.ipv4_routes,
            AddressFamily::V6 => &self.ipv6_routes,
        }
    }
}

/// The policy that a route check must prove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyPolicy {
    /// The tunnel adapter identity.
    pub tunnel: TunnelIdentity,
    /// The IPv6 policy that the tunnel requested.
    pub ipv6: Ipv6RoutePolicy,
    /// IPv4 destinations for the best-route checks.
    pub ipv4_probes: Vec<Ipv4Addr>,
    /// IPv6 destinations for the best-route checks.
    pub ipv6_probes: Vec<Ipv6Addr>,
}

impl VerifyPolicy {
    /// Build a policy with the default probe destinations.
    pub fn new(tunnel: TunnelIdentity, ipv6: Ipv6RoutePolicy) -> Self {
        Self {
            tunnel,
            ipv6,
            ipv4_probes: DEFAULT_IPV4_PROBES.to_vec(),
            ipv6_probes: DEFAULT_IPV6_PROBES.to_vec(),
        }
    }
}

/// A route that the check proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenRoute {
    /// The proven prefix.
    pub prefix: RoutePrefix,
    /// The tunnel interface index from the matching row.
    pub interface_index: u32,
    /// The tunnel interface LUID from the matching row.
    pub interface_luid: u64,
    /// The next hop from the matching row.
    pub next_hop: IpAddr,
    /// The route metric offset from the matching row.
    pub metric: u32,
    /// The route protocol from the matching row. This value is for diagnostics.
    pub protocol: u32,
}

/// The result of a managed-policy check.
///
/// This value proves the exact routes and the listed probe destinations. It
/// does not prove that no other route can bypass the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteProof {
    /// The proven `0.0.0.0/1` route.
    pub first_half: ProvenRoute,
    /// The proven `128.0.0.0/1` route.
    pub second_half: ProvenRoute,
    /// The proven `2000::/3` route.
    pub ipv6: ProvenRoute,
    /// The managed IPv6 policy that this proof covers.
    pub ipv6_policy: Ipv6RoutePolicy,
    /// The number of best-route probes that matched.
    pub probes_checked: usize,
}

/// A reason that the route check did not prove the policy.
///
/// Every variant is a failure. Do not show a success state for any variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteVerifyError {
    /// The tunnel identity is not usable.
    InvalidTunnelIdentity(&'static str),
    /// The probe policy is not usable.
    InvalidPolicy(&'static str),
    /// The observation is not consistent.
    InvalidObservation(&'static str),
    /// The exact route is absent.
    MissingRoute {
        /// The absent prefix.
        prefix: RoutePrefix,
    },
    /// The exact route exists, but another interface owns it.
    ForeignRoute {
        /// The prefix.
        prefix: RoutePrefix,
        /// The interface that owns the route.
        interface_index: u32,
    },
    /// The interface index belongs to a different adapter now.
    IndexReused {
        /// The prefix.
        prefix: RoutePrefix,
        /// The reused index.
        interface_index: u32,
        /// The LUID from the row.
        interface_luid: u64,
    },
    /// A second exact-prefix route on another interface makes the result
    /// ambiguous. This check does not read interface metrics.
    CompetingRoute {
        /// The prefix.
        prefix: RoutePrefix,
        /// The other interface.
        interface_index: u32,
    },
    /// The tunnel adapter has more than one row for the exact prefix.
    DuplicateTunnelRoute {
        /// The prefix.
        prefix: RoutePrefix,
        /// The number of rows on the tunnel adapter.
        count: usize,
    },
    /// The exact route does not use the unspecified next hop.
    UnexpectedNextHop {
        /// The prefix.
        prefix: RoutePrefix,
        /// The next hop from the row.
        next_hop: IpAddr,
    },
    /// The exact route is a loopback route.
    LoopbackRoute {
        /// The prefix.
        prefix: RoutePrefix,
    },
    /// Windows selects a different interface for the destination.
    BestInterfaceMismatch {
        /// The probe destination.
        destination: IpAddr,
        /// The tunnel interface index.
        expected: u32,
        /// The interface that Windows selects.
        actual: u32,
    },
    /// Windows selects a different route for the destination.
    BestRouteMismatch {
        /// The probe destination.
        destination: IpAddr,
        /// The required prefix.
        expected: RoutePrefix,
        /// The selected prefix.
        actual: RoutePrefix,
        /// The interface of the selected route.
        interface_index: u32,
    },
    /// The selected route is not on the tunnel adapter.
    BestRouteIdentityMismatch {
        /// The probe destination.
        destination: IpAddr,
        /// The interface index from the selected row.
        interface_index: u32,
        /// The interface LUID from the selected row.
        interface_luid: u64,
    },
    /// The observation has no probe for a policy destination.
    MissingBestRoute {
        /// The destination that has no probe.
        destination: IpAddr,
    },
    /// The IPv6 inherit policy has no tunnel route to prove.
    Ipv6InheritNotVerifiable,
    /// A Windows API call failed.
    Api {
        /// The API name.
        operation: &'static str,
        /// The Windows error code.
        code: u32,
    },
}

impl fmt::Display for RouteVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTunnelIdentity(message) => write!(formatter, "{message}"),
            Self::InvalidPolicy(message) => write!(formatter, "invalid route policy: {message}"),
            Self::InvalidObservation(message) => {
                write!(formatter, "invalid route observation: {message}")
            }
            Self::MissingRoute { prefix } => {
                write!(formatter, "the route table has no {prefix} route")
            }
            Self::ForeignRoute {
                prefix,
                interface_index,
            } => write!(
                formatter,
                "the {prefix} route belongs to interface {interface_index}"
            ),
            Self::IndexReused {
                prefix,
                interface_index,
                interface_luid,
            } => write!(
                formatter,
                "the {prefix} route uses interface index {interface_index} with LUID {interface_luid}, not the tunnel adapter"
            ),
            Self::CompetingRoute {
                prefix,
                interface_index,
            } => write!(
                formatter,
                "interface {interface_index} also has the {prefix} route; this check does not read interface metrics, so the selected route is ambiguous"
            ),
            Self::DuplicateTunnelRoute { prefix, count } => write!(
                formatter,
                "the tunnel adapter has {count} {prefix} routes"
            ),
            Self::UnexpectedNextHop { prefix, next_hop } => write!(
                formatter,
                "the {prefix} route has next hop {next_hop}, not the unspecified address"
            ),
            Self::LoopbackRoute { prefix } => {
                write!(formatter, "the {prefix} route is a loopback route")
            }
            Self::BestInterfaceMismatch {
                destination,
                expected,
                actual,
            } => write!(
                formatter,
                "Windows selects interface {actual} for {destination}, not the tunnel interface {expected}"
            ),
            Self::BestRouteMismatch {
                destination,
                expected,
                actual,
                interface_index,
            } => write!(
                formatter,
                "Windows selects {actual} on interface {interface_index} for {destination}, not {expected}"
            ),
            Self::BestRouteIdentityMismatch {
                destination,
                interface_index,
                interface_luid,
            } => write!(
                formatter,
                "the best route for {destination} uses interface index {interface_index} with LUID {interface_luid}, not the tunnel adapter"
            ),
            Self::MissingBestRoute { destination } => {
                write!(formatter, "the observation has no best route for {destination}")
            }
            Self::Ipv6InheritNotVerifiable => write!(
                formatter,
                "the IPv6 inherit policy has no tunnel route, so this check cannot prove it"
            ),
            Self::Api { operation, code } => {
                write!(formatter, "{operation} failed with Windows error {code}")
            }
        }
    }
}

impl std::error::Error for RouteVerifyError {}

fn valid_interface_index(index: u32) -> bool {
    index != 0 && index <= MAX_INTERFACE_INDEX
}

fn validate_tunnel(tunnel: TunnelIdentity) -> Result<(), RouteVerifyError> {
    if !valid_interface_index(tunnel.interface_index) {
        return Err(RouteVerifyError::InvalidTunnelIdentity(
            "the interface index must be a nonzero 24-bit number",
        ));
    }
    if tunnel.interface_luid == 0 {
        return Err(RouteVerifyError::InvalidTunnelIdentity(
            "the interface LUID must be nonzero",
        ));
    }
    Ok(())
}

fn validate_destination(destination: IpAddr) -> Result<(), RouteVerifyError> {
    match destination {
        IpAddr::V4(address) => {
            if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
                return Err(RouteVerifyError::InvalidPolicy(
                    "an IPv4 probe must be a unicast host",
                ));
            }
        }
        IpAddr::V6(address) => {
            if address.is_unspecified() || address.is_multicast() {
                return Err(RouteVerifyError::InvalidPolicy(
                    "an IPv6 probe must be a unicast host",
                ));
            }
        }
    }
    Ok(())
}

fn validate_probe_lists(policy: &VerifyPolicy) -> Result<(), RouteVerifyError> {
    let mut seen = Vec::new();
    for destination in &policy.ipv4_probes {
        let destination = IpAddr::V4(*destination);
        validate_destination(destination)?;
        if seen.contains(&destination) {
            return Err(RouteVerifyError::InvalidPolicy(
                "the IPv4 probe list has a duplicate destination",
            ));
        }
        seen.push(destination);
    }
    let mut seen = Vec::new();
    for destination in &policy.ipv6_probes {
        let destination = IpAddr::V6(*destination);
        validate_destination(destination)?;
        if seen.contains(&destination) {
            return Err(RouteVerifyError::InvalidPolicy(
                "the IPv6 probe list has a duplicate destination",
            ));
        }
        seen.push(destination);
    }
    Ok(())
}

fn validate_managed_policy(policy: &VerifyPolicy) -> Result<(), RouteVerifyError> {
    validate_probe_lists(policy)?;
    if policy.ipv4_probes.is_empty() {
        return Err(RouteVerifyError::InvalidPolicy(
            "at least one IPv4 probe is required",
        ));
    }
    let first = policy
        .ipv4_probes
        .iter()
        .any(|destination| IPV4_ROUTES[0].contains(IpAddr::V4(*destination)));
    let second = policy
        .ipv4_probes
        .iter()
        .any(|destination| IPV4_ROUTES[1].contains(IpAddr::V4(*destination)));
    if !first || !second {
        return Err(RouteVerifyError::InvalidPolicy(
            "the IPv4 probe list needs one destination in each half",
        ));
    }
    if policy.ipv6_probes.is_empty() {
        return Err(RouteVerifyError::InvalidPolicy(
            "at least one IPv6 probe is required for a managed IPv6 policy",
        ));
    }
    for destination in &policy.ipv6_probes {
        if !IPV6_TUNNEL_ROUTE.contains(IpAddr::V6(*destination)) {
            return Err(RouteVerifyError::InvalidPolicy(
                "every IPv6 probe must be inside 2000::/3",
            ));
        }
    }
    Ok(())
}

fn validate_observation(observation: &RouteObservation) -> Result<(), RouteVerifyError> {
    for route in &observation.ipv4_routes {
        validate_row(route, AddressFamily::V4)?;
    }
    for route in &observation.ipv6_routes {
        validate_row(route, AddressFamily::V6)?;
    }
    let mut seen = Vec::new();
    for probe in &observation.probes {
        validate_destination(probe.destination)
            .map_err(|_| RouteVerifyError::InvalidObservation("a probe is not a unicast host"))?;
        if seen.contains(&probe.destination) {
            return Err(RouteVerifyError::InvalidObservation(
                "the observation has a duplicate probe destination",
            ));
        }
        seen.push(probe.destination);
        if !valid_interface_index(probe.best_interface_index) {
            return Err(RouteVerifyError::InvalidObservation(
                "a best-route probe has an invalid interface index",
            ));
        }
        let family = match probe.destination {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        };
        validate_row(&probe.route, family)?;
        if !probe.route.prefix.contains(probe.destination) {
            return Err(RouteVerifyError::InvalidObservation(
                "a best-route prefix does not contain its destination",
            ));
        }
    }
    Ok(())
}

fn validate_row(route: &ObservedRoute, family: AddressFamily) -> Result<(), RouteVerifyError> {
    if !route.prefix.is_valid() || route.prefix.family() != family {
        return Err(RouteVerifyError::InvalidObservation(
            "a route row has an invalid prefix or the wrong address family",
        ));
    }
    if !valid_interface_index(route.interface_index) {
        return Err(RouteVerifyError::InvalidObservation(
            "a route row has an invalid interface index",
        ));
    }
    if route.interface_luid == 0 {
        return Err(RouteVerifyError::InvalidObservation(
            "a route row has a zero interface LUID",
        ));
    }
    let next_hop_family = match route.next_hop {
        IpAddr::V4(_) => AddressFamily::V4,
        IpAddr::V6(_) => AddressFamily::V6,
    };
    if next_hop_family != family {
        return Err(RouteVerifyError::InvalidObservation(
            "a route row has a next hop from the wrong address family",
        ));
    }
    Ok(())
}

/// Prove the requested policy from one route observation.
///
/// This function is pure. It changes no route and creates no device.
///
/// It returns an error for a missing route, a foreign route, a competing exact
/// prefix, a reused interface index, a bad next hop, or a best-route mismatch.
/// It also returns an error for the [`Ipv6RoutePolicy::Inherit`] policy, because
/// that policy has no tunnel route to prove. Do not report the inherit policy
/// as verified.
///
/// A successful result is not proof that the tunnel cannot be bypassed. See the
/// module documentation.
pub fn verify(
    observation: &RouteObservation,
    policy: &VerifyPolicy,
) -> Result<RouteProof, RouteVerifyError> {
    validate_tunnel(policy.tunnel)?;
    if !policy.ipv6.is_managed() {
        return Err(RouteVerifyError::Ipv6InheritNotVerifiable);
    }
    validate_managed_policy(policy)?;
    validate_observation(observation)?;

    let first_half = prove_exact(
        observation.routes_for(AddressFamily::V4),
        IPV4_ROUTES[0],
        policy.tunnel,
    )?;
    let second_half = prove_exact(
        observation.routes_for(AddressFamily::V4),
        IPV4_ROUTES[1],
        policy.tunnel,
    )?;
    let ipv6 = prove_exact(
        observation.routes_for(AddressFamily::V6),
        IPV6_TUNNEL_ROUTE,
        policy.tunnel,
    )?;

    let mut probes_checked = 0usize;
    for probe in &observation.probes {
        let expected = expected_prefix(probe.destination)?;
        check_probe(probe, expected, policy.tunnel)?;
        probes_checked += 1;
    }
    for destination in &policy.ipv4_probes {
        let destination = IpAddr::V4(*destination);
        if !observation
            .probes
            .iter()
            .any(|probe| probe.destination == destination)
        {
            return Err(RouteVerifyError::MissingBestRoute { destination });
        }
    }
    for destination in &policy.ipv6_probes {
        let destination = IpAddr::V6(*destination);
        if !observation
            .probes
            .iter()
            .any(|probe| probe.destination == destination)
        {
            return Err(RouteVerifyError::MissingBestRoute { destination });
        }
    }

    Ok(RouteProof {
        first_half,
        second_half,
        ipv6,
        ipv6_policy: policy.ipv6,
        probes_checked,
    })
}

fn expected_prefix(destination: IpAddr) -> Result<RoutePrefix, RouteVerifyError> {
    match destination {
        IpAddr::V4(_) => IPV4_ROUTES
            .iter()
            .copied()
            .find(|prefix| prefix.contains(destination))
            .ok_or(RouteVerifyError::InvalidObservation(
                "an IPv4 probe has no managed half",
            )),
        IpAddr::V6(_) => {
            if IPV6_TUNNEL_ROUTE.contains(destination) {
                Ok(IPV6_TUNNEL_ROUTE)
            } else {
                Err(RouteVerifyError::InvalidObservation(
                    "an IPv6 probe is outside 2000::/3",
                ))
            }
        }
    }
}

fn prove_exact(
    routes: &[ObservedRoute],
    expected: RoutePrefix,
    tunnel: TunnelIdentity,
) -> Result<ProvenRoute, RouteVerifyError> {
    let mut owned = Vec::new();
    let mut foreign = None;
    let mut reused = None;
    for route in routes.iter().filter(|route| route.prefix == expected) {
        if route.interface_index == tunnel.interface_index {
            if route.interface_luid == tunnel.interface_luid {
                owned.push(route);
            } else if reused.is_none() {
                reused = Some(route);
            }
        } else if foreign.is_none() {
            foreign = Some(route);
        }
    }

    if owned.is_empty() && foreign.is_none() && reused.is_none() {
        return Err(RouteVerifyError::MissingRoute { prefix: expected });
    }
    if let Some(route) = reused {
        return Err(RouteVerifyError::IndexReused {
            prefix: expected,
            interface_index: route.interface_index,
            interface_luid: route.interface_luid,
        });
    }
    let Some(own) = owned.first() else {
        let route = foreign.ok_or(RouteVerifyError::InvalidObservation(
            "a route candidate has no interface",
        ))?;
        return Err(RouteVerifyError::ForeignRoute {
            prefix: expected,
            interface_index: route.interface_index,
        });
    };
    if owned.len() > 1 {
        return Err(RouteVerifyError::DuplicateTunnelRoute {
            prefix: expected,
            count: owned.len(),
        });
    }
    if let Some(route) = foreign {
        return Err(RouteVerifyError::CompetingRoute {
            prefix: expected,
            interface_index: route.interface_index,
        });
    }
    if !own.next_hop.is_unspecified() {
        return Err(RouteVerifyError::UnexpectedNextHop {
            prefix: expected,
            next_hop: own.next_hop,
        });
    }
    if own.loopback {
        return Err(RouteVerifyError::LoopbackRoute { prefix: expected });
    }
    Ok(ProvenRoute {
        prefix: own.prefix,
        interface_index: own.interface_index,
        interface_luid: own.interface_luid,
        next_hop: own.next_hop,
        metric: own.metric,
        protocol: own.protocol,
    })
}

fn check_probe(
    probe: &BestRouteProbe,
    expected: RoutePrefix,
    tunnel: TunnelIdentity,
) -> Result<(), RouteVerifyError> {
    if probe.best_interface_index != tunnel.interface_index {
        return Err(RouteVerifyError::BestInterfaceMismatch {
            destination: probe.destination,
            expected: tunnel.interface_index,
            actual: probe.best_interface_index,
        });
    }
    if probe.route.prefix != expected {
        return Err(RouteVerifyError::BestRouteMismatch {
            destination: probe.destination,
            expected,
            actual: probe.route.prefix,
            interface_index: probe.route.interface_index,
        });
    }
    if probe.route.interface_index != tunnel.interface_index
        || probe.route.interface_luid != tunnel.interface_luid
    {
        return Err(RouteVerifyError::BestRouteIdentityMismatch {
            destination: probe.destination,
            interface_index: probe.route.interface_index,
            interface_luid: probe.route.interface_luid,
        });
    }
    if !probe.route.next_hop.is_unspecified() {
        return Err(RouteVerifyError::UnexpectedNextHop {
            prefix: expected,
            next_hop: probe.route.next_hop,
        });
    }
    if probe.route.loopback {
        return Err(RouteVerifyError::LoopbackRoute { prefix: expected });
    }
    Ok(())
}

#[cfg(windows)]
pub use win32::{observe, verify_live};

#[cfg(windows)]
mod win32 {
    //! Windows ABI layer.
    //!
    //! The type layout is checked at compile time for both MSVC targets. The
    //! checks below assert the offsets that the Microsoft headers define.

    use super::{
        validate_probe_lists, validate_tunnel, BestRouteProbe, ObservedRoute, RouteObservation,
        RoutePrefix, RouteProof, RouteVerifyError, VerifyPolicy, AF_INET, AF_INET6,
    };
    use std::ffi::c_void;
    use std::mem::{align_of, offset_of, size_of};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr;

    /// A bound on the route row count. A normal table has a few hundred rows.
    /// This bound rejects a corrupt count before the loop reads memory.
    const MAX_ROUTE_ROWS: usize = 1 << 18;

    // The fields mirror the Windows headers. Not every field is read here.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawSockaddrIn {
        family: u16,
        port: u16,
        address: [u8; 4],
        zero: [u8; 8],
    }

    // The fields mirror the Windows headers. Not every field is read here.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawSockaddrIn6 {
        family: u16,
        port: u16,
        flow_info: u32,
        address: [u8; 16],
        scope_id: u32,
    }

    // The fields mirror the Windows headers. Not every field is read here.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    union RawSockaddrInet {
        family: u16,
        v4: RawSockaddrIn,
        v6: RawSockaddrIn6,
    }

    impl RawSockaddrInet {
        fn family(&self) -> u16 {
            // SAFETY: Every union member starts with the address family. A
            // `u16` read is valid for an initialized union.
            unsafe { self.family }
        }
    }

    // The fields mirror the Windows headers. Not every field is read here.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawIpAddressPrefix {
        prefix: RawSockaddrInet,
        prefix_length: u8,
    }

    /// The Windows `MIB_IPFORWARD_ROW2` layout.
    // The fields mirror the Windows headers. Not every field is read here.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawMibIpForwardRow2 {
        interface_luid: u64,
        interface_index: u32,
        destination_prefix: RawIpAddressPrefix,
        next_hop: RawSockaddrInet,
        site_prefix_length: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        metric: u32,
        protocol: i32,
        loopback: u8,
        autoconfigure_address: u8,
        publish: u8,
        immortal: u8,
        age: u32,
        origin: i32,
    }

    /// The prefix of `MIB_IPFORWARD_TABLE2`. The real table has a flexible
    /// array after `NumEntries`. `offset_of!` gives the row offset, including
    /// the alignment padding before the first row.
    // The fields mirror the Windows headers. Not every field is read here.
    #[allow(dead_code)]
    #[repr(C)]
    struct RawMibIpForwardTable2 {
        num_entries: u32,
        first_row: RawMibIpForwardRow2,
    }

    const ROWS_OFFSET: usize = offset_of!(RawMibIpForwardTable2, first_row);

    const _: () = {
        assert!(size_of::<RawSockaddrIn>() == 16);
        assert!(size_of::<RawSockaddrIn6>() == 28);
        assert!(size_of::<RawSockaddrInet>() == 28);
        assert!(align_of::<RawSockaddrInet>() == 4);
        assert!(size_of::<RawIpAddressPrefix>() == 32);
        assert!(offset_of!(RawIpAddressPrefix, prefix_length) == 28);
        assert!(size_of::<RawMibIpForwardRow2>() == 104);
        assert!(align_of::<RawMibIpForwardRow2>() == 8);
        assert!(offset_of!(RawMibIpForwardRow2, interface_luid) == 0);
        assert!(offset_of!(RawMibIpForwardRow2, interface_index) == 8);
        assert!(offset_of!(RawMibIpForwardRow2, destination_prefix) == 12);
        assert!(offset_of!(RawMibIpForwardRow2, next_hop) == 44);
        assert!(offset_of!(RawMibIpForwardRow2, site_prefix_length) == 72);
        assert!(offset_of!(RawMibIpForwardRow2, valid_lifetime) == 76);
        assert!(offset_of!(RawMibIpForwardRow2, preferred_lifetime) == 80);
        assert!(offset_of!(RawMibIpForwardRow2, metric) == 84);
        assert!(offset_of!(RawMibIpForwardRow2, protocol) == 88);
        assert!(offset_of!(RawMibIpForwardRow2, loopback) == 92);
        assert!(offset_of!(RawMibIpForwardRow2, age) == 96);
        assert!(offset_of!(RawMibIpForwardRow2, origin) == 100);
        assert!(ROWS_OFFSET == 8);
        assert!(size_of::<RawMibIpForwardRow2>().is_multiple_of(align_of::<RawMibIpForwardRow2>()));
    };

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetIpForwardTable2(family: u16, table: *mut *mut RawMibIpForwardTable2) -> u32;
        fn GetBestInterfaceEx(destination: *const RawSockaddrInet, index: *mut u32) -> u32;
        fn GetBestRoute2(
            interface_luid: *const u64,
            interface_index: u32,
            source_address: *const RawSockaddrInet,
            destination_address: *const RawSockaddrInet,
            address_sort_options: u32,
            best_route: *mut RawMibIpForwardRow2,
            best_source_address: *mut RawSockaddrInet,
        ) -> u32;
        fn FreeMibTable(memory: *mut c_void);
    }

    /// Read the route table and the best routes for one policy.
    ///
    /// This function never changes a route and never creates a device. It
    /// returns an error for every API failure. It does not turn a failure into
    /// an empty table.
    pub fn observe(policy: &VerifyPolicy) -> Result<RouteObservation, RouteVerifyError> {
        validate_tunnel(policy.tunnel)?;
        if !policy.ipv6.is_managed() {
            return Err(RouteVerifyError::Ipv6InheritNotVerifiable);
        }
        validate_probe_lists(policy)?;

        let ipv4_routes = snapshot(AF_INET)?;
        let ipv6_routes = if policy.ipv6_probes.is_empty() {
            Vec::new()
        } else {
            snapshot(AF_INET6)?
        };

        let mut probes = Vec::with_capacity(policy.ipv4_probes.len() + policy.ipv6_probes.len());
        for destination in &policy.ipv4_probes {
            probes.push(best_route(IpAddr::V4(*destination))?);
        }
        for destination in &policy.ipv6_probes {
            probes.push(best_route(IpAddr::V6(*destination))?);
        }
        Ok(RouteObservation {
            ipv4_routes,
            ipv6_routes,
            probes,
        })
    }

    /// Observe the live route data and prove the managed policy.
    ///
    /// The caller must install the routes and resolve the tunnel adapter index
    /// before this call. The call reads the table and the selected routes. It
    /// changes nothing.
    pub fn verify_live(policy: &VerifyPolicy) -> Result<RouteProof, RouteVerifyError> {
        let observation = observe(policy)?;
        super::verify(&observation, policy)
    }

    fn snapshot(family: u16) -> Result<Vec<ObservedRoute>, RouteVerifyError> {
        let mut table: *mut RawMibIpForwardTable2 = ptr::null_mut();
        let status = unsafe { GetIpForwardTable2(family, &mut table) };
        if status != 0 {
            if !table.is_null() {
                // SAFETY: A failed call must not return a table, but a non-null
                // value is still owned by the IP helper API. Release it.
                unsafe { FreeMibTable(table.cast::<c_void>()) };
            }
            return Err(RouteVerifyError::Api {
                operation: "GetIpForwardTable2",
                code: status,
            });
        }
        if table.is_null() {
            return Err(RouteVerifyError::InvalidObservation(
                "GetIpForwardTable2 returned a null table",
            ));
        }

        let result = (|| {
            // SAFETY: The API returned a non-null table. `NumEntries` is the
            // first field of the documented layout.
            let count = unsafe { (*table).num_entries } as usize;
            if count > MAX_ROUTE_ROWS {
                return Err(RouteVerifyError::InvalidObservation(
                    "the route table entry count is out of range",
                ));
            }
            let base = table.cast::<u8>();
            let stride = size_of::<RawMibIpForwardRow2>();
            let mut routes = Vec::with_capacity(count);
            for index in 0..count {
                let offset = ROWS_OFFSET + index * stride;
                // SAFETY: The API owns a table buffer with `count` rows. The
                // table starts at `table`, the rows start at `ROWS_OFFSET`, and
                // the stride is the documented C array stride. The bound above
                // keeps the offset inside the table allocation. The row type is
                // `repr(C)` and its layout is asserted above.
                let raw = unsafe { &*base.add(offset).cast::<RawMibIpForwardRow2>() };
                routes.push(observed_from_raw(raw)?);
            }
            Ok(routes)
        })();
        // SAFETY: `FreeMibTable` releases a table from the IP helper API. The
        // pointer is non-null and is not used after this call.
        unsafe { FreeMibTable(table.cast::<c_void>()) };
        result
    }

    fn best_route(destination: IpAddr) -> Result<BestRouteProbe, RouteVerifyError> {
        // `GetBestRoute2` is interface scoped. Ask it for the tunnel interface
        // and it returns the tunnel route even when Windows would send the
        // packet through another adapter. Select the interface first with
        // `GetBestInterfaceEx`, then ask for the route on that interface.
        let destination_raw = sockaddr(destination);
        let mut best_interface_index: u32 = 0;
        // SAFETY: The destination points to an initialized `SOCKADDR_INET`.
        // The output pointer is valid for one `NET_IFINDEX`.
        let status = unsafe { GetBestInterfaceEx(&destination_raw, &mut best_interface_index) };
        if status != 0 {
            return Err(RouteVerifyError::Api {
                operation: "GetBestInterfaceEx",
                code: status,
            });
        }
        if best_interface_index == 0 || best_interface_index > super::MAX_INTERFACE_INDEX {
            return Err(RouteVerifyError::InvalidObservation(
                "GetBestInterfaceEx returned an invalid interface index",
            ));
        }

        // A zero LUID makes `GetBestRoute2` use the interface index. Microsoft
        // requires one of the two interface values to be set.
        let zero_luid: u64 = 0;
        let mut row: RawMibIpForwardRow2 = unsafe { std::mem::zeroed() };
        let mut best_source: RawSockaddrInet = unsafe { std::mem::zeroed() };
        // SAFETY: The destination and source pointers are valid. The row and
        // source output pointers are valid for one value each. A null source
        // address is allowed.
        let status = unsafe {
            GetBestRoute2(
                &zero_luid,
                best_interface_index,
                ptr::null(),
                &destination_raw,
                0,
                &mut row,
                &mut best_source,
            )
        };
        if status != 0 {
            return Err(RouteVerifyError::Api {
                operation: "GetBestRoute2",
                code: status,
            });
        }
        Ok(BestRouteProbe {
            destination,
            best_interface_index,
            route: observed_from_raw(&row)?,
        })
    }

    fn observed_from_raw(raw: &RawMibIpForwardRow2) -> Result<ObservedRoute, RouteVerifyError> {
        let prefix = prefix_from_raw(&raw.destination_prefix)?;
        let next_hop = address_from_sockaddr(&raw.next_hop)?;
        Ok(ObservedRoute {
            prefix,
            interface_index: raw.interface_index,
            interface_luid: raw.interface_luid,
            next_hop,
            metric: raw.metric,
            protocol: raw.protocol as u32,
            loopback: raw.loopback != 0,
        })
    }

    fn prefix_from_raw(raw: &RawIpAddressPrefix) -> Result<RoutePrefix, RouteVerifyError> {
        let length = raw.prefix_length;
        let address = match raw.prefix.family() {
            AF_INET => IpAddr::V4(Ipv4Addr::from(unsafe { raw.prefix.v4.address })),
            AF_INET6 => IpAddr::V6(Ipv6Addr::from(unsafe { raw.prefix.v6.address })),
            _ => {
                return Err(RouteVerifyError::InvalidObservation(
                    "a route row has an unsupported address family",
                ))
            }
        };
        RoutePrefix::new(address, length).ok_or(RouteVerifyError::InvalidObservation(
            "a route row has an invalid prefix",
        ))
    }

    fn address_from_sockaddr(address: &RawSockaddrInet) -> Result<IpAddr, RouteVerifyError> {
        match address.family() {
            AF_INET => Ok(IpAddr::V4(Ipv4Addr::from(unsafe { address.v4.address }))),
            AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(unsafe { address.v6.address }))),
            _ => Err(RouteVerifyError::InvalidObservation(
                "a route row has an unsupported next-hop family",
            )),
        }
    }

    fn sockaddr(address: IpAddr) -> RawSockaddrInet {
        match address {
            IpAddr::V4(address) => RawSockaddrInet {
                v4: RawSockaddrIn {
                    family: AF_INET,
                    port: 0,
                    address: address.octets(),
                    zero: [0; 8],
                },
            },
            IpAddr::V6(address) => RawSockaddrInet {
                v6: RawSockaddrIn6 {
                    family: AF_INET6,
                    port: 0,
                    flow_info: 0,
                    address: address.octets(),
                    scope_id: 0,
                },
            },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const INDEX: u32 = 7;
        const LUID: u64 = 0x0000_6000_0000_0007;

        fn v4_prefix(address: [u8; 4], length: u8) -> RawIpAddressPrefix {
            RawIpAddressPrefix {
                prefix: RawSockaddrInet {
                    v4: RawSockaddrIn {
                        family: AF_INET,
                        port: 0,
                        address,
                        zero: [0; 8],
                    },
                },
                prefix_length: length,
            }
        }

        fn v6_prefix(address: [u8; 16], length: u8) -> RawIpAddressPrefix {
            RawIpAddressPrefix {
                prefix: RawSockaddrInet {
                    v6: RawSockaddrIn6 {
                        family: AF_INET6,
                        port: 0,
                        flow_info: 0,
                        address,
                        scope_id: 0,
                    },
                },
                prefix_length: length,
            }
        }

        fn v4_any() -> RawSockaddrInet {
            sockaddr(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }

        fn row(prefix: RawIpAddressPrefix) -> RawMibIpForwardRow2 {
            RawMibIpForwardRow2 {
                interface_luid: LUID,
                interface_index: INDEX,
                destination_prefix: prefix,
                next_hop: v4_any(),
                site_prefix_length: 0,
                valid_lifetime: u32::MAX,
                preferred_lifetime: u32::MAX,
                metric: 0,
                protocol: 10006,
                loopback: 0,
                autoconfigure_address: 0,
                publish: 0,
                immortal: 0,
                age: 0,
                origin: 0,
            }
        }

        #[test]
        fn the_row_layout_matches_the_windows_headers() {
            assert_eq!(size_of::<RawMibIpForwardRow2>(), 104);
            assert_eq!(offset_of!(RawMibIpForwardRow2, interface_index), 8);
            assert_eq!(offset_of!(RawMibIpForwardRow2, destination_prefix), 12);
            assert_eq!(offset_of!(RawMibIpForwardRow2, next_hop), 44);
            assert_eq!(offset_of!(RawMibIpForwardRow2, metric), 84);
            assert_eq!(ROWS_OFFSET, 8);
        }

        #[test]
        fn a_raw_ipv4_row_converts_to_native_values() {
            let raw = row(v4_prefix([0, 0, 0, 0], 1));
            let route = observed_from_raw(&raw).unwrap();
            assert_eq!(
                route.prefix,
                RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1).unwrap()
            );
            assert_eq!(route.interface_index, INDEX);
            assert_eq!(route.interface_luid, LUID);
            assert_eq!(route.next_hop, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            assert_eq!(route.protocol, 10006);
            assert!(!route.loopback);
        }

        #[test]
        fn a_raw_ipv6_row_converts_to_native_values() {
            let mut address = [0u8; 16];
            address[0] = 0x20;
            address[1] = 0x00;
            let raw = row(v6_prefix(address, 3));
            let route = observed_from_raw(&raw).unwrap();
            assert_eq!(
                route.prefix,
                RoutePrefix::new(IpAddr::V6("2000::".parse::<Ipv6Addr>().unwrap()), 3).unwrap()
            );
        }

        #[test]
        fn a_raw_row_with_host_bits_is_rejected() {
            let raw = row(v4_prefix([0, 0, 0, 1], 1));
            assert_eq!(
                observed_from_raw(&raw).unwrap_err(),
                RouteVerifyError::InvalidObservation("a route row has an invalid prefix")
            );
        }

        #[test]
        fn a_raw_row_with_an_unknown_family_is_rejected() {
            let mut prefix = v4_prefix([0, 0, 0, 0], 1);
            prefix.prefix.family = 99;
            let raw = row(prefix);
            assert_eq!(
                observed_from_raw(&raw).unwrap_err(),
                RouteVerifyError::InvalidObservation(
                    "a route row has an unsupported address family"
                )
            );
        }

        #[test]
        fn a_sockaddr_keeps_the_family_and_the_address_bytes() {
            let v4 = sockaddr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
            assert_eq!(v4.family(), AF_INET);
            assert_eq!(unsafe { v4.v4.address }, [192, 0, 2, 1]);

            let v6 = sockaddr(IpAddr::V6("2001:db8::1".parse().unwrap()));
            assert_eq!(v6.family(), AF_INET6);
            assert_eq!(
                unsafe { v6.v6.address },
                "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: u32 = 7;
    const LUID: u64 = 0x0000_6000_0000_0007;
    const OTHER_INDEX: u32 = 12;
    const OTHER_LUID: u64 = 0x0000_6000_0000_000c;

    fn tunnel() -> TunnelIdentity {
        TunnelIdentity::new(INDEX, LUID).unwrap()
    }

    fn v4(address: [u8; 4], length: u8) -> RoutePrefix {
        RoutePrefix::new(IpAddr::V4(Ipv4Addr::from(address)), length).unwrap()
    }

    fn v6(address: &str, length: u8) -> RoutePrefix {
        RoutePrefix::new(IpAddr::V6(address.parse().unwrap()), length).unwrap()
    }

    fn route(prefix: RoutePrefix, ifindex: u32, luid: u64) -> ObservedRoute {
        ObservedRoute {
            prefix,
            interface_index: ifindex,
            interface_luid: luid,
            next_hop: unspecified(prefix),
            metric: 0,
            protocol: 10006,
            loopback: false,
        }
    }

    fn unspecified(prefix: RoutePrefix) -> IpAddr {
        match prefix.family() {
            AddressFamily::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            AddressFamily::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }

    fn policy(ipv6: Ipv6RoutePolicy) -> VerifyPolicy {
        VerifyPolicy::new(tunnel(), ipv6)
    }

    fn probe(
        destination: IpAddr,
        best_interface_index: u32,
        prefix: RoutePrefix,
        ifindex: u32,
        luid: u64,
    ) -> BestRouteProbe {
        BestRouteProbe {
            destination,
            best_interface_index,
            route: route(prefix, ifindex, luid),
        }
    }

    fn good_observation(policy: &VerifyPolicy) -> RouteObservation {
        RouteObservation {
            ipv4_routes: vec![
                route(IPV4_ROUTES[0], INDEX, LUID),
                route(IPV4_ROUTES[1], INDEX, LUID),
            ],
            ipv6_routes: vec![route(IPV6_TUNNEL_ROUTE, INDEX, LUID)],
            probes: policy
                .ipv4_probes
                .iter()
                .map(|destination| {
                    let destination = IpAddr::V4(*destination);
                    let prefix = IPV4_ROUTES
                        .iter()
                        .copied()
                        .find(|prefix| prefix.contains(destination))
                        .unwrap();
                    probe(destination, INDEX, prefix, INDEX, LUID)
                })
                .chain(policy.ipv6_probes.iter().map(|destination| {
                    probe(
                        IpAddr::V6(*destination),
                        INDEX,
                        IPV6_TUNNEL_ROUTE,
                        INDEX,
                        LUID,
                    )
                }))
                .collect(),
        }
    }

    #[test]
    fn a_complete_block_policy_is_proven() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let proof = verify(&good_observation(&policy), &policy).unwrap();
        assert_eq!(proof.first_half.prefix, IPV4_ROUTES[0]);
        assert_eq!(proof.second_half.prefix, IPV4_ROUTES[1]);
        assert_eq!(proof.ipv6.prefix, IPV6_TUNNEL_ROUTE);
        assert_eq!(proof.ipv6_policy, Ipv6RoutePolicy::Block);
        assert_eq!(
            proof.probes_checked,
            DEFAULT_IPV4_PROBES.len() + DEFAULT_IPV6_PROBES.len()
        );
    }

    #[test]
    fn a_complete_forward_policy_is_proven() {
        let policy = policy(Ipv6RoutePolicy::Forward);
        let proof = verify(&good_observation(&policy), &policy).unwrap();
        assert_eq!(proof.ipv6_policy, Ipv6RoutePolicy::Forward);
    }

    #[test]
    fn the_inherit_policy_is_never_verified() {
        let policy = policy(Ipv6RoutePolicy::Inherit);
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            RouteVerifyError::Ipv6InheritNotVerifiable
        );
        assert!(!Ipv6RoutePolicy::Inherit.is_managed());
    }

    #[cfg(windows)]
    #[test]
    fn live_inherit_policy_is_rejected_before_route_lookup() {
        let mut policy = policy(Ipv6RoutePolicy::Inherit);
        // An empty list fails validation if observation is attempted.
        policy.ipv4_probes.clear();
        assert_eq!(
            verify_live(&policy).unwrap_err(),
            RouteVerifyError::Ipv6InheritNotVerifiable
        );
    }

    #[test]
    fn the_identity_rejects_zero_and_large_values() {
        assert_eq!(
            TunnelIdentity::new(0, LUID).unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity(
                "the interface index must be a nonzero 24-bit number"
            )
        );
        assert_eq!(
            TunnelIdentity::new(MAX_INTERFACE_INDEX + 1, LUID).unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity(
                "the interface index must be a nonzero 24-bit number"
            )
        );
        assert_eq!(
            TunnelIdentity::new(INDEX, 0).unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity("the interface LUID must be nonzero")
        );
    }

    #[test]
    fn route_prefixes_reject_host_bits_and_large_lengths() {
        assert!(RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)), 1).is_none());
        assert!(RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 33).is_none());
        assert!(RoutePrefix::new(IpAddr::V6("2000::1".parse().unwrap()), 3).is_none());
        assert!(RoutePrefix::new(IpAddr::V6("2000::".parse().unwrap()), 129).is_none());
        assert!(RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).is_some());
        assert!(RoutePrefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).is_some());
    }

    #[test]
    fn route_prefixes_contain_the_expected_destinations() {
        assert!(IPV4_ROUTES[0].contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!IPV4_ROUTES[0].contains(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 1))));
        assert!(IPV4_ROUTES[1].contains(IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222))));
        assert!(IPV6_TUNNEL_ROUTE.contains(IpAddr::V6("2606:4700:4700::1111".parse().unwrap())));
        assert!(!IPV6_TUNNEL_ROUTE.contains(IpAddr::V6("64:ff9b::1".parse().unwrap())));
        assert!(!IPV4_ROUTES[0].contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn a_missing_half_route_fails() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv4_routes.remove(0);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MissingRoute {
                prefix: IPV4_ROUTES[0]
            }
        );
        let mut observation = good_observation(&policy);
        observation.ipv4_routes.remove(1);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MissingRoute {
                prefix: IPV4_ROUTES[1]
            }
        );
    }

    #[test]
    fn a_route_on_another_interface_is_foreign() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv4_routes[0] = route(IPV4_ROUTES[0], OTHER_INDEX, OTHER_LUID);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::ForeignRoute {
                prefix: IPV4_ROUTES[0],
                interface_index: OTHER_INDEX
            }
        );
    }

    #[test]
    fn a_reused_interface_index_is_not_ownership() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv4_routes[0].interface_luid = OTHER_LUID;
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::IndexReused {
                prefix: IPV4_ROUTES[0],
                interface_index: INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_second_tunnel_row_is_ambiguous() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let mut second = route(IPV4_ROUTES[0], INDEX, LUID);
        second.metric = 1;
        observation.ipv4_routes.push(second);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::DuplicateTunnelRoute {
                prefix: IPV4_ROUTES[0],
                count: 2
            }
        );
    }

    #[test]
    fn a_competing_exact_route_on_another_interface_is_ambiguous() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation
            .ipv4_routes
            .push(route(IPV4_ROUTES[0], OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::CompetingRoute {
                prefix: IPV4_ROUTES[0],
                interface_index: OTHER_INDEX
            }
        );
    }

    #[test]
    fn a_competing_exact_route_with_a_higher_metric_is_still_ambiguous() {
        // This check does not read interface metrics. A higher route metric on
        // the other interface does not prove that the tunnel wins, because the
        // total metric also includes the interface metric.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let mut competing = route(IPV4_ROUTES[0], OTHER_INDEX, OTHER_LUID);
        competing.metric = 9999;
        observation.ipv4_routes.push(competing);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::CompetingRoute {
                prefix: IPV4_ROUTES[0],
                interface_index: OTHER_INDEX
            }
        );
    }

    #[test]
    fn a_default_route_on_another_interface_is_expected() {
        // A /0 route is less specific than /1. It does not compete with the
        // managed halves and must not fail the check.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation
            .ipv4_routes
            .push(route(v4([0, 0, 0, 0], 0), OTHER_INDEX, OTHER_LUID));
        assert!(verify(&observation, &policy).is_ok());
    }

    #[test]
    fn a_gateway_next_hop_is_not_the_installed_route() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv4_routes[0].next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::UnexpectedNextHop {
                prefix: IPV4_ROUTES[0],
                next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
            }
        );
    }

    #[test]
    fn a_loopback_route_is_rejected() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv4_routes[0].loopback = true;
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::LoopbackRoute {
                prefix: IPV4_ROUTES[0]
            }
        );
    }

    #[test]
    fn a_missing_probe_is_inconclusive() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let missing = IpAddr::V4(policy.ipv4_probes[0]);
        observation
            .probes
            .retain(|probe| probe.destination != missing);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MissingBestRoute {
                destination: missing
            }
        );
    }

    #[test]
    fn a_best_interface_on_another_adapter_is_a_bypass() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.probes[0].best_interface_index = OTHER_INDEX;
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::BestInterfaceMismatch {
                destination: observation.probes[0].destination,
                expected: INDEX,
                actual: OTHER_INDEX
            }
        );
    }

    #[test]
    fn a_more_specific_best_route_is_a_bypass() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let destination = observation.probes[0].destination;
        let specific = v4([1, 1, 1, 1], 32);
        observation.probes[0].route = route(specific, OTHER_INDEX, OTHER_LUID);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::BestRouteMismatch {
                destination,
                expected: IPV4_ROUTES[0],
                actual: specific,
                interface_index: OTHER_INDEX
            }
        );
    }

    #[test]
    fn a_best_route_with_the_right_prefix_but_a_foreign_identity_fails() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let destination = observation.probes[0].destination;
        observation.probes[0].route = route(IPV4_ROUTES[0], OTHER_INDEX, OTHER_LUID);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::BestRouteIdentityMismatch {
                destination,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_best_route_with_a_reused_luid_fails() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let destination = observation.probes[0].destination;
        observation.probes[0].route.interface_luid = OTHER_LUID;
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::BestRouteIdentityMismatch {
                destination,
                interface_index: INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_best_route_with_a_gateway_is_rejected() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.probes[0].route.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::UnexpectedNextHop {
                prefix: IPV4_ROUTES[0],
                next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
            }
        );
    }

    #[test]
    fn the_ipv6_block_route_must_be_on_the_tunnel() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv6_routes[0] = route(IPV6_TUNNEL_ROUTE, OTHER_INDEX, OTHER_LUID);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::ForeignRoute {
                prefix: IPV6_TUNNEL_ROUTE,
                interface_index: OTHER_INDEX
            }
        );
    }

    #[test]
    fn a_missing_ipv6_route_fails() {
        let policy = policy(Ipv6RoutePolicy::Forward);
        let mut observation = good_observation(&policy);
        observation.ipv6_routes.clear();
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MissingRoute {
                prefix: IPV6_TUNNEL_ROUTE
            }
        );
    }

    #[test]
    fn a_more_specific_ipv6_best_route_is_a_bypass() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let destination = IpAddr::V6("2606:4700:4700::1111".parse().unwrap());
        let specific = v6("2606:4700::", 32);
        for probe in &mut observation.probes {
            if probe.destination == destination {
                probe.best_interface_index = OTHER_INDEX;
                probe.route = route(specific, OTHER_INDEX, OTHER_LUID);
            }
        }
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::BestInterfaceMismatch {
                destination,
                expected: INDEX,
                actual: OTHER_INDEX
            }
        );
    }

    #[test]
    fn a_more_specific_route_on_the_tunnel_is_not_the_managed_prefix() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let destination = observation.probes[0].destination;
        let specific = v4([1, 1, 1, 1], 32);
        observation.probes[0].route = route(specific, INDEX, LUID);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::BestRouteMismatch {
                destination,
                expected: IPV4_ROUTES[0],
                actual: specific,
                interface_index: INDEX
            }
        );
    }

    #[test]
    fn a_wrong_family_row_is_an_invalid_observation() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation
            .ipv6_routes
            .push(route(v4([0, 0, 0, 0], 1), INDEX, LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::InvalidObservation(
                "a route row has an invalid prefix or the wrong address family"
            )
        );
    }

    #[test]
    fn a_host_bit_row_is_an_invalid_observation() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv4_routes[0].prefix = RoutePrefix {
            address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            length: 1,
        };
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::InvalidObservation(
                "a route row has an invalid prefix or the wrong address family"
            )
        );
    }

    #[test]
    fn a_duplicate_probe_is_an_invalid_observation() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.probes.push(observation.probes[0]);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::InvalidObservation(
                "the observation has a duplicate probe destination"
            )
        );
    }

    #[test]
    fn a_probe_outside_its_route_is_an_invalid_observation() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.probes[0].route.prefix = IPV4_ROUTES[1];
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::InvalidObservation(
                "a best-route prefix does not contain its destination"
            )
        );
    }

    #[test]
    fn an_ipv6_probe_outside_the_managed_prefix_fails() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let outside = IpAddr::V6("64:ff9b::1".parse().unwrap());
        observation.probes.push(BestRouteProbe {
            destination: outside,
            best_interface_index: INDEX,
            route: route(v6("64:ff9b::", 96), INDEX, LUID),
        });
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::InvalidObservation("an IPv6 probe is outside 2000::/3")
        );
    }

    #[test]
    fn a_policy_without_a_probe_in_each_half_is_invalid() {
        let mut policy = policy(Ipv6RoutePolicy::Block);
        policy
            .ipv4_probes
            .retain(|destination| !IPV4_ROUTES[1].contains(IpAddr::V4(*destination)));
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "the IPv4 probe list needs one destination in each half"
            )
        );
    }

    #[test]
    fn a_policy_without_an_ipv6_probe_is_invalid() {
        let mut policy = policy(Ipv6RoutePolicy::Block);
        policy.ipv6_probes.clear();
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "at least one IPv6 probe is required for a managed IPv6 policy"
            )
        );
    }

    #[test]
    fn a_bad_probe_destination_is_invalid() {
        let mut policy = policy(Ipv6RoutePolicy::Block);
        policy.ipv4_probes.push(Ipv4Addr::BROADCAST);
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy("an IPv4 probe must be a unicast host")
        );
    }

    #[test]
    fn an_ipv6_probe_outside_2000_slash_3_is_invalid() {
        let mut policy = policy(Ipv6RoutePolicy::Block);
        policy.ipv6_probes.push("64:ff9b::1".parse().unwrap());
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy("every IPv6 probe must be inside 2000::/3")
        );
    }

    #[test]
    fn api_errors_keep_the_operation_and_code() {
        let error = RouteVerifyError::Api {
            operation: "GetBestRoute2",
            code: 1168,
        };
        assert_eq!(
            error.to_string(),
            "GetBestRoute2 failed with Windows error 1168"
        );
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn the_display_text_names_the_prefix() {
        let error = RouteVerifyError::MissingRoute {
            prefix: IPV4_ROUTES[0],
        };
        assert_eq!(error.to_string(), "the route table has no 0.0.0.0/1 route");
    }

    #[test]
    fn a_more_specific_route_for_an_unprobed_destination_is_outside_this_proof() {
        // This test records a limit, not a guarantee. The check proves only
        // the exact managed prefixes and the probe destinations. A
        // more-specific route for a destination that is not probed can still
        // bypass the tunnel. The result must not be described as fail-closed.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation
            .ipv4_routes
            .push(route(v4([203, 0, 113, 1], 32), OTHER_INDEX, OTHER_LUID));
        assert!(verify(&observation, &policy).is_ok());
    }
}
