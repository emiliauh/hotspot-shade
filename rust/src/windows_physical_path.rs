//! Read-only Windows physical adapter and gateway evidence foundation.
//!
//! The source device proxy needs evidence that the target device has one
//! physical hotspot adapter, that Windows selects that adapter for the source
//! device destination, and that the destination is the current default IPv4
//! gateway. This module collects that evidence and proves it with pure checks.
//! It changes no route, opens no TUN device, creates no adapter, opens no
//! socket, and sends no packet.
//!
//! The Windows token gate, `windows_route_verify::require_token_destination_proof`,
//! runs this evidence through `observe_token_destination` at each source
//! device token use (owner decision, 2026-11-06). The gate adds probes scoped
//! to the pinned interface and, during a run, accepts only the run's own
//! tunnel `/1` routes and the adapter that the start proved. The evidence is
//! not authentication of the source device.
//!
//! # What the evidence proves
//!
//! `verify` accepts a `PhysicalPathObservation` only when all of these
//! facts are present in the same observation:
//!
//! 1. Two default route probes, one in each IPv4 half, select the genuine
//!    `0.0.0.0/0` route. Both probes agree on the gateway, the interface index,
//!    and the interface LUID. A split default route such as `0.0.0.0/1` fails.
//! 2. The gateway is a private or shared IPv4 unicast address and is not the
//!    adapter address. For prefixes of `/30` or broader, it is also not the
//!    subnet network or broadcast address. A `/31` has two host addresses.
//! 3. The source device destination equals that gateway. An on-link address
//!    elsewhere in the hotspot subnet is refused, because this module has no
//!    way to prove that such an address is a source device.
//! 4. The selected adapter reports an Ethernet or IEEE 802.11 interface type,
//!    the hardware interface flag, an up operational state, an up
//!    administrative state, a media connect state of connected, broadcast
//!    access, no tunnel type, no filter interface flag, and a nonzero physical
//!    address of a plausible length. The module does not read `MediaType` or
//!    `PhysicalMediumType`; see the limitations below.
//! 5. The adapter reports exactly one usable IPv4 address. Usable means the
//!    DAD state is `NlDadStatePreferred`, the address is not skip-as-source, and
//!    it is a reachable unicast address under the
//!    `platform_windows::usable_ipv4` policy. The reader also refuses zero or
//!    inconsistent lifetimes; see the limitations below. That policy
//!    rejects the `0.0.0.0/8` range, loopback, the limited broadcast address,
//!    multicast, and the APIPA range `169.254.0.0/16`, so a leftover APIPA
//!    address does not count next to a DHCP lease. The observation carries the
//!    real count that the reader measured and `verify` requires it to be one.
//!    The address is private or shared, and its on-link prefix is no broader
//!    than IPv4 `/16`. The gateway is inside that prefix. An additional usable
//!    address, including a static address or a second DHCP lease, makes the
//!    observation unusable.
//! 6. The route to the destination leaves through the same adapter, is an
//!    on-link route, is no broader than the adapter prefix, is not the default
//!    route, is not a loopback route, and is not a local route.
//! 7. The adapter identity and the default gateway agree before and after the
//!    destination route read.
//!
//! A successful proof is evidence for the exact values that the caller
//! supplied and for the moments of the reads. It is not a lock and it does not
//! make the tunnel fail-closed.
//!
//! # What the evidence does not prove
//!
//! - It does not prove that the adapter is the hotspot link. A driver can
//!   report a virtual adapter as hardware Ethernet or Wi-Fi.
//! - It does not read or check `MediaType` or `PhysicalMediumType`. The
//!   accepted interface type, hardware flag, media connect state, access type,
//!   and physical address are driver claims. They do not prove a physical
//!   medium.
//! - It does not compare the gateway with local addresses on other adapters. It
//!   rejects the selected adapter address and, for `/30` or broader prefixes,
//!   the subnet network and broadcast addresses.
//! - It refuses an otherwise usable address whose reported valid or preferred
//!   lifetime is zero, or whose preferred lifetime exceeds its valid lifetime.
//!   Those fields and DAD state are point-in-time reports; they do not prove
//!   that an address remains usable after the read.
//! - It does not prove who created an adapter or that a LUID, index, or GUID
//!   cannot be reused. Windows can remove an adapter and assign its values to a
//!   new adapter later.
//! - It does not read the gateway MAC, SSID, or BSSID. Those values are
//!   spoofable guards, not identity, and this module does not use them.
//! - It does not authenticate the source device. Any device at the gateway
//!   address can accept the v1 token, and that token crosses the hotspot link
//!   in cleartext. A source-authenticated protocol or an explicit v1
//!   threat-model decision is still needed.
//! - It does not prevent a route, adapter, VPN, filter driver, or local DNS
//!   answer from changing after the observation. A more-specific route can
//!   bypass a tunnel that uses this proof.
//! - It does not compare interface metrics or prove that no competing default
//!   route exists on another adapter. It proves the route that Windows selects
//!   for the fixed probes at the time of the read.
//! - It does not enable or verify IPv6. The source device destination in this
//!   mode is numeric IPv4 only.
//!
//! # Unproven races
//!
//! Every Windows read below is a separate call. The module brackets the
//! destination route read with a default gateway read and a physical adapter
//! read on each side, then compares the results. That proves agreement at
//! those moments, not continuous ownership. These races remain:
//!
//! - `GetBestInterfaceEx` and `GetBestRoute2` are separate calls. The route can
//!   change between them.
//! - `GetIfEntry2`, `read_live_identity`, and `GetUnicastIpAddressTable` are
//!   separate calls. The adapter and its addresses can change between them.
//!   The adapter reader repeats the identity read after the address table, so a
//!   LUID that names another adapter at that moment fails closed. That recheck
//!   is still a separate call and does not prove that the address rows belong
//!   to the adapter at the instant they are read.
//! - The two default route probes are separate calls. Both can succeed and a
//!   later probe can still select a different route.
//! - Windows can change the route table immediately after the final read. There
//!   is no atomic snapshot that includes the interface GUID, the adapter
//!   flags, the IPv4 address, and the selected route.
//! - A filter driver or a virtual adapter can answer the interface flags in a
//!   way that this module accepts. The hardware flag is a driver claim, not a
//!   measurement.
//! - The read order is fixed and tested, but the order does not make the reads
//!   atomic. A change between two reads of the same bracket is still possible.
//!
//! # Layers
//!
//! The private `prove` check is pure. It changes nothing and runs on every
//! platform. A test-only `verify` wrapper exposes it to fixed-data tests.
//! `observe` is Windows only. It calls `GetBestInterfaceEx`, `GetBestRoute2`,
//! `GetIfEntry2`, and `GetUnicastIpAddressTable`, repeats the identity read
//! after the address table, then calls `prove`. The live reader runs through a
//! private read-order seam so host tests can prove the bracket order without a
//! Windows API call.
//!
//! # Minting boundary
//!
//! `prove` turns a `PhysicalPathObservation` into a [`PhysicalPathProof`]. It
//! cannot tell a live observation from a value built by hand. This module keeps
//! `prove` private, keeps the observation types crate private, and keeps the
//! proof fields private, so `observe` is the only production proof producer.
//! The test-only `verify` wrapper can still mint a proof from invented values,
//! and the path-included evidence test loads this module into its own test
//! crate, so tests need that entry point. That is a production boundary, not
//! proof of provenance.
//!
//! The proof is point-in-time. The token gate calls `observe_token_destination`
//! itself at each token use and never accepts a proof value that another
//! caller passes in, because that value can come from a test. Do not describe
//! this module as making the tunnel fail-closed.
//!
//! # Microsoft references
//!
//! - `GetBestInterfaceEx`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getbestinterfaceex>
//! - `GetBestRoute2`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getbestroute2>
//! - `GetIfEntry2`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getifentry2>
//! - `GetUnicastIpAddressTable`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getunicastipaddresstable>
//! - `MIB_IF_ROW2`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_if_row2>
//! - `MIB_UNICASTIPADDRESS_ROW`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row>
//! - `MIB_IPFORWARD_ROW2`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2>
//! - `IF_TYPE`:
//!   <https://learn.microsoft.com/windows/win32/api/ifdef/ne-ifdef-if_type>
//! - `FreeMibTable`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-freemibtable>
//!
//! # Integration points
//!
//! 1. `rust/src/lib.rs` registers the module for Windows and for host tests.
//!    It has no dependency on service startup, route mutation, or the GUI.
//! 2. The token gate parses the source device address as numeric IPv4 and
//!    calls `observe_token_destination` before every token use. A host name
//!    or IPv6 destination is refused.
//! 3. The service records the start-time adapter with the tunnel identity.
//!    The CLI and the GUI rerun the gate for that binding during a run and
//!    stop the run on a refusal.
//! 4. Pass [`PhysicalPathProof::adapter`] and
//!    [`PhysicalPathProof::proven_local_subnet`] to
//!    `windows_route_verify::VerifyPolicy::with_local_subnet`. The route proof
//!    then expects the on-link hotspot route on that retained adapter. The
//!    caller still has to supply the tunnel adapter identity and run
//!    `verify_live_retained`.
//! 5. Do not put the gateway, the local address, the LUID, the GUID, or this
//!    proof in browser status, logs, diagnostics, or failure text unless a
//!    reviewed status field needs it. The proof is for a start gate.
//!
//! # Windows host status
//!
//! The raw row layouts are asserted for `x86_64-pc-windows-msvc` and
//! `i686-pc-windows-msvc`. `MIB_UNICASTIPADDRESS_ROW` is 80 bytes on both
//! targets: the `SCOPE_ID` union is one 4-byte field at offset 68 and
//! `CreationTimeStamp` starts at offset 72. `MIB_UNICASTIPADDRESS_TABLE` is 88
//! bytes and its first row starts at offset 8. The field order was checked with
//! compile-time layout assertions against the `windows-sys` 0.61.2 bindings for
//! both targets and compared with the `winapi` 0.3.9 declarations. The Windows
//! SDK C header was not present on the non-Windows host used for the check, so
//! this is a metadata cross-check, not a header compile. The API behavior on a
//! live Windows host is not measured here. In particular, a live host must
//! confirm that a physical Wi-Fi or Ethernet adapter reports the hardware flag,
//! that a normal hotspot gateway produces an on-link destination route with an
//! unspecified next hop, that `GetUnicastIpAddressTable` reports exactly one
//! preferred address that is not skip-as-source and is not APIPA, that the
//! identity read after the table still names the same adapter, and that the two
//! default probes select the same row. This module creates no route, TUN device,
//! or adapter, and it handles no token.

use crate::windows_route_verify::{
    BestRouteProbe, LocalSubnetProvenance, ProvenLocalSubnet, RetainedAdapterIdentity, RoutePrefix,
    RouteVerifyError,
};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// The two destinations that the default route probes use.
///
/// One is in `0.0.0.0/1` and one is in `128.0.0.0/1`. A split default route for
/// either half cannot make both probes agree. The probes send no packet.
pub const GATEWAY_PROBES: [Ipv4Addr; 2] =
    [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(208, 67, 222, 222)];

/// The broadest on-link prefix that one hotspot link may have.
///
/// The prefix length must be at least 16. A broader prefix such as `/8` is not
/// evidence for one link and is refused. This is a policy bound, not a
/// measurement.
pub const MIN_LOCAL_IPV4_PREFIX_LENGTH: u8 = 16;

/// The smallest physical address length that the evidence accepts.
pub const MIN_PHYSICAL_ADDRESS_LENGTH: u32 = 6;

/// The largest physical address length that the evidence accepts.
pub const MAX_PHYSICAL_ADDRESS_LENGTH: u32 = 32;

const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
const IF_TYPE_IEEE80211: u32 = 71;
const IF_OPER_STATUS_UP: u32 = 1;
const NET_IF_ADMIN_STATUS_UP: u32 = 1;
const MEDIA_CONNECT_STATE_CONNECTED: u32 = 1;
const NET_IF_ACCESS_BROADCAST: u32 = 2;
const TUNNEL_TYPE_NONE: u32 = 0;
/// `MIB_IPPROTO_LOCAL`. Windows gives this protocol to every route it makes from
/// an interface address, including the on-link subnet route, so the protocol
/// does not say that a destination is a local address.
#[cfg(test)]
const ROUTE_PROTOCOL_LOCAL: u32 = 2;
const MAX_INTERFACE_INDEX: u32 = 0x00ff_ffff;

const DEFAULT_ROUTE: RoutePrefix = RoutePrefix {
    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    length: 0,
};

/// The physical interface type that the evidence accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalAdapterKind {
    /// An Ethernet interface type (`IF_TYPE_ETHERNET_CSMACD`).
    ///
    /// A USB tethering adapter can report this type. The type is a driver
    /// claim, not proof of a physical medium.
    Ethernet,
    /// An IEEE 802.11 interface type (`IF_TYPE_IEEE80211`).
    ///
    /// The type is a driver claim, not proof of a physical medium.
    Wifi,
}

impl PhysicalAdapterKind {
    /// Map the Windows `IF_TYPE` value to an accepted physical kind.
    ///
    /// Loopback, tunnel, Bluetooth, mobile broadband, and every other type
    /// return `None`. The caller must not substitute a broader type.
    pub fn from_interface_type(interface_type: u32) -> Option<Self> {
        match interface_type {
            IF_TYPE_ETHERNET_CSMACD => Some(Self::Ethernet),
            IF_TYPE_IEEE80211 => Some(Self::Wifi),
            _ => None,
        }
    }
}

/// One read of the selected physical adapter.
///
/// The fields are the values that the Windows APIs returned. `verify` checks
/// every field. A caller can build this value from fixed test data, but a live
/// caller must read it from `GetIfEntry2`, `ConvertInterfaceLuidToGuid`,
/// `ConvertInterfaceLuidToIndex`, and `GetUnicastIpAddressTable`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PhysicalAdapterObservation {
    /// The retained identity of the adapter.
    pub identity: RetainedAdapterIdentity,
    /// The Windows `IF_TYPE` value.
    ///
    /// The policy accepts Ethernet and IEEE 802.11 only. It does not read
    /// `MIB_IF_ROW2::MediaType` or `PhysicalMediumType`.
    pub interface_type: u32,
    /// The Windows `IF_OPER_STATUS` value.
    pub oper_status: u32,
    /// The Windows `NET_IF_ADMIN_STATUS` value.
    pub admin_status: u32,
    /// The Windows `NET_IF_MEDIA_CONNECT_STATE` value.
    ///
    /// This is the link state, not the medium type.
    pub media_connect_state: u32,
    /// The Windows `NET_IF_ACCESS_TYPE` value.
    pub access_type: u32,
    /// The Windows `TUNNEL_TYPE` value.
    pub tunnel_type: u32,
    /// The `HardwareInterface` flag from `MIB_IF_ROW2`.
    pub hardware_interface: bool,
    /// The `FilterInterface` flag from `MIB_IF_ROW2`.
    pub filter_interface: bool,
    /// The `PhysicalAddressLength` value from `MIB_IF_ROW2`.
    pub physical_address_length: u32,
    /// True when at least one byte of the physical address is nonzero.
    pub physical_address_nonzero: bool,
    /// The one usable IPv4 address that the adapter reported.
    pub ipv4_address: Ipv4Addr,
    /// The on-link prefix length for that address.
    pub on_link_prefix_length: u8,
    /// The number of usable IPv4 addresses that the adapter reported.
    ///
    /// Usable means the DAD state is `NlDadStatePreferred`, the address is not
    /// skip-as-source, and it passes the `platform_windows::usable_ipv4`
    /// reachability policy. The reader refuses zero or inconsistent lifetimes
    /// for otherwise usable rows. It counts the real value; it never
    /// substitutes a constant. `verify` requires exactly one.
    pub usable_ipv4_address_count: u32,
}

impl fmt::Debug for PhysicalAdapterObservation {
    /// Print the policy fields without the adapter identity or address.
    ///
    /// The LUID, GUID, interface index, and IPv4 address are never written to a
    /// log, diagnostic, or error text. The interface type and state values are
    /// driver claims and are safe to print.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhysicalAdapterObservation")
            .field("identity", &"<redacted>")
            .field("interface_type", &self.interface_type)
            .field("oper_status", &self.oper_status)
            .field("admin_status", &self.admin_status)
            .field("media_connect_state", &self.media_connect_state)
            .field("access_type", &self.access_type)
            .field("tunnel_type", &self.tunnel_type)
            .field("hardware_interface", &self.hardware_interface)
            .field("filter_interface", &self.filter_interface)
            .field("physical_address_length", &self.physical_address_length)
            .field("physical_address_nonzero", &self.physical_address_nonzero)
            .field("ipv4_address", &"<redacted>")
            .field("on_link_prefix_length", &self.on_link_prefix_length)
            .field("usable_ipv4_address_count", &self.usable_ipv4_address_count)
            .finish()
    }
}

impl PhysicalAdapterObservation {
    /// Return the accepted physical kind, or `None`.
    pub fn kind(&self) -> Option<PhysicalAdapterKind> {
        PhysicalAdapterKind::from_interface_type(self.interface_type)
    }

    /// Return the on-link prefix for the address.
    ///
    /// The address must have a valid prefix length. Host bits in the address
    /// are not an error; the network address is derived from the prefix.
    pub fn ipv4_prefix(&self) -> Result<RoutePrefix, PhysicalPathError> {
        if self.on_link_prefix_length > 32 {
            return Err(PhysicalPathError::AdapterAddressUnusable(
                "the on-link prefix length is above 32",
            ));
        }
        let network = network_v4(self.ipv4_address, self.on_link_prefix_length);
        RoutePrefix::new(IpAddr::V4(network), self.on_link_prefix_length).ok_or(
            PhysicalPathError::AdapterAddressUnusable("the on-link prefix is invalid"),
        )
    }
}

/// One pair of default route probes.
///
/// A live caller fills `probes` with [`GATEWAY_PROBES`] in order. `verify`
/// checks both rows and their agreement. The type keeps both probes together
/// so a caller cannot hide a split default route.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GatewayObservation {
    /// The two probes, in [`GATEWAY_PROBES`] order.
    pub probes: [BestRouteProbe; 2],
}

impl fmt::Debug for GatewayObservation {
    /// Print only the probe count. The probes hold the gateway and interface.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayObservation")
            .field("probe_count", &self.probes.len())
            .field("probes", &"<redacted>")
            .finish()
    }
}

/// The completed evidence that `verify` checks.
///
/// The two adapter reads and the two gateway reads bracket the destination
/// route read. They are separate Windows calls. See the module documentation
/// for the races that remain.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PhysicalPathObservation {
    /// The physical adapter read before the destination route.
    pub adapter_before: PhysicalAdapterObservation,
    /// The physical adapter read after the destination route.
    pub adapter_after: PhysicalAdapterObservation,
    /// The default gateway probes before the destination route.
    pub gateway_before: GatewayObservation,
    /// The default gateway probes after the destination route.
    pub gateway_after: GatewayObservation,
    /// The best route to the source device destination.
    pub destination_route: BestRouteProbe,
    /// The numeric IPv4 source device destination.
    pub destination_address: Ipv4Addr,
}

impl fmt::Debug for PhysicalPathObservation {
    /// Print the observation shape without any gateway, address, or identity.
    ///
    /// The nested adapter and gateway values redact their own sensitive fields.
    /// The destination route is a `windows_route_verify` value with public
    /// fields, so it is redacted here rather than through its own Debug.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhysicalPathObservation")
            .field("adapter_before", &self.adapter_before)
            .field("adapter_after", &self.adapter_after)
            .field("gateway_before", &self.gateway_before)
            .field("gateway_after", &self.gateway_after)
            .field("destination_route", &"<redacted>")
            .field("destination_address", &"<redacted>")
            .finish()
    }
}

/// A physical path that the checks proved.
///
/// The fields are private. Build this value with `verify` or `observe`.
/// The proof records the retained adapter identity, the physical kind, the
/// gateway, and the local IPv4 prefix that a route check may use as a proven
/// local subnet.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PhysicalPathProof {
    adapter: RetainedAdapterIdentity,
    kind: PhysicalAdapterKind,
    gateway: Ipv4Addr,
    local_address: Ipv4Addr,
    local_prefix: RoutePrefix,
}

impl fmt::Debug for PhysicalPathProof {
    /// Print the proof shape without the gateway, address, or identity.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhysicalPathProof")
            .field("adapter", &"<redacted>")
            .field("kind", &self.kind)
            .field("gateway", &"<redacted>")
            .field("local_address", &"<redacted>")
            .field("local_prefix_length", &self.local_prefix.length)
            .finish()
    }
}

impl PhysicalPathProof {
    /// Return the retained physical adapter identity.
    ///
    /// Its `Debug` output contains interface identifiers. Do not log it or
    /// include it in status or diagnostic output.
    pub fn adapter(self) -> RetainedAdapterIdentity {
        self.adapter
    }

    /// Return the accepted physical adapter kind.
    pub fn kind(self) -> PhysicalAdapterKind {
        self.kind
    }

    /// Return the default IPv4 gateway.
    pub fn gateway(self) -> Ipv4Addr {
        self.gateway
    }

    /// Return the adapter IPv4 address.
    pub fn local_address(self) -> Ipv4Addr {
        self.local_address
    }

    /// Return the adapter on-link IPv4 prefix.
    pub fn local_prefix(self) -> RoutePrefix {
        self.local_prefix
    }

    /// Build the local subnet proof for `windows_route_verify`.
    ///
    /// The provenance is [`LocalSubnetProvenance::LocalInterface`]. The prefix
    /// and identity were read from the physical adapter. The route verifier
    /// still rechecks the retained identity before and after its route reads.
    ///
    /// The route verifier rejects a prefix that contains a best-route probe or
    /// that is broader than its own local subnet bound. A hotspot prefix is
    /// normally `/24` or `/28`, so both checks pass.
    pub fn proven_local_subnet(self) -> Result<ProvenLocalSubnet, PhysicalPathError> {
        ProvenLocalSubnet::new(
            self.local_prefix,
            self.adapter,
            LocalSubnetProvenance::LocalInterface,
        )
        .map_err(PhysicalPathError::RouteVerify)
    }
}

/// A reason that the physical path evidence is not proven.
///
/// Every variant is a failure. Do not show a success state for any variant.
#[derive(Clone, PartialEq, Eq)]
pub enum PhysicalPathError {
    /// The destination is not a private or shared IPv4 unicast address.
    InvalidDestination(&'static str),
    /// The observation is internally inconsistent.
    InvalidObservation(&'static str),
    /// The default route is missing, ambiguous, or not usable.
    GatewayUnusable(&'static str),
    /// The destination is not the current default IPv4 gateway.
    DestinationMismatch,
    /// The adapter does not meet the physical adapter policy.
    AdapterNotPhysical(&'static str),
    /// The adapter identity changed during the observation.
    AdapterIdentityChanged,
    /// The adapter IPv4 address or prefix is not usable.
    AdapterAddressUnusable(&'static str),
    /// The gateway is not inside the adapter on-link prefix.
    GatewayNotOnAdapterSubnet,
    /// The route to the destination does not leave through the adapter.
    DestinationRouteUnusable(&'static str),
    /// A retained identity or local subnet check failed.
    RouteVerify(RouteVerifyError),
    /// A Windows API call failed.
    ///
    /// This variant exists only on Windows. The live observer is the only
    /// producer, and its message names the operation and code, never a
    /// gateway, address, LUID, or GUID.
    #[cfg(any(windows, test))]
    Api {
        /// The API name.
        operation: &'static str,
        /// The Windows error code.
        code: u32,
    },
}

impl fmt::Debug for PhysicalPathError {
    /// Print a redacted form of the error.
    ///
    /// `windows_route_verify::RouteVerifyError` carries prefixes, next hops,
    /// indexes, LUIDs, and GUIDs in its Debug output. This module must not pass
    /// those values to a log, so the wrapped value is replaced by a marker. The
    /// other variants hold only fixed policy text, an operation name, and a
    /// Windows error code.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDestination(message) => formatter
                .debug_tuple("InvalidDestination")
                .field(message)
                .finish(),
            Self::InvalidObservation(message) => formatter
                .debug_tuple("InvalidObservation")
                .field(message)
                .finish(),
            Self::GatewayUnusable(message) => formatter
                .debug_tuple("GatewayUnusable")
                .field(message)
                .finish(),
            Self::DestinationMismatch => formatter.write_str("DestinationMismatch"),
            Self::AdapterNotPhysical(message) => formatter
                .debug_tuple("AdapterNotPhysical")
                .field(message)
                .finish(),
            Self::AdapterIdentityChanged => formatter.write_str("AdapterIdentityChanged"),
            Self::AdapterAddressUnusable(message) => formatter
                .debug_tuple("AdapterAddressUnusable")
                .field(message)
                .finish(),
            Self::GatewayNotOnAdapterSubnet => formatter.write_str("GatewayNotOnAdapterSubnet"),
            Self::DestinationRouteUnusable(message) => formatter
                .debug_tuple("DestinationRouteUnusable")
                .field(message)
                .finish(),
            Self::RouteVerify(RouteVerifyError::Api {
                operation:
                    operation @ ("ConvertInterfaceLuidToGuid" | "ConvertInterfaceLuidToIndex"),
                code,
            }) => formatter
                .debug_struct("Api")
                .field("operation", operation)
                .field("code", code)
                .finish(),
            Self::RouteVerify(_) => formatter.write_str("RouteVerify(<redacted>)"),
            #[cfg(any(windows, test))]
            Self::Api {
                operation:
                    operation @ ("GetBestInterfaceEx"
                    | "GetBestRoute2"
                    | "GetIfEntry2"
                    | "GetUnicastIpAddressTable"),
                code,
            } => formatter
                .debug_struct("Api")
                .field("operation", operation)
                .field("code", code)
                .finish(),
            #[cfg(any(windows, test))]
            Self::Api { .. } => formatter.write_str("Api(<redacted>)"),
        }
    }
}

impl fmt::Display for PhysicalPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDestination(message) => {
                write!(formatter, "invalid source device destination: {message}")
            }
            Self::InvalidObservation(message) => {
                write!(formatter, "invalid physical path observation: {message}")
            }
            Self::GatewayUnusable(message) => {
                write!(
                    formatter,
                    "the default IPv4 gateway is not usable: {message}"
                )
            }
            Self::DestinationMismatch => write!(
                formatter,
                "the source device destination is not the current default IPv4 gateway"
            ),
            Self::AdapterNotPhysical(message) => {
                write!(
                    formatter,
                    "the adapter is not an accepted physical link: {message}"
                )
            }
            Self::AdapterIdentityChanged => write!(
                formatter,
                "the physical adapter identity changed during the observation"
            ),
            Self::AdapterAddressUnusable(message) => {
                write!(
                    formatter,
                    "the adapter IPv4 address is not usable: {message}"
                )
            }
            Self::GatewayNotOnAdapterSubnet => write!(
                formatter,
                "the default IPv4 gateway is not on the physical adapter prefix"
            ),
            Self::DestinationRouteUnusable(message) => {
                write!(
                    formatter,
                    "the route to the source device is not usable: {message}"
                )
            }
            Self::RouteVerify(RouteVerifyError::Api {
                operation:
                    operation @ ("ConvertInterfaceLuidToGuid" | "ConvertInterfaceLuidToIndex"),
                code,
            }) => write!(formatter, "{operation} failed with Windows error {code}"),
            Self::RouteVerify(_) => formatter.write_str("the physical route evidence was refused"),
            #[cfg(any(windows, test))]
            Self::Api {
                operation:
                    operation @ ("GetBestInterfaceEx"
                    | "GetBestRoute2"
                    | "GetIfEntry2"
                    | "GetUnicastIpAddressTable"),
                code,
            } => {
                write!(formatter, "{operation} failed with Windows error {code}")
            }
            #[cfg(any(windows, test))]
            Self::Api { .. } => formatter.write_str("the physical route evidence was refused"),
        }
    }
}

impl std::error::Error for PhysicalPathError {}

impl PhysicalPathError {
    /// A fixed-vocabulary reason for a presence failure in diagnostics.
    ///
    /// The reason is the variant name plus the fixed static message, and only
    /// the Windows error code for an `Api` or a wrapped route error. It never
    /// holds an address, prefix, next hop, index, LUID, or GUID, so a
    /// diagnostics or probe line built from it cannot leak the hotspot
    /// network. Do not put this reason in user-facing status text.
    pub fn presence_reason(&self) -> String {
        match self {
            Self::InvalidDestination(message) => format!("InvalidDestination: {message}"),
            Self::InvalidObservation(message) => format!("InvalidObservation: {message}"),
            Self::GatewayUnusable(message) => format!("GatewayUnusable: {message}"),
            Self::DestinationMismatch => "DestinationMismatch".to_string(),
            Self::AdapterNotPhysical(message) => format!("AdapterNotPhysical: {message}"),
            Self::AdapterIdentityChanged => "AdapterIdentityChanged".to_string(),
            Self::AdapterAddressUnusable(message) => format!("AdapterAddressUnusable: {message}"),
            Self::GatewayNotOnAdapterSubnet => "GatewayNotOnAdapterSubnet".to_string(),
            Self::DestinationRouteUnusable(message) => {
                format!("DestinationRouteUnusable: {message}")
            }
            Self::RouteVerify(inner) => format!("RouteVerify: {}", inner.presence_kind()),
            #[cfg(any(windows, test))]
            Self::Api { code, .. } => format!("Api: {code}"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct GatewaySelection {
    gateway: Ipv4Addr,
    interface_index: u32,
    interface_luid: u64,
}

/// The read operations that `observe` brackets.
///
/// The live implementation calls the Windows APIs. Host tests implement this
/// trait to record the order and to stop at a chosen failure. The trait is
/// private, so it is not part of the module surface.
#[cfg(any(windows, test))]
trait PhysicalPathReads {
    /// Read both default route probes.
    fn read_gateway(&mut self) -> Result<GatewayObservation, PhysicalPathError>;

    /// Read the selected physical adapter.
    fn read_adapter(
        &mut self,
        interface_luid: u64,
        expected_index: u32,
    ) -> Result<PhysicalAdapterObservation, PhysicalPathError>;

    /// Read the best route to the source device destination.
    fn read_destination_route(
        &mut self,
        destination: Ipv4Addr,
    ) -> Result<BestRouteProbe, PhysicalPathError>;
}

/// Run the read sequence and prove the result.
///
/// The order is fixed: default gateway, physical adapter, destination route,
/// default gateway, physical adapter. The destination route is bracketed by a
/// gateway read and an adapter read on each side. Each read is still a separate
/// call, so the result is evidence at those moments, not a lock.
///
/// The destination is checked before the first read. A destination that does
/// not equal the first gateway selection stops before the adapter or route
/// read. A gateway or adapter change after the route read stops with an error
/// before the final proof.
#[cfg(any(windows, test))]
fn observe_with_reads<R: PhysicalPathReads>(
    reads: &mut R,
    destination: Ipv4Addr,
) -> Result<PhysicalPathProof, PhysicalPathError> {
    validate_destination(destination)?;
    let gateway_before = reads.read_gateway()?;
    let selected = selected_gateway(&gateway_before)?;
    if selected.gateway != destination {
        return Err(PhysicalPathError::DestinationMismatch);
    }
    let adapter_before = reads.read_adapter(selected.interface_luid, selected.interface_index)?;
    let destination_route = reads.read_destination_route(destination)?;
    let gateway_after = reads.read_gateway()?;
    let selected_after = selected_gateway(&gateway_after)?;
    if selected_after != selected {
        return Err(PhysicalPathError::GatewayUnusable(
            "the gateway or its interface changed during the observation",
        ));
    }
    let adapter_after = reads.read_adapter(selected.interface_luid, selected.interface_index)?;
    prove(&PhysicalPathObservation {
        adapter_before,
        adapter_after,
        gateway_before,
        gateway_after,
        destination_route,
        destination_address: destination,
    })
}

/// The tunnel run that this process owns while a source device tunnel is live.
///
/// While the tunnel runs, Windows selects the tunnel's own `/1` routes for the
/// default probes, so the unscoped probes cannot name the physical gateway.
/// The token gate then accepts an unscoped probe only when it selects the
/// exact `/1` route of this retained tunnel adapter, and it reads the physical
/// gateway with probes scoped to the pinned interface. `outer` is the physical
/// adapter that the start proved. A later read must report the same index,
/// LUID, and GUID.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TokenRun {
    /// The index and LUID of the tunnel adapter that owns the `/1` routes.
    pub tunnel: crate::windows_route_verify::TunnelIdentity,
    /// The physical adapter that the start-time gate proved.
    pub outer: RetainedAdapterIdentity,
}

/// The reads that the token gate brackets.
///
/// `read_gateway` is the unscoped best-route read. `read_pinned_gateway` asks
/// `GetBestRoute2` for the same two probes on the pinned interface only, which
/// is the route lookup that an outer socket pinned with `IP_UNICAST_IF` uses.
#[cfg(any(windows, test))]
trait TokenPathReads: PhysicalPathReads {
    /// Read both default route probes on the pinned interface only.
    fn read_pinned_gateway(
        &mut self,
        interface_index: u32,
    ) -> Result<GatewayObservation, PhysicalPathError>;
}

/// Check the unscoped default probes for the token gate.
///
/// Each probe must select either the physical `0.0.0.0/0` route that the
/// pinned probes selected, with the same gateway, index, and LUID, or, during
/// an owned run only, the exact `/1` half route of the retained tunnel adapter
/// with the unspecified next hop. Any other row, such as a VPN `/0` on another
/// adapter, a split default `/1` that this process does not own, or a
/// more-specific route, fails closed.
#[cfg(any(windows, test))]
fn check_unscoped_probes(
    observation: &GatewayObservation,
    pinned: GatewaySelection,
    run: Option<&TokenRun>,
) -> Result<(), PhysicalPathError> {
    for (position, expected) in GATEWAY_PROBES.iter().enumerate() {
        let probe = &observation.probes[position];
        if probe.destination != IpAddr::V4(*expected) {
            return Err(PhysicalPathError::GatewayUnusable(
                "the default route probes are not the fixed two-half set",
            ));
        }
        if !valid_interface_index(probe.best_interface_index) {
            return Err(PhysicalPathError::InvalidObservation(
                "GetBestInterfaceEx returned an invalid interface index",
            ));
        }
        let route = &probe.route;
        if route.loopback {
            return Err(PhysicalPathError::GatewayUnusable(
                "the selected default route is a loopback route",
            ));
        }
        if route.prefix == DEFAULT_ROUTE {
            let physical = probe.best_interface_index == pinned.interface_index
                && route.interface_index == pinned.interface_index
                && route.interface_luid == pinned.interface_luid
                && route.next_hop == IpAddr::V4(pinned.gateway);
            if !physical {
                return Err(PhysicalPathError::GatewayUnusable(
                    "Windows selects a default route that is not the pinned physical gateway",
                ));
            }
            continue;
        }
        let owned = run.is_some_and(|run| {
            route.prefix == crate::windows_route_verify::IPV4_ROUTES[position]
                && probe.best_interface_index == run.tunnel.interface_index
                && route.interface_index == run.tunnel.interface_index
                && route.interface_luid == run.tunnel.interface_luid
                && route.next_hop == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        });
        if !owned {
            return Err(PhysicalPathError::GatewayUnusable(
                "a VPN, split default, or more-specific route takes the default path",
            ));
        }
    }
    Ok(())
}

/// Prove that one source device destination may receive the proxy token.
///
/// This is the pure core of the Windows token gate. The read order is fixed:
/// unscoped gateway, pinned gateway, physical adapter, destination route,
/// unscoped gateway, pinned gateway, physical adapter. The pure [`prove`]
/// check then runs on the pinned gateway reads, so every physical adapter,
/// gateway, address, and destination route rule of this module applies.
///
/// The destination must equal the IPv4 gateway of the genuine `0.0.0.0/0`
/// route on the pinned interface. The pinned interface must be the adapter
/// that the route row names: the same index and LUID, and the GUID that the
/// identity read reports for that LUID. Without a run, the unscoped probes
/// must select the same physical default route. During a run, they may also
/// select the run's own tunnel `/1` routes, and the adapter must equal the
/// adapter that the start proved. A VPN, a split default route, a second
/// default route, a changed adapter, or a failed read is an error.
///
/// The result is evidence at the moments of the reads. It does not
/// authenticate the source device, and it is not a lock.
#[cfg(any(windows, test))]
fn prove_token_destination<R: TokenPathReads>(
    reads: &mut R,
    destination: Ipv4Addr,
    pinned_index: u32,
    run: Option<&TokenRun>,
) -> Result<PhysicalPathProof, PhysicalPathError> {
    validate_destination(destination)?;
    if !valid_interface_index(pinned_index) {
        return Err(PhysicalPathError::InvalidObservation(
            "the outer socket pin is not a valid interface index",
        ));
    }
    if let Some(run) = run {
        if run.outer.interface_index() != pinned_index {
            return Err(PhysicalPathError::AdapterIdentityChanged);
        }
        if run.tunnel.interface_index == pinned_index
            || run.tunnel.interface_luid == run.outer.interface_luid()
        {
            return Err(PhysicalPathError::AdapterNotPhysical(
                "the pinned interface is the tunnel adapter",
            ));
        }
    }
    let unscoped_before = reads.read_gateway()?;
    let pinned_before = reads.read_pinned_gateway(pinned_index)?;
    let selection = selected_gateway(&pinned_before)?;
    if selection.interface_index != pinned_index {
        return Err(PhysicalPathError::GatewayUnusable(
            "the default route is not on the pinned interface",
        ));
    }
    check_unscoped_probes(&unscoped_before, selection, run)?;
    if selection.gateway != destination {
        return Err(PhysicalPathError::DestinationMismatch);
    }
    let adapter_before = reads.read_adapter(selection.interface_luid, pinned_index)?;
    if run.is_some_and(|run| run.outer != adapter_before.identity) {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    let destination_route = reads.read_destination_route(destination)?;
    let unscoped_after = reads.read_gateway()?;
    let pinned_after = reads.read_pinned_gateway(pinned_index)?;
    if selected_gateway(&pinned_after)? != selection {
        return Err(PhysicalPathError::GatewayUnusable(
            "the gateway or its interface changed during the observation",
        ));
    }
    check_unscoped_probes(&unscoped_after, selection, run)?;
    let adapter_after = reads.read_adapter(selection.interface_luid, pinned_index)?;
    let proof = prove(&PhysicalPathObservation {
        adapter_before,
        adapter_after,
        gateway_before: pinned_before,
        gateway_after: pinned_after,
        destination_route,
        destination_address: destination,
    })?;
    if proof.adapter.interface_index() != pinned_index
        || run.is_some_and(|run| run.outer != proof.adapter)
    {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    Ok(proof)
}

/// Prove the physical path from one complete observation.
///
/// This function is pure. It changes no route, opens no socket, and creates no
/// device. It returns a proof only for the exact evidence that the module
/// documents. A missing, ambiguous, or changed value is an error, never a
/// fallback.
///
/// The source device destination must equal the current default gateway. An
/// on-link address inside the same subnet is not accepted.
///
/// This function is private to the module. Production code reaches it only
/// through `observe`, which reads the values from Windows. The test-only
/// `verify` wrapper exposes it for fixed-data tests. See the minting boundary
/// in the module documentation.
fn prove(observation: &PhysicalPathObservation) -> Result<PhysicalPathProof, PhysicalPathError> {
    let gateway_before = selected_gateway(&observation.gateway_before)?;
    let gateway_after = selected_gateway(&observation.gateway_after)?;
    if gateway_before != gateway_after {
        return Err(PhysicalPathError::GatewayUnusable(
            "the gateway or its interface changed during the observation",
        ));
    }
    if !is_private_hotspot_ipv4(gateway_before.gateway) {
        return Err(PhysicalPathError::GatewayUnusable(
            "the gateway is not a private or shared address",
        ));
    }
    validate_destination(observation.destination_address)?;
    if observation.destination_address != gateway_before.gateway {
        return Err(PhysicalPathError::DestinationMismatch);
    }

    let kind = validate_adapter(&observation.adapter_before)?;
    let after_kind = validate_adapter(&observation.adapter_after)?;
    if kind != after_kind {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    if observation.adapter_before != observation.adapter_after {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    let adapter = &observation.adapter_before;
    if adapter.identity.interface_index() != gateway_before.interface_index
        || adapter.identity.interface_luid() != gateway_before.interface_luid
    {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }

    let local_prefix = adapter.ipv4_prefix()?;
    if !local_prefix.contains(IpAddr::V4(gateway_before.gateway)) {
        return Err(PhysicalPathError::GatewayNotOnAdapterSubnet);
    }
    validate_gateway_host_address(adapter, local_prefix, gateway_before.gateway)?;
    validate_destination_route(
        adapter,
        local_prefix,
        &observation.destination_route,
        observation.destination_address,
    )?;

    Ok(PhysicalPathProof {
        adapter: adapter.identity,
        kind,
        gateway: gateway_before.gateway,
        local_address: adapter.ipv4_address,
        local_prefix,
    })
}

/// Run the pure proof check on a caller-built observation.
///
/// This wrapper is compiled only for tests. Production code must call
/// `observe` so that every value comes from a live Windows read. The
/// path-included evidence test builds fixed observations, so it needs this
/// entry point. The wrapper does not weaken the production boundary because it
/// does not exist outside a test build.
#[cfg(test)]
pub(crate) fn verify(
    observation: &PhysicalPathObservation,
) -> Result<PhysicalPathProof, PhysicalPathError> {
    prove(observation)
}

fn selected_gateway(
    observation: &GatewayObservation,
) -> Result<GatewaySelection, PhysicalPathError> {
    let mut selected: Option<GatewaySelection> = None;
    for (position, expected) in GATEWAY_PROBES.iter().enumerate() {
        let probe = &observation.probes[position];
        if probe.destination != IpAddr::V4(*expected) {
            return Err(PhysicalPathError::GatewayUnusable(
                "the default route probes are not the fixed two-half set",
            ));
        }
        if !valid_interface_index(probe.best_interface_index) {
            return Err(PhysicalPathError::InvalidObservation(
                "GetBestInterfaceEx returned an invalid interface index",
            ));
        }
        let route = &probe.route;
        if route.prefix != DEFAULT_ROUTE {
            return Err(PhysicalPathError::GatewayUnusable(
                "the selected route is not the 0.0.0.0/0 default route",
            ));
        }
        if route.interface_index != probe.best_interface_index {
            return Err(PhysicalPathError::GatewayUnusable(
                "the selected default route is not on the selected interface",
            ));
        }
        if route.interface_luid == 0 {
            return Err(PhysicalPathError::GatewayUnusable(
                "the selected default route has a zero interface LUID",
            ));
        }
        if route.loopback {
            return Err(PhysicalPathError::GatewayUnusable(
                "the selected default route is a loopback route",
            ));
        }
        let IpAddr::V4(gateway) = route.next_hop else {
            return Err(PhysicalPathError::GatewayUnusable(
                "the selected default route has no IPv4 next hop",
            ));
        };
        if !is_private_hotspot_ipv4(gateway) {
            return Err(PhysicalPathError::GatewayUnusable(
                "the selected default route has no private or shared unicast gateway",
            ));
        }
        let current = GatewaySelection {
            gateway,
            interface_index: route.interface_index,
            interface_luid: route.interface_luid,
        };
        match selected {
            None => selected = Some(current),
            Some(previous) if previous == current => {}
            Some(_) => {
                return Err(PhysicalPathError::GatewayUnusable(
                    "the two default route probes selected different routes",
                ))
            }
        }
    }
    selected.ok_or(PhysicalPathError::GatewayUnusable(
        "the default gateway check has no probe",
    ))
}

/// Decide the physical default route from one gateway and one adapter
/// observation.
///
/// This is the pure core of Windows default route discovery. It changes
/// nothing. It returns the interface index and the IPv4 gateway only when the
/// two gateway probes agree on the genuine `0.0.0.0/0` route with a real
/// private or shared IPv4 next hop (never on-link or zero), and the selected
/// adapter is an accepted physical Ethernet or Wi-Fi adapter that matches the
/// route. A split default route, a VPN route, a loopback, a tunnel, a virtual
/// adapter, or an identity mismatch is an error, never a fallback.
///
/// The live reader `win32::default_physical_route` fills these observations
/// from `GetBestInterfaceEx`, `GetBestRoute2`, `GetIfEntry2`, and
/// `GetUnicastIpAddressTable`. Tests build them from fixed data.
#[cfg(any(windows, test))]
pub(crate) fn default_physical_route_from(
    gateway: &GatewayObservation,
    adapter: &PhysicalAdapterObservation,
) -> Result<(u32, Ipv4Addr), PhysicalPathError> {
    let selection = selected_gateway(gateway)?;
    validate_adapter(adapter)?;
    if adapter.identity.interface_index() != selection.interface_index
        || adapter.identity.interface_luid() != selection.interface_luid
    {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    Ok((selection.interface_index, selection.gateway))
}

fn validate_destination(destination: Ipv4Addr) -> Result<(), PhysicalPathError> {
    if !is_private_hotspot_ipv4(destination) {
        return Err(PhysicalPathError::InvalidDestination(
            "the destination must be a private or shared IPv4 unicast address",
        ));
    }
    Ok(())
}

fn validate_adapter(
    adapter: &PhysicalAdapterObservation,
) -> Result<PhysicalAdapterKind, PhysicalPathError> {
    if !adapter.hardware_interface {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the hardware interface flag is clear",
        ));
    }
    if adapter.filter_interface {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the filter interface flag is set",
        ));
    }
    if adapter.tunnel_type != TUNNEL_TYPE_NONE {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the adapter has a tunnel type",
        ));
    }
    let kind = adapter.kind().ok_or(PhysicalPathError::AdapterNotPhysical(
        "the interface type is not Ethernet or IEEE 802.11",
    ))?;
    if adapter.oper_status != IF_OPER_STATUS_UP {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the operational state is not up",
        ));
    }
    if adapter.admin_status != NET_IF_ADMIN_STATUS_UP {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the administrative state is not up",
        ));
    }
    if adapter.media_connect_state != MEDIA_CONNECT_STATE_CONNECTED {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the media is not connected",
        ));
    }
    if adapter.access_type != NET_IF_ACCESS_BROADCAST {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the access type is not broadcast",
        ));
    }
    if adapter.physical_address_length < MIN_PHYSICAL_ADDRESS_LENGTH
        || adapter.physical_address_length > MAX_PHYSICAL_ADDRESS_LENGTH
    {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the physical address length is not plausible",
        ));
    }
    if !adapter.physical_address_nonzero {
        return Err(PhysicalPathError::AdapterNotPhysical(
            "the physical address is all zero",
        ));
    }
    if !is_private_hotspot_ipv4(adapter.ipv4_address) {
        return Err(PhysicalPathError::AdapterAddressUnusable(
            "the adapter address is not private or shared",
        ));
    }
    if adapter.usable_ipv4_address_count != 1 {
        return Err(PhysicalPathError::AdapterAddressUnusable(
            "the adapter must report exactly one usable IPv4 address",
        ));
    }
    let prefix = adapter.ipv4_prefix()?;
    if prefix.length < MIN_LOCAL_IPV4_PREFIX_LENGTH {
        return Err(PhysicalPathError::AdapterAddressUnusable(
            "the on-link prefix is too broad for one hotspot link",
        ));
    }
    if prefix.length <= 30 {
        let IpAddr::V4(prefix_address) = prefix.address else {
            return Err(PhysicalPathError::AdapterAddressUnusable(
                "the on-link prefix is not IPv4",
            ));
        };
        let network = u32::from(prefix_address);
        let broadcast = network | !ipv4_mask(prefix.length);
        let address = u32::from(adapter.ipv4_address);
        if address == network {
            return Err(PhysicalPathError::AdapterAddressUnusable(
                "the adapter address is the subnet network address",
            ));
        }
        if address == broadcast {
            return Err(PhysicalPathError::AdapterAddressUnusable(
                "the adapter address is the subnet broadcast address",
            ));
        }
    }
    Ok(kind)
}

/// Reject a gateway that names the adapter itself or an address that cannot
/// be one host on the adapter prefix.
///
/// A `/31` prefix has two host addresses under RFC 3021, so the network and
/// broadcast rule applies only to prefixes of `/30` or broader. A `/32` cannot
/// contain a different gateway, and the self check refuses it.
fn validate_gateway_host_address(
    adapter: &PhysicalAdapterObservation,
    local_prefix: RoutePrefix,
    gateway: Ipv4Addr,
) -> Result<(), PhysicalPathError> {
    if gateway == adapter.ipv4_address {
        return Err(PhysicalPathError::GatewayUnusable(
            "the gateway is the adapter address",
        ));
    }
    if local_prefix.length <= 30 {
        let IpAddr::V4(prefix_address) = local_prefix.address else {
            return Err(PhysicalPathError::GatewayUnusable(
                "the adapter prefix is not IPv4",
            ));
        };
        let network = u32::from(prefix_address);
        let broadcast = network | !ipv4_mask(local_prefix.length);
        let address = u32::from(gateway);
        if address == network {
            return Err(PhysicalPathError::GatewayUnusable(
                "the gateway is the subnet network address",
            ));
        }
        if address == broadcast {
            return Err(PhysicalPathError::GatewayUnusable(
                "the gateway is the subnet broadcast address",
            ));
        }
    }
    Ok(())
}

fn validate_destination_route(
    adapter: &PhysicalAdapterObservation,
    local_prefix: RoutePrefix,
    destination_route: &BestRouteProbe,
    destination: Ipv4Addr,
) -> Result<(), PhysicalPathError> {
    if destination_route.destination != IpAddr::V4(destination) {
        return Err(PhysicalPathError::InvalidObservation(
            "the destination route probe names another destination",
        ));
    }
    if !valid_interface_index(destination_route.best_interface_index) {
        return Err(PhysicalPathError::InvalidObservation(
            "the destination route has an invalid best interface index",
        ));
    }
    if destination_route.best_interface_index != adapter.identity.interface_index() {
        return Err(PhysicalPathError::DestinationRouteUnusable(
            "Windows selects another interface for the destination",
        ));
    }
    let route = &destination_route.route;
    if !route.prefix.is_valid() {
        return Err(PhysicalPathError::InvalidObservation(
            "the destination route has an invalid prefix",
        ));
    }
    if route.interface_index != adapter.identity.interface_index()
        || route.interface_luid != adapter.identity.interface_luid()
    {
        return Err(PhysicalPathError::DestinationRouteUnusable(
            "the destination route is not on the selected adapter",
        ));
    }
    if route.loopback {
        return Err(PhysicalPathError::DestinationRouteUnusable(
            "the destination route is a loopback route",
        ));
    }
    // Windows marks the on-link subnet route as a local-protocol route, so the
    // protocol is not checked. A local address is the adapter address itself.
    if destination == adapter.ipv4_address {
        return Err(PhysicalPathError::DestinationRouteUnusable(
            "the destination is a local address",
        ));
    }
    if !route.prefix.contains(IpAddr::V4(destination)) {
        return Err(PhysicalPathError::DestinationRouteUnusable(
            "the destination route does not contain the destination",
        ));
    }
    if route.prefix.length == 0 {
        return Err(PhysicalPathError::DestinationRouteUnusable(
            "the destination route is the default route, not an on-link route",
        ));
    }
    if route.prefix.length < local_prefix.length || !local_prefix.contains(route.prefix.address) {
        return Err(PhysicalPathError::DestinationRouteUnusable(
            "the destination route is broader than the adapter prefix",
        ));
    }
    if !route.next_hop.is_unspecified() || !route.next_hop.is_ipv4() {
        return Err(PhysicalPathError::DestinationRouteUnusable(
            "the destination route uses a next hop instead of the adapter link",
        ));
    }
    Ok(())
}

fn is_private_hotspot_ipv4(address: Ipv4Addr) -> bool {
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_link_local()
    {
        return false;
    }
    let [first, second, _, _] = address.octets();
    first == 10
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168)
        || (first == 100 && (64..=127).contains(&second))
}

fn valid_interface_index(index: u32) -> bool {
    index != 0 && index <= MAX_INTERFACE_INDEX
}

fn ipv4_mask(length: u8) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(length))
    }
}

fn network_v4(address: Ipv4Addr, length: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(address) & ipv4_mask(length))
}

#[cfg(any(windows, test))]
#[path = "windows_physical_path_win32.rs"]
mod win32;

#[cfg(windows)]
pub(crate) use win32::default_physical_route;
#[cfg(windows)]
pub use win32::observe;
#[cfg(windows)]
pub(crate) use win32::observe_token_destination;

/// Run the Windows token gate for one source device destination with no owned
/// run.
///
/// This is the read-only gate that the presence probe and manual check use
/// while no tunnel runs: the unscoped default route must be the physical
/// hotspot route, the pinned interface must be a physical Ethernet or Wi-Fi
/// adapter, and the destination must equal its default gateway. It changes no
/// route, opens no socket, and sends no packet. See `prove_token_destination`
/// for the exact rules.
#[cfg(windows)]
pub fn observe_token_destination_idle(
    destination: Ipv4Addr,
    pinned_index: u32,
) -> Result<PhysicalPathProof, PhysicalPathError> {
    observe_token_destination(destination, pinned_index, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_route_verify::{AdapterGuid, ObservedRoute, RouteVerifyError, IPV4_ROUTES};
    use std::collections::VecDeque;

    const INDEX: u32 = 17;
    const LUID: u64 = 0x0000_6000_0000_0011;
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 1);
    const LOCAL: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 2);
    const PREFIX_LENGTH: u8 = 28;

    fn guid(seed: u8) -> AdapterGuid {
        AdapterGuid::new(
            0x0011_2233 + u32::from(seed),
            0x4455,
            0x6677,
            [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, seed],
        )
    }

    fn identity(index: u32, luid: u64, guid: AdapterGuid) -> RetainedAdapterIdentity {
        RetainedAdapterIdentity::new(index, luid, guid).unwrap()
    }

    fn prefix(address: Ipv4Addr, length: u8) -> RoutePrefix {
        RoutePrefix::new(IpAddr::V4(network_v4(address, length)), length).unwrap()
    }

    fn route(
        destination: RoutePrefix,
        index: u32,
        luid: u64,
        next_hop: IpAddr,
        protocol: u32,
        loopback: bool,
    ) -> ObservedRoute {
        ObservedRoute {
            prefix: destination,
            interface_index: index,
            interface_luid: luid,
            next_hop,
            metric: 0,
            protocol,
            loopback,
        }
    }

    fn gateway_probe(
        destination: Ipv4Addr,
        gateway: Ipv4Addr,
        index: u32,
        luid: u64,
    ) -> BestRouteProbe {
        BestRouteProbe {
            destination: IpAddr::V4(destination),
            best_interface_index: index,
            route: route(DEFAULT_ROUTE, index, luid, IpAddr::V4(gateway), 3, false),
        }
    }

    fn gateway_observation(gateway: Ipv4Addr, index: u32, luid: u64) -> GatewayObservation {
        GatewayObservation {
            probes: [
                gateway_probe(GATEWAY_PROBES[0], gateway, index, luid),
                gateway_probe(GATEWAY_PROBES[1], gateway, index, luid),
            ],
        }
    }

    fn destination_probe(
        destination: Ipv4Addr,
        route_prefix: RoutePrefix,
        index: u32,
        luid: u64,
        next_hop: IpAddr,
        protocol: u32,
        loopback: bool,
    ) -> BestRouteProbe {
        BestRouteProbe {
            destination: IpAddr::V4(destination),
            best_interface_index: index,
            route: route(route_prefix, index, luid, next_hop, protocol, loopback),
        }
    }

    fn adapter(
        identity_value: RetainedAdapterIdentity,
        interface_type: u32,
        address: Ipv4Addr,
        length: u8,
    ) -> PhysicalAdapterObservation {
        PhysicalAdapterObservation {
            identity: identity_value,
            interface_type,
            oper_status: IF_OPER_STATUS_UP,
            admin_status: NET_IF_ADMIN_STATUS_UP,
            media_connect_state: MEDIA_CONNECT_STATE_CONNECTED,
            access_type: NET_IF_ACCESS_BROADCAST,
            tunnel_type: TUNNEL_TYPE_NONE,
            hardware_interface: true,
            filter_interface: false,
            physical_address_length: 6,
            physical_address_nonzero: true,
            ipv4_address: address,
            on_link_prefix_length: length,
            usable_ipv4_address_count: 1,
        }
    }

    fn default_adapter() -> PhysicalAdapterObservation {
        adapter(
            identity(INDEX, LUID, guid(1)),
            IF_TYPE_IEEE80211,
            LOCAL,
            PREFIX_LENGTH,
        )
    }

    fn default_destination_route() -> BestRouteProbe {
        destination_probe(
            GATEWAY,
            prefix(LOCAL, PREFIX_LENGTH),
            INDEX,
            LUID,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ROUTE_PROTOCOL_LOCAL,
            false,
        )
    }

    fn default_observation() -> PhysicalPathObservation {
        PhysicalPathObservation {
            adapter_before: default_adapter(),
            adapter_after: default_adapter(),
            gateway_before: gateway_observation(GATEWAY, INDEX, LUID),
            gateway_after: gateway_observation(GATEWAY, INDEX, LUID),
            destination_route: default_destination_route(),
            destination_address: GATEWAY,
        }
    }

    #[test]
    fn a_complete_physical_path_is_proven() {
        let observation = default_observation();
        let proof = verify(&observation).unwrap();
        assert_eq!(proof.adapter(), identity(INDEX, LUID, guid(1)));
        assert_eq!(proof.kind(), PhysicalAdapterKind::Wifi);
        assert_eq!(proof.gateway(), GATEWAY);
        assert_eq!(proof.local_address(), LOCAL);
        assert_eq!(proof.local_prefix(), prefix(LOCAL, PREFIX_LENGTH));
    }

    #[test]
    fn an_ethernet_hotspot_link_is_proven() {
        let mut observation = default_observation();
        observation.adapter_before.interface_type = IF_TYPE_ETHERNET_CSMACD;
        observation.adapter_after.interface_type = IF_TYPE_ETHERNET_CSMACD;
        let proof = verify(&observation).unwrap();
        assert_eq!(proof.kind(), PhysicalAdapterKind::Ethernet);
    }

    #[test]
    fn default_physical_route_accepts_agreeing_physical_probes() {
        let (index, gateway) = default_physical_route_from(
            &gateway_observation(GATEWAY, INDEX, LUID),
            &default_adapter(),
        )
        .unwrap();
        assert_eq!(index, INDEX);
        assert_eq!(gateway, GATEWAY);
    }

    #[test]
    fn default_physical_route_refuses_disagreeing_probes() {
        let mut gateway = gateway_observation(GATEWAY, INDEX, LUID);
        gateway.probes[1].route.next_hop = IpAddr::V4(Ipv4Addr::new(172, 20, 10, 254));
        assert!(matches!(
            default_physical_route_from(&gateway, &default_adapter()).unwrap_err(),
            PhysicalPathError::GatewayUnusable(_)
        ));
    }

    #[test]
    fn default_physical_route_refuses_a_zero_or_on_link_gateway() {
        let gateway = GatewayObservation {
            probes: [
                gateway_probe(GATEWAY_PROBES[0], Ipv4Addr::UNSPECIFIED, INDEX, LUID),
                gateway_probe(GATEWAY_PROBES[1], Ipv4Addr::UNSPECIFIED, INDEX, LUID),
            ],
        };
        assert_eq!(
            default_physical_route_from(&gateway, &default_adapter()).unwrap_err(),
            PhysicalPathError::GatewayUnusable(
                "the selected default route has no private or shared unicast gateway"
            )
        );
    }

    #[test]
    fn default_physical_route_refuses_a_non_physical_adapter() {
        let adapter = adapter(
            identity(INDEX, LUID, guid(1)),
            24, // IF_TYPE_SOFTWARE_LOOPBACK
            LOCAL,
            PREFIX_LENGTH,
        );
        assert!(matches!(
            default_physical_route_from(&gateway_observation(GATEWAY, INDEX, LUID), &adapter)
                .unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn default_physical_route_refuses_a_tunnel_adapter() {
        let mut adapter = default_adapter();
        adapter.tunnel_type = 2;
        assert!(matches!(
            default_physical_route_from(&gateway_observation(GATEWAY, INDEX, LUID), &adapter)
                .unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn default_physical_route_refuses_a_gateway_on_another_adapter() {
        assert_eq!(
            default_physical_route_from(
                &gateway_observation(GATEWAY, INDEX + 1, LUID),
                &default_adapter(),
            )
            .unwrap_err(),
            PhysicalPathError::AdapterIdentityChanged
        );
    }

    #[test]
    fn the_proof_feeds_the_route_local_subnet_gate() {
        let proof = verify(&default_observation()).unwrap();
        let subnet = proof.proven_local_subnet().unwrap();
        assert_eq!(subnet.prefix(), proof.local_prefix());
        assert_eq!(subnet.adapter(), proof.adapter());
        assert_eq!(subnet.provenance(), LocalSubnetProvenance::LocalInterface);
    }

    #[test]
    fn the_destination_must_be_the_default_gateway() {
        let mut observation = default_observation();
        let other = Ipv4Addr::new(172, 20, 10, 3);
        observation.destination_address = other;
        observation.destination_route = destination_probe(
            other,
            prefix(LOCAL, PREFIX_LENGTH),
            INDEX,
            LUID,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            3,
            false,
        );
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationMismatch
        );
    }

    #[test]
    fn a_public_gateway_is_refused() {
        let mut observation = default_observation();
        let public = Ipv4Addr::new(8, 8, 8, 8);
        observation.gateway_before = gateway_observation(public, INDEX, LUID);
        observation.gateway_after = gateway_observation(public, INDEX, LUID);
        observation.destination_address = public;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable(
                "the selected default route has no private or shared unicast gateway"
            )
        );
    }

    #[test]
    fn a_gateway_change_is_refused() {
        let mut observation = default_observation();
        observation.gateway_after =
            gateway_observation(Ipv4Addr::new(172, 20, 10, 254), INDEX, LUID);
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable(_)
        ));
    }

    #[test]
    fn a_split_default_route_is_refused() {
        let mut observation = default_observation();
        observation.gateway_before.probes[1].route.prefix =
            RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1).unwrap();
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable(_)
        ));
    }

    #[test]
    fn a_default_route_on_another_interface_is_refused() {
        let mut observation = default_observation();
        observation.gateway_before.probes[0].route.interface_index = INDEX + 1;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable(_)
        ));
    }

    #[test]
    fn a_default_route_with_a_loopback_flag_is_refused() {
        let mut observation = default_observation();
        observation.gateway_before.probes[0].route.loopback = true;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable(_)
        ));
    }

    #[test]
    fn a_default_route_with_a_zero_luid_is_refused() {
        let mut observation = default_observation();
        observation.gateway_before.probes[0].route.interface_luid = 0;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable(_)
        ));
    }

    #[test]
    fn the_default_probes_must_be_the_fixed_two_half_set() {
        let mut observation = default_observation();
        observation.gateway_before.probes[1].destination = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable(_)
        ));
    }

    #[test]
    fn the_gateway_probes_cover_both_managed_halves() {
        assert!(IPV4_ROUTES[0].contains(IpAddr::V4(GATEWAY_PROBES[0])));
        assert!(IPV4_ROUTES[1].contains(IpAddr::V4(GATEWAY_PROBES[1])));
    }

    #[test]
    fn a_tunnel_interface_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.tunnel_type = 2;
        observation.adapter_after.tunnel_type = 2;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn a_filter_interface_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.filter_interface = true;
        observation.adapter_after.filter_interface = true;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn a_missing_hardware_flag_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.hardware_interface = false;
        observation.adapter_after.hardware_interface = false;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn a_loopback_interface_type_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.interface_type = 24;
        observation.adapter_after.interface_type = 24;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn a_down_adapter_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.oper_status = 2;
        observation.adapter_after.oper_status = 2;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn a_disconnected_media_state_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.media_connect_state = 2;
        observation.adapter_after.media_connect_state = 2;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn a_non_broadcast_access_type_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.access_type = 3;
        observation.adapter_after.access_type = 3;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn a_missing_physical_address_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.physical_address_length = 0;
        observation.adapter_after.physical_address_length = 0;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn an_all_zero_physical_address_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.physical_address_nonzero = false;
        observation.adapter_after.physical_address_nonzero = false;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical(_)
        ));
    }

    #[test]
    fn an_adapter_identity_change_is_refused() {
        let mut observation = default_observation();
        observation.adapter_after = adapter(
            identity(INDEX + 1, LUID, guid(1)),
            IF_TYPE_IEEE80211,
            LOCAL,
            PREFIX_LENGTH,
        );
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterIdentityChanged
        );
    }

    #[test]
    fn a_gateway_on_another_adapter_is_refused() {
        let mut observation = default_observation();
        observation.gateway_before = gateway_observation(GATEWAY, INDEX + 1, LUID);
        observation.gateway_after = gateway_observation(GATEWAY, INDEX + 1, LUID);
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterIdentityChanged
        );
    }

    #[test]
    fn a_gateway_outside_the_adapter_prefix_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.on_link_prefix_length = 32;
        observation.adapter_after.on_link_prefix_length = 32;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayNotOnAdapterSubnet
        );
    }

    #[test]
    fn a_gateway_that_is_the_adapter_address_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.ipv4_address = GATEWAY;
        observation.adapter_after.ipv4_address = GATEWAY;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable("the gateway is the adapter address")
        );
    }

    #[test]
    fn a_gateway_that_is_the_subnet_network_address_is_refused() {
        let mut observation = default_observation();
        let network = Ipv4Addr::new(172, 20, 10, 0);
        observation.gateway_before = gateway_observation(network, INDEX, LUID);
        observation.gateway_after = gateway_observation(network, INDEX, LUID);
        observation.destination_address = network;
        observation.destination_route = destination_probe(
            network,
            prefix(LOCAL, PREFIX_LENGTH),
            INDEX,
            LUID,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            3,
            false,
        );
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable("the gateway is the subnet network address")
        );
    }

    #[test]
    fn a_gateway_that_is_the_subnet_broadcast_address_is_refused() {
        let mut observation = default_observation();
        let broadcast = Ipv4Addr::new(172, 20, 10, 15);
        observation.gateway_before = gateway_observation(broadcast, INDEX, LUID);
        observation.gateway_after = gateway_observation(broadcast, INDEX, LUID);
        observation.destination_address = broadcast;
        observation.destination_route = destination_probe(
            broadcast,
            prefix(LOCAL, PREFIX_LENGTH),
            INDEX,
            LUID,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            3,
            false,
        );
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::GatewayUnusable("the gateway is the subnet broadcast address")
        );
    }

    #[test]
    fn a_slash_31_gateway_is_a_host_address() {
        // A /31 prefix has two host addresses under RFC 3021. It has no
        // reserved network or broadcast address, so the gateway check does not
        // reject the other address.
        let gateway = Ipv4Addr::new(172, 20, 10, 1);
        let local = Ipv4Addr::new(172, 20, 10, 0);
        let mut observation = default_observation();
        observation.adapter_before =
            adapter(identity(INDEX, LUID, guid(1)), IF_TYPE_IEEE80211, local, 31);
        observation.adapter_after = observation.adapter_before;
        observation.gateway_before = gateway_observation(gateway, INDEX, LUID);
        observation.gateway_after = gateway_observation(gateway, INDEX, LUID);
        observation.destination_address = gateway;
        observation.destination_route = destination_probe(
            gateway,
            RoutePrefix::new(IpAddr::V4(local), 31).unwrap(),
            INDEX,
            LUID,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            3,
            false,
        );
        assert!(verify(&observation).is_ok());
    }

    #[test]
    fn an_adapter_with_no_usable_ipv4_address_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.usable_ipv4_address_count = 0;
        observation.adapter_after.usable_ipv4_address_count = 0;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(
                "the adapter must report exactly one usable IPv4 address"
            )
        );
    }

    #[test]
    fn an_adapter_with_two_usable_ipv4_addresses_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.usable_ipv4_address_count = 2;
        observation.adapter_after.usable_ipv4_address_count = 2;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(
                "the adapter must report exactly one usable IPv4 address"
            )
        );
    }

    #[test]
    fn a_broad_adapter_prefix_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.on_link_prefix_length = 8;
        observation.adapter_after.on_link_prefix_length = 8;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(_)
        ));
    }

    #[test]
    fn a_prefix_length_above_32_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.on_link_prefix_length = 33;
        observation.adapter_after.on_link_prefix_length = 33;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(_)
        ));
    }

    #[test]
    fn a_subnet_network_address_is_refused() {
        let mut observation = default_observation();
        let network = Ipv4Addr::new(172, 20, 10, 0);
        observation.adapter_before.ipv4_address = network;
        observation.adapter_after.ipv4_address = network;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(_)
        ));
    }

    #[test]
    fn a_subnet_broadcast_address_is_refused() {
        let mut observation = default_observation();
        let broadcast = Ipv4Addr::new(172, 20, 10, 15);
        observation.adapter_before.ipv4_address = broadcast;
        observation.adapter_after.ipv4_address = broadcast;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(_)
        ));
    }

    #[test]
    fn a_destination_route_on_another_interface_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.best_interface_index = INDEX + 1;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(
                "Windows selects another interface for the destination"
            )
        );
    }

    #[test]
    fn a_destination_route_with_another_luid_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.interface_luid = LUID + 1;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(_)
        ));
    }

    #[test]
    fn a_default_route_to_the_destination_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.prefix = DEFAULT_ROUTE;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(_)
        ));
    }

    #[test]
    fn a_broader_destination_route_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.prefix = prefix(Ipv4Addr::new(172, 20, 0, 0), 16);
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(
                "the destination route is broader than the adapter prefix"
            )
        );
    }

    #[test]
    fn a_destination_route_with_a_gateway_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.next_hop = IpAddr::V4(Ipv4Addr::new(172, 20, 10, 254));
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(
                "the destination route uses a next hop instead of the adapter link"
            )
        );
    }

    #[test]
    fn a_loopback_destination_route_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.loopback = true;
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(_)
        ));
    }

    #[test]
    fn an_on_link_route_from_windows_with_the_local_protocol_is_accepted() {
        // Windows reports the on-link subnet route of a hotspot client with
        // MIB_IPPROTO_LOCAL. Version 0.2.3.0 refused that route.
        let observation = default_observation();
        assert_eq!(
            observation.destination_route.route.protocol,
            ROUTE_PROTOCOL_LOCAL
        );
        assert!(verify(&observation).is_ok());
    }

    #[test]
    fn an_on_link_route_with_another_protocol_is_accepted() {
        let mut observation = default_observation();
        observation.destination_route.route.protocol = 3;
        assert!(verify(&observation).is_ok());
    }

    #[test]
    fn a_destination_route_that_does_not_contain_the_destination_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.prefix = prefix(Ipv4Addr::new(172, 20, 10, 16), 28);
        assert!(matches!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(_)
        ));
    }

    #[test]
    fn an_invalid_destination_route_prefix_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.prefix = RoutePrefix {
            address: IpAddr::V4(Ipv4Addr::new(172, 20, 10, 1)),
            length: 28,
        };
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::InvalidObservation("the destination route has an invalid prefix")
        );
    }

    #[test]
    fn a_destination_probe_for_another_destination_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.destination = IpAddr::V4(Ipv4Addr::new(172, 20, 10, 3));
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::InvalidObservation(
                "the destination route probe names another destination"
            )
        );
    }

    #[test]
    fn normal_hotspot_gateways_are_private_or_shared() {
        for gateway in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(172, 31, 255, 254),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 127, 255, 254),
        ] {
            assert!(is_private_hotspot_ipv4(gateway), "{gateway}");
        }
    }

    #[test]
    fn public_and_special_gateways_are_refused() {
        for gateway in [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(172, 32, 0, 1),
            Ipv4Addr::new(100, 128, 0, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::UNSPECIFIED,
        ] {
            assert!(!is_private_hotspot_ipv4(gateway), "{gateway}");
        }
    }

    #[test]
    fn a_zero_interface_index_is_not_valid() {
        assert!(!valid_interface_index(0));
        assert!(valid_interface_index(1));
        assert!(valid_interface_index(MAX_INTERFACE_INDEX));
        assert!(!valid_interface_index(MAX_INTERFACE_INDEX + 1));
    }

    #[test]
    fn the_physical_adapter_kind_accepts_only_ethernet_and_wifi() {
        assert_eq!(
            PhysicalAdapterKind::from_interface_type(IF_TYPE_ETHERNET_CSMACD),
            Some(PhysicalAdapterKind::Ethernet)
        );
        assert_eq!(
            PhysicalAdapterKind::from_interface_type(IF_TYPE_IEEE80211),
            Some(PhysicalAdapterKind::Wifi)
        );
        for interface_type in [0, 1, 23, 24, 131, 243] {
            assert_eq!(
                PhysicalAdapterKind::from_interface_type(interface_type),
                None
            );
        }
    }

    #[test]
    fn a_link_local_adapter_address_is_refused() {
        let mut observation = default_observation();
        let apipa = Ipv4Addr::new(169, 254, 10, 20);
        observation.adapter_before.ipv4_address = apipa;
        observation.adapter_after.ipv4_address = apipa;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(
                "the adapter address is not private or shared"
            )
        );
    }

    #[test]
    fn a_multicast_adapter_address_is_refused() {
        let mut observation = default_observation();
        let multicast = Ipv4Addr::new(224, 0, 0, 1);
        observation.adapter_before.ipv4_address = multicast;
        observation.adapter_after.ipv4_address = multicast;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(
                "the adapter address is not private or shared"
            )
        );
    }

    #[test]
    fn a_down_administrative_state_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.admin_status = 2;
        observation.adapter_after.admin_status = 2;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical("the administrative state is not up")
        );
    }

    #[test]
    fn an_implausibly_short_physical_address_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.physical_address_length = 5;
        observation.adapter_after.physical_address_length = 5;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical("the physical address length is not plausible")
        );
    }

    #[test]
    fn an_implausibly_long_physical_address_is_refused() {
        let mut observation = default_observation();
        observation.adapter_before.physical_address_length = 33;
        observation.adapter_after.physical_address_length = 33;
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::AdapterNotPhysical("the physical address length is not plausible")
        );
    }

    #[test]
    fn the_physical_address_length_bounds_are_inclusive() {
        for length in [MIN_PHYSICAL_ADDRESS_LENGTH, MAX_PHYSICAL_ADDRESS_LENGTH] {
            let mut observation = default_observation();
            observation.adapter_before.physical_address_length = length;
            observation.adapter_after.physical_address_length = length;
            assert!(verify(&observation).is_ok(), "length={length}");
        }
    }

    #[test]
    fn a_minimum_width_hotspot_prefix_is_accepted() {
        let mut observation = default_observation();
        let local = Ipv4Addr::new(172, 20, 10, 2);
        let gateway = Ipv4Addr::new(172, 20, 10, 1);
        observation.adapter_before = adapter(
            identity(INDEX, LUID, guid(1)),
            IF_TYPE_IEEE80211,
            local,
            MIN_LOCAL_IPV4_PREFIX_LENGTH,
        );
        observation.adapter_after = observation.adapter_before;
        observation.gateway_before = gateway_observation(gateway, INDEX, LUID);
        observation.gateway_after = gateway_observation(gateway, INDEX, LUID);
        observation.destination_address = gateway;
        observation.destination_route = destination_probe(
            gateway,
            prefix(local, MIN_LOCAL_IPV4_PREFIX_LENGTH),
            INDEX,
            LUID,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            3,
            false,
        );
        assert!(verify(&observation).is_ok());
    }

    #[test]
    fn an_ipv6_destination_route_prefix_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.prefix =
            RoutePrefix::new(IpAddr::V6("2001:db8::".parse().unwrap()), 32).unwrap();
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(
                "the destination route does not contain the destination"
            )
        );
    }

    #[test]
    fn an_ipv6_destination_route_next_hop_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.route.next_hop = IpAddr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::DestinationRouteUnusable(
                "the destination route uses a next hop instead of the adapter link"
            )
        );
    }

    #[test]
    fn a_destination_route_for_an_ipv6_destination_is_refused() {
        let mut observation = default_observation();
        observation.destination_route.destination = IpAddr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(
            verify(&observation).unwrap_err(),
            PhysicalPathError::InvalidObservation(
                "the destination route probe names another destination"
            )
        );
    }

    #[test]
    fn the_observation_debug_output_redacts_addresses_and_identity() {
        let observation = default_observation();
        let proof = verify(&observation).unwrap();
        let guid = proof.adapter().interface_guid().to_string();
        let luid = proof.adapter().interface_luid().to_string();
        for text in [
            format!("{observation:?}"),
            format!("{:?}", observation.adapter_before),
            format!("{:?}", observation.gateway_before),
            format!("{proof:?}"),
        ] {
            assert!(!text.contains("172.20.10.1"), "{text}");
            assert!(!text.contains("172.20.10.2"), "{text}");
            assert!(!text.contains("172.20.10.0"), "{text}");
            assert!(!text.contains(&guid), "{text}");
            assert!(!text.contains(&luid), "{text}");
            assert!(!text.contains(&format!("{INDEX}")), "{text}");
        }
    }

    #[test]
    fn the_error_debug_output_redacts_a_wrapped_route_error() {
        let error = PhysicalPathError::RouteVerify(RouteVerifyError::UnexpectedNextHop {
            prefix: prefix(Ipv4Addr::new(172, 20, 10, 0), 28),
            next_hop: IpAddr::V4(Ipv4Addr::new(172, 20, 9, 254)),
        });
        let text = format!("{error:?}");
        assert_eq!(text, "RouteVerify(<redacted>)");
        assert!(!text.contains("172.20.10.0"));
        assert!(!text.contains("172.20.9.254"));
        let display = error.to_string();
        assert_eq!(display, "the physical route evidence was refused");
        assert!(!display.contains("172.20.10.0"));
        assert!(!display.contains("172.20.9.254"));
    }

    #[test]
    fn known_identity_api_errors_keep_only_operation_and_code() {
        for operation in ["ConvertInterfaceLuidToGuid", "ConvertInterfaceLuidToIndex"] {
            let error =
                PhysicalPathError::RouteVerify(RouteVerifyError::Api { operation, code: 5 });
            assert_eq!(
                error.to_string(),
                format!("{operation} failed with Windows error 5")
            );
            assert_eq!(
                format!("{error:?}"),
                format!("Api {{ operation: \"{operation}\", code: 5 }}")
            );
        }
        let unknown = PhysicalPathError::RouteVerify(RouteVerifyError::Api {
            operation: "172.20.10.1",
            code: 5,
        });
        assert_eq!(
            unknown.to_string(),
            "the physical route evidence was refused"
        );
        assert_eq!(format!("{unknown:?}"), "RouteVerify(<redacted>)");
    }

    #[test]
    fn presence_reason_is_a_fixed_vocabulary_without_addresses() {
        let route_error = RouteVerifyError::UnexpectedNextHop {
            prefix: prefix(Ipv4Addr::new(172, 20, 10, 0), 28),
            next_hop: IpAddr::V4(Ipv4Addr::new(172, 20, 9, 254)),
        };
        let cases: Vec<(PhysicalPathError, String)> = vec![
            (
                PhysicalPathError::InvalidDestination(
                    "the destination must be a private or shared IPv4 unicast address",
                ),
                "InvalidDestination: the destination must be a private or shared IPv4 unicast address"
                    .to_string(),
            ),
            (
                PhysicalPathError::InvalidObservation("the on-link prefix length is above 32"),
                "InvalidObservation: the on-link prefix length is above 32".to_string(),
            ),
            (
                PhysicalPathError::GatewayUnusable(
                    "the two default route probes selected different routes",
                ),
                "GatewayUnusable: the two default route probes selected different routes".to_string(),
            ),
            (PhysicalPathError::DestinationMismatch, "DestinationMismatch".to_string()),
            (
                PhysicalPathError::AdapterNotPhysical("the filter interface flag is set"),
                "AdapterNotPhysical: the filter interface flag is set".to_string(),
            ),
            (PhysicalPathError::AdapterIdentityChanged, "AdapterIdentityChanged".to_string()),
            (
                PhysicalPathError::AdapterAddressUnusable(
                    "the adapter must report exactly one usable IPv4 address",
                ),
                "AdapterAddressUnusable: the adapter must report exactly one usable IPv4 address"
                    .to_string(),
            ),
            (
                PhysicalPathError::GatewayNotOnAdapterSubnet,
                "GatewayNotOnAdapterSubnet".to_string(),
            ),
            (
                PhysicalPathError::DestinationRouteUnusable(
                    "the destination route uses a next hop instead of the adapter link",
                ),
                "DestinationRouteUnusable: the destination route uses a next hop instead of the adapter link"
                    .to_string(),
            ),
            (
                PhysicalPathError::RouteVerify(route_error),
                "RouteVerify: UnexpectedNextHop".to_string(),
            ),
            (
                PhysicalPathError::Api {
                    operation: "GetBestRoute2",
                    code: 5,
                },
                "Api: 5".to_string(),
            ),
        ];
        for (error, expected) in cases {
            let text = error.presence_reason();
            assert_eq!(text, expected);
            assert!(!text.contains("172.20.10.0"), "{text}");
            assert!(!text.contains("172.20.9.254"), "{text}");
        }
    }

    #[test]
    fn the_error_display_does_not_name_the_gateway_or_identity() {
        let observation = default_observation();
        let mut changed = observation.clone();
        changed.adapter_after = adapter(
            identity(INDEX + 1, LUID + 1, guid(2)),
            IF_TYPE_IEEE80211,
            LOCAL,
            PREFIX_LENGTH,
        );
        let text = changed_error_text(&changed);
        assert!(!text.contains("172.20.10.1"));
        assert!(!text.contains("172.20.10.2"));
        assert!(!text.contains("00112233"));
        assert!(!text.contains(&LUID.to_string()));
    }

    fn changed_error_text(observation: &PhysicalPathObservation) -> String {
        verify(observation).unwrap_err().to_string()
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReadCall {
        Gateway,
        Adapter {
            interface_luid: u64,
            interface_index: u32,
        },
        Destination(Ipv4Addr),
    }

    struct FakeReads {
        calls: Vec<ReadCall>,
        gateways: VecDeque<Result<GatewayObservation, PhysicalPathError>>,
        adapters: VecDeque<Result<PhysicalAdapterObservation, PhysicalPathError>>,
        routes: VecDeque<Result<BestRouteProbe, PhysicalPathError>>,
    }

    fn fake_reads() -> FakeReads {
        FakeReads {
            calls: Vec::new(),
            gateways: VecDeque::from([
                Ok(gateway_observation(GATEWAY, INDEX, LUID)),
                Ok(gateway_observation(GATEWAY, INDEX, LUID)),
            ]),
            adapters: VecDeque::from([Ok(default_adapter()), Ok(default_adapter())]),
            routes: VecDeque::from([Ok(default_destination_route())]),
        }
    }

    impl PhysicalPathReads for FakeReads {
        fn read_gateway(&mut self) -> Result<GatewayObservation, PhysicalPathError> {
            self.calls.push(ReadCall::Gateway);
            self.gateways
                .pop_front()
                .expect("the observer read the gateway more than twice")
        }

        fn read_adapter(
            &mut self,
            interface_luid: u64,
            expected_index: u32,
        ) -> Result<PhysicalAdapterObservation, PhysicalPathError> {
            self.calls.push(ReadCall::Adapter {
                interface_luid,
                interface_index: expected_index,
            });
            self.adapters
                .pop_front()
                .expect("the observer read the adapter more than twice")
        }

        fn read_destination_route(
            &mut self,
            destination: Ipv4Addr,
        ) -> Result<BestRouteProbe, PhysicalPathError> {
            self.calls.push(ReadCall::Destination(destination));
            self.routes
                .pop_front()
                .expect("the observer read the destination route more than once")
        }
    }

    fn adapter_call() -> ReadCall {
        ReadCall::Adapter {
            interface_luid: LUID,
            interface_index: INDEX,
        }
    }

    #[test]
    fn the_observer_brackets_the_destination_route_with_gateway_and_adapter_reads() {
        let mut reads = fake_reads();
        let proof = observe_with_reads(&mut reads, GATEWAY).unwrap();
        assert_eq!(proof.gateway(), GATEWAY);
        assert_eq!(
            reads.calls,
            vec![
                ReadCall::Gateway,
                adapter_call(),
                ReadCall::Destination(GATEWAY),
                ReadCall::Gateway,
                adapter_call(),
            ]
        );
        assert!(reads.gateways.is_empty());
        assert!(reads.adapters.is_empty());
        assert!(reads.routes.is_empty());
    }

    #[test]
    fn the_observer_reads_nothing_for_an_invalid_destination() {
        let mut reads = fake_reads();
        let error = observe_with_reads(&mut reads, Ipv4Addr::new(8, 8, 8, 8)).unwrap_err();
        assert!(matches!(
            error,
            PhysicalPathError::InvalidDestination(
                "the destination must be a private or shared IPv4 unicast address"
            )
        ));
        assert!(reads.calls.is_empty());
        assert_eq!(reads.gateways.len(), 2);
        assert_eq!(reads.adapters.len(), 2);
        assert_eq!(reads.routes.len(), 1);
    }

    #[test]
    fn the_observer_stops_before_the_adapter_when_the_destination_is_not_the_gateway() {
        let mut reads = fake_reads();
        let error = observe_with_reads(&mut reads, Ipv4Addr::new(172, 20, 10, 3)).unwrap_err();
        assert_eq!(error, PhysicalPathError::DestinationMismatch);
        assert_eq!(reads.calls, vec![ReadCall::Gateway]);
        assert_eq!(reads.adapters.len(), 2);
        assert_eq!(reads.routes.len(), 1);
    }

    #[test]
    fn the_observer_stops_before_the_route_when_the_first_adapter_read_fails() {
        let mut reads = fake_reads();
        reads.adapters.pop_front();
        reads
            .adapters
            .push_front(Err(PhysicalPathError::InvalidObservation(
                "test adapter failure",
            )));
        let error = observe_with_reads(&mut reads, GATEWAY).unwrap_err();
        assert_eq!(
            error,
            PhysicalPathError::InvalidObservation("test adapter failure")
        );
        assert_eq!(reads.calls, vec![ReadCall::Gateway, adapter_call()]);
        assert_eq!(reads.gateways.len(), 1);
        assert_eq!(reads.routes.len(), 1);
    }

    #[test]
    fn the_observer_stops_before_the_second_gateway_when_the_route_read_fails() {
        let mut reads = fake_reads();
        reads.routes.clear();
        reads
            .routes
            .push_back(Err(PhysicalPathError::InvalidObservation(
                "test route failure",
            )));
        let error = observe_with_reads(&mut reads, GATEWAY).unwrap_err();
        assert_eq!(
            error,
            PhysicalPathError::InvalidObservation("test route failure")
        );
        assert_eq!(
            reads.calls,
            vec![
                ReadCall::Gateway,
                adapter_call(),
                ReadCall::Destination(GATEWAY),
            ]
        );
        assert_eq!(reads.gateways.len(), 1);
        assert_eq!(reads.adapters.len(), 1);
    }

    #[test]
    fn the_observer_stops_before_the_second_adapter_when_the_second_gateway_read_fails() {
        let mut reads = fake_reads();
        reads.gateways.pop_back();
        reads
            .gateways
            .push_back(Err(PhysicalPathError::InvalidObservation(
                "test gateway failure",
            )));
        let error = observe_with_reads(&mut reads, GATEWAY).unwrap_err();
        assert_eq!(
            error,
            PhysicalPathError::InvalidObservation("test gateway failure")
        );
        assert_eq!(
            reads.calls,
            vec![
                ReadCall::Gateway,
                adapter_call(),
                ReadCall::Destination(GATEWAY),
                ReadCall::Gateway,
            ]
        );
        assert_eq!(reads.adapters.len(), 1);
        assert!(reads.routes.is_empty());
    }

    #[test]
    fn the_observer_refuses_a_gateway_change_without_reading_the_adapter_again() {
        let mut reads = fake_reads();
        reads.gateways.pop_back();
        reads.gateways.push_back(Ok(gateway_observation(
            Ipv4Addr::new(172, 20, 10, 254),
            INDEX,
            LUID,
        )));
        let error = observe_with_reads(&mut reads, GATEWAY).unwrap_err();
        assert_eq!(
            error,
            PhysicalPathError::GatewayUnusable(
                "the gateway or its interface changed during the observation"
            )
        );
        assert_eq!(
            reads.calls,
            vec![
                ReadCall::Gateway,
                adapter_call(),
                ReadCall::Destination(GATEWAY),
                ReadCall::Gateway,
            ]
        );
        assert_eq!(reads.adapters.len(), 1);
    }

    #[test]
    fn the_observer_stops_after_the_last_bracket_when_the_second_adapter_read_fails() {
        let mut reads = fake_reads();
        reads.adapters.pop_back();
        reads
            .adapters
            .push_back(Err(PhysicalPathError::InvalidObservation(
                "test adapter failure",
            )));
        let error = observe_with_reads(&mut reads, GATEWAY).unwrap_err();
        assert_eq!(
            error,
            PhysicalPathError::InvalidObservation("test adapter failure")
        );
        assert_eq!(
            reads.calls,
            vec![
                ReadCall::Gateway,
                adapter_call(),
                ReadCall::Destination(GATEWAY),
                ReadCall::Gateway,
                adapter_call(),
            ]
        );
        assert!(reads.gateways.is_empty());
        assert!(reads.routes.is_empty());
    }

    #[test]
    fn the_observer_applies_the_pure_checks_after_all_bracketed_reads() {
        let mut reads = fake_reads();
        let mut route = default_destination_route();
        route.best_interface_index = INDEX + 1;
        reads.routes.pop_front();
        reads.routes.push_front(Ok(route));
        let error = observe_with_reads(&mut reads, GATEWAY).unwrap_err();
        assert_eq!(
            error,
            PhysicalPathError::DestinationRouteUnusable(
                "Windows selects another interface for the destination"
            )
        );
        assert_eq!(
            reads.calls,
            vec![
                ReadCall::Gateway,
                adapter_call(),
                ReadCall::Destination(GATEWAY),
                ReadCall::Gateway,
                adapter_call(),
            ]
        );
        assert!(reads.gateways.is_empty());
        assert!(reads.adapters.is_empty());
        assert!(reads.routes.is_empty());
    }

    #[test]
    fn the_observer_refuses_an_adapter_change_after_the_destination_route() {
        let mut reads = fake_reads();
        reads.adapters.pop_back();
        reads.adapters.push_back(Ok(adapter(
            identity(INDEX + 1, LUID, guid(1)),
            IF_TYPE_IEEE80211,
            LOCAL,
            PREFIX_LENGTH,
        )));
        let error = observe_with_reads(&mut reads, GATEWAY).unwrap_err();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
        assert_eq!(
            reads.calls,
            vec![
                ReadCall::Gateway,
                adapter_call(),
                ReadCall::Destination(GATEWAY),
                ReadCall::Gateway,
                adapter_call(),
            ]
        );
        assert!(reads.gateways.is_empty());
        assert!(reads.adapters.is_empty());
        assert!(reads.routes.is_empty());
    }

    #[test]
    fn the_observer_refuses_an_adapter_guid_change_after_the_destination_route() {
        let mut reads = fake_reads();
        reads.adapters.pop_back();
        reads.adapters.push_back(Ok(adapter(
            identity(INDEX, LUID, guid(2)),
            IF_TYPE_IEEE80211,
            LOCAL,
            PREFIX_LENGTH,
        )));
        let error = observe_with_reads(&mut reads, GATEWAY).unwrap_err();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
        assert_eq!(reads.calls.len(), 5);
    }

    // The Windows token gate.

    const TUNNEL_INDEX: u32 = 41;
    const TUNNEL_LUID: u64 = 0x0000_6100_0000_0029;
    const VPN_INDEX: u32 = 52;
    const VPN_LUID: u64 = 0x0000_6100_0000_0034;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TokenCall {
        Unscoped,
        Pinned(u32),
        Adapter(u64, u32),
        Destination(Ipv4Addr),
    }

    /// A fake route and adapter table. Each read returns the next queued
    /// value, so a test can change the table between the two brackets.
    struct TokenTable {
        calls: Vec<TokenCall>,
        unscoped: VecDeque<Result<GatewayObservation, PhysicalPathError>>,
        pinned: VecDeque<Result<GatewayObservation, PhysicalPathError>>,
        adapters: VecDeque<Result<PhysicalAdapterObservation, PhysicalPathError>>,
        routes: VecDeque<Result<BestRouteProbe, PhysicalPathError>>,
    }

    fn physical_table() -> TokenTable {
        TokenTable {
            calls: Vec::new(),
            unscoped: VecDeque::from([
                Ok(gateway_observation(GATEWAY, INDEX, LUID)),
                Ok(gateway_observation(GATEWAY, INDEX, LUID)),
            ]),
            pinned: VecDeque::from([
                Ok(gateway_observation(GATEWAY, INDEX, LUID)),
                Ok(gateway_observation(GATEWAY, INDEX, LUID)),
            ]),
            adapters: VecDeque::from([Ok(default_adapter()), Ok(default_adapter())]),
            routes: VecDeque::from([Ok(default_destination_route())]),
        }
    }

    /// The unscoped probes see the owned tunnel `/1` routes.
    fn tunnel_halves(index: u32, luid: u64, next_hop: Ipv4Addr) -> GatewayObservation {
        let probe = |position: usize| BestRouteProbe {
            destination: IpAddr::V4(GATEWAY_PROBES[position]),
            best_interface_index: index,
            route: route(
                IPV4_ROUTES[position],
                index,
                luid,
                IpAddr::V4(next_hop),
                3,
                false,
            ),
        };
        GatewayObservation {
            probes: [probe(0), probe(1)],
        }
    }

    fn running_table() -> TokenTable {
        let mut table = physical_table();
        table.unscoped = VecDeque::from([
            Ok(tunnel_halves(
                TUNNEL_INDEX,
                TUNNEL_LUID,
                Ipv4Addr::UNSPECIFIED,
            )),
            Ok(tunnel_halves(
                TUNNEL_INDEX,
                TUNNEL_LUID,
                Ipv4Addr::UNSPECIFIED,
            )),
        ]);
        table
    }

    fn run() -> TokenRun {
        TokenRun {
            tunnel: crate::windows_route_verify::TunnelIdentity::new(TUNNEL_INDEX, TUNNEL_LUID)
                .unwrap(),
            outer: identity(INDEX, LUID, guid(1)),
        }
    }

    impl PhysicalPathReads for TokenTable {
        fn read_gateway(&mut self) -> Result<GatewayObservation, PhysicalPathError> {
            self.calls.push(TokenCall::Unscoped);
            self.unscoped.pop_front().expect("unscoped read")
        }
        fn read_adapter(
            &mut self,
            interface_luid: u64,
            expected_index: u32,
        ) -> Result<PhysicalAdapterObservation, PhysicalPathError> {
            self.calls
                .push(TokenCall::Adapter(interface_luid, expected_index));
            self.adapters.pop_front().expect("adapter read")
        }
        fn read_destination_route(
            &mut self,
            destination: Ipv4Addr,
        ) -> Result<BestRouteProbe, PhysicalPathError> {
            self.calls.push(TokenCall::Destination(destination));
            self.routes.pop_front().expect("destination read")
        }
    }

    impl TokenPathReads for TokenTable {
        fn read_pinned_gateway(
            &mut self,
            interface_index: u32,
        ) -> Result<GatewayObservation, PhysicalPathError> {
            self.calls.push(TokenCall::Pinned(interface_index));
            self.pinned.pop_front().expect("pinned read")
        }
    }

    fn gate(table: &mut TokenTable, run: Option<&TokenRun>) -> Result<(), PhysicalPathError> {
        prove_token_destination(table, GATEWAY, INDEX, run).map(|proof| {
            assert_eq!(proof.gateway(), GATEWAY);
            assert_eq!(proof.adapter(), identity(INDEX, LUID, guid(1)));
        })
    }

    #[test]
    fn the_token_gate_passes_on_the_exact_physical_gateway() {
        let mut table = physical_table();
        gate(&mut table, None).unwrap();
        assert_eq!(
            table.calls,
            vec![
                TokenCall::Unscoped,
                TokenCall::Pinned(INDEX),
                TokenCall::Adapter(LUID, INDEX),
                TokenCall::Destination(GATEWAY),
                TokenCall::Unscoped,
                TokenCall::Pinned(INDEX),
                TokenCall::Adapter(LUID, INDEX),
            ]
        );
    }

    #[test]
    fn the_token_gate_passes_during_an_owned_run() {
        let mut table = running_table();
        gate(&mut table, Some(&run())).unwrap();
        assert_eq!(table.calls.len(), 7);
    }

    #[test]
    fn the_token_gate_refuses_another_destination_before_the_adapter_read() {
        let mut table = physical_table();
        let error = prove_token_destination(&mut table, Ipv4Addr::new(172, 20, 10, 3), INDEX, None)
            .unwrap_err();
        assert_eq!(error, PhysicalPathError::DestinationMismatch);
        assert_eq!(
            table.calls,
            vec![TokenCall::Unscoped, TokenCall::Pinned(INDEX)]
        );
    }

    #[test]
    fn the_token_gate_refuses_a_public_or_loopback_destination_without_a_read() {
        for destination in [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::LOCALHOST] {
            let mut table = physical_table();
            assert!(matches!(
                prove_token_destination(&mut table, destination, INDEX, None),
                Err(PhysicalPathError::InvalidDestination(_))
            ));
            assert!(table.calls.is_empty());
        }
    }

    #[test]
    fn the_token_gate_refuses_a_vpn_default_route() {
        // A full VPN installs its own /0 with a gateway on another adapter
        // and wins the unscoped lookup. The pinned lookup still names the
        // hotspot gateway, but the token must not go out while the VPN owns
        // the default path.
        let mut table = physical_table();
        table.unscoped[0] = Ok(gateway_observation(
            Ipv4Addr::new(10, 8, 0, 1),
            VPN_INDEX,
            VPN_LUID,
        ));
        assert_eq!(
            gate(&mut table, None),
            Err(PhysicalPathError::GatewayUnusable(
                "Windows selects a default route that is not the pinned physical gateway",
            ))
        );
    }

    #[test]
    fn the_token_gate_refuses_a_vpn_default_route_on_the_pinned_interface() {
        // The pinned lookup names a /0 on another LUID or with a gateway that
        // is not the destination.
        let mut table = physical_table();
        table.pinned[0] = Ok(gateway_observation(GATEWAY, INDEX, VPN_LUID));
        assert!(gate(&mut table, None).is_err());
        // The pinned and unscoped lookups agree on a gateway that is not the
        // destination.
        let mut table = physical_table();
        let other = gateway_observation(Ipv4Addr::new(10, 8, 0, 1), INDEX, LUID);
        table.pinned[0] = Ok(other);
        table.unscoped[0] = Ok(other);
        assert_eq!(
            gate(&mut table, None),
            Err(PhysicalPathError::DestinationMismatch)
        );
        // Only the pinned lookup changed: the unscoped default disagrees.
        let mut table = physical_table();
        table.pinned[0] = Ok(other);
        assert!(matches!(
            gate(&mut table, None),
            Err(PhysicalPathError::GatewayUnusable(_))
        ));
    }

    #[test]
    fn the_token_gate_refuses_a_split_default_route() {
        // OpenVPN `redirect-gateway def1`: both halves go to a VPN adapter.
        let mut table = physical_table();
        table.unscoped[0] = Ok(tunnel_halves(
            VPN_INDEX,
            VPN_LUID,
            Ipv4Addr::new(10, 8, 0, 1),
        ));
        assert_eq!(
            gate(&mut table, None),
            Err(PhysicalPathError::GatewayUnusable(
                "a VPN, split default, or more-specific route takes the default path",
            ))
        );
        // The same split default during an owned run is still foreign.
        let mut table = running_table();
        table.unscoped[1] = Ok(tunnel_halves(VPN_INDEX, VPN_LUID, Ipv4Addr::UNSPECIFIED));
        assert!(gate(&mut table, Some(&run())).is_err());
        // An owned run's /1 is not accepted when no run is known.
        let mut table = running_table();
        assert!(gate(&mut table, None).is_err());
        // A pinned lookup that returns a /1 is not the default route.
        let mut table = physical_table();
        table.pinned[0] = Ok(tunnel_halves(INDEX, LUID, GATEWAY));
        assert!(gate(&mut table, None).is_err());
    }

    #[test]
    fn the_token_gate_refuses_an_owned_half_with_a_gateway_or_reused_luid() {
        let mut table = running_table();
        table.unscoped[0] = Ok(tunnel_halves(
            TUNNEL_INDEX,
            TUNNEL_LUID,
            Ipv4Addr::new(10, 8, 0, 1),
        ));
        assert!(gate(&mut table, Some(&run())).is_err());
        let mut table = running_table();
        table.unscoped[0] = Ok(tunnel_halves(TUNNEL_INDEX, VPN_LUID, Ipv4Addr::UNSPECIFIED));
        assert!(gate(&mut table, Some(&run())).is_err());
    }

    #[test]
    fn the_token_gate_refuses_a_loopback_default_route() {
        let mut table = physical_table();
        if let Ok(observation) = table.unscoped[0].as_mut() {
            observation.probes[1].route.loopback = true;
        }
        assert_eq!(
            gate(&mut table, None),
            Err(PhysicalPathError::GatewayUnusable(
                "the selected default route is a loopback route",
            ))
        );
        let mut table = physical_table();
        if let Ok(observation) = table.pinned[0].as_mut() {
            observation.probes[0].route.loopback = true;
        }
        assert!(gate(&mut table, None).is_err());
    }

    #[test]
    fn the_token_gate_refuses_a_virtual_or_tunnel_adapter() {
        let virtual_adapters = [
            PhysicalAdapterObservation {
                hardware_interface: false,
                ..default_adapter()
            },
            PhysicalAdapterObservation {
                tunnel_type: 14,
                ..default_adapter()
            },
            PhysicalAdapterObservation {
                filter_interface: true,
                ..default_adapter()
            },
            PhysicalAdapterObservation {
                interface_type: 53,
                ..default_adapter()
            },
            PhysicalAdapterObservation {
                interface_type: 24,
                ..default_adapter()
            },
        ];
        for adapter_value in virtual_adapters {
            let mut table = physical_table();
            table.adapters = VecDeque::from([Ok(adapter_value), Ok(adapter_value)]);
            assert!(
                matches!(
                    gate(&mut table, None),
                    Err(PhysicalPathError::AdapterNotPhysical(_))
                ),
                "{adapter_value:?}"
            );
        }
        // The pin cannot name the tunnel adapter during a run.
        let mut table = running_table();
        let tunnel_pin = TokenRun {
            tunnel: crate::windows_route_verify::TunnelIdentity::new(INDEX, TUNNEL_LUID).unwrap(),
            outer: identity(INDEX, LUID, guid(1)),
        };
        assert!(matches!(
            gate(&mut table, Some(&tunnel_pin)),
            Err(PhysicalPathError::AdapterNotPhysical(_))
        ));
        assert!(table.calls.is_empty());
    }

    #[test]
    fn the_token_gate_refuses_a_mismatched_luid_index_or_guid() {
        // The pinned route names another interface index.
        let mut table = physical_table();
        table.pinned[0] = Ok(gateway_observation(GATEWAY, INDEX + 1, LUID));
        assert_eq!(
            gate(&mut table, None),
            Err(PhysicalPathError::GatewayUnusable(
                "the default route is not on the pinned interface",
            ))
        );
        // The adapter at the route LUID reports another GUID than the start.
        let mut table = running_table();
        let changed = adapter(
            identity(INDEX, LUID, guid(9)),
            IF_TYPE_IEEE80211,
            LOCAL,
            PREFIX_LENGTH,
        );
        table.adapters = VecDeque::from([Ok(changed), Ok(changed)]);
        assert_eq!(
            gate(&mut table, Some(&run())),
            Err(PhysicalPathError::AdapterIdentityChanged)
        );
        // The second adapter read names another index.
        let mut table = physical_table();
        table.adapters[1] = Ok(adapter(
            identity(INDEX + 1, LUID, guid(1)),
            IF_TYPE_IEEE80211,
            LOCAL,
            PREFIX_LENGTH,
        ));
        assert_eq!(
            gate(&mut table, None),
            Err(PhysicalPathError::AdapterIdentityChanged)
        );
        // A run whose start adapter is at another index refuses before a read.
        let mut table = running_table();
        let moved = TokenRun {
            outer: identity(INDEX + 1, LUID, guid(1)),
            ..run()
        };
        assert_eq!(
            gate(&mut table, Some(&moved)),
            Err(PhysicalPathError::AdapterIdentityChanged)
        );
        assert!(table.calls.is_empty());
    }

    #[test]
    fn the_token_gate_refuses_multiple_or_changing_gateways() {
        // The two pinned probes disagree.
        let mut table = physical_table();
        if let Ok(observation) = table.pinned[0].as_mut() {
            observation.probes[1].route.next_hop = IpAddr::V4(Ipv4Addr::new(172, 20, 10, 5));
        }
        assert!(matches!(
            gate(&mut table, None),
            Err(PhysicalPathError::GatewayUnusable(_))
        ));
        // A second default route wins one unscoped half.
        let mut table = physical_table();
        if let Ok(observation) = table.unscoped[1].as_mut() {
            observation.probes[0] = gateway_probe(
                GATEWAY_PROBES[0],
                Ipv4Addr::new(192, 168, 1, 1),
                VPN_INDEX,
                VPN_LUID,
            );
        }
        assert!(gate(&mut table, None).is_err());
        // The pinned gateway changes between the brackets.
        let mut table = physical_table();
        table.pinned[1] = Ok(gateway_observation(
            Ipv4Addr::new(172, 20, 10, 9),
            INDEX,
            LUID,
        ));
        assert_eq!(
            gate(&mut table, None),
            Err(PhysicalPathError::GatewayUnusable(
                "the gateway or its interface changed during the observation",
            ))
        );
    }

    #[test]
    fn the_token_gate_fails_closed_on_any_read_error() {
        let failure = || PhysicalPathError::Api {
            operation: "GetBestRoute2",
            code: 1168,
        };
        for step in 0..7 {
            let mut table = physical_table();
            match step {
                0 => table.unscoped[0] = Err(failure()),
                1 => table.pinned[0] = Err(failure()),
                2 => table.adapters[0] = Err(failure()),
                3 => table.routes[0] = Err(failure()),
                4 => table.unscoped[1] = Err(failure()),
                5 => table.pinned[1] = Err(failure()),
                _ => table.adapters[1] = Err(failure()),
            }
            assert_eq!(gate(&mut table, None), Err(failure()), "step {step}");
        }
        // A zero pin reads nothing.
        let mut table = physical_table();
        assert!(prove_token_destination(&mut table, GATEWAY, 0, None).is_err());
        assert!(table.calls.is_empty());
    }
}
