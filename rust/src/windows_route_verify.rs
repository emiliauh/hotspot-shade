//! Read-only Windows route verification foundation.
//!
//! This module checks the Windows route table for the routes that the tunnel
//! installs. It proves five facts from observed route data:
//!
//! 1. The table has the exact `0.0.0.0/1` and `128.0.0.0/1` routes.
//! 2. The tunnel adapter owns both routes. Ownership means the interface index
//!    and the interface LUID match the tunnel adapter.
//! 3. The route for the selected IPv6 policy is present and owned.
//! 4. Every more-specific route inside a managed prefix is either covered by a
//!    caller-proven local subnet, reported as a warning for a non-internet
//!    range, or a failure. There is no blanket private or shared exclusion.
//! 5. Windows selects the tunnel route for a fixed set of probe destinations.
//!
//! The module changes no route and creates no device. It reads the route table
//! with `GetIpForwardTable2`, `GetBestInterfaceEx`, and `GetBestRoute2` only.
//!
//! # The tunnel is not fail-closed
//!
//! A successful result does not prove that no traffic can bypass the tunnel.
//! Windows uses the longest matching prefix. A more-specific route on another
//! interface bypasses the tunnel. A local DNS answer bypasses the tunnel. This
//! module checks the exact prefixes that the tunnel manages, the more-specific
//! routes that the scan reports, and the probe destinations in the policy. Do
//! not describe the tunnel as fail-closed.
//!
//! The IPv6 block route sends `2000::/3` to the tunnel adapter. It does not
//! cover IPv6 addresses outside `2000::/3`. It does not cover link-local,
//! multicast, or NAT64 addresses. The IPv6 block policy is a reduction of the
//! IPv6 path, not a complete block.
//!
//! # Layers
//!
//! [`verify`] is a pure function. It reads a [`RouteObservation`] and returns a
//! [`RouteProof`] or an error. [`verify_retained`] is the same check bound to a
//! [`RetainedAdapterIdentity`]. Tests cover this layer without a Windows host.
//!
//! `observe`, `verify_live`, `verify_live_retained`, `read_live_identity`, and
//! `confirm_retained_identity` are Windows only. They call `iphlpapi.dll` and
//! convert the ABI rows into [`ObservedRoute`] values. `observe` never treats an
//! API error as an empty table. `verify_live` returns an error for every
//! inconclusive state.
//!
//! # Microsoft references
//!
//! - `GetIpForwardTable2`: <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2>
//! - `GetBestRoute2`: <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getbestroute2>
//! - `GetBestInterfaceEx`: <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getbestinterfaceex>
//! - `ConvertInterfaceLuidToGuid`: <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoguid>
//! - `ConvertInterfaceLuidToIndex`: <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoindex>
//! - `MIB_IPFORWARD_ROW2`: <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2>
//! - `MIB_IPFORWARD_TABLE2`: <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_table2>
//! - `IP_ADDRESS_PREFIX`: <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix>
//! - `SOCKADDR_INET`: <https://learn.microsoft.com/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet>
//!
//! # Adapter identity
//!
//! [`TunnelIdentity`] holds the interface index and the interface LUID. The
//! index is not stable: Windows can reuse it after an adapter is removed. The
//! LUID is more stable, but Windows can assign a LUID to a new adapter after the
//! old one is gone.
//!
//! [`RetainedAdapterIdentity`] adds the interface GUID. `verify_live_retained`
//! reads the live GUID and index for the retained tunnel LUID and for the LUID
//! of each local physical adapter that a [`ProvenLocalSubnet`] names. It reads
//! them before the route reads and again after them. The reads bracket the
//! observation. A matching result therefore proves each adapter unit at those
//! two moments, not continuous ownership. Each identity read is a separate
//! call, so one round is not an atomic snapshot of every adapter. Windows
//! offers no atomic compare-and-verify that includes the interface GUID, and
//! an adapter can change after the second read. The result does not prove who
//! created an adapter.
//!
//! A local adapter must not share the index, the LUID, or the GUID of the
//! tunnel adapter. The pure layer rejects that policy before any read. The
//! comparison uses identity values only. It cannot detect a local adapter that
//! is another tunnel type, such as a third-party VPN adapter, and it does not
//! prove that the local adapter is physical. `verify_live` has no identity
//! check, so it refuses a policy with a local subnet.
//!
//! # Default gateway
//!
//! `default_ipv4_gateway` probes one destination in each IPv4 half. Each
//! selected row must be the genuine `0.0.0.0/0` route on the interface that
//! `GetBestInterfaceEx` chose, not loopback, with a unicast IPv4 next hop, and
//! the rows must agree. A VPN split-default route such as `0.0.0.0/1` fails the
//! check, so its gateway is never reported as the default gateway. The result
//! does not prove that the gateway is a source device or that the interface is
//! physical. A full VPN that installs its own `/0` route with a gateway still
//! passes. The caller keeps its interface and address checks.
//!
//! # More-specific routes
//!
//! Windows uses the longest matching prefix. A more-specific route on another
//! adapter can take traffic that the managed `/1` or `2000::/3` route should
//! carry. [`verify`] scans both tables for such a route.
//!
//! The scan reports a row when all of these are true:
//!
//! - The row prefix is strictly longer than the managed prefix, and its network
//!   address is inside the managed prefix.
//! - The row is not owned by the tunnel adapter. Ownership requires both the
//!   interface index and the interface LUID to match.
//! - The row is not covered by a [`ProvenLocalSubnet`] that the caller supplied
//!   for the same adapter identity.
//! - IPv6 local-subnet exceptions are not allowed in block mode.
//!
//! A covered local row must also use the unspecified next hop. The caller must
//! prove that the subnet belongs to the local hotspot link, for example from the
//! address and prefix on the hotspot adapter or from an authenticated source
//! device. This module cannot prove ownership. It records the caller's proof
//! source and uses it only to keep that exact on-link local route out of the
//! failure set.
//!
//! There is no blanket exclusion for private, shared, or special-purpose
//! ranges. A more-specific route for `10.0.0.0/8`, `100.64.0.0/10`, or a
//! globally reachable exception such as `192.0.0.9/32` is a failure unless a
//! proven local subnet covers it on the same adapter. Do not claim that a
//! private destination cannot bypass the tunnel.
//!
//! A row for a range that cannot carry global internet unicast is a warning,
//! not a proof. These ranges are `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`,
//! `192.0.2.0/24`, `192.88.99.0/24`, `198.18.0.0/15`, `198.51.100.0/24`,
//! `203.0.113.0/24`, `224.0.0.0/4`, and `240.0.0.0/4` for IPv4, and
//! `2001:2::/48`, `2001:10::/28`, `2001:20::/28`, `2001:db8::/32`,
//! `3ffe::/16`, and `3fff::/20` for IPv6. `192.0.0.0/24` is not excluded,
//! because `192.0.0.9/32` and `192.0.0.10/32` are globally reachable. A warning
//! names a route that this check did not prove. A caller that needs a strict
//! gate must inspect the warnings.
//!
//! A directly connected IPv6 hotspot `/64` is inside `2000::/3`. Without a
//! proven local subnet it is a failure, so a forward gate would reject a normal
//! host. Supply the hotspot `/64` with the retained identity of the physical
//! adapter, and its on-link route is expected. A different `/64`, a broader
//! route, or the same prefix on another adapter is still a failure.
//!
//! The scan reads one snapshot of the table. A route can change after the read.
//! A route for a warned range can still bypass the tunnel in a way that this
//! module does not prove. The scan does not prove the absence of every bypass.
//!
//! # Local subnet proof
//!
//! [`ProvenLocalSubnet`] is an explicit caller assertion. It pairs a prefix with
//! a [`RetainedAdapterIdentity`] and a [`LocalSubnetProvenance`]. The pure layer
//! checks the identity shape and the prefix width. It cannot check that the
//! operating system assigned the prefix to that adapter, that the adapter is the
//! hotspot link, or that the interface metric makes the local route win. Those
//! facts need native proof.
//!
//! A live caller must read the address and prefix from the physical adapter,
//! resolve the LUID to a GUID, and retain the result. Do not build a local
//! subnet from an unauthenticated packet, a browser value, or a route row alone.
//! The retained GUID is not present in a route row, so the pure layer compares
//! the index and LUID. `verify_live_retained` confirms the GUID and index of
//! the local adapter before and after the route reads. The local adapter must
//! not share the index, LUID, or GUID of the tunnel adapter.
//! Without a proven local subnet, a private or shared route is a failure, not a
//! silent allowance.
//!
//! A hotspot link is one link. The pure layer rejects a local proof wider than
//! IPv4 `/16` or IPv6 `/64` as too broad for one hotspot link, and it rejects a
//! proof that contains a best-route probe. Those bounds keep a whole private
//! block such as `10.0.0.0/8` from becoming proof for arbitrary routes. The
//! bounds are policy limits, not measurements.
//!
//! # IPv6 stack state
//!
//! A block policy must not report protection when the IPv6 stack state is
//! unknown or when a probe fails. [`RouteObservation`] carries an
//! [`Ipv6Stack`] value. `Present` comes only from a successful IPv6 route table
//! read. `Absent` comes only from the documented `ERROR_NOT_SUPPORTED` result
//! of that table read. Every other API error is a failure with no stack claim.
//!
//! A probe runs only after a successful table read. A probe that fails with
//! `ERROR_NOT_SUPPORTED` after that read is a contradiction, not proof of an
//! absent stack. `observe` maps it to
//! [`RouteVerifyError::Ipv6ProbeInconclusive`].
//!
//! A block policy with an absent stack returns [`RouteVerifyError::Ipv6StackAbsent`].
//! A block policy with an unknown stack returns
//! [`RouteVerifyError::Ipv6StackUnknown`]. Neither is a success state. The
//! policy is reported as not proven, not as protected.
//!
//! # IPv6 source hint
//!
//! `GetBestRoute2` may fail on a tunnel adapter with no usable IPv6 source
//! address when the caller passes a null source. Forward mode therefore allows
//! an explicit source hint through [`VerifyPolicy::with_ipv6_source`]. Block
//! mode rejects a hint: the block adapter carries no IPv6 address, so a hint
//! would describe an address that the policy does not expect. A failed probe is
//! still a failure with a hint.
//!
//! The hint is only a route lookup constraint. This module does not read back
//! the source address that Windows selects, and it does not prove that the
//! address is assigned to the tunnel adapter. Address assignment and duplicate
//! address detection are unimplemented gates. Windows can ignore the hint or
//! return a different source without this module noticing.
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
//!   Confirm the error code that Windows returns for that case.
//! - The selected routes may need time to converge after installation.
//! - `GetBestRoute2` is called with a null `InterfaceLuid` and a nonzero
//!   interface index. Microsoft documents the LUID parameter as optional and
//!   says the interface index is used when no LUID is set. The live result for
//!   that form still needs a measurement.
//! - The route table stride must equal `size_of::<MIB_IPFORWARD_ROW2>()`. The
//!   C array rule gives this stride. Microsoft warns that alignment padding may
//!   exist between rows, so confirm the stride on the target host.
//! - The interface metric is not read. A competing exact prefix on another
//!   interface is therefore an error, because this module cannot compare the
//!   total metrics. A metric-aware result needs a native read, such as a
//!   measured best route or the per-interface metric, and that read is not part
//!   of this module.
//! - A [`ProvenLocalSubnet`] is a caller assertion. This module cannot enumerate
//!   interface addresses or prove that the prefix belongs to the hotspot link.
//!   A live caller must read the address and prefix from the physical adapter,
//!   resolve the LUID to a GUID, and retain that identity. Do not derive a local
//!   subnet from a route row or an unauthenticated value.
//! - `ConvertInterfaceLuidToGuid` and `ConvertInterfaceLuidToIndex` must report
//!   the same GUID and index that the route rows carry. A live host must also
//!   confirm the error code for a LUID that names no interface.
//! - A source hint must belong to the tunnel adapter. This module cannot prove
//!   that, because it does not enumerate interface addresses. It also does not
//!   read the source address that `GetBestRoute2` returns. Address assignment
//!   and duplicate address detection are unimplemented gates.
//! - The more-specific scan reports an unproven route for private, shared, and
//!   global destinations. A warning for a non-internet range is not proof. A
//!   live host with a route for `192.0.0.9/32`, a global exception inside a
//!   special-purpose block, must show the failure rather than an exclusion.
//!
//! # Unimplemented gates
//!
//! These items are not implemented in this module. Do not report them as
//! verified:
//!
//! 1. The live ABI behavior on a Windows host. See the limits above.
//! 2. IPv6 source address assignment and duplicate address detection. A hint is
//!    not proof that the tunnel adapter owns the address.
//! 3. Interface address enumeration and local subnet ownership. A caller-supplied
//!    [`ProvenLocalSubnet`] is an assertion, not a measurement. Without native
//!    proof the scan reports the route instead of allowing it.
//! 4. Interface metric comparison. An exact competing prefix is an error, not a
//!    metric-ordered decision.
//! 5. Integration into the direct start gate. The route proof is not wired to
//!    the Windows direct start. Windows direct mode stays disabled until every
//!    gate is measured on a live host. The separate source device token gate,
//!    `require_token_destination_proof`, is wired; it uses the physical path
//!    evidence, not this route proof.
//!
//! # Integration prerequisites
//!
//! 1. Keep the pure layer available on every platform. The FFI layer is behind
//!    `cfg(windows)`.
//! 2. Call `verify_live` for a managed IPv6 policy only, after `RouteManager`
//!    installs the routes and after the adapter has an interface index. Prefer
//!    `verify_live_retained` when the caller retained the adapter GUID. A
//!    policy with a local subnet requires `verify_live_retained`.
//! 3. Pass the exact LUID and index of the tunnel adapter. Do not persist the
//!    index across a link change. `verify_live_retained` also rejects a retained
//!    index that no longer matches the live index for the LUID.
//! 4. Treat `Ipv6InheritNotVerifiable` as "not verified". Do not show a
//!    success state for the inherit policy, and do not turn a forward or block
//!    result into an inherit result.
//! 5. Run the checks only for block or forward. On a host without an IPv6
//!    stack, `observe` returns `Ipv6StackAbsent`. Do not convert that error
//!    into a success.
//! 6. A block result needs the IPv6 stack present and every IPv6 probe to
//!    succeed. A failed probe is not proof that the traffic is blocked.
//! 7. Forward mode may pass a source address hint with
//!    [`VerifyPolicy::with_ipv6_source`]. The hint may avoid a source-selection
//!    failure, and this module does not measure that effect. It does not
//!    weaken the route or probe checks. The caller must establish that the
//!    address is assigned to the tunnel adapter. This module cannot.
//! 8. Supply the local hotspot subnet through [`VerifyPolicy::with_local_subnet`]
//!    only when the caller proved its ownership and retained the physical
//!    adapter identity. Do not add a broad private block, a whole managed half,
//!    or a prefix that contains a probe destination. A missing proof is a
//!    failure, not a reason to loosen the scan.
//! 9. Inspect [`RouteProof::warnings`] before a strict gate reports success. A
//!    warning means the scan did not prove that route.
//! 10. The direct mode stays disabled until all of these gates are verified on a
//!     live Windows host.

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

/// IPv4 blocks whose routes cannot carry global internet unicast.
///
/// A more-specific route wholly inside one of these blocks is a warning, not a
/// proof. The private, shared, and protocol-assignment ranges are deliberately
/// absent: a route for `10.0.0.0/8`, `100.64.0.0/10`, or `192.0.0.0/24` is a
/// failure unless a proven local subnet covers it. `192.0.0.0/24` contains the
/// globally reachable exception hosts `192.0.0.9` and `192.0.0.10`.
const IPV4_NON_INTERNET: [RoutePrefix; 10] = [
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        length: 8,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        length: 8,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        length: 16,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        length: 24,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(192, 88, 99, 0)),
        length: 24,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)),
        length: 15,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
        length: 24,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
        length: 24,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        length: 4,
    },
    RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0)),
        length: 4,
    },
];

/// IPv6 blocks whose routes cannot carry global internet unicast.
///
/// Every managed IPv6 prefix is inside `2000::/3`. These blocks cover the
/// special-purpose ranges inside `2000::/3` that cannot carry ordinary public
/// internet unicast traffic. A route for a private, shared, or other unproven
/// range is a failure, not a warning.
const IPV6_NON_INTERNET: [RoutePrefix; 6] = [
    RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0)),
        length: 48,
    },
    RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0)),
        length: 28,
    },
    RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0)),
        length: 28,
    },
    RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
        length: 32,
    },
    RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::new(0x3ffe, 0, 0, 0, 0, 0, 0, 0)),
        length: 16,
    },
    RoutePrefix {
        address: IpAddr::V6(Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0)),
        length: 20,
    },
];

/// Default IPv4 best-route probes. Four are in `0.0.0.0/1` and three are in
/// `128.0.0.0/1`. Every IPv4 `/2` block has at least one probe.
///
/// The probes check the selected route. They send no packet.
pub const DEFAULT_IPV4_PROBES: [Ipv4Addr; 7] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(64, 6, 64, 6),
    Ipv4Addr::new(129, 6, 15, 28),
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

/// The Windows `ERROR_NOT_SUPPORTED` value.
///
/// `GetIpForwardTable2` and `GetBestRoute2` return this value when the host has
/// no IPv6 stack for an IPv6 request. This module treats only this documented
/// value as an absent stack. Every other error is inconclusive.
#[cfg(any(windows, test))]
const ERROR_NOT_SUPPORTED: u32 = 50;

/// A 16-byte Windows GUID.
///
/// The layout matches the Windows `GUID` type that
/// `ConvertInterfaceLuidToGuid` writes. The fields are private so that the
/// display form and the comparison use one representation.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl AdapterGuid {
    /// The zero GUID. Windows does not return it for a valid interface.
    pub const ZERO: Self = Self {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    /// Build a GUID from its Windows fields.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Return true for the zero GUID.
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }
}

impl fmt::Display for AdapterGuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

const _: () = {
    assert!(std::mem::size_of::<AdapterGuid>() == 16);
    assert!(std::mem::align_of::<AdapterGuid>() == 4);
};

/// True when the observation established that the host has an IPv6 stack.
///
/// The default is [`Ipv6Stack::Unknown`]. A caller must not treat `Unknown` or
/// `Absent` as a blocked IPv6 policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ipv6Stack {
    /// A successful IPv6 route table read proved the stack is present.
    Present,
    /// Windows reported the documented "no IPv6 stack" error.
    Absent,
    /// The observation did not establish the state.
    #[default]
    Unknown,
}

impl Ipv6Stack {
    /// Return true only for [`Ipv6Stack::Present`].
    pub fn is_present(self) -> bool {
        self == Self::Present
    }
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

/// The identity values that the live stack reported for one retained LUID.
///
/// Build this value from `ConvertInterfaceLuidToGuid` and
/// `ConvertInterfaceLuidToIndex`, or from fixed test data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveAdapterIdentity {
    /// The live `NET_IFINDEX` for the LUID.
    pub interface_index: u32,
    /// The live GUID for the LUID.
    pub interface_guid: AdapterGuid,
}

/// The full identity that a caller retained for an adapter.
///
/// All three values must match at check time: the interface index, the
/// interface LUID, and the interface GUID. The index can be reused and the LUID
/// can be reassigned, so neither value alone identifies the adapter. The fields
/// are private so that every value passes [`RetainedAdapterIdentity::new`].
///
/// The tunnel policy uses this type for the tunnel adapter. A
/// [`ProvenLocalSubnet`] uses it for the local physical adapter that owns the
/// hotspot subnet. A route row carries the index and LUID only, so the pure
/// layer compares those two values. `verify_live_retained` reads the live GUID
/// and index for every retained adapter in the policy before and after the
/// route reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedAdapterIdentity {
    interface_index: u32,
    interface_luid: u64,
    interface_guid: AdapterGuid,
}

impl RetainedAdapterIdentity {
    /// Build a retained identity.
    ///
    /// Return an error for a zero or oversized index, a zero LUID, or a zero
    /// GUID. Windows does not use those values for a real interface.
    pub fn new(
        interface_index: u32,
        interface_luid: u64,
        interface_guid: AdapterGuid,
    ) -> Result<Self, RouteVerifyError> {
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
        if interface_guid.is_zero() {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface GUID must be nonzero",
            ));
        }
        Ok(Self {
            interface_index,
            interface_luid,
            interface_guid,
        })
    }

    /// Return the retained interface index.
    pub fn interface_index(self) -> u32 {
        self.interface_index
    }

    /// Return the retained interface LUID.
    pub fn interface_luid(self) -> u64 {
        self.interface_luid
    }

    /// Return the retained interface GUID.
    pub fn interface_guid(self) -> AdapterGuid {
        self.interface_guid
    }

    /// Return the two-value index and LUID identity used by the route checks.
    pub fn tunnel(self) -> TunnelIdentity {
        TunnelIdentity {
            interface_index: self.interface_index,
            interface_luid: self.interface_luid,
        }
    }

    /// Compare the retained identity with live values for the retained LUID.
    ///
    /// Return an error for a zero or invalid live value, a different GUID, or a
    /// different index. A different GUID means the LUID now names another
    /// adapter. A different index means the retained index is stale. Both
    /// failures keep every route that this program owns.
    pub fn matches(self, live: LiveAdapterIdentity) -> Result<(), RouteVerifyError> {
        if live.interface_guid.is_zero() {
            return Err(RouteVerifyError::InvalidObservation(
                "the live adapter lookup returned the zero GUID",
            ));
        }
        if !valid_interface_index(live.interface_index) {
            return Err(RouteVerifyError::InvalidObservation(
                "the live adapter lookup returned an invalid interface index",
            ));
        }
        if live.interface_guid != self.interface_guid {
            return Err(RouteVerifyError::AdapterIdentityChanged {
                retained: self.interface_guid,
                observed: live.interface_guid,
            });
        }
        if live.interface_index != self.interface_index {
            return Err(RouteVerifyError::InterfaceIndexChanged {
                retained: self.interface_index,
                observed: live.interface_index,
            });
        }
        Ok(())
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
    /// Whether the observation established that the IPv6 stack is present.
    ///
    /// The default is [`Ipv6Stack::Unknown`]. A managed IPv6 policy is not
    /// proven for `Unknown` or `Absent`.
    pub ipv6_stack: Ipv6Stack,
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

/// The broadest IPv4 local subnet that a caller may prove.
///
/// A hotspot link is one link, not a whole private block. This bound keeps
/// `10.0.0.0/8` or `100.64.0.0/10` from becoming proof for every route inside
/// it. It is a policy bound, not a measurement.
const MIN_LOCAL_IPV4_LENGTH: u8 = 16;

/// The broadest IPv6 local subnet that a caller may prove.
///
/// A normal hotspot prefix is `/64` or longer. This policy bound does not prove
/// that the prefix is assigned to one link.
pub(crate) const MIN_LOCAL_IPV6_LENGTH: u8 = 64;

/// How a caller established that a prefix belongs to the local hotspot link.
///
/// The value records the caller's assertion. This module cannot verify it. Use
/// it only for a prefix that the caller read from the physical adapter or from
/// an authenticated source device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalSubnetProvenance {
    /// The caller read the address and prefix from the local physical adapter.
    LocalInterface,
    /// The caller authenticated the source device and received the subnet from
    /// it.
    AuthenticatedSourceDevice,
}

/// A local subnet that the caller proved belongs to the local hotspot link.
///
/// The prefix and the retained physical adapter identity are the caller's
/// assertion. The pure layer checks the prefix width, the identity shape, and
/// the on-link next hop. It cannot prove that the operating system assigned the
/// prefix to the adapter, that the adapter is the hotspot link, or that the
/// interface metric selects the local route. Those facts need native proof.
/// `verify_live_retained` confirms the retained GUID and index of the adapter
/// before and after the route reads. That proves the adapter unit at those two
/// moments, not that the adapter is physical or owns the prefix.
///
/// The fields are private so that every value passes [`ProvenLocalSubnet::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenLocalSubnet {
    prefix: RoutePrefix,
    adapter: RetainedAdapterIdentity,
    provenance: LocalSubnetProvenance,
}

impl ProvenLocalSubnet {
    /// Build a proven local subnet.
    ///
    /// Return an error for an invalid prefix, for a prefix that is not more
    /// specific than the managed prefix for its family, or for a prefix wider
    /// than IPv4 `/16` or IPv6 `/64`. A whole private block must not become
    /// proof for arbitrary routes. The caller accepts responsibility for the
    /// ownership and the interface of the prefix.
    pub fn new(
        prefix: RoutePrefix,
        adapter: RetainedAdapterIdentity,
        provenance: LocalSubnetProvenance,
    ) -> Result<Self, RouteVerifyError> {
        if !prefix.is_valid() {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet has an invalid prefix",
            ));
        }
        let managed_length = match prefix.family() {
            AddressFamily::V4 => IPV4_ROUTES[0].length,
            AddressFamily::V6 => IPV6_TUNNEL_ROUTE.length,
        };
        if prefix.length <= managed_length {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet must be more specific than the managed prefix",
            ));
        }
        let link_length = match prefix.family() {
            AddressFamily::V4 => MIN_LOCAL_IPV4_LENGTH,
            AddressFamily::V6 => MIN_LOCAL_IPV6_LENGTH,
        };
        if prefix.length < link_length {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet is too broad for one hotspot link",
            ));
        }
        Ok(Self {
            prefix,
            adapter,
            provenance,
        })
    }

    /// Return the proven prefix.
    pub fn prefix(self) -> RoutePrefix {
        self.prefix
    }

    /// Return the retained physical adapter identity for the subnet.
    pub fn adapter(self) -> RetainedAdapterIdentity {
        self.adapter
    }

    /// Return the caller's proof source.
    pub fn provenance(self) -> LocalSubnetProvenance {
        self.provenance
    }

    /// Return true when this subnet covers an on-link route on its adapter.
    ///
    /// The route must be inside the subnet, at least as specific as the subnet,
    /// on the retained adapter, on-link, and not a loopback row. A broader route
    /// inside the managed prefix is not covered.
    fn covers(self, route: &ObservedRoute) -> bool {
        route.interface_index == self.adapter.interface_index()
            && route.interface_luid == self.adapter.interface_luid()
            && route.prefix.family() == self.prefix.family()
            && route.prefix.length >= self.prefix.length
            && self.prefix.contains(route.prefix.address)
            && route.next_hop.is_unspecified()
            && !route.loopback
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
    /// Optional IPv6 source address for the best-route probes.
    ///
    /// Forward mode may set this when Windows cannot select a source address
    /// for an IPv6 probe. Block mode rejects it. This value is only a route
    /// lookup constraint. The module does not prove that the tunnel adapter
    /// owns the address.
    pub ipv6_source: Option<Ipv6Addr>,
    /// Local subnets that the caller proved belong to the local hotspot link.
    ///
    /// An on-link route inside a subnet on the retained physical adapter is
    /// expected and is not a bypass. Every other more-specific route is a
    /// failure or a warning. Leave this empty when no proof exists: the scan
    /// then reports a private, shared, or global route instead of allowing it.
    /// IPv6 local-subnet exceptions are invalid in block mode.
    pub local_subnets: Vec<ProvenLocalSubnet>,
}

impl VerifyPolicy {
    /// Build a policy with the default probe destinations and no local subnet.
    pub fn new(tunnel: TunnelIdentity, ipv6: Ipv6RoutePolicy) -> Self {
        Self {
            tunnel,
            ipv6,
            ipv4_probes: DEFAULT_IPV4_PROBES.to_vec(),
            ipv6_probes: DEFAULT_IPV6_PROBES.to_vec(),
            ipv6_source: None,
            local_subnets: Vec::new(),
        }
    }

    /// Set an IPv6 source address for the best-route probes.
    ///
    /// Use this only for forward mode. The caller must establish that the
    /// address is assigned to the tunnel adapter; this check cannot prove it.
    /// Verification rejects the value for block mode and rejects an
    /// unspecified, multicast, loopback, or IPv4-mapped address. A probe that
    /// still fails is a failure, not a proof. Windows can ignore the hint or
    /// choose another source, and this module does not read the choice back.
    pub fn with_ipv6_source(mut self, source: Ipv6Addr) -> Self {
        self.ipv6_source = Some(source);
        self
    }

    /// Add a local subnet that the caller proved belongs to the hotspot link.
    ///
    /// Add only a prefix whose ownership the caller established from the
    /// physical adapter or an authenticated source device. A missing proof is a
    /// failure, not a reason to loosen the scan. An IPv6 subnet is invalid
    /// when the policy uses block mode.
    pub fn with_local_subnet(mut self, subnet: ProvenLocalSubnet) -> Self {
        self.local_subnets.push(subnet);
        self
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

/// Why the scan did not prove a more-specific route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteWarningReason {
    /// The prefix cannot carry global internet unicast. The scan reports the
    /// route instead of claiming that it is safe or proven.
    NonInternetRange,
}

/// A more-specific route that the scan did not prove.
///
/// A warning is not a success for that route. A strict gate must inspect the
/// list. The route is outside a proven local subnet, or it is inside a range
/// that cannot carry global internet unicast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteWarning {
    /// The route prefix.
    pub prefix: RoutePrefix,
    /// The interface index of the row.
    pub interface_index: u32,
    /// The interface LUID of the row.
    pub interface_luid: u64,
    /// Why the route was not proven.
    pub reason: RouteWarningReason,
}

/// The result of a managed-policy check.
///
/// This value proves the exact routes and the listed probe destinations. It
/// records the more-specific routes that the scan reported. A warning is not
/// proof that the route is safe. It does not prove that no other route can
/// bypass the tunnel. Inspect [`RouteProof::warnings`] before a strict gate
/// reports success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteProof {
    /// The proven `0.0.0.0/1` route.
    pub first_half: ProvenRoute,
    /// The proven `128.0.0.0/1` route.
    pub second_half: ProvenRoute,
    /// The proven `2000::/3` route.
    pub ipv6: ProvenRoute,
    /// The managed IPv6 policy that this proof covers.
    ///
    /// This value is never [`Ipv6RoutePolicy::Inherit`]. The inherit policy has
    /// no route to prove and is always an error.
    pub ipv6_policy: Ipv6RoutePolicy,
    /// The number of best-route probes that matched.
    pub probes_checked: usize,
    /// More-specific routes that the scan did not prove.
    ///
    /// A warning for a non-internet range is not proof that the route is safe.
    /// An unproven private, shared, or global route is a failure and is not in
    /// this list.
    pub warnings: Vec<RouteWarning>,
}

/// A managed-policy proof bound to the retained adapter identity.
///
/// The fields are private. Build this value with [`verify_retained`], which
/// checks the retained identity against the policy before it proves a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedRouteProof {
    adapter: RetainedAdapterIdentity,
    proof: RouteProof,
}

impl RetainedRouteProof {
    /// Return the retained adapter that this proof covers.
    pub fn adapter(&self) -> RetainedAdapterIdentity {
        self.adapter
    }

    /// Return the route proof.
    pub fn proof(&self) -> &RouteProof {
        &self.proof
    }
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
    /// A more-specific route inside a managed prefix can carry public internet
    /// traffic on another adapter. Windows uses the longest matching prefix, so
    /// the managed route does not carry that traffic.
    MoreSpecificRoute {
        /// The managed prefix.
        managed: RoutePrefix,
        /// The more-specific prefix on the other adapter.
        competing: RoutePrefix,
        /// The interface index of the other adapter.
        interface_index: u32,
        /// The interface LUID of the other adapter.
        interface_luid: u64,
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
    /// The policy adapter and the retained adapter are not the same.
    RetainedIdentityMismatch {
        /// The interface index in the policy.
        policy_index: u32,
        /// The interface LUID in the policy.
        policy_luid: u64,
        /// The retained interface index.
        retained_index: u32,
        /// The retained interface LUID.
        retained_luid: u64,
    },
    /// The retained LUID now names a different adapter GUID.
    AdapterIdentityChanged {
        /// The retained GUID.
        retained: AdapterGuid,
        /// The GUID that the live lookup returned.
        observed: AdapterGuid,
    },
    /// The retained interface index no longer matches the live index for the
    /// retained LUID.
    InterfaceIndexChanged {
        /// The retained index.
        retained: u32,
        /// The index that the live lookup returned.
        observed: u32,
    },
    /// The host reported no IPv6 stack. The observation is inconclusive for the
    /// IPv6 policy, not proof of a block.
    Ipv6StackAbsent,
    /// The observation did not establish whether the host has an IPv6 stack.
    /// The IPv6 policy is not proven.
    Ipv6StackUnknown,
    /// An IPv6 best-route probe failed. The policy is not proven, and the
    /// failure does not prove that the traffic is blocked.
    Ipv6ProbeInconclusive {
        /// The probe destination.
        destination: IpAddr,
        /// The Windows error code.
        code: u32,
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
            Self::MoreSpecificRoute {
                managed,
                competing,
                interface_index,
                interface_luid,
            } => write!(
                formatter,
                "interface {interface_index} with LUID {interface_luid} has the more specific route {competing} inside {managed}, which is not covered by a proven local subnet, so that traffic can bypass the tunnel"
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
            Self::RetainedIdentityMismatch {
                policy_index,
                policy_luid,
                retained_index,
                retained_luid,
            } => write!(
                formatter,
                "the retained adapter (index {retained_index}, LUID {retained_luid}) is not the policy adapter (index {policy_index}, LUID {policy_luid})"
            ),
            Self::AdapterIdentityChanged { retained, observed } => write!(
                formatter,
                "the retained LUID now names adapter {observed}, not the retained adapter {retained}"
            ),
            Self::InterfaceIndexChanged { retained, observed } => write!(
                formatter,
                "the retained adapter is now interface index {observed}, not the retained index {retained}"
            ),
            Self::Ipv6StackAbsent => write!(
                formatter,
                "Windows reports no IPv6 stack, so the IPv6 policy has no route to prove and this check does not report it as protected"
            ),
            Self::Ipv6StackUnknown => write!(
                formatter,
                "the observation did not establish the IPv6 stack state, so the IPv6 policy is not proven"
            ),
            Self::Ipv6ProbeInconclusive { destination, code } => write!(
                formatter,
                "the {destination} IPv6 probe failed with Windows error {code}; the IPv6 policy is not proven"
            ),
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

impl RouteVerifyError {
    /// A fixed-vocabulary word for a presence failure in diagnostics.
    ///
    /// The word is the variant name, and for a variant that carries a Windows
    /// error code it is the variant name plus that code. It never holds an
    /// address, prefix, next hop, index, LUID, or GUID, so a diagnostics or
    /// probe line built from it cannot leak the hotspot network. Do not put
    /// this word in user-facing status text.
    pub fn presence_kind(&self) -> String {
        match self {
            Self::InvalidTunnelIdentity(_) => "InvalidTunnelIdentity".to_string(),
            Self::InvalidPolicy(_) => "InvalidPolicy".to_string(),
            Self::InvalidObservation(_) => "InvalidObservation".to_string(),
            Self::MissingRoute { .. } => "MissingRoute".to_string(),
            Self::ForeignRoute { .. } => "ForeignRoute".to_string(),
            Self::IndexReused { .. } => "IndexReused".to_string(),
            Self::CompetingRoute { .. } => "CompetingRoute".to_string(),
            Self::MoreSpecificRoute { .. } => "MoreSpecificRoute".to_string(),
            Self::DuplicateTunnelRoute { .. } => "DuplicateTunnelRoute".to_string(),
            Self::UnexpectedNextHop { .. } => "UnexpectedNextHop".to_string(),
            Self::LoopbackRoute { .. } => "LoopbackRoute".to_string(),
            Self::BestInterfaceMismatch { .. } => "BestInterfaceMismatch".to_string(),
            Self::BestRouteMismatch { .. } => "BestRouteMismatch".to_string(),
            Self::BestRouteIdentityMismatch { .. } => "BestRouteIdentityMismatch".to_string(),
            Self::MissingBestRoute { .. } => "MissingBestRoute".to_string(),
            Self::RetainedIdentityMismatch { .. } => "RetainedIdentityMismatch".to_string(),
            Self::AdapterIdentityChanged { .. } => "AdapterIdentityChanged".to_string(),
            Self::InterfaceIndexChanged { .. } => "InterfaceIndexChanged".to_string(),
            Self::Ipv6StackAbsent => "Ipv6StackAbsent".to_string(),
            Self::Ipv6StackUnknown => "Ipv6StackUnknown".to_string(),
            Self::Ipv6ProbeInconclusive { code, .. } => {
                format!("Ipv6ProbeInconclusive({code})")
            }
            Self::Ipv6InheritNotVerifiable => "Ipv6InheritNotVerifiable".to_string(),
            Self::Api { code, .. } => format!("Api({code})"),
        }
    }
}

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

fn validate_ipv6_source(policy: &VerifyPolicy) -> Result<(), RouteVerifyError> {
    let Some(source) = policy.ipv6_source else {
        return Ok(());
    };
    if policy.ipv6 == Ipv6RoutePolicy::Block {
        return Err(RouteVerifyError::InvalidPolicy(
            "the block policy does not use an IPv6 source address",
        ));
    }
    if source.is_unspecified()
        || source.is_multicast()
        || source.is_loopback()
        || source.to_ipv4_mapped().is_some()
    {
        return Err(RouteVerifyError::InvalidPolicy(
            "the IPv6 source address must be a unicast address, and this check cannot prove that the tunnel adapter owns it",
        ));
    }
    Ok(())
}

fn validate_local_subnets(policy: &VerifyPolicy) -> Result<(), RouteVerifyError> {
    for (position, subnet) in policy.local_subnets.iter().enumerate() {
        let adapter = subnet.adapter();
        // The local proof names the physical adapter. The tunnel adapter is
        // never the local hotspot link, so a shared index or LUID is a policy
        // error, not an allowance for routes on the tunnel.
        if adapter.interface_index() == policy.tunnel.interface_index
            || adapter.interface_luid() == policy.tunnel.interface_luid
        {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet adapter has the tunnel adapter identity",
            ));
        }
        // Two subnets on one adapter must name it with the same three values.
        // A shared index or LUID with any other difference is ambiguous.
        for earlier in &policy.local_subnets[..position] {
            let earlier = earlier.adapter();
            let shares = earlier.interface_index() == adapter.interface_index()
                || earlier.interface_luid() == adapter.interface_luid()
                || earlier.interface_guid() == adapter.interface_guid();
            if shares && earlier != adapter {
                return Err(RouteVerifyError::InvalidPolicy(
                    "two local subnets name one adapter with different identities",
                ));
            }
        }
        let prefix = subnet.prefix();
        if !prefix.is_valid() {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet has an invalid prefix",
            ));
        }
        if prefix.family() == AddressFamily::V6 && policy.ipv6 == Ipv6RoutePolicy::Block {
            return Err(RouteVerifyError::InvalidPolicy(
                "IPv6 local subnet exceptions are not allowed in block mode",
            ));
        }
        let managed_length = match prefix.family() {
            AddressFamily::V4 => IPV4_ROUTES[0].length,
            AddressFamily::V6 => IPV6_TUNNEL_ROUTE.length,
        };
        if prefix.length <= managed_length {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet must be more specific than the managed prefix",
            ));
        }
        let link_length = match prefix.family() {
            AddressFamily::V4 => MIN_LOCAL_IPV4_LENGTH,
            AddressFamily::V6 => MIN_LOCAL_IPV6_LENGTH,
        };
        if prefix.length < link_length {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet is too broad for one hotspot link",
            ));
        }
        for destination in &policy.ipv4_probes {
            if prefix.contains(IpAddr::V4(*destination)) {
                return Err(RouteVerifyError::InvalidPolicy(
                    "a local subnet contains a best-route probe destination",
                ));
            }
        }
        for destination in &policy.ipv6_probes {
            if prefix.contains(IpAddr::V6(*destination)) {
                return Err(RouteVerifyError::InvalidPolicy(
                    "a local subnet contains a best-route probe destination",
                ));
            }
        }
    }
    Ok(())
}

fn validate_managed_policy(policy: &VerifyPolicy) -> Result<(), RouteVerifyError> {
    validate_probe_lists(policy)?;
    validate_ipv6_source(policy)?;
    validate_local_subnets(policy)?;
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
    if !observation.ipv6_stack.is_present() && !observation.ipv6_routes.is_empty() {
        return Err(RouteVerifyError::InvalidObservation(
            "the observation has IPv6 routes but the IPv6 stack state is not present",
        ));
    }
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
/// It also returns an error for a more-specific route inside a managed prefix
/// that is not covered by a proven local subnet. Private, shared, and global
/// destinations are all handled the same way: without proof the route is a
/// failure. A route that cannot carry global internet unicast is returned in
/// [`RouteProof::warnings`] and is not proof that the route is safe. It also
/// returns an error for the [`Ipv6RoutePolicy::Inherit`] policy, because that
/// policy has no tunnel route to prove. Do not report the inherit policy as
/// verified.
///
/// It returns an error when the observation does not prove that the IPv6 stack
/// is present. A block policy is not reported as protected on an unknown or
/// absent stack.
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
    match observation.ipv6_stack {
        Ipv6Stack::Present => {}
        Ipv6Stack::Absent => return Err(RouteVerifyError::Ipv6StackAbsent),
        Ipv6Stack::Unknown => return Err(RouteVerifyError::Ipv6StackUnknown),
    }

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
    let mut warnings = scan_more_specific(
        observation.routes_for(AddressFamily::V4),
        IPV4_ROUTES[0],
        policy.tunnel,
        &policy.local_subnets,
    )?;
    warnings.extend(scan_more_specific(
        observation.routes_for(AddressFamily::V4),
        IPV4_ROUTES[1],
        policy.tunnel,
        &policy.local_subnets,
    )?);
    let ipv6 = prove_exact(
        observation.routes_for(AddressFamily::V6),
        IPV6_TUNNEL_ROUTE,
        policy.tunnel,
    )?;
    warnings.extend(scan_more_specific(
        observation.routes_for(AddressFamily::V6),
        IPV6_TUNNEL_ROUTE,
        policy.tunnel,
        &policy.local_subnets,
    )?);

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
        warnings,
    })
}

/// Prove a managed policy and bind the result to a retained adapter identity.
///
/// This function is pure. It requires the policy adapter to match the retained
/// index and LUID, then calls [`verify`]. The returned proof carries the
/// retained identity so that a caller cannot pair one adapter's proof with
/// another adapter's identity.
///
/// A live caller must also read the live GUID and index for the retained LUID.
/// Use the Windows `verify_live_retained` function for that check. This pure
/// function cannot read the operating system.
pub fn verify_retained(
    observation: &RouteObservation,
    policy: &VerifyPolicy,
    retained: &RetainedAdapterIdentity,
) -> Result<RetainedRouteProof, RouteVerifyError> {
    check_retained_binding(policy, retained)?;
    let proof = verify(observation, policy)?;
    Ok(RetainedRouteProof {
        adapter: *retained,
        proof,
    })
}

/// Check that the retained tunnel identity matches the policy and that no
/// local subnet adapter shares any tunnel identity value.
///
/// This check is pure. It compares identity values only. It cannot detect a
/// local adapter that is another tunnel type, such as a third-party VPN
/// adapter, and it cannot prove that the local adapter is physical.
fn check_retained_binding(
    policy: &VerifyPolicy,
    retained: &RetainedAdapterIdentity,
) -> Result<(), RouteVerifyError> {
    let tunnel = retained.tunnel();
    if tunnel.interface_index != policy.tunnel.interface_index
        || tunnel.interface_luid != policy.tunnel.interface_luid
    {
        return Err(RouteVerifyError::RetainedIdentityMismatch {
            policy_index: policy.tunnel.interface_index,
            policy_luid: policy.tunnel.interface_luid,
            retained_index: tunnel.interface_index,
            retained_luid: tunnel.interface_luid,
        });
    }
    for subnet in &policy.local_subnets {
        let adapter = subnet.adapter();
        if adapter.interface_index() == retained.interface_index()
            || adapter.interface_luid() == retained.interface_luid()
            || adapter.interface_guid() == retained.interface_guid()
        {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet adapter has the tunnel adapter identity",
            ));
        }
    }
    Ok(())
}

/// Return each distinct local subnet adapter in the policy, in policy order.
#[cfg(any(windows, test))]
fn local_adapters(policy: &VerifyPolicy) -> Vec<RetainedAdapterIdentity> {
    let mut adapters: Vec<RetainedAdapterIdentity> = Vec::new();
    for subnet in &policy.local_subnets {
        let adapter = subnet.adapter();
        if !adapters.contains(&adapter) {
            adapters.push(adapter);
        }
    }
    adapters
}

/// Run a retained verification with every adapter identity confirmed before
/// and after the observation.
///
/// The confirmed adapters are the retained tunnel adapter and each distinct
/// local physical adapter that a [`ProvenLocalSubnet`] names. A route row
/// carries only the index and LUID, so this live confirmation is the only
/// check that uses the retained GUID of a local adapter.
///
/// The pure binding and local subnet checks run first, so a local adapter that
/// shares a tunnel identity value stops the check before any read. The first
/// confirmation round stops a stale retained identity before any route is
/// read. The second round runs after the observation and before the pure route
/// check. The two rounds bracket the route data and prove each adapter unit at
/// those two moments, not continuous ownership. Each confirmation is a
/// separate read, so the rounds are not one atomic snapshot of every adapter.
/// The confirmation does not prove that a local adapter is physical, that it
/// is the hotspot link, or that it owns the subnet prefix. The live Windows
/// caller supplies `confirm_retained_identity` and `observe`. Tests supply
/// fixed closures.
#[cfg(any(windows, test))]
fn verify_between_identity_confirmations<C, O>(
    policy: &VerifyPolicy,
    retained: &RetainedAdapterIdentity,
    mut confirm: C,
    observe: O,
) -> Result<RetainedRouteProof, RouteVerifyError>
where
    C: FnMut(&RetainedAdapterIdentity) -> Result<LiveAdapterIdentity, RouteVerifyError>,
    O: FnOnce() -> Result<RouteObservation, RouteVerifyError>,
{
    check_retained_binding(policy, retained)?;
    validate_local_subnets(policy)?;
    let locals = local_adapters(policy);
    confirm(retained)?;
    for adapter in &locals {
        confirm(adapter)?;
    }
    let observation = observe()?;
    // Second moment: every retained LUID must still name the same adapter after
    // the route reads. Windows has no atomic identity-and-route read.
    confirm(retained)?;
    for adapter in &locals {
        confirm(adapter)?;
    }
    verify_retained(&observation, policy, retained)
}

/// The destinations that `default_ipv4_gateway` probes. One is in each managed
/// IPv4 half, so a split-default route for either half fails the check.
///
/// The probes check the selected route. They send no packet.
#[cfg(any(windows, test))]
const DEFAULT_GATEWAY_PROBES: [Ipv4Addr; 2] =
    [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(208, 67, 222, 222)];

/// The fixed error code of the Windows token gate.
///
/// Every refusal uses this one code. It names no gateway, address, LUID,
/// GUID, or Windows error, so a status answer, a log line, or an error text
/// cannot leak the hotspot network. The GUI maps it to fixed text.
#[cfg(any(windows, test))]
pub(crate) const TOKEN_DESTINATION_REFUSED: &str = "source_gateway_unproven";

/// The single gate before any source device token byte leaves this process on
/// Windows.
///
/// Call it at each token use: the service start check, every presence probe,
/// and every manual check. It runs the read-only physical adapter and default
/// gateway check in `windows_physical_path::observe_token_destination` and
/// returns the proven physical adapter identity, so a running tunnel can
/// require the same adapter at later probes.
///
/// The destination must be numeric IPv4, its port must be nonzero, and the
/// caller must name the interface index that the outer socket pins to. The
/// destination must equal the gateway of the genuine `0.0.0.0/0` route on that
/// interface, as selected by the default best-route probes. The interface must
/// be a physical Ethernet or IEEE 802.11 adapter with no tunnel type and no
/// filter flag, whose LUID, GUID, and index agree before and after the reads.
/// Without `run`, the unscoped probes must select the same physical default
/// route. With `run`, they may also select the exact `/1` routes of the
/// tunnel adapter that this process owns. A VPN, a split default route, a
/// second default route, a loopback row, a virtual adapter, a mismatched
/// identity, or a failed read returns [`TOKEN_DESTINATION_REFUSED`].
///
/// This is the same trust level as the macOS and Linux gateway checks. It does
/// not authenticate the source device: any device at the gateway address can
/// accept the v1 token, and that token crosses the hotspot link in cleartext.
/// The reads are separate Windows calls, so the result is evidence at those
/// moments, not a lock.
#[cfg(windows)]
pub(crate) fn require_token_destination_proof(
    destination: std::net::SocketAddr,
    pinned_index: Option<u32>,
    run: Option<crate::windows_physical_path::TokenRun>,
) -> std::io::Result<RetainedAdapterIdentity> {
    require_token_destination_with(destination, pinned_index, |address, index| {
        crate::windows_physical_path::observe_token_destination(address, index, run.as_ref())
    })
}

/// The shape checks of [`require_token_destination_proof`] around an
/// injected observation. Tests pass a fake route and adapter table.
#[cfg(any(windows, test))]
pub(crate) fn require_token_destination_with<F>(
    destination: std::net::SocketAddr,
    pinned_index: Option<u32>,
    observe: F,
) -> std::io::Result<RetainedAdapterIdentity>
where
    F: FnOnce(
        Ipv4Addr,
        u32,
    ) -> Result<
        crate::windows_physical_path::PhysicalPathProof,
        crate::windows_physical_path::PhysicalPathError,
    >,
{
    let refused =
        || std::io::Error::new(std::io::ErrorKind::NotConnected, TOKEN_DESTINATION_REFUSED);
    let std::net::SocketAddr::V4(destination) = destination else {
        return Err(refused());
    };
    let Some(index) = pinned_index.filter(|index| valid_interface_index(*index)) else {
        return Err(refused());
    };
    if destination.port() == 0 {
        return Err(refused());
    }
    observe(*destination.ip(), index)
        .map(|proof| proof.adapter())
        .map_err(|_| refused())
}

/// Select the IPv4 default gateway from best-route probes.
///
/// Every probe must select the genuine `0.0.0.0/0` route, not a more-specific
/// route such as a VPN split-default `0.0.0.0/1` or `128.0.0.0/1`. The
/// selected row must be on the interface that `GetBestInterfaceEx` chose, must
/// have a nonzero LUID, must not be a loopback row, and must have a unicast
/// IPv4 next hop. Every probe must agree on the interface, the LUID, and the
/// next hop. Any other result is an error, never a fallback.
///
/// This check proves only that Windows selected one `/0` route with a gateway
/// for the probe destinations at the time of the read. It does not prove that
/// the gateway is a source device, that the interface is physical, or that
/// the interface is the hotspot link. A full VPN that installs its own `/0`
/// route with a gateway still passes this check. The caller must keep its own
/// interface and address checks.
#[cfg(any(windows, test))]
fn select_default_ipv4_gateway(
    probes: &[BestRouteProbe],
) -> Result<(Ipv4Addr, u32), RouteVerifyError> {
    let default_route = RoutePrefix {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        length: 0,
    };
    let mut selected: Option<(Ipv4Addr, u32, u64)> = None;
    for probe in probes {
        if !matches!(probe.destination, IpAddr::V4(_)) {
            return Err(RouteVerifyError::InvalidObservation(
                "a default gateway probe is not an IPv4 destination",
            ));
        }
        if !valid_interface_index(probe.best_interface_index) {
            return Err(RouteVerifyError::InvalidObservation(
                "GetBestInterfaceEx returned an invalid interface index",
            ));
        }
        let route = &probe.route;
        if route.prefix != default_route {
            return Err(RouteVerifyError::InvalidObservation(
                "the selected IPv4 route is not the 0.0.0.0/0 default route",
            ));
        }
        if route.interface_index != probe.best_interface_index {
            return Err(RouteVerifyError::InvalidObservation(
                "the default route is not on the interface that Windows selected",
            ));
        }
        if route.interface_luid == 0 {
            return Err(RouteVerifyError::InvalidObservation(
                "the default route has a zero interface LUID",
            ));
        }
        if route.loopback {
            return Err(RouteVerifyError::InvalidObservation(
                "the default route is a loopback route",
            ));
        }
        let IpAddr::V4(gateway) = route.next_hop else {
            return Err(RouteVerifyError::InvalidObservation(
                "the default route has no IPv4 gateway",
            ));
        };
        if gateway.is_unspecified()
            || gateway.is_loopback()
            || gateway.is_multicast()
            || gateway.is_broadcast()
        {
            return Err(RouteVerifyError::InvalidObservation(
                "the default route has no unicast IPv4 gateway",
            ));
        }
        let current = (gateway, route.interface_index, route.interface_luid);
        match selected {
            None => selected = Some(current),
            Some(previous) if previous == current => {}
            Some(_) => {
                return Err(RouteVerifyError::InvalidObservation(
                    "the default gateway probes selected different routes",
                ))
            }
        }
    }
    selected.map(|(gateway, index, _)| (gateway, index)).ok_or(
        RouteVerifyError::InvalidObservation("the default gateway check has no probe"),
    )
}

/// Map a failed IPv6 route table read to a verification error.
///
/// Only the documented `ERROR_NOT_SUPPORTED` value means the host has no IPv6
/// stack. Every other value keeps the API operation and code, so the caller
/// cannot mistake an inconclusive read for an absent stack.
#[cfg(any(windows, test))]
fn ipv6_table_failure(code: u32) -> RouteVerifyError {
    if code == ERROR_NOT_SUPPORTED {
        RouteVerifyError::Ipv6StackAbsent
    } else {
        RouteVerifyError::Api {
            operation: "GetIpForwardTable2",
            code,
        }
    }
}

/// Map a failed IPv6 best-route probe to a verification error.
///
/// A probe runs only after a successful IPv6 table read, so the observation
/// already proved the IPv6 stack present. Every probe failure is therefore
/// inconclusive, including the documented `ERROR_NOT_SUPPORTED` value. That
/// value cannot prove an absent stack here, and it must never be reported as
/// proof that the traffic is blocked.
#[cfg(any(windows, test))]
fn ipv6_probe_failure(destination: IpAddr, code: u32) -> RouteVerifyError {
    RouteVerifyError::Ipv6ProbeInconclusive { destination, code }
}

/// Return the scope id for an IPv6 source address on one interface.
///
/// A link-local address is scoped to its interface. Windows expects the
/// interface index in `sin6_scope_id` for such an address. Every other address
/// uses a zero scope id.
#[cfg(any(windows, test))]
fn source_scope(source: Ipv6Addr, interface_index: u32) -> u32 {
    if source.is_unicast_link_local() {
        interface_index
    } else {
        0
    }
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

fn prefix_is_within(prefix: RoutePrefix, block: RoutePrefix) -> bool {
    prefix.family() == block.family()
        && block.length <= prefix.length
        && block.contains(prefix.address)
}

/// Return true when a prefix has no address that can be ordinary global
/// internet unicast traffic.
///
/// The check is conservative in the other direction: a prefix that spans a
/// non-internet block and a public block is in scope. The module documentation
/// lists the blocks and the limits of this classification. Private and shared
/// ranges are deliberately not in the list, because a route for them can carry
/// hotspot or carrier traffic that would otherwise bypass the tunnel.
fn non_internet_range(prefix: RoutePrefix) -> bool {
    let blocks: &[RoutePrefix] = match prefix.family() {
        AddressFamily::V4 => &IPV4_NON_INTERNET,
        AddressFamily::V6 => &IPV6_NON_INTERNET,
    };
    blocks.iter().any(|block| prefix_is_within(prefix, *block))
}

/// Report a more-specific route inside a managed prefix that another adapter
/// owns and that no proven local subnet covers.
///
/// A row that the tunnel adapter owns is not a bypass. Ownership requires both
/// the interface index and the interface LUID to match, because either value
/// alone can describe another adapter. A row covered by a caller-proven local
/// subnet on the same retained adapter is expected. A row for a non-internet
/// range is returned as a warning, not a success. Every other row is a failure.
fn scan_more_specific(
    routes: &[ObservedRoute],
    managed: RoutePrefix,
    tunnel: TunnelIdentity,
    local_subnets: &[ProvenLocalSubnet],
) -> Result<Vec<RouteWarning>, RouteVerifyError> {
    let mut warnings = Vec::new();
    for route in routes {
        if route.prefix.length <= managed.length {
            continue;
        }
        if !managed.contains(route.prefix.address) {
            continue;
        }
        if route.interface_index == tunnel.interface_index
            && route.interface_luid == tunnel.interface_luid
        {
            continue;
        }
        if local_subnets.iter().any(|subnet| subnet.covers(route)) {
            continue;
        }
        if non_internet_range(route.prefix) {
            warnings.push(RouteWarning {
                prefix: route.prefix,
                interface_index: route.interface_index,
                interface_luid: route.interface_luid,
                reason: RouteWarningReason::NonInternetRange,
            });
            continue;
        }
        return Err(RouteVerifyError::MoreSpecificRoute {
            managed,
            competing: route.prefix,
            interface_index: route.interface_index,
            interface_luid: route.interface_luid,
        });
    }
    Ok(warnings)
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
pub use win32::{
    confirm_retained_identity, default_ipv4_gateway, observe, read_live_identity, verify_live,
    verify_live_retained,
};

#[cfg(windows)]
mod win32 {
    //! Windows ABI layer.
    //!
    //! The type layout is checked at compile time for both MSVC targets. The
    //! checks below assert the offsets that the Microsoft headers define.

    use super::{
        ipv6_probe_failure, ipv6_table_failure, source_scope, validate_managed_policy,
        validate_tunnel, AdapterGuid, BestRouteProbe, Ipv6Stack, LiveAdapterIdentity,
        ObservedRoute, RetainedAdapterIdentity, RetainedRouteProof, RouteObservation, RoutePrefix,
        RouteProof, RouteVerifyError, VerifyPolicy, AF_INET, AF_INET6,
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
        fn ConvertInterfaceLuidToGuid(
            interface_luid: *const u64,
            interface_guid: *mut AdapterGuid,
        ) -> u32;
        fn ConvertInterfaceLuidToIndex(
            interface_luid: *const u64,
            interface_index: *mut u32,
        ) -> u32;
        fn FreeMibTable(memory: *mut c_void);
    }

    /// Read the live identity values for one interface LUID.
    ///
    /// The call reads `ConvertInterfaceLuidToGuid` and
    /// `ConvertInterfaceLuidToIndex`. It changes nothing. Any nonzero status is
    /// an error with the API name and code. A failed lookup is never reported as
    /// a zero GUID or a zero index. The two reads are separate calls, so the
    /// result is a snapshot, not a lock.
    pub fn read_live_identity(
        interface_luid: u64,
    ) -> Result<LiveAdapterIdentity, RouteVerifyError> {
        if interface_luid == 0 {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface LUID must be nonzero",
            ));
        }
        let mut interface_guid = AdapterGuid::ZERO;
        // SAFETY: The LUID pointer is valid for one initialized value. The GUID
        // pointer is valid for one `GUID` value, and `AdapterGuid` has the same
        // 16-byte layout.
        let status = unsafe { ConvertInterfaceLuidToGuid(&interface_luid, &mut interface_guid) };
        if status != 0 {
            return Err(RouteVerifyError::Api {
                operation: "ConvertInterfaceLuidToGuid",
                code: status,
            });
        }
        let mut interface_index: u32 = 0;
        // SAFETY: The LUID pointer is valid and the index pointer is valid for
        // one `NET_IFINDEX` value.
        let status = unsafe { ConvertInterfaceLuidToIndex(&interface_luid, &mut interface_index) };
        if status != 0 {
            return Err(RouteVerifyError::Api {
                operation: "ConvertInterfaceLuidToIndex",
                code: status,
            });
        }
        Ok(LiveAdapterIdentity {
            interface_index,
            interface_guid,
        })
    }

    /// Prove that the retained LUID still names the retained adapter.
    ///
    /// This call reads the GUID and the index for the retained LUID. It changes
    /// nothing. It fails when the GUID differs, the index differs, or either
    /// live value is invalid. It does not prove who created the adapter. One
    /// identity read is not atomic with any route read. `verify_live_retained`
    /// calls this function before and after its observation to bracket the
    /// route reads.
    pub fn confirm_retained_identity(
        retained: &RetainedAdapterIdentity,
    ) -> Result<LiveAdapterIdentity, RouteVerifyError> {
        let live = read_live_identity(retained.interface_luid())?;
        retained.matches(live)?;
        Ok(live)
    }

    /// Return the next-hop IPv4 address and interface index for the current
    /// default route.
    ///
    /// This call reads the live routing table through `GetBestInterfaceEx` and
    /// `GetBestRoute2` for one destination in each IPv4 half. It changes
    /// nothing. Each selected row must be the genuine `0.0.0.0/0` route on the
    /// selected interface, not loopback, with a unicast gateway, and both rows
    /// must agree. A VPN split-default `/1` route fails the check instead of
    /// naming the VPN gateway. An on-link route also fails, so it cannot be
    /// mistaken for a hotspot gateway. See `select_default_ipv4_gateway` for
    /// the limits of this result.
    pub fn default_ipv4_gateway() -> Result<(Ipv4Addr, u32), RouteVerifyError> {
        let mut probes = Vec::with_capacity(super::DEFAULT_GATEWAY_PROBES.len());
        for destination in super::DEFAULT_GATEWAY_PROBES {
            probes.push(best_route(IpAddr::V4(destination), None)?);
        }
        super::select_default_ipv4_gateway(&probes)
    }

    /// Read the route table and the best routes for one policy.
    ///
    /// This function never changes a route and never creates a device. It
    /// returns an error for every API failure. It does not turn a failure into
    /// an empty table, and it does not skip the IPv6 proof.
    ///
    /// The IPv6 table read decides the stack state. A successful read sets
    /// [`Ipv6Stack::Present`]. The documented `ERROR_NOT_SUPPORTED` value
    /// returns [`RouteVerifyError::Ipv6StackAbsent`]. Every other error keeps
    /// the API operation and code. A probe failure is always inconclusive,
    /// because the table read already proved the stack present. A probe that
    /// returns `ERROR_NOT_SUPPORTED` after that read is a contradiction, not an
    /// absent stack.
    pub fn observe(policy: &VerifyPolicy) -> Result<RouteObservation, RouteVerifyError> {
        validate_tunnel(policy.tunnel)?;
        if !policy.ipv6.is_managed() {
            return Err(RouteVerifyError::Ipv6InheritNotVerifiable);
        }
        validate_managed_policy(policy)?;

        let ipv4_routes = snapshot(AF_INET)?;
        let ipv6_routes = ipv6_snapshot()?;

        let mut probes = Vec::with_capacity(policy.ipv4_probes.len() + policy.ipv6_probes.len());
        for destination in &policy.ipv4_probes {
            probes.push(best_route(IpAddr::V4(*destination), None)?);
        }
        let source = policy.ipv6_source.map(IpAddr::V6);
        for destination in &policy.ipv6_probes {
            probes.push(best_route(IpAddr::V6(*destination), source)?);
        }
        Ok(RouteObservation {
            ipv4_routes,
            ipv6_routes,
            ipv6_stack: Ipv6Stack::Present,
            probes,
        })
    }

    /// Observe the live route data and prove the managed policy.
    ///
    /// The caller must install the routes and resolve the tunnel adapter index
    /// before this call. The call reads the table and the selected routes. It
    /// changes nothing. A source hint comes from the policy. A policy with a
    /// local subnet is refused, because this call has no live identity check
    /// for the local adapter. Use `verify_live_retained` for that policy.
    pub fn verify_live(policy: &VerifyPolicy) -> Result<RouteProof, RouteVerifyError> {
        // A local subnet allowance depends on the retained GUID of its local
        // adapter. This function has no live identity check, so it refuses the
        // allowance instead of trusting a reusable index and LUID.
        if !policy.local_subnets.is_empty() {
            return Err(RouteVerifyError::InvalidPolicy(
                "a local subnet needs the retained identity check in verify_live_retained",
            ));
        }
        let observation = observe(policy)?;
        super::verify(&observation, policy)
    }

    /// Confirm the retained adapters before and after the route reads, then
    /// prove the managed policy.
    ///
    /// The call reads the live GUID and index for the retained tunnel LUID and
    /// for the LUID of each local physical adapter in the policy, then reads
    /// the route table and the selected routes, then reads every identity
    /// again. It changes nothing. A local adapter that shares an index, LUID,
    /// or GUID with the tunnel stops the check before any read. A different
    /// GUID or index stops the check before or after the route reads. The
    /// identity reads bracket the observation and prove each adapter unit at
    /// those two moments, not continuous ownership. Windows offers no atomic
    /// identity-and-route read, so an adapter can change after the second
    /// read. The check does not prove that a local adapter is physical, is the
    /// hotspot link, or owns its subnet prefix.
    pub fn verify_live_retained(
        policy: &VerifyPolicy,
        retained: &RetainedAdapterIdentity,
    ) -> Result<RetainedRouteProof, RouteVerifyError> {
        super::verify_between_identity_confirmations(
            policy,
            retained,
            confirm_retained_identity,
            || observe(policy),
        )
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

    fn ipv6_snapshot() -> Result<Vec<ObservedRoute>, RouteVerifyError> {
        match snapshot(AF_INET6) {
            Ok(routes) => Ok(routes),
            Err(RouteVerifyError::Api { code, .. }) => Err(ipv6_table_failure(code)),
            Err(error) => Err(error),
        }
    }

    fn best_route(
        destination: IpAddr,
        source: Option<IpAddr>,
    ) -> Result<BestRouteProbe, RouteVerifyError> {
        // `GetBestRoute2` is interface scoped. Ask it for the tunnel interface
        // and it returns the tunnel route even when Windows would send the
        // packet through another adapter. Select the interface first with
        // `GetBestInterfaceEx`, then ask for the route on that interface.
        let destination_raw = sockaddr(destination, 0);
        let mut best_interface_index: u32 = 0;
        // SAFETY: The destination points to an initialized `SOCKADDR_INET`.
        // The output pointer is valid for one `NET_IFINDEX`.
        let status = unsafe { GetBestInterfaceEx(&destination_raw, &mut best_interface_index) };
        if status != 0 {
            return Err(match destination {
                IpAddr::V6(_) => ipv6_probe_failure(destination, status),
                IpAddr::V4(_) => RouteVerifyError::Api {
                    operation: "GetBestInterfaceEx",
                    code: status,
                },
            });
        }
        if best_interface_index == 0 || best_interface_index > super::MAX_INTERFACE_INDEX {
            return Err(RouteVerifyError::InvalidObservation(
                "GetBestInterfaceEx returned an invalid interface index",
            ));
        }

        // A source hint is scoped to the interface that this call uses. A
        // link-local source needs that index in `sin6_scope_id`. The hint is
        // only a lookup constraint: this module does not read the best source
        // back and cannot prove that the adapter owns the hinted address.
        let source_raw = source.map(|source| {
            let scope = match source {
                IpAddr::V6(address) => source_scope(address, best_interface_index),
                IpAddr::V4(_) => 0,
            };
            sockaddr(source, scope)
        });
        let source_pointer = match source_raw.as_ref() {
            Some(value) => value as *const RawSockaddrInet,
            None => ptr::null(),
        };

        // `InterfaceLuid` is optional. Pass a null pointer and a nonzero
        // interface index. Microsoft documents that the parameters are used in
        // order, and that the interface index is used when no LUID is set.
        let mut row: RawMibIpForwardRow2 = unsafe { std::mem::zeroed() };
        let mut best_source: RawSockaddrInet = unsafe { std::mem::zeroed() };
        // SAFETY: The destination and source pointers are valid. The row and
        // source output pointers are valid for one value each. A null LUID with
        // a nonzero interface index is the documented optional form. A null
        // source address is allowed.
        let status = unsafe {
            GetBestRoute2(
                ptr::null(),
                best_interface_index,
                source_pointer,
                &destination_raw,
                0,
                &mut row,
                &mut best_source,
            )
        };
        if status != 0 {
            return Err(match destination {
                IpAddr::V6(_) => ipv6_probe_failure(destination, status),
                IpAddr::V4(_) => RouteVerifyError::Api {
                    operation: "GetBestRoute2",
                    code: status,
                },
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

    fn sockaddr(address: IpAddr, scope_id: u32) -> RawSockaddrInet {
        match address {
            IpAddr::V4(address) => {
                // Initialize the whole union, not only the 16-byte IPv4 member.
                // The union is 28 bytes because of `SOCKADDR_IN6`, and the
                // pointer is passed to `GetBestRoute2` and `GetBestInterfaceEx`
                // as `*const SOCKADDR_INET`. Starting from an initialized IPv6
                // member and then assigning the IPv4 member leaves no
                // uninitialized tail bytes for the FFI call to observe.
                let mut raw = RawSockaddrInet {
                    v6: RawSockaddrIn6 {
                        family: AF_INET,
                        port: 0,
                        flow_info: 0,
                        address: [0; 16],
                        scope_id: 0,
                    },
                };
                raw.v4 = RawSockaddrIn {
                    family: AF_INET,
                    port: 0,
                    address: address.octets(),
                    zero: [0; 8],
                };
                raw
            }
            IpAddr::V6(address) => RawSockaddrInet {
                v6: RawSockaddrIn6 {
                    family: AF_INET6,
                    port: 0,
                    flow_info: 0,
                    address: address.octets(),
                    scope_id,
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
            sockaddr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
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
            let v4 = sockaddr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 0);
            assert_eq!(v4.family(), AF_INET);
            assert_eq!(unsafe { v4.v4.address }, [192, 0, 2, 1]);

            let v6 = sockaddr(IpAddr::V6("2001:db8::1".parse().unwrap()), 0);
            assert_eq!(v6.family(), AF_INET6);
            assert_eq!(
                unsafe { v6.v6.address },
                "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
            );
            assert_eq!(unsafe { v6.v6.scope_id }, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_gate_checks_the_shape_before_any_read() {
        use crate::windows_physical_path::PhysicalPathError;
        use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
        let gateway = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 20, 10, 1), 1080));
        let mut reads = 0;
        let mut refuse = |_: Ipv4Addr, _: u32| {
            reads += 1;
            Err(PhysicalPathError::DestinationMismatch)
        };
        for (destination, pin) in [
            (
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1080, 0, 0)),
                Some(7),
            ),
            (gateway, None),
            (gateway, Some(0)),
            (gateway, Some(MAX_INTERFACE_INDEX + 1)),
            (
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 20, 10, 1), 0)),
                Some(7),
            ),
        ] {
            let error = require_token_destination_with(destination, pin, &mut refuse).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
            assert_eq!(error.to_string(), TOKEN_DESTINATION_REFUSED);
        }
        assert_eq!(reads, 0);
        // A failed observation is the same fixed refusal. The text holds no
        // address and no Windows error.
        let error = require_token_destination_with(gateway, Some(7), |address, index| {
            assert_eq!(address, Ipv4Addr::new(172, 20, 10, 1));
            assert_eq!(index, 7);
            Err(PhysicalPathError::GatewayUnusable("test"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), TOKEN_DESTINATION_REFUSED);
        assert!(!error.to_string().contains("172.20"));
    }

    #[test]
    fn presence_kind_names_the_variant_and_never_an_address() {
        let prefix = RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(172, 20, 10, 0)), 28).unwrap();
        let next_hop = IpAddr::V4(Ipv4Addr::new(172, 20, 9, 254));
        let cases: Vec<(RouteVerifyError, String)> = vec![
            (
                RouteVerifyError::MissingRoute { prefix },
                "MissingRoute".to_string(),
            ),
            (
                RouteVerifyError::UnexpectedNextHop { prefix, next_hop },
                "UnexpectedNextHop".to_string(),
            ),
            (
                RouteVerifyError::InvalidObservation("the default route is a loopback route"),
                "InvalidObservation".to_string(),
            ),
            (
                RouteVerifyError::Api {
                    operation: "GetBestRoute2",
                    code: 5,
                },
                "Api(5)".to_string(),
            ),
            (
                RouteVerifyError::Ipv6ProbeInconclusive {
                    destination: IpAddr::V6("2001:db8::1".parse().unwrap()),
                    code: 123,
                },
                "Ipv6ProbeInconclusive(123)".to_string(),
            ),
            (
                RouteVerifyError::Ipv6StackAbsent,
                "Ipv6StackAbsent".to_string(),
            ),
        ];
        for (error, expected) in cases {
            let text = error.presence_kind();
            assert_eq!(text, expected);
            assert!(!text.contains("172.20.10.0"), "{text}");
            assert!(!text.contains("172.20.9.254"), "{text}");
            assert!(!text.contains("2001:db8"), "{text}");
        }
    }

    const INDEX: u32 = 7;
    const LUID: u64 = 0x0000_6000_0000_0007;
    const OTHER_INDEX: u32 = 12;
    const OTHER_LUID: u64 = 0x0000_6000_0000_000c;
    const THIRD_INDEX: u32 = 18;
    const THIRD_LUID: u64 = 0x0000_6000_0000_0012;

    fn tunnel() -> TunnelIdentity {
        TunnelIdentity::new(INDEX, LUID).unwrap()
    }

    fn local_subnet(
        prefix: RoutePrefix,
        ifindex: u32,
        luid: u64,
        provenance: LocalSubnetProvenance,
    ) -> ProvenLocalSubnet {
        ProvenLocalSubnet::new(
            prefix,
            RetainedAdapterIdentity::new(ifindex, luid, local_guid()).unwrap(),
            provenance,
        )
        .unwrap()
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

    fn guid() -> AdapterGuid {
        AdapterGuid::new(
            0x0011_2233,
            0x4455,
            0x6677,
            [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        )
    }

    fn other_guid() -> AdapterGuid {
        AdapterGuid::new(
            0x0011_2233,
            0x4455,
            0x6677,
            [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00],
        )
    }

    fn local_guid() -> AdapterGuid {
        AdapterGuid::new(
            0x7766_5544,
            0x3322,
            0x1100,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        )
    }

    fn retained() -> RetainedAdapterIdentity {
        RetainedAdapterIdentity::new(INDEX, LUID, guid()).unwrap()
    }

    fn live(index: u32, guid: AdapterGuid) -> LiveAdapterIdentity {
        LiveAdapterIdentity {
            interface_index: index,
            interface_guid: guid,
        }
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
            ipv6_stack: Ipv6Stack::Present,
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
        assert!(proof.warnings.is_empty());
    }

    #[test]
    fn a_complete_forward_policy_is_proven() {
        let policy = policy(Ipv6RoutePolicy::Forward);
        let proof = verify(&good_observation(&policy), &policy).unwrap();
        assert_eq!(proof.ipv6_policy, Ipv6RoutePolicy::Forward);
        assert!(proof.warnings.is_empty());
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
    fn the_default_ipv4_probes_cover_every_two_bit_block() {
        for block in 0u8..4 {
            assert!(
                DEFAULT_IPV4_PROBES
                    .iter()
                    .any(|destination| destination.octets()[0] / 64 == block),
                "no default IPv4 probe is in the {}/2 block",
                u16::from(block) * 64
            );
        }
    }

    #[test]
    fn a_documentation_more_specific_route_is_a_warning() {
        // The scan reports this route instead of claiming that it is safe.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let prefix = v4([203, 0, 113, 1], 32);
        observation
            .ipv4_routes
            .push(route(prefix, OTHER_INDEX, OTHER_LUID));
        let proof = verify(&observation, &policy).unwrap();
        assert_eq!(
            proof.warnings,
            vec![RouteWarning {
                prefix,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID,
                reason: RouteWarningReason::NonInternetRange
            }]
        );
    }

    #[test]
    fn a_public_more_specific_route_for_an_unprobed_destination_is_caught() {
        // The probe list does not name this destination. The table scan must
        // still find the more-specific route on the other adapter.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let competing = v4([93, 184, 216, 0], 24);
        observation
            .ipv4_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[0],
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_public_more_specific_route_in_the_second_half_is_caught() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let competing = v4([129, 6, 15, 0], 24);
        observation
            .ipv4_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[1],
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn an_unproven_private_more_specific_route_is_a_bypass() {
        // A blanket private exclusion would hide a hotspot or carrier route.
        // Without a proven local subnet the route is a failure.
        for competing in [
            v4([10, 0, 0, 0], 8),
            v4([10, 1, 2, 0], 24),
            v4([172, 16, 0, 0], 12),
            v4([192, 168, 1, 0], 24),
        ] {
            let policy = policy(Ipv6RoutePolicy::Block);
            let mut observation = good_observation(&policy);
            observation
                .ipv4_routes
                .push(route(competing, OTHER_INDEX, OTHER_LUID));
            let managed = IPV4_ROUTES
                .iter()
                .copied()
                .find(|prefix| prefix.contains(competing.address))
                .unwrap();
            assert_eq!(
                verify(&observation, &policy).unwrap_err(),
                RouteVerifyError::MoreSpecificRoute {
                    managed,
                    competing,
                    interface_index: OTHER_INDEX,
                    interface_luid: OTHER_LUID
                },
                "{competing} must not be silently excluded"
            );
        }
    }

    #[test]
    fn an_unproven_shared_more_specific_route_is_a_bypass() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let competing = v4([100, 64, 0, 0], 10);
        observation
            .ipv4_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[0],
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_globally_reachable_exception_host_route_is_not_excluded() {
        // 192.0.0.9/32 is globally reachable inside the protocol-assignment
        // block. A whole-block exclusion would miss this route.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let competing = v4([192, 0, 0, 9], 32);
        observation
            .ipv4_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[1],
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn an_ipv6_globally_reachable_exception_route_is_not_excluded() {
        // 2001:4:112::/48 is an AS112 anycast block inside the IETF
        // protocol-assignment space. It is globally reachable and must not be
        // excluded by a broad special-purpose rule.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let competing = v6("2001:4:112::", 48);
        observation
            .ipv6_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV6_TUNNEL_ROUTE,
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_proven_local_ipv4_subnet_is_not_a_bypass() {
        let local = v4([10, 1, 2, 0], 24);
        let subnet = local_subnet(
            local,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        );
        assert_eq!(subnet.prefix(), local);
        assert_eq!(subnet.adapter().interface_index(), OTHER_INDEX);
        assert_eq!(subnet.adapter().interface_luid(), OTHER_LUID);
        assert_eq!(subnet.adapter().interface_guid(), local_guid());
        assert_eq!(subnet.provenance(), LocalSubnetProvenance::LocalInterface);
        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(subnet);
        let mut observation = good_observation(&policy);
        observation
            .ipv4_routes
            .push(route(local, OTHER_INDEX, OTHER_LUID));
        let proof = verify(&observation, &policy).unwrap();
        assert!(proof.warnings.is_empty());
    }

    #[test]
    fn a_proven_local_subnet_on_another_adapter_is_still_a_bypass() {
        let local = v4([10, 1, 2, 0], 24);
        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            local,
            THIRD_INDEX,
            THIRD_LUID,
            LocalSubnetProvenance::AuthenticatedSourceDevice,
        ));
        let mut observation = good_observation(&policy);
        observation
            .ipv4_routes
            .push(route(local, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[0],
                competing: local,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_broader_route_than_the_proven_local_subnet_is_a_bypass() {
        let local = v4([10, 1, 2, 0], 24);
        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            local,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        let mut observation = good_observation(&policy);
        let competing = v4([10, 0, 0, 0], 8);
        observation
            .ipv4_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[0],
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_proven_local_route_with_a_gateway_is_a_bypass() {
        let local = v4([10, 1, 2, 0], 24);
        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            local,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        let mut observation = good_observation(&policy);
        let mut competing = route(local, OTHER_INDEX, OTHER_LUID);
        competing.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        observation.ipv4_routes.push(competing);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[0],
                competing: local,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_proven_ipv6_hotspot_slash_64_is_not_a_bypass() {
        let local = v6("2606:4700:1234::", 64);
        let policy = policy(Ipv6RoutePolicy::Forward).with_local_subnet(local_subnet(
            local,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        let mut observation = good_observation(&policy);
        observation
            .ipv6_routes
            .push(route(local, OTHER_INDEX, OTHER_LUID));
        let proof = verify(&observation, &policy).unwrap();
        assert_eq!(proof.ipv6_policy, Ipv6RoutePolicy::Forward);
        assert!(proof.warnings.is_empty());
    }

    #[test]
    fn an_unproven_ipv6_hotspot_slash_64_is_a_bypass() {
        let competing = v6("2606:4700:1234::", 64);
        let policy = policy(Ipv6RoutePolicy::Forward);
        let mut observation = good_observation(&policy);
        observation
            .ipv6_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV6_TUNNEL_ROUTE,
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn block_mode_rejects_a_global_local_subnet_exception_and_route() {
        let local = v6("2606:4700:1234::", 64);
        let block = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&block);
        observation
            .ipv6_routes
            .push(route(local, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &block).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV6_TUNNEL_ROUTE,
                competing: local,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID,
            }
        );
        let with_exception = block.with_local_subnet(local_subnet(
            local,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        assert_eq!(
            verify(&observation, &with_exception).unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "IPv6 local subnet exceptions are not allowed in block mode"
            )
        );
    }

    #[test]
    fn a_more_specific_ipv6_route_outside_the_proven_slash_64_is_a_bypass() {
        let local = v6("2606:4700:1234::", 64);
        let policy = policy(Ipv6RoutePolicy::Forward).with_local_subnet(local_subnet(
            local,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        let mut observation = good_observation(&policy);
        let competing = v6("2606:4700::", 48);
        observation
            .ipv6_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV6_TUNNEL_ROUTE,
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_more_specific_public_range_that_spans_a_non_internet_block_is_caught() {
        // 0.0.0.0/2 covers 1.1.1.1, so it is not wholly inside 0.0.0.0/8.
        // The network address alone would look non-internet; the range check
        // must not be fooled by it.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let competing = v4([0, 0, 0, 0], 2);
        observation
            .ipv4_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[0],
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_more_specific_route_owned_by_the_tunnel_is_out_of_scope() {
        // Traffic for this prefix still enters the tunnel adapter.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation
            .ipv4_routes
            .push(route(v4([93, 184, 216, 0], 24), INDEX, LUID));
        assert!(verify(&observation, &policy).is_ok());
    }

    #[test]
    fn a_more_specific_route_on_the_tunnel_index_with_a_reused_luid_is_caught() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let competing = v4([93, 184, 216, 0], 24);
        observation
            .ipv4_routes
            .push(route(competing, INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[0],
                competing,
                interface_index: INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_less_specific_route_is_not_part_of_the_scan() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation
            .ipv4_routes
            .push(route(v4([0, 0, 0, 0], 0), OTHER_INDEX, OTHER_LUID));
        assert!(verify(&observation, &policy).is_ok());
    }

    #[test]
    fn a_more_specific_route_outside_the_managed_prefix_is_not_part_of_the_scan() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        // 64:ff9b::/96 is a NAT64 prefix outside 2000::/3.
        observation
            .ipv6_routes
            .push(route(v6("64:ff9b::", 96), OTHER_INDEX, OTHER_LUID));
        assert!(verify(&observation, &policy).is_ok());
    }

    #[test]
    fn a_more_specific_ipv6_route_inside_the_managed_prefix_is_caught() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let competing = v6("2606:4700::", 32);
        observation
            .ipv6_routes
            .push(route(competing, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV6_TUNNEL_ROUTE,
                competing,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn an_ipv6_documentation_more_specific_route_is_a_warning() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let prefix = v6("2001:db8::", 32);
        observation
            .ipv6_routes
            .push(route(prefix, OTHER_INDEX, OTHER_LUID));
        let proof = verify(&observation, &policy).unwrap();
        assert_eq!(
            proof.warnings,
            vec![RouteWarning {
                prefix,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID,
                reason: RouteWarningReason::NonInternetRange
            }]
        );
    }

    #[test]
    fn the_more_specific_error_names_the_route_and_the_adapter() {
        let error = RouteVerifyError::MoreSpecificRoute {
            managed: IPV4_ROUTES[0],
            competing: v4([93, 184, 216, 0], 24),
            interface_index: OTHER_INDEX,
            interface_luid: OTHER_LUID,
        };
        assert_eq!(
            error.to_string(),
            "interface 12 with LUID 105553116266508 has the more specific route 93.184.216.0/24 inside 0.0.0.0/1, which is not covered by a proven local subnet, so that traffic can bypass the tunnel"
        );
    }

    #[test]
    fn a_typical_host_table_with_a_proven_local_subnet_is_proven() {
        // A normal host keeps a default route, loopback, multicast, broadcast,
        // and the local subnet route. The local subnet needs an explicit proof;
        // the non-internet routes become warnings.
        let local = v4([192, 168, 1, 0], 24);
        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            local,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        let mut observation = good_observation(&policy);
        for prefix in [
            v4([0, 0, 0, 0], 0),
            v4([127, 0, 0, 0], 8),
            local,
            v4([169, 254, 0, 0], 16),
            v4([224, 0, 0, 0], 4),
            v4([255, 255, 255, 255], 32),
        ] {
            observation
                .ipv4_routes
                .push(route(prefix, OTHER_INDEX, OTHER_LUID));
        }
        for prefix in [v6("fe80::", 10), v6("ff00::", 8)] {
            observation
                .ipv6_routes
                .push(route(prefix, OTHER_INDEX, OTHER_LUID));
        }
        let proof = verify(&observation, &policy).unwrap();
        assert_eq!(proof.warnings.len(), 4);
        assert!(proof
            .warnings
            .iter()
            .all(|warning| warning.reason == RouteWarningReason::NonInternetRange));
    }

    #[test]
    fn a_typical_host_table_without_local_proof_is_not_proven() {
        // Removing the proof must report the private local route, not hide it.
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        let local = v4([192, 168, 1, 0], 24);
        observation
            .ipv4_routes
            .push(route(local, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MoreSpecificRoute {
                managed: IPV4_ROUTES[1],
                competing: local,
                interface_index: OTHER_INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_local_subnet_must_be_more_specific_than_the_managed_prefix() {
        assert_eq!(
            ProvenLocalSubnet::new(
                v4([0, 0, 0, 0], 1),
                retained(),
                LocalSubnetProvenance::LocalInterface
            )
            .unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "a local subnet must be more specific than the managed prefix"
            )
        );
        assert_eq!(
            ProvenLocalSubnet::new(
                v6("2000::", 3),
                retained(),
                LocalSubnetProvenance::LocalInterface
            )
            .unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "a local subnet must be more specific than the managed prefix"
            )
        );
    }

    #[test]
    fn a_local_subnet_with_host_bits_is_rejected() {
        let invalid = RoutePrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            length: 24,
        };
        assert_eq!(
            ProvenLocalSubnet::new(invalid, retained(), LocalSubnetProvenance::LocalInterface)
                .unwrap_err(),
            RouteVerifyError::InvalidPolicy("a local subnet has an invalid prefix")
        );
        let invalid = RoutePrefix {
            address: IpAddr::V6("2606:4700::1".parse().unwrap()),
            length: 48,
        };
        assert_eq!(
            ProvenLocalSubnet::new(invalid, retained(), LocalSubnetProvenance::LocalInterface)
                .unwrap_err(),
            RouteVerifyError::InvalidPolicy("a local subnet has an invalid prefix")
        );
    }

    #[test]
    fn a_local_subnet_cannot_contain_a_probe_destination() {
        let bad_v4 = v4([1, 1, 0, 0], 16);
        let v4_policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            bad_v4,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        assert_eq!(
            verify(&good_observation(&v4_policy), &v4_policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "a local subnet contains a best-route probe destination"
            )
        );

        let bad_v6 = v6("2001:4860:4860::", 64);
        let v6_policy = policy(Ipv6RoutePolicy::Forward).with_local_subnet(local_subnet(
            bad_v6,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        assert_eq!(
            verify(&good_observation(&v6_policy), &v6_policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "a local subnet contains a best-route probe destination"
            )
        );
    }

    #[test]
    fn a_local_subnet_cannot_cover_a_whole_private_block() {
        for prefix in [
            v4([10, 0, 0, 0], 8),
            v4([100, 64, 0, 0], 10),
            v4([172, 16, 0, 0], 12),
            v6("2606:4700::", 32),
            v6("2606:4700:1234::", 48),
        ] {
            assert_eq!(
                ProvenLocalSubnet::new(prefix, retained(), LocalSubnetProvenance::LocalInterface)
                    .unwrap_err(),
                RouteVerifyError::InvalidPolicy("a local subnet is too broad for one hotspot link"),
                "{prefix} must not become proof for arbitrary routes"
            );
        }
    }

    #[test]
    fn a_retained_proof_keeps_a_proven_local_subnet() {
        let local = v4([10, 1, 2, 0], 24);
        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            local,
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::AuthenticatedSourceDevice,
        ));
        let mut observation = good_observation(&policy);
        observation
            .ipv4_routes
            .push(route(local, OTHER_INDEX, OTHER_LUID));
        let proof = verify_retained(&observation, &policy, &retained()).unwrap();
        assert_eq!(proof.proof().warnings.len(), 0);
    }

    #[test]
    fn the_non_internet_ranges_are_bounded() {
        for prefix in [
            v4([0, 0, 0, 0], 8),
            v4([127, 0, 0, 0], 8),
            v4([169, 254, 0, 0], 16),
            v4([192, 0, 2, 0], 24),
            v4([192, 88, 99, 0], 24),
            v4([198, 18, 0, 0], 15),
            v4([198, 51, 100, 0], 24),
            v4([203, 0, 113, 0], 24),
            v4([224, 0, 0, 0], 4),
            v4([240, 0, 0, 0], 4),
        ] {
            assert!(
                non_internet_range(prefix),
                "{prefix} must be a non-internet range"
            );
        }
        for prefix in [
            v6("2001:2::", 48),
            v6("2001:10::", 28),
            v6("2001:20::", 28),
            v6("2001:db8::", 32),
            v6("3ffe::", 16),
            v6("3fff::", 20),
        ] {
            assert!(
                non_internet_range(prefix),
                "{prefix} must be a non-internet range"
            );
        }
        for prefix in [
            v4([0, 0, 0, 0], 2),
            v4([8, 8, 8, 0], 24),
            v4([10, 0, 0, 0], 8),
            v4([100, 64, 0, 0], 10),
            v4([129, 6, 15, 0], 24),
            v4([172, 16, 0, 0], 12),
            v4([192, 0, 0, 0], 24),
            v4([192, 0, 0, 9], 32),
            v4([192, 168, 0, 0], 16),
            v6("2000::", 3),
            v6("2606:4700::", 32),
        ] {
            assert!(
                !non_internet_range(prefix),
                "{prefix} must be in the failure scope, not a warning"
            );
        }
        // This prefix spans the "this network" block and a public block.
        assert!(!non_internet_range(v4([0, 0, 0, 0], 7)));
    }

    #[test]
    fn a_retained_proof_confirms_the_adapter_before_and_after_the_observation() {
        use std::cell::RefCell;

        let policy = policy(Ipv6RoutePolicy::Block);
        let events = RefCell::new(Vec::new());
        let proof = verify_between_identity_confirmations(
            &policy,
            &retained(),
            |_| {
                events.borrow_mut().push("confirm");
                Ok(live(INDEX, guid()))
            },
            || {
                events.borrow_mut().push("observe");
                Ok(good_observation(&policy))
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), vec!["confirm", "observe", "confirm"]);
        assert_eq!(proof.adapter(), retained());
    }

    #[test]
    fn a_changed_identity_after_the_observation_discards_the_proof() {
        use std::cell::Cell;

        let policy = policy(Ipv6RoutePolicy::Block);
        let calls = Cell::new(0u32);
        let error = verify_between_identity_confirmations(
            &policy,
            &retained(),
            |_| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Ok(live(INDEX, guid()))
                } else {
                    Err(RouteVerifyError::AdapterIdentityChanged {
                        retained: guid(),
                        observed: other_guid(),
                    })
                }
            },
            || Ok(good_observation(&policy)),
        )
        .unwrap_err();
        assert_eq!(calls.get(), 2);
        assert_eq!(
            error,
            RouteVerifyError::AdapterIdentityChanged {
                retained: guid(),
                observed: other_guid()
            }
        );
    }

    #[test]
    fn a_mismatched_identity_is_rejected_before_the_first_confirmation() {
        use std::cell::Cell;

        let policy = policy(Ipv6RoutePolicy::Block);
        let other = RetainedAdapterIdentity::new(OTHER_INDEX, OTHER_LUID, guid()).unwrap();
        let confirmed = Cell::new(false);
        let observed = Cell::new(false);
        let error = verify_between_identity_confirmations(
            &policy,
            &other,
            |_| {
                confirmed.set(true);
                Ok(live(OTHER_INDEX, guid()))
            },
            || {
                observed.set(true);
                Ok(good_observation(&policy))
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::RetainedIdentityMismatch {
                policy_index: INDEX,
                policy_luid: LUID,
                retained_index: OTHER_INDEX,
                retained_luid: OTHER_LUID
            }
        );
        assert!(!confirmed.get());
        assert!(!observed.get());
    }

    #[test]
    fn a_guid_prints_in_windows_form() {
        assert_eq!(guid().to_string(), "00112233-4455-6677-8899-AABBCCDDEEFF");
        assert!(AdapterGuid::ZERO.is_zero());
        assert!(!guid().is_zero());
        assert!(!guid().to_string().contains('{'));
    }

    #[test]
    fn the_retained_identity_rejects_zero_values() {
        assert_eq!(
            RetainedAdapterIdentity::new(0, LUID, guid()).unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity(
                "the interface index must be a nonzero 24-bit number"
            )
        );
        assert_eq!(
            RetainedAdapterIdentity::new(MAX_INTERFACE_INDEX + 1, LUID, guid()).unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity(
                "the interface index must be a nonzero 24-bit number"
            )
        );
        assert_eq!(
            RetainedAdapterIdentity::new(INDEX, 0, guid()).unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity("the interface LUID must be nonzero")
        );
        assert_eq!(
            RetainedAdapterIdentity::new(INDEX, LUID, AdapterGuid::ZERO).unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity("the interface GUID must be nonzero")
        );
    }

    #[test]
    fn a_retained_identity_matches_the_live_values() {
        let retained = retained();
        assert_eq!(retained.interface_index(), INDEX);
        assert_eq!(retained.interface_luid(), LUID);
        assert_eq!(retained.interface_guid(), guid());
        assert_eq!(retained.tunnel(), tunnel());
        assert_eq!(retained.matches(live(INDEX, guid())), Ok(()));
    }

    #[test]
    fn a_reused_luid_with_a_new_guid_fails() {
        assert_eq!(
            retained().matches(live(INDEX, other_guid())),
            Err(RouteVerifyError::AdapterIdentityChanged {
                retained: guid(),
                observed: other_guid()
            })
        );
    }

    #[test]
    fn a_stale_retained_index_fails() {
        assert_eq!(
            retained().matches(live(OTHER_INDEX, guid())),
            Err(RouteVerifyError::InterfaceIndexChanged {
                retained: INDEX,
                observed: OTHER_INDEX
            })
        );
    }

    #[test]
    fn a_zero_live_guid_is_an_invalid_observation() {
        assert_eq!(
            retained().matches(live(INDEX, AdapterGuid::ZERO)),
            Err(RouteVerifyError::InvalidObservation(
                "the live adapter lookup returned the zero GUID"
            ))
        );
    }

    #[test]
    fn an_invalid_live_index_is_an_invalid_observation() {
        assert_eq!(
            retained().matches(live(0, guid())),
            Err(RouteVerifyError::InvalidObservation(
                "the live adapter lookup returned an invalid interface index"
            ))
        );
        assert_eq!(
            retained().matches(live(MAX_INTERFACE_INDEX + 1, guid())),
            Err(RouteVerifyError::InvalidObservation(
                "the live adapter lookup returned an invalid interface index"
            ))
        );
    }

    #[test]
    fn a_retained_identity_must_match_the_policy() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let observation = good_observation(&policy);
        let other = RetainedAdapterIdentity::new(OTHER_INDEX, OTHER_LUID, guid()).unwrap();
        assert_eq!(
            verify_retained(&observation, &policy, &other).unwrap_err(),
            RouteVerifyError::RetainedIdentityMismatch {
                policy_index: INDEX,
                policy_luid: LUID,
                retained_index: OTHER_INDEX,
                retained_luid: OTHER_LUID
            }
        );

        // The same LUID with a different retained index is also a mismatch.
        let stale_index = RetainedAdapterIdentity::new(OTHER_INDEX, LUID, guid()).unwrap();
        assert_eq!(
            verify_retained(&observation, &policy, &stale_index).unwrap_err(),
            RouteVerifyError::RetainedIdentityMismatch {
                policy_index: INDEX,
                policy_luid: LUID,
                retained_index: OTHER_INDEX,
                retained_luid: LUID
            }
        );
    }

    #[test]
    fn a_retained_block_proof_carries_the_identity_and_the_policy() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let proof = verify_retained(&good_observation(&policy), &policy, &retained()).unwrap();
        assert_eq!(proof.adapter(), retained());
        assert_eq!(proof.proof().ipv6_policy, Ipv6RoutePolicy::Block);
        assert_eq!(proof.proof().ipv6.prefix, IPV6_TUNNEL_ROUTE);
    }

    #[test]
    fn an_unknown_ipv6_stack_is_not_a_block_proof() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv6_stack = Ipv6Stack::Unknown;
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::InvalidObservation(
                "the observation has IPv6 routes but the IPv6 stack state is not present"
            )
        );

        observation.ipv6_routes.clear();
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::Ipv6StackUnknown
        );
    }

    #[test]
    fn an_absent_ipv6_stack_is_not_a_block_proof() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv6_stack = Ipv6Stack::Absent;
        observation.ipv6_routes.clear();
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::Ipv6StackAbsent
        );
    }

    #[test]
    fn an_absent_ipv6_stack_keeps_the_absence_message_distinct() {
        // The block policy has no route to prove on an absent stack. The text
        // must not claim protection.
        let text = RouteVerifyError::Ipv6StackAbsent.to_string();
        assert!(text.contains("does not report it as protected"));
        assert!(!text.contains("blocked"));
        assert_ne!(
            RouteVerifyError::Ipv6StackAbsent.to_string(),
            RouteVerifyError::Ipv6StackUnknown.to_string()
        );
    }

    #[test]
    fn a_forward_policy_is_never_reported_as_block_or_inherit() {
        let policy = policy(Ipv6RoutePolicy::Forward);
        let proof = verify(&good_observation(&policy), &policy).unwrap();
        assert_eq!(proof.ipv6_policy, Ipv6RoutePolicy::Forward);
        assert_ne!(proof.ipv6_policy, Ipv6RoutePolicy::Block);
        assert_ne!(proof.ipv6_policy, Ipv6RoutePolicy::Inherit);
        assert!(proof.ipv6_policy.is_managed());
    }

    #[test]
    fn the_inherit_policy_never_uses_a_retained_proof() {
        let policy = policy(Ipv6RoutePolicy::Inherit);
        assert_eq!(
            verify_retained(&good_observation(&policy), &policy, &retained()).unwrap_err(),
            RouteVerifyError::Ipv6InheritNotVerifiable
        );
    }

    #[test]
    fn a_conflicting_ipv6_exact_route_is_ambiguous() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation
            .ipv6_routes
            .push(route(IPV6_TUNNEL_ROUTE, OTHER_INDEX, OTHER_LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::CompetingRoute {
                prefix: IPV6_TUNNEL_ROUTE,
                interface_index: OTHER_INDEX
            }
        );
    }

    #[test]
    fn a_second_ipv6_tunnel_row_is_ambiguous() {
        let policy = policy(Ipv6RoutePolicy::Forward);
        let mut observation = good_observation(&policy);
        observation
            .ipv6_routes
            .push(route(IPV6_TUNNEL_ROUTE, INDEX, LUID));
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::DuplicateTunnelRoute {
                prefix: IPV6_TUNNEL_ROUTE,
                count: 2
            }
        );
    }

    #[test]
    fn an_ipv6_route_on_the_wrong_luid_fails() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation.ipv6_routes[0].interface_luid = OTHER_LUID;
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::IndexReused {
                prefix: IPV6_TUNNEL_ROUTE,
                interface_index: INDEX,
                interface_luid: OTHER_LUID
            }
        );
    }

    #[test]
    fn a_missing_ipv6_route_does_not_downgrade_block_to_inherit() {
        let policy = policy(Ipv6RoutePolicy::Block);
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
    fn a_missing_ipv6_probe_is_not_a_block_proof() {
        let policy = policy(Ipv6RoutePolicy::Block);
        let mut observation = good_observation(&policy);
        observation
            .probes
            .retain(|probe| probe.destination.is_ipv4());
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::MissingBestRoute {
                destination: IpAddr::V6(policy.ipv6_probes[0])
            }
        );
    }

    #[test]
    fn a_forward_policy_accepts_a_unicast_ipv6_source_hint() {
        let forward =
            policy(Ipv6RoutePolicy::Forward).with_ipv6_source("fd42:6873:6861::1".parse().unwrap());
        let proof = verify(&good_observation(&forward), &forward).unwrap();
        assert_eq!(proof.ipv6_policy, Ipv6RoutePolicy::Forward);

        let link_local =
            policy(Ipv6RoutePolicy::Forward).with_ipv6_source("fe80::1".parse().unwrap());
        assert!(verify(&good_observation(&link_local), &link_local).is_ok());
    }

    #[test]
    fn a_block_policy_rejects_an_ipv6_source_hint() {
        let policy =
            policy(Ipv6RoutePolicy::Block).with_ipv6_source("fd42:6873:6861::1".parse().unwrap());
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy("the block policy does not use an IPv6 source address")
        );
    }

    #[test]
    fn a_bad_ipv6_source_hint_is_invalid() {
        for source in ["::", "ff02::1", "::1", "::ffff:192.0.2.1"] {
            let policy = policy(Ipv6RoutePolicy::Forward)
                .with_ipv6_source(source.parse::<Ipv6Addr>().unwrap());
            assert_eq!(
                verify(&good_observation(&policy), &policy).unwrap_err(),
                RouteVerifyError::InvalidPolicy(
                    "the IPv6 source address must be a unicast address, and this check cannot prove that the tunnel adapter owns it"
                ),
                "source {source} must be rejected"
            );
        }
    }

    #[test]
    fn a_link_local_source_hint_uses_the_interface_scope() {
        assert_eq!(source_scope("fe80::1".parse().unwrap(), INDEX), INDEX);
        assert_eq!(source_scope("2001:db8::1".parse().unwrap(), INDEX), 0);
        assert_eq!(source_scope("fd42:6873:6861::1".parse().unwrap(), INDEX), 0);
    }

    #[test]
    fn an_ipv6_probe_failure_is_always_inconclusive() {
        let destination = IpAddr::V6("2606:4700:4700::1111".parse().unwrap());
        assert_eq!(
            ipv6_probe_failure(destination, 1231),
            RouteVerifyError::Ipv6ProbeInconclusive {
                destination,
                code: 1231
            }
        );
        // The IPv6 table read already returned success before any probe runs.
        // The "no IPv6 stack" code after that read is a contradiction, not an
        // absent stack and not a block proof.
        assert_eq!(
            ipv6_probe_failure(destination, ERROR_NOT_SUPPORTED),
            RouteVerifyError::Ipv6ProbeInconclusive {
                destination,
                code: ERROR_NOT_SUPPORTED
            }
        );
        assert_ne!(
            ipv6_probe_failure(destination, ERROR_NOT_SUPPORTED),
            RouteVerifyError::Ipv6StackAbsent
        );
        assert_eq!(
            RouteVerifyError::Ipv6ProbeInconclusive {
                destination,
                code: 1231
            }
            .to_string(),
            "the 2606:4700:4700::1111 IPv6 probe failed with Windows error 1231; the IPv6 policy is not proven"
        );
    }

    #[test]
    fn an_ipv6_table_failure_only_maps_the_documented_absent_code() {
        assert_eq!(
            ipv6_table_failure(ERROR_NOT_SUPPORTED),
            RouteVerifyError::Ipv6StackAbsent
        );
        assert_eq!(
            ipv6_table_failure(1168),
            RouteVerifyError::Api {
                operation: "GetIpForwardTable2",
                code: 1168
            }
        );
        assert_eq!(
            ipv6_table_failure(5),
            RouteVerifyError::Api {
                operation: "GetIpForwardTable2",
                code: 5
            }
        );
    }

    #[test]
    fn a_default_observation_has_an_unknown_ipv6_stack() {
        let observation = RouteObservation::default();
        assert_eq!(observation.ipv6_stack, Ipv6Stack::Unknown);
        assert!(!observation.ipv6_stack.is_present());
        assert_eq!(Ipv6Stack::default(), Ipv6Stack::Unknown);

        let policy = policy(Ipv6RoutePolicy::Block);
        assert_eq!(
            verify(&observation, &policy).unwrap_err(),
            RouteVerifyError::Ipv6StackUnknown
        );
    }

    // Default gateway selection.

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 43, 1);
    const VPN_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);

    fn gateway_probe(
        destination: Ipv4Addr,
        best_interface_index: u32,
        prefix: RoutePrefix,
        ifindex: u32,
        luid: u64,
        next_hop: Ipv4Addr,
    ) -> BestRouteProbe {
        let mut route = route(prefix, ifindex, luid);
        route.next_hop = IpAddr::V4(next_hop);
        BestRouteProbe {
            destination: IpAddr::V4(destination),
            best_interface_index,
            route,
        }
    }

    fn genuine_default_probes() -> Vec<BestRouteProbe> {
        DEFAULT_GATEWAY_PROBES
            .iter()
            .map(|destination| {
                gateway_probe(
                    *destination,
                    OTHER_INDEX,
                    v4([0, 0, 0, 0], 0),
                    OTHER_INDEX,
                    OTHER_LUID,
                    GATEWAY,
                )
            })
            .collect()
    }

    #[test]
    fn the_default_gateway_probes_cover_both_halves() {
        assert!(IPV4_ROUTES[0].contains(IpAddr::V4(DEFAULT_GATEWAY_PROBES[0])));
        assert!(IPV4_ROUTES[1].contains(IpAddr::V4(DEFAULT_GATEWAY_PROBES[1])));
    }

    #[test]
    fn a_genuine_default_route_names_the_gateway() {
        assert_eq!(
            select_default_ipv4_gateway(&genuine_default_probes()),
            Ok((GATEWAY, OTHER_INDEX))
        );
    }

    #[test]
    fn a_vpn_split_default_route_is_not_the_default_gateway() {
        // An OpenVPN `redirect-gateway def1` table: both halves go to a private
        // VPN gateway on the VPN adapter, and the physical /0 still exists.
        let probes: Vec<BestRouteProbe> = DEFAULT_GATEWAY_PROBES
            .iter()
            .zip(IPV4_ROUTES)
            .map(|(destination, half)| {
                gateway_probe(
                    *destination,
                    THIRD_INDEX,
                    half,
                    THIRD_INDEX,
                    THIRD_LUID,
                    VPN_GATEWAY,
                )
            })
            .collect();
        assert_eq!(
            select_default_ipv4_gateway(&probes),
            Err(RouteVerifyError::InvalidObservation(
                "the selected IPv4 route is not the 0.0.0.0/0 default route",
            ))
        );
    }

    #[test]
    fn a_split_default_route_in_the_second_half_is_caught() {
        let mut probes = genuine_default_probes();
        probes[1] = gateway_probe(
            DEFAULT_GATEWAY_PROBES[1],
            THIRD_INDEX,
            IPV4_ROUTES[1],
            THIRD_INDEX,
            THIRD_LUID,
            VPN_GATEWAY,
        );
        assert_eq!(
            select_default_ipv4_gateway(&probes),
            Err(RouteVerifyError::InvalidObservation(
                "the selected IPv4 route is not the 0.0.0.0/0 default route",
            ))
        );
    }

    #[test]
    fn a_more_specific_route_with_a_gateway_is_not_the_default_gateway() {
        let mut probes = genuine_default_probes();
        probes[0] = gateway_probe(
            DEFAULT_GATEWAY_PROBES[0],
            OTHER_INDEX,
            v4([8, 0, 0, 0], 8),
            OTHER_INDEX,
            OTHER_LUID,
            GATEWAY,
        );
        assert!(select_default_ipv4_gateway(&probes).is_err());
    }

    #[test]
    fn a_default_route_on_another_interface_than_the_best_interface_fails() {
        let mut probes = genuine_default_probes();
        probes[0].best_interface_index = THIRD_INDEX;
        assert_eq!(
            select_default_ipv4_gateway(&probes),
            Err(RouteVerifyError::InvalidObservation(
                "the default route is not on the interface that Windows selected",
            ))
        );
    }

    #[test]
    fn a_loopback_default_route_is_not_a_gateway() {
        let mut probes = genuine_default_probes();
        probes[1].route.loopback = true;
        assert_eq!(
            select_default_ipv4_gateway(&probes),
            Err(RouteVerifyError::InvalidObservation(
                "the default route is a loopback route",
            ))
        );
    }

    #[test]
    fn an_on_link_default_route_is_not_a_gateway() {
        let mut probes = genuine_default_probes();
        for probe in &mut probes {
            probe.route.next_hop = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        }
        assert_eq!(
            select_default_ipv4_gateway(&probes),
            Err(RouteVerifyError::InvalidObservation(
                "the default route has no unicast IPv4 gateway",
            ))
        );
    }

    #[test]
    fn a_non_unicast_or_ipv6_gateway_is_rejected() {
        for bad in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let mut probes = genuine_default_probes();
            probes[0].route.next_hop = bad;
            assert!(select_default_ipv4_gateway(&probes).is_err(), "{bad}");
        }
    }

    #[test]
    fn default_gateway_probes_that_disagree_fail() {
        let mut probes = genuine_default_probes();
        probes[1].route.next_hop = IpAddr::V4(Ipv4Addr::new(192, 168, 43, 2));
        assert_eq!(
            select_default_ipv4_gateway(&probes),
            Err(RouteVerifyError::InvalidObservation(
                "the default gateway probes selected different routes",
            ))
        );
        let mut probes = genuine_default_probes();
        probes[1].route.interface_luid = THIRD_LUID;
        assert!(select_default_ipv4_gateway(&probes).is_err());
    }

    #[test]
    fn a_default_gateway_check_without_a_valid_probe_fails() {
        assert_eq!(
            select_default_ipv4_gateway(&[]),
            Err(RouteVerifyError::InvalidObservation(
                "the default gateway check has no probe",
            ))
        );
        let mut probes = genuine_default_probes();
        probes[0].best_interface_index = 0;
        assert!(select_default_ipv4_gateway(&probes).is_err());
        let mut probes = genuine_default_probes();
        probes[0].route.interface_luid = 0;
        assert!(select_default_ipv4_gateway(&probes).is_err());
        let mut probes = genuine_default_probes();
        probes[0].destination = IpAddr::V6(DEFAULT_IPV6_PROBES[0]);
        assert!(select_default_ipv4_gateway(&probes).is_err());
    }

    // Local physical adapter identity.

    fn local_policy() -> VerifyPolicy {
        policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            v4([10, 1, 2, 0], 24),
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ))
    }

    fn live_for(adapter: &RetainedAdapterIdentity) -> LiveAdapterIdentity {
        live(adapter.interface_index(), adapter.interface_guid())
    }

    fn local_observation(policy: &VerifyPolicy) -> RouteObservation {
        let mut observation = good_observation(policy);
        observation
            .ipv4_routes
            .push(route(v4([10, 1, 2, 0], 24), OTHER_INDEX, OTHER_LUID));
        observation
    }

    #[test]
    fn a_local_subnet_on_the_tunnel_index_is_invalid() {
        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            v4([10, 1, 2, 0], 24),
            INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "a local subnet adapter has the tunnel adapter identity"
            )
        );
    }

    #[test]
    fn a_local_subnet_on_the_tunnel_luid_is_invalid() {
        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            v4([10, 1, 2, 0], 24),
            OTHER_INDEX,
            LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            RouteVerifyError::InvalidPolicy(
                "a local subnet adapter has the tunnel adapter identity"
            )
        );
    }

    #[test]
    fn a_local_subnet_with_the_tunnel_guid_is_rejected_before_any_read() {
        use std::cell::Cell;

        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(
            ProvenLocalSubnet::new(
                v4([10, 1, 2, 0], 24),
                RetainedAdapterIdentity::new(OTHER_INDEX, OTHER_LUID, guid()).unwrap(),
                LocalSubnetProvenance::LocalInterface,
            )
            .unwrap(),
        );
        let expected = RouteVerifyError::InvalidPolicy(
            "a local subnet adapter has the tunnel adapter identity",
        );
        assert_eq!(
            verify_retained(&local_observation(&policy), &policy, &retained()).unwrap_err(),
            expected
        );
        let confirmed = Cell::new(false);
        let observed = Cell::new(false);
        let error = verify_between_identity_confirmations(
            &policy,
            &retained(),
            |adapter| {
                confirmed.set(true);
                Ok(live_for(adapter))
            },
            || {
                observed.set(true);
                Ok(local_observation(&policy))
            },
        )
        .unwrap_err();
        assert_eq!(error, expected);
        assert!(!confirmed.get());
        assert!(!observed.get());
    }

    #[test]
    fn a_block_mode_ipv6_exception_is_rejected_before_any_read() {
        use std::cell::Cell;

        let policy = policy(Ipv6RoutePolicy::Block).with_local_subnet(local_subnet(
            v6("2606:4700:1234::", 64),
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        let confirmed = Cell::new(false);
        let observed = Cell::new(false);
        let error = verify_between_identity_confirmations(
            &policy,
            &retained(),
            |adapter| {
                confirmed.set(true);
                Ok(live_for(adapter))
            },
            || {
                observed.set(true);
                Ok(good_observation(&policy))
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::InvalidPolicy(
                "IPv6 local subnet exceptions are not allowed in block mode"
            )
        );
        assert!(!confirmed.get());
        assert!(!observed.get());
    }

    #[test]
    fn local_subnets_that_disagree_on_one_adapter_are_invalid() {
        use std::cell::Cell;

        let other_identity =
            RetainedAdapterIdentity::new(THIRD_INDEX, OTHER_LUID, local_guid()).unwrap();
        let policy = local_policy().with_local_subnet(
            ProvenLocalSubnet::new(
                v4([10, 1, 3, 0], 24),
                other_identity,
                LocalSubnetProvenance::LocalInterface,
            )
            .unwrap(),
        );
        let expected = RouteVerifyError::InvalidPolicy(
            "two local subnets name one adapter with different identities",
        );
        assert_eq!(
            verify(&good_observation(&policy), &policy).unwrap_err(),
            expected
        );
        let confirmed = Cell::new(false);
        let error = verify_between_identity_confirmations(
            &policy,
            &retained(),
            |adapter| {
                confirmed.set(true);
                Ok(live_for(adapter))
            },
            || Ok(good_observation(&policy)),
        )
        .unwrap_err();
        assert_eq!(error, expected);
        assert!(!confirmed.get());
    }

    #[test]
    fn the_local_adapter_is_confirmed_before_and_after_the_observation() {
        use std::cell::RefCell;

        let policy = local_policy();
        let events = RefCell::new(Vec::new());
        let proof = verify_between_identity_confirmations(
            &policy,
            &retained(),
            |adapter| {
                events.borrow_mut().push(adapter.interface_luid());
                Ok(live_for(adapter))
            },
            || {
                events.borrow_mut().push(0);
                Ok(local_observation(&policy))
            },
        )
        .unwrap();
        assert_eq!(
            *events.borrow(),
            vec![LUID, OTHER_LUID, 0, LUID, OTHER_LUID]
        );
        assert!(proof.proof().warnings.is_empty());
    }

    #[test]
    fn two_subnets_on_one_local_adapter_confirm_it_once_per_round() {
        use std::cell::RefCell;

        let policy = local_policy().with_local_subnet(local_subnet(
            v4([10, 1, 3, 0], 24),
            OTHER_INDEX,
            OTHER_LUID,
            LocalSubnetProvenance::LocalInterface,
        ));
        let events = RefCell::new(Vec::new());
        verify_between_identity_confirmations(
            &policy,
            &retained(),
            |adapter| {
                events.borrow_mut().push(adapter.interface_luid());
                Ok(live_for(adapter))
            },
            || {
                events.borrow_mut().push(0);
                Ok(local_observation(&policy))
            },
        )
        .unwrap();
        assert_eq!(
            *events.borrow(),
            vec![LUID, OTHER_LUID, 0, LUID, OTHER_LUID]
        );
    }

    #[test]
    fn a_stale_local_adapter_stops_the_check_before_the_route_reads() {
        use std::cell::Cell;

        let policy = local_policy();
        let observed = Cell::new(false);
        let error = verify_between_identity_confirmations(
            &policy,
            &retained(),
            |adapter| {
                let live = if adapter.interface_luid() == OTHER_LUID {
                    live(OTHER_INDEX, other_guid())
                } else {
                    live_for(adapter)
                };
                adapter.matches(live)?;
                Ok(live)
            },
            || {
                observed.set(true);
                Ok(local_observation(&policy))
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::AdapterIdentityChanged {
                retained: local_guid(),
                observed: other_guid(),
            }
        );
        assert!(!observed.get());
    }

    #[test]
    fn a_local_adapter_change_after_the_observation_discards_the_proof() {
        use std::cell::Cell;

        let policy = local_policy();
        let observed = Cell::new(false);
        let error = verify_between_identity_confirmations(
            &policy,
            &retained(),
            |adapter| {
                let live = if observed.get() && adapter.interface_luid() == OTHER_LUID {
                    live(THIRD_INDEX, local_guid())
                } else {
                    live_for(adapter)
                };
                adapter.matches(live)?;
                Ok(live)
            },
            || {
                observed.set(true);
                Ok(local_observation(&policy))
            },
        )
        .unwrap_err();
        assert!(observed.get());
        assert_eq!(
            error,
            RouteVerifyError::InterfaceIndexChanged {
                retained: OTHER_INDEX,
                observed: THIRD_INDEX,
            }
        );
    }
}
