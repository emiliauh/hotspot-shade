//! Linux TUN platform layer.
//!
//! The service uses this module for direct mode and source device proxy mode.
//! The device is `/dev/net/tun` with `TUNSETIFF` and `IFF_TUN | IFF_NO_PI`.
//! The kernel returns raw IP packets. There is no address-family prefix and no
//! packet information header.
//!
//! The caller owns the relay loop. Keep the device, link guard, and route
//! manager alive for the full relay lifetime. Stop the relay before dropping
//! them. Drop the route manager first, then the link guard, then the device.
//! Address cleanup needs the device.
//!
//! # Resource ownership
//!
//! [`Tun`] owns its descriptor. The descriptor closes on every failure path and
//! on drop. [`LinkGuard`] removes the IPv4 address that it added.
//! [`RouteManager`] owns a dedicated routing table and two policy rules for
//! each address family. It records the table id, every rule selector, and
//! every route key before the add. Cleanup proves each object again, deletes
//! only a matching object, and is idempotent. See the cleanup section below.
//!
//! # Dedicated table and rules
//!
//! The tunnel installs these objects:
//!
//! - Table [`TUNNEL_TABLE`] for IPv4 and IPv6.
//! - Rule priority [`OUTER_RULE_PRIORITY`]: `oif <physical> lookup main`.
//! - Rule priority [`TUNNEL_RULE_PRIORITY`]: `lookup TUNNEL_TABLE`.
//! - The two IPv4 `/1` routes in the tunnel table. They point at the TUN.
//! - The `2000::/3` route in the tunnel table. It points at the TUN in forward
//!   mode and is a blackhole in block mode.
//!
//! Every outer socket sets `SO_BINDTODEVICE` in [`crate::normalization`]. The
//! higher priority rule matches only a socket that is bound to the physical
//! interface. The relay, the source device probe, and the diagnostic sockets
//! therefore use table main. The lower priority rule sends every other output
//! packet to the tunnel table. Do not add the lower priority rule without the
//! `oif` rule: a plain rule also matches the relay's own sockets, and the relay
//! then fails because the tunnel route does not name the physical device.
//!
//! # IPv6 policy
//!
//! The policy is explicit. [`Ipv6Policy::Block`] is the direct-mode default,
//! [`Ipv6Policy::Forward`] is the source device proxy mode, and
//! [`Ipv6Policy::Inherit`] is an explicit leak path. This module keeps the
//! three values separate.
//!
//! The manager installs one IPv6 route in the dedicated table. Forward mode
//! uses a unicast route to the TUN. Block mode uses a blackhole route in that
//! table only; it never changes table main. The start gate verifies the block
//! policy from the dedicated table and from one fake lookup for each default
//! probe. The Linux service accepts direct mode and source device proxy mode.
//!
//! # Route verification
//!
//! [`RouteManager::verify_interface`] reads the link with `RTM_GETLINK`. It
//! proves the interface index, the name, and the TUN link type. It does not
//! require the link to be up, because [`LinkGuard`] brings the link up after
//! this check. The proof holds a weak token for the live [`Tun`] handle. A
//! dropped device, or a second device with the same name and index, cannot use
//! the proof.
//!
//! [`RouteManager::verify_ipv4`] sends one `RTM_GETROUTE` request for each fake
//! probe. It sets `RTM_F_FIB_MATCH` and `RTM_F_LOOKUP_TABLE`, so the reply is
//! the route that the kernel selected through the policy rules. The route must
//! be the exact /1 prefix, in the tunnel table, with the project protocol
//! marker, type unicast, the recorded interface index, no gateway, no
//! multipath, no nexthop object, and no encapsulation.
//!
//! [`RouteManager::verify_ipv6_forward`] sends one `RTM_GETROUTE` request for
//! each global-unicast probe. The request sets only `RTM_F_FIB_MATCH`. It does
//! not set `RTM_F_LOOKUP_TABLE` or `RTA_OIF`; IPv6 accepts only
//! `RTM_F_FIB_MATCH`, and a pinned output interface can mask a competing exact
//! prefix. The reply must be the exact `2000::/3` prefix, in the tunnel table,
//! with the project protocol marker, type unicast, the tunnel output
//! interface, no gateway, no multipath, no nexthop object, no encapsulation,
//! no source selector, and no dead or link-down flag. The tunnel link must be
//! up. The outer interface proof must name a different link and that link must
//! be up.
//!
//! [`RouteManager::verify_ipv6_block`] reads the dedicated table and sends one
//! fake lookup for each default probe. The table must hold exactly the recorded
//! `2000::/3` blackhole with the project protocol marker. The kernel reports a
//! blackhole FIB entry as `EINVAL`, so every probe must get `EINVAL`. A unicast
//! reply or a missing route is a bypass. Other kernel errors are inconclusive.
//! The block check does not prove that the blackhole is the only route that can
//! affect IPv6 traffic. See the limits below.
//!
//! The probes send no packet. Verification reads native netlink data. The
//! netlink checks send no write request. A kernel that denies the read, or that
//! does not support `RTM_F_FIB_MATCH`, is an inconclusive result, not a success.
//!
//! A forward route check does not prove that the outer sockets set
//! `SO_BINDTODEVICE`. It does not prove that no more-specific route bypasses the
//! tunnel. Do not describe the tunnel as fail-closed.
//!
//! [`RouteManager::verify_start`] is the start gate. It requires the recorded
//! IPv4 route, then runs the selected IPv6 check. A block policy returns the
//! blackhole proof. A forward policy returns the tunnel route proof. A start
//! path must not run the relay when this method returns an error.
//!
//! # Start order
//!
//! 1. Open the TUN device and record its identity.
//! 2. Call [`RouteManager::verify_interface`] to prove the link identity.
//! 3. Prove the physical outer link with [`RouteManager::verify_outer_pin`].
//! 4. Configure the address and link with [`LinkGuard::install`] for the same
//!    proof and live device.
//! 5. Install the rules and routes with [`RouteManager::install_verified`].
//! 6. Call [`RouteManager::verify_start`] with the same proof, live device,
//!    and outer proof.
//! 7. Do not start the relay when a check fails. Remove the routes and the
//!    link.
//!
//! The Linux worker checks the physical link every 2 seconds with
//! [`link_ready`]. The check uses `RTM_GETLINK` and one address read. After 20
//! seconds without the link, the worker stops and removes its objects. A
//! missing link is down. A read failure is unknown, not link loss.
//!
//! # Limits of the proof
//!
//! Linux routes and rules have no creator identifier. A process with
//! `CAP_NET_ADMIN` can install an identical object. The protocol marker is an
//! attribution signal. It is not proof of creation. The dedicated table, the
//! fixed rule priorities, the empty-table precondition, and the
//! `NLM_F_EXCL` add reduce the risk. They do not prove the creator. The
//! cleanup check and the delete are not atomic. A privileged process can change
//! an object between them.
//!
//! A privileged process can also delete the TUN device and create another TUN
//! with the same name and index. The Rust proof detects a different [`Tun`]
//! handle, but it cannot detect a kernel replacement under the same handle. The
//! check is a snapshot.
//!
//! The probe set is finite. A more-specific route in another table, a policy
//! rule with a higher priority, or a local DNS path can bypass the tunnel. The
//! IPv4 and IPv6 probes use the verifier's user id and no mark or output
//! interface. Local addresses use the local table. Do not describe the tunnel
//! as fail-closed.
//!
//! The IPv6 forward check covers `2000::/3` only. It does not cover
//! link-local, unique-local, multicast, NAT64, or addresses outside
//! `2000::/3`. The IPv6 block check covers the same prefix and the finite probe
//! set. A more-specific route, a higher-priority rule, or a local path can
//! still bypass or shadow the blackhole. The outer interface proof proves the
//! link identity and state. It does not prove that a socket sets
//! `SO_BINDTODEVICE`. The check is a snapshot. A privileged process can change
//! a route or a link after the check.
//!
//! # Cleanup
//!
//! Cleanup does not parse `ip route` text. That text is localized and can map a
//! protocol number to a local name. Cleanup reads the same objects through
//! netlink and compares each one with its record. It deletes a route only when
//! the family, prefix, source, TOS, table, protocol, type, output interface,
//! metric, preferred source, flow, and route shape match. It deletes a rule
//! only when the family, prefix lengths, destination, source, TOS, table,
//! priority, action, flags, input and output interface names, goto target,
//! protocol, mark, mask, flow, tunnel id, suppress values, l3mdev, uid range,
//! IP protocol, port ranges, port masks, DSCP, DSCP mask, and flow label match.
//! An unknown rule selector blocks the delete. An absent object is already
//! clean. A different object at the same key, or a failed read, is left in
//! place, kept in the record, and reported. A crash leaves the policy rules:
//! device-bound routes and the address go away with the TUN device, but rules
//! are not bound to it. The next start refuses while the priorities are in use.
//! See `docs/LINUX_TEST_VM.md` for the operator cleanup command.
//!
//! An add can be applied before its acknowledgement arrives. On an ACK
//! timeout, the manager reads the object again and keeps the record only when
//! the object matches. The rollback then removes an add that the kernel applied
//! without an answer.
//!
//! # Packet bounds
//!
//! [`PacketBuffer`] holds one allocation for the configured MTU. A read never
//! returns more than the MTU. A write rejects an empty packet, an oversize
//! packet, a malformed IP packet, and a packet with a length that disagrees
//! with its IP header.

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// The Linux TUN control device.
pub const TUN_DEVICE: &str = "/dev/net/tun";

/// The default link MTU.
pub const DEFAULT_MTU: u32 = 1500;

/// The smallest MTU that this module accepts. This is the IPv4 minimum.
pub const MIN_MTU: u32 = 576;

/// The largest MTU that one TUN packet can hold.
pub const MAX_MTU: u32 = 65_535;

/// The TUN flags. `IFF_TUN` gives IP frames. `IFF_NO_PI` removes the packet
/// information header, so the frame is a raw IP packet. `IFF_TUN_EXCL`
/// refuses an existing device, including a detached persistent device.
pub const TUN_FLAGS: libc::c_short =
    (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;

/// The numeric route protocol marker. Commands and netlink replies use this
/// number. Cleanup does not map it to a protocol name.
const ROUTE_PROTOCOL_ID: u8 = 196;

/// The main routing table. The tunnel installs its /1 routes in this table.
const RT_TABLE_MAIN: u32 = 254;

/// A unicast FIB entry. Every tunnel route must have this type.
const RTN_UNICAST: u8 = 1;

/// Ask `RTM_GETROUTE` for the selected FIB entry, not the resolved output
/// route. The entry gives the matched prefix and protocol marker.
const RTM_F_FIB_MATCH: u32 = 0x2000;

/// Ask `RTM_GETROUTE` to report the table that the IPv4 policy lookup selected.
/// Do not set this flag for IPv6. The IPv6 request validator accepts only
/// `RTM_F_FIB_MATCH`.
const RTM_F_LOOKUP_TABLE: u32 = 0x1000;

/// The reply reports a resolved route, not a FIB entry. An IPv6 kernel without
/// FIB-match support can return this flag. The IPv6 check treats it as a
/// failure.
const RTM_F_CLONED: u32 = 0x2;

/// A netlink header. `struct nlmsghdr` is 16 bytes on every Linux target.
const NLMSG_HDRLEN: usize = 16;

/// A netlink route message. The values are from `linux/rtnetlink.h`.
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;

/// Route attribute types. The values are from `linux/rtnetlink.h`.
const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_FLOW: u16 = 11;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;
const RTA_NH_ID: u16 = 30;
const RTA_ENCAP: u16 = 22;
const RTA_ENCAP_TYPE: u16 = 21;

/// Policy rule attribute types. The values are from `linux/fib_rules.h`.
const FRA_DST: u16 = 1;
const FRA_SRC: u16 = 2;
const FRA_IIFNAME: u16 = 3;
const FRA_GOTO: u16 = 4;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_FLOW: u16 = 11;
const FRA_TUN_ID: u16 = 12;
const FRA_SUPPRESS_IFGROUP: u16 = 13;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_OIFNAME: u16 = 17;
const FRA_PAD: u16 = 18;
const FRA_L3MDEV: u16 = 19;
const FRA_UID_RANGE: u16 = 20;
const FRA_PROTOCOL: u16 = 21;
const FRA_IP_PROTO: u16 = 22;
const FRA_SPORT_RANGE: u16 = 23;
const FRA_DPORT_RANGE: u16 = 24;
const FRA_DSCP: u16 = 25;
const FRA_FLOWLABEL: u16 = 26;
const FRA_FLOWLABEL_MASK: u16 = 27;
const FRA_SPORT_MASK: u16 = 28;
const FRA_DPORT_MASK: u16 = 29;
const FRA_DSCP_MASK: u16 = 30;

/// The `FR_ACT_TO_TBL` rule action. It selects a routing table.
const FR_ACT_TO_TBL: u8 = 1;

/// Rule header flags that change the selector. Detached and unresolved bits
/// describe live state, not ownership, so the comparison ignores them.
const FIB_RULE_PERMANENT: u32 = 0x0000_0001;
const FIB_RULE_INVERT: u32 = 0x0000_0002;
const FIB_RULE_FIND_SADDR: u32 = 0x0001_0000;
const RULE_SELECTOR_FLAGS: u32 = FIB_RULE_PERMANENT | FIB_RULE_INVERT | FIB_RULE_FIND_SADDR;

/// The dedicated routing table for the tunnel. The table is empty before the
/// install. The manager records the id and deletes only its own objects.
pub const TUNNEL_TABLE: u32 = 700;

/// The rule priority for sockets that are bound to the physical interface.
/// This rule sends the relay's own outer sockets to table main.
pub const OUTER_RULE_PRIORITY: u32 = 17_000;

/// The rule priority for the tunnel table. Every other output packet uses the
/// tunnel table.
pub const TUNNEL_RULE_PRIORITY: u32 = 17_001;

/// The IPv6 route metric that the kernel assigns when the add request omits
/// `RTA_PRIORITY`. The ownership record must hold this value to match the reply.
const IPV6_DEFAULT_METRIC: u32 = 1024;

/// A blackhole FIB entry. The IPv6 block policy uses it in the tunnel table.
const RTN_BLACKHOLE: u8 = 6;

/// The `RT_SCOPE_UNIVERSE` and `RT_SCOPE_LINK` scope values.
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;

/// Link attribute types. The values are from `linux/if_link.h`.
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;

/// The netlink attribute type mask. It removes the nested and byte-order flags.
const NLA_TYPE_MASK: u16 = 0x3fff;

/// Nexthop flags that mark a route as unusable.
const RTNH_F_DEAD: u32 = 1;
const RTNH_F_LINKDOWN: u32 = 16;

/// The ARP hardware type of a TUN link. A TAP link uses `ARPHRD_ETHER`.
const ARPHRD_NONE: u16 = 0xfffe;

/// The `IFF_UP` link flag.
const IFF_UP: u32 = 0x1;

/// The `IFF_LOOPBACK` link flag. An outer interface must not be loopback.
const IFF_LOOPBACK: u32 = 0x8;

/// Link kinds that are not a physical outer path. `IFLA_INFO_KIND` is absent
/// for most physical links. This list rejects the common tunnel devices.
const NON_PHYSICAL_LINK_KINDS: &[&str] = &["tun", "tap", "wireguard"];

/// The netlink reply deadline. A slow reply is inconclusive.
const NETLINK_TIMEOUT: Duration = Duration::from_secs(2);

/// The largest netlink reply that this module accepts. A route dump covers
/// every table. A busy host can return several entries after a device appears.
const MAX_NETLINK_REPLY: usize = 256 * 1024;

const IFREQ_RESERVED: usize = 22;

/// One `ifreq` for `TUNSETIFF`.
///
/// Linux `ifreq` starts with the interface name and then a union. `TUNSETIFF`
/// reads `ifr_flags` from the start of that union. This layout covers the
/// 40-byte 64-bit `ifreq` and the smaller 32-bit form.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    reserved: [u8; IFREQ_RESERVED],
}

/// Return true for an interface name that this module creates or accepts.
///
/// The kernel limit is 15 bytes. This module also rejects whitespace and path
/// separators, so the name can never change a command argument.
pub fn valid_ifname(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 15
        && name != "."
        && name != ".."
        && !name.starts_with('-')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn check_ifname(name: &str) -> io::Result<()> {
    if valid_ifname(name) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid tunnel interface name",
        ))
    }
}

/// Check the MTU and return it as a byte count.
pub fn validate_mtu(mtu: u32) -> io::Result<usize> {
    if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tunnel MTU must be 576 to 65535",
        ));
    }
    Ok(mtu as usize)
}

/// Build one `ifreq` for `TUNSETIFF`.
fn build_ifreq(name: &str) -> io::Result<IfReq> {
    if !valid_ifname(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid tunnel interface name",
        ));
    }
    let mut request = IfReq {
        name: [0; libc::IFNAMSIZ],
        flags: TUN_FLAGS,
        reserved: [0; IFREQ_RESERVED],
    };
    for (destination, source) in request.name.iter_mut().zip(name.bytes()) {
        *destination = source as libc::c_char;
    }
    Ok(request)
}

/// Return the declared IP packet length and check the header bounds.
///
/// IPv4 packets may carry trailing bytes. The returned length excludes them.
/// IPv6 packets must hold the payload length that the header declares.
fn packet_len(packet: &[u8]) -> io::Result<usize> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            if packet.len() < 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short IPv4 packet",
                ));
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20 || header > packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid IPv4 header length",
                ));
            }
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total < header || total > packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid IPv4 total length",
                ));
            }
            Ok(total)
        }
        Some(6) => {
            if packet.len() < 40 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short IPv6 packet",
                ));
            }
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let total = 40 + payload;
            if total > packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid IPv6 payload length",
                ));
            }
            Ok(total)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IP version",
        )),
    }
}

/// One allocation for one packet. Create one buffer and reuse it.
pub struct PacketBuffer {
    data: Vec<u8>,
}

impl PacketBuffer {
    /// Allocate a buffer for the MTU.
    pub fn new(mtu: u32) -> io::Result<Self> {
        let size = validate_mtu(mtu)?;
        Ok(Self {
            data: vec![0u8; size],
        })
    }

    /// Return the buffer size in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return true when the buffer has no bytes. A valid buffer never does.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// One system call layer for packet reads and writes.
/// Tests use a fake layer to send packets without a TUN device.
trait PacketIo {
    fn read(&self, buffer: &mut [u8]) -> io::Result<usize>;
    fn write(&self, packet: &[u8]) -> io::Result<usize>;
}

struct FdIo(RawFd);

impl PacketIo for FdIo {
    fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = unsafe { libc::read(self.0, buffer.as_mut_ptr().cast(), buffer.len()) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(size as usize)
    }

    fn write(&self, packet: &[u8]) -> io::Result<usize> {
        let size = unsafe { libc::write(self.0, packet.as_ptr().cast(), packet.len()) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(size as usize)
    }
}

/// Read one raw IP packet. The packet has no prefix.
fn read_one(io: &dyn PacketIo, buffer: &mut [u8], mtu: usize) -> io::Result<usize> {
    let size = io.read(buffer)?;
    if size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty tunnel packet",
        ));
    }
    if size > mtu {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tunnel packet is larger than the MTU",
        ));
    }
    if size > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tunnel packet is larger than the buffer",
        ));
    }
    let declared = packet_len(&buffer[..size])?;
    if declared > size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tunnel packet is shorter than its IP header",
        ));
    }
    Ok(declared)
}

/// Write one raw IP packet. The packet has no prefix.
fn write_one(io: &dyn PacketIo, packet: &[u8], mtu: usize) -> io::Result<usize> {
    if packet.is_empty() || packet.len() > mtu {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid packet length",
        ));
    }
    if packet_len(packet)? != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet length does not match its IP header",
        ));
    }
    let size = io.write(packet)?;
    if size != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial tunnel write",
        ));
    }
    Ok(size)
}

/// Return the interface index for a name.
///
/// The TUN device records this value after `TUNSETIFF`. The route proof uses
/// the index as the primary identity. A later name lookup is only a consistency
/// check.
fn interface_index(name: &str) -> io::Result<u32> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

/// A private token for one live [`Tun`] handle.
///
/// The token has no value. Its allocation is the identity. A
/// [`VerifiedInterface`] holds a weak reference, so the proof expires when the
/// device drops. A second device with the same name and index has another
/// allocation.
#[derive(Debug)]
struct TunToken;

/// A nonblocking Linux TUN device.
#[derive(Debug)]
pub struct Tun {
    fd: OwnedFd,
    ifname: String,
    ifindex: u32,
    mtu: usize,
    token: Arc<TunToken>,
}

impl Tun {
    /// Open a TUN device with the requested name and MTU.
    ///
    /// This call needs `CAP_NET_ADMIN` or root. It creates one device and one
    /// descriptor. Every failure path closes the descriptor. Pass the same MTU
    /// to [`LinkGuard::install`]. The descriptor is nonblocking. A future packet
    /// loop must wait for readiness and handle `WouldBlock` and `Interrupted`.
    /// `IFF_TUN_EXCL` refuses an existing device. The method records the
    /// interface index while the device is open. Use [`Tun::ifindex`] as the
    /// route identity.
    pub fn open(ifname: &str, mtu: u32) -> io::Result<Self> {
        let mtu = validate_mtu(mtu)?;
        let mut request = build_ifreq(ifname)?;
        let path = CString::new(TUN_DEVICE)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TUN path"))?;
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw < 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("cannot open {}: {}", TUN_DEVICE, error),
            ));
        }
        // Own the descriptor before any operation that can fail.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = unsafe { CStr::from_ptr(request.name.as_ptr()) }
            .to_str()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tunnel interface name is not valid text",
                )
            })?
            .to_owned();
        if !valid_ifname(&actual) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected tunnel interface name",
            ));
        }
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let ifindex = interface_index(&actual)?;
        Ok(Self {
            fd,
            ifname: actual,
            ifindex,
            mtu,
            token: Arc::new(TunToken),
        })
    }

    /// Return the interface name that the kernel assigned.
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Return the interface index that the kernel assigned.
    ///
    /// The value is read once, while the device exists. Use it as the identity
    /// of the link. Do not resolve the name again for verification.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Return the link MTU in bytes.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Wait for a packet without spinning. Return false when the timeout expires.
    /// An interrupt is returned to the caller so it can check its stop flag.
    pub fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        let millis = timeout.as_millis().saturating_add(u128::from(
            !timeout.subsec_nanos().is_multiple_of(1_000_000),
        ));
        let millis = millis.min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("tunnel device is unavailable"));
        }
        Ok(result > 0 && descriptor.revents & libc::POLLIN != 0)
    }

    /// Read one raw IP packet. Return its length without a prefix.
    ///
    /// The buffer must hold at least the MTU. Reuse the same buffer for every
    /// packet.
    pub fn read_packet<'a>(&self, buffer: &'a mut PacketBuffer) -> io::Result<&'a [u8]> {
        if buffer.data.len() < self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet buffer is smaller than the MTU",
            ));
        }
        let size = read_one(&FdIo(self.fd.as_raw_fd()), &mut buffer.data, self.mtu)?;
        Ok(&buffer.data[..size])
    }

    /// Write one raw IP packet. Return its byte count without a prefix.
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        write_one(&FdIo(self.fd.as_raw_fd()), packet, self.mtu)
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Run a system command without a shell.
/// The program must be an absolute path in a trusted system directory.
trait CommandRunner: Send + Sync {
    fn run(&self, program: &Path, args: &[String]) -> io::Result<()>;
}

struct SystemRunner;

fn run_system(program: &Path, args: &[String]) -> io::Result<std::process::Output> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::other(format!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

impl CommandRunner for SystemRunner {
    fn run(&self, program: &Path, args: &[String]) -> io::Result<()> {
        run_system(program, args).map(|_| ())
    }
}

/// Return the trusted absolute path of the `ip` tool.
fn ip_path() -> io::Result<PathBuf> {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        let path = Path::new(candidate);
        if matches!(std::fs::metadata(path), Ok(metadata) if metadata.is_file()) {
            return Ok(path.to_path_buf());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "the ip tool is not in a system directory",
    ))
}

/// Return the peer address in the same /30 as the tunnel address.
fn peer_in_subnet(address: Ipv4Addr) -> io::Result<Ipv4Addr> {
    if address.octets()[0] == 0
        || address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tunnel address must be a unicast host in a /30",
        ));
    }
    let mut octets = address.octets();
    let host = octets[3] & 3;
    if host != 1 && host != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tunnel address must be a host in a /30",
        ));
    }
    octets[3] = (octets[3] & !3) | (3 - host);
    Ok(Ipv4Addr::from(octets))
}

/// Owns the IPv4 address and link state that the process added.
///
/// Install this after the TUN device exists. Dropping the guard removes the
/// address. The kernel removes the device and its link state when the last
/// descriptor closes.
pub struct LinkGuard {
    ifname: String,
    address: Ipv4Addr,
    peer: Ipv4Addr,
    ip: PathBuf,
    runner: Arc<dyn CommandRunner>,
    address_installed: bool,
}

impl LinkGuard {
    /// Add the point-to-point IPv4 address, set the MTU, and bring the link up.
    /// Use the MTU from [`Tun::open`] and an interface proof for the same live
    /// device.
    pub fn install(
        proof: &VerifiedInterface,
        tun: &Tun,
        address: Ipv4Addr,
        mtu: u32,
    ) -> io::Result<Self> {
        proof.require_tun(tun)?;
        if proof.ifname() != tun.ifname() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface verification names another interface",
            ));
        }
        if validate_mtu(mtu)? != tun.mtu() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the configured MTU does not match the tunnel device",
            ));
        }
        let current = interface_index(tun.ifname()).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot check the tunnel link: {error}"),
            )
        })?;
        if current != tun.ifindex() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the interface index changed after verification",
            ));
        }
        Self::install_with(
            Arc::new(SystemRunner),
            ip_path()?,
            tun.ifname(),
            address,
            mtu,
        )
    }

    /// Install with a fake runner and a fixed tool path.
    fn install_with(
        runner: Arc<dyn CommandRunner>,
        ip: PathBuf,
        ifname: &str,
        address: Ipv4Addr,
        mtu: u32,
    ) -> io::Result<Self> {
        let mtu = validate_mtu(mtu)?;
        let peer = peer_in_subnet(address)?;
        if !valid_ifname(ifname) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid tunnel interface name",
            ));
        }
        if !ip.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the ip tool path must be absolute",
            ));
        }
        let mut guard = Self {
            ifname: ifname.to_owned(),
            address,
            peer,
            ip,
            runner,
            address_installed: false,
        };
        guard
            .runner
            .run(&guard.ip, &guard.address_args("add"))
            .map_err(|error| {
                io::Error::new(error.kind(), format!("cannot add tunnel address: {error}"))
            })?;
        guard.address_installed = true;
        for args in [
            vec![
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                guard.ifname.clone(),
                "mtu".to_owned(),
                mtu.to_string(),
            ],
            vec![
                "link".to_owned(),
                "set".to_owned(),
                "dev".to_owned(),
                guard.ifname.clone(),
                "up".to_owned(),
            ],
        ] {
            if let Err(error) = guard.runner.run(&guard.ip, &args) {
                return Err(guard.rollback(io::Error::new(
                    error.kind(),
                    format!("cannot configure the tunnel link: {error}"),
                )));
            }
        }
        Ok(guard)
    }

    fn address_args(&self, action: &str) -> Vec<String> {
        vec![
            "address".to_owned(),
            action.to_owned(),
            format!("{}/32", self.address),
            "peer".to_owned(),
            self.peer.to_string(),
            "dev".to_owned(),
            self.ifname.clone(),
        ]
    }

    fn rollback(&mut self, error: io::Error) -> io::Error {
        match self.remove() {
            Ok(()) => error,
            Err(cleanup) => io::Error::new(
                error.kind(),
                format!("{error}; address cleanup failed: {cleanup}"),
            ),
        }
    }

    /// Return true while the address is recorded as installed.
    pub fn has_address(&self) -> bool {
        self.address_installed
    }

    /// Remove the address. Keep a failed removal for another attempt.
    pub fn remove(&mut self) -> io::Result<()> {
        if !self.address_installed {
            return Ok(());
        }
        match self.runner.run(&self.ip, &self.address_args("del")) {
            Ok(()) => {
                self.address_installed = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            eprintln!("[route] address cleanup failed: {}", error);
        }
    }
}

/// The interface identity of the tunnel device.
///
/// The index is recorded while the device descriptor is open. The name comes
/// from `TUNSETIFF`. Do not build this value from a name lookup at verification
/// time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelIdentity {
    ifindex: u32,
    name: String,
}

impl TunnelIdentity {
    /// Build an identity from an interface index and name.
    pub fn new(ifindex: u32, name: &str) -> Result<Self, RouteVerifyError> {
        if ifindex == 0 || ifindex > i32::MAX as u32 {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface index must be nonzero and fit in an i32",
            ));
        }
        if !valid_ifname(name) {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface name is not valid",
            ));
        }
        Ok(Self {
            ifindex,
            name: name.to_owned(),
        })
    }

    /// Return the interface index.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Return the interface name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The identity of the physical interface that the outer sockets use.
///
/// This value records an interface index and name. It is not proof that a
/// socket set `SO_BINDTODEVICE`. The normalized socket helper owns that proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OuterLinkIdentity {
    ifindex: u32,
    name: String,
}

impl OuterLinkIdentity {
    /// Build an outer interface identity from an index and a name.
    pub fn new(ifindex: u32, name: &str) -> Result<Self, RouteVerifyError> {
        if ifindex == 0 || ifindex > i32::MAX as u32 {
            return Err(RouteVerifyError::InvalidOuterInterface(
                "the outer interface index must be nonzero and fit in an i32",
            ));
        }
        if !valid_ifname(name) {
            return Err(RouteVerifyError::InvalidOuterInterface(
                "the outer interface name is not valid",
            ));
        }
        Ok(Self {
            ifindex,
            name: name.to_owned(),
        })
    }

    /// Return the interface index.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Return the interface name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Proof that an outer interface is a live, non-tunnel link.
///
/// Only [`RouteManager::verify_outer_pin`] can create this value. It proves
/// the interface index, the name, the link-up flag, and the link type. It does
/// not prove that a socket is bound to the interface. It does not prove that
/// the interface is the physical hotspot. The caller must select that
/// interface.
#[derive(Debug)]
pub struct OuterPinProof {
    manager: Arc<()>,
    identity: OuterLinkIdentity,
}

impl OuterPinProof {
    /// Return the interface name.
    pub fn ifname(&self) -> &str {
        self.identity.name()
    }

    /// Return the interface index.
    pub fn ifindex(&self) -> u32 {
        self.identity.ifindex()
    }
}

/// An IPv4 prefix with an address and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Prefix {
    address: Ipv4Addr,
    length: u8,
}

impl Ipv4Prefix {
    /// Build a prefix. Return `None` for a length above 32 or an address with
    /// host bits set.
    pub fn new(address: Ipv4Addr, length: u8) -> Option<Self> {
        if length > 32 {
            return None;
        }
        if u32::from(address) & mask_v4(length) != u32::from(address) {
            return None;
        }
        Some(Self { address, length })
    }

    /// Return the network address.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Return the prefix length.
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Return true when the prefix contains the address.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & mask_v4(self.length) == u32::from(self.address)
    }
}

impl std::fmt::Display for Ipv4Prefix {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.length)
    }
}

fn mask_v4(length: u8) -> u32 {
    if length == 0 {
        0
    } else if length >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - u32::from(length))
    }
}

/// An IPv6 prefix with an address and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    address: Ipv6Addr,
    length: u8,
}

impl Ipv6Prefix {
    /// Build a prefix. Return `None` for a length above 128 or an address with
    /// host bits set.
    pub fn new(address: Ipv6Addr, length: u8) -> Option<Self> {
        if length > 128 {
            return None;
        }
        if u128::from(address) & mask_v6(length) != u128::from(address) {
            return None;
        }
        Some(Self { address, length })
    }

    /// Return the network address.
    pub fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// Return the prefix length.
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Return true when the prefix contains the address.
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        u128::from(address) & mask_v6(self.length) == u128::from(self.address)
    }
}

impl std::fmt::Display for Ipv6Prefix {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.length)
    }
}

fn mask_v6(length: u8) -> u128 {
    if length == 0 {
        0
    } else if length >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - u32::from(length))
    }
}

/// The global unicast IPv6 prefix. The tunnel owns this prefix in forward
/// mode. Link-local, unique-local, multicast, and NAT64 addresses are outside
/// this prefix.
pub const IPV6_GLOBAL_UNICAST: Ipv6Prefix = Ipv6Prefix {
    address: Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0),
    length: 3,
};

/// The `2001:db8::/32` documentation prefix.
const IPV6_DOCUMENTATION_2001_DB8: Ipv6Prefix = Ipv6Prefix {
    address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
    length: 32,
};

/// The `3fff::/20` documentation prefix.
const IPV6_DOCUMENTATION_3FFF: Ipv6Prefix = Ipv6Prefix {
    address: Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
    length: 20,
};

fn half_prefix(destination: Ipv4Addr) -> Ipv4Prefix {
    if destination.octets()[0] & 0x80 == 0 {
        IPV4_FIRST_HALF
    } else {
        IPV4_SECOND_HALF
    }
}

/// The first IPv4 /1 route. It covers 0.0.0.0 to 127.255.255.255.
pub const IPV4_FIRST_HALF: Ipv4Prefix = Ipv4Prefix {
    address: Ipv4Addr::new(0, 0, 0, 0),
    length: 1,
};

/// The second IPv4 /1 route. It covers 128.0.0.0 to 255.255.255.255.
pub const IPV4_SECOND_HALF: Ipv4Prefix = Ipv4Prefix {
    address: Ipv4Addr::new(128, 0, 0, 0),
    length: 1,
};

/// Default IPv4 probe destinations. Three probes are in the first half and
/// two are in the second half. The route check sends no packet.
pub const DEFAULT_IPV4_PROBES: [Ipv4Addr; 5] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(200, 1, 1, 1),
    Ipv4Addr::new(208, 67, 222, 222),
];

/// Default IPv6 probe destinations. Every probe is inside `2000::/3`. The
/// route check sends no packet.
pub const DEFAULT_IPV6_PROBES: [Ipv6Addr; 3] = [
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe),
];

/// One link from `RTM_GETLINK`, converted to native values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedLink {
    /// The interface index.
    pub ifindex: u32,
    /// The interface name.
    pub name: String,
    /// The `IFLA_INFO_KIND` value. A TUN link uses `tun`.
    pub kind: Option<String>,
    /// The `ifi_type` value. A TUN link uses `ARPHRD_NONE`.
    pub hardware_type: u16,
    /// The `ifi_flags` value.
    pub flags: u32,
}

/// One FIB entry from `RTM_GETROUTE` with `RTM_F_FIB_MATCH`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedRoute {
    /// The matched prefix.
    pub prefix: Ipv4Prefix,
    /// The `rtm_src_len` value. A source-specific route uses a nonzero value.
    pub source_length: u8,
    /// The source selector, when the kernel reports one.
    pub source: Option<Ipv4Addr>,
    /// The `rtm_tos` selector.
    pub tos: u8,
    /// The routing table that the policy lookup selected.
    pub table: u32,
    /// The route protocol marker.
    pub protocol: u8,
    /// The `rtm_type` value.
    pub route_type: u8,
    /// The output interface. A blackhole route has no output interface.
    pub ifindex: Option<u32>,
    /// The gateway, when the route has one.
    pub gateway: Option<Ipv4Addr>,
    /// The preferred source address, when the kernel reports one.
    pub prefsrc: Option<Ipv4Addr>,
    /// The `RTA_FLOW` class id, when the kernel reports one.
    pub flow: Option<u32>,
    /// True when `RTA_MULTIPATH` is present.
    pub multipath: bool,
    /// True when `RTA_VIA` is present.
    pub via: bool,
    /// True when an encapsulation attribute is present.
    pub encap: bool,
    /// The `RTA_NH_ID` value, when a nexthop object is used.
    pub nexthop_id: Option<u32>,
    /// True when the route has the dead flag.
    pub dead: bool,
    /// True when the route has the link-down flag.
    pub link_down: bool,
    /// The route priority, when the kernel reports one.
    pub priority: Option<u32>,
}

/// One fake probe and the route that the kernel selected for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedProbe {
    /// The probe destination.
    pub destination: Ipv4Addr,
    /// The selected FIB entry.
    pub route: ObservedRoute,
}

/// The read-only route data that one check collected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteObservation {
    /// The tunnel link.
    pub link: ObservedLink,
    /// The probe results.
    pub probes: Vec<ObservedProbe>,
}

/// One route that the check proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenRoute {
    /// The proven prefix.
    pub prefix: Ipv4Prefix,
    /// The routing table.
    pub table: u32,
    /// The protocol marker.
    pub protocol: u8,
    /// The output interface.
    pub ifindex: u32,
    /// The route priority, when the kernel reports one.
    pub priority: Option<u32>,
}

/// The IPv4 part of a successful route check.
///
/// This value proves the two /1 routes and the probe destinations only. It
/// does not prove that no other route can bypass the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenIpv4Routes {
    /// The tunnel interface index.
    pub ifindex: u32,
    /// The tunnel interface name.
    pub ifname: String,
    /// The proven first-half route.
    pub first_half: ProvenRoute,
    /// The proven second-half route.
    pub second_half: ProvenRoute,
    /// The number of probes that matched.
    pub probes_checked: usize,
}

/// One FIB entry from an IPv6 `RTM_GETROUTE` with `RTM_F_FIB_MATCH`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedIpv6Route {
    /// The matched prefix.
    pub prefix: Ipv6Prefix,
    /// The `rtm_src_len` value. A source-specific route uses a nonzero value.
    pub source_length: u8,
    /// The source selector, when the kernel reports one.
    pub source: Option<Ipv6Addr>,
    /// The `rtm_tos` selector.
    pub tos: u8,
    /// The routing table that the kernel reports.
    pub table: u32,
    /// The route protocol marker.
    pub protocol: u8,
    /// The `rtm_type` value.
    pub route_type: u8,
    /// The output interface. A blackhole route has no output interface.
    pub ifindex: Option<u32>,
    /// The gateway, when the route has one.
    pub gateway: Option<Ipv6Addr>,
    /// The preferred source address, when the kernel reports one.
    pub prefsrc: Option<Ipv6Addr>,
    /// The `RTA_FLOW` class id, when the kernel reports one.
    pub flow: Option<u32>,
    /// True when `RTA_MULTIPATH` is present.
    pub multipath: bool,
    /// True when `RTA_VIA` is present.
    pub via: bool,
    /// True when an encapsulation attribute is present.
    pub encap: bool,
    /// The `RTA_NH_ID` value, when a nexthop object is used.
    pub nexthop_id: Option<u32>,
    /// True when the route has the dead flag.
    pub dead: bool,
    /// True when the route has the link-down flag.
    pub link_down: bool,
    /// True when the kernel returned a resolved route, not a FIB entry.
    pub cloned: bool,
    /// The route priority, when the kernel reports one.
    pub priority: Option<u32>,
}

/// One IPv6 fake probe and the route that the kernel selected for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedIpv6Probe {
    /// The probe destination.
    pub destination: Ipv6Addr,
    /// The selected FIB entry.
    pub route: ObservedIpv6Route,
}

/// The read-only IPv6 route data that one check collected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6RouteObservation {
    /// The tunnel link.
    pub link: ObservedLink,
    /// The physical interface that the outer sockets use.
    pub outer_link: ObservedLink,
    /// The probe results.
    pub probes: Vec<ObservedIpv6Probe>,
}

/// The IPv6 forward route that the check proved.
///
/// This value proves the exact `2000::/3` route, the tunnel output interface,
/// and the finite probe set. It does not prove that this process installed the
/// route. It does not prove that no other route can bypass the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenIpv6Route {
    /// The proven prefix.
    pub prefix: Ipv6Prefix,
    /// The routing table.
    pub table: u32,
    /// The protocol marker.
    pub protocol: u8,
    /// The tunnel output interface.
    pub ifindex: u32,
    /// The outer interface from the pin proof.
    pub outer_ifindex: u32,
    /// The route priority, when the kernel reports one.
    pub priority: Option<u32>,
    /// The number of probes that matched.
    pub probes_checked: usize,
}

/// The IPv6 block policy that the check proved.
///
/// This value proves that the dedicated table holds the recorded blackhole
/// route and that every probe selected a non-unicast FIB entry. It does not
/// prove that this process installed the route. It does not prove that no
/// more-specific route can bypass the blackhole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenIpv6Block {
    /// The proven prefix.
    pub prefix: Ipv6Prefix,
    /// The routing table.
    pub table: u32,
    /// The protocol marker.
    pub protocol: u8,
    /// The number of blocked probes.
    pub probes_checked: usize,
}

/// One IPv6 block probe and its policy result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockedIpv6Probe {
    /// The probe destination.
    pub destination: Ipv6Addr,
    /// True when the kernel reported a non-unicast FIB entry.
    pub blocked: bool,
}

/// The read-only IPv6 block data that one check collected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6BlockObservation {
    /// The tunnel link.
    pub link: ObservedLink,
    /// True when the dedicated table holds exactly the recorded blackhole.
    pub route_recorded: bool,
    /// The probe results.
    pub probes: Vec<BlockedIpv6Probe>,
}

/// A reason that the route check did not prove the policy.
///
/// Every variant is a failure. [`RouteVerifyError::is_inconclusive`] is true
/// only when the check could not observe the state. A route mismatch and a
/// missing link are observed failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteVerifyError {
    /// The tunnel identity is not usable.
    InvalidTunnelIdentity(&'static str),
    /// The probe policy is not usable.
    InvalidPolicy(&'static str),
    /// The outer interface identity is not usable.
    InvalidOuterInterface(&'static str),
    /// The route manager has no complete set of installed routes.
    NotInstalled,
    /// The interface index does not exist.
    LinkMissing {
        /// The missing interface index.
        ifindex: u32,
    },
    /// The link is not the recorded TUN link.
    LinkMismatch(&'static str),
    /// The outer link is not the recorded outer interface.
    OuterLinkMismatch(&'static str),
    /// A read-only operation did not complete. The state is unknown.
    Unavailable {
        /// The operation name.
        operation: &'static str,
        /// The kernel error number. `ETIMEDOUT` means a reply timeout.
        errno: i32,
    },
    /// A netlink reply was not valid. The state is unknown.
    MalformedReply(&'static str),
    /// The observation has no probe for a requested destination.
    MissingProbe {
        /// The requested probe destination.
        destination: Ipv4Addr,
    },
    /// The kernel has no route to the destination.
    NoRoute {
        /// The probe destination.
        destination: Ipv4Addr,
    },
    /// The selected route is not the expected /1 prefix.
    UnexpectedPrefix {
        /// The probe destination.
        destination: Ipv4Addr,
        /// The required prefix.
        expected: Ipv4Prefix,
        /// The selected prefix.
        actual: Ipv4Prefix,
    },
    /// The selected route uses another interface or no interface.
    ForeignInterface {
        /// The prefix.
        prefix: Ipv4Prefix,
        /// The tunnel interface index.
        expected: u32,
        /// The interface from the selected route.
        actual: Option<u32>,
    },
    /// The selected route has another protocol marker.
    UnexpectedProtocol {
        /// The prefix.
        prefix: Ipv4Prefix,
        /// The required marker.
        expected: u8,
        /// The marker from the selected route.
        actual: u8,
    },
    /// The selected route is in another table.
    UnexpectedTable {
        /// The prefix.
        prefix: Ipv4Prefix,
        /// The required table.
        expected: u32,
        /// The table from the selected route.
        actual: u32,
    },
    /// The selected route is not a unicast route.
    NonUnicastRoute {
        /// The prefix.
        prefix: Ipv4Prefix,
        /// The route type from the selected route.
        route_type: u8,
    },
    /// The selected route uses a gateway.
    RouteGateway {
        /// The prefix.
        prefix: Ipv4Prefix,
    },
    /// The selected route is a multipath route.
    MultipathRoute {
        /// The prefix.
        prefix: Ipv4Prefix,
    },
    /// The selected route uses an encapsulation.
    EncapsulatedRoute {
        /// The prefix.
        prefix: Ipv4Prefix,
    },
    /// The selected route uses a nexthop object.
    NexthopObjectRoute {
        /// The prefix.
        prefix: Ipv4Prefix,
    },
    /// The selected route is dead or link-down.
    RouteDown {
        /// The prefix.
        prefix: Ipv4Prefix,
    },
    /// The IPv6 observation has no probe for a requested destination.
    MissingIpv6Probe {
        /// The requested probe destination.
        destination: Ipv6Addr,
    },
    /// The kernel has no IPv6 route to the destination.
    NoIpv6Route {
        /// The probe destination.
        destination: Ipv6Addr,
    },
    /// The selected IPv6 route is not the expected `2000::/3` prefix.
    UnexpectedIpv6Prefix {
        /// The probe destination.
        destination: Ipv6Addr,
        /// The required prefix.
        expected: Ipv6Prefix,
        /// The selected prefix.
        actual: Ipv6Prefix,
    },
    /// The selected IPv6 route uses another interface or no interface.
    Ipv6ForeignInterface {
        /// The prefix.
        prefix: Ipv6Prefix,
        /// The tunnel interface index.
        expected: u32,
        /// The interface from the selected route.
        actual: Option<u32>,
    },
    /// The selected IPv6 route has another protocol marker.
    Ipv6UnexpectedProtocol {
        /// The prefix.
        prefix: Ipv6Prefix,
        /// The required marker.
        expected: u8,
        /// The marker from the selected route.
        actual: u8,
    },
    /// The selected IPv6 route is in another table.
    Ipv6UnexpectedTable {
        /// The prefix.
        prefix: Ipv6Prefix,
        /// The required table.
        expected: u32,
        /// The table from the selected route.
        actual: u32,
    },
    /// The selected IPv6 route is not a unicast route.
    Ipv6NonUnicastRoute {
        /// The prefix.
        prefix: Ipv6Prefix,
        /// The route type from the selected route.
        route_type: u8,
    },
    /// The selected IPv6 route uses a gateway.
    Ipv6RouteGateway {
        /// The prefix.
        prefix: Ipv6Prefix,
    },
    /// The selected IPv6 route is a multipath route.
    Ipv6MultipathRoute {
        /// The prefix.
        prefix: Ipv6Prefix,
    },
    /// The selected IPv6 route uses an encapsulation.
    Ipv6EncapsulatedRoute {
        /// The prefix.
        prefix: Ipv6Prefix,
    },
    /// The selected IPv6 route uses a nexthop object.
    Ipv6NexthopObjectRoute {
        /// The prefix.
        prefix: Ipv6Prefix,
    },
    /// The selected IPv6 route is dead or link-down.
    Ipv6RouteDown {
        /// The prefix.
        prefix: Ipv6Prefix,
    },
    /// The selected IPv6 route has a source selector.
    Ipv6SourceSpecificRoute {
        /// The prefix.
        prefix: Ipv6Prefix,
    },
    /// The kernel returned a resolved IPv6 route, not a FIB entry.
    Ipv6ClonedRoute {
        /// The prefix.
        prefix: Ipv6Prefix,
    },
    /// The IPv6 forward check requires the forward policy.
    Ipv6ForwardPolicyRequired,
    /// The IPv6 block route is not recorded in the dedicated table.
    Ipv6BlockNotRecorded,
    /// An IPv6 probe selected a unicast route instead of the blackhole.
    Ipv6BlockBypass {
        /// The probe destination.
        destination: Ipv6Addr,
    },
    /// The full IPv6 forward start policy is not verified.
    Ipv6ForwardUnverified,
    /// The inherit policy is not a start mode.
    Ipv6InheritNotAllowed,
}

impl RouteVerifyError {
    /// Return true when the check could not observe the state.
    ///
    /// An inconclusive result is not a success. It is also not proof that the
    /// route failed. A caller must treat both cases as fail closed.
    pub fn is_inconclusive(&self) -> bool {
        matches!(
            self,
            Self::Unavailable { .. }
                | Self::MalformedReply(_)
                | Self::MissingProbe { .. }
                | Self::MissingIpv6Probe { .. }
        )
    }
}

impl std::fmt::Display for RouteVerifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTunnelIdentity(message) => write!(formatter, "{message}"),
            Self::InvalidPolicy(message) => write!(formatter, "invalid route policy: {message}"),
            Self::InvalidOuterInterface(message) => {
                write!(formatter, "invalid outer interface: {message}")
            }
            Self::NotInstalled => write!(formatter, "the tunnel routes are not recorded as installed"),
            Self::LinkMissing { ifindex } => {
                write!(formatter, "interface {ifindex} does not exist")
            }
            Self::LinkMismatch(message) => write!(formatter, "{message}"),
            Self::OuterLinkMismatch(message) => write!(formatter, "{message}"),
            Self::Unavailable { operation, errno } => {
                write!(formatter, "{operation} did not complete: kernel error {errno}")
            }
            Self::MalformedReply(message) => {
                write!(formatter, "the netlink data is not valid: {message}")
            }
            Self::MissingProbe { destination } => {
                write!(formatter, "the route observation has no probe for {destination}")
            }
            Self::NoRoute { destination } => {
                write!(formatter, "the kernel has no route to {destination}")
            }
            Self::UnexpectedPrefix {
                destination,
                expected,
                actual,
            } => write!(
                formatter,
                "the kernel selects {actual} for {destination}, not {expected}"
            ),
            Self::ForeignInterface {
                prefix,
                expected,
                actual,
            } => match actual {
                Some(actual) => write!(
                    formatter,
                    "the {prefix} route uses interface {actual}, not the tunnel interface {expected}"
                ),
                None => write!(
                    formatter,
                    "the {prefix} route has no output interface; the tunnel interface is {expected}"
                ),
            },
            Self::UnexpectedProtocol {
                prefix,
                expected,
                actual,
            } => write!(
                formatter,
                "the {prefix} route has protocol marker {actual}, not {expected}"
            ),
            Self::UnexpectedTable {
                prefix,
                expected,
                actual,
            } => write!(
                formatter,
                "the {prefix} route is in table {actual}, not table {expected}"
            ),
            Self::NonUnicastRoute { prefix, route_type } => {
                write!(formatter, "the {prefix} route has type {route_type}, not unicast")
            }
            Self::RouteGateway { prefix } => {
                write!(formatter, "the {prefix} route uses a gateway")
            }
            Self::MultipathRoute { prefix } => {
                write!(formatter, "the {prefix} route is a multipath route")
            }
            Self::EncapsulatedRoute { prefix } => {
                write!(formatter, "the {prefix} route uses an encapsulation")
            }
            Self::NexthopObjectRoute { prefix } => {
                write!(formatter, "the {prefix} route uses a nexthop object")
            }
            Self::RouteDown { prefix } => {
                write!(formatter, "the {prefix} route is dead or link-down")
            }
            Self::MissingIpv6Probe { destination } => {
                write!(
                    formatter,
                    "the IPv6 route observation has no probe for {destination}"
                )
            }
            Self::NoIpv6Route { destination } => {
                write!(formatter, "the kernel has no IPv6 route to {destination}")
            }
            Self::UnexpectedIpv6Prefix {
                destination,
                expected,
                actual,
            } => write!(
                formatter,
                "the kernel selects {actual} for {destination}, not {expected}"
            ),
            Self::Ipv6ForeignInterface {
                prefix,
                expected,
                actual,
            } => match actual {
                Some(actual) => write!(
                    formatter,
                    "the {prefix} IPv6 route uses interface {actual}, not the tunnel interface {expected}"
                ),
                None => write!(
                    formatter,
                    "the {prefix} IPv6 route has no output interface; the tunnel interface is {expected}"
                ),
            },
            Self::Ipv6UnexpectedProtocol {
                prefix,
                expected,
                actual,
            } => write!(
                formatter,
                "the {prefix} IPv6 route has protocol marker {actual}, not {expected}"
            ),
            Self::Ipv6UnexpectedTable {
                prefix,
                expected,
                actual,
            } => write!(
                formatter,
                "the {prefix} IPv6 route is in table {actual}, not table {expected}"
            ),
            Self::Ipv6NonUnicastRoute { prefix, route_type } => {
                write!(
                    formatter,
                    "the {prefix} IPv6 route has type {route_type}, not unicast"
                )
            }
            Self::Ipv6RouteGateway { prefix } => {
                write!(formatter, "the {prefix} IPv6 route uses a gateway")
            }
            Self::Ipv6MultipathRoute { prefix } => {
                write!(formatter, "the {prefix} IPv6 route is a multipath route")
            }
            Self::Ipv6EncapsulatedRoute { prefix } => {
                write!(formatter, "the {prefix} IPv6 route uses an encapsulation")
            }
            Self::Ipv6NexthopObjectRoute { prefix } => {
                write!(formatter, "the {prefix} IPv6 route uses a nexthop object")
            }
            Self::Ipv6RouteDown { prefix } => {
                write!(formatter, "the {prefix} IPv6 route is dead or link-down")
            }
            Self::Ipv6SourceSpecificRoute { prefix } => {
                write!(formatter, "the {prefix} IPv6 route has a source selector")
            }
            Self::Ipv6ClonedRoute { prefix } => {
                write!(
                    formatter,
                    "the {prefix} IPv6 route is a resolved route, not a FIB entry"
                )
            }
            Self::Ipv6ForwardPolicyRequired => {
                write!(formatter, "the IPv6 forward check requires the forward policy")
            }
            Self::Ipv6BlockNotRecorded => {
                write!(
                    formatter,
                    "the IPv6 block route is not recorded in the dedicated table"
                )
            }
            Self::Ipv6BlockBypass { destination } => write!(
                formatter,
                "the kernel selects a unicast route for {destination}; the IPv6 block is not active"
            ),
            Self::Ipv6ForwardUnverified => {
                write!(
                    formatter,
                    "the Linux IPv6 forward start policy is not verified"
                )
            }
            Self::Ipv6InheritNotAllowed => write!(
                formatter,
                "Linux start requires the IPv6 block policy; inherit is not a start mode"
            ),
        }
    }
}

impl std::error::Error for RouteVerifyError {}

/// Return true for one fake probe destination.
fn valid_probe(destination: Ipv4Addr) -> bool {
    let octets = destination.octets();
    !destination.is_unspecified()
        && !destination.is_loopback()
        && !destination.is_multicast()
        && !destination.is_broadcast()
        && octets[0] != 0
        && !(octets[0] == 169 && octets[1] == 254)
}

fn validate_probes(probes: &[ObservedProbe]) -> Result<(), RouteVerifyError> {
    let mut seen = Vec::new();
    for probe in probes {
        if !valid_probe(probe.destination) {
            return Err(RouteVerifyError::InvalidPolicy(
                "every probe must be a unicast host outside special-use ranges",
            ));
        }
        if seen.contains(&probe.destination) {
            return Err(RouteVerifyError::InvalidPolicy(
                "the probe list has a duplicate destination",
            ));
        }
        seen.push(probe.destination);
    }
    let first = probes
        .iter()
        .any(|probe| half_prefix(probe.destination) == IPV4_FIRST_HALF);
    let second = probes
        .iter()
        .any(|probe| half_prefix(probe.destination) == IPV4_SECOND_HALF);
    if !first || !second {
        return Err(RouteVerifyError::InvalidPolicy(
            "the probe list needs one destination in each /1 half",
        ));
    }
    Ok(())
}

/// Return true for one fake IPv6 probe destination.
///
/// The probe must be a global unicast host in `2000::/3`. Documentation
/// prefixes are rejected.
fn valid_ipv6_probe(destination: Ipv6Addr) -> bool {
    IPV6_GLOBAL_UNICAST.contains(destination)
        && !destination.is_unspecified()
        && !destination.is_loopback()
        && !destination.is_multicast()
        && !IPV6_DOCUMENTATION_2001_DB8.contains(destination)
        && !IPV6_DOCUMENTATION_3FFF.contains(destination)
}

fn validate_ipv6_probes(probes: &[ObservedIpv6Probe]) -> Result<(), RouteVerifyError> {
    if probes.is_empty() {
        return Err(RouteVerifyError::InvalidPolicy(
            "the IPv6 probe list needs at least one destination",
        ));
    }
    let mut seen = Vec::new();
    for probe in probes {
        if !valid_ipv6_probe(probe.destination) {
            return Err(RouteVerifyError::InvalidPolicy(
                "every IPv6 probe must be a global unicast host in 2000::/3",
            ));
        }
        if seen.contains(&probe.destination) {
            return Err(RouteVerifyError::InvalidPolicy(
                "the IPv6 probe list has a duplicate destination",
            ));
        }
        seen.push(probe.destination);
    }
    Ok(())
}

fn verify_link_identity(
    link: &ObservedLink,
    identity: &TunnelIdentity,
) -> Result<(), RouteVerifyError> {
    if link.ifindex != identity.ifindex {
        return Err(RouteVerifyError::LinkMismatch(
            "the link index does not match the tunnel identity",
        ));
    }
    if link.name != identity.name {
        return Err(RouteVerifyError::LinkMismatch(
            "the link name does not match the tunnel identity",
        ));
    }
    if link.kind.as_deref() != Some("tun") {
        return Err(RouteVerifyError::LinkMismatch(
            "the link is not a TUN device",
        ));
    }
    if link.hardware_type != ARPHRD_NONE {
        return Err(RouteVerifyError::LinkMismatch(
            "the link hardware type is not TUN",
        ));
    }
    Ok(())
}

fn verify_link(link: &ObservedLink, identity: &TunnelIdentity) -> Result<(), RouteVerifyError> {
    verify_link_identity(link, identity)?;
    if link.flags & IFF_UP == 0 {
        return Err(RouteVerifyError::LinkMismatch("the tunnel link is not up"));
    }
    Ok(())
}

fn validate_route(
    probe: &ObservedProbe,
    expected: Ipv4Prefix,
    identity: &TunnelIdentity,
    table: u32,
) -> Result<(), RouteVerifyError> {
    let route = &probe.route;
    let prefix = route.prefix;
    if prefix != expected {
        return Err(RouteVerifyError::UnexpectedPrefix {
            destination: probe.destination,
            expected,
            actual: prefix,
        });
    }
    if route.table != table {
        return Err(RouteVerifyError::UnexpectedTable {
            prefix,
            expected: table,
            actual: route.table,
        });
    }

    if route.protocol != ROUTE_PROTOCOL_ID {
        return Err(RouteVerifyError::UnexpectedProtocol {
            prefix,
            expected: ROUTE_PROTOCOL_ID,
            actual: route.protocol,
        });
    }
    if route.route_type != RTN_UNICAST {
        return Err(RouteVerifyError::NonUnicastRoute {
            prefix,
            route_type: route.route_type,
        });
    }
    if route.ifindex != Some(identity.ifindex) {
        return Err(RouteVerifyError::ForeignInterface {
            prefix,
            expected: identity.ifindex,
            actual: route.ifindex,
        });
    }
    if route.gateway.is_some() || route.via {
        return Err(RouteVerifyError::RouteGateway { prefix });
    }
    if route.multipath {
        return Err(RouteVerifyError::MultipathRoute { prefix });
    }
    if route.encap {
        return Err(RouteVerifyError::EncapsulatedRoute { prefix });
    }
    if route.nexthop_id.is_some() {
        return Err(RouteVerifyError::NexthopObjectRoute { prefix });
    }
    if route.dead || route.link_down {
        return Err(RouteVerifyError::RouteDown { prefix });
    }
    Ok(())
}

/// Prove the two IPv4 /1 routes from one observation.
///
/// This function is pure. It changes no route and sends no packet. It proves
/// the exact prefixes, the main table, the protocol marker, the unicast type,
/// the tunnel interface index, and the absence of a gateway, multipath,
/// encapsulation, nexthop object, and a down route.
///
/// A successful result is not proof that no traffic can bypass the tunnel. See
/// the module documentation.
pub fn verify_ipv4_selection(
    observation: &RouteObservation,
    identity: &TunnelIdentity,
) -> Result<ProvenIpv4Routes, RouteVerifyError> {
    verify_ipv4_selection_in(observation, identity, RT_TABLE_MAIN)
}

/// Prove the two IPv4 /1 routes in a named table.
///
/// This function is the same check as [`verify_ipv4_selection`], with an
/// explicit table id. The tunnel start path uses [`TUNNEL_TABLE`].
pub fn verify_ipv4_selection_in(
    observation: &RouteObservation,
    identity: &TunnelIdentity,
    table: u32,
) -> Result<ProvenIpv4Routes, RouteVerifyError> {
    verify_link(&observation.link, identity)?;
    validate_probes(&observation.probes)?;
    let mut first_half = None;
    let mut second_half = None;
    let mut first_count = 0usize;
    let mut second_count = 0usize;
    for probe in &observation.probes {
        let expected = half_prefix(probe.destination);
        validate_route(probe, expected, identity, table)?;
        let proven = ProvenRoute {
            prefix: expected,
            table,
            protocol: ROUTE_PROTOCOL_ID,
            ifindex: identity.ifindex,
            priority: probe.route.priority,
        };

        if expected == IPV4_FIRST_HALF {
            first_half = Some(proven);
            first_count += 1;
        } else {
            second_half = Some(proven);
            second_count += 1;
        }
    }
    let Some(first_half) = first_half else {
        return Err(RouteVerifyError::InvalidPolicy(
            "the probe list has no destination in 0.0.0.0/1",
        ));
    };
    let Some(second_half) = second_half else {
        return Err(RouteVerifyError::InvalidPolicy(
            "the probe list has no destination in 128.0.0.0/1",
        ));
    };
    Ok(ProvenIpv4Routes {
        ifindex: identity.ifindex,
        ifname: identity.name.clone(),
        first_half,
        second_half,
        probes_checked: first_count + second_count,
    })
}

/// Prove that an observed link is the recorded outer interface.
///
/// The link must be up, must not be loopback, must not be a TUN or TAP device,
/// and must not use `ARPHRD_NONE`. This function does not prove that a socket
/// is bound to the interface.
fn prove_outer_link(
    link: &ObservedLink,
    identity: &OuterLinkIdentity,
) -> Result<(), RouteVerifyError> {
    if link.ifindex != identity.ifindex {
        return Err(RouteVerifyError::OuterLinkMismatch(
            "the outer link index does not match the outer interface",
        ));
    }
    if link.name != identity.name {
        return Err(RouteVerifyError::OuterLinkMismatch(
            "the outer link name does not match the outer interface",
        ));
    }
    if link.flags & IFF_UP == 0 {
        return Err(RouteVerifyError::OuterLinkMismatch(
            "the outer link is not up",
        ));
    }
    if link.flags & IFF_LOOPBACK != 0 {
        return Err(RouteVerifyError::OuterLinkMismatch(
            "the outer link is a loopback link",
        ));
    }
    if link.hardware_type == ARPHRD_NONE {
        return Err(RouteVerifyError::OuterLinkMismatch(
            "the outer link has no hardware type",
        ));
    }
    if let Some(kind) = link.kind.as_deref() {
        if NON_PHYSICAL_LINK_KINDS.contains(&kind) {
            return Err(RouteVerifyError::OuterLinkMismatch(
                "the outer link is a tunnel or virtual link",
            ));
        }
    }
    Ok(())
}

fn validate_ipv6_route(
    probe: &ObservedIpv6Probe,
    expected: Ipv6Prefix,
    identity: &TunnelIdentity,
    table: u32,
) -> Result<(), RouteVerifyError> {
    let route = &probe.route;
    let prefix = route.prefix;
    if route.cloned {
        return Err(RouteVerifyError::Ipv6ClonedRoute { prefix });
    }
    if prefix != expected {
        return Err(RouteVerifyError::UnexpectedIpv6Prefix {
            destination: probe.destination,
            expected,
            actual: prefix,
        });
    }
    if route.source_length != 0 || route.source.is_some() {
        return Err(RouteVerifyError::Ipv6SourceSpecificRoute { prefix });
    }
    if route.table != table {
        return Err(RouteVerifyError::Ipv6UnexpectedTable {
            prefix,
            expected: table,
            actual: route.table,
        });
    }

    if route.protocol != ROUTE_PROTOCOL_ID {
        return Err(RouteVerifyError::Ipv6UnexpectedProtocol {
            prefix,
            expected: ROUTE_PROTOCOL_ID,
            actual: route.protocol,
        });
    }
    if route.route_type != RTN_UNICAST {
        return Err(RouteVerifyError::Ipv6NonUnicastRoute {
            prefix,
            route_type: route.route_type,
        });
    }
    if route.gateway.is_some() || route.via {
        return Err(RouteVerifyError::Ipv6RouteGateway { prefix });
    }
    if route.multipath {
        return Err(RouteVerifyError::Ipv6MultipathRoute { prefix });
    }
    if route.encap {
        return Err(RouteVerifyError::Ipv6EncapsulatedRoute { prefix });
    }
    if route.nexthop_id.is_some() {
        return Err(RouteVerifyError::Ipv6NexthopObjectRoute { prefix });
    }
    if route.ifindex != Some(identity.ifindex) {
        return Err(RouteVerifyError::Ipv6ForeignInterface {
            prefix,
            expected: identity.ifindex,
            actual: route.ifindex,
        });
    }
    if route.dead || route.link_down {
        return Err(RouteVerifyError::Ipv6RouteDown { prefix });
    }
    Ok(())
}

/// Prove the IPv6 forward route from one observation.
///
/// This function is pure. It changes no route and sends no packet. It proves
/// the exact `2000::/3` prefix, the main table, the protocol marker, the
/// unicast type, the tunnel output interface, no gateway, no multipath, no
/// encapsulation, no nexthop object, no source selector, and a live route. The
/// tunnel link and the outer link must be up. The outer link must differ from
/// the tunnel link.
///
/// A successful result is not proof that this process installed the route. It
/// is not proof that the outer sockets are pinned. It is not proof that no
/// traffic can bypass the tunnel. See the module documentation.
pub fn verify_ipv6_forward_selection(
    observation: &Ipv6RouteObservation,
    identity: &TunnelIdentity,
    outer: &OuterLinkIdentity,
) -> Result<ProvenIpv6Route, RouteVerifyError> {
    verify_ipv6_forward_selection_in(observation, identity, outer, RT_TABLE_MAIN)
}

/// Prove the IPv6 forward route in a named table.
///
/// This function is the same check as [`verify_ipv6_forward_selection`], with
/// an explicit table id. The tunnel start path uses [`TUNNEL_TABLE`].
pub fn verify_ipv6_forward_selection_in(
    observation: &Ipv6RouteObservation,
    identity: &TunnelIdentity,
    outer: &OuterLinkIdentity,
    table: u32,
) -> Result<ProvenIpv6Route, RouteVerifyError> {
    verify_link(&observation.link, identity)?;
    prove_outer_link(&observation.outer_link, outer)?;
    if outer.ifindex == identity.ifindex {
        return Err(RouteVerifyError::InvalidOuterInterface(
            "the outer interface is the tunnel interface",
        ));
    }
    validate_ipv6_probes(&observation.probes)?;
    for probe in &observation.probes {
        validate_ipv6_route(probe, IPV6_GLOBAL_UNICAST, identity, table)?;
    }
    let first = &observation.probes[0];
    Ok(ProvenIpv6Route {
        prefix: IPV6_GLOBAL_UNICAST,
        table,
        protocol: ROUTE_PROTOCOL_ID,
        ifindex: identity.ifindex,
        outer_ifindex: outer.ifindex,
        priority: first.route.priority,
        probes_checked: observation.probes.len(),
    })
}

/// Prove the IPv6 block policy from one observation.
///
/// This function is pure. It changes no route and sends no packet. It proves
/// the tunnel link, the recorded `2000::/3` blackhole in the dedicated table,
/// and one non-unicast FIB result for every probe. It does not prove that this
/// process installed the route. A more-specific route can still bypass the
/// blackhole. See the module documentation.
pub fn verify_ipv6_block_selection_in(
    observation: &Ipv6BlockObservation,
    identity: &TunnelIdentity,
    table: u32,
) -> Result<ProvenIpv6Block, RouteVerifyError> {
    verify_link(&observation.link, identity)?;
    if !observation.route_recorded {
        return Err(RouteVerifyError::Ipv6BlockNotRecorded);
    }
    let mut seen = Vec::new();
    for probe in &observation.probes {
        if !valid_ipv6_probe(probe.destination) {
            return Err(RouteVerifyError::InvalidPolicy(
                "every IPv6 block probe must be a global unicast host",
            ));
        }
        if seen.contains(&probe.destination) {
            return Err(RouteVerifyError::InvalidPolicy(
                "the IPv6 block probe list has a duplicate destination",
            ));
        }
        seen.push(probe.destination);
    }
    for destination in DEFAULT_IPV6_PROBES {
        if !observation
            .probes
            .iter()
            .any(|probe| probe.destination == destination)
        {
            return Err(RouteVerifyError::MissingIpv6Probe { destination });
        }
    }
    for probe in &observation.probes {
        if !probe.blocked {
            return Err(RouteVerifyError::Ipv6BlockBypass {
                destination: probe.destination,
            });
        }
    }
    Ok(ProvenIpv6Block {
        prefix: IPV6_GLOBAL_UNICAST,
        table,
        protocol: ROUTE_PROTOCOL_ID,
        probes_checked: observation.probes.len(),
    })
}

/// One read-only IPv6 block observation layer. Tests use a fake layer.
trait Ipv6BlockObserver: Send + Sync {
    /// Read the tunnel link, the dedicated table, and every block probe.
    fn observe_ipv6_block(
        &self,
        identity: &TunnelIdentity,
        probes: &[Ipv6Addr],
        table: u32,
    ) -> Result<Ipv6BlockObservation, RouteVerifyError>;
}

struct SystemIpv6BlockObserver;

impl Ipv6BlockObserver for SystemIpv6BlockObserver {
    fn observe_ipv6_block(
        &self,
        identity: &TunnelIdentity,
        probes: &[Ipv6Addr],
        table: u32,
    ) -> Result<Ipv6BlockObservation, RouteVerifyError> {
        let netlink = NetlinkRoute::open()?;
        let link = netlink.link(identity.ifindex)?;
        let routes = netlink.table_routes(libc::AF_INET6 as u8, table)?;
        let route_recorded = route_is_recorded(&routes, &RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST));
        let mut observed = Vec::with_capacity(probes.len());
        for destination in probes {
            observed.push(BlockedIpv6Probe {
                destination: *destination,
                blocked: netlink.route_ipv6_blocked(*destination)?,
            });
        }
        Ok(Ipv6BlockObservation {
            link,
            route_recorded,
            probes: observed,
        })
    }
}

/// One read-only observation layer. Tests use a fake layer.
trait RouteObserver: Send + Sync {
    /// Read the link and the selected route for every probe.
    fn observe(
        &self,
        identity: &TunnelIdentity,
        probes: &[Ipv4Addr],
    ) -> Result<RouteObservation, RouteVerifyError>;
}

struct SystemRouteObserver;

impl RouteObserver for SystemRouteObserver {
    fn observe(
        &self,
        identity: &TunnelIdentity,
        probes: &[Ipv4Addr],
    ) -> Result<RouteObservation, RouteVerifyError> {
        let netlink = NetlinkRoute::open()?;
        let link = netlink.link(identity.ifindex)?;
        let mut observed = Vec::with_capacity(probes.len());
        for destination in probes {
            observed.push(ObservedProbe {
                destination: *destination,
                route: netlink.route(*destination)?,
            });
        }
        Ok(RouteObservation {
            link,
            probes: observed,
        })
    }
}

/// One read-only IPv6 observation layer. Tests use a fake layer.
trait Ipv6RouteObserver: Send + Sync {
    /// Read the tunnel link, the outer link, and the selected route for every
    /// probe.
    fn observe_ipv6(
        &self,
        identity: &TunnelIdentity,
        outer: &OuterLinkIdentity,
        probes: &[Ipv6Addr],
    ) -> Result<Ipv6RouteObservation, RouteVerifyError>;
}

struct SystemIpv6RouteObserver;

impl Ipv6RouteObserver for SystemIpv6RouteObserver {
    fn observe_ipv6(
        &self,
        identity: &TunnelIdentity,
        outer: &OuterLinkIdentity,
        probes: &[Ipv6Addr],
    ) -> Result<Ipv6RouteObservation, RouteVerifyError> {
        let netlink = NetlinkRoute::open()?;
        let link = netlink.link(identity.ifindex)?;
        let outer_link = netlink.link(outer.ifindex)?;
        let mut observed = Vec::with_capacity(probes.len());
        for destination in probes {
            observed.push(ObservedIpv6Probe {
                destination: *destination,
                route: netlink.route_ipv6(*destination)?,
            });
        }
        Ok(Ipv6RouteObservation {
            link,
            outer_link,
            probes: observed,
        })
    }
}

/// A netlink error before it is mapped to the check context.
enum ReplyError {
    Kernel(i32),
    Unavailable { operation: &'static str, errno: i32 },
    Malformed(&'static str),
}

fn unavailable(operation: &'static str, error: &io::Error) -> ReplyError {
    ReplyError::Unavailable {
        operation,
        errno: error.raw_os_error().unwrap_or(libc::EIO),
    }
}

fn unavailable_error(operation: &'static str, error: &io::Error) -> RouteVerifyError {
    RouteVerifyError::Unavailable {
        operation,
        errno: error.raw_os_error().unwrap_or(libc::EIO),
    }
}

fn write_error(error: ReplyError) -> RouteVerifyError {
    match error {
        ReplyError::Kernel(errno) => RouteVerifyError::Unavailable {
            operation: "route control",
            errno,
        },
        ReplyError::Unavailable { operation, errno } => {
            RouteVerifyError::Unavailable { operation, errno }
        }
        ReplyError::Malformed(message) => RouteVerifyError::MalformedReply(message),
    }
}

fn next_sequence() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_i32(bytes: &[u8]) -> i32 {
    i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn write_u16(bytes: &mut [u8], value: u16) {
    bytes[..2].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32(bytes: &mut [u8], value: u32) {
    bytes[..4].copy_from_slice(&value.to_ne_bytes());
}

/// Build one `RTM_GETROUTE` request for a fake probe.
fn encode_route_get(sequence: u32, destination: Ipv4Addr) -> Vec<u8> {
    let mut message = vec![0u8; NLMSG_HDRLEN + 12 + 8];
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    write_u16(&mut message[4..6], RTM_GETROUTE);
    write_u16(&mut message[6..8], NLM_F_REQUEST);
    write_u32(&mut message[8..12], sequence);
    let route = NLMSG_HDRLEN;
    message[route] = libc::AF_INET as u8;
    message[route + 1] = 32;
    let flags = (RTM_F_FIB_MATCH | RTM_F_LOOKUP_TABLE).to_ne_bytes();
    message[route + 8..route + 12].copy_from_slice(&flags);
    let attr = route + 12;
    write_u16(&mut message[attr..attr + 2], 8);
    write_u16(&mut message[attr + 2..attr + 4], RTA_DST);
    message[attr + 4..attr + 8].copy_from_slice(&destination.octets());
    message
}

/// Build one IPv6 `RTM_GETROUTE` request for a fake probe.
///
/// `struct rtmsg` is 12 bytes. The request sets `rtm_dst_len` to 128 and sends
/// a 16-byte `RTA_DST`. The kernel accepts only `RTM_F_FIB_MATCH` in `rtm_flags`
/// for an IPv6 get-route request. Do not add `RTM_F_LOOKUP_TABLE`.
///
/// The request does not set `RTA_OIF`. The kernel does not require it for an
/// IPv6 FIB match, and a pinned output interface can mask a competing exact
/// prefix. The reply must name the tunnel output interface.
fn encode_ipv6_route_get(sequence: u32, destination: Ipv6Addr) -> Vec<u8> {
    let mut message = vec![0u8; NLMSG_HDRLEN + 12 + 20];
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    write_u16(&mut message[4..6], RTM_GETROUTE);
    write_u16(&mut message[6..8], NLM_F_REQUEST);
    write_u32(&mut message[8..12], sequence);
    let route = NLMSG_HDRLEN;
    message[route] = libc::AF_INET6 as u8;
    message[route + 1] = 128;
    let flags = RTM_F_FIB_MATCH.to_ne_bytes();
    message[route + 8..route + 12].copy_from_slice(&flags);
    let destination_attr = route + 12;
    write_u16(&mut message[destination_attr..destination_attr + 2], 20);
    write_u16(
        &mut message[destination_attr + 2..destination_attr + 4],
        RTA_DST,
    );
    message[destination_attr + 4..destination_attr + 20].copy_from_slice(&destination.octets());
    message
}

/// Build one `RTM_GETLINK` request for an interface index.
fn encode_link_get(sequence: u32, ifindex: u32) -> Vec<u8> {
    let mut message = vec![0u8; NLMSG_HDRLEN + 16];
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    write_u16(&mut message[4..6], RTM_GETLINK);
    write_u16(&mut message[6..8], NLM_F_REQUEST);
    write_u32(&mut message[8..12], sequence);
    let info = NLMSG_HDRLEN;
    message[info + 4..info + 8].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    message
}

/// Start one netlink message with a fixed payload length.
fn begin_netlink(kind: u16, flags: u16, sequence: u32, payload: usize) -> Vec<u8> {
    let mut message = vec![0u8; NLMSG_HDRLEN + payload];
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    write_u16(&mut message[4..6], kind);
    write_u16(&mut message[6..8], flags);
    write_u32(&mut message[8..12], sequence);
    message
}

/// Append one aligned netlink attribute.
fn push_attr(message: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let start = message.len();
    let length = 4 + value.len();
    let aligned = (length + 3) & !3;
    message.resize(start + aligned, 0);
    write_u16(&mut message[start..start + 2], length as u16);
    write_u16(&mut message[start + 2..start + 4], kind);
    message[start + 4..start + 4 + value.len()].copy_from_slice(value);
}

/// Build one `RTM_NEWROUTE` or `RTM_DELROUTE` request for a recorded key.
fn encode_route_change(sequence: u32, key: &RouteKey, delete: bool) -> Vec<u8> {
    let kind = if delete { RTM_DELROUTE } else { RTM_NEWROUTE };
    let flags = if delete {
        NLM_F_REQUEST | NLM_F_ACK
    } else {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    };
    let mut message = begin_netlink(kind, flags, sequence, 12);
    let route = NLMSG_HDRLEN;
    message[route] = key.family;
    message[route + 1] = key.length;
    if key.table < 256 {
        message[route + 4] = key.table as u8;
    }
    message[route + 5] = key.protocol;
    message[route + 6] = key.scope;
    message[route + 7] = key.route_type;
    push_attr(&mut message, RTA_TABLE, &key.table.to_ne_bytes());
    if key.length > 0 {
        push_attr(&mut message, RTA_DST, &key.destination);
    }
    if let Some(ifindex) = key.oif {
        push_attr(&mut message, RTA_OIF, &ifindex.to_ne_bytes());
    }
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    message
}

/// Build one `RTM_NEWRULE` or `RTM_DELRULE` request for a recorded key.
///
/// A delete omits the output interface name. The kernel resolves that name
/// when it adds a rule and rejects the delete when the link is gone. The rule
/// priority and the table are the delete key. The ownership check runs before
/// the delete and proves the output interface from the reply.
fn encode_rule_change(sequence: u32, rule: &RuleKey, delete: bool) -> Vec<u8> {
    let kind = if delete { RTM_DELRULE } else { RTM_NEWRULE };
    let flags = if delete {
        NLM_F_REQUEST | NLM_F_ACK
    } else {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    };
    let mut message = begin_netlink(kind, flags, sequence, 12);
    let header = NLMSG_HDRLEN;
    message[header] = rule.family;
    message[header + 1] = rule.destination_length;
    message[header + 2] = rule.source_length;
    if rule.table < 256 {
        message[header + 4] = rule.table as u8;
    }
    message[header + 7] = rule.action;
    if rule.table > 255 {
        push_attr(&mut message, FRA_TABLE, &rule.table.to_ne_bytes());
    }
    push_attr(&mut message, FRA_PRIORITY, &rule.priority.to_ne_bytes());
    if !delete {
        if let Some(oif) = rule.oif.as_deref() {
            let mut name = oif.as_bytes().to_vec();
            name.push(0);
            push_attr(&mut message, FRA_OIFNAME, &name);
        }
    }
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    message
}

/// Build one `RTM_GETROUTE` dump request for a family.
///
/// A table above 255 does not fit in `rtm_table`, and the kernel ignores
/// `RTA_TABLE` for a dump. The request dumps every table. [`NetlinkRoute`]
/// filters the replies by their reported table.
fn encode_route_dump(sequence: u32, family: u8) -> Vec<u8> {
    let mut message = begin_netlink(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, sequence, 12);
    message[NLMSG_HDRLEN] = family;
    message
}

/// Build one `RTM_GETRULE` dump request for a family.
fn encode_rule_dump(sequence: u32, family: u8) -> Vec<u8> {
    let mut message = begin_netlink(RTM_GETRULE, NLM_F_REQUEST | NLM_F_DUMP, sequence, 12);
    message[NLMSG_HDRLEN] = family;
    message
}

/// Visit every netlink attribute in a payload.
fn visit_attrs(
    mut data: &[u8],
    mut visit: impl FnMut(u16, &[u8]) -> Result<(), RouteVerifyError>,
) -> Result<(), RouteVerifyError> {
    while !data.is_empty() {
        if data.len() < 4 {
            return Err(RouteVerifyError::MalformedReply("short netlink attribute"));
        }
        let length = read_u16(&data[0..2]) as usize;
        if length < 4 || length > data.len() {
            return Err(RouteVerifyError::MalformedReply(
                "invalid netlink attribute length",
            ));
        }
        let kind = read_u16(&data[2..4]) & NLA_TYPE_MASK;
        visit(kind, &data[4..length])?;
        let aligned = (length + 3) & !3;
        if aligned > data.len() {
            return Err(RouteVerifyError::MalformedReply(
                "unaligned netlink attribute",
            ));
        }
        data = &data[aligned..];
    }
    Ok(())
}

fn parse_route_reply(message: &[u8]) -> Result<ObservedRoute, RouteVerifyError> {
    if message.len() < NLMSG_HDRLEN {
        return Err(RouteVerifyError::MalformedReply("short netlink header"));
    }
    let total = read_u32(&message[0..4]) as usize;
    if total < NLMSG_HDRLEN || total > message.len() {
        return Err(RouteVerifyError::MalformedReply(
            "invalid netlink message length",
        ));
    }
    if read_u16(&message[4..6]) != RTM_NEWROUTE {
        return Err(RouteVerifyError::MalformedReply(
            "unexpected netlink message type",
        ));
    }
    let payload = &message[NLMSG_HDRLEN..total];
    if payload.len() < 12 {
        return Err(RouteVerifyError::MalformedReply("short route message"));
    }
    if payload[0] != libc::AF_INET as u8 {
        return Err(RouteVerifyError::MalformedReply(
            "route message is not IPv4",
        ));
    }
    let destination_length = payload[1];
    if destination_length > 32 {
        return Err(RouteVerifyError::MalformedReply(
            "route prefix length is above 32",
        ));
    }
    let source_length = payload[2];
    if source_length > 32 {
        return Err(RouteVerifyError::MalformedReply(
            "route source length is above 32",
        ));
    }
    let tos = payload[3];
    let table = u32::from(payload[4]);
    let protocol = payload[5];
    let route_type = payload[7];
    let flags = read_u32(&payload[8..12]);
    let mut destination = None;
    let mut source = None;
    let mut table_attr = None;
    let mut ifindex = None;
    let mut gateway = None;
    let mut prefsrc = None;
    let mut flow = None;
    let mut multipath = false;
    let mut via = false;
    let mut encap = false;
    let mut nexthop_id = None;
    let mut priority = None;
    visit_attrs(&payload[12..], |kind, value| {
        let require_four = |value: &[u8]| {
            if value.len() == 4 {
                Ok(())
            } else {
                Err(RouteVerifyError::MalformedReply(
                    "route attribute has the wrong length",
                ))
            }
        };
        match kind {
            RTA_DST => {
                require_four(value)?;
                destination = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            RTA_SRC => {
                require_four(value)?;
                source = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            RTA_OIF => {
                require_four(value)?;
                let index = read_u32(value);
                ifindex = (index != 0).then_some(index);
            }
            RTA_GATEWAY => {
                require_four(value)?;
                gateway = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            RTA_PREFSRC => {
                require_four(value)?;
                prefsrc = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            RTA_FLOW => {
                require_four(value)?;
                let class_id = read_u32(value);
                flow = (class_id != 0).then_some(class_id);
            }
            RTA_TABLE => {
                require_four(value)?;
                table_attr = Some(read_u32(value));
            }
            RTA_PRIORITY => {
                require_four(value)?;
                let metric = read_u32(value);
                priority = (metric != 0).then_some(metric);
            }
            RTA_MULTIPATH => multipath = true,
            RTA_VIA => via = true,
            RTA_ENCAP | RTA_ENCAP_TYPE => encap = true,
            RTA_NH_ID => {
                require_four(value)?;
                nexthop_id = Some(read_u32(value));
            }
            _ => {}
        }
        Ok(())
    })?;
    if destination_length > 0 && destination.is_none() {
        return Err(RouteVerifyError::MalformedReply(
            "route message has no destination address",
        ));
    }
    if source_length > 0 && source.is_none() {
        return Err(RouteVerifyError::MalformedReply(
            "route message has no source address",
        ));
    }
    let address = destination.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let prefix = Ipv4Prefix::new(address, destination_length).ok_or(
        RouteVerifyError::MalformedReply("route message has an invalid prefix"),
    )?;
    Ok(ObservedRoute {
        prefix,
        source_length,
        source,
        tos,
        table: table_attr.unwrap_or(table),
        protocol,
        route_type,
        ifindex,
        gateway,
        prefsrc,
        flow,
        multipath,
        via,
        encap,
        nexthop_id,
        dead: flags & RTNH_F_DEAD != 0,
        link_down: flags & RTNH_F_LINKDOWN != 0,
        priority,
    })
}

fn ipv6_from_bytes(value: &[u8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&value[..16]);
    Ipv6Addr::from(octets)
}

fn parse_ipv6_route_reply(message: &[u8]) -> Result<ObservedIpv6Route, RouteVerifyError> {
    if message.len() < NLMSG_HDRLEN {
        return Err(RouteVerifyError::MalformedReply("short netlink header"));
    }
    let total = read_u32(&message[0..4]) as usize;
    if total < NLMSG_HDRLEN || total > message.len() {
        return Err(RouteVerifyError::MalformedReply(
            "invalid netlink message length",
        ));
    }
    if read_u16(&message[4..6]) != RTM_NEWROUTE {
        return Err(RouteVerifyError::MalformedReply(
            "unexpected netlink message type",
        ));
    }
    let payload = &message[NLMSG_HDRLEN..total];
    if payload.len() < 12 {
        return Err(RouteVerifyError::MalformedReply("short route message"));
    }
    if payload[0] != libc::AF_INET6 as u8 {
        return Err(RouteVerifyError::MalformedReply(
            "route message is not IPv6",
        ));
    }
    let destination_length = payload[1];
    if destination_length > 128 {
        return Err(RouteVerifyError::MalformedReply(
            "route prefix length is above 128",
        ));
    }
    let source_length = payload[2];
    if source_length > 128 {
        return Err(RouteVerifyError::MalformedReply(
            "route source length is above 128",
        ));
    }
    let tos = payload[3];
    let table = u32::from(payload[4]);
    let protocol = payload[5];
    let route_type = payload[7];
    let flags = read_u32(&payload[8..12]);
    let mut destination = None;
    let mut source = None;
    let mut table_attr = None;
    let mut ifindex = None;
    let mut gateway = None;
    let mut prefsrc = None;
    let mut flow = None;
    let mut multipath = false;
    let mut via = false;
    let mut encap = false;
    let mut nexthop_id = None;
    let mut priority = None;
    visit_attrs(&payload[12..], |kind, value| {
        let require_four = |value: &[u8]| {
            if value.len() == 4 {
                Ok(())
            } else {
                Err(RouteVerifyError::MalformedReply(
                    "route attribute has the wrong length",
                ))
            }
        };
        let require_sixteen = |value: &[u8]| {
            if value.len() == 16 {
                Ok(())
            } else {
                Err(RouteVerifyError::MalformedReply(
                    "IPv6 route attribute has the wrong length",
                ))
            }
        };
        match kind {
            RTA_DST => {
                require_sixteen(value)?;
                destination = Some(ipv6_from_bytes(value));
            }
            RTA_SRC => {
                require_sixteen(value)?;
                source = Some(ipv6_from_bytes(value));
            }
            RTA_OIF => {
                require_four(value)?;
                let index = read_u32(value);
                ifindex = (index != 0).then_some(index);
            }
            RTA_GATEWAY => {
                require_sixteen(value)?;
                gateway = Some(ipv6_from_bytes(value));
            }
            RTA_PREFSRC => {
                require_sixteen(value)?;
                prefsrc = Some(ipv6_from_bytes(value));
            }
            RTA_FLOW => {
                require_four(value)?;
                let class_id = read_u32(value);
                flow = (class_id != 0).then_some(class_id);
            }
            RTA_TABLE => {
                require_four(value)?;
                table_attr = Some(read_u32(value));
            }
            RTA_PRIORITY => {
                require_four(value)?;
                let metric = read_u32(value);
                priority = (metric != 0).then_some(metric);
            }
            RTA_MULTIPATH => multipath = true,
            RTA_VIA => via = true,
            RTA_ENCAP | RTA_ENCAP_TYPE => encap = true,
            RTA_NH_ID => {
                require_four(value)?;
                nexthop_id = Some(read_u32(value));
            }
            _ => {}
        }
        Ok(())
    })?;
    if destination_length > 0 && destination.is_none() {
        return Err(RouteVerifyError::MalformedReply(
            "route message has no destination address",
        ));
    }
    if source_length > 0 && source.is_none() {
        return Err(RouteVerifyError::MalformedReply(
            "route message has no source address",
        ));
    }
    let address = destination.unwrap_or(Ipv6Addr::UNSPECIFIED);
    let prefix = Ipv6Prefix::new(address, destination_length).ok_or(
        RouteVerifyError::MalformedReply("route message has an invalid prefix"),
    )?;
    Ok(ObservedIpv6Route {
        prefix,
        source_length,
        source,
        tos,
        table: table_attr.unwrap_or(table),
        protocol,
        route_type,
        ifindex,
        gateway,
        prefsrc,
        flow,
        multipath,
        via,
        encap,
        nexthop_id,
        dead: flags & RTNH_F_DEAD != 0,
        link_down: flags & RTNH_F_LINKDOWN != 0,
        cloned: flags & RTM_F_CLONED != 0,
        priority,
    })
}

fn parse_link_reply(message: &[u8]) -> Result<ObservedLink, RouteVerifyError> {
    if message.len() < NLMSG_HDRLEN {
        return Err(RouteVerifyError::MalformedReply("short netlink header"));
    }
    let total = read_u32(&message[0..4]) as usize;
    if total < NLMSG_HDRLEN || total > message.len() {
        return Err(RouteVerifyError::MalformedReply(
            "invalid netlink message length",
        ));
    }
    if read_u16(&message[4..6]) != RTM_NEWLINK {
        return Err(RouteVerifyError::MalformedReply(
            "unexpected netlink message type",
        ));
    }
    let payload = &message[NLMSG_HDRLEN..total];
    if payload.len() < 16 {
        return Err(RouteVerifyError::MalformedReply("short link message"));
    }
    if payload[0] != 0 {
        return Err(RouteVerifyError::MalformedReply(
            "link message is not address-family neutral",
        ));
    }
    let hardware_type = read_u16(&payload[2..4]);
    let index = read_i32(&payload[4..8]);
    if index <= 0 {
        return Err(RouteVerifyError::MalformedReply(
            "link message has an invalid interface index",
        ));
    }
    let flags = read_u32(&payload[8..12]);
    let mut name = None;
    let mut kind = None;
    visit_attrs(&payload[16..], |attribute, value| {
        match attribute {
            IFLA_IFNAME => {
                let text = cstr_text(value)?;
                if text.is_empty() {
                    return Err(RouteVerifyError::MalformedReply(
                        "link message has an empty interface name",
                    ));
                }
                name = Some(text.to_owned());
            }
            IFLA_LINKINFO => {
                visit_attrs(value, |nested, nested_value| {
                    if nested == IFLA_INFO_KIND {
                        kind = Some(cstr_text(nested_value)?.to_owned());
                    }
                    Ok(())
                })?;
            }
            _ => {}
        }
        Ok(())
    })?;
    let name = name.ok_or(RouteVerifyError::MalformedReply(
        "link message has no interface name",
    ))?;
    Ok(ObservedLink {
        ifindex: index as u32,
        name,
        kind,
        hardware_type,
        flags,
    })
}

fn cstr_text(value: &[u8]) -> Result<&str, RouteVerifyError> {
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    std::str::from_utf8(&value[..end])
        .map_err(|_| RouteVerifyError::MalformedReply("link text is not UTF-8"))
}

/// Require one netlink attribute to have an exact length.
fn require_attr_len(
    value: &[u8],
    length: usize,
    message: &'static str,
) -> Result<(), RouteVerifyError> {
    if value.len() == length {
        Ok(())
    } else {
        Err(RouteVerifyError::MalformedReply(message))
    }
}

/// Convert one `RTM_NEWRULE` reply into a rule key.
///
/// The parser reads every selector attribute. An attribute that this module
/// does not know sets `unexpected`. Cleanup refuses such a rule because the
/// record cannot prove the full selector set.
fn parse_rule_reply(message: &[u8]) -> Result<RuleKey, RouteVerifyError> {
    if message.len() < NLMSG_HDRLEN {
        return Err(RouteVerifyError::MalformedReply("short netlink header"));
    }
    let total = read_u32(&message[0..4]) as usize;
    if total < NLMSG_HDRLEN || total > message.len() {
        return Err(RouteVerifyError::MalformedReply(
            "invalid netlink message length",
        ));
    }
    if read_u16(&message[4..6]) != RTM_NEWRULE {
        return Err(RouteVerifyError::MalformedReply(
            "unexpected netlink message type",
        ));
    }
    let payload = &message[NLMSG_HDRLEN..total];
    if payload.len() < 12 {
        return Err(RouteVerifyError::MalformedReply(
            "short policy rule message",
        ));
    }
    let family = payload[0];
    let destination_length = payload[1];
    let source_length = payload[2];
    let tos = payload[3];
    let table = u32::from(payload[4]);
    let action = payload[7];
    let flags = read_u32(&payload[8..12]);
    let address_size = match family {
        x if x == libc::AF_INET as u8 => 4,
        x if x == libc::AF_INET6 as u8 => 16,
        _ => {
            return Err(RouteVerifyError::MalformedReply(
                "policy rule family is not IPv4 or IPv6",
            ))
        }
    };
    let mut table_attr = None;
    let mut priority = None;
    let mut destination = None;
    let mut source = None;
    let mut oif = None;
    let mut iifname = None;
    let mut goto = None;
    let mut protocol = 0u8;
    let mut fwmark = None;
    let mut fwmask = None;
    let mut flow = None;
    let mut tun_id = None;
    let mut suppress_ifgroup = None;
    let mut suppress_prefixlen = None;
    let mut l3mdev = None;
    let mut uid_range = None;
    let mut ip_proto = None;
    let mut sport_range = None;
    let mut dport_range = None;
    let mut sport_mask = None;
    let mut dport_mask = None;
    let mut dscp = None;
    let mut dscp_mask = None;
    let mut flowlabel = None;
    let mut flowlabel_mask = None;
    let mut unexpected = false;
    visit_attrs(&payload[12..], |kind, value| {
        match kind {
            FRA_TABLE => {
                require_attr_len(value, 4, "policy rule table has the wrong length")?;
                table_attr = Some(read_u32(value));
            }
            FRA_PRIORITY => {
                require_attr_len(value, 4, "policy rule priority has the wrong length")?;
                priority = Some(read_u32(value));
            }
            FRA_OIFNAME => {
                let name = cstr_text(value)?;
                if !valid_ifname(name) {
                    return Err(RouteVerifyError::MalformedReply(
                        "policy rule has an invalid output interface",
                    ));
                }
                oif = Some(name.to_owned());
            }
            FRA_IIFNAME => {
                let name = cstr_text(value)?;
                if !valid_ifname(name) {
                    return Err(RouteVerifyError::MalformedReply(
                        "policy rule has an invalid input interface",
                    ));
                }
                iifname = Some(name.to_owned());
            }
            FRA_DST => {
                require_attr_len(
                    value,
                    address_size,
                    "policy rule destination has the wrong length",
                )?;
                destination = Some(value.to_vec());
            }
            FRA_SRC => {
                require_attr_len(
                    value,
                    address_size,
                    "policy rule source has the wrong length",
                )?;
                source = Some(value.to_vec());
            }
            FRA_GOTO => {
                require_attr_len(value, 4, "policy rule goto target has the wrong length")?;
                goto = Some(read_u32(value));
            }
            FRA_PROTOCOL => {
                require_attr_len(value, 1, "policy rule protocol has the wrong length")?;
                protocol = value[0];
            }
            FRA_FWMARK => {
                require_attr_len(value, 4, "policy rule mark has the wrong length")?;
                fwmark = Some(read_u32(value));
            }
            FRA_FWMASK => {
                require_attr_len(value, 4, "policy rule mark mask has the wrong length")?;
                fwmask = Some(read_u32(value));
            }
            FRA_FLOW => {
                require_attr_len(value, 4, "policy rule flow has the wrong length")?;
                flow = Some(read_u32(value));
            }
            FRA_TUN_ID => {
                require_attr_len(value, 8, "policy rule tunnel id has the wrong length")?;
                tun_id = Some(u64::from_be_bytes(value[..8].try_into().unwrap()));
            }
            FRA_SUPPRESS_IFGROUP => {
                require_attr_len(value, 4, "policy rule interface group has the wrong length")?;
                let group = read_u32(value);
                suppress_ifgroup = (group != u32::MAX).then_some(group);
            }
            FRA_SUPPRESS_PREFIXLEN => {
                require_attr_len(value, 4, "policy rule prefix length has the wrong length")?;
                let length = read_u32(value);
                suppress_prefixlen = (length != u32::MAX).then_some(length);
            }
            FRA_L3MDEV => {
                require_attr_len(value, 1, "policy rule l3mdev has the wrong length")?;
                l3mdev = Some(value[0]);
            }
            FRA_UID_RANGE => {
                require_attr_len(value, 8, "policy rule uid range has the wrong length")?;
                uid_range = Some((read_u32(&value[0..4]), read_u32(&value[4..8])));
            }
            FRA_IP_PROTO => {
                require_attr_len(value, 1, "policy rule IP protocol has the wrong length")?;
                ip_proto = Some(value[0]);
            }
            FRA_SPORT_RANGE => {
                require_attr_len(
                    value,
                    4,
                    "policy rule source port range has the wrong length",
                )?;
                sport_range = Some((read_u16(&value[0..2]), read_u16(&value[2..4])));
            }
            FRA_DPORT_RANGE => {
                require_attr_len(
                    value,
                    4,
                    "policy rule destination port range has the wrong length",
                )?;
                dport_range = Some((read_u16(&value[0..2]), read_u16(&value[2..4])));
            }
            FRA_SPORT_MASK => {
                require_attr_len(
                    value,
                    2,
                    "policy rule source port mask has the wrong length",
                )?;
                sport_mask = Some(read_u16(value));
            }
            FRA_DPORT_MASK => {
                require_attr_len(
                    value,
                    2,
                    "policy rule destination port mask has the wrong length",
                )?;
                dport_mask = Some(read_u16(value));
            }
            FRA_DSCP => {
                require_attr_len(value, 1, "policy rule DSCP has the wrong length")?;
                dscp = Some(value[0]);
            }
            FRA_DSCP_MASK => {
                require_attr_len(value, 1, "policy rule DSCP mask has the wrong length")?;
                dscp_mask = Some(value[0]);
            }
            FRA_FLOWLABEL => {
                require_attr_len(value, 4, "policy rule flow label has the wrong length")?;
                flowlabel = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
            }
            FRA_FLOWLABEL_MASK => {
                require_attr_len(value, 4, "policy rule flow label mask has the wrong length")?;
                flowlabel_mask = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
            }
            FRA_PAD => {}
            _ => unexpected = true,
        }
        Ok(())
    })?;
    // The kernel omits `FRA_PRIORITY` for a rule with priority 0. The local
    // rule is one example. Treat an absent attribute as priority 0.
    let priority = priority.unwrap_or(0);
    if destination_length > 0 && destination.is_none() {
        return Err(RouteVerifyError::MalformedReply(
            "policy rule has no destination address",
        ));
    }
    if source_length > 0 && source.is_none() {
        return Err(RouteVerifyError::MalformedReply(
            "policy rule has no source address",
        ));
    }
    Ok(RuleKey {
        family,
        destination_length,
        destination,
        source_length,
        source,
        tos,
        table: table_attr.unwrap_or(table),
        priority,
        action,
        flags: flags & RULE_SELECTOR_FLAGS,
        iifname,
        oif,
        goto,
        protocol,
        fwmark,
        fwmask,
        flow,
        tun_id,
        suppress_ifgroup,
        suppress_prefixlen,
        l3mdev,
        uid_range,
        ip_proto,
        sport_range,
        dport_range,
        sport_mask,
        dport_mask,
        dscp,
        dscp_mask,
        flowlabel,
        flowlabel_mask,
        unexpected,
    })
}

/// One route key that this process created in the dedicated table.
///
/// The scope is part of the add request and the record. The kernel does not
/// return the scope in a delete match, so [`RouteKey::same_key`] compares every
/// other selector.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteKey {
    family: u8,
    destination: Vec<u8>,
    length: u8,
    source_length: u8,
    source: Option<Vec<u8>>,
    tos: u8,
    table: u32,
    protocol: u8,
    route_type: u8,
    scope: u8,
    oif: Option<u32>,
    metric: Option<u32>,
    prefsrc: Option<Vec<u8>>,
    flow: Option<u32>,
}

impl RouteKey {
    fn ipv4(prefix: Ipv4Prefix, ifindex: u32) -> Self {
        Self {
            family: libc::AF_INET as u8,
            destination: prefix.address().octets().to_vec(),
            length: prefix.length(),
            source_length: 0,
            source: None,
            tos: 0,
            table: TUNNEL_TABLE,
            protocol: ROUTE_PROTOCOL_ID,
            route_type: RTN_UNICAST,
            scope: RT_SCOPE_LINK,
            oif: Some(ifindex),
            metric: None,
            prefsrc: None,
            flow: None,
        }
    }

    fn ipv6(prefix: Ipv6Prefix, ifindex: u32) -> Self {
        Self {
            family: libc::AF_INET6 as u8,
            destination: prefix.address().octets().to_vec(),
            length: prefix.length(),
            source_length: 0,
            source: None,
            tos: 0,
            table: TUNNEL_TABLE,
            protocol: ROUTE_PROTOCOL_ID,
            route_type: RTN_UNICAST,
            scope: RT_SCOPE_UNIVERSE,
            oif: Some(ifindex),
            metric: Some(IPV6_DEFAULT_METRIC),
            prefsrc: None,
            flow: None,
        }
    }

    fn ipv6_block(prefix: Ipv6Prefix) -> Self {
        Self {
            family: libc::AF_INET6 as u8,
            destination: prefix.address().octets().to_vec(),
            length: prefix.length(),
            source_length: 0,
            source: None,
            tos: 0,
            table: TUNNEL_TABLE,
            protocol: ROUTE_PROTOCOL_ID,
            route_type: RTN_BLACKHOLE,
            scope: RT_SCOPE_UNIVERSE,
            oif: None,
            metric: Some(IPV6_DEFAULT_METRIC),
            prefsrc: None,
            flow: None,
        }
    }

    /// Compare every field except the scope.
    ///
    /// A blackhole route has no real output interface. The kernel reports the
    /// loopback interface for it, so the output interface is not a selector for
    /// a blackhole route.
    fn same_key(&self, other: &RouteKey) -> bool {
        self.family == other.family
            && self.destination == other.destination
            && self.length == other.length
            && self.source_length == other.source_length
            && self.source == other.source
            && self.tos == other.tos
            && self.table == other.table
            && self.protocol == other.protocol
            && self.route_type == other.route_type
            && (self.route_type == RTN_BLACKHOLE || self.oif == other.oif)
            && self.metric == other.metric
            && self.prefsrc == other.prefsrc
            && self.flow == other.flow
    }

    fn from_ipv4(route: &ObservedRoute) -> Self {
        Self {
            family: libc::AF_INET as u8,
            destination: route.prefix.address().octets().to_vec(),
            length: route.prefix.length(),
            source_length: route.source_length,
            source: route.source.map(|address| address.octets().to_vec()),
            tos: route.tos,
            table: route.table,
            protocol: route.protocol,
            route_type: route.route_type,
            scope: RT_SCOPE_UNIVERSE,
            oif: route.ifindex,
            metric: route.priority,
            prefsrc: route.prefsrc.map(|address| address.octets().to_vec()),
            flow: route.flow,
        }
    }

    fn from_ipv6(route: &ObservedIpv6Route) -> Self {
        Self {
            family: libc::AF_INET6 as u8,
            destination: route.prefix.address().octets().to_vec(),
            length: route.prefix.length(),
            source_length: route.source_length,
            source: route.source.map(|address| address.octets().to_vec()),
            tos: route.tos,
            table: route.table,
            protocol: route.protocol,
            route_type: route.route_type,
            scope: RT_SCOPE_UNIVERSE,
            oif: route.ifindex,
            metric: route.priority,
            prefsrc: route.prefsrc.map(|address| address.octets().to_vec()),
            flow: route.flow,
        }
    }
}

/// One route from a table dump and its shape.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedRouteKey {
    key: RouteKey,
    gateway: bool,
    multipath: bool,
    encap: bool,
    nexthop: bool,
}

impl ObservedRouteKey {
    /// Return true when the route has the simple shape that this manager adds.
    fn is_clean(&self) -> bool {
        !self.gateway && !self.multipath && !self.encap && !self.nexthop
    }
}

/// One policy rule key that this process created.
///
/// Every selector field is compared before a delete. The kernel fills some
/// selector attributes with a default value, so the constructors and the parser
/// use the same normalized form. An unknown selector sets `unexpected`, and the
/// ownership check then refuses the rule.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RuleKey {
    family: u8,
    destination_length: u8,
    destination: Option<Vec<u8>>,
    source_length: u8,
    source: Option<Vec<u8>>,
    tos: u8,
    table: u32,
    priority: u32,
    action: u8,
    flags: u32,
    iifname: Option<String>,
    oif: Option<String>,
    goto: Option<u32>,
    protocol: u8,
    fwmark: Option<u32>,
    fwmask: Option<u32>,
    flow: Option<u32>,
    tun_id: Option<u64>,
    suppress_ifgroup: Option<u32>,
    suppress_prefixlen: Option<u32>,
    l3mdev: Option<u8>,
    uid_range: Option<(u32, u32)>,
    ip_proto: Option<u8>,
    sport_range: Option<(u16, u16)>,
    dport_range: Option<(u16, u16)>,
    sport_mask: Option<u16>,
    dport_mask: Option<u16>,
    dscp: Option<u8>,
    dscp_mask: Option<u8>,
    flowlabel: Option<u32>,
    flowlabel_mask: Option<u32>,
    unexpected: bool,
}

impl RuleKey {
    fn base(family: u8, table: u32, priority: u32, oif: Option<String>) -> Self {
        Self {
            family,
            destination_length: 0,
            destination: None,
            source_length: 0,
            source: None,
            tos: 0,
            table,
            priority,
            action: FR_ACT_TO_TBL,
            flags: 0,
            iifname: None,
            oif,
            goto: None,
            protocol: 0,
            fwmark: None,
            fwmask: None,
            flow: None,
            tun_id: None,
            suppress_ifgroup: None,
            suppress_prefixlen: None,
            l3mdev: None,
            uid_range: None,
            ip_proto: None,
            sport_range: None,
            dport_range: None,
            sport_mask: None,
            dport_mask: None,
            dscp: None,
            dscp_mask: None,
            flowlabel: None,
            flowlabel_mask: None,
            unexpected: false,
        }
    }

    fn outer(family: u8, ifname: &str) -> Self {
        Self::base(
            family,
            RT_TABLE_MAIN,
            OUTER_RULE_PRIORITY,
            Some(ifname.to_owned()),
        )
    }

    fn tunnel(family: u8) -> Self {
        Self::base(family, TUNNEL_TABLE, TUNNEL_RULE_PRIORITY, None)
    }
}

/// Return true when the table dump holds exactly one route at the recorded
/// prefix and that route matches every recorded selector.
fn route_is_recorded(observed: &[ObservedRouteKey], key: &RouteKey) -> bool {
    let same: Vec<&ObservedRouteKey> = observed
        .iter()
        .filter(|item| {
            item.key.family == key.family
                && item.key.destination == key.destination
                && item.key.length == key.length
        })
        .collect();
    same.len() == 1 && same[0].is_clean() && key.same_key(&same[0].key)
}

/// Return true when the rule dump holds exactly one rule at the recorded
/// priority and that rule matches every recorded selector.
fn rule_is_recorded(observed: &[RuleKey], rule: &RuleKey) -> bool {
    let same: Vec<&RuleKey> = observed
        .iter()
        .filter(|item| item.priority == rule.priority)
        .collect();
    same.len() == 1 && same[0] == rule
}

/// Return true when a write failed because the kernel did not answer before
/// the netlink deadline. The write can still be applied.
fn is_ack_timeout(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::TimedOut || error.raw_os_error() == Some(libc::ETIMEDOUT)
}

/// One route and rule control layer.
///
/// Tests use a fake layer. The system layer uses rtnetlink. Every method maps a
/// kernel error to [`io::Error`]. A failed read is inconclusive. Do not treat it
/// as proof that the object is absent.
trait RouteControl: Send + Sync {
    fn table_routes(&self, family: u8, table: u32) -> io::Result<Vec<ObservedRouteKey>>;
    fn add_route(&self, key: &RouteKey) -> io::Result<()>;
    fn delete_route(&self, key: &RouteKey) -> io::Result<()>;
    fn rules(&self, family: u8) -> io::Result<Vec<RuleKey>>;
    fn add_rule(&self, rule: &RuleKey) -> io::Result<()>;
    fn delete_rule(&self, rule: &RuleKey) -> io::Result<()>;
}

struct SystemControl;

fn route_error_to_io(error: RouteVerifyError) -> io::Error {
    match error {
        RouteVerifyError::Unavailable { errno, .. } => io::Error::from_raw_os_error(errno),
        RouteVerifyError::MalformedReply(message) => {
            io::Error::new(io::ErrorKind::InvalidData, message)
        }
        other => io::Error::other(other.to_string()),
    }
}

impl RouteControl for SystemControl {
    fn table_routes(&self, family: u8, table: u32) -> io::Result<Vec<ObservedRouteKey>> {
        let netlink = NetlinkRoute::open().map_err(route_error_to_io)?;
        netlink
            .table_routes(family, table)
            .map_err(route_error_to_io)
    }

    fn add_route(&self, key: &RouteKey) -> io::Result<()> {
        let netlink = NetlinkRoute::open().map_err(route_error_to_io)?;
        netlink.add_route(key).map_err(route_error_to_io)
    }

    fn delete_route(&self, key: &RouteKey) -> io::Result<()> {
        let netlink = NetlinkRoute::open().map_err(route_error_to_io)?;
        netlink.delete_route(key).map_err(route_error_to_io)
    }

    fn rules(&self, family: u8) -> io::Result<Vec<RuleKey>> {
        let netlink = NetlinkRoute::open().map_err(route_error_to_io)?;
        netlink.rules(family).map_err(route_error_to_io)
    }

    fn add_rule(&self, rule: &RuleKey) -> io::Result<()> {
        let netlink = NetlinkRoute::open().map_err(route_error_to_io)?;
        netlink.add_rule(rule).map_err(route_error_to_io)
    }

    fn delete_rule(&self, rule: &RuleKey) -> io::Result<()> {
        let netlink = NetlinkRoute::open().map_err(route_error_to_io)?;
        netlink.delete_rule(rule).map_err(route_error_to_io)
    }
}

/// One netlink route socket.
///
/// The route checks send read-only requests. The install and cleanup path sends
/// acknowledged write requests. A write request uses `NLM_F_EXCL`, so an
/// existing object makes the add fail.
struct NetlinkRoute {
    fd: OwnedFd,
}

impl NetlinkRoute {
    fn open() -> Result<Self, RouteVerifyError> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(unavailable_error(
                "netlink socket",
                &io::Error::last_os_error(),
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(unavailable_error(
                "netlink bind",
                &io::Error::last_os_error(),
            ));
        }
        Ok(Self { fd })
    }

    fn link(&self, ifindex: u32) -> Result<ObservedLink, RouteVerifyError> {
        let sequence = next_sequence();
        let message = encode_link_get(sequence, ifindex);
        let reply = self
            .request(&message, sequence, RTM_NEWLINK)
            .map_err(|error| match error {
                ReplyError::Kernel(errno) if errno == libc::ENODEV => {
                    RouteVerifyError::LinkMissing { ifindex }
                }
                ReplyError::Kernel(errno) => RouteVerifyError::Unavailable {
                    operation: "RTM_GETLINK",
                    errno,
                },
                ReplyError::Unavailable { operation, errno } => {
                    RouteVerifyError::Unavailable { operation, errno }
                }
                ReplyError::Malformed(reason) => RouteVerifyError::MalformedReply(reason),
            })?;
        parse_link_reply(&reply)
    }

    fn route(&self, destination: Ipv4Addr) -> Result<ObservedRoute, RouteVerifyError> {
        let sequence = next_sequence();
        let message = encode_route_get(sequence, destination);
        let reply =
            self.request(&message, sequence, RTM_NEWROUTE)
                .map_err(|error| match error {
                    ReplyError::Kernel(errno) => match errno {
                        libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENETDOWN | libc::ENOENT => {
                            RouteVerifyError::NoRoute { destination }
                        }
                        errno => RouteVerifyError::Unavailable {
                            operation: "RTM_GETROUTE",
                            errno,
                        },
                    },
                    ReplyError::Unavailable { operation, errno } => {
                        RouteVerifyError::Unavailable { operation, errno }
                    }
                    ReplyError::Malformed(reason) => RouteVerifyError::MalformedReply(reason),
                })?;
        parse_route_reply(&reply)
    }

    /// Read the IPv6 FIB entry for a fake probe.
    ///
    /// The kernel reports a blackhole route as `EINVAL` and a reject or throw
    /// route as another error. This method maps only unreachable errors to a
    /// route result. Every other kernel error is inconclusive, not a success.
    fn route_ipv6(&self, destination: Ipv6Addr) -> Result<ObservedIpv6Route, RouteVerifyError> {
        let sequence = next_sequence();
        let message = encode_ipv6_route_get(sequence, destination);
        let reply =
            self.request(&message, sequence, RTM_NEWROUTE)
                .map_err(|error| match error {
                    ReplyError::Kernel(errno) => match errno {
                        libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENETDOWN | libc::ENOENT => {
                            RouteVerifyError::NoIpv6Route { destination }
                        }
                        errno => RouteVerifyError::Unavailable {
                            operation: "RTM_GETROUTE",
                            errno,
                        },
                    },
                    ReplyError::Unavailable { operation, errno } => {
                        RouteVerifyError::Unavailable { operation, errno }
                    }
                    ReplyError::Malformed(reason) => RouteVerifyError::MalformedReply(reason),
                })?;
        parse_ipv6_route_reply(&reply)
    }

    /// Return true when an IPv6 FIB lookup selects a non-unicast entry.
    ///
    /// The kernel returns `EINVAL` for a blackhole FIB entry. A unicast entry
    /// returns a route message, so this method parses the reply and reports
    /// false. A missing route reports false. Every other kernel error is
    /// inconclusive, not a block.
    fn route_ipv6_blocked(&self, destination: Ipv6Addr) -> Result<bool, RouteVerifyError> {
        let sequence = next_sequence();
        let message = encode_ipv6_route_get(sequence, destination);
        let reply = match self.request(&message, sequence, RTM_NEWROUTE) {
            Ok(reply) => reply,
            Err(ReplyError::Kernel(errno)) if errno == libc::EINVAL => return Ok(true),
            Err(ReplyError::Kernel(errno)) => match errno {
                libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENETDOWN | libc::ENOENT => {
                    return Ok(false)
                }
                errno => {
                    return Err(RouteVerifyError::Unavailable {
                        operation: "RTM_GETROUTE",
                        errno,
                    })
                }
            },
            Err(ReplyError::Unavailable { operation, errno }) => {
                return Err(RouteVerifyError::Unavailable { operation, errno })
            }
            Err(ReplyError::Malformed(reason)) => {
                return Err(RouteVerifyError::MalformedReply(reason))
            }
        };
        let route = parse_ipv6_route_reply(&reply)?;
        Ok(route.route_type != RTN_UNICAST)
    }

    fn request(&self, message: &[u8], sequence: u32, expected: u16) -> Result<Vec<u8>, ReplyError> {
        if message.len() < NLMSG_HDRLEN {
            return Err(ReplyError::Malformed("short netlink request"));
        }
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(unavailable("netlink send", &io::Error::last_os_error()));
        }
        if sent as usize != message.len() {
            return Err(ReplyError::Malformed("partial netlink send"));
        }
        let deadline = Instant::now() + NETLINK_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ReplyError::Unavailable {
                    operation: "netlink reply",
                    errno: libc::ETIMEDOUT,
                });
            }
            let mut descriptor = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let millis = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(unavailable("netlink poll", &error));
            }
            if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(ReplyError::Unavailable {
                    operation: "netlink poll",
                    errno: libc::EIO,
                });
            }
            if descriptor.revents & libc::POLLIN == 0 {
                continue;
            }
            let mut buffer = vec![0u8; MAX_NETLINK_REPLY];
            let mut source: libc::sockaddr_nl = unsafe { mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            };
            let mut received: libc::msghdr = unsafe { mem::zeroed() };
            received.msg_name = (&mut source as *mut libc::sockaddr_nl).cast();
            received.msg_namelen = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            received.msg_iov = &mut iov;
            received.msg_iovlen = 1;
            let size = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut received, 0) };
            if size < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(unavailable("netlink receive", &error));
            }
            if received.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(ReplyError::Malformed("netlink reply is too large"));
            }
            if source.nl_pid != 0 {
                continue;
            }
            let size = size as usize;
            if size < NLMSG_HDRLEN {
                return Err(ReplyError::Malformed("short netlink reply"));
            }
            let total = read_u32(&buffer[0..4]) as usize;
            if total < NLMSG_HDRLEN || total > size {
                return Err(ReplyError::Malformed("invalid netlink reply length"));
            }
            if read_u32(&buffer[8..12]) != sequence {
                continue;
            }
            // The kernel sets `nlmsg_pid` to the destination port ID in a
            // reply. Do not require zero. The source address above proves that
            // the kernel sent the message.
            match read_u16(&buffer[4..6]) {
                NLMSG_ERROR => {
                    if total < NLMSG_HDRLEN + 4 {
                        return Err(ReplyError::Malformed("short netlink error"));
                    }
                    let errno = read_i32(&buffer[NLMSG_HDRLEN..NLMSG_HDRLEN + 4]);
                    if errno < 0 {
                        return Err(ReplyError::Kernel(-errno));
                    }
                    return Err(ReplyError::Malformed("unexpected netlink acknowledgement"));
                }
                NLMSG_DONE => return Err(ReplyError::Malformed("unexpected netlink done message")),
                kind if kind == expected => return Ok(buffer[..total].to_vec()),
                _ => continue,
            }
        }
    }

    /// Send one request.
    fn send_message(&self, message: &[u8]) -> Result<(), ReplyError> {
        if message.len() < NLMSG_HDRLEN {
            return Err(ReplyError::Malformed("short netlink request"));
        }
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(unavailable("netlink send", &io::Error::last_os_error()));
        }
        if sent as usize != message.len() {
            return Err(ReplyError::Malformed("partial netlink send"));
        }
        Ok(())
    }

    /// Receive one datagram from the kernel before the deadline.
    fn receive(&self, deadline: Instant) -> Result<(Vec<u8>, usize), ReplyError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ReplyError::Unavailable {
                    operation: "netlink reply",
                    errno: libc::ETIMEDOUT,
                });
            }
            let mut descriptor = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let millis = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(unavailable("netlink poll", &error));
            }
            if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(ReplyError::Unavailable {
                    operation: "netlink poll",
                    errno: libc::EIO,
                });
            }
            if descriptor.revents & libc::POLLIN == 0 {
                continue;
            }
            let mut buffer = vec![0u8; MAX_NETLINK_REPLY];
            let mut source: libc::sockaddr_nl = unsafe { mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            };
            let mut received: libc::msghdr = unsafe { mem::zeroed() };
            received.msg_name = (&mut source as *mut libc::sockaddr_nl).cast();
            received.msg_namelen = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            received.msg_iov = &mut iov;
            received.msg_iovlen = 1;
            let size = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut received, 0) };
            if size < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(unavailable("netlink receive", &error));
            }
            if received.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(ReplyError::Malformed("netlink reply is too large"));
            }
            if source.nl_pid != 0 {
                continue;
            }
            let size = size as usize;
            if size < NLMSG_HDRLEN {
                return Err(ReplyError::Malformed("short netlink reply"));
            }
            return Ok((buffer, size));
        }
    }

    /// Send one request and wait for its acknowledgement.
    fn acknowledged(&self, message: &[u8], sequence: u32) -> Result<(), ReplyError> {
        self.send_message(message)?;
        let deadline = Instant::now() + NETLINK_TIMEOUT;
        loop {
            let (buffer, size) = self.receive(deadline)?;
            let mut offset = 0usize;
            while offset + NLMSG_HDRLEN <= size {
                let total = read_u32(&buffer[offset..offset + 4]) as usize;
                if total < NLMSG_HDRLEN || offset + total > size {
                    return Err(ReplyError::Malformed("invalid netlink reply length"));
                }
                if read_u32(&buffer[offset + 8..offset + 12]) == sequence {
                    match read_u16(&buffer[offset + 4..offset + 6]) {
                        NLMSG_ERROR => {
                            if total < NLMSG_HDRLEN + 4 {
                                return Err(ReplyError::Malformed("short netlink error"));
                            }
                            let errno =
                                read_i32(&buffer[offset + NLMSG_HDRLEN..offset + NLMSG_HDRLEN + 4]);
                            if errno < 0 {
                                return Err(ReplyError::Kernel(-errno));
                            }
                            return Ok(());
                        }
                        NLMSG_DONE => {
                            return Err(ReplyError::Malformed("unexpected netlink done message"));
                        }
                        _ => {}
                    }
                }
                offset += (total + 3) & !3;
            }
        }
    }

    /// Send one dump request and collect every matching message.
    fn dump(
        &self,
        message: &[u8],
        sequence: u32,
        expected: u16,
    ) -> Result<Vec<Vec<u8>>, ReplyError> {
        self.send_message(message)?;
        let deadline = Instant::now() + NETLINK_TIMEOUT;
        let mut replies = Vec::new();
        loop {
            let (buffer, size) = self.receive(deadline)?;
            let mut offset = 0usize;
            while offset + NLMSG_HDRLEN <= size {
                let total = read_u32(&buffer[offset..offset + 4]) as usize;
                if total < NLMSG_HDRLEN || offset + total > size {
                    return Err(ReplyError::Malformed("invalid netlink reply length"));
                }
                if read_u32(&buffer[offset + 8..offset + 12]) == sequence {
                    match read_u16(&buffer[offset + 4..offset + 6]) {
                        NLMSG_ERROR => {
                            if total < NLMSG_HDRLEN + 4 {
                                return Err(ReplyError::Malformed("short netlink error"));
                            }
                            let errno =
                                read_i32(&buffer[offset + NLMSG_HDRLEN..offset + NLMSG_HDRLEN + 4]);
                            if errno < 0 {
                                return Err(ReplyError::Kernel(-errno));
                            }
                        }
                        NLMSG_DONE => return Ok(replies),
                        kind if kind == expected => {
                            replies.push(buffer[offset..offset + total].to_vec());
                            if replies.len() > 4096 {
                                return Err(ReplyError::Malformed("netlink dump is too large"));
                            }
                        }
                        _ => {}
                    }
                }
                offset += (total + 3) & !3;
            }
        }
    }

    /// Read the routes of one family and table. The request sends no packet.
    ///
    /// The kernel ignores a table selector above 255 in a dump request. The
    /// request dumps every table of the family. The method keeps only the
    /// replies whose reported table matches.
    fn table_routes(
        &self,
        family: u8,
        table: u32,
    ) -> Result<Vec<ObservedRouteKey>, RouteVerifyError> {
        if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
            return Err(RouteVerifyError::InvalidPolicy(
                "the route table family must be IPv4 or IPv6",
            ));
        }
        let sequence = next_sequence();
        let message = encode_route_dump(sequence, family);
        let replies = self
            .dump(&message, sequence, RTM_NEWROUTE)
            .map_err(write_error)?;
        let mut routes = Vec::new();
        for reply in replies {
            if family == libc::AF_INET as u8 {
                let route = parse_route_reply(&reply)?;
                if route.table != table {
                    continue;
                }
                routes.push(ObservedRouteKey {
                    key: RouteKey::from_ipv4(&route),
                    gateway: route.gateway.is_some() || route.via,
                    multipath: route.multipath,
                    encap: route.encap,
                    nexthop: route.nexthop_id.is_some(),
                });
            } else {
                let route = parse_ipv6_route_reply(&reply)?;
                if route.table != table {
                    continue;
                }
                routes.push(ObservedRouteKey {
                    key: RouteKey::from_ipv6(&route),
                    gateway: route.gateway.is_some() || route.via,
                    multipath: route.multipath,
                    encap: route.encap,
                    nexthop: route.nexthop_id.is_some(),
                });
            }
        }
        Ok(routes)
    }

    /// Read every policy rule of one family. The request sends no packet.
    fn rules(&self, family: u8) -> Result<Vec<RuleKey>, RouteVerifyError> {
        if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
            return Err(RouteVerifyError::InvalidPolicy(
                "the rule family must be IPv4 or IPv6",
            ));
        }
        let sequence = next_sequence();
        let message = encode_rule_dump(sequence, family);
        let replies = self
            .dump(&message, sequence, RTM_NEWRULE)
            .map_err(write_error)?;
        replies
            .iter()
            .map(|reply| parse_rule_reply(reply))
            .collect()
    }

    fn add_route(&self, key: &RouteKey) -> Result<(), RouteVerifyError> {
        let sequence = next_sequence();
        let message = encode_route_change(sequence, key, false);
        self.acknowledged(&message, sequence).map_err(write_error)
    }

    fn delete_route(&self, key: &RouteKey) -> Result<(), RouteVerifyError> {
        let sequence = next_sequence();
        let message = encode_route_change(sequence, key, true);
        self.acknowledged(&message, sequence).map_err(write_error)
    }

    fn add_rule(&self, rule: &RuleKey) -> Result<(), RouteVerifyError> {
        let sequence = next_sequence();
        let message = encode_rule_change(sequence, rule, false);
        self.acknowledged(&message, sequence).map_err(write_error)
    }

    fn delete_rule(&self, rule: &RuleKey) -> Result<(), RouteVerifyError> {
        let sequence = next_sequence();
        let message = encode_rule_change(sequence, rule, true);
        self.acknowledged(&message, sequence).map_err(write_error)
    }
}

/// Proof that the tunnel link is the expected TUN device.
///
/// Only [`RouteManager::verify_interface`] can create this value. It binds the
/// proof to one route manager and one live [`Tun`] handle. The proof holds a
/// weak token, so it expires when the device drops. A different device with the
/// same name and index cannot use the proof.
#[derive(Debug)]
pub struct VerifiedInterface {
    manager: Arc<()>,
    identity: TunnelIdentity,
    tun: Weak<TunToken>,
}

impl VerifiedInterface {
    /// Return the interface name.
    pub fn ifname(&self) -> &str {
        self.identity.name()
    }

    /// Return the interface index.
    pub fn ifindex(&self) -> u32 {
        self.identity.ifindex()
    }

    /// Return true when the proof belongs to this live device.
    fn is_for_tun(&self, tun: &Tun) -> bool {
        let Some(token) = self.tun.upgrade() else {
            return false;
        };
        Arc::ptr_eq(&token, &tun.token)
            && self.identity.ifindex == tun.ifindex
            && self.identity.name == tun.ifname
    }

    /// Refuse a proof from another device or a dropped device.
    fn require_tun(&self, tun: &Tun) -> io::Result<()> {
        if self.is_for_tun(tun) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface verification is stale or belongs to another device",
            ))
        }
    }
}

/// The IPv6 policy for the tunnel.
///
/// The values are distinct. Do not fold `Forward` and `Inherit` into one flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Policy {
    /// Block all IPv6 traffic. This is the direct-mode default.
    Block,
    /// Forward IPv6 through the tunnel. This is the source device proxy mode.
    Forward,
    /// Use the existing network path. This is an explicit leak.
    Inherit,
}

/// Tracks only the routes and rules that this instance created.
///
/// The two IPv4 /1 routes and one IPv6 route live in [`TUNNEL_TABLE`]. Two
/// policy rules per family select the table for unbound traffic and keep the
/// relay's bound outer sockets in table main. See the module documentation.
///
/// Every object carries a record: the table id, every rule selector, and the
/// route key with its metric, preferred source, and flow. Cleanup reads each
/// object again, deletes only a matching object, and keeps a record that it
/// cannot prove. An install refuses a non-empty table or a used rule priority.
/// Linux gives an object no creator identity. Do not describe the ownership
/// proof as complete.
pub struct RouteManager {
    ifname: String,
    ipv6: Ipv6Policy,
    table: u32,
    routes: Vec<RouteKey>,
    rules: Vec<RuleKey>,
    control: Arc<dyn RouteControl>,
    identity: Arc<()>,
}

/// Proof that the full start policy was checked.
///
/// Only [`RouteManager::verify_start`] can create this value. The private field
/// keeps other code from making the proof. A forward policy holds both route
/// proofs. A block policy holds the IPv4 proof and the block proof.
#[derive(Debug)]
pub struct VerifiedRoutes {
    ipv4: ProvenIpv4Routes,
    ipv6: Option<ProvenIpv6Route>,
    ipv6_block: Option<ProvenIpv6Block>,
}

impl VerifiedRoutes {
    /// Return the proven IPv4 routes.
    pub fn ipv4(&self) -> &ProvenIpv4Routes {
        &self.ipv4
    }

    /// Return the proven IPv6 forward route.
    pub fn ipv6(&self) -> Option<&ProvenIpv6Route> {
        self.ipv6.as_ref()
    }

    /// Return the proven IPv6 block policy.
    pub fn ipv6_block(&self) -> Option<&ProvenIpv6Block> {
        self.ipv6_block.as_ref()
    }
}

impl RouteManager {
    /// Create a manager for the named tunnel interface.
    ///
    /// The policy is recorded as one of the three explicit values. The
    /// constructor runs no netlink request. The manager uses the system route
    /// control layer.
    pub fn new(ifname: &str, ipv6: Ipv6Policy) -> io::Result<Self> {
        check_ifname(ifname)?;
        Ok(Self {
            ifname: ifname.to_owned(),
            ipv6,
            table: TUNNEL_TABLE,
            routes: Vec::new(),
            rules: Vec::new(),
            control: Arc::new(SystemControl),
            identity: Arc::new(()),
        })
    }

    /// Create a manager with a test control layer.
    #[cfg(test)]
    fn with_control(
        ifname: &str,
        ipv6: Ipv6Policy,
        control: Arc<dyn RouteControl>,
    ) -> io::Result<Self> {
        check_ifname(ifname)?;
        Ok(Self {
            ifname: ifname.to_owned(),
            ipv6,
            table: TUNNEL_TABLE,
            routes: Vec::new(),
            rules: Vec::new(),
            control,
            identity: Arc::new(()),
        })
    }

    /// Create a manager for a test that does not inspect the control layer.
    ///
    /// The `ip` argument is checked for the link guard tests. This constructor
    /// is not compiled in production.
    #[cfg(test)]
    fn with_runner(
        ifname: &str,
        ipv6: Ipv6Policy,
        ip: PathBuf,
        _runner: Arc<dyn CommandRunner>,
    ) -> io::Result<Self> {
        check_ifname(ifname)?;
        if !ip.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the ip tool path must be absolute",
            ));
        }
        Self::with_control(ifname, ipv6, Arc::new(EmptyControl))
    }

    /// Return the recorded IPv6 policy.
    pub fn ipv6_policy(&self) -> Ipv6Policy {
        self.ipv6
    }

    /// Return the dedicated table id.
    pub fn table_id(&self) -> u32 {
        self.table
    }

    /// Return the tunnel identity for a device that this manager controls.
    fn identity_for(&self, tun: &Tun) -> Result<TunnelIdentity, RouteVerifyError> {
        if tun.ifname() != self.ifname {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the device does not match the route manager",
            ));
        }
        TunnelIdentity::new(tun.ifindex(), tun.ifname())
    }

    /// Return the identity only when the proof belongs to this manager and this
    /// live device. A stale proof, or a device with the same name and index,
    /// does not pass.
    fn proof_identity(
        &self,
        proof: &VerifiedInterface,
        tun: &Tun,
    ) -> Result<TunnelIdentity, RouteVerifyError> {
        proof.require_tun(tun).map_err(|_| {
            RouteVerifyError::InvalidTunnelIdentity(
                "the interface proof is stale or names another device",
            )
        })?;
        if !Arc::ptr_eq(&self.identity, &proof.manager) {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface proof belongs to another route manager",
            ));
        }
        let identity = self.identity_for(tun)?;
        if proof.identity != identity {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface proof names another interface",
            ));
        }
        Ok(identity)
    }

    /// Prove that the tunnel link is the recorded TUN device.
    ///
    /// This method is read-only. It does not require the link to be up. Use the
    /// proof before any link or route change. [`LinkGuard`] brings the link up
    /// after this check.
    pub fn verify_interface(&self, tun: &Tun) -> Result<VerifiedInterface, RouteVerifyError> {
        self.verify_interface_with(tun, &SystemRouteObserver)
    }

    fn verify_interface_with(
        &self,
        tun: &Tun,
        observer: &dyn RouteObserver,
    ) -> Result<VerifiedInterface, RouteVerifyError> {
        let identity = self.identity_for(tun)?;
        let observation = observer.observe(&identity, &[])?;
        verify_link_identity(&observation.link, &identity)?;
        Ok(VerifiedInterface {
            manager: Arc::clone(&self.identity),
            identity,
            tun: Arc::downgrade(&tun.token),
        })
    }

    /// Install the two policy rules and the three routes.
    ///
    /// The proof must belong to the live device in `tun`. A stale proof, or a
    /// proof from another device with the same name and index, is refused. The
    /// outer interface must be a valid name that differs from the tunnel
    /// interface.
    ///
    /// The method first reads the dedicated table and the rule list. An object
    /// in that table, or a rule at either reserved priority, is an inconclusive
    /// ownership state, and the method changes nothing. Every add uses
    /// `NLM_F_EXCL`. A failed add removes the objects that are already
    /// recorded.
    pub fn install_verified(
        &mut self,
        proof: &VerifiedInterface,
        tun: &Tun,
        outer_ifname: &str,
    ) -> io::Result<()> {
        self.proof_identity(proof, tun)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        if !valid_ifname(outer_ifname) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the outer interface name is not valid",
            ));
        }
        if outer_ifname == self.ifname {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the outer interface is the tunnel interface",
            ));
        }
        if self.ipv6 == Ipv6Policy::Inherit {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux inherit is an explicit leak and is not a start mode",
            ));
        }
        if !self.routes.is_empty() || !self.rules.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "routes already installed or cleanup incomplete",
            ));
        }
        let control = Arc::clone(&self.control);
        self.require_empty_table(control.as_ref())?;
        self.require_free_priorities(control.as_ref())?;
        match self.add_objects(control.as_ref(), outer_ifname, proof.ifindex()) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.rollback(error)),
        }
    }

    /// Refuse a dedicated table that holds any route.
    fn require_empty_table(&self, control: &dyn RouteControl) -> io::Result<()> {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let routes = control.table_routes(family, self.table)?;
            if !routes.is_empty() {
                return Err(io::Error::other(format!(
                    "routing table {} is not empty; route ownership is inconclusive",
                    self.table
                )));
            }
        }
        Ok(())
    }

    /// Refuse a reserved rule priority that is already in use.
    fn require_free_priorities(&self, control: &dyn RouteControl) -> io::Result<()> {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let rules = control.rules(family)?;
            if rules.iter().any(|rule| {
                rule.priority == OUTER_RULE_PRIORITY || rule.priority == TUNNEL_RULE_PRIORITY
            }) {
                return Err(io::Error::other(format!(
                    "a policy rule with priority {} or {} already exists; rule ownership is inconclusive",
                    OUTER_RULE_PRIORITY, TUNNEL_RULE_PRIORITY
                )));
            }
        }
        Ok(())
    }

    /// Add the rules and routes and record each accepted object.
    fn add_objects(
        &mut self,
        control: &dyn RouteControl,
        outer_ifname: &str,
        ifindex: u32,
    ) -> io::Result<()> {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let rule = RuleKey::outer(family, outer_ifname);
            self.add_rule_recorded(control, rule, "outer policy rule")?;
            let rule = RuleKey::tunnel(family);
            self.add_rule_recorded(control, rule, "tunnel policy rule")?;
        }
        for prefix in [IPV4_FIRST_HALF, IPV4_SECOND_HALF] {
            let key = RouteKey::ipv4(prefix, ifindex);
            self.add_route_recorded(control, key, "IPv4 route")?;
        }
        let key = match self.ipv6 {
            Ipv6Policy::Forward => RouteKey::ipv6(IPV6_GLOBAL_UNICAST, ifindex),
            Ipv6Policy::Block => RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST),
            Ipv6Policy::Inherit => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Linux inherit is an explicit leak and is not a start mode",
                ))
            }
        };
        self.add_route_recorded(control, key, "IPv6 route")?;
        Ok(())
    }

    /// Record a rule before the add. On an ACK timeout, read the rule list
    /// again. Keep the record when the rule is present and matches, so the
    /// rollback removes an add that the kernel applied without an answer.
    fn add_rule_recorded(
        &mut self,
        control: &dyn RouteControl,
        rule: RuleKey,
        operation: &str,
    ) -> io::Result<()> {
        let index = self.rules.len();
        self.rules.push(rule.clone());
        match control.add_rule(&rule) {
            Ok(()) => Ok(()),
            Err(error) => {
                let keep = is_ack_timeout(&error)
                    && control
                        .rules(rule.family)
                        .map(|observed| rule_is_recorded(&observed, &rule))
                        .unwrap_or(true);
                if !keep {
                    self.rules.remove(index);
                }
                Err(add_error(operation, &error))
            }
        }
    }

    /// Record a route before the add. On an ACK timeout, read the table again.
    /// Keep the record when the route is present and matches, so the rollback
    /// removes an add that the kernel applied without an answer.
    fn add_route_recorded(
        &mut self,
        control: &dyn RouteControl,
        key: RouteKey,
        operation: &str,
    ) -> io::Result<()> {
        let index = self.routes.len();
        self.routes.push(key.clone());
        match control.add_route(&key) {
            Ok(()) => Ok(()),
            Err(error) => {
                let keep = is_ack_timeout(&error)
                    && control
                        .table_routes(key.family, key.table)
                        .map(|observed| route_is_recorded(&observed, &key))
                        .unwrap_or(true);
                if !keep {
                    self.routes.remove(index);
                }
                Err(add_error(operation, &error))
            }
        }
    }

    /// Remove the objects that a failed setup recorded.
    fn rollback(&mut self, error: io::Error) -> io::Error {
        match self.remove() {
            Ok(()) => error,
            Err(cleanup) => io::Error::new(
                error.kind(),
                format!("{error}; route cleanup failed: {cleanup}"),
            ),
        }
    }

    /// Record the start routes without a kernel change. Test builds only.
    ///
    /// This method lets a test reach the read-only route checks without root
    /// and without a route change. It records no rule and changes no table.
    #[cfg(test)]
    fn install_for_test(&mut self) -> io::Result<()> {
        if !self.routes.is_empty() || !self.rules.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "routes already installed or cleanup incomplete",
            ));
        }
        for prefix in [IPV4_FIRST_HALF, IPV4_SECOND_HALF] {
            self.routes.push(RouteKey {
                family: libc::AF_INET as u8,
                destination: prefix.address().octets().to_vec(),
                length: prefix.length(),
                source_length: 0,
                source: None,
                tos: 0,
                table: self.table,
                protocol: ROUTE_PROTOCOL_ID,
                route_type: RTN_UNICAST,
                scope: RT_SCOPE_LINK,
                oif: None,
                metric: None,
                prefsrc: None,
                flow: None,
            });
        }
        if self.ipv6 != Ipv6Policy::Inherit {
            let key = match self.ipv6 {
                Ipv6Policy::Forward => RouteKey::ipv6(IPV6_GLOBAL_UNICAST, 0),
                Ipv6Policy::Block => RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST),
                Ipv6Policy::Inherit => unreachable!(),
            };
            self.routes.push(key);
        }
        Ok(())
    }

    /// Remove every recorded object that the kernel still shows as ours.
    ///
    /// The call reads each object again and compares it with its record. A
    /// matching object is deleted. An absent object is already clean. A
    /// different object at the same key, or a failed read, is left in place,
    /// kept in the record, and reported. The call is idempotent. It returns an
    /// error when any record is still unproven.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.routes.is_empty() && self.rules.is_empty() {
            return Ok(());
        }
        let control = Arc::clone(&self.control);
        let mut failures = Vec::new();
        let mut kept_routes = Vec::new();
        for key in std::mem::take(&mut self.routes).into_iter().rev() {
            match control.table_routes(key.family, key.table) {
                Ok(observed) => {
                    let present = observed.iter().any(|item| {
                        item.key.family == key.family
                            && item.key.destination == key.destination
                            && item.key.length == key.length
                    });
                    if !present {
                        continue;
                    }
                    if route_is_recorded(&observed, &key) {
                        match control.delete_route(&key) {
                            Ok(()) => {}
                            Err(error) if is_missing(&error) => {}
                            Err(error) => {
                                failures.push(format!(
                                    "cannot delete route {} from table {}: {error}",
                                    describe_prefix(&key),
                                    key.table
                                ));
                                kept_routes.push(key);
                            }
                        }
                    } else {
                        failures.push(format!(
                            "route {} in table {} is not the recorded object; it was left in place",
                            describe_prefix(&key),
                            key.table
                        ));
                        kept_routes.push(key);
                    }
                }
                Err(error) => {
                    failures.push(format!(
                        "cannot prove route {} in table {}: {error}",
                        describe_prefix(&key),
                        key.table
                    ));
                    kept_routes.push(key);
                }
            }
        }
        self.routes = kept_routes;
        let mut kept_rules = Vec::new();
        for rule in std::mem::take(&mut self.rules).into_iter().rev() {
            match control.rules(rule.family) {
                Ok(observed) => {
                    let present = observed.iter().any(|item| item.priority == rule.priority);
                    if !present {
                        continue;
                    }
                    if rule_is_recorded(&observed, &rule) {
                        match control.delete_rule(&rule) {
                            Ok(()) => {}
                            Err(error) if is_missing(&error) => {}
                            Err(error) => {
                                failures.push(format!(
                                    "cannot delete the policy rule at priority {}: {error}",
                                    rule.priority
                                ));
                                kept_rules.push(rule);
                            }
                        }
                    } else {
                        failures.push(format!(
                            "the policy rule at priority {} is not the recorded object; it was left in place",
                            rule.priority
                        ));
                        kept_rules.push(rule);
                    }
                }
                Err(error) => {
                    failures.push(format!(
                        "cannot prove the policy rule at priority {}: {error}",
                        rule.priority
                    ));
                    kept_rules.push(rule);
                }
            }
        }
        self.rules = kept_rules;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }

    /// Prove the installed IPv4 routes. This method is read-only.
    ///
    /// The proof must belong to the live device in `tun`. The two /1 routes
    /// must be recorded as installed. The method uses fake probes. It sends no
    /// packet.
    pub fn verify_ipv4(
        &self,
        proof: &VerifiedInterface,
        tun: &Tun,
    ) -> Result<ProvenIpv4Routes, RouteVerifyError> {
        let identity = self.proof_identity(proof, tun)?;
        self.verify_ipv4_with(&identity, &SystemRouteObserver)
    }

    fn verify_ipv4_with(
        &self,
        identity: &TunnelIdentity,
        observer: &dyn RouteObserver,
    ) -> Result<ProvenIpv4Routes, RouteVerifyError> {
        if identity.name != self.ifname {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface does not match the route manager",
            ));
        }
        if !self.records(IPV4_FIRST_HALF) || !self.records(IPV4_SECOND_HALF) {
            return Err(RouteVerifyError::NotInstalled);
        }
        let observation = observer.observe(identity, &DEFAULT_IPV4_PROBES)?;
        for destination in DEFAULT_IPV4_PROBES {
            if !observation
                .probes
                .iter()
                .any(|probe| probe.destination == destination)
            {
                return Err(RouteVerifyError::MissingProbe { destination });
            }
        }
        verify_ipv4_selection_in(&observation, identity, self.table)
    }

    /// Return true when the record holds one IPv4 prefix in the tunnel table.
    fn records(&self, prefix: Ipv4Prefix) -> bool {
        self.routes.iter().any(|key| {
            key.family == libc::AF_INET as u8
                && key.destination == prefix.address().octets()
                && key.length == prefix.length()
                && key.table == self.table
        })
    }

    /// Return true when the record holds one IPv6 prefix in the tunnel table.
    fn records_ipv6(&self, prefix: Ipv6Prefix) -> bool {
        self.routes.iter().any(|key| {
            key.family == libc::AF_INET6 as u8
                && key.destination == prefix.address().octets()
                && key.length == prefix.length()
                && key.table == self.table
        })
    }

    /// Prove that the named interface is a live outer interface.
    ///
    /// This method is read-only. It resolves the interface name, reads the link
    /// with `RTM_GETLINK`, and checks the index, the name, the up flag, and the
    /// link type. It does not prove that a socket is bound to the interface.
    /// The caller must select the physical hotspot interface.
    pub fn verify_outer_pin(&self, ifname: &str) -> Result<OuterPinProof, RouteVerifyError> {
        if !valid_ifname(ifname) {
            return Err(RouteVerifyError::InvalidOuterInterface(
                "the outer interface name is not valid",
            ));
        }
        if ifname == self.ifname {
            return Err(RouteVerifyError::InvalidOuterInterface(
                "the outer interface is the tunnel interface",
            ));
        }
        let ifindex = interface_index(ifname).map_err(|error| RouteVerifyError::Unavailable {
            operation: "outer interface lookup",
            errno: error.raw_os_error().unwrap_or(libc::EIO),
        })?;
        let netlink = NetlinkRoute::open()?;
        let link = netlink.link(ifindex)?;
        self.outer_pin_from_link(&link, ifindex, ifname)
    }

    fn outer_pin_from_link(
        &self,
        link: &ObservedLink,
        ifindex: u32,
        ifname: &str,
    ) -> Result<OuterPinProof, RouteVerifyError> {
        let identity = OuterLinkIdentity::new(ifindex, ifname)?;
        prove_outer_link(link, &identity)?;
        Ok(OuterPinProof {
            manager: Arc::clone(&self.identity),
            identity,
        })
    }

    /// Check the IPv6 forward route. This method is read-only.
    ///
    /// The interface proof must belong to the live device in `tun`. The outer
    /// proof must belong to this manager. The policy must be
    /// [`Ipv6Policy::Forward`]. The method sends one fake probe for each
    /// default IPv6 destination. It sends no packet.
    ///
    /// This method does not install a route. It does not prove that this
    /// process installed the observed route. Do not use it as a start gate
    /// until setup, cleanup, and a live test are complete.
    pub fn verify_ipv6_forward(
        &self,
        proof: &VerifiedInterface,
        tun: &Tun,
        outer: &OuterPinProof,
    ) -> Result<ProvenIpv6Route, RouteVerifyError> {
        let identity = self.proof_identity(proof, tun)?;
        self.verify_ipv6_forward_with(&identity, outer, &SystemIpv6RouteObserver)
    }

    fn verify_ipv6_forward_with(
        &self,
        identity: &TunnelIdentity,
        outer: &OuterPinProof,
        observer: &dyn Ipv6RouteObserver,
    ) -> Result<ProvenIpv6Route, RouteVerifyError> {
        match self.ipv6 {
            Ipv6Policy::Forward => {}
            Ipv6Policy::Block => return Err(RouteVerifyError::Ipv6ForwardPolicyRequired),
            Ipv6Policy::Inherit => return Err(RouteVerifyError::Ipv6InheritNotAllowed),
        }
        if identity.name != self.ifname {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface does not match the route manager",
            ));
        }
        if !self.records_ipv6(IPV6_GLOBAL_UNICAST) {
            return Err(RouteVerifyError::NotInstalled);
        }
        if !Arc::ptr_eq(&self.identity, &outer.manager) {
            return Err(RouteVerifyError::InvalidOuterInterface(
                "the outer interface proof belongs to another route manager",
            ));
        }
        let observation = observer.observe_ipv6(identity, &outer.identity, &DEFAULT_IPV6_PROBES)?;
        for destination in DEFAULT_IPV6_PROBES {
            if !observation
                .probes
                .iter()
                .any(|probe| probe.destination == destination)
            {
                return Err(RouteVerifyError::MissingIpv6Probe { destination });
            }
        }
        verify_ipv6_forward_selection_in(&observation, identity, &outer.identity, self.table)
    }

    /// Check the IPv6 block policy. This method is read-only.
    ///
    /// The interface proof must belong to the live device in `tun`. The policy
    /// must be [`Ipv6Policy::Block`]. The dedicated table must hold exactly the
    /// recorded blackhole route. Every fake probe must select a non-unicast
    /// FIB entry. The method sends no packet.
    ///
    /// This method does not prove that this process installed the observed
    /// route. Do not use it as a start gate until setup, cleanup, and a live
    /// test are complete.
    pub fn verify_ipv6_block(
        &self,
        proof: &VerifiedInterface,
        tun: &Tun,
    ) -> Result<ProvenIpv6Block, RouteVerifyError> {
        let identity = self.proof_identity(proof, tun)?;
        self.verify_ipv6_block_with(&identity, &SystemIpv6BlockObserver)
    }

    fn verify_ipv6_block_with(
        &self,
        identity: &TunnelIdentity,
        observer: &dyn Ipv6BlockObserver,
    ) -> Result<ProvenIpv6Block, RouteVerifyError> {
        if self.ipv6 != Ipv6Policy::Block {
            return Err(RouteVerifyError::InvalidPolicy(
                "the IPv6 block check requires the block policy",
            ));
        }
        if identity.name != self.ifname {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface does not match the route manager",
            ));
        }
        if !self.records_ipv6(IPV6_GLOBAL_UNICAST) {
            return Err(RouteVerifyError::NotInstalled);
        }
        let observation =
            observer.observe_ipv6_block(identity, &DEFAULT_IPV6_PROBES, self.table)?;
        verify_ipv6_block_selection_in(&observation, identity, self.table)
    }

    /// Verify the full start policy. This method is read-only.
    ///
    /// The interface proof must belong to the live device. The outer proof must
    /// belong to this manager. A forward policy returns both route proofs. A
    /// block policy returns the IPv4 proof and the block proof. The inherit
    /// policy is never a start mode. A start path must not run the relay when
    /// this method returns an error.
    pub fn verify_start(
        &self,
        proof: &VerifiedInterface,
        tun: &Tun,
        outer: &OuterPinProof,
    ) -> Result<VerifiedRoutes, RouteVerifyError> {
        let identity = self.proof_identity(proof, tun)?;
        let ipv4 = self.verify_ipv4_with(&identity, &SystemRouteObserver)?;
        match self.ipv6 {
            Ipv6Policy::Forward => {
                let ipv6 =
                    self.verify_ipv6_forward_with(&identity, outer, &SystemIpv6RouteObserver)?;
                Ok(VerifiedRoutes {
                    ipv4,
                    ipv6: Some(ipv6),
                    ipv6_block: None,
                })
            }
            Ipv6Policy::Block => {
                let ipv6_block =
                    self.verify_ipv6_block_with(&identity, &SystemIpv6BlockObserver)?;
                Ok(VerifiedRoutes {
                    ipv4,
                    ipv6: None,
                    ipv6_block: Some(ipv6_block),
                })
            }
            Ipv6Policy::Inherit => Err(RouteVerifyError::Ipv6InheritNotAllowed),
        }
    }

    /// Verify the IPv4 start routes and the IPv6 block policy. Read-only.
    ///
    /// This method has no outer interface proof, so a forward policy cannot
    /// finish the IPv6 check. Use [`RouteManager::verify_start`] for the start
    /// gate. The proof must belong to the live device in `tun`.
    pub fn verify(
        &self,
        proof: &VerifiedInterface,
        tun: &Tun,
    ) -> Result<VerifiedRoutes, RouteVerifyError> {
        let identity = self.proof_identity(proof, tun)?;
        self.verify_with(&identity, &SystemRouteObserver, &SystemIpv6BlockObserver)
    }

    fn verify_with(
        &self,
        identity: &TunnelIdentity,
        observer: &dyn RouteObserver,
        block_observer: &dyn Ipv6BlockObserver,
    ) -> Result<VerifiedRoutes, RouteVerifyError> {
        if identity.name != self.ifname {
            return Err(RouteVerifyError::InvalidTunnelIdentity(
                "the interface does not match the route manager",
            ));
        }
        match self.ipv6 {
            Ipv6Policy::Inherit => Err(RouteVerifyError::Ipv6InheritNotAllowed),
            Ipv6Policy::Forward => {
                self.verify_ipv4_with(identity, observer)?;
                Err(RouteVerifyError::Ipv6ForwardUnverified)
            }
            Ipv6Policy::Block => {
                let ipv4 = self.verify_ipv4_with(identity, observer)?;
                let ipv6_block = self.verify_ipv6_block_with(identity, block_observer)?;
                Ok(VerifiedRoutes {
                    ipv4,
                    ipv6: None,
                    ipv6_block: Some(ipv6_block),
                })
            }
        }
    }

    /// Return true while a route or rule is recorded as installed.
    pub fn has_installed_routes(&self) -> bool {
        !self.routes.is_empty() || !self.rules.is_empty()
    }
}

/// Return true when the named link is up and has a usable IPv4 address.
///
/// This read-only check uses `RTM_GETLINK` for the link state and `getifaddrs`
/// for the address. It starts no process and changes no route. A missing link is
/// a down link, not an error. A netlink read failure is an error, so the caller
/// does not count an unknown state as link loss.
pub fn link_ready(ifname: &str) -> io::Result<bool> {
    if !valid_ifname(ifname) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    let index = match interface_index(ifname) {
        Ok(index) => index,
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => return Ok(false),
        Err(error) => return Err(error),
    };
    let netlink = NetlinkRoute::open().map_err(route_error_to_io)?;
    let link = match netlink.link(index) {
        Ok(link) => link,
        Err(RouteVerifyError::LinkMissing { .. }) => return Ok(false),
        Err(error) => return Err(io::Error::other(error.to_string())),
    };
    if link.name != ifname
        || link.flags & IFF_UP == 0
        || link.flags & IFF_LOOPBACK != 0
        || link.hardware_type == ARPHRD_NONE
    {
        return Ok(false);
    }
    if let Some(kind) = link.kind.as_deref() {
        if NON_PHYSICAL_LINK_KINDS.contains(&kind) {
            return Ok(false);
        }
    }
    crate::autostop::link_observation(ifname)
}

fn add_error(operation: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("cannot add the {operation}: {error}"))
}

fn is_missing(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH))
}

fn describe_prefix(key: &RouteKey) -> String {
    if key.family == libc::AF_INET as u8 && key.destination.len() == 4 {
        let octets: [u8; 4] = key.destination.as_slice().try_into().unwrap_or([0; 4]);
        return format!("{}/{}", Ipv4Addr::from(octets), key.length);
    }
    if key.family == libc::AF_INET6 as u8 && key.destination.len() == 16 {
        let octets: [u8; 16] = key.destination.as_slice().try_into().unwrap_or([0; 16]);
        return format!("{}/{}", Ipv6Addr::from(octets), key.length);
    }
    format!("family {} prefix length {}", key.family, key.length)
}

/// A test control layer that reports an empty kernel and accepts no change.
#[cfg(test)]
struct EmptyControl;

#[cfg(test)]
impl RouteControl for EmptyControl {
    fn table_routes(&self, _family: u8, _table: u32) -> io::Result<Vec<ObservedRouteKey>> {
        Ok(Vec::new())
    }
    fn add_route(&self, _key: &RouteKey) -> io::Result<()> {
        Ok(())
    }
    fn delete_route(&self, _key: &RouteKey) -> io::Result<()> {
        Ok(())
    }
    fn rules(&self, _family: u8) -> io::Result<Vec<RuleKey>> {
        Ok(Vec::new())
    }
    fn add_rule(&self, _rule: &RuleKey) -> io::Result<()> {
        Ok(())
    }
    fn delete_rule(&self, _rule: &RuleKey) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            eprintln!("[route] cleanup failed: {}", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A fake packet source and sink. It creates no device and changes no
    /// route.
    #[derive(Default)]
    struct FakeIo {
        reads: Mutex<VecDeque<Vec<u8>>>,
        read_error: Mutex<Option<io::ErrorKind>>,
        writes: Mutex<Vec<Vec<u8>>>,
        write_return: Mutex<Option<usize>>,
        write_error: Mutex<Option<io::ErrorKind>>,
    }

    impl FakeIo {
        fn with_reads(packets: Vec<Vec<u8>>) -> Self {
            let io = Self::default();
            *io.reads.lock().unwrap() = packets.into();
            io
        }
    }

    impl PacketIo for FakeIo {
        fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
            if let Some(kind) = *self.read_error.lock().unwrap() {
                return Err(io::Error::from(kind));
            }
            let Some(packet) = self.reads.lock().unwrap().pop_front() else {
                return Ok(0);
            };
            assert!(packet.len() <= buffer.len());
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }

        fn write(&self, packet: &[u8]) -> io::Result<usize> {
            if let Some(kind) = *self.write_error.lock().unwrap() {
                return Err(io::Error::from(kind));
            }
            self.writes.lock().unwrap().push(packet.to_vec());
            Ok(self.write_return.lock().unwrap().unwrap_or(packet.len()))
        }
    }

    /// A fake command runner. It records every argument separately and can
    /// inject one failure at a chosen call index.
    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<Vec<String>>>,
        fail_at: Mutex<Option<usize>>,
    }

    fn recorded_call(program: &Path, args: &[String]) -> Vec<String> {
        let mut call = vec![program.to_string_lossy().into_owned()];
        call.extend_from_slice(args);
        call
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &Path, args: &[String]) -> io::Result<()> {
            let call = recorded_call(program, args);
            let index = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(call);
                calls.len() - 1
            };
            if *self.fail_at.lock().unwrap() == Some(index) {
                return Err(io::Error::other("injected failure"));
            }
            Ok(())
        }
    }

    /// A fake route and rule control layer. It holds kernel objects in memory,
    /// records every call, and can inject a failure, an ACK timeout, or a read
    /// error.
    #[derive(Default)]
    struct FakeControl {
        routes: Mutex<Vec<ObservedRouteKey>>,
        rules: Mutex<Vec<RuleKey>>,
        calls: Mutex<Vec<String>>,
        fail_at: Mutex<Option<usize>>,
        timeout_at: Mutex<Option<usize>>,
        timeout_applies: Mutex<bool>,
        read_error: Mutex<bool>,
    }

    impl FakeControl {
        fn record(&self, call: String) -> usize {
            let mut calls = self.calls.lock().unwrap();
            calls.push(call);
            calls.len() - 1
        }

        fn injected(&self, index: usize) -> io::Result<()> {
            if *self.fail_at.lock().unwrap() == Some(index) {
                return Err(io::Error::other("injected failure"));
            }
            Ok(())
        }

        fn timed_out(&self, index: usize) -> Option<io::Error> {
            if *self.timeout_at.lock().unwrap() == Some(index) {
                return Some(io::Error::from_raw_os_error(libc::ETIMEDOUT));
            }
            None
        }

        fn fail_call(&self, index: usize) {
            *self.fail_at.lock().unwrap() = Some(index);
        }

        /// Make one write call lose its acknowledgement. When `applies` is
        /// true, the fake kernel applies the object before it reports the
        /// timeout.
        fn timeout_call(&self, index: usize, applies: bool) {
            *self.timeout_at.lock().unwrap() = Some(index);
            *self.timeout_applies.lock().unwrap() = applies;
        }

        fn fail_reads(&self) {
            *self.read_error.lock().unwrap() = true;
        }

        fn allow_reads(&self) {
            *self.read_error.lock().unwrap() = false;
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn route_count(&self) -> usize {
            self.routes.lock().unwrap().len()
        }

        fn rule_count(&self) -> usize {
            self.rules.lock().unwrap().len()
        }

        fn route_keys(&self) -> Vec<RouteKey> {
            self.routes
                .lock()
                .unwrap()
                .iter()
                .map(|item| item.key.clone())
                .collect()
        }

        fn rule_keys(&self) -> Vec<RuleKey> {
            self.rules.lock().unwrap().clone()
        }

        fn put_route(&self, key: RouteKey) {
            self.routes.lock().unwrap().push(ObservedRouteKey {
                key,
                gateway: false,
                multipath: false,
                encap: false,
                nexthop: false,
            });
        }

        fn put_foreign_route(&self, key: RouteKey) {
            self.routes.lock().unwrap().push(ObservedRouteKey {
                key,
                gateway: true,
                multipath: false,
                encap: false,
                nexthop: false,
            });
        }

        fn put_rule(&self, rule: RuleKey) {
            self.rules.lock().unwrap().push(rule);
        }

        fn clear_objects(&self) {
            self.routes.lock().unwrap().clear();
            self.rules.lock().unwrap().clear();
        }
    }

    impl RouteControl for FakeControl {
        fn table_routes(&self, family: u8, table: u32) -> io::Result<Vec<ObservedRouteKey>> {
            self.record(format!("read-routes {family} {table}"));
            if *self.read_error.lock().unwrap() {
                return Err(io::Error::other("injected read failure"));
            }
            Ok(self
                .routes
                .lock()
                .unwrap()
                .iter()
                .filter(|item| item.key.family == family && item.key.table == table)
                .cloned()
                .collect())
        }

        fn add_route(&self, key: &RouteKey) -> io::Result<()> {
            let index = self.record(format!("add-route {}", describe_prefix(key)));
            self.injected(index)?;
            if let Some(error) = self.timed_out(index) {
                if *self.timeout_applies.lock().unwrap() {
                    self.put_route(key.clone());
                }
                return Err(error);
            }
            let mut routes = self.routes.lock().unwrap();
            if routes.iter().any(|item| item.key.same_key(key)) {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            routes.push(ObservedRouteKey {
                key: key.clone(),
                gateway: false,
                multipath: false,
                encap: false,
                nexthop: false,
            });
            Ok(())
        }

        fn delete_route(&self, key: &RouteKey) -> io::Result<()> {
            let index = self.record(format!("delete-route {}", describe_prefix(key)));
            self.injected(index)?;
            let mut routes = self.routes.lock().unwrap();
            let before = routes.len();
            routes.retain(|item| !item.key.same_key(key));
            if routes.len() == before {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            Ok(())
        }

        fn rules(&self, family: u8) -> io::Result<Vec<RuleKey>> {
            self.record(format!("read-rules {family}"));
            if *self.read_error.lock().unwrap() {
                return Err(io::Error::other("injected read failure"));
            }
            Ok(self
                .rules
                .lock()
                .unwrap()
                .iter()
                .filter(|item| item.family == family)
                .cloned()
                .collect())
        }

        fn add_rule(&self, rule: &RuleKey) -> io::Result<()> {
            let index = self.record(format!("add-rule {}", rule.priority));
            self.injected(index)?;
            if let Some(error) = self.timed_out(index) {
                if *self.timeout_applies.lock().unwrap() {
                    self.put_rule(rule.clone());
                }
                return Err(error);
            }
            let mut rules = self.rules.lock().unwrap();
            if rules
                .iter()
                .any(|item| item.family == rule.family && item.priority == rule.priority)
            {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            rules.push(rule.clone());
            Ok(())
        }

        fn delete_rule(&self, rule: &RuleKey) -> io::Result<()> {
            let index = self.record(format!("delete-rule {}", rule.priority));
            self.injected(index)?;
            let mut rules = self.rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|item| {
                !(item.family == rule.family
                    && item.priority == rule.priority
                    && item.table == rule.table)
            });
            if rules.len() == before {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            Ok(())
        }
    }

    fn test_ip() -> PathBuf {
        PathBuf::from("/usr/sbin/ip")
    }

    const TEST_IFNAME: &str = "hs-tun0";
    const TEST_IFINDEX: u32 = 7;
    const TEST_OUTER_IFNAME: &str = "wlan0";
    const TEST_OUTER_IFINDEX: u32 = 9;

    fn test_identity() -> TunnelIdentity {
        TunnelIdentity::new(TEST_IFINDEX, TEST_IFNAME).unwrap()
    }

    fn test_link() -> ObservedLink {
        ObservedLink {
            ifindex: TEST_IFINDEX,
            name: TEST_IFNAME.to_owned(),
            kind: Some("tun".to_owned()),
            hardware_type: ARPHRD_NONE,
            flags: IFF_UP,
        }
    }

    fn test_route(prefix: Ipv4Prefix) -> ObservedRoute {
        ObservedRoute {
            prefix,
            source_length: 0,
            source: None,
            tos: 0,
            table: RT_TABLE_MAIN,
            protocol: ROUTE_PROTOCOL_ID,
            route_type: RTN_UNICAST,
            ifindex: Some(TEST_IFINDEX),
            gateway: None,
            prefsrc: None,
            flow: None,
            multipath: false,
            via: false,
            encap: false,
            nexthop_id: None,
            dead: false,
            link_down: false,
            priority: None,
        }
    }

    fn test_probe(destination: Ipv4Addr) -> ObservedProbe {
        ObservedProbe {
            destination,
            route: test_route(half_prefix(destination)),
        }
    }

    fn good_observation() -> RouteObservation {
        RouteObservation {
            link: test_link(),
            probes: DEFAULT_IPV4_PROBES
                .iter()
                .map(|destination| test_probe(*destination))
                .collect(),
        }
    }

    fn good_observation_in(table: u32) -> RouteObservation {
        let mut observation = good_observation();
        for probe in &mut observation.probes {
            probe.route.table = table;
        }
        observation
    }

    fn test_outer_link() -> ObservedLink {
        ObservedLink {
            ifindex: TEST_OUTER_IFINDEX,
            name: TEST_OUTER_IFNAME.to_owned(),
            kind: None,
            hardware_type: libc::ARPHRD_ETHER,
            flags: IFF_UP,
        }
    }

    fn test_outer() -> OuterLinkIdentity {
        OuterLinkIdentity::new(TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME).unwrap()
    }

    fn test_ipv6_route() -> ObservedIpv6Route {
        ObservedIpv6Route {
            prefix: IPV6_GLOBAL_UNICAST,
            source_length: 0,
            source: None,
            tos: 0,
            table: RT_TABLE_MAIN,
            protocol: ROUTE_PROTOCOL_ID,
            route_type: RTN_UNICAST,
            ifindex: Some(TEST_IFINDEX),
            gateway: None,
            prefsrc: None,
            flow: None,
            multipath: false,
            via: false,
            encap: false,
            nexthop_id: None,
            dead: false,
            link_down: false,
            cloned: false,
            priority: None,
        }
    }

    fn test_ipv6_probe(destination: Ipv6Addr) -> ObservedIpv6Probe {
        ObservedIpv6Probe {
            destination,
            route: test_ipv6_route(),
        }
    }

    fn good_ipv6_observation() -> Ipv6RouteObservation {
        Ipv6RouteObservation {
            link: test_link(),
            outer_link: test_outer_link(),
            probes: DEFAULT_IPV6_PROBES
                .iter()
                .map(|destination| test_ipv6_probe(*destination))
                .collect(),
        }
    }

    fn good_ipv6_observation_in(table: u32) -> Ipv6RouteObservation {
        let mut observation = good_ipv6_observation();
        for probe in &mut observation.probes {
            probe.route.table = table;
        }
        observation
    }

    fn good_ipv6_block_observation() -> Ipv6BlockObservation {
        Ipv6BlockObservation {
            link: test_link(),
            route_recorded: true,
            probes: DEFAULT_IPV6_PROBES
                .iter()
                .map(|destination| BlockedIpv6Probe {
                    destination: *destination,
                    blocked: true,
                })
                .collect(),
        }
    }

    fn fake_tun() -> Tun {
        fake_tun_named(TEST_IFINDEX, TEST_IFNAME)
    }

    fn fake_tun_named(ifindex: u32, ifname: &str) -> Tun {
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        let _peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Tun {
            fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            ifname: ifname.to_owned(),
            ifindex,
            mtu: 1500,
            token: Arc::new(TunToken),
        }
    }

    /// A fake observer. It returns one fixed observation and records the probe
    /// list. It creates no socket and sends no packet.
    struct FakeObserver {
        observation: RouteObservation,
        error: Option<RouteVerifyError>,
        calls: Mutex<Vec<Vec<Ipv4Addr>>>,
    }

    impl FakeObserver {
        fn good() -> Self {
            Self {
                observation: good_observation(),
                error: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn failing(error: RouteVerifyError) -> Self {
            Self {
                observation: good_observation(),
                error: Some(error),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn from_observation(observation: RouteObservation) -> Self {
            Self {
                observation,
                error: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn in_table(table: u32) -> Self {
            let mut observation = good_observation();
            for probe in &mut observation.probes {
                probe.route.table = table;
            }
            Self::from_observation(observation)
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl RouteObserver for FakeObserver {
        fn observe(
            &self,
            _identity: &TunnelIdentity,
            probes: &[Ipv4Addr],
        ) -> Result<RouteObservation, RouteVerifyError> {
            self.calls.lock().unwrap().push(probes.to_vec());
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(self.observation.clone())
        }
    }

    /// A fake IPv6 observer. It records the identities and the probe list. It
    /// creates no socket and sends no packet.
    struct FakeIpv6Observer {
        observation: Ipv6RouteObservation,
        error: Option<RouteVerifyError>,
        calls: Mutex<Vec<(u32, u32, Vec<Ipv6Addr>)>>,
    }

    impl FakeIpv6Observer {
        fn good() -> Self {
            Self {
                observation: good_ipv6_observation(),
                error: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn from_observation(observation: Ipv6RouteObservation) -> Self {
            Self {
                observation,
                error: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn in_table(table: u32) -> Self {
            let mut observation = good_ipv6_observation();
            for probe in &mut observation.probes {
                probe.route.table = table;
            }
            Self::from_observation(observation)
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl Ipv6RouteObserver for FakeIpv6Observer {
        fn observe_ipv6(
            &self,
            identity: &TunnelIdentity,
            outer: &OuterLinkIdentity,
            probes: &[Ipv6Addr],
        ) -> Result<Ipv6RouteObservation, RouteVerifyError> {
            self.calls
                .lock()
                .unwrap()
                .push((identity.ifindex(), outer.ifindex(), probes.to_vec()));
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(self.observation.clone())
        }
    }

    /// A fake IPv6 block observer. It records the identity and the probe list.
    /// It creates no socket and sends no packet.
    struct FakeIpv6BlockObserver {
        observation: Ipv6BlockObservation,
        error: Option<RouteVerifyError>,
        calls: Mutex<Vec<(u32, Vec<Ipv6Addr>)>>,
    }

    impl FakeIpv6BlockObserver {
        fn good() -> Self {
            Self {
                observation: good_ipv6_block_observation(),
                error: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn from_observation(observation: Ipv6BlockObservation) -> Self {
            Self {
                observation,
                error: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn failing(error: RouteVerifyError) -> Self {
            Self {
                observation: good_ipv6_block_observation(),
                error: Some(error),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl Ipv6BlockObserver for FakeIpv6BlockObserver {
        fn observe_ipv6_block(
            &self,
            identity: &TunnelIdentity,
            probes: &[Ipv6Addr],
            _table: u32,
        ) -> Result<Ipv6BlockObservation, RouteVerifyError> {
            self.calls
                .lock()
                .unwrap()
                .push((identity.ifindex(), probes.to_vec()));
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(self.observation.clone())
        }
    }

    fn test_netlink_message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; NLMSG_HDRLEN + payload.len()];
        let length = message.len() as u32;
        write_u32(&mut message[0..4], length);
        write_u16(&mut message[4..6], kind);
        write_u32(&mut message[8..12], sequence);
        message[NLMSG_HDRLEN..].copy_from_slice(payload);
        message
    }

    fn test_attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let aligned = (length + 3) & !3;
        let mut attr = vec![0u8; aligned];
        write_u16(&mut attr[0..2], length as u16);
        write_u16(&mut attr[2..4], kind);
        attr[4..4 + value.len()].copy_from_slice(value);
        attr
    }

    struct TestRouteSpec {
        destination: Option<Ipv4Addr>,
        destination_length: u8,
        table: u32,
        protocol: u8,
        route_type: u8,
        flags: u32,
        ifindex: Option<u32>,
    }

    fn test_route_payload_raw(spec: TestRouteSpec, extra: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[0] = libc::AF_INET as u8;
        payload[1] = spec.destination_length;
        payload[4] = spec.table as u8;
        payload[5] = spec.protocol;
        payload[6] = 253;
        payload[7] = spec.route_type;
        payload[8..12].copy_from_slice(&spec.flags.to_ne_bytes());
        let mut attributes = vec![test_attr(RTA_TABLE, &spec.table.to_ne_bytes())];
        if let Some(destination) = spec.destination {
            attributes.push(test_attr(RTA_DST, &destination.octets()));
        }
        if let Some(ifindex) = spec.ifindex {
            attributes.push(test_attr(RTA_OIF, &ifindex.to_ne_bytes()));
        }
        attributes.extend_from_slice(extra);
        for attribute in attributes {
            payload.extend_from_slice(&attribute);
        }
        payload
    }

    fn test_route_payload(
        prefix: Ipv4Prefix,
        table: u32,
        protocol: u8,
        route_type: u8,
        flags: u32,
        ifindex: Option<u32>,
        extra: &[Vec<u8>],
    ) -> Vec<u8> {
        let destination = (prefix.length() > 0).then_some(prefix.address());
        test_route_payload_raw(
            TestRouteSpec {
                destination,
                destination_length: prefix.length(),
                table,
                protocol,
                route_type,
                flags,
                ifindex,
            },
            extra,
        )
    }

    struct TestIpv6RouteSpec {
        destination: Option<Ipv6Addr>,
        destination_length: u8,
        source: Option<Ipv6Addr>,
        source_length: u8,
        table: u32,
        protocol: u8,
        route_type: u8,
        flags: u32,
        ifindex: Option<u32>,
    }

    fn test_ipv6_route_payload_raw(spec: TestIpv6RouteSpec, extra: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[0] = libc::AF_INET6 as u8;
        payload[1] = spec.destination_length;
        payload[2] = spec.source_length;
        payload[4] = spec.table as u8;
        payload[5] = spec.protocol;
        payload[7] = spec.route_type;
        payload[8..12].copy_from_slice(&spec.flags.to_ne_bytes());
        let mut attributes = vec![test_attr(RTA_TABLE, &spec.table.to_ne_bytes())];
        if let Some(destination) = spec.destination {
            attributes.push(test_attr(RTA_DST, &destination.octets()));
        }
        if let Some(source) = spec.source {
            attributes.push(test_attr(RTA_SRC, &source.octets()));
        }
        if let Some(ifindex) = spec.ifindex {
            attributes.push(test_attr(RTA_OIF, &ifindex.to_ne_bytes()));
        }
        attributes.extend_from_slice(extra);
        for attribute in attributes {
            payload.extend_from_slice(&attribute);
        }
        payload
    }

    fn test_ipv6_route_payload(
        prefix: Ipv6Prefix,
        table: u32,
        protocol: u8,
        route_type: u8,
        flags: u32,
        ifindex: Option<u32>,
        extra: &[Vec<u8>],
    ) -> Vec<u8> {
        let destination = (prefix.length() > 0).then_some(prefix.address());
        test_ipv6_route_payload_raw(
            TestIpv6RouteSpec {
                destination,
                destination_length: prefix.length(),
                source: None,
                source_length: 0,
                table,
                protocol,
                route_type,
                flags,
                ifindex,
            },
            extra,
        )
    }

    fn test_link_payload(
        ifindex: u32,
        name: &str,
        kind: Option<&str>,
        hardware_type: u16,
        flags: u32,
    ) -> Vec<u8> {
        let mut payload = vec![0u8; 16];
        payload[2..4].copy_from_slice(&hardware_type.to_ne_bytes());
        payload[4..8].copy_from_slice(&(ifindex as i32).to_ne_bytes());
        payload[8..12].copy_from_slice(&flags.to_ne_bytes());
        let mut name_value = name.as_bytes().to_vec();
        name_value.push(0);
        payload.extend_from_slice(&test_attr(IFLA_IFNAME, &name_value));
        if let Some(kind) = kind {
            let mut kind_value = kind.as_bytes().to_vec();
            kind_value.push(0);
            let nested = test_attr(IFLA_INFO_KIND, &kind_value);
            payload.extend_from_slice(&test_attr(IFLA_LINKINFO, &nested));
        }
        payload
    }

    fn ipv4_packet(len: usize) -> Vec<u8> {
        assert!(len >= 20);
        let mut packet = vec![0u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[9] = 17;
        packet
    }

    fn ipv6_packet(payload: usize) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        packet[6] = 59;
        packet[7] = 64;
        packet
    }

    #[test]
    fn tun_flags_are_tun_without_packet_information() {
        assert_eq!(TUN_FLAGS as u16, 0x9001);
        assert_ne!((TUN_FLAGS as u16) & (libc::IFF_TUN_EXCL as u16), 0);
    }

    #[test]
    fn ipv6_netlink_layout_is_checked() {
        assert_eq!(NLMSG_HDRLEN, std::mem::size_of::<libc::nlmsghdr>());
        assert_eq!(libc::AF_INET6, 10);
        assert_eq!(RTM_F_FIB_MATCH, 0x2000);
        assert_eq!(RTM_F_LOOKUP_TABLE, 0x1000);
        assert_eq!(RTM_F_FIB_MATCH & RTM_F_LOOKUP_TABLE, 0);
        assert_eq!(RTM_F_CLONED, 0x2);
        assert_eq!(RTA_SRC, 2);
        assert_eq!(RTA_DST, 1);
        assert_eq!(RTA_OIF, 4);
    }

    #[test]
    fn ifreq_has_the_linux_layout_and_raw_name() {
        let request = build_ifreq("hs-tun0").unwrap();
        assert_eq!(request.flags, TUN_FLAGS);
        let name = unsafe { CStr::from_ptr(request.name.as_ptr()) }
            .to_str()
            .unwrap();
        assert_eq!(name, "hs-tun0");
        assert_eq!(&request.reserved, &[0u8; IFREQ_RESERVED]);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
    }

    #[test]
    fn interface_names_are_bounded_and_safe() {
        assert!(valid_ifname("hs-tun0"));
        assert!(valid_ifname("hotspot_shade.1"));
        assert!(valid_ifname(&"a".repeat(15)));
        assert!(!valid_ifname(""));
        assert!(!valid_ifname("."));
        assert!(!valid_ifname(".."));
        assert!(!valid_ifname("a/b"));
        assert!(!valid_ifname("a b"));
        assert!(!valid_ifname("-a"));
        assert!(!valid_ifname("bad\nname"));
        assert!(!valid_ifname("caf\u{e9}"));
        assert!(!valid_ifname(&"a".repeat(16)));
        assert!(build_ifreq("a/b").is_err());
    }

    #[test]
    fn link_ready_reads_the_kernel_without_a_change() {
        assert_eq!(
            link_ready("").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        // A missing link is a down link, not an unknown state.
        assert!(!link_ready("hs-missing0").unwrap());
        // The loopback link is not a physical outer link.
        assert!(!link_ready("lo").unwrap());
    }

    #[test]
    fn mtu_is_bounded() {
        assert_eq!(validate_mtu(576).unwrap(), 576);
        assert_eq!(validate_mtu(1500).unwrap(), 1500);
        assert_eq!(validate_mtu(65_535).unwrap(), 65_535);
        assert!(validate_mtu(0).is_err());
        assert!(validate_mtu(575).is_err());
        assert!(validate_mtu(65_536).is_err());
    }

    #[test]
    fn packet_headers_are_checked_before_a_device_call() {
        assert_eq!(packet_len(&ipv4_packet(20)).unwrap(), 20);
        assert_eq!(packet_len(&ipv6_packet(8)).unwrap(), 48);
        assert!(packet_len(&[]).is_err());
        assert!(packet_len(&[0x45; 19]).is_err());
        assert!(packet_len(&[0x35; 20]).is_err());
        assert!(packet_len(&[0x60; 39]).is_err());
        let mut bad_v4 = ipv4_packet(20);
        bad_v4[2..4].copy_from_slice(&21u16.to_be_bytes());
        assert!(packet_len(&bad_v4).is_err());
        let mut bad_v6 = ipv6_packet(8);
        bad_v6[4..6].copy_from_slice(&16u16.to_be_bytes());
        assert!(packet_len(&bad_v6).is_err());
    }

    #[test]
    fn packet_buffer_keeps_one_bounded_allocation() {
        let mut buffer = PacketBuffer::new(1500).unwrap();
        assert_eq!(buffer.len(), 1500);
        assert!(!buffer.is_empty());
        let address = buffer.data.as_ptr();
        buffer.data[0] = 0x45;
        assert_eq!(buffer.data.as_ptr(), address);
        assert!(PacketBuffer::new(100).is_err());
        assert!(PacketBuffer::new(65_536).is_err());
    }

    #[test]
    fn read_returns_raw_ip_without_a_prefix() {
        let packet = ipv4_packet(40);
        let io = FakeIo::with_reads(vec![packet.clone()]);
        let mut buffer = vec![0u8; 1500];
        let size = read_one(&io, &mut buffer, 1500).unwrap();
        assert_eq!(size, 40);
        assert_eq!(&buffer[..size], &packet[..]);
        assert_eq!(buffer[0], 0x45);
    }

    #[test]
    fn read_ignores_ipv4_trailing_bytes() {
        let mut packet = ipv4_packet(20);
        packet.extend_from_slice(&[0xff; 4]);
        let io = FakeIo::with_reads(vec![packet]);
        let mut buffer = vec![0u8; 1500];
        assert_eq!(read_one(&io, &mut buffer, 1500).unwrap(), 20);
    }

    #[test]
    fn read_rejects_empty_oversize_and_malformed_packets() {
        let io = FakeIo::default();
        let mut buffer = vec![0u8; 2048];
        assert_eq!(
            read_one(&io, &mut buffer, 1500).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let io = FakeIo::with_reads(vec![ipv4_packet(1501)]);
        let mut buffer = vec![0u8; 2048];
        assert_eq!(
            read_one(&io, &mut buffer, 1500).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let io = FakeIo::with_reads(vec![vec![0x45; 20]]);
        let mut buffer = vec![0u8; 2048];
        assert_eq!(
            read_one(&io, &mut buffer, 1500).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn read_propagates_would_block() {
        let io = FakeIo::default();
        *io.read_error.lock().unwrap() = Some(io::ErrorKind::WouldBlock);
        let mut buffer = vec![0u8; 1500];
        assert_eq!(
            read_one(&io, &mut buffer, 1500).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn write_sends_raw_ip_and_rejects_bad_packets() {
        let io = FakeIo::default();
        let packet = ipv4_packet(40);
        assert_eq!(write_one(&io, &packet, 1500).unwrap(), 40);
        assert_eq!(*io.writes.lock().unwrap(), vec![packet.clone()]);

        assert_eq!(
            write_one(&io, &[], 1500).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            write_one(&io, &ipv4_packet(1501), 1500).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            write_one(&io, &[0x10], 1500).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut trailing = ipv4_packet(20);
        trailing.push(0);
        assert_eq!(
            write_one(&io, &trailing, 1500).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(io.writes.lock().unwrap().len(), 1);
    }

    #[test]
    fn write_reports_a_partial_write_and_propagates_would_block() {
        let io = FakeIo::default();
        *io.write_return.lock().unwrap() = Some(3);
        let error = write_one(&io, &ipv4_packet(20), 1500).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);

        let io = FakeIo::default();
        *io.write_error.lock().unwrap() = Some(io::ErrorKind::WouldBlock);
        let error = write_one(&io, &ipv4_packet(20), 1500).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    /// Exercise the real descriptor path with a Unix datagram socket pair.
    /// This is a fake packet source. It creates no TUN device.
    #[test]
    fn fd_io_round_trips_raw_ip_without_a_prefix() {
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        let device = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let packet = ipv4_packet(20);

        assert_eq!(
            write_one(&FdIo(device.as_raw_fd()), &packet, 1500).unwrap(),
            20
        );
        let mut received = [0u8; 64];
        let size = unsafe {
            libc::recv(
                peer.as_raw_fd(),
                received.as_mut_ptr().cast(),
                received.len(),
                0,
            )
        };
        assert_eq!(size, 20);
        assert_eq!(&received[..20], &packet[..]);

        let sent = unsafe { libc::send(peer.as_raw_fd(), packet.as_ptr().cast(), packet.len(), 0) };
        assert_eq!(sent, 20);
        let mut buffer = vec![0u8; 1500];
        assert_eq!(
            read_one(&FdIo(device.as_raw_fd()), &mut buffer, 1500).unwrap(),
            20
        );
        assert_eq!(&buffer[..20], &packet[..]);
    }

    #[test]
    fn wait_readable_reports_timeout_and_packet_without_a_tun() {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) },
            0
        );
        let device = Tun {
            fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            ifname: "hs-tun0".into(),
            ifindex: 7,
            mtu: 1500,
            token: Arc::new(TunToken),
        };
        let peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        assert!(!device.wait_readable(Duration::ZERO).unwrap());
        let packet = ipv4_packet(20);
        assert_eq!(
            unsafe { libc::send(peer.as_raw_fd(), packet.as_ptr().cast(), packet.len(), 0) },
            20
        );
        assert!(device.wait_readable(Duration::ZERO).unwrap());
        let mut buffer = PacketBuffer::new(1500).unwrap();
        assert_eq!(device.read_packet(&mut buffer).unwrap(), packet);
        assert!(!device.wait_readable(Duration::ZERO).unwrap());
    }

    #[test]
    fn open_rejects_bad_input_before_the_device() {
        for name in ["", ".", "a/b", "a b"] {
            let error = Tun::open(name, 1500).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        for mtu in [0, 100, 65_536] {
            let error = Tun::open("hs-tun0", mtu).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn install_and_cleanup_use_the_dedicated_table_and_rules() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let observer = FakeObserver::in_table(TUNNEL_TABLE);
        let proof = routes.verify_interface_with(&tun, &observer).unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        assert_eq!(routes.table_id(), TUNNEL_TABLE);
        assert!(routes.has_installed_routes());
        assert_eq!(
            control.calls(),
            vec![
                "read-routes 2 700",
                "read-routes 10 700",
                "read-rules 2",
                "read-rules 10",
                "add-rule 17000",
                "add-rule 17001",
                "add-rule 17000",
                "add-rule 17001",
                "add-route 0.0.0.0/1",
                "add-route 128.0.0.0/1",
                "add-route 2000::/3",
            ]
        );
        let rules = control.rule_keys();
        assert_eq!(rules.len(), 4);
        assert_eq!(
            rules[0],
            RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME)
        );
        assert_eq!(rules[1], RuleKey::tunnel(libc::AF_INET as u8));
        assert_eq!(
            rules[2],
            RuleKey::outer(libc::AF_INET6 as u8, TEST_OUTER_IFNAME)
        );
        assert_eq!(rules[3], RuleKey::tunnel(libc::AF_INET6 as u8));
        assert_eq!(rules[0].table, RT_TABLE_MAIN);
        assert_eq!(rules[1].table, TUNNEL_TABLE);
        let keys = control.route_keys();
        assert_eq!(keys.len(), 3);
        assert!(keys
            .iter()
            .all(|key| key.table == TUNNEL_TABLE && key.protocol == ROUTE_PROTOCOL_ID));
        assert_eq!(keys[0], RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX));
        assert_eq!(keys[1], RouteKey::ipv4(IPV4_SECOND_HALF, TEST_IFINDEX));
        assert_eq!(keys[2], RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX));

        let ipv4 = routes
            .verify_ipv4_with(&test_identity(), &observer)
            .unwrap();
        assert_eq!(ipv4.first_half.table, TUNNEL_TABLE);
        assert_eq!(ipv4.probes_checked, DEFAULT_IPV4_PROBES.len());
        let outer = routes
            .outer_pin_from_link(&test_outer_link(), TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME)
            .unwrap();
        let ipv6_observer = FakeIpv6Observer::in_table(TUNNEL_TABLE);
        let ipv6 = routes
            .verify_ipv6_forward_with(&test_identity(), &outer, &ipv6_observer)
            .unwrap();
        assert_eq!(ipv6.table, TUNNEL_TABLE);
        assert_eq!(ipv6.ifindex, TEST_IFINDEX);

        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
        assert_eq!(control.route_count(), 0);
        assert_eq!(control.rule_count(), 0);
        let deletes: Vec<String> = control
            .calls()
            .into_iter()
            .filter(|call| call.starts_with("delete-"))
            .collect();
        assert_eq!(
            deletes,
            vec![
                "delete-route 2000::/3",
                "delete-route 128.0.0.0/1",
                "delete-route 0.0.0.0/1",
                "delete-rule 17001",
                "delete-rule 17000",
                "delete-rule 17001",
                "delete-rule 17000",
            ]
        );
        let calls = control.calls().len();
        routes.remove().unwrap();
        assert_eq!(control.calls().len(), calls, "stop is idempotent");
    }

    #[test]
    fn install_refuses_a_non_empty_dedicated_table() {
        let control = Arc::new(FakeControl::default());
        control.put_route(RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX));
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        let error = routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap_err();
        assert!(error.to_string().contains("not empty"));
        assert!(!routes.has_installed_routes());
        assert!(control.calls().iter().all(|call| !call.starts_with("add-")));
    }

    #[test]
    fn install_refuses_a_used_rule_priority() {
        let control = Arc::new(FakeControl::default());
        control.put_rule(RuleKey::outer(libc::AF_INET as u8, "wlan9"));
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        let error = routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap_err();
        assert!(error.to_string().contains("priority"));
        assert!(!routes.has_installed_routes());
        assert!(control.calls().iter().all(|call| !call.starts_with("add-")));
    }

    #[test]
    fn install_failure_rolls_back_the_accepted_objects() {
        let control = Arc::new(FakeControl::default());
        // The first four calls read the table and the rules. Calls four to
        // seven add the four rules. Call eight adds the first route.
        control.fail_call(8);
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        let error = routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap_err();
        assert!(error.to_string().contains("injected failure"));
        assert!(!routes.has_installed_routes());
        assert_eq!(control.route_count(), 0);
        assert_eq!(control.rule_count(), 0);
        assert!(control
            .calls()
            .iter()
            .any(|call| call.starts_with("delete-rule")));
    }

    #[test]
    fn cleanup_leaves_a_foreign_route_and_keeps_its_record() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        control.clear_objects();
        let key = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
        control.put_foreign_route(key.clone());
        let error = routes.remove().unwrap_err();
        assert!(error.to_string().contains("not the recorded object"));
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 1);
        assert_eq!(control.rule_count(), 0);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-route {}", describe_prefix(&key))));
    }

    #[test]
    fn cleanup_leaves_a_rule_with_an_unproven_selector() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        control.put_rule(RuleKey::tunnel(libc::AF_INET as u8));
        let error = routes.remove().unwrap_err();
        assert!(error.to_string().contains("not the recorded object"));
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 0);
        // The second IPv4 tunnel rule is not provable. Every other rule and
        // route is removed.
        assert_eq!(control.rule_count(), 2);
    }

    #[test]
    fn cleanup_leaves_a_rule_with_a_foreign_selector() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        control.clear_objects();
        let mut rule = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
        rule.iifname = Some("eth0".into());
        rule.uid_range = Some((1000, 1000));
        rule.l3mdev = Some(1);
        control.put_rule(rule);
        let error = routes.remove().unwrap_err();
        assert!(error.to_string().contains("not the recorded object"));
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 0);
        assert_eq!(control.rule_count(), 1);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == "delete-rule 17000"));
    }

    #[test]
    fn cleanup_leaves_a_route_with_a_foreign_metric_or_source() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        control.clear_objects();
        let mut key = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
        key.metric = Some(5);
        key.prefsrc = Some(vec![10, 0, 0, 1]);
        key.flow = Some(7);
        control.put_route(key.clone());
        let error = routes.remove().unwrap_err();
        assert!(error.to_string().contains("not the recorded object"));
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 1);
        assert_eq!(control.rule_count(), 0);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-route {}", describe_prefix(&key))));
    }

    #[test]
    fn install_timeout_after_apply_rolls_back_the_rule() {
        let control = Arc::new(FakeControl::default());
        // Calls zero to three read the table and rules. Call four adds the
        // first rule. The fake applies the rule and then reports a timeout.
        control.timeout_call(4, true);
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        let error = routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!routes.has_installed_routes());
        assert_eq!(control.rule_count(), 0);
        assert_eq!(control.route_count(), 0);
        assert!(control
            .calls()
            .iter()
            .any(|call| call == "delete-rule 17000"));
    }

    #[test]
    fn install_timeout_without_apply_drops_the_rule_record() {
        let control = Arc::new(FakeControl::default());
        control.timeout_call(4, false);
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        let error = routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!routes.has_installed_routes());
        assert_eq!(control.rule_count(), 0);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call.starts_with("delete-")));
    }

    #[test]
    fn install_route_timeout_after_apply_rolls_back_every_object() {
        let control = Arc::new(FakeControl::default());
        // The first route add is call eight, after four rules.
        control.timeout_call(8, true);
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        let error = routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!routes.has_installed_routes());
        assert_eq!(control.rule_count(), 0);
        assert_eq!(control.route_count(), 0);
        assert!(control
            .calls()
            .iter()
            .any(|call| call == "delete-route 0.0.0.0/1"));
    }

    #[test]
    fn cleanup_treats_an_absent_object_as_clean() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        control.clear_objects();
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
        assert!(!control
            .calls()
            .iter()
            .any(|call| call.starts_with("delete-")));
    }

    #[test]
    fn cleanup_read_failure_keeps_every_record() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        control.fail_reads();
        let error = routes.remove().unwrap_err();
        assert!(error.to_string().contains("cannot prove"));
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 3);
        assert_eq!(control.rule_count(), 4);
        control.allow_reads();
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
        assert_eq!(control.route_count(), 0);
        assert_eq!(control.rule_count(), 0);
    }

    #[test]
    fn block_policy_installs_one_blackhole_in_the_dedicated_table() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Block, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        let keys = control.route_keys();
        assert_eq!(keys.len(), 3);
        let v6 = keys
            .iter()
            .find(|key| key.family == libc::AF_INET6 as u8)
            .unwrap();
        assert_eq!(v6.route_type, RTN_BLACKHOLE);
        assert_eq!(v6.oif, None);
        assert_eq!(v6.table, TUNNEL_TABLE);
        assert!(keys
            .iter()
            .filter(|key| key.family == libc::AF_INET6 as u8)
            .all(|key| key.route_type == RTN_BLACKHOLE));
        let outer = routes
            .outer_pin_from_link(&test_outer_link(), TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME)
            .unwrap();
        assert_eq!(
            routes
                .verify_ipv6_forward_with(
                    &test_identity(),
                    &outer,
                    &FakeIpv6Observer::in_table(TUNNEL_TABLE)
                )
                .unwrap_err(),
            RouteVerifyError::Ipv6ForwardPolicyRequired
        );
        routes.remove().unwrap();
        assert_eq!(control.route_count(), 0);
        assert_eq!(control.rule_count(), 0);
    }

    #[test]
    fn inherit_policy_changes_nothing() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Inherit, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        let error = routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!routes.has_installed_routes());
        assert!(control.calls().is_empty());
    }

    #[test]
    fn install_rejects_the_tunnel_interface_as_the_outer_link() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        let tun = fake_tun();
        let proof = routes
            .verify_interface_with(&tun, &FakeObserver::good())
            .unwrap();
        let error = routes
            .install_verified(&proof, &tun, TEST_IFNAME)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(control.calls().is_empty());
    }

    #[test]
    fn recorded_routes_require_the_tunnel_table() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Block, control).unwrap();
        routes.install_for_test().unwrap();
        assert_eq!(
            routes
                .verify_ipv4_with(&test_identity(), &FakeObserver::good())
                .unwrap_err(),
            RouteVerifyError::UnexpectedTable {
                prefix: IPV4_FIRST_HALF,
                expected: TUNNEL_TABLE,
                actual: RT_TABLE_MAIN,
            }
        );
    }

    #[test]
    fn rule_messages_set_the_selector_and_the_delete_key() {
        let outer = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
        let message = encode_rule_change(7, &outer, false);
        assert_eq!(read_u16(&message[4..6]), RTM_NEWRULE);
        let flags = read_u16(&message[6..8]);
        assert_eq!(flags & NLM_F_CREATE, NLM_F_CREATE);
        assert_eq!(flags & NLM_F_EXCL, NLM_F_EXCL);
        assert_eq!(flags & NLM_F_ACK, NLM_F_ACK);
        assert_eq!(parse_rule_reply(&message).unwrap(), outer);
        let payload = &message[NLMSG_HDRLEN..];
        assert_eq!(payload[4], RT_TABLE_MAIN as u8);
        assert_eq!(payload[7], FR_ACT_TO_TBL);

        let tunnel = RuleKey::tunnel(libc::AF_INET6 as u8);
        let message = encode_rule_change(8, &tunnel, false);
        assert_eq!(parse_rule_reply(&message).unwrap(), tunnel);
        let payload = &message[NLMSG_HDRLEN..];
        assert_eq!(payload[4], 0, "a table above 255 uses the attribute");

        let message = encode_rule_change(9, &outer, true);
        assert_eq!(read_u16(&message[4..6]), RTM_DELRULE);
        let flags = read_u16(&message[6..8]);
        assert_eq!(flags & NLM_F_CREATE, 0);
        assert_eq!(flags & NLM_F_EXCL, 0);
        assert!(!message
            .windows(TEST_OUTER_IFNAME.len())
            .any(|window| window == TEST_OUTER_IFNAME.as_bytes()));
    }

    #[test]
    fn route_messages_set_the_table_protocol_and_scope() {
        let key = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
        let message = encode_route_change(11, &key, false);
        assert_eq!(read_u16(&message[4..6]), RTM_NEWROUTE);
        let flags = read_u16(&message[6..8]);
        assert_eq!(flags & NLM_F_CREATE, NLM_F_CREATE);
        assert_eq!(flags & NLM_F_EXCL, NLM_F_EXCL);
        let payload = &message[NLMSG_HDRLEN..];
        assert_eq!(payload[0], libc::AF_INET as u8);
        assert_eq!(payload[1], 1);
        assert_eq!(payload[4], 0);
        assert_eq!(payload[5], ROUTE_PROTOCOL_ID);
        assert_eq!(payload[6], RT_SCOPE_LINK);
        assert_eq!(payload[7], RTN_UNICAST);
        let mut table = None;
        let mut destination = None;
        let mut oif = None;
        visit_attrs(&payload[12..], |kind, value| {
            match kind {
                RTA_TABLE if value.len() == 4 => table = Some(read_u32(value)),
                RTA_DST => destination = Some(value.to_vec()),
                RTA_OIF if value.len() == 4 => oif = Some(read_u32(value)),
                _ => {}
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(table, Some(TUNNEL_TABLE));
        assert_eq!(destination, Some(vec![0, 0, 0, 0]));
        assert_eq!(oif, Some(TEST_IFINDEX));

        let message = encode_route_change(12, &key, true);
        assert_eq!(read_u16(&message[4..6]), RTM_DELROUTE);
        assert_eq!(read_u16(&message[6..8]) & NLM_F_EXCL, 0);

        let v6 = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
        let message = encode_route_change(13, &v6, false);
        let payload = &message[NLMSG_HDRLEN..];
        assert_eq!(payload[0], libc::AF_INET6 as u8);
        assert_eq!(payload[1], 3);
        assert_eq!(payload[7], RTN_BLACKHOLE);
        let mut oif = None;
        visit_attrs(&payload[12..], |kind, value| {
            if kind == RTA_OIF && value.len() == 4 {
                oif = Some(read_u32(value));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(oif, None, "a blackhole route names no device");
    }

    #[test]
    fn dump_requests_name_one_family() {
        let message = encode_route_dump(14, libc::AF_INET as u8);
        assert_eq!(read_u16(&message[4..6]), RTM_GETROUTE);
        assert_eq!(read_u16(&message[6..8]) & NLM_F_DUMP, NLM_F_DUMP);
        let payload = &message[NLMSG_HDRLEN..];
        assert_eq!(payload[0], libc::AF_INET as u8);
        let message = encode_rule_dump(15, libc::AF_INET6 as u8);
        assert_eq!(read_u16(&message[4..6]), RTM_GETRULE);
        assert_eq!(message[NLMSG_HDRLEN], libc::AF_INET6 as u8);
    }

    #[test]
    fn rule_reply_parser_defaults_a_zero_priority() {
        let spec = [
            libc::AF_INET as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            FR_ACT_TO_TBL,
            0,
            0,
            0,
            0,
        ];
        let mut message = test_netlink_message(RTM_NEWRULE, 18, &spec);
        push_attr(&mut message, FRA_TABLE, &255u32.to_ne_bytes());
        // The kernel includes `FRA_SUPPRESS_PREFIXLEN` with the unset value on
        // a normal rule. The parser normalizes that value to `None`.
        push_attr(
            &mut message,
            FRA_SUPPRESS_PREFIXLEN,
            &u32::MAX.to_ne_bytes(),
        );
        let length = message.len() as u32;
        write_u32(&mut message[0..4], length);
        let parsed = parse_rule_reply(&message).unwrap();
        assert_eq!(parsed.priority, 0);
        assert_eq!(parsed.table, 255);
        assert_eq!(parsed.action, FR_ACT_TO_TBL);
        assert_eq!(parsed.suppress_prefixlen, None);
    }

    #[test]
    fn rule_reply_parser_reads_every_selector() {
        let spec = [
            libc::AF_INET as u8,
            8,
            8,
            16,
            0,
            0,
            0,
            FR_ACT_TO_TBL,
            0,
            0,
            0,
            0,
        ];
        let mut message = test_netlink_message(RTM_NEWRULE, 19, &spec);
        push_attr(&mut message, FRA_DST, &[10, 0, 0, 0]);
        push_attr(&mut message, FRA_SRC, &[10, 0, 0, 1]);
        push_attr(&mut message, FRA_IIFNAME, b"eth0\0");
        push_attr(&mut message, FRA_GOTO, &2u32.to_ne_bytes());
        push_attr(
            &mut message,
            FRA_PRIORITY,
            &OUTER_RULE_PRIORITY.to_ne_bytes(),
        );
        push_attr(&mut message, FRA_PROTOCOL, &[10]);
        push_attr(&mut message, FRA_FWMARK, &1u32.to_ne_bytes());
        push_attr(&mut message, FRA_FWMASK, &0xffu32.to_ne_bytes());
        push_attr(&mut message, FRA_FLOW, &7u32.to_ne_bytes());
        push_attr(&mut message, FRA_TUN_ID, &2u64.to_be_bytes());
        push_attr(&mut message, FRA_SUPPRESS_IFGROUP, &4u32.to_ne_bytes());
        push_attr(&mut message, FRA_SUPPRESS_PREFIXLEN, &16u32.to_ne_bytes());
        push_attr(&mut message, FRA_TABLE, &TUNNEL_TABLE.to_ne_bytes());
        push_attr(&mut message, FRA_OIFNAME, b"wlan0\0");
        push_attr(&mut message, FRA_L3MDEV, &[1]);
        let mut uid_range = Vec::new();
        uid_range.extend_from_slice(&1000u32.to_ne_bytes());
        uid_range.extend_from_slice(&2000u32.to_ne_bytes());
        push_attr(&mut message, FRA_UID_RANGE, &uid_range);
        push_attr(&mut message, FRA_IP_PROTO, &[6]);
        let mut sport = Vec::new();
        sport.extend_from_slice(&1000u16.to_ne_bytes());
        sport.extend_from_slice(&2000u16.to_ne_bytes());
        push_attr(&mut message, FRA_SPORT_RANGE, &sport);
        let mut dport = Vec::new();
        dport.extend_from_slice(&80u16.to_ne_bytes());
        dport.extend_from_slice(&80u16.to_ne_bytes());
        push_attr(&mut message, FRA_DPORT_RANGE, &dport);
        push_attr(&mut message, FRA_SPORT_MASK, &0xff00u16.to_ne_bytes());
        push_attr(&mut message, FRA_DPORT_MASK, &0xffffu16.to_ne_bytes());
        push_attr(&mut message, FRA_DSCP, &[10]);
        push_attr(&mut message, FRA_DSCP_MASK, &[0x3f]);
        push_attr(&mut message, FRA_FLOWLABEL, &0x12345u32.to_be_bytes());
        push_attr(&mut message, FRA_FLOWLABEL_MASK, &0xfffffu32.to_be_bytes());
        push_attr(&mut message, FRA_PAD, &[]);
        let length = message.len() as u32;
        write_u32(&mut message[0..4], length);
        let parsed = parse_rule_reply(&message).unwrap();
        assert_eq!(parsed.family, libc::AF_INET as u8);
        assert_eq!(parsed.destination_length, 8);
        assert_eq!(parsed.destination, Some(vec![10, 0, 0, 0]));
        assert_eq!(parsed.source_length, 8);
        assert_eq!(parsed.source, Some(vec![10, 0, 0, 1]));
        assert_eq!(parsed.tos, 16);
        assert_eq!(parsed.table, TUNNEL_TABLE);
        assert_eq!(parsed.priority, OUTER_RULE_PRIORITY);
        assert_eq!(parsed.iifname.as_deref(), Some("eth0"));
        assert_eq!(parsed.oif.as_deref(), Some("wlan0"));
        assert_eq!(parsed.goto, Some(2));
        assert_eq!(parsed.protocol, 10);
        assert_eq!(parsed.fwmark, Some(1));
        assert_eq!(parsed.fwmask, Some(0xff));
        assert_eq!(parsed.flow, Some(7));
        assert_eq!(parsed.tun_id, Some(2));
        assert_eq!(parsed.suppress_ifgroup, Some(4));
        assert_eq!(parsed.suppress_prefixlen, Some(16));
        assert_eq!(parsed.l3mdev, Some(1));
        assert_eq!(parsed.uid_range, Some((1000, 2000)));
        assert_eq!(parsed.ip_proto, Some(6));
        assert_eq!(parsed.sport_range, Some((1000, 2000)));
        assert_eq!(parsed.dport_range, Some((80, 80)));
        assert_eq!(parsed.sport_mask, Some(0xff00));
        assert_eq!(parsed.dport_mask, Some(0xffff));
        assert_eq!(parsed.dscp, Some(10));
        assert_eq!(parsed.dscp_mask, Some(0x3f));
        assert_eq!(parsed.flowlabel, Some(0x12345));
        assert_eq!(parsed.flowlabel_mask, Some(0xfffff));
        assert!(!parsed.unexpected);
    }

    #[test]
    fn rule_reply_parser_marks_an_unknown_selector() {
        let spec = [
            libc::AF_INET as u8,
            0,
            0,
            0,
            RT_TABLE_MAIN as u8,
            0,
            0,
            FR_ACT_TO_TBL,
            0,
            0,
            0,
            0,
        ];
        let mut message = test_netlink_message(RTM_NEWRULE, 20, &spec);
        push_attr(
            &mut message,
            FRA_PRIORITY,
            &OUTER_RULE_PRIORITY.to_ne_bytes(),
        );
        // Attribute 31 is not a selector that this module knows.
        push_attr(&mut message, 31, &[0; 4]);
        let length = message.len() as u32;
        write_u32(&mut message[0..4], length);
        let parsed = parse_rule_reply(&message).unwrap();
        assert!(parsed.unexpected);
        assert!(!rule_is_recorded(
            &[parsed],
            &RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME)
        ));
    }

    #[test]
    fn rule_reply_parser_reads_native_selectors() {
        let rule = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
        let message = encode_rule_change(16, &rule, false);
        let parsed = parse_rule_reply(&message).unwrap();
        assert_eq!(parsed.priority, OUTER_RULE_PRIORITY);
        assert_eq!(parsed.table, RT_TABLE_MAIN);
        assert_eq!(parsed.oif.as_deref(), Some(TEST_OUTER_IFNAME));
        assert!(parsed.fwmark.is_none());
        assert_eq!(parsed.protocol, 0);
        assert_eq!(parsed.tos, 0);
        assert_eq!(parsed.suppress_prefixlen, None);
        let tunnel = RuleKey::tunnel(libc::AF_INET6 as u8);
        let message = encode_rule_change(17, &tunnel, false);
        let parsed = parse_rule_reply(&message).unwrap();
        assert_eq!(parsed.priority, TUNNEL_RULE_PRIORITY);
        assert_eq!(parsed.table, TUNNEL_TABLE);
        assert_eq!(parsed.oif, None);
        assert_eq!(parsed.action, FR_ACT_TO_TBL);
    }

    fn changed_rule(base: &RuleKey, change: impl FnOnce(&mut RuleKey)) -> RuleKey {
        let mut rule = base.clone();
        change(&mut rule);
        rule
    }

    #[test]
    fn rule_ownership_compares_every_selector() {
        let base = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
        assert!(rule_is_recorded(std::slice::from_ref(&base), &base));
        let variants = vec![
            (
                "family",
                changed_rule(&base, |r| r.family = libc::AF_INET6 as u8),
            ),
            (
                "destination_length",
                changed_rule(&base, |r| r.destination_length = 8),
            ),
            (
                "destination",
                changed_rule(&base, |r| r.destination = Some(vec![10, 0, 0, 0])),
            ),
            (
                "source_length",
                changed_rule(&base, |r| r.source_length = 8),
            ),
            (
                "source",
                changed_rule(&base, |r| r.source = Some(vec![10, 0, 0, 1])),
            ),
            ("tos", changed_rule(&base, |r| r.tos = 16)),
            ("table", changed_rule(&base, |r| r.table = TUNNEL_TABLE)),
            ("action", changed_rule(&base, |r| r.action = 2)),
            ("flags", changed_rule(&base, |r| r.flags = FIB_RULE_INVERT)),
            (
                "iifname",
                changed_rule(&base, |r| r.iifname = Some("eth0".into())),
            ),
            ("oif", changed_rule(&base, |r| r.oif = Some("eth0".into()))),
            ("goto", changed_rule(&base, |r| r.goto = Some(1))),
            ("protocol", changed_rule(&base, |r| r.protocol = 10)),
            ("fwmark", changed_rule(&base, |r| r.fwmark = Some(1))),
            ("fwmask", changed_rule(&base, |r| r.fwmask = Some(1))),
            ("flow", changed_rule(&base, |r| r.flow = Some(1))),
            ("tun_id", changed_rule(&base, |r| r.tun_id = Some(1))),
            (
                "suppress_ifgroup",
                changed_rule(&base, |r| r.suppress_ifgroup = Some(1)),
            ),
            (
                "suppress_prefixlen",
                changed_rule(&base, |r| r.suppress_prefixlen = Some(1)),
            ),
            ("l3mdev", changed_rule(&base, |r| r.l3mdev = Some(1))),
            (
                "uid_range",
                changed_rule(&base, |r| r.uid_range = Some((1000, 1000))),
            ),
            ("ip_proto", changed_rule(&base, |r| r.ip_proto = Some(6))),
            (
                "sport_range",
                changed_rule(&base, |r| r.sport_range = Some((1000, 2000))),
            ),
            (
                "dport_range",
                changed_rule(&base, |r| r.dport_range = Some((80, 80))),
            ),
            (
                "sport_mask",
                changed_rule(&base, |r| r.sport_mask = Some(0xff)),
            ),
            (
                "dport_mask",
                changed_rule(&base, |r| r.dport_mask = Some(0xff)),
            ),
            ("dscp", changed_rule(&base, |r| r.dscp = Some(1))),
            ("dscp_mask", changed_rule(&base, |r| r.dscp_mask = Some(1))),
            ("flowlabel", changed_rule(&base, |r| r.flowlabel = Some(1))),
            (
                "flowlabel_mask",
                changed_rule(&base, |r| r.flowlabel_mask = Some(1)),
            ),
            ("unexpected", changed_rule(&base, |r| r.unexpected = true)),
        ];
        for (label, rule) in variants {
            assert!(
                !rule_is_recorded(std::slice::from_ref(&rule), &base),
                "the ownership check accepted a rule with a different {label}"
            );
        }
    }

    #[test]
    fn route_ownership_compares_every_selector() {
        let key = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
        let clean = ObservedRouteKey {
            key: key.clone(),
            gateway: false,
            multipath: false,
            encap: false,
            nexthop: false,
        };
        assert!(route_is_recorded(std::slice::from_ref(&clean), &key));

        let mut variants = Vec::new();
        let mut changed = key.clone();
        changed.metric = Some(5);
        variants.push(("metric", changed));
        let mut changed = key.clone();
        changed.prefsrc = Some(vec![10, 0, 0, 1]);
        variants.push(("preferred source", changed));
        let mut changed = key.clone();
        changed.flow = Some(7);
        variants.push(("flow", changed));
        let mut changed = key.clone();
        changed.source_length = 8;
        changed.source = Some(vec![10, 0, 0, 0]);
        variants.push(("source", changed));
        let mut changed = key.clone();
        changed.tos = 16;
        variants.push(("TOS", changed));
        for (label, changed) in variants {
            let observed = ObservedRouteKey {
                key: changed,
                ..clean.clone()
            };
            assert!(
                !route_is_recorded(&[observed], &key),
                "the ownership check accepted a route with a different {label}"
            );
        }

        let mut busy = clean.clone();
        busy.gateway = true;
        assert!(!route_is_recorded(&[busy], &key));

        let v6 = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
        let mut v6_observed = ObservedRouteKey {
            key: v6.clone(),
            gateway: false,
            multipath: false,
            encap: false,
            nexthop: false,
        };
        assert!(route_is_recorded(&[v6_observed.clone()], &v6));
        let mut changed_v6 = v6.clone();
        changed_v6.source_length = 64;
        changed_v6.source = Some("2001:db8::".parse::<Ipv6Addr>().unwrap().octets().to_vec());
        v6_observed.key = changed_v6;
        assert!(!route_is_recorded(&[v6_observed], &v6));
        let mut duplicate = clean.clone();
        duplicate.key.metric = Some(5);
        assert!(!route_is_recorded(&[clean, duplicate], &key));
    }

    #[test]
    fn block_policy_passes_the_full_start_gate() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Block, control.clone()).unwrap();
        let tun = fake_tun();
        let observer = FakeObserver::in_table(TUNNEL_TABLE);
        let proof = routes.verify_interface_with(&tun, &observer).unwrap();
        assert_eq!(proof.ifname(), TEST_IFNAME);
        assert_eq!(proof.ifindex(), TEST_IFINDEX);
        assert_eq!(routes.ipv6_policy(), Ipv6Policy::Block);
        {
            let calls = observer.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert!(calls[0].is_empty());
        }
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        let block_observer = FakeIpv6BlockObserver::good();
        let verified = routes
            .verify_with(&test_identity(), &observer, &block_observer)
            .unwrap();
        assert_eq!(verified.ipv6(), None);
        let block = verified.ipv6_block().expect("block proof");
        assert_eq!(block.prefix, IPV6_GLOBAL_UNICAST);
        assert_eq!(block.table, TUNNEL_TABLE);
        assert_eq!(block.protocol, ROUTE_PROTOCOL_ID);
        assert_eq!(block.probes_checked, DEFAULT_IPV6_PROBES.len());
        assert_eq!(block_observer.call_count(), 1);
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn block_start_gate_refuses_a_missing_route_or_a_bypass() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Block, control).unwrap();
        let tun = fake_tun();
        let observer = FakeObserver::in_table(TUNNEL_TABLE);
        let proof = routes.verify_interface_with(&tun, &observer).unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        let mut missing = good_ipv6_block_observation();
        missing.route_recorded = false;
        assert_eq!(
            routes
                .verify_with(
                    &test_identity(),
                    &observer,
                    &FakeIpv6BlockObserver::from_observation(missing)
                )
                .unwrap_err(),
            RouteVerifyError::Ipv6BlockNotRecorded
        );
        let mut bypass = good_ipv6_block_observation();
        bypass.probes[1].blocked = false;
        assert_eq!(
            routes
                .verify_with(
                    &test_identity(),
                    &observer,
                    &FakeIpv6BlockObserver::from_observation(bypass)
                )
                .unwrap_err(),
            RouteVerifyError::Ipv6BlockBypass {
                destination: DEFAULT_IPV6_PROBES[1],
            }
        );
        let mut missing_probe = good_ipv6_block_observation();
        missing_probe
            .probes
            .retain(|probe| probe.destination != DEFAULT_IPV6_PROBES[2]);
        assert_eq!(
            routes
                .verify_with(
                    &test_identity(),
                    &observer,
                    &FakeIpv6BlockObserver::from_observation(missing_probe)
                )
                .unwrap_err(),
            RouteVerifyError::MissingIpv6Probe {
                destination: DEFAULT_IPV6_PROBES[2],
            }
        );
        routes.remove().unwrap();
    }

    #[test]
    fn blackhole_route_key_ignores_the_loopback_output_interface() {
        let key = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
        let mut observed = ObservedRouteKey {
            key: key.clone(),
            gateway: false,
            multipath: false,
            encap: false,
            nexthop: false,
        };
        observed.key.oif = Some(1);
        assert!(route_is_recorded(&[observed], &key));
        let mut other = ObservedRouteKey {
            key: key.clone(),
            gateway: false,
            multipath: false,
            encap: false,
            nexthop: false,
        };
        other.key.route_type = RTN_UNICAST;
        other.key.oif = Some(1);
        assert!(!route_is_recorded(&[other], &key));
    }

    #[test]
    fn inherit_policy_is_inert_until_verified() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Inherit, control.clone()).unwrap();
        let tun = fake_tun();
        let observer = FakeObserver::good();
        let proof = routes.verify_interface_with(&tun, &observer).unwrap();
        assert_eq!(routes.ipv6_policy(), Ipv6Policy::Inherit);
        let error = routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!routes.has_installed_routes());
        assert!(control.calls().is_empty());
        assert_eq!(
            routes
                .verify_with(&test_identity(), &observer, &FakeIpv6BlockObserver::good())
                .unwrap_err(),
            RouteVerifyError::Ipv6InheritNotAllowed
        );
        assert_eq!(observer.call_count(), 1);
    }

    #[test]
    fn forward_policy_is_distinct_and_installs_the_start_routes() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        assert_eq!(routes.ipv6_policy(), Ipv6Policy::Forward);
        assert_ne!(Ipv6Policy::Block, Ipv6Policy::Forward);
        assert_ne!(Ipv6Policy::Forward, Ipv6Policy::Inherit);
        assert_ne!(Ipv6Policy::Block, Ipv6Policy::Inherit);
        let tun = fake_tun();
        let observer = FakeObserver::in_table(TUNNEL_TABLE);
        let proof = routes.verify_interface_with(&tun, &observer).unwrap();
        routes
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        assert_eq!(control.route_count(), 3);
        assert_eq!(control.rule_count(), 4);
        // The full verification has no outer proof. The IPv4 check passes and
        // the IPv6 forward policy stays unproven.
        assert_eq!(
            routes
                .verify_with(&test_identity(), &observer, &FakeIpv6BlockObserver::good())
                .unwrap_err(),
            RouteVerifyError::Ipv6ForwardUnverified
        );
        let outer = routes
            .outer_pin_from_link(&test_outer_link(), TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME)
            .unwrap();
        assert!(routes
            .verify_ipv6_forward_with(
                &test_identity(),
                &outer,
                &FakeIpv6Observer::in_table(TUNNEL_TABLE)
            )
            .is_ok());
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn interface_proof_binds_to_the_manager_and_link() {
        let fake = Arc::new(FakeRunner::default());
        let mut first =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        let mut second =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        let tun = fake_tun();
        let observer = FakeObserver::good();
        let proof = first.verify_interface_with(&tun, &observer).unwrap();
        let other = fake_tun_named(TEST_IFINDEX, "hs-tun1");
        let wrong_link = LinkGuard::install(&proof, &other, "198.18.0.5".parse().unwrap(), 1500);
        assert!(
            matches!(wrong_link, Err(ref error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            second
                .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(fake.calls.lock().unwrap().is_empty());
        first
            .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
            .unwrap();
        assert!(first.has_installed_routes());
        assert!(!second.has_installed_routes());
        first.remove().unwrap();
    }

    #[test]
    fn stale_interface_proof_is_refused() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        let tun = fake_tun();
        let observer = FakeObserver::good();
        let proof = routes.verify_interface_with(&tun, &observer).unwrap();
        drop(tun);
        let replacement = fake_tun();
        assert!(!proof.is_for_tun(&replacement));
        assert_eq!(
            routes
                .install_verified(&proof, &replacement, TEST_OUTER_IFNAME)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            routes.verify_ipv4(&proof, &replacement),
            Err(RouteVerifyError::InvalidTunnelIdentity(_))
        ));
        assert!(matches!(
            routes.verify(&proof, &replacement),
            Err(RouteVerifyError::InvalidTunnelIdentity(_))
        ));
        let error = LinkGuard::install(&proof, &replacement, "198.18.0.5".parse().unwrap(), 1500)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn same_name_and_index_replacement_is_refused() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        let original = fake_tun();
        let replacement = fake_tun();
        assert_eq!(original.ifname(), replacement.ifname());
        assert_eq!(original.ifindex(), replacement.ifindex());
        assert!(!Arc::ptr_eq(&original.token, &replacement.token));
        let observer = FakeObserver::good();
        let proof = routes.verify_interface_with(&original, &observer).unwrap();
        assert!(proof.is_for_tun(&original));
        assert!(!proof.is_for_tun(&replacement));
        assert_eq!(
            routes
                .install_verified(&proof, &replacement, TEST_OUTER_IFNAME)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            routes.verify_ipv4(&proof, &replacement),
            Err(RouteVerifyError::InvalidTunnelIdentity(_))
        ));
        assert!(matches!(
            routes.verify(&proof, &replacement),
            Err(RouteVerifyError::InvalidTunnelIdentity(_))
        ));
        assert_eq!(
            LinkGuard::install(&proof, &replacement, "198.18.0.5".parse().unwrap(), 1500)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        routes
            .install_verified(&proof, &original, TEST_OUTER_IFNAME)
            .unwrap();
        assert!(routes.has_installed_routes());
        routes.remove().unwrap();
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn ipv4_verification_proves_both_halves() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        routes.install_for_test().unwrap();
        let observer = FakeObserver::in_table(TUNNEL_TABLE);
        let proof = routes
            .verify_ipv4_with(&test_identity(), &observer)
            .unwrap();
        assert_eq!(proof.ifindex, TEST_IFINDEX);
        assert_eq!(proof.ifname, TEST_IFNAME);
        assert_eq!(proof.first_half.prefix, IPV4_FIRST_HALF);
        assert_eq!(proof.second_half.prefix, IPV4_SECOND_HALF);
        assert_eq!(proof.first_half.table, TUNNEL_TABLE);
        assert_eq!(proof.first_half.protocol, ROUTE_PROTOCOL_ID);
        assert_eq!(proof.probes_checked, DEFAULT_IPV4_PROBES.len());
        {
            let calls = observer.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0], DEFAULT_IPV4_PROBES.to_vec());
        }
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
        assert_eq!(fake.calls.lock().unwrap().len(), 0);
    }

    #[test]
    fn ipv4_verification_requires_both_recorded_routes() {
        let fake = Arc::new(FakeRunner::default());
        let routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        let observer = FakeObserver::good();
        assert_eq!(
            routes
                .verify_ipv4_with(&test_identity(), &observer)
                .unwrap_err(),
            RouteVerifyError::NotInstalled
        );
        assert_eq!(observer.call_count(), 0);
    }

    #[test]
    fn ipv4_verification_requires_every_policy_probe() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        routes.install_for_test().unwrap();
        let mut observation = good_observation_in(TUNNEL_TABLE);
        observation.probes = vec![
            test_probe(DEFAULT_IPV4_PROBES[0]),
            test_probe(DEFAULT_IPV4_PROBES[3]),
        ];
        for probe in &mut observation.probes {
            probe.route.table = TUNNEL_TABLE;
        }
        let observer = FakeObserver::from_observation(observation);
        let error = routes
            .verify_ipv4_with(&test_identity(), &observer)
            .unwrap_err();
        assert!(matches!(error, RouteVerifyError::MissingProbe { .. }));
        assert!(error.is_inconclusive());
        routes.routes.clear();
    }

    #[test]
    fn verification_distinguishes_unknown_from_route_failure() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        routes.install_for_test().unwrap();
        let unknown = FakeObserver::failing(RouteVerifyError::Unavailable {
            operation: "test",
            errno: libc::ETIMEDOUT,
        });
        let error = routes
            .verify_ipv4_with(&test_identity(), &unknown)
            .unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::Unavailable {
                operation: "test",
                errno: libc::ETIMEDOUT,
            }
        );
        assert!(error.is_inconclusive());
        let failure = FakeObserver::failing(RouteVerifyError::NoRoute {
            destination: DEFAULT_IPV4_PROBES[0],
        });
        let error = routes
            .verify_ipv4_with(&test_identity(), &failure)
            .unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::NoRoute {
                destination: DEFAULT_IPV4_PROBES[0],
            }
        );
        assert!(!error.is_inconclusive());
        assert!(!RouteVerifyError::LinkMissing {
            ifindex: TEST_IFINDEX
        }
        .is_inconclusive());
        assert!(RouteVerifyError::MalformedReply("test").is_inconclusive());
        assert!(RouteVerifyError::MissingIpv6Probe {
            destination: DEFAULT_IPV6_PROBES[0],
        }
        .is_inconclusive());
        assert!(!RouteVerifyError::NoIpv6Route {
            destination: DEFAULT_IPV6_PROBES[0],
        }
        .is_inconclusive());
        routes.routes.clear();
    }

    #[test]
    fn full_block_verification_returns_a_proof() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        routes.install_for_test().unwrap();
        let observer = FakeObserver::in_table(TUNNEL_TABLE);
        let block_observer = FakeIpv6BlockObserver::good();
        let verified = routes
            .verify_with(&test_identity(), &observer, &block_observer)
            .unwrap();
        assert_eq!(verified.ipv6(), None);
        assert_eq!(
            verified.ipv6_block().map(|block| block.probes_checked),
            Some(DEFAULT_IPV6_PROBES.len())
        );
        assert_eq!(observer.call_count(), 1);
        {
            let calls = observer.calls.lock().unwrap();
            assert_eq!(calls[0], DEFAULT_IPV4_PROBES.to_vec());
        }
        assert_eq!(block_observer.call_count(), 1);
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn full_block_verification_propagates_an_unknown_result() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        routes.install_for_test().unwrap();
        let observer = FakeObserver::in_table(TUNNEL_TABLE);
        let block_observer = FakeIpv6BlockObserver::failing(RouteVerifyError::Unavailable {
            operation: "test",
            errno: libc::ETIMEDOUT,
        });
        let error = routes
            .verify_with(&test_identity(), &observer, &block_observer)
            .unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::Unavailable {
                operation: "test",
                errno: libc::ETIMEDOUT,
            }
        );
        assert!(error.is_inconclusive());
        routes.remove().unwrap();
    }

    #[test]
    fn full_inherit_verification_does_not_probe() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Inherit, test_ip(), fake.clone())
                .unwrap();
        routes.install_for_test().unwrap();
        let observer = FakeObserver::good();
        assert_eq!(
            routes
                .verify_with(&test_identity(), &observer, &FakeIpv6BlockObserver::good())
                .unwrap_err(),
            RouteVerifyError::Ipv6InheritNotAllowed
        );
        assert_eq!(observer.call_count(), 0);
        routes.routes.clear();
    }

    #[test]
    fn ipv6_forward_verification_returns_a_proof() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Forward, test_ip(), fake).unwrap();
        routes.install_for_test().unwrap();
        let outer = routes
            .outer_pin_from_link(&test_outer_link(), TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME)
            .unwrap();
        assert_eq!(outer.ifname(), TEST_OUTER_IFNAME);
        assert_eq!(outer.ifindex(), TEST_OUTER_IFINDEX);
        let observer = FakeIpv6Observer::in_table(TUNNEL_TABLE);
        let proof = routes
            .verify_ipv6_forward_with(&test_identity(), &outer, &observer)
            .unwrap();
        assert_eq!(proof.prefix, IPV6_GLOBAL_UNICAST);
        assert_eq!(proof.table, TUNNEL_TABLE);
        assert_eq!(proof.ifindex, TEST_IFINDEX);
        assert_eq!(proof.outer_ifindex, TEST_OUTER_IFINDEX);
        assert_eq!(proof.probes_checked, DEFAULT_IPV6_PROBES.len());
        assert_eq!(observer.call_count(), 1);
        {
            let calls = observer.calls.lock().unwrap();
            assert_eq!(calls[0].0, TEST_IFINDEX);
            assert_eq!(calls[0].1, TEST_OUTER_IFINDEX);
            assert_eq!(calls[0].2, DEFAULT_IPV6_PROBES.to_vec());
        }
        // The scoped check uses the recorded route. It installs no rule.
        assert!(routes.has_installed_routes());
        routes.routes.clear();
    }

    #[test]
    fn ipv6_forward_verification_requires_every_policy_probe() {
        let fake = Arc::new(FakeRunner::default());
        let mut routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Forward, test_ip(), fake).unwrap();
        routes.install_for_test().unwrap();
        let outer = routes
            .outer_pin_from_link(&test_outer_link(), TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME)
            .unwrap();
        let mut observation = good_ipv6_observation_in(TUNNEL_TABLE);
        observation
            .probes
            .retain(|probe| probe.destination != DEFAULT_IPV6_PROBES[1]);
        let observer = FakeIpv6Observer::from_observation(observation);
        assert_eq!(
            routes
                .verify_ipv6_forward_with(&test_identity(), &outer, &observer)
                .unwrap_err(),
            RouteVerifyError::MissingIpv6Probe {
                destination: DEFAULT_IPV6_PROBES[1],
            }
        );
        assert_eq!(observer.call_count(), 1);
        routes.routes.clear();
    }

    #[test]
    fn ipv6_forward_verification_is_inert_for_other_policies() {
        for (policy, expected) in [
            (
                Ipv6Policy::Block,
                RouteVerifyError::Ipv6ForwardPolicyRequired,
            ),
            (Ipv6Policy::Inherit, RouteVerifyError::Ipv6InheritNotAllowed),
        ] {
            let fake = Arc::new(FakeRunner::default());
            let routes = RouteManager::with_runner(TEST_IFNAME, policy, test_ip(), fake).unwrap();
            let outer = routes
                .outer_pin_from_link(&test_outer_link(), TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME)
                .unwrap();
            let observer = FakeIpv6Observer::good();
            assert_eq!(
                routes
                    .verify_ipv6_forward_with(&test_identity(), &outer, &observer)
                    .unwrap_err(),
                expected
            );
            assert_eq!(observer.call_count(), 0);
        }
    }

    #[test]
    fn ipv6_forward_verification_binds_the_outer_proof() {
        let fake = Arc::new(FakeRunner::default());
        let first =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Forward, test_ip(), fake.clone())
                .unwrap();
        let mut second =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Forward, test_ip(), fake).unwrap();
        second.install_for_test().unwrap();
        let outer = first
            .outer_pin_from_link(&test_outer_link(), TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME)
            .unwrap();
        let observer = FakeIpv6Observer::good();
        assert!(matches!(
            second
                .verify_ipv6_forward_with(&test_identity(), &outer, &observer)
                .unwrap_err(),
            RouteVerifyError::InvalidOuterInterface(_)
        ));
        assert_eq!(observer.call_count(), 0);
        second.routes.clear();
    }

    #[test]
    fn outer_pin_rejects_non_physical_links() {
        let fake = Arc::new(FakeRunner::default());
        let routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Forward, test_ip(), fake).unwrap();
        assert!(routes
            .outer_pin_from_link(&test_outer_link(), TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME)
            .is_ok());

        for mutate in 0..7 {
            let mut link = test_outer_link();
            match mutate {
                0 => link.flags = 0,
                1 => link.flags = IFF_UP | IFF_LOOPBACK,
                2 => link.hardware_type = ARPHRD_NONE,
                3 => link.kind = Some("tun".to_owned()),
                4 => link.kind = Some("tap".to_owned()),
                5 => link.kind = Some("wireguard".to_owned()),
                _ => link.ifindex = TEST_OUTER_IFINDEX + 1,
            }
            assert!(matches!(
                routes.outer_pin_from_link(&link, TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME),
                Err(RouteVerifyError::OuterLinkMismatch(_))
            ));
        }

        let mut link = test_outer_link();
        link.name = "wlan1".to_owned();
        assert!(matches!(
            routes.outer_pin_from_link(&link, TEST_OUTER_IFINDEX, TEST_OUTER_IFNAME),
            Err(RouteVerifyError::OuterLinkMismatch(_))
        ));
    }

    #[test]
    fn interface_proof_allows_a_link_that_is_not_up_yet() {
        let fake = Arc::new(FakeRunner::default());
        let routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        let tun = fake_tun();
        let mut observation = good_observation();
        observation.link.flags = 0;
        let observer = FakeObserver::from_observation(observation.clone());
        let proof = routes.verify_interface_with(&tun, &observer).unwrap();
        assert_eq!(proof.ifname(), TEST_IFNAME);
        assert_eq!(proof.ifindex(), TEST_IFINDEX);
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::LinkMismatch(_)
        ));
    }

    #[test]
    fn verification_rejects_another_interface_identity() {
        let fake = Arc::new(FakeRunner::default());
        let routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        let other = TunnelIdentity::new(TEST_IFINDEX, "hs-tun1").unwrap();
        let observer = FakeObserver::good();
        assert!(matches!(
            routes.verify_ipv4_with(&other, &observer).unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity(_)
        ));
        assert!(matches!(
            routes
                .verify_with(&other, &observer, &FakeIpv6BlockObserver::good())
                .unwrap_err(),
            RouteVerifyError::InvalidTunnelIdentity(_)
        ));
        assert_eq!(observer.call_count(), 0);
    }

    #[test]
    fn ipv4_selection_accepts_both_halves() {
        let proof = verify_ipv4_selection(&good_observation(), &test_identity()).unwrap();
        assert_eq!(proof.ifindex, TEST_IFINDEX);
        assert_eq!(proof.ifname, TEST_IFNAME);
        assert_eq!(proof.first_half.prefix, IPV4_FIRST_HALF);
        assert_eq!(proof.second_half.prefix, IPV4_SECOND_HALF);
        assert_eq!(proof.first_half.table, RT_TABLE_MAIN);
        assert_eq!(proof.first_half.protocol, ROUTE_PROTOCOL_ID);
        assert_eq!(proof.first_half.ifindex, TEST_IFINDEX);
        assert_eq!(proof.probes_checked, DEFAULT_IPV4_PROBES.len());
    }

    #[test]
    fn ipv4_selection_rejects_a_default_route() {
        let mut observation = good_observation();
        let default = Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        for probe in &mut observation.probes {
            probe.route = test_route(default);
        }
        let error = verify_ipv4_selection(&observation, &test_identity()).unwrap_err();
        assert!(matches!(
            error,
            RouteVerifyError::UnexpectedPrefix {
                expected,
                actual,
                ..
            } if expected == IPV4_FIRST_HALF && actual == default
        ));
    }

    #[test]
    fn ipv4_selection_rejects_a_more_specific_route() {
        let mut observation = good_observation();
        let destination = observation.probes[0].destination;
        let host = Ipv4Prefix::new(destination, 32).unwrap();
        observation.probes[0].route.prefix = host;
        let error = verify_ipv4_selection(&observation, &test_identity()).unwrap_err();
        assert!(matches!(
            error,
            RouteVerifyError::UnexpectedPrefix {
                expected,
                actual,
                ..
            } if expected == IPV4_FIRST_HALF && actual == host
        ));
    }

    #[test]
    fn ipv4_selection_rejects_a_foreign_interface() {
        let mut observation = good_observation();
        observation.probes[0].route.ifindex = Some(TEST_IFINDEX + 1);
        let error = verify_ipv4_selection(&observation, &test_identity()).unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::ForeignInterface {
                prefix: IPV4_FIRST_HALF,
                expected: TEST_IFINDEX,
                actual: Some(TEST_IFINDEX + 1),
            }
        );
    }

    #[test]
    fn ipv4_selection_rejects_another_table() {
        let mut observation = good_observation();
        observation.probes[0].route.table = 1000;
        let error = verify_ipv4_selection(&observation, &test_identity()).unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::UnexpectedTable {
                prefix: IPV4_FIRST_HALF,
                expected: RT_TABLE_MAIN,
                actual: 1000,
            }
        );
    }

    #[test]
    fn ipv4_selection_rejects_another_protocol_marker() {
        let mut observation = good_observation();
        observation.probes[0].route.protocol = 0;
        let error = verify_ipv4_selection(&observation, &test_identity()).unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::UnexpectedProtocol {
                prefix: IPV4_FIRST_HALF,
                expected: ROUTE_PROTOCOL_ID,
                actual: 0,
            }
        );
    }

    #[test]
    fn ipv4_selection_rejects_a_non_unicast_route() {
        let mut observation = good_observation();
        observation.probes[0].route.route_type = 6;
        let error = verify_ipv4_selection(&observation, &test_identity()).unwrap_err();
        assert_eq!(
            error,
            RouteVerifyError::NonUnicastRoute {
                prefix: IPV4_FIRST_HALF,
                route_type: 6,
            }
        );
    }

    #[test]
    fn ipv4_selection_rejects_unsupported_route_shapes() {
        let mut observation = good_observation();
        observation.probes[0].route.gateway = Some(Ipv4Addr::new(10, 0, 0, 1));
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::RouteGateway { .. }
        ));

        let mut observation = good_observation();
        observation.probes[0].route.via = true;
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::RouteGateway { .. }
        ));

        let mut observation = good_observation();
        observation.probes[0].route.multipath = true;
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::MultipathRoute { .. }
        ));

        let mut observation = good_observation();
        observation.probes[0].route.encap = true;
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::EncapsulatedRoute { .. }
        ));

        let mut observation = good_observation();
        observation.probes[0].route.nexthop_id = Some(42);
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::NexthopObjectRoute { .. }
        ));

        let mut observation = good_observation();
        observation.probes[0].route.dead = true;
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::RouteDown { .. }
        ));

        let mut observation = good_observation();
        observation.probes[0].route.link_down = true;
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::RouteDown { .. }
        ));
    }

    #[test]
    fn ipv4_selection_checks_the_link_identity() {
        for mutate in 0..5 {
            let mut observation = good_observation();
            match mutate {
                0 => observation.link.ifindex = TEST_IFINDEX + 1,
                1 => observation.link.name = "hs-tun1".to_owned(),
                2 => observation.link.kind = Some("tap".to_owned()),
                3 => observation.link.hardware_type = 1,
                _ => observation.link.flags = 0,
            }
            assert!(matches!(
                verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
                RouteVerifyError::LinkMismatch(_)
            ));
        }
    }

    #[test]
    fn ipv4_selection_requires_one_probe_in_each_half() {
        let mut observation = good_observation();
        observation
            .probes
            .retain(|probe| half_prefix(probe.destination) == IPV4_FIRST_HALF);
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::InvalidPolicy(_)
        ));
    }

    #[test]
    fn ipv4_selection_rejects_special_and_duplicate_probes() {
        let mut observation = good_observation();
        let duplicate = observation.probes[1].destination;
        observation.probes.push(test_probe(duplicate));
        assert!(matches!(
            verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
            RouteVerifyError::InvalidPolicy(_)
        ));

        for destination in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            let mut observation = good_observation();
            observation.probes[0].destination = destination;
            assert!(matches!(
                verify_ipv4_selection(&observation, &test_identity()).unwrap_err(),
                RouteVerifyError::InvalidPolicy(_)
            ));
        }
    }

    #[test]
    fn route_manager_uses_the_device_identity() {
        let fake = Arc::new(FakeRunner::default());
        let routes =
            RouteManager::with_runner(TEST_IFNAME, Ipv6Policy::Block, test_ip(), fake.clone())
                .unwrap();
        let tun = fake_tun();
        assert_eq!(tun.ifname(), TEST_IFNAME);
        assert_eq!(tun.ifindex(), TEST_IFINDEX);
        assert_eq!(routes.identity_for(&tun).unwrap(), test_identity());
        let other =
            RouteManager::with_runner("hs-tun1", Ipv6Policy::Block, test_ip(), fake).unwrap();
        assert!(matches!(
            other.identity_for(&tun),
            Err(RouteVerifyError::InvalidTunnelIdentity(_))
        ));
    }

    #[test]
    fn ipv6_selection_accepts_the_global_unicast_route() {
        let proof = verify_ipv6_forward_selection(
            &good_ipv6_observation(),
            &test_identity(),
            &test_outer(),
        )
        .unwrap();
        assert_eq!(proof.prefix, IPV6_GLOBAL_UNICAST);
        assert_eq!(proof.table, RT_TABLE_MAIN);
        assert_eq!(proof.protocol, ROUTE_PROTOCOL_ID);
        assert_eq!(proof.ifindex, TEST_IFINDEX);
        assert_eq!(proof.outer_ifindex, TEST_OUTER_IFINDEX);
        assert_eq!(proof.probes_checked, DEFAULT_IPV6_PROBES.len());
    }

    #[test]
    fn ipv6_selection_rejects_a_default_route() {
        let mut observation = good_ipv6_observation();
        let default = Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0).unwrap();
        for probe in &mut observation.probes {
            probe.route.prefix = default;
        }
        let error = verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
            .unwrap_err();
        assert!(matches!(
            error,
            RouteVerifyError::UnexpectedIpv6Prefix {
                expected,
                actual,
                ..
            } if expected == IPV6_GLOBAL_UNICAST && actual == default
        ));
    }

    #[test]
    fn ipv6_selection_rejects_a_more_specific_route() {
        let mut observation = good_ipv6_observation();
        let destination = observation.probes[0].destination;
        let host = Ipv6Prefix::new(destination, 128).unwrap();
        observation.probes[0].route.prefix = host;
        let error = verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
            .unwrap_err();
        assert!(matches!(
            error,
            RouteVerifyError::UnexpectedIpv6Prefix {
                destination: actual_destination,
                expected,
                actual,
            } if actual_destination == destination
                && expected == IPV6_GLOBAL_UNICAST
                && actual == host
        ));
    }

    #[test]
    fn ipv6_selection_rejects_a_foreign_interface() {
        let mut observation = good_ipv6_observation();
        observation.probes[0].route.ifindex = Some(TEST_IFINDEX + 1);
        assert_eq!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6ForeignInterface {
                prefix: IPV6_GLOBAL_UNICAST,
                expected: TEST_IFINDEX,
                actual: Some(TEST_IFINDEX + 1),
            }
        );

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.ifindex = None;
        assert_eq!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6ForeignInterface {
                prefix: IPV6_GLOBAL_UNICAST,
                expected: TEST_IFINDEX,
                actual: None,
            }
        );
    }

    #[test]
    fn ipv6_selection_rejects_another_table() {
        let mut observation = good_ipv6_observation();
        observation.probes[0].route.table = 100;
        assert_eq!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6UnexpectedTable {
                prefix: IPV6_GLOBAL_UNICAST,
                expected: RT_TABLE_MAIN,
                actual: 100,
            }
        );
    }

    #[test]
    fn ipv6_selection_rejects_another_protocol_marker() {
        let mut observation = good_ipv6_observation();
        observation.probes[0].route.protocol = 7;
        assert_eq!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6UnexpectedProtocol {
                prefix: IPV6_GLOBAL_UNICAST,
                expected: ROUTE_PROTOCOL_ID,
                actual: 7,
            }
        );
    }

    #[test]
    fn ipv6_selection_rejects_a_non_unicast_route() {
        let mut observation = good_ipv6_observation();
        observation.probes[0].route.route_type = 6;
        assert_eq!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6NonUnicastRoute {
                prefix: IPV6_GLOBAL_UNICAST,
                route_type: 6,
            }
        );
    }

    #[test]
    fn ipv6_selection_rejects_unsupported_route_shapes() {
        let mut observation = good_ipv6_observation();
        observation.probes[0].route.gateway = Some("fe80::1".parse().unwrap());
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6RouteGateway { .. }
        ));

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.via = true;
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6RouteGateway { .. }
        ));

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.multipath = true;
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6MultipathRoute { .. }
        ));

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.encap = true;
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6EncapsulatedRoute { .. }
        ));

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.nexthop_id = Some(42);
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6NexthopObjectRoute { .. }
        ));

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.dead = true;
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6RouteDown { .. }
        ));

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.link_down = true;
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6RouteDown { .. }
        ));

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.source_length = 64;
        observation.probes[0].route.source = Some("2001:db8::1".parse().unwrap());
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6SourceSpecificRoute { .. }
        ));

        let mut observation = good_ipv6_observation();
        observation.probes[0].route.cloned = true;
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::Ipv6ClonedRoute { .. }
        ));
    }

    #[test]
    fn ipv6_selection_checks_the_link_identity() {
        for mutate in 0..5 {
            let mut observation = good_ipv6_observation();
            match mutate {
                0 => observation.link.ifindex = TEST_IFINDEX + 1,
                1 => observation.link.name = "hs-tun1".to_owned(),
                2 => observation.link.kind = Some("tap".to_owned()),
                3 => observation.link.hardware_type = 1,
                _ => observation.link.flags = 0,
            }
            assert!(matches!(
                verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                    .unwrap_err(),
                RouteVerifyError::LinkMismatch(_)
            ));
        }
    }

    #[test]
    fn ipv6_selection_checks_the_outer_link() {
        for mutate in 0..7 {
            let mut observation = good_ipv6_observation();
            match mutate {
                0 => observation.outer_link.ifindex = TEST_OUTER_IFINDEX + 1,
                1 => observation.outer_link.name = "wlan1".to_owned(),
                2 => observation.outer_link.flags = 0,
                3 => observation.outer_link.flags = IFF_UP | IFF_LOOPBACK,
                4 => observation.outer_link.hardware_type = ARPHRD_NONE,
                5 => observation.outer_link.kind = Some("tun".to_owned()),
                _ => observation.outer_link.kind = Some("wireguard".to_owned()),
            }
            assert!(matches!(
                verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                    .unwrap_err(),
                RouteVerifyError::OuterLinkMismatch(_)
            ));
        }

        let other = OuterLinkIdentity::new(TEST_OUTER_IFINDEX + 1, TEST_OUTER_IFNAME).unwrap();
        assert!(matches!(
            verify_ipv6_forward_selection(&good_ipv6_observation(), &test_identity(), &other)
                .unwrap_err(),
            RouteVerifyError::OuterLinkMismatch(_)
        ));

        let same_as_tunnel = OuterLinkIdentity::new(TEST_IFINDEX, TEST_IFNAME).unwrap();
        let mut observation = good_ipv6_observation();
        observation.outer_link = ObservedLink {
            ifindex: TEST_IFINDEX,
            name: TEST_IFNAME.to_owned(),
            kind: None,
            hardware_type: libc::ARPHRD_ETHER,
            flags: IFF_UP,
        };
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &same_as_tunnel)
                .unwrap_err(),
            RouteVerifyError::InvalidOuterInterface(_)
        ));
    }

    #[test]
    fn ipv6_selection_requires_global_unicast_probes() {
        let mut observation = good_ipv6_observation();
        observation.probes.clear();
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::InvalidPolicy(_)
        ));

        let mut observation = good_ipv6_observation();
        let duplicate = observation.probes[0].destination;
        observation.probes.push(test_ipv6_probe(duplicate));
        assert!(matches!(
            verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                .unwrap_err(),
            RouteVerifyError::InvalidPolicy(_)
        ));

        for destination in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            "fe80::1".parse().unwrap(),
            "4000::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "3fff::1".parse().unwrap(),
        ] {
            let mut observation = good_ipv6_observation();
            observation.probes[0].destination = destination;
            assert!(matches!(
                verify_ipv6_forward_selection(&observation, &test_identity(), &test_outer())
                    .unwrap_err(),
                RouteVerifyError::InvalidPolicy(_)
            ));
        }

        for destination in DEFAULT_IPV6_PROBES {
            assert!(valid_ipv6_probe(destination));
        }
    }

    #[test]
    fn ipv6_block_selection_requires_the_recorded_route_and_blocked_probes() {
        let observation = good_ipv6_block_observation();
        let proof =
            verify_ipv6_block_selection_in(&observation, &test_identity(), TUNNEL_TABLE).unwrap();
        assert_eq!(proof.prefix, IPV6_GLOBAL_UNICAST);
        assert_eq!(proof.table, TUNNEL_TABLE);
        assert_eq!(proof.protocol, ROUTE_PROTOCOL_ID);
        assert_eq!(proof.probes_checked, DEFAULT_IPV6_PROBES.len());

        let mut missing = observation.clone();
        missing.route_recorded = false;
        assert_eq!(
            verify_ipv6_block_selection_in(&missing, &test_identity(), TUNNEL_TABLE).unwrap_err(),
            RouteVerifyError::Ipv6BlockNotRecorded
        );

        let mut bypass = observation.clone();
        bypass.probes[0].blocked = false;
        assert_eq!(
            verify_ipv6_block_selection_in(&bypass, &test_identity(), TUNNEL_TABLE).unwrap_err(),
            RouteVerifyError::Ipv6BlockBypass {
                destination: DEFAULT_IPV6_PROBES[0],
            }
        );

        let empty = Ipv6BlockObservation {
            link: test_link(),
            route_recorded: true,
            probes: Vec::new(),
        };
        assert_eq!(
            verify_ipv6_block_selection_in(&empty, &test_identity(), TUNNEL_TABLE).unwrap_err(),
            RouteVerifyError::MissingIpv6Probe {
                destination: DEFAULT_IPV6_PROBES[0],
            }
        );
    }

    #[test]
    fn tunnel_identity_is_bounded() {
        assert!(TunnelIdentity::new(1, TEST_IFNAME).is_ok());
        assert!(TunnelIdentity::new(0, TEST_IFNAME).is_err());
        assert!(TunnelIdentity::new(i32::MAX as u32 + 1, TEST_IFNAME).is_err());
        assert!(TunnelIdentity::new(TEST_IFINDEX, "").is_err());
        assert!(TunnelIdentity::new(TEST_IFINDEX, "a/b").is_err());
    }

    #[test]
    fn ipv4_prefixes_are_checked() {
        assert_eq!(
            Ipv4Prefix::new(Ipv4Addr::new(0, 0, 0, 0), 0),
            Some(Ipv4Prefix {
                address: Ipv4Addr::UNSPECIFIED,
                length: 0
            })
        );
        assert!(Ipv4Prefix::new(Ipv4Addr::new(1, 1, 1, 1), 1).is_none());
        assert!(Ipv4Prefix::new(Ipv4Addr::new(0, 0, 0, 0), 33).is_none());
        assert!(IPV4_FIRST_HALF.contains(Ipv4Addr::new(127, 255, 255, 255)));
        assert!(!IPV4_FIRST_HALF.contains(Ipv4Addr::new(128, 0, 0, 0)));
        assert!(IPV4_SECOND_HALF.contains(Ipv4Addr::new(255, 255, 255, 255)));
        assert_eq!(IPV4_FIRST_HALF.to_string(), "0.0.0.0/1");
    }

    #[test]
    fn ipv6_prefixes_are_checked() {
        assert_eq!(
            Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 0),
            Some(Ipv6Prefix {
                address: Ipv6Addr::UNSPECIFIED,
                length: 0
            })
        );
        assert!(Ipv6Prefix::new(IPV6_GLOBAL_UNICAST.address(), 3).is_some());
        assert!(Ipv6Prefix::new("2000::1".parse().unwrap(), 3).is_none());
        assert!(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 129).is_none());
        assert!(IPV6_GLOBAL_UNICAST.contains(DEFAULT_IPV6_PROBES[0]));
        assert!(!IPV6_GLOBAL_UNICAST.contains("fe80::1".parse().unwrap()));
        assert!(!IPV6_GLOBAL_UNICAST.contains("4000::1".parse().unwrap()));
        assert_eq!(IPV6_GLOBAL_UNICAST.to_string(), "2000::/3");
        assert!(IPV6_DOCUMENTATION_2001_DB8.contains("2001:db8::1".parse().unwrap()));
        assert!(IPV6_DOCUMENTATION_3FFF.contains("3fff::1".parse().unwrap()));
    }

    #[test]
    fn outer_interface_identity_is_bounded() {
        assert!(OuterLinkIdentity::new(1, TEST_OUTER_IFNAME).is_ok());
        assert!(OuterLinkIdentity::new(0, TEST_OUTER_IFNAME).is_err());
        assert!(OuterLinkIdentity::new(i32::MAX as u32 + 1, TEST_OUTER_IFNAME).is_err());
        assert!(OuterLinkIdentity::new(TEST_OUTER_IFINDEX, "").is_err());
        assert!(OuterLinkIdentity::new(TEST_OUTER_IFINDEX, "a/b").is_err());
    }

    #[test]
    fn protocol_marker_is_numeric_and_local_names_do_not_matter() {
        let key = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
        assert_eq!(key.protocol, 196);
        let message = encode_route_change(20, &key, false);
        let payload = &message[NLMSG_HDRLEN..];
        assert_eq!(payload[5], 196);
        assert_ne!(payload[5], 0);
    }

    #[test]
    fn netlink_route_reply_reads_a_non_default_protocol_number() {
        let payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            7,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        let message = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        let route = parse_route_reply(&message).unwrap();
        assert_eq!(route.protocol, 7);
        let probe = ObservedProbe {
            destination: Ipv4Addr::new(1, 1, 1, 1),
            route,
        };
        assert_eq!(
            validate_route(&probe, IPV4_FIRST_HALF, &test_identity(), RT_TABLE_MAIN).unwrap_err(),
            RouteVerifyError::UnexpectedProtocol {
                prefix: IPV4_FIRST_HALF,
                expected: ROUTE_PROTOCOL_ID,
                actual: 7,
            }
        );
    }

    #[test]
    fn netlink_dumps_a_table_and_the_rule_list() {
        let netlink = NetlinkRoute::open().expect("open route netlink");
        let routes = netlink
            .table_routes(libc::AF_INET as u8, TUNNEL_TABLE)
            .expect("dump the tunnel table");
        assert!(routes.iter().all(|route| route.key.table == TUNNEL_TABLE));
        let rules = netlink
            .rules(libc::AF_INET as u8)
            .expect("dump the IPv4 rules");
        assert!(
            rules.iter().any(|rule| rule.priority == 0),
            "the IPv4 local rule is present"
        );
        let rules = netlink
            .rules(libc::AF_INET6 as u8)
            .expect("dump the IPv6 rules");
        assert!(
            rules.iter().any(|rule| rule.priority == 0),
            "the IPv6 local rule is present"
        );
    }

    #[test]
    fn netlink_reads_the_kernel_loopback_link_and_route() {
        // These requests only query the kernel. They do not send packets.
        let index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(index, 0, "loopback interface is unavailable");
        let netlink = NetlinkRoute::open().expect("open route netlink");
        let link = netlink.link(index).expect("read loopback link");
        assert_eq!(link.ifindex, index);
        assert_eq!(link.name, "lo");
        let route = netlink
            .route(Ipv4Addr::LOCALHOST)
            .expect("read loopback route");
        assert_eq!(route.ifindex, Some(index));
    }

    #[test]
    fn netlink_route_get_sets_the_fib_match_flags() {
        let destination = Ipv4Addr::new(1, 1, 1, 1);
        let message = encode_route_get(7, destination);
        assert_eq!(message.len(), 36);
        assert_eq!(read_u32(&message[0..4]) as usize, message.len());
        assert_eq!(read_u16(&message[4..6]), RTM_GETROUTE);
        assert_eq!(read_u16(&message[6..8]), NLM_F_REQUEST);
        assert_eq!(read_u32(&message[8..12]), 7);
        assert_eq!(message[NLMSG_HDRLEN], libc::AF_INET as u8);
        assert_eq!(message[NLMSG_HDRLEN + 1], 32);
        assert_eq!(
            read_u32(&message[NLMSG_HDRLEN + 8..NLMSG_HDRLEN + 12]),
            RTM_F_FIB_MATCH | RTM_F_LOOKUP_TABLE
        );
        assert_eq!(read_u16(&message[NLMSG_HDRLEN + 12..NLMSG_HDRLEN + 14]), 8);
        assert_eq!(
            read_u16(&message[NLMSG_HDRLEN + 14..NLMSG_HDRLEN + 16]),
            RTA_DST
        );
        assert_eq!(&message[32..36], &destination.octets());
    }

    #[test]
    fn netlink_ipv6_route_get_sets_only_the_fib_match_flag() {
        let destination = DEFAULT_IPV6_PROBES[0];
        let message = encode_ipv6_route_get(11, destination);
        assert_eq!(message.len(), 48);
        assert_eq!(read_u32(&message[0..4]) as usize, message.len());
        assert_eq!(read_u16(&message[4..6]), RTM_GETROUTE);
        assert_eq!(read_u16(&message[6..8]), NLM_F_REQUEST);
        assert_eq!(read_u32(&message[8..12]), 11);
        let route = NLMSG_HDRLEN;
        assert_eq!(message[route], libc::AF_INET6 as u8);
        assert_eq!(message[route + 1], 128);
        assert_eq!(message[route + 2], 0);
        assert_eq!(message[route + 4], 0);
        assert_eq!(message[route + 5], 0);
        assert_eq!(message[route + 6], 0);
        assert_eq!(message[route + 7], 0);
        let flags = read_u32(&message[route + 8..route + 12]);
        assert_eq!(flags, RTM_F_FIB_MATCH);
        assert_eq!(flags & RTM_F_LOOKUP_TABLE, 0);
        let destination_attr = route + 12;
        assert_eq!(
            read_u16(&message[destination_attr..destination_attr + 2]),
            20
        );
        assert_eq!(
            read_u16(&message[destination_attr + 2..destination_attr + 4]),
            RTA_DST
        );
        assert_eq!(
            &message[destination_attr + 4..destination_attr + 20],
            &destination.octets()
        );
        let interface_attr = destination_attr + 20;
        // The request has no RTA_OIF. A pinned output interface can mask a
        // competing exact prefix.
        assert_eq!(message.len(), interface_attr);
    }

    #[test]
    fn netlink_link_get_names_the_index() {
        let message = encode_link_get(9, TEST_IFINDEX);
        assert_eq!(message.len(), 32);
        assert_eq!(read_u32(&message[0..4]) as usize, message.len());
        assert_eq!(read_u16(&message[4..6]), RTM_GETLINK);
        assert_eq!(read_u16(&message[6..8]), NLM_F_REQUEST);
        assert_eq!(read_u32(&message[8..12]), 9);
        assert_eq!(
            read_i32(&message[NLMSG_HDRLEN + 4..NLMSG_HDRLEN + 8]),
            TEST_IFINDEX as i32
        );
    }

    #[test]
    fn netlink_route_reply_parses_a_fib_entry() {
        let extra = [
            test_attr(RTA_PRIORITY, &10u32.to_ne_bytes()),
            test_attr(RTA_PREFSRC, &[10, 0, 0, 2]),
            test_attr(RTA_FLOW, &7u32.to_ne_bytes()),
            test_attr(RTA_GATEWAY, &[10, 0, 0, 1]),
        ];
        let payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        let route = parse_route_reply(&message).unwrap();
        assert_eq!(route.prefix, IPV4_FIRST_HALF);
        assert_eq!(route.table, RT_TABLE_MAIN);
        assert_eq!(route.protocol, ROUTE_PROTOCOL_ID);
        assert_eq!(route.route_type, RTN_UNICAST);
        assert_eq!(route.ifindex, Some(TEST_IFINDEX));
        assert_eq!(route.gateway, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(route.priority, Some(10));
        assert_eq!(route.prefsrc, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(route.flow, Some(7));
        assert!(!route.multipath);
        assert!(!route.dead);
        assert!(!route.link_down);
    }

    #[test]
    fn netlink_route_reply_parses_unsupported_route_shapes() {
        let extra = [
            test_attr(RTA_NH_ID, &42u32.to_ne_bytes()),
            test_attr(RTA_VIA, &[0u8; 4]),
            test_attr(RTA_ENCAP_TYPE, &1u16.to_ne_bytes()),
            test_attr(RTA_MULTIPATH, &[]),
        ];
        let payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        let route = parse_route_reply(&message).unwrap();
        assert_eq!(route.nexthop_id, Some(42));
        assert!(route.via);
        assert!(route.encap);
        assert!(route.multipath);
        assert!(!route.dead);
        assert!(!route.link_down);
    }

    #[test]
    fn netlink_route_reply_reads_the_down_flags() {
        let payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            RTNH_F_DEAD | RTNH_F_LINKDOWN,
            Some(TEST_IFINDEX),
            &[],
        );
        let message = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        let route = parse_route_reply(&message).unwrap();
        assert!(route.dead);
        assert!(route.link_down);

        let payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            2,
            Some(TEST_IFINDEX),
            &[],
        );
        let message = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        let route = parse_route_reply(&message).unwrap();
        assert!(!route.dead);
        assert!(!route.link_down);
    }

    #[test]
    fn netlink_ipv6_route_reply_parses_a_fib_entry() {
        let gateway: Ipv6Addr = "fe80::1".parse().unwrap();
        let prefsrc: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let extra = [
            test_attr(RTA_PRIORITY, &100u32.to_ne_bytes()),
            test_attr(RTA_PREFSRC, &prefsrc.octets()),
            test_attr(RTA_FLOW, &9u32.to_ne_bytes()),
            test_attr(RTA_GATEWAY, &gateway.octets()),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 5, &payload);
        let route = parse_ipv6_route_reply(&message).unwrap();
        assert_eq!(route.prefix, IPV6_GLOBAL_UNICAST);
        assert_eq!(route.source_length, 0);
        assert_eq!(route.source, None);
        assert_eq!(route.table, RT_TABLE_MAIN);
        assert_eq!(route.protocol, ROUTE_PROTOCOL_ID);
        assert_eq!(route.route_type, RTN_UNICAST);
        assert_eq!(route.ifindex, Some(TEST_IFINDEX));
        assert_eq!(route.gateway, Some(gateway));
        assert!(!route.multipath);
        assert!(!route.via);
        assert!(!route.encap);
        assert_eq!(route.nexthop_id, None);
        assert!(!route.dead);
        assert!(!route.link_down);
        assert!(!route.cloned);
        assert_eq!(route.priority, Some(100));
        assert_eq!(route.prefsrc, Some(prefsrc));
        assert_eq!(route.flow, Some(9));
    }

    #[test]
    fn netlink_ipv6_route_reply_parses_unsupported_shapes() {
        let extra = [
            test_attr(RTA_MULTIPATH, &[]),
            test_attr(RTA_VIA, &[0, 0]),
            test_attr(RTA_ENCAP_TYPE, &0u16.to_ne_bytes()),
            test_attr(RTA_ENCAP, &[]),
            test_attr(RTA_NH_ID, &42u32.to_ne_bytes()),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            100,
            7,
            6,
            RTNH_F_DEAD | RTNH_F_LINKDOWN | RTM_F_CLONED,
            None,
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 6, &payload);
        let route = parse_ipv6_route_reply(&message).unwrap();
        assert_eq!(route.table, 100);
        assert_eq!(route.protocol, 7);
        assert_eq!(route.route_type, 6);
        assert_eq!(route.ifindex, None);
        assert!(route.multipath);
        assert!(route.via);
        assert!(route.encap);
        assert_eq!(route.nexthop_id, Some(42));
        assert!(route.dead);
        assert!(route.link_down);
        assert!(route.cloned);
    }

    #[test]
    fn netlink_ipv6_route_reply_reads_a_table_above_255() {
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            300,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        let message = test_netlink_message(RTM_NEWROUTE, 8, &payload);
        let route = parse_ipv6_route_reply(&message).unwrap();
        assert_eq!(route.table, 300);
    }

    #[test]
    fn netlink_ipv6_route_reply_reads_the_source_selector() {
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let payload = test_ipv6_route_payload_raw(
            TestIpv6RouteSpec {
                destination: Some(IPV6_GLOBAL_UNICAST.address()),
                destination_length: 3,
                source: Some(source),
                source_length: 64,
                table: RT_TABLE_MAIN,
                protocol: ROUTE_PROTOCOL_ID,
                route_type: RTN_UNICAST,
                flags: 0,
                ifindex: Some(TEST_IFINDEX),
            },
            &[],
        );
        let message = test_netlink_message(RTM_NEWROUTE, 7, &payload);
        let route = parse_ipv6_route_reply(&message).unwrap();
        assert_eq!(route.source_length, 64);
        assert_eq!(route.source, Some(source));
    }

    #[test]
    fn netlink_ipv6_route_reply_rejects_invalid_shapes() {
        let wrong_type = test_netlink_message(RTM_NEWLINK, 3, &[0u8; 16]);
        assert!(matches!(
            parse_ipv6_route_reply(&wrong_type),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        payload[0] = libc::AF_INET as u8;
        let wrong_family = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_ipv6_route_reply(&wrong_family),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        payload[1] = 129;
        let long_prefix = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_ipv6_route_reply(&long_prefix),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        payload[2] = 129;
        let long_source = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_ipv6_route_reply(&long_source),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let missing_destination = test_netlink_message(
            RTM_NEWROUTE,
            3,
            &test_ipv6_route_payload_raw(
                TestIpv6RouteSpec {
                    destination: None,
                    destination_length: 3,
                    source: None,
                    source_length: 0,
                    table: RT_TABLE_MAIN,
                    protocol: ROUTE_PROTOCOL_ID,
                    route_type: RTN_UNICAST,
                    flags: 0,
                    ifindex: Some(TEST_IFINDEX),
                },
                &[],
            ),
        );
        assert!(matches!(
            parse_ipv6_route_reply(&missing_destination),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let missing_source = test_netlink_message(
            RTM_NEWROUTE,
            3,
            &test_ipv6_route_payload_raw(
                TestIpv6RouteSpec {
                    destination: Some(IPV6_GLOBAL_UNICAST.address()),
                    destination_length: 3,
                    source: None,
                    source_length: 64,
                    table: RT_TABLE_MAIN,
                    protocol: ROUTE_PROTOCOL_ID,
                    route_type: RTN_UNICAST,
                    flags: 0,
                    ifindex: Some(TEST_IFINDEX),
                },
                &[],
            ),
        );
        assert!(matches!(
            parse_ipv6_route_reply(&missing_source),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let short_destination = test_netlink_message(
            RTM_NEWROUTE,
            3,
            &test_ipv6_route_payload_raw(
                TestIpv6RouteSpec {
                    destination: None,
                    destination_length: 3,
                    source: None,
                    source_length: 0,
                    table: RT_TABLE_MAIN,
                    protocol: ROUTE_PROTOCOL_ID,
                    route_type: RTN_UNICAST,
                    flags: 0,
                    ifindex: Some(TEST_IFINDEX),
                },
                &[test_attr(RTA_DST, &[0u8; 4])],
            ),
        );
        assert!(matches!(
            parse_ipv6_route_reply(&short_destination),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let short_gateway = test_netlink_message(
            RTM_NEWROUTE,
            3,
            &test_ipv6_route_payload(
                IPV6_GLOBAL_UNICAST,
                RT_TABLE_MAIN,
                ROUTE_PROTOCOL_ID,
                RTN_UNICAST,
                0,
                Some(TEST_IFINDEX),
                &[test_attr(RTA_GATEWAY, &[0u8; 4])],
            ),
        );
        assert!(matches!(
            parse_ipv6_route_reply(&short_gateway),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut message = test_netlink_message(RTM_NEWROUTE, 3, &[0u8; 16]);
        write_u32(&mut message[0..4], 4);
        assert!(matches!(
            parse_ipv6_route_reply(&message),
            Err(RouteVerifyError::MalformedReply(_))
        ));
        assert!(matches!(
            parse_ipv6_route_reply(&message[..8]),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        payload.extend_from_slice(&[0, 0]);
        let truncated = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_ipv6_route_reply(&truncated),
            Err(RouteVerifyError::MalformedReply(_))
        ));
    }

    #[test]
    fn netlink_route_reply_rejects_invalid_shapes() {
        let wrong_type = test_netlink_message(RTM_NEWLINK, 3, &[0u8; 16]);
        assert!(matches!(
            parse_route_reply(&wrong_type),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = vec![0u8; 12];
        payload[0] = libc::AF_INET as u8;
        payload[1] = 1;
        let missing_destination = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_route_reply(&missing_destination),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let payload = test_route_payload_raw(
            TestRouteSpec {
                destination: Some(Ipv4Addr::new(0, 0, 0, 1)),
                destination_length: 1,
                table: RT_TABLE_MAIN,
                protocol: ROUTE_PROTOCOL_ID,
                route_type: RTN_UNICAST,
                flags: 0,
                ifindex: Some(TEST_IFINDEX),
            },
            &[],
        );
        let host_bits = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_route_reply(&host_bits),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_route_payload_raw(
            TestRouteSpec {
                destination: None,
                destination_length: 33,
                table: RT_TABLE_MAIN,
                protocol: ROUTE_PROTOCOL_ID,
                route_type: RTN_UNICAST,
                flags: 0,
                ifindex: Some(TEST_IFINDEX),
            },
            &[],
        );
        let long_prefix = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_route_reply(&long_prefix),
            Err(RouteVerifyError::MalformedReply(_))
        ));
        payload[0] = 10;
        let wrong_family = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_route_reply(&wrong_family),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        payload[12..14].copy_from_slice(&2u16.to_ne_bytes());
        let short_attribute = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_route_reply(&short_attribute),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        payload[12..14].copy_from_slice(&1000u16.to_ne_bytes());
        let long_attribute = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_route_reply(&long_attribute),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        payload.extend_from_slice(&[0u8, 0]);
        let truncated_tail = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_route_reply(&truncated_tail),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_route_payload(
            IPV4_FIRST_HALF,
            RT_TABLE_MAIN,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &[],
        );
        payload.extend_from_slice(&[5u8, 0, 28, 0, 0]);
        let unaligned_attribute = test_netlink_message(RTM_NEWROUTE, 3, &payload);
        assert!(matches!(
            parse_route_reply(&unaligned_attribute),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        for attribute in [
            RTA_DST,
            RTA_OIF,
            RTA_GATEWAY,
            RTA_TABLE,
            RTA_PRIORITY,
            RTA_NH_ID,
        ] {
            let extra = [test_attr(attribute, &[0u8; 2])];
            let payload = test_route_payload(
                IPV4_FIRST_HALF,
                RT_TABLE_MAIN,
                ROUTE_PROTOCOL_ID,
                RTN_UNICAST,
                0,
                Some(TEST_IFINDEX),
                &extra,
            );
            let message = test_netlink_message(RTM_NEWROUTE, 3, &payload);
            assert!(
                matches!(
                    parse_route_reply(&message),
                    Err(RouteVerifyError::MalformedReply(_))
                ),
                "attribute {attribute} with a short value was accepted"
            );
        }
    }

    #[test]
    fn netlink_link_reply_parses_a_tun_link() {
        let payload =
            test_link_payload(TEST_IFINDEX, TEST_IFNAME, Some("tun"), ARPHRD_NONE, IFF_UP);
        let message = test_netlink_message(RTM_NEWLINK, 4, &payload);
        assert_eq!(parse_link_reply(&message).unwrap(), test_link());
    }

    #[test]
    fn netlink_link_reply_rejects_invalid_shapes() {
        let payload = test_link_payload(TEST_IFINDEX, TEST_IFNAME, Some("tun"), ARPHRD_NONE, 0);
        let wrong_type = test_netlink_message(RTM_NEWROUTE, 4, &payload);
        assert!(matches!(
            parse_link_reply(&wrong_type),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let missing_name = test_netlink_message(RTM_NEWLINK, 4, &[0u8; 16]);
        assert!(matches!(
            parse_link_reply(&missing_name),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut short = vec![0u8; 8];
        short[0] = 16;
        let message = test_netlink_message(RTM_NEWLINK, 4, &short);
        assert!(matches!(
            parse_link_reply(&message),
            Err(RouteVerifyError::MalformedReply(_))
        ));
    }

    #[test]
    fn netlink_link_reply_reads_nested_attributes_with_flags() {
        let mut payload = test_link_payload(TEST_IFINDEX, TEST_IFNAME, None, ARPHRD_NONE, IFF_UP);
        let mut kind = b"tun\0".to_vec();
        kind.push(0);
        let nested = test_attr(IFLA_INFO_KIND | 0x8000, &kind);
        payload.extend_from_slice(&test_attr(IFLA_LINKINFO | 0x8000, &nested));
        let message = test_netlink_message(RTM_NEWLINK, 4, &payload);
        assert_eq!(parse_link_reply(&message).unwrap(), test_link());
    }

    #[test]
    fn netlink_link_reply_rejects_truncated_nested_attributes() {
        let mut payload = test_link_payload(TEST_IFINDEX, TEST_IFNAME, None, ARPHRD_NONE, IFF_UP);
        payload.extend_from_slice(&test_attr(IFLA_LINKINFO, &[0u8, 0]));
        let short_nested = test_netlink_message(RTM_NEWLINK, 4, &payload);
        assert!(matches!(
            parse_link_reply(&short_nested),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_link_payload(TEST_IFINDEX, TEST_IFNAME, None, ARPHRD_NONE, IFF_UP);
        let mut inner = test_attr(IFLA_INFO_KIND, b"tun\0");
        inner[0..2].copy_from_slice(&12u16.to_ne_bytes());
        payload.extend_from_slice(&test_attr(IFLA_LINKINFO, &inner));
        let long_inner = test_netlink_message(RTM_NEWLINK, 4, &payload);
        assert!(matches!(
            parse_link_reply(&long_inner),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_link_payload(TEST_IFINDEX, TEST_IFNAME, None, ARPHRD_NONE, IFF_UP);
        let mut inner = test_attr(IFLA_INFO_KIND, b"tun\0");
        inner[0..2].copy_from_slice(&0u16.to_ne_bytes());
        payload.extend_from_slice(&test_attr(IFLA_LINKINFO, &inner));
        let zero_inner = test_netlink_message(RTM_NEWLINK, 4, &payload);
        assert!(matches!(
            parse_link_reply(&zero_inner),
            Err(RouteVerifyError::MalformedReply(_))
        ));

        let mut payload = test_link_payload(TEST_IFINDEX, TEST_IFNAME, None, ARPHRD_NONE, IFF_UP);
        let mut inner = test_attr(IFLA_INFO_KIND, b"tun\0");
        inner.extend_from_slice(&[0u8, 0]);
        payload.extend_from_slice(&test_attr(IFLA_LINKINFO, &inner));
        let trailing_inner = test_netlink_message(RTM_NEWLINK, 4, &payload);
        assert!(matches!(
            parse_link_reply(&trailing_inner),
            Err(RouteVerifyError::MalformedReply(_))
        ));
    }

    #[test]
    fn netlink_visit_rejects_truncated_outer_attributes() {
        let short = visit_attrs(&[1u8, 0, 1, 0], |_, _| Ok(()));
        assert!(matches!(short, Err(RouteVerifyError::MalformedReply(_))));
        let truncated = visit_attrs(&[8u8, 0, 1, 0, 0, 0, 0], |_, _| Ok(()));
        assert!(matches!(
            truncated,
            Err(RouteVerifyError::MalformedReply(_))
        ));
        let unaligned = visit_attrs(&[5u8, 0, 1, 0, 0], |_, _| Ok(()));
        assert!(matches!(
            unaligned,
            Err(RouteVerifyError::MalformedReply(_))
        ));
        let empty_tail = visit_attrs(&[0u8; 2], |_, _| Ok(()));
        assert!(matches!(
            empty_tail,
            Err(RouteVerifyError::MalformedReply(_))
        ));
    }

    #[test]
    fn routes_reject_bad_names_and_relative_tools() {
        assert!(RouteManager::with_runner(
            "",
            Ipv6Policy::Block,
            test_ip(),
            Arc::new(FakeRunner::default())
        )
        .is_err());
        assert!(RouteManager::with_runner(
            "a/b",
            Ipv6Policy::Block,
            test_ip(),
            Arc::new(FakeRunner::default())
        )
        .is_err());
        assert!(RouteManager::with_runner(
            "hs-tun0",
            Ipv6Policy::Block,
            PathBuf::from("ip"),
            Arc::new(FakeRunner::default())
        )
        .is_err());
    }

    #[test]
    fn link_install_adds_a_peer_and_brings_the_link_up() {
        let fake = Arc::new(FakeRunner::default());
        let mut link = LinkGuard::install_with(
            fake.clone(),
            test_ip(),
            "hs-tun0",
            "198.18.0.5".parse().unwrap(),
            1500,
        )
        .unwrap();
        assert!(link.has_address());
        {
            let calls = fake.calls.lock().unwrap();
            assert_eq!(calls.len(), 3);
            assert!(calls[0].contains(&"198.18.0.5/32".to_string()));
            assert!(calls[0].contains(&"198.18.0.6".to_string()));
            assert!(calls[0].contains(&"peer".to_string()));
            assert!(calls[1].contains(&"mtu".to_string()));
            assert!(calls[1].contains(&"1500".to_string()));
            assert!(calls[2].contains(&"up".to_string()));
        }
        link.remove().unwrap();
        assert!(!link.has_address());
        link.remove().unwrap();
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert!(calls[3].contains(&"del".to_string()));
        assert!(calls[3].contains(&"198.18.0.5/32".to_string()));
    }

    #[test]
    fn link_rollback_removes_the_address_after_a_failure() {
        let fake = Arc::new(FakeRunner::default());
        *fake.fail_at.lock().unwrap() = Some(1);
        let error = LinkGuard::install_with(
            fake.clone(),
            test_ip(),
            "hs-tun0",
            "198.18.0.5".parse().unwrap(),
            1500,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[2].contains(&"del".to_string()));
        assert!(calls[2].contains(&"198.18.0.5/32".to_string()));
    }

    #[test]
    fn link_cleanup_failure_is_retained_and_retryable() {
        let fake = Arc::new(FakeRunner::default());
        let mut link = LinkGuard::install_with(
            fake.clone(),
            test_ip(),
            "hs-tun0",
            "198.18.0.5".parse().unwrap(),
            1500,
        )
        .unwrap();
        *fake.fail_at.lock().unwrap() = Some(3);
        assert!(link.remove().is_err());
        assert!(link.has_address());
        *fake.fail_at.lock().unwrap() = None;
        link.remove().unwrap();
        assert!(!link.has_address());
    }

    #[test]
    fn link_rejects_bad_names_addresses_mtus_and_tools() {
        let runner = Arc::new(FakeRunner::default());
        for name in ["", ".", "a/b", "a b"] {
            assert!(LinkGuard::install_with(
                runner.clone(),
                test_ip(),
                name,
                "198.18.0.5".parse().unwrap(),
                1500
            )
            .is_err());
        }
        for address in ["198.18.0.0", "198.18.0.3", "127.0.0.1", "0.0.0.1"] {
            assert!(LinkGuard::install_with(
                runner.clone(),
                test_ip(),
                "hs-tun0",
                address.parse().unwrap(),
                1500
            )
            .is_err());
        }
        for mtu in [0, 100, 65_536] {
            assert!(LinkGuard::install_with(
                runner.clone(),
                test_ip(),
                "hs-tun0",
                "198.18.0.5".parse().unwrap(),
                mtu
            )
            .is_err());
        }
        assert!(LinkGuard::install_with(
            runner,
            PathBuf::from("ip"),
            "hs-tun0",
            "198.18.0.5".parse().unwrap(),
            1500
        )
        .is_err());
    }

    #[test]
    fn peer_address_is_the_other_host_in_a_slash_30() {
        assert_eq!(
            peer_in_subnet("198.18.0.5".parse().unwrap()).unwrap(),
            "198.18.0.6".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            peer_in_subnet("198.18.0.6".parse().unwrap()).unwrap(),
            "198.18.0.5".parse::<Ipv4Addr>().unwrap()
        );
        assert!(peer_in_subnet("198.18.0.0".parse().unwrap()).is_err());
        assert!(peer_in_subnet("198.18.0.3".parse().unwrap()).is_err());
    }
}
