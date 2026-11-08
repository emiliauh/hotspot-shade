//! Windows ABI layer for the physical adapter and gateway evidence.
//!
//! The raw types mirror the Windows headers. The layout is asserted for
//! `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc`. On both targets
//! `MIB_UNICASTIPADDRESS_ROW` is 80 bytes: the `SCOPE_ID` union is one 4-byte
//! field at offset 68, `CreationTimeStamp` starts at offset 72, and
//! `MIB_UNICASTIPADDRESS_TABLE` is 88 bytes with the first row at offset 8.
//! The field order was checked with compile-time layout assertions against the
//! `windows-sys` 0.61.2 bindings for both targets and compared with the
//! `winapi` 0.3.9 declarations. The SDK C header was not available on the
//! non-Windows host, so this is a metadata cross-check, not a header compile.
//! The API behavior on a live Windows host is not measured. Do not read these
//! compile-time checks as proof that a live adapter reports the expected flags
//! or that a live route lookup returns an on-link row.
//!
//! Every function here is read-only. `GetIfEntry2`, `GetUnicastIpAddressTable`,
//! `GetBestInterfaceEx`, and `GetBestRoute2` change no route and create no
//! device. `GetUnicastIpAddressTable` allocates a table that `FreeMibTable`
//! releases.
//!
//! The raw types, the layout assertions, and the row parsing compile in host
//! tests as well as on Windows. Only the FFI declarations and the live reader
//! are gated to Windows. That lets the host test the 80-byte row stride and the
//! usable-address policy without a Windows API call.
//!
//! The usable-address policy matches `platform_windows::usable_ipv4`. A
//! preferred APIPA address in `169.254.0.0/16` is not usable, so it does not
//! count when a DHCP lease is present. The reader returns the real usable
//! count, and the pure verifier requires exactly one. The reader also rechecks
//! the adapter GUID and index after the `GetUnicastIpAddressTable` call, because
//! that call is separate from the identity reads.

use super::{PhysicalAdapterObservation, PhysicalPathError};
#[cfg(windows)]
use super::{PhysicalPathProof, GATEWAY_PROBES};
#[cfg(windows)]
use crate::windows_route_verify::BestRouteProbe;
use crate::windows_route_verify::{
    AdapterGuid, LiveAdapterIdentity, ObservedRoute, RetainedAdapterIdentity, RoutePrefix,
};
#[cfg(windows)]
use std::ffi::c_void;
use std::mem::{align_of, offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;
#[cfg(windows)]
const ERROR_SUCCESS: u32 = 0;
#[cfg(windows)]
const MAX_INTERFACE_INDEX: u32 = 0x00ff_ffff;
const MAX_ADDRESS_ROWS: usize = 1 << 16;
const IF_MAX_STRING_SIZE: usize = 256;
const IF_MAX_PHYS_ADDRESS_LENGTH: usize = 32;
const NL_DAD_STATE_PREFERRED: i32 = 4;

/// True when an IPv4 address can carry traffic on the physical interface.
///
/// This mirrors `platform_windows::usable_ipv4`, which the interface status
/// observer uses. The classifier rejects the `0.0.0.0/8` "this network" range,
/// loopback (`127.0.0.0/8`), the limited broadcast address, multicast, and the
/// APIPA range `169.254.0.0/16`. An APIPA address means DHCP did not complete,
/// so it is not a usable hotspot address. It must not make the usable count
/// two when a DHCP lease is present.
fn is_usable_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && address.octets()[0] != 0
        && !address.is_loopback()
        && !address.is_broadcast()
        && !address.is_multicast()
        && !(address.octets()[0] == 169 && address.octets()[1] == 254)
}

/// The Windows `SOCKADDR_IN` layout.
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

/// The Windows `SOCKADDR_IN6` layout.
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

/// The Windows `SOCKADDR_INET` union.
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
        // SAFETY: Every union member starts with the address family. A `u16`
        // read is valid for an initialized union.
        unsafe { self.family }
    }

    fn ipv4(&self) -> Option<Ipv4Addr> {
        if self.family() == AF_INET {
            // SAFETY: The family tag was checked. The IPv4 member is active.
            Some(Ipv4Addr::from(unsafe { self.v4.address }))
        } else {
            None
        }
    }

    fn ip_address(&self) -> Result<IpAddr, PhysicalPathError> {
        match self.family() {
            AF_INET => Ok(IpAddr::V4(Ipv4Addr::from(unsafe {
                // SAFETY: The family tag was checked. The IPv4 member is
                // active.
                self.v4.address
            }))),
            AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(unsafe {
                // SAFETY: The family tag was checked. The IPv6 member is
                // active.
                self.v6.address
            }))),
            _ => Err(PhysicalPathError::InvalidObservation(
                "a Windows address has an unsupported family",
            )),
        }
    }
}

/// The Windows `IP_ADDRESS_PREFIX` layout.
// The fields mirror the Windows headers. Not every field is read here.
#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
struct RawIpAddressPrefix {
    prefix: RawSockaddrInet,
    prefix_length: u8,
}

impl RawIpAddressPrefix {
    fn parse(&self) -> Result<RoutePrefix, PhysicalPathError> {
        let address = self.prefix.ip_address()?;
        RoutePrefix::new(address, self.prefix_length).ok_or(PhysicalPathError::InvalidObservation(
            "a Windows route prefix is invalid",
        ))
    }
}

/// The Windows `MIB_IF_ROW2` layout.
///
/// `MediaType` and `PhysicalMediumType` are present for layout only. The
/// physical policy reads the interface type, the flags, the tunnel type, the
/// media connect state, the access type, and the physical address. It does not
/// read the medium fields. A driver can report the hardware flag and an
/// Ethernet or Wi-Fi interface type for a virtual adapter, so the medium fields
/// would not prove a physical link either.
// The fields mirror the Windows headers. Not every field is read here.
#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
struct RawMibIfRow2 {
    interface_luid: u64,
    interface_index: u32,
    interface_guid: AdapterGuid,
    alias: [u16; IF_MAX_STRING_SIZE + 1],
    description: [u16; IF_MAX_STRING_SIZE + 1],
    physical_address_length: u32,
    physical_address: [u8; IF_MAX_PHYS_ADDRESS_LENGTH],
    permanent_physical_address: [u8; IF_MAX_PHYS_ADDRESS_LENGTH],
    mtu: u32,
    if_type: u32,
    tunnel_type: i32,
    // `MediaType` and `PhysicalMediumType` follow. They are present for
    // layout only and are not read; see the type documentation.
    media_type: i32,
    physical_medium_type: i32,
    access_type: i32,
    direction_type: i32,
    flags: u8,
    padding: [u8; 3],
    oper_status: i32,
    admin_status: i32,
    media_connect_state: i32,
    network_guid: AdapterGuid,
    connection_type: i32,
    padding2: [u8; 4],
    counters: [u64; 20],
}

impl RawMibIfRow2 {
    fn hardware_interface(&self) -> bool {
        self.flags & 0x01 != 0
    }

    fn filter_interface(&self) -> bool {
        self.flags & 0x02 != 0
    }

    fn physical_address_nonzero(&self) -> bool {
        let length = self.physical_address_length as usize;
        if length > IF_MAX_PHYS_ADDRESS_LENGTH {
            return false;
        }
        self.physical_address[..length]
            .iter()
            .any(|byte| *byte != 0)
    }
}

/// The Windows `MIB_UNICASTIPADDRESS_ROW` layout.
///
/// `ScopeId` is one `SCOPE_ID` union value of 4 bytes. The C type is a struct
/// that wraps a union of `Zone`, `InterfaceIndex`, and `Value`; every member is
/// 4 bytes. `CreationTimeStamp` follows it at offset 72. Do not split
/// `ScopeId` into two fields: that reads a 4-byte field past the documented row
/// and makes the stride 88 instead of 80.
// The fields mirror the Windows headers. Not every field is read here.
#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
struct RawMibUnicastIpAddressRow {
    address: RawSockaddrInet,
    interface_luid: u64,
    interface_index: u32,
    prefix_origin: i32,
    suffix_origin: i32,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    on_link_prefix_length: u8,
    skip_as_source: u8,
    padding: [u8; 2],
    dad_state: i32,
    scope_id: u32,
    creation_time_stamp: i64,
}

impl RawMibUnicastIpAddressRow {
    /// Return true when Windows may use this row as a source address.
    ///
    /// The policy requires the preferred DAD state and a clear
    /// `SkipAsSource` flag. Lifetime evidence is checked separately before
    /// selecting an address. The address family, value, and prefix are
    /// checked separately by the pure layer.
    fn is_usable_source(&self) -> bool {
        self.skip_as_source == 0 && self.dad_state == NL_DAD_STATE_PREFERRED
    }

    /// Return true when the row is a usable IPv4 source address.
    ///
    /// The row must pass [`Self::is_usable_source`] and name an IPv4 address
    /// that passes [`is_usable_ipv4`]. The `GetUnicastIpAddressTable` call uses
    /// `AF_INET`, so a non-IPv4 row here is not a usable IPv4 address.
    fn is_usable_source_ipv4(&self) -> bool {
        self.is_usable_source() && self.address.ipv4().is_some_and(is_usable_ipv4)
    }
}

/// The Windows `MIB_UNICASTIPADDRESS_TABLE` header.
///
/// The C declaration is `ULONG NumEntries; MIB_UNICASTIPADDRESS_ROW Table[1];`.
/// The first row starts after the 8-byte header. The rows that the API allocates
/// use the 80-byte row stride, not this Rust struct's total size.
// The fields mirror the Windows headers. Not every field is read here.
#[allow(dead_code)]
#[repr(C)]
struct RawMibUnicastIpAddressTable {
    num_entries: u32,
    first_row: RawMibUnicastIpAddressRow,
}

const ADDRESS_ROWS_OFFSET: usize = offset_of!(RawMibUnicastIpAddressTable, first_row);

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

const _: () = {
    assert!(size_of::<RawSockaddrIn>() == 16);
    assert!(size_of::<RawSockaddrIn6>() == 28);
    assert!(size_of::<RawSockaddrInet>() == 28);
    assert!(align_of::<RawSockaddrInet>() == 4);
    assert!(size_of::<RawIpAddressPrefix>() == 32);
    assert!(offset_of!(RawIpAddressPrefix, prefix_length) == 28);

    assert!(size_of::<RawMibIfRow2>() == 1352);
    assert!(align_of::<RawMibIfRow2>() == 8);
    assert!(offset_of!(RawMibIfRow2, interface_luid) == 0);
    assert!(offset_of!(RawMibIfRow2, interface_index) == 8);
    assert!(offset_of!(RawMibIfRow2, interface_guid) == 12);
    assert!(offset_of!(RawMibIfRow2, alias) == 28);
    assert!(offset_of!(RawMibIfRow2, description) == 542);
    assert!(offset_of!(RawMibIfRow2, physical_address_length) == 1056);
    assert!(offset_of!(RawMibIfRow2, physical_address) == 1060);
    assert!(offset_of!(RawMibIfRow2, permanent_physical_address) == 1092);
    assert!(offset_of!(RawMibIfRow2, mtu) == 1124);
    assert!(offset_of!(RawMibIfRow2, if_type) == 1128);
    assert!(offset_of!(RawMibIfRow2, tunnel_type) == 1132);
    assert!(offset_of!(RawMibIfRow2, media_type) == 1136);
    assert!(offset_of!(RawMibIfRow2, physical_medium_type) == 1140);
    assert!(offset_of!(RawMibIfRow2, access_type) == 1144);
    assert!(offset_of!(RawMibIfRow2, direction_type) == 1148);
    assert!(offset_of!(RawMibIfRow2, flags) == 1152);
    assert!(offset_of!(RawMibIfRow2, oper_status) == 1156);
    assert!(offset_of!(RawMibIfRow2, admin_status) == 1160);
    assert!(offset_of!(RawMibIfRow2, media_connect_state) == 1164);
    assert!(offset_of!(RawMibIfRow2, network_guid) == 1168);
    assert!(offset_of!(RawMibIfRow2, connection_type) == 1184);
    assert!(offset_of!(RawMibIfRow2, counters) == 1192);

    assert!(size_of::<RawMibUnicastIpAddressRow>() == 80);
    assert!(align_of::<RawMibUnicastIpAddressRow>() == 8);
    assert!(offset_of!(RawMibUnicastIpAddressRow, address) == 0);
    assert!(offset_of!(RawMibUnicastIpAddressRow, interface_luid) == 32);
    assert!(offset_of!(RawMibUnicastIpAddressRow, interface_index) == 40);
    assert!(offset_of!(RawMibUnicastIpAddressRow, prefix_origin) == 44);
    assert!(offset_of!(RawMibUnicastIpAddressRow, suffix_origin) == 48);
    assert!(offset_of!(RawMibUnicastIpAddressRow, valid_lifetime) == 52);
    assert!(offset_of!(RawMibUnicastIpAddressRow, preferred_lifetime) == 56);
    assert!(offset_of!(RawMibUnicastIpAddressRow, on_link_prefix_length) == 60);
    assert!(offset_of!(RawMibUnicastIpAddressRow, skip_as_source) == 61);
    assert!(offset_of!(RawMibUnicastIpAddressRow, dad_state) == 64);
    assert!(offset_of!(RawMibUnicastIpAddressRow, scope_id) == 68);
    assert!(offset_of!(RawMibUnicastIpAddressRow, creation_time_stamp) == 72);
    assert!(size_of::<RawMibUnicastIpAddressTable>() == 88);
    assert!(align_of::<RawMibUnicastIpAddressTable>() == 8);
    assert!(ADDRESS_ROWS_OFFSET == 8);

    assert!(size_of::<RawMibIpForwardRow2>() == 104);
    assert!(align_of::<RawMibIpForwardRow2>() == 8);
    assert!(offset_of!(RawMibIpForwardRow2, interface_luid) == 0);
    assert!(offset_of!(RawMibIpForwardRow2, interface_index) == 8);
    assert!(offset_of!(RawMibIpForwardRow2, destination_prefix) == 12);
    assert!(offset_of!(RawMibIpForwardRow2, next_hop) == 44);
    assert!(offset_of!(RawMibIpForwardRow2, metric) == 84);
    assert!(offset_of!(RawMibIpForwardRow2, protocol) == 88);
    assert!(offset_of!(RawMibIpForwardRow2, loopback) == 92);
};

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
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
    fn GetIfEntry2(row: *mut RawMibIfRow2) -> u32;
    fn GetUnicastIpAddressTable(family: u16, table: *mut *mut RawMibUnicastIpAddressTable) -> u32;
    fn FreeMibTable(memory: *mut c_void);
}

/// The live reader that the fixed-order observation seam uses.
#[cfg(windows)]
struct Win32Reads;

#[cfg(windows)]
impl super::PhysicalPathReads for Win32Reads {
    fn read_gateway(&mut self) -> Result<super::GatewayObservation, PhysicalPathError> {
        observe_gateway()
    }

    fn read_adapter(
        &mut self,
        interface_luid: u64,
        expected_index: u32,
    ) -> Result<PhysicalAdapterObservation, PhysicalPathError> {
        read_adapter(interface_luid, expected_index)
    }

    fn read_destination_route(
        &mut self,
        destination: Ipv4Addr,
    ) -> Result<BestRouteProbe, PhysicalPathError> {
        best_route(destination)
    }
}

/// Read the live physical path evidence for one source device destination.
///
/// The call reads the default route, the selected physical adapter, the
/// adapter IPv4 address, the route to the destination, and then the default
/// route and adapter again. It changes no route and creates no device. It
/// returns a proof only for a private or shared numeric IPv4 destination that
/// equals the current default gateway and leaves through the accepted physical
/// adapter.
///
/// The function is not authentication. Any device at that gateway can accept
/// the v1 token. The token gate uses `observe_token_destination`, which adds
/// the pinned-interface probes and the owned-run rules.
#[cfg(windows)]
pub fn observe(destination: Ipv4Addr) -> Result<PhysicalPathProof, PhysicalPathError> {
    super::observe_with_reads(&mut Win32Reads, destination)
}

#[cfg(windows)]
impl super::TokenPathReads for Win32Reads {
    fn read_pinned_gateway(
        &mut self,
        interface_index: u32,
    ) -> Result<super::GatewayObservation, PhysicalPathError> {
        let first = best_route_on(GATEWAY_PROBES[0], interface_index)?;
        let second = best_route_on(GATEWAY_PROBES[1], interface_index)?;
        Ok(super::GatewayObservation {
            probes: [first, second],
        })
    }
}

/// Run the Windows token gate for one source device destination.
///
/// The call reads the unscoped default route, the default route on the pinned
/// interface, the physical adapter and its IPv4 address, the route to the
/// destination, and then the three default and adapter reads again. It changes
/// no route, creates no device, opens no socket, and sends no packet. See
/// `prove_token_destination` for the rules. It is not authentication: any
/// device at the gateway address can accept the v1 token.
#[cfg(windows)]
pub(crate) fn observe_token_destination(
    destination: Ipv4Addr,
    pinned_index: u32,
    run: Option<&super::TokenRun>,
) -> Result<PhysicalPathProof, PhysicalPathError> {
    super::prove_token_destination(&mut Win32Reads, destination, pinned_index, run)
}

/// Ask `GetBestRoute2` for the route to one destination on one interface.
///
/// `GetBestRoute2` is interface scoped when it receives an interface index.
/// That is the lookup that an outer socket pinned with `IP_UNICAST_IF` uses,
/// so it names the physical default route even while the tunnel `/1` routes
/// win the unscoped lookup. The probe records the pinned index as the selected
/// interface. It does not call `GetBestInterfaceEx`.
#[cfg(windows)]
fn best_route_on(
    destination: Ipv4Addr,
    interface_index: u32,
) -> Result<BestRouteProbe, PhysicalPathError> {
    if interface_index == 0 || interface_index > MAX_INTERFACE_INDEX {
        return Err(PhysicalPathError::InvalidObservation(
            "the pinned interface index is invalid",
        ));
    }
    let destination_raw = sockaddr_v4(destination);
    let mut row: RawMibIpForwardRow2 = unsafe { std::mem::zeroed() };
    let mut best_source: RawSockaddrInet = unsafe { std::mem::zeroed() };
    // SAFETY: The destination pointer is valid. A null LUID with a nonzero
    // interface index is the documented optional form. The row and source
    // output pointers are valid for one value each. A null source address is
    // allowed.
    let status = unsafe {
        GetBestRoute2(
            ptr::null(),
            interface_index,
            ptr::null(),
            &destination_raw,
            0,
            &mut row,
            &mut best_source,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(PhysicalPathError::Api {
            operation: "GetBestRoute2",
            code: status,
        });
    }
    Ok(BestRouteProbe {
        destination: IpAddr::V4(destination),
        best_interface_index: interface_index,
        route: observed_route(&row)?,
    })
}

#[cfg(windows)]
fn best_route(destination: Ipv4Addr) -> Result<BestRouteProbe, PhysicalPathError> {
    let destination_raw = sockaddr_v4(destination);
    let mut best_interface_index: u32 = 0;
    // SAFETY: The destination points to an initialized `SOCKADDR_INET`. The
    // output pointer is valid for one `NET_IFINDEX`.
    let status = unsafe { GetBestInterfaceEx(&destination_raw, &mut best_interface_index) };
    if status != ERROR_SUCCESS {
        return Err(PhysicalPathError::Api {
            operation: "GetBestInterfaceEx",
            code: status,
        });
    }
    if best_interface_index == 0 || best_interface_index > MAX_INTERFACE_INDEX {
        return Err(PhysicalPathError::InvalidObservation(
            "GetBestInterfaceEx returned an invalid interface index",
        ));
    }

    let mut row: RawMibIpForwardRow2 = unsafe { std::mem::zeroed() };
    let mut best_source: RawSockaddrInet = unsafe { std::mem::zeroed() };
    // SAFETY: The destination pointer is valid. A null LUID with a nonzero
    // interface index is the documented optional form. The row and source
    // output pointers are valid for one value each. A null source address is
    // allowed.
    let status = unsafe {
        GetBestRoute2(
            ptr::null(),
            best_interface_index,
            ptr::null(),
            &destination_raw,
            0,
            &mut row,
            &mut best_source,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(PhysicalPathError::Api {
            operation: "GetBestRoute2",
            code: status,
        });
    }
    Ok(BestRouteProbe {
        destination: IpAddr::V4(destination),
        best_interface_index,
        route: observed_route(&row)?,
    })
}

#[cfg(windows)]
fn observe_gateway() -> Result<super::GatewayObservation, PhysicalPathError> {
    let first = best_route(GATEWAY_PROBES[0])?;
    let second = best_route(GATEWAY_PROBES[1])?;
    Ok(super::GatewayObservation {
        probes: [first, second],
    })
}

/// Read the physical default IPv4 route.
///
/// The call reads the two unscoped default route probes and the selected
/// physical adapter, then runs the pure [`super::default_physical_route_from`]
/// decision. It returns the interface index and the IPv4 gateway only when both
/// probes agree on the genuine `0.0.0.0/0` route with a real IPv4 next hop and
/// the adapter is an accepted physical Ethernet or Wi-Fi adapter that matches
/// the route. It changes no route, opens no device, and creates no socket. A
/// VPN, a split default route, a loopback, a tunnel, a virtual adapter, or a
/// failed read is an error, never a fallback.
#[cfg(windows)]
pub(crate) fn default_physical_route() -> Result<(u32, Ipv4Addr), PhysicalPathError> {
    let gateway = observe_gateway()?;
    let selection = super::selected_gateway(&gateway)?;
    let adapter = read_adapter(selection.interface_luid, selection.interface_index)?;
    super::default_physical_route_from(&gateway, &adapter)
}

/// The three reads that make one adapter observation.
///
/// The live implementation calls `GetIfEntry2`, `ConvertInterfaceLuidToGuid`
/// with `ConvertInterfaceLuidToIndex`, and `GetUnicastIpAddressTable`. The
/// trait is private. Host tests use it to prove that the identity recheck runs
/// after the address table and that a mismatch stops the read. The order is
/// fixed, but each call stays a separate Windows call.
#[cfg(any(windows, test))]
trait AdapterReadSource {
    /// Read the `MIB_IF_ROW2` for one LUID.
    fn read_interface_row(
        &mut self,
        interface_luid: u64,
    ) -> Result<RawMibIfRow2, PhysicalPathError>;

    /// Read the live index and GUID for one LUID.
    fn read_live_identity(
        &mut self,
        interface_luid: u64,
    ) -> Result<LiveAdapterIdentity, PhysicalPathError>;

    /// Read the IPv4 unicast address rows for one LUID.
    fn read_address_rows(
        &mut self,
        interface_luid: u64,
    ) -> Result<Vec<RawMibUnicastIpAddressRow>, PhysicalPathError>;
}

#[cfg(windows)]
struct Win32AdapterReads;

#[cfg(windows)]
impl AdapterReadSource for Win32AdapterReads {
    fn read_interface_row(
        &mut self,
        interface_luid: u64,
    ) -> Result<RawMibIfRow2, PhysicalPathError> {
        read_if_entry(interface_luid)
    }

    fn read_live_identity(
        &mut self,
        interface_luid: u64,
    ) -> Result<LiveAdapterIdentity, PhysicalPathError> {
        crate::windows_route_verify::read_live_identity(interface_luid)
            .map_err(PhysicalPathError::RouteVerify)
    }

    fn read_address_rows(
        &mut self,
        interface_luid: u64,
    ) -> Result<Vec<RawMibUnicastIpAddressRow>, PhysicalPathError> {
        read_unicast_addresses(interface_luid)
    }
}

#[cfg(windows)]
fn read_adapter(
    interface_luid: u64,
    expected_index: u32,
) -> Result<PhysicalAdapterObservation, PhysicalPathError> {
    read_adapter_with_source(&mut Win32AdapterReads, interface_luid, expected_index)
}

/// Read one adapter through the injected read source.
///
/// The sequence is fixed: `MIB_IF_ROW2`, live identity, address table, live
/// identity. The second identity read proves that the LUID still names the same
/// adapter after the table read. The table rows are selected only after that
/// recheck, so a mismatch never becomes an adapter observation. A mismatch
/// before the table stops before the address read.
#[cfg(any(windows, test))]
fn read_adapter_with_source<R: AdapterReadSource>(
    source: &mut R,
    interface_luid: u64,
    expected_index: u32,
) -> Result<PhysicalAdapterObservation, PhysicalPathError> {
    let row = source.read_interface_row(interface_luid)?;
    if row.interface_luid != interface_luid {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    if row.interface_index != expected_index {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    if row.interface_guid.is_zero() {
        return Err(PhysicalPathError::InvalidObservation(
            "GetIfEntry2 returned the zero GUID",
        ));
    }

    let live = source.read_live_identity(interface_luid)?;
    if live.interface_index != row.interface_index || live.interface_guid != row.interface_guid {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    let identity =
        RetainedAdapterIdentity::new(row.interface_index, interface_luid, row.interface_guid)
            .map_err(PhysicalPathError::RouteVerify)?;

    let addresses = source.read_address_rows(interface_luid)?;
    // Recheck the identity after the unicast address table read. The table is a
    // separate call, so Windows can remove the adapter and reuse its LUID while
    // the rows are copied. The recheck proves agreement at this moment; it does
    // not make the two reads atomic.
    let recheck = source.read_live_identity(interface_luid)?;
    confirm_rechecked_identity(identity, recheck)?;
    let (address, usable_count) =
        select_usable_address(&addresses, interface_luid, expected_index)?;
    adapter_observation(&row, identity, &address, usable_count)
}

#[cfg(windows)]
fn read_if_entry(interface_luid: u64) -> Result<RawMibIfRow2, PhysicalPathError> {
    let mut row: RawMibIfRow2 = unsafe { std::mem::zeroed() };
    row.interface_luid = interface_luid;
    // SAFETY: The row points to an initialized `MIB_IF_ROW2` with a nonzero
    // interface LUID. The API fills the remaining fields.
    let status = unsafe { GetIfEntry2(&mut row) };
    if status != ERROR_SUCCESS {
        return Err(PhysicalPathError::Api {
            operation: "GetIfEntry2",
            code: status,
        });
    }
    Ok(row)
}

/// Confirm that the identity recheck taken after the unicast address table
/// still names the retained adapter.
///
/// A zero GUID, a different index, or a different GUID means the LUID no longer
/// names the adapter that supplied the address rows. The caller keeps the error
/// and reports it; it does not fall back to the stale row.
fn confirm_rechecked_identity(
    identity: RetainedAdapterIdentity,
    recheck: LiveAdapterIdentity,
) -> Result<(), PhysicalPathError> {
    if recheck.interface_guid.is_zero() {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    if recheck.interface_index != identity.interface_index()
        || recheck.interface_guid != identity.interface_guid()
    {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    Ok(())
}

/// Select the usable IPv4 address evidence for the adapter.
///
/// A usable row has the preferred DAD state, is not skip-as-source, and passes
/// [`is_usable_ipv4`]. Zero or inconsistent lifetimes on an otherwise usable
/// row refuse the observation. `u32::MAX` is an infinite lifetime. An APIPA
/// row does not count when a DHCP lease is present. The function returns the
/// first usable row in table order and the real number of usable rows. It does
/// not assert a count: the pure verifier
/// requires exactly one, so two usable rows fail closed there with the count
/// preserved. Zero usable rows fail here because there is no address to report.
fn select_usable_address(
    addresses: &[RawMibUnicastIpAddressRow],
    interface_luid: u64,
    expected_index: u32,
) -> Result<(RawMibUnicastIpAddressRow, u32), PhysicalPathError> {
    // Refuse inconsistent or expired lifetime evidence rather than silently
    // dropping that row and accepting another address as the only candidate.
    if addresses.iter().any(|address| {
        address.interface_luid == interface_luid
            && address.is_usable_source_ipv4()
            && (address.valid_lifetime == 0
                || address.preferred_lifetime == 0
                || address.preferred_lifetime > address.valid_lifetime)
    }) {
        return Err(PhysicalPathError::AdapterAddressUnusable(
            "the adapter reports unusable IPv4 address lifetime evidence",
        ));
    }
    let usable: Vec<&RawMibUnicastIpAddressRow> = addresses
        .iter()
        .filter(|address| address.interface_luid == interface_luid)
        .filter(|address| address.is_usable_source_ipv4())
        .collect();
    let Some(address) = usable.first() else {
        return Err(PhysicalPathError::AdapterAddressUnusable(
            "the adapter reports no usable IPv4 address",
        ));
    };
    if usable
        .iter()
        .any(|address| address.interface_index != expected_index)
    {
        return Err(PhysicalPathError::AdapterIdentityChanged);
    }
    // The table reader bounds the row count at `MAX_ADDRESS_ROWS`, so the
    // conversion cannot truncate.
    Ok((**address, usable.len() as u32))
}

fn adapter_observation(
    row: &RawMibIfRow2,
    identity: RetainedAdapterIdentity,
    address: &RawMibUnicastIpAddressRow,
    usable_ipv4_address_count: u32,
) -> Result<PhysicalAdapterObservation, PhysicalPathError> {
    let ipv4_address = address
        .address
        .ipv4()
        .ok_or(PhysicalPathError::InvalidObservation(
            "the adapter address is not IPv4",
        ))?;
    Ok(PhysicalAdapterObservation {
        identity,
        interface_type: row.if_type,
        oper_status: row.oper_status as u32,
        admin_status: row.admin_status as u32,
        media_connect_state: row.media_connect_state as u32,
        access_type: row.access_type as u32,
        tunnel_type: row.tunnel_type as u32,
        hardware_interface: row.hardware_interface(),
        filter_interface: row.filter_interface(),
        physical_address_length: row.physical_address_length,
        physical_address_nonzero: row.physical_address_nonzero(),
        ipv4_address,
        on_link_prefix_length: address.on_link_prefix_length,
        usable_ipv4_address_count,
    })
}

/// Return the documented byte length of a unicast address table.
///
/// The header is `ADDRESS_ROWS_OFFSET` bytes and every row uses the C array
/// stride of `size_of::<RawMibUnicastIpAddressRow>()`, which is 80 on both
/// Windows targets. The count bound keeps the multiplication small even on a
/// 32-bit target.
fn unicast_table_length(num_entries: u32) -> Result<usize, PhysicalPathError> {
    let count = num_entries as usize;
    if count > MAX_ADDRESS_ROWS {
        return Err(PhysicalPathError::InvalidObservation(
            "the unicast address table entry count is out of range",
        ));
    }
    ADDRESS_ROWS_OFFSET
        .checked_add(count * size_of::<RawMibUnicastIpAddressRow>())
        .ok_or(PhysicalPathError::InvalidObservation(
            "the unicast address table byte length is out of range",
        ))
}

/// Copy the rows for one interface out of a table buffer.
///
/// The buffer must hold the documented header and `num_entries` rows. A short
/// buffer fails closed instead of reading past its end. The rows start at
/// `ADDRESS_ROWS_OFFSET` and advance by the row size, not by the size of the
/// header struct. Reads use `read_unaligned` because a byte slice has alignment
/// one.
fn unicast_rows_for_interface(
    table: &[u8],
    num_entries: u32,
    interface_luid: u64,
) -> Result<Vec<RawMibUnicastIpAddressRow>, PhysicalPathError> {
    let required = unicast_table_length(num_entries)?;
    if table.len() < required {
        return Err(PhysicalPathError::InvalidObservation(
            "the unicast address table buffer is shorter than its entry count",
        ));
    }
    let stride = size_of::<RawMibUnicastIpAddressRow>();
    let mut addresses = Vec::new();
    for index in 0..num_entries as usize {
        let offset = ADDRESS_ROWS_OFFSET + index * stride;
        // SAFETY: The length check above proves that `offset + stride` is
        // inside `table`. Every bit pattern is valid for this integer row
        // type, and `read_unaligned` does not require an aligned pointer.
        let raw = unsafe {
            ptr::read_unaligned(
                table
                    .as_ptr()
                    .add(offset)
                    .cast::<RawMibUnicastIpAddressRow>(),
            )
        };
        if raw.interface_luid == interface_luid {
            addresses.push(raw);
        }
    }
    Ok(addresses)
}

#[cfg(windows)]
fn read_unicast_addresses(
    interface_luid: u64,
) -> Result<Vec<RawMibUnicastIpAddressRow>, PhysicalPathError> {
    let mut table: *mut RawMibUnicastIpAddressTable = ptr::null_mut();
    // SAFETY: The family is `AF_INET`. The output pointer is valid for one
    // table pointer.
    let status = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if status != ERROR_SUCCESS {
        if !table.is_null() {
            // SAFETY: A failed call must not return a table, but a non-null
            // value is still owned by the IP helper API. Release it.
            unsafe { FreeMibTable(table.cast::<c_void>()) };
        }
        return Err(PhysicalPathError::Api {
            operation: "GetUnicastIpAddressTable",
            code: status,
        });
    }
    if table.is_null() {
        return Err(PhysicalPathError::InvalidObservation(
            "GetUnicastIpAddressTable returned a null table",
        ));
    }

    let result = (|| {
        // SAFETY: The API returned a non-null table. `NumEntries` is the first
        // field of the documented layout.
        let count = unsafe { (*table).num_entries };
        let length = unicast_table_length(count)?;
        // SAFETY: `GetUnicastIpAddressTable` returns a
        // `MIB_UNICASTIPADDRESS_TABLE` with the header and `NumEntries` rows.
        // `length` is exactly that documented size, and the pointer is valid
        // for the whole allocation until `FreeMibTable`.
        let bytes = unsafe { std::slice::from_raw_parts(table.cast::<u8>(), length) };
        unicast_rows_for_interface(bytes, count, interface_luid)
    })();
    // SAFETY: `FreeMibTable` releases a table from the IP helper API. The
    // pointer is non-null and is not used after this call.
    unsafe { FreeMibTable(table.cast::<c_void>()) };
    result
}

fn observed_route(raw: &RawMibIpForwardRow2) -> Result<ObservedRoute, PhysicalPathError> {
    Ok(ObservedRoute {
        prefix: raw.destination_prefix.parse()?,
        interface_index: raw.interface_index,
        interface_luid: raw.interface_luid,
        next_hop: raw.next_hop.ip_address()?,
        metric: raw.metric,
        protocol: raw.protocol as u32,
        loopback: raw.loopback != 0,
    })
}

fn sockaddr_v4(address: Ipv4Addr) -> RawSockaddrInet {
    // Initialize the whole union, not only the 16-byte IPv4 member. The union
    // is 28 bytes because of `SOCKADDR_IN6`, and the pointer is passed to
    // `GetBestInterfaceEx`. Starting from an initialized IPv6 member and then
    // assigning the IPv4 member leaves no uninitialized tail bytes for the FFI
    // call to observe.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_route_verify::AdapterGuid;
    use std::collections::VecDeque;

    const INDEX: u32 = 9;
    const LUID: u64 = 0x0000_6000_0000_0009;

    fn guid(seed: u8) -> AdapterGuid {
        AdapterGuid::new(0x0011_2233, 0x4455, 0x6677, [1, 2, 3, 4, 5, 6, 7, seed])
    }

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

    fn route_row() -> RawMibIpForwardRow2 {
        RawMibIpForwardRow2 {
            interface_luid: LUID,
            interface_index: INDEX,
            destination_prefix: v4_prefix([0, 0, 0, 0], 0),
            next_hop: sockaddr_v4(Ipv4Addr::new(172, 20, 10, 1)),
            site_prefix_length: 0,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            metric: 25,
            protocol: 3,
            loopback: 0,
            autoconfigure_address: 0,
            publish: 0,
            immortal: 0,
            age: 0,
            origin: 0,
        }
    }

    fn address_row(address: Ipv4Addr, length: u8) -> RawMibUnicastIpAddressRow {
        RawMibUnicastIpAddressRow {
            address: sockaddr_v4(address),
            interface_luid: LUID,
            interface_index: INDEX,
            prefix_origin: 1,
            suffix_origin: 1,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            on_link_prefix_length: length,
            skip_as_source: 0,
            padding: [0; 2],
            dad_state: NL_DAD_STATE_PREFERRED,
            scope_id: 0,
            creation_time_stamp: 0,
        }
    }

    fn if_row() -> RawMibIfRow2 {
        let mut row: RawMibIfRow2 = unsafe { std::mem::zeroed() };
        row.interface_luid = LUID;
        row.interface_index = INDEX;
        row.interface_guid = guid(1);
        row.physical_address_length = 6;
        row.physical_address = [
            0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        row.if_type = 71;
        row.tunnel_type = 0;
        row.access_type = 2;
        row.flags = 0x01;
        row.oper_status = 1;
        row.admin_status = 1;
        row.media_connect_state = 1;
        row
    }

    #[test]
    fn the_interface_row_layout_matches_the_windows_headers() {
        assert_eq!(size_of::<RawMibIfRow2>(), 1352);
        assert_eq!(offset_of!(RawMibIfRow2, interface_guid), 12);
        assert_eq!(offset_of!(RawMibIfRow2, physical_address_length), 1056);
        assert_eq!(offset_of!(RawMibIfRow2, if_type), 1128);
        assert_eq!(offset_of!(RawMibIfRow2, flags), 1152);
        assert_eq!(offset_of!(RawMibIfRow2, counters), 1192);
    }

    #[test]
    fn the_unicast_address_row_layout_matches_the_windows_headers() {
        assert_eq!(size_of::<RawMibUnicastIpAddressRow>(), 80);
        assert_eq!(align_of::<RawMibUnicastIpAddressRow>(), 8);
        assert_eq!(offset_of!(RawMibUnicastIpAddressRow, interface_luid), 32);
        assert_eq!(
            offset_of!(RawMibUnicastIpAddressRow, on_link_prefix_length),
            60
        );
        assert_eq!(offset_of!(RawMibUnicastIpAddressRow, skip_as_source), 61);
        assert_eq!(offset_of!(RawMibUnicastIpAddressRow, dad_state), 64);
        assert_eq!(offset_of!(RawMibUnicastIpAddressRow, scope_id), 68);
        assert_eq!(
            offset_of!(RawMibUnicastIpAddressRow, creation_time_stamp),
            72
        );
        assert_eq!(size_of::<RawMibUnicastIpAddressTable>(), 88);
        assert_eq!(ADDRESS_ROWS_OFFSET, 8);
    }

    fn table_with_rows(rows: &[RawMibUnicastIpAddressRow]) -> Vec<u8> {
        // Use the documented literal stride, not `size_of`, so a regression to
        // an 88-byte row fails this test instead of moving with it.
        const ROW_STRIDE: usize = 80;
        assert_eq!(size_of::<RawMibUnicastIpAddressRow>(), ROW_STRIDE);
        let mut buffer = vec![0u8; ADDRESS_ROWS_OFFSET + rows.len() * ROW_STRIDE];
        buffer[..4].copy_from_slice(&(rows.len() as u32).to_ne_bytes());
        for (index, row) in rows.iter().enumerate() {
            let offset = ADDRESS_ROWS_OFFSET + index * ROW_STRIDE;
            let bytes = &mut buffer[offset..offset + ROW_STRIDE];
            // Serialize initialized fields only. Copying the Rust struct as raw
            // bytes would also read union tail and alignment padding.
            bytes[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            bytes[4..8].copy_from_slice(&row.address.ipv4().unwrap().octets());
            bytes[32..40].copy_from_slice(&row.interface_luid.to_ne_bytes());
            bytes[40..44].copy_from_slice(&row.interface_index.to_ne_bytes());
            bytes[44..48].copy_from_slice(&row.prefix_origin.to_ne_bytes());
            bytes[48..52].copy_from_slice(&row.suffix_origin.to_ne_bytes());
            bytes[52..56].copy_from_slice(&row.valid_lifetime.to_ne_bytes());
            bytes[56..60].copy_from_slice(&row.preferred_lifetime.to_ne_bytes());
            bytes[60] = row.on_link_prefix_length;
            bytes[61] = row.skip_as_source;
            bytes[64..68].copy_from_slice(&row.dad_state.to_ne_bytes());
            bytes[68..72].copy_from_slice(&row.scope_id.to_ne_bytes());
            bytes[72..80].copy_from_slice(&row.creation_time_stamp.to_ne_bytes());
        }
        buffer
    }

    #[test]
    fn a_multi_row_unicast_table_uses_the_eighty_byte_stride() {
        let mut first = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        first.scope_id = 0x0bad_f00d;
        first.creation_time_stamp = 11;
        let mut other = address_row(Ipv4Addr::new(172, 20, 10, 3), 28);
        other.interface_luid = LUID + 1;
        other.scope_id = 0x1111_2222;
        other.creation_time_stamp = 22;
        let mut third = address_row(Ipv4Addr::new(172, 20, 10, 4), 28);
        third.scope_id = 0x3333_4444;
        third.creation_time_stamp = 33;

        let buffer = table_with_rows(&[first, other, third]);
        assert_eq!(buffer.len(), ADDRESS_ROWS_OFFSET + 3 * 80);
        let rows = unicast_rows_for_interface(&buffer, 3, LUID).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].scope_id, 0x0bad_f00d);
        assert_eq!(rows[0].creation_time_stamp, 11);
        assert_eq!(rows[0].address.ipv4(), Some(Ipv4Addr::new(172, 20, 10, 2)));
        assert_eq!(rows[1].scope_id, 0x3333_4444);
        assert_eq!(rows[1].creation_time_stamp, 33);
        assert_eq!(rows[1].address.ipv4(), Some(Ipv4Addr::new(172, 20, 10, 4)));
    }

    #[test]
    fn a_short_unicast_table_buffer_is_refused() {
        let row = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        let mut buffer = table_with_rows(&[row, row]);
        buffer.pop();
        let error = unicast_rows_for_interface(&buffer, 2, LUID).err().unwrap();
        assert_eq!(
            error,
            PhysicalPathError::InvalidObservation(
                "the unicast address table buffer is shorter than its entry count"
            )
        );
    }

    #[test]
    fn an_unaligned_unicast_table_slice_is_read_safely() {
        let row = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        let table = table_with_rows(&[row]);
        let mut storage = vec![0u8; table.len() + 8];
        let offset = (0..8)
            .find(|offset| (storage.as_ptr() as usize + offset) & 7 != 0)
            .unwrap();
        storage[offset..offset + table.len()].copy_from_slice(&table);
        let rows =
            unicast_rows_for_interface(&storage[offset..offset + table.len()], 1, LUID).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].address.ipv4(), Some(Ipv4Addr::new(172, 20, 10, 2)));
    }

    #[test]
    fn a_unicast_table_entry_count_above_the_bound_is_refused() {
        let row = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        let buffer = table_with_rows(&[row]);
        let error = unicast_rows_for_interface(&buffer, (MAX_ADDRESS_ROWS + 1) as u32, LUID)
            .err()
            .unwrap();
        assert_eq!(
            error,
            PhysicalPathError::InvalidObservation(
                "the unicast address table entry count is out of range"
            )
        );
    }

    #[test]
    fn one_usable_address_and_one_unusable_row_select_the_usable_row() {
        let mut usable = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        usable.interface_index = INDEX;
        let mut unusable = address_row(Ipv4Addr::new(172, 20, 10, 3), 28);
        unusable.skip_as_source = 1;
        let (address, count) = select_usable_address(&[unusable, usable], LUID, INDEX).unwrap();
        assert_eq!(count, 1);
        assert_eq!(address.address.ipv4(), Some(Ipv4Addr::new(172, 20, 10, 2)));
    }

    #[test]
    fn a_usable_address_with_a_changed_interface_index_is_refused() {
        let mut row = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        row.interface_index = INDEX + 1;
        let error = select_usable_address(&[row], LUID, INDEX).err().unwrap();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
    }

    #[test]
    fn the_usable_ipv4_policy_matches_the_platform_policy() {
        for unusable in [
            "0.0.0.0",
            "0.1.2.3",
            "0.255.255.255",
            "127.0.0.1",
            "127.255.255.254",
            "255.255.255.255",
            "224.0.0.1",
            "239.255.255.250",
            "169.254.10.20",
            "169.254.0.1",
        ] {
            assert!(!is_usable_ipv4(unusable.parse().unwrap()), "{unusable}");
        }
        for usable in ["10.0.0.2", "172.20.10.2", "192.168.1.20", "100.64.0.2"] {
            assert!(is_usable_ipv4(usable.parse().unwrap()), "{usable}");
        }
    }

    #[test]
    fn an_apipa_address_next_to_a_dhcp_address_is_not_counted() {
        for apipa_first in [true, false] {
            let apipa = address_row(Ipv4Addr::new(169, 254, 10, 20), 16);
            let dhcp = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
            let rows = if apipa_first {
                [apipa, dhcp]
            } else {
                [dhcp, apipa]
            };
            let (address, count) = select_usable_address(&rows, LUID, INDEX).unwrap();
            assert_eq!(count, 1, "apipa_first={apipa_first}");
            assert_eq!(
                address.address.ipv4(),
                Some(Ipv4Addr::new(172, 20, 10, 2)),
                "apipa_first={apipa_first}"
            );
        }
    }

    #[test]
    fn an_apipa_address_alone_is_not_a_usable_source() {
        let apipa = address_row(Ipv4Addr::new(169, 254, 10, 20), 16);
        let error = select_usable_address(&[apipa], LUID, INDEX).err().unwrap();
        assert_eq!(
            error,
            PhysicalPathError::AdapterAddressUnusable("the adapter reports no usable IPv4 address")
        );
    }

    #[test]
    fn two_usable_addresses_report_their_real_count() {
        let first = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        let second = address_row(Ipv4Addr::new(172, 20, 10, 3), 28);
        let (address, count) = select_usable_address(&[first, second], LUID, INDEX).unwrap();
        // The reader reports the first row and the measured count. It does not
        // invent a count of one. The pure verifier refuses a count other than
        // one, so conflicting usable addresses are never accepted.
        assert_eq!(count, 2);
        assert_eq!(address.address.ipv4(), Some(Ipv4Addr::new(172, 20, 10, 2)));
        let identity = RetainedAdapterIdentity::new(INDEX, LUID, guid(1)).unwrap();
        let observation = adapter_observation(&if_row(), identity, &address, count).unwrap();
        assert_eq!(observation.usable_ipv4_address_count, 2);
        assert_eq!(
            super::super::validate_adapter(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(
                "the adapter must report exactly one usable IPv4 address"
            )
        );
    }

    #[test]
    fn a_tentative_address_is_not_a_usable_source() {
        let mut tentative = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        tentative.dad_state = 1;
        let error = select_usable_address(&[tentative], LUID, INDEX)
            .err()
            .unwrap();
        assert_eq!(
            error,
            PhysicalPathError::AdapterAddressUnusable("the adapter reports no usable IPv4 address")
        );
    }

    #[test]
    fn the_identity_recheck_after_the_address_table_must_match() {
        let identity = RetainedAdapterIdentity::new(INDEX, LUID, guid(1)).unwrap();
        let same = LiveAdapterIdentity {
            interface_index: INDEX,
            interface_guid: guid(1),
        };
        assert_eq!(confirm_rechecked_identity(identity, same), Ok(()));

        let other_guid = LiveAdapterIdentity {
            interface_index: INDEX,
            interface_guid: guid(2),
        };
        assert_eq!(
            confirm_rechecked_identity(identity, other_guid).unwrap_err(),
            PhysicalPathError::AdapterIdentityChanged
        );

        let other_index = LiveAdapterIdentity {
            interface_index: INDEX + 1,
            interface_guid: guid(1),
        };
        assert_eq!(
            confirm_rechecked_identity(identity, other_index).unwrap_err(),
            PhysicalPathError::AdapterIdentityChanged
        );

        let zero_guid = LiveAdapterIdentity {
            interface_index: INDEX,
            interface_guid: AdapterGuid::ZERO,
        };
        assert_eq!(
            confirm_rechecked_identity(identity, zero_guid).unwrap_err(),
            PhysicalPathError::AdapterIdentityChanged
        );
    }

    #[test]
    fn no_usable_address_is_refused() {
        let mut duplicate = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        duplicate.dad_state = 2;
        let error = select_usable_address(&[duplicate], LUID, INDEX)
            .err()
            .unwrap();
        assert_eq!(
            error,
            PhysicalPathError::AdapterAddressUnusable("the adapter reports no usable IPv4 address")
        );
    }

    #[test]
    fn a_usable_address_on_another_interface_is_not_selected() {
        let mut other = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        other.interface_luid = LUID + 1;
        let error = select_usable_address(&[other], LUID, INDEX).err().unwrap();
        assert_eq!(
            error,
            PhysicalPathError::AdapterAddressUnusable("the adapter reports no usable IPv4 address")
        );
    }

    #[test]
    fn the_interface_flag_byte_uses_the_documented_bits() {
        let mut row = if_row();
        assert!(row.hardware_interface());
        assert!(!row.filter_interface());
        row.flags = 0x02;
        assert!(!row.hardware_interface());
        assert!(row.filter_interface());
        row.flags = 0x03;
        assert!(row.hardware_interface());
        assert!(row.filter_interface());
        row.flags = 0;
        assert!(!row.hardware_interface());
        assert!(!row.filter_interface());
    }

    #[test]
    fn a_nonzero_physical_address_is_present() {
        let mut row = if_row();
        assert!(row.physical_address_nonzero());
        row.physical_address = [0; IF_MAX_PHYS_ADDRESS_LENGTH];
        assert!(!row.physical_address_nonzero());
        row.physical_address_length = 0;
        assert!(!row.physical_address_nonzero());
        row.physical_address_length = 33;
        assert!(!row.physical_address_nonzero());
    }

    #[test]
    fn a_raw_ipv4_route_row_converts_to_native_values() {
        let raw = route_row();
        let route = observed_route(&raw).unwrap();
        assert_eq!(
            route.prefix,
            RoutePrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()
        );
        assert_eq!(route.interface_index, INDEX);
        assert_eq!(route.interface_luid, LUID);
        assert_eq!(route.next_hop, IpAddr::V4(Ipv4Addr::new(172, 20, 10, 1)));
        assert_eq!(route.metric, 25);
        assert_eq!(route.protocol, 3);
        assert!(!route.loopback);
    }

    #[test]
    fn a_raw_row_with_host_bits_is_rejected() {
        let mut raw = route_row();
        raw.destination_prefix = v4_prefix([0, 0, 0, 1], 1);
        assert!(matches!(
            observed_route(&raw).unwrap_err(),
            PhysicalPathError::InvalidObservation(_)
        ));
    }

    #[test]
    fn a_raw_route_with_an_unknown_family_is_rejected() {
        let mut raw = route_row();
        raw.next_hop = RawSockaddrInet {
            v4: RawSockaddrIn {
                family: 99,
                port: 0,
                address: [0; 4],
                zero: [0; 8],
            },
        };
        assert!(matches!(
            observed_route(&raw).unwrap_err(),
            PhysicalPathError::InvalidObservation(_)
        ));
    }

    #[test]
    fn a_raw_unicast_address_keeps_the_prefix() {
        let raw = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        assert_eq!(raw.address.ipv4(), Some(Ipv4Addr::new(172, 20, 10, 2)));
        assert_eq!(raw.on_link_prefix_length, 28);
        assert_eq!(raw.interface_luid, LUID);
        assert_eq!(raw.interface_index, INDEX);
    }

    #[test]
    fn a_raw_address_with_the_wrong_family_is_rejected() {
        let mut raw = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        raw.address = RawSockaddrInet {
            v4: RawSockaddrIn {
                family: 99,
                port: 0,
                address: [0; 4],
                zero: [0; 8],
            },
        };
        assert_eq!(raw.address.ipv4(), None);
        assert!(matches!(
            raw.address.ip_address().unwrap_err(),
            PhysicalPathError::InvalidObservation(_)
        ));
    }

    #[test]
    fn an_adapter_row_converts_to_the_live_observation_shape() {
        let row = if_row();
        let address = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        let identity = RetainedAdapterIdentity::new(INDEX, LUID, guid(1)).unwrap();
        let observation = adapter_observation(&row, identity, &address, 1).unwrap();
        assert_eq!(observation.interface_type, 71);
        assert_eq!(observation.oper_status, 1);
        assert_eq!(observation.admin_status, 1);
        assert_eq!(observation.media_connect_state, 1);
        assert_eq!(observation.access_type, 2);
        assert!(observation.hardware_interface);
        assert!(!observation.filter_interface);
        assert_eq!(observation.physical_address_length, 6);
        assert!(observation.physical_address_nonzero);
        assert_eq!(observation.ipv4_address, Ipv4Addr::new(172, 20, 10, 2));
        assert_eq!(observation.on_link_prefix_length, 28);
        assert_eq!(observation.usable_ipv4_address_count, 1);
    }

    #[test]
    fn the_ipv4_sockaddr_initializes_the_whole_union() {
        let raw = sockaddr_v4(Ipv4Addr::new(172, 20, 10, 1));
        assert_eq!(raw.family(), AF_INET);
        // SAFETY: `sockaddr_v4` initializes every byte of the union before the
        // value is used, and the slice borrows the initialized value.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawSockaddrInet as *const u8,
                size_of::<RawSockaddrInet>(),
            )
        };
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[4..8], &[172, 20, 10, 1]);
        assert!(
            bytes[16..].iter().all(|byte| *byte == 0),
            "the IPv6 tail must be initialized"
        );
    }

    #[test]
    fn an_address_row_with_a_non_ipv4_family_is_not_usable() {
        let mut row = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        row.address = RawSockaddrInet {
            v4: RawSockaddrIn {
                family: 99,
                port: 0,
                address: [172, 20, 10, 2],
                zero: [0; 8],
            },
        };
        let error = select_usable_address(&[row], LUID, INDEX).err().unwrap();
        assert_eq!(
            error,
            PhysicalPathError::AdapterAddressUnusable("the adapter reports no usable IPv4 address")
        );
    }

    #[test]
    fn a_skip_as_source_address_is_not_counted_next_to_a_usable_address() {
        let mut skipped = address_row(Ipv4Addr::new(172, 20, 10, 3), 28);
        skipped.skip_as_source = 1;
        let usable = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        let (address, count) = select_usable_address(&[skipped, usable], LUID, INDEX).unwrap();
        assert_eq!(count, 1);
        assert_eq!(address.address.ipv4(), Some(Ipv4Addr::new(172, 20, 10, 2)));
    }

    #[test]
    fn unusable_lifetime_evidence_refuses_even_with_another_usable_address() {
        for (valid, preferred) in [(0, 0), (120, 0), (0, 1), (10, 11)] {
            let mut stale = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
            stale.valid_lifetime = valid;
            stale.preferred_lifetime = preferred;
            let current = address_row(Ipv4Addr::new(172, 20, 10, 3), 28);
            for rows in [vec![stale], vec![current, stale], vec![stale, current]] {
                assert!(matches!(
                    select_usable_address(&rows, LUID, INDEX),
                    Err(PhysicalPathError::AdapterAddressUnusable(_))
                ));
            }
        }
    }

    #[test]
    fn positive_and_infinite_lifetimes_can_be_selected() {
        for (valid, preferred) in [(1, 1), (100, 10), (u32::MAX, 60), (u32::MAX, u32::MAX)] {
            let mut address = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
            address.valid_lifetime = valid;
            address.preferred_lifetime = preferred;
            assert_eq!(select_usable_address(&[address], LUID, INDEX).unwrap().1, 1);
        }
    }

    #[test]
    fn zero_lifetime_on_an_ineligible_row_does_not_hide_the_usable_row() {
        let current = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        let mut other_luid = address_row(Ipv4Addr::new(172, 20, 10, 3), 28);
        other_luid.interface_luid = LUID + 1;
        other_luid.valid_lifetime = 0;
        let mut skipped = address_row(Ipv4Addr::new(172, 20, 10, 4), 28);
        skipped.skip_as_source = 1;
        skipped.preferred_lifetime = 0;
        let mut tentative = address_row(Ipv4Addr::new(172, 20, 10, 5), 28);
        tentative.dad_state = 1;
        tentative.preferred_lifetime = 0;
        let rows = [current, other_luid, skipped, tentative];
        assert_eq!(select_usable_address(&rows, LUID, INDEX).unwrap().1, 1);
    }

    #[test]
    fn every_non_preferred_dad_state_is_not_usable() {
        for state in [0, 1, 2, 3] {
            let mut row = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
            row.dad_state = state;
            let error = select_usable_address(&[row], LUID, INDEX).err().unwrap();
            assert_eq!(
                error,
                PhysicalPathError::AdapterAddressUnusable(
                    "the adapter reports no usable IPv4 address"
                ),
                "dad_state={state}"
            );
        }
    }

    #[test]
    fn an_address_on_another_luid_does_not_increase_the_count() {
        let mut other = address_row(Ipv4Addr::new(172, 20, 10, 3), 28);
        other.interface_luid = LUID + 1;
        let current = address_row(Ipv4Addr::new(172, 20, 10, 2), 28);
        for rows in [[other, current], [current, other]] {
            let (address, count) = select_usable_address(&rows, LUID, INDEX).unwrap();
            assert_eq!(count, 1);
            assert_eq!(address.address.ipv4(), Some(Ipv4Addr::new(172, 20, 10, 2)));
        }
    }

    #[test]
    fn the_unicast_table_length_accepts_the_bound_and_rejects_one_more() {
        assert_eq!(unicast_table_length(0).unwrap(), ADDRESS_ROWS_OFFSET);
        assert!(unicast_table_length(MAX_ADDRESS_ROWS as u32).is_ok());
        assert_eq!(
            unicast_table_length((MAX_ADDRESS_ROWS + 1) as u32).unwrap_err(),
            PhysicalPathError::InvalidObservation(
                "the unicast address table entry count is out of range"
            )
        );
    }

    #[test]
    fn an_empty_unicast_table_has_no_rows() {
        let buffer = table_with_rows(&[]);
        let rows = unicast_rows_for_interface(&buffer, 0, LUID).unwrap();
        assert!(rows.is_empty());
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AdapterReadCall {
        InterfaceRow(u64),
        LiveIdentity(u64),
        AddressRows(u64),
    }

    struct FakeAdapterReads {
        calls: Vec<AdapterReadCall>,
        rows: VecDeque<Result<RawMibIfRow2, PhysicalPathError>>,
        identities: VecDeque<Result<LiveAdapterIdentity, PhysicalPathError>>,
        tables: VecDeque<Result<Vec<RawMibUnicastIpAddressRow>, PhysicalPathError>>,
    }

    fn fake_adapter_reads() -> FakeAdapterReads {
        FakeAdapterReads {
            calls: Vec::new(),
            rows: VecDeque::from([Ok(if_row())]),
            identities: VecDeque::from([
                Ok(LiveAdapterIdentity {
                    interface_index: INDEX,
                    interface_guid: guid(1),
                }),
                Ok(LiveAdapterIdentity {
                    interface_index: INDEX,
                    interface_guid: guid(1),
                }),
            ]),
            tables: VecDeque::from([Ok(vec![address_row(Ipv4Addr::new(172, 20, 10, 2), 28)])]),
        }
    }

    impl AdapterReadSource for FakeAdapterReads {
        fn read_interface_row(
            &mut self,
            interface_luid: u64,
        ) -> Result<RawMibIfRow2, PhysicalPathError> {
            self.calls
                .push(AdapterReadCall::InterfaceRow(interface_luid));
            self.rows
                .pop_front()
                .expect("the adapter reader read the interface row more than once")
        }

        fn read_live_identity(
            &mut self,
            interface_luid: u64,
        ) -> Result<LiveAdapterIdentity, PhysicalPathError> {
            self.calls
                .push(AdapterReadCall::LiveIdentity(interface_luid));
            self.identities
                .pop_front()
                .expect("the adapter reader read the identity more than twice")
        }

        fn read_address_rows(
            &mut self,
            interface_luid: u64,
        ) -> Result<Vec<RawMibUnicastIpAddressRow>, PhysicalPathError> {
            self.calls
                .push(AdapterReadCall::AddressRows(interface_luid));
            self.tables
                .pop_front()
                .expect("the adapter reader read the address table more than once")
        }
    }

    fn adapter_call(interface_luid: u64) -> AdapterReadCall {
        AdapterReadCall::LiveIdentity(interface_luid)
    }

    #[test]
    fn the_adapter_read_places_the_identity_recheck_after_the_address_table() {
        let mut reads = fake_adapter_reads();
        let observation = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap();
        assert_eq!(observation.usable_ipv4_address_count, 1);
        assert_eq!(
            reads.calls,
            vec![
                AdapterReadCall::InterfaceRow(LUID),
                adapter_call(LUID),
                AdapterReadCall::AddressRows(LUID),
                adapter_call(LUID),
            ]
        );
        assert!(reads.rows.is_empty());
        assert!(reads.identities.is_empty());
        assert!(reads.tables.is_empty());
    }

    #[test]
    fn the_adapter_read_refuses_a_recheck_guid_mismatch_after_the_table() {
        let mut reads = fake_adapter_reads();
        reads.identities.pop_back();
        reads.identities.push_back(Ok(LiveAdapterIdentity {
            interface_index: INDEX,
            interface_guid: guid(2),
        }));
        let error = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap_err();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
        assert_eq!(
            reads.calls,
            vec![
                AdapterReadCall::InterfaceRow(LUID),
                adapter_call(LUID),
                AdapterReadCall::AddressRows(LUID),
                adapter_call(LUID),
            ],
            "the recheck must run after the address table"
        );
        assert!(reads.identities.is_empty());
        assert!(reads.tables.is_empty());
    }

    #[test]
    fn the_adapter_read_refuses_a_recheck_index_mismatch_after_the_table() {
        let mut reads = fake_adapter_reads();
        reads.identities.pop_back();
        reads.identities.push_back(Ok(LiveAdapterIdentity {
            interface_index: INDEX + 1,
            interface_guid: guid(1),
        }));
        let error = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap_err();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
        assert_eq!(reads.calls.len(), 4);
        assert!(reads.calls.contains(&AdapterReadCall::AddressRows(LUID)));
    }

    #[test]
    fn the_adapter_read_refuses_a_zero_guid_recheck_after_the_table() {
        let mut reads = fake_adapter_reads();
        reads.identities.pop_back();
        reads.identities.push_back(Ok(LiveAdapterIdentity {
            interface_index: INDEX,
            interface_guid: AdapterGuid::ZERO,
        }));
        let error = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap_err();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
        assert!(reads.calls.contains(&AdapterReadCall::AddressRows(LUID)));
    }

    #[test]
    fn the_adapter_read_refuses_a_mismatch_before_the_address_table() {
        let mut reads = fake_adapter_reads();
        reads.identities.pop_front();
        reads.identities.push_front(Ok(LiveAdapterIdentity {
            interface_index: INDEX,
            interface_guid: guid(2),
        }));
        let error = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap_err();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
        assert_eq!(
            reads.calls,
            vec![AdapterReadCall::InterfaceRow(LUID), adapter_call(LUID),]
        );
        assert_eq!(reads.identities.len(), 1);
        assert_eq!(reads.tables.len(), 1);
    }

    #[test]
    fn the_adapter_read_refuses_a_row_luid_mismatch_before_any_identity_read() {
        let mut reads = fake_adapter_reads();
        reads.rows.pop_front();
        let mut row = if_row();
        row.interface_luid = LUID + 1;
        reads.rows.push_front(Ok(row));
        let error = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap_err();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
        assert_eq!(reads.calls, vec![AdapterReadCall::InterfaceRow(LUID)]);
        assert_eq!(reads.identities.len(), 2);
        assert_eq!(reads.tables.len(), 1);
    }

    #[test]
    fn the_adapter_read_refuses_a_row_index_mismatch_before_any_identity_read() {
        let mut reads = fake_adapter_reads();
        reads.rows.pop_front();
        let mut row = if_row();
        row.interface_index = INDEX + 1;
        reads.rows.push_front(Ok(row));
        let error = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap_err();
        assert_eq!(error, PhysicalPathError::AdapterIdentityChanged);
        assert_eq!(reads.calls, vec![AdapterReadCall::InterfaceRow(LUID)]);
        assert_eq!(reads.identities.len(), 2);
        assert_eq!(reads.tables.len(), 1);
    }

    #[test]
    fn the_adapter_read_refuses_a_zero_guid_row_before_any_identity_read() {
        let mut reads = fake_adapter_reads();
        reads.rows.pop_front();
        let mut row = if_row();
        row.interface_guid = AdapterGuid::ZERO;
        reads.rows.push_front(Ok(row));
        let error = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap_err();
        assert_eq!(
            error,
            PhysicalPathError::InvalidObservation("GetIfEntry2 returned the zero GUID")
        );
        assert_eq!(reads.calls, vec![AdapterReadCall::InterfaceRow(LUID)]);
        assert_eq!(reads.identities.len(), 2);
        assert_eq!(reads.tables.len(), 1);
    }

    #[test]
    fn the_adapter_read_stops_before_the_recheck_when_the_table_read_fails() {
        let mut reads = fake_adapter_reads();
        reads.tables.pop_front();
        reads
            .tables
            .push_front(Err(PhysicalPathError::InvalidObservation(
                "test table failure",
            )));
        let error = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap_err();
        assert_eq!(
            error,
            PhysicalPathError::InvalidObservation("test table failure")
        );
        assert_eq!(
            reads.calls,
            vec![
                AdapterReadCall::InterfaceRow(LUID),
                adapter_call(LUID),
                AdapterReadCall::AddressRows(LUID),
            ]
        );
        assert_eq!(reads.identities.len(), 1);
    }

    #[test]
    fn the_adapter_read_preserves_two_usable_addresses_for_the_pure_check() {
        let mut reads = fake_adapter_reads();
        reads.tables.pop_front();
        reads.tables.push_front(Ok(vec![
            address_row(Ipv4Addr::new(172, 20, 10, 2), 28),
            address_row(Ipv4Addr::new(172, 20, 10, 3), 28),
        ]));
        let observation = read_adapter_with_source(&mut reads, LUID, INDEX).unwrap();
        assert_eq!(observation.usable_ipv4_address_count, 2);
        assert_eq!(
            super::super::validate_adapter(&observation).unwrap_err(),
            PhysicalPathError::AdapterAddressUnusable(
                "the adapter must report exactly one usable IPv4 address"
            )
        );
    }

    #[test]
    fn an_api_error_names_the_operation_and_code_without_identity() {
        for operation in [
            "GetBestInterfaceEx",
            "GetBestRoute2",
            "GetIfEntry2",
            "GetUnicastIpAddressTable",
        ] {
            let error = PhysicalPathError::Api {
                operation,
                code: 87,
            };
            assert_eq!(
                error.to_string(),
                format!("{operation} failed with Windows error 87")
            );
            assert_eq!(
                format!("{error:?}"),
                format!("Api {{ operation: \"{operation}\", code: 87 }}")
            );
        }
        let unknown = PhysicalPathError::Api {
            operation: "172.20.10.1",
            code: 87,
        };
        assert_eq!(
            unknown.to_string(),
            "the physical route evidence was refused"
        );
        assert_eq!(format!("{unknown:?}"), "Api(<redacted>)");
    }
}
