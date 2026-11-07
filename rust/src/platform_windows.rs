//! Windows Wintun device, interface, and route lifecycle.
//!
//! The caller owns the relay loop. Keep the tunnel and route manager alive for
//! the full relay lifetime. Stop the relay before dropping them.
//!
//! Routes must go before the device. A [`RouteManager`] or [`Ipv6Tunnel`]
//! checks the retained LUID and GUID before it deletes anything. When the
//! adapter is gone, Windows has removed its routes. The manager then sends no
//! delete command, because Windows can reuse an interface index or a LUID for
//! another adapter. This check limits the damage of a wrong drop order. It does
//! not replace the correct order.
//!
//! Wintun delivers raw IP frames without an Ethernet header. The adapter is a
//! layer 3 device. Read and write one IP packet per call.
//!
//! `wintun.dll` is not bundled. Install it next to the `hotspotshade` binary.
//! The loader uses that absolute path and safe dependency search flags. It does
//! not search the current directory or `PATH`, and it fails closed when the DLL
//! is missing or cannot load.
//!
//! Treat the install directory as trusted. A person who can replace
//! `wintun.dll` in that directory can run code as this process. Only an
//! administrator must be able to write to that directory.
//!
//! # Physical link observation
//!
//! [`physical_link_observation`] is a read-only, one-shot check. It resolves one
//! interface alias or index to a LUID and GUID, holds that pair for the read,
//! and proves it again after it reads the interface and IPv4 tables. It reads
//! the legacy `MIB_IFROW.dwAdminStatus` and `MIB_IFROW.dwOperStatus` enums. A
//! `CONNECTED` or `OPERATIONAL` interface with a usable IPv4 address is up. A
//! documented down state is down. An API failure, an ambiguous target, a target
//! that no longer resolves, or an inconsistent identity is unknown, so the
//! policy never invents link loss.
//!
//! A one-shot read cannot prove that an alias still names the interface it
//! named on an earlier sample. A rename looks like an absent alias, and a
//! reused alias looks like a different interface. [`RetainedPhysicalLinkObserver`]
//! is the seam for a caller that binds once after it selects the physical
//! interface and keeps the LUID and GUID for the tunnel lifetime. The Windows
//! direct start binds the exact index, LUID, and GUID from its outer adapter
//! proof behind the closed direct evidence gate. The relay pins that start
//! index, so the direct worker calls [`RetainedPhysicalLinkObserver::observe_sample`]
//! and stops at once when the retained adapter moves to another index or is
//! gone. The CLI and GUI auto-stop path still does not use it:
//! `autostop::link_observation` returns `Unsupported` on Windows and the GUI
//! maps that to unknown. That gate stays in place until an independent review
//! and a native Windows test pass. Do not describe Windows auto-stop as
//! working.
//!
//! The result says nothing about which interface is the hotspot, and a link-up
//! result does not prove that the internet works. It creates no device and
//! changes no route. No live Windows host has verified it yet.
//!
//! Every child process removes `HOTSPOTSHADE_PHONE_TOKEN` from its environment.
//! A route or link command never inherits the source device token.
//!
//! The tunnel relay uses these helpers in source device proxy mode. A live
//! Windows tunnel test is still needed. `rust-windows` CI compiles this module
//! and runs the hermetic tests. Do not read that CI result as proof that a live
//! Windows tunnel works.
//!
//! # Adapter ownership
//!
//! Wintun source, `api/adapter.c`, `NciSetAdapterName`: when the requested name
//! is in use, Wintun renames the adapter that holds the name to
//! `"<Name> <n>"`, then gives the new adapter the requested name. A program
//! that creates an adapter must not depend on the requested name being free.
//! This module does four things:
//!
//! 1. Check the name and the deterministic GUID before the create call, and
//!    fail closed when either is in use.
//! 2. Use a name format that the Wintun suffix code never makes. The Wintun
//!    suffix always adds a space before the number. The names in
//!    [`adapter_name`] use a hyphen and have no space.
//! 3. Read the LUID from the created handle and prove that the name maps back
//!    to the same LUID.
//! 4. Read the GUID from the LUID and compare it with the deterministic GUID.
//!    The LUID and the GUID form the ownership state.
//!
//! The GUID is deterministic for a unit. A new adapter for the same unit has
//! the same GUID. The ownership check rejects a foreign adapter. It cannot tell
//! a replacement for the same unit apart.
//!
//! On any mismatch, close the adapter that this call created. This program does
//! not rename or delete another adapter.
//!
//! Windows can reuse a `NET_LUID` after an adapter is removed. A LUID lookup
//! alone can therefore name a foreign adapter. Every `netsh` link and route
//! command resolves the interface index and the GUID from the retained LUID.
//! Both values must match the ownership state. When a lookup fails or the GUID
//! differs, the command does not run, and a route record stays for a later
//! attempt.
//!
//! The name check and the create call are separate. A foreign adapter can take
//! the name between them, and Wintun then renames it. The Wintun API cannot
//! close this window. Report the window. Do not describe the create as atomic.
//! Do not claim that a failed start changed no other adapter.
//!
//! The ownership check and a `netsh` command are also separate. Windows can
//! remove the adapter and reuse the LUID between them. A separate `netsh`
//! process cannot make the command atomic. This code narrows the window and
//! fails closed, but it does not prove full atomic ownership. Do not describe
//! configure, install, or delete as atomic.

use crate::windows_route_verify::{
    Ipv6RoutePolicy, LiveAdapterIdentity, RetainedAdapterIdentity, RouteProof, RouteVerifyError,
    TunnelIdentity, VerifyPolicy,
};
use std::ffi::{c_void, OsStr};
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_BAD_EXE_FORMAT: u32 = 193;
const ERROR_NO_DATA: u32 = 232;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_NOT_FOUND: u32 = 1168;
/// The environment variable that carries a source device token on the command
/// line. A child process must never inherit it.
const PHONE_TOKEN_ENV: &str = "HOTSPOTSHADE_PHONE_TOKEN";
const SESSION_CAPACITY: u32 = 0x40_0000;
const TUNNEL_MTU: usize = 1500;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xffff_ffff;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
/// Search only the directory that holds the loaded DLL and `System32`.
/// Do not add `LOAD_LIBRARY_SEARCH_USER_DIRS`, `PATH`, or the current directory.
const SECURE_LOAD_FLAGS: u32 = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
const MAX_EXECUTABLE_PATH: usize = 32768;
/// `IF_MAX_STRING_SIZE` is 256. The alias buffer includes the terminating zero.
const MAX_INTERFACE_ALIAS: usize = 257;
/// `MAX_INTERFACE_NAME_LEN` from `ipmib.h`.
const MAX_INTERFACE_NAME_LEN: usize = 256;
/// `MAXLEN_PHYSADDR` from `ipmib.h`.
const MAXLEN_PHYSADDR: usize = 8;
/// `MAXLEN_IFDESCR` from `ipmib.h`.
const MAXLEN_IFDESCR: usize = 256;
/// `MIB_IF_ADMIN_STATUS_UP` from `ipmib.h`. This is the administrative status
/// enum. It is not the operational status enum.
const MIB_IF_ADMIN_STATUS_UP: u32 = 1;
/// `MIB_IF_ADMIN_STATUS_DOWN` from `ipmib.h`.
const MIB_IF_ADMIN_STATUS_DOWN: u32 = 2;
/// `MIB_IF_OPER_STATUS_*` from `ipmib.h`. `MIB_IFROW.dwOperStatus` uses this
/// legacy enum, not `IF_OPER_STATUS` from `ifdef.h`. The values differ, so a
/// comparison against `IF_OPER_STATUS` would report a healthy interface as
/// down.
const MIB_IF_OPER_STATUS_NON_OPERATIONAL: u32 = 0;
const MIB_IF_OPER_STATUS_UNREACHABLE: u32 = 1;
const MIB_IF_OPER_STATUS_DISCONNECTED: u32 = 2;
const MIB_IF_OPER_STATUS_CONNECTING: u32 = 3;
const MIB_IF_OPER_STATUS_CONNECTED: u32 = 4;
const MIB_IF_OPER_STATUS_OPERATIONAL: u32 = 5;

type Handle = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl Guid {
    const ZERO: Self = Self {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// Return the equivalent read-only route verification GUID.
    fn route_verify_guid(self) -> crate::windows_route_verify::AdapterGuid {
        crate::windows_route_verify::AdapterGuid::new(
            self.data1, self.data2, self.data3, self.data4,
        )
    }
}

const _: () = {
    assert!(std::mem::size_of::<Guid>() == 16);
    assert!(std::mem::align_of::<Guid>() == 4);
};

/// The Windows `MIB_IFROW` layout from `ipmib.h`.
///
/// `GetIfEntry` fills this structure. Every field is a 32-bit value, a 16-bit
/// value, or a byte array, so the layout is the same on x86 and x64. The
/// compile-time size check catches a wrong field list before it can read a
/// status from the wrong offset. The observer reads only the index and the two
/// status values. The other fields exist because the Windows ABI requires the
/// full structure.
#[repr(C)]
#[allow(dead_code)]
struct MibIfRow {
    name: [u16; MAX_INTERFACE_NAME_LEN],
    index: u32,
    kind: u32,
    mtu: u32,
    speed: u32,
    phys_addr_len: u32,
    phys_addr: [u8; MAXLEN_PHYSADDR],
    admin_status: u32,
    oper_status: u32,
    last_change: u32,
    in_octets: u32,
    in_ucast_pkts: u32,
    in_nucast_pkts: u32,
    in_discards: u32,
    in_errors: u32,
    in_unknown_protos: u32,
    out_octets: u32,
    out_ucast_pkts: u32,
    out_nucast_pkts: u32,
    out_discards: u32,
    out_errors: u32,
    out_qlen: u32,
    descr_len: u32,
    descr: [u8; MAXLEN_IFDESCR],
}

/// The Windows `MIB_IPADDRROW` layout from `ipmib.h`.
///
/// `GetIpAddrTable` returns a `MIB_IPADDRTABLE` with a 4-byte row count and
/// then this 24-byte row for each IPv4 address. `address` is in network byte
/// order. `index` is the interface index. `w_type` holds the address flags.
/// The other fields exist because the Windows ABI requires the full row.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct MibIpAddrRow {
    address: u32,
    index: u32,
    mask: u32,
    broadcast: u32,
    reasm_size: u32,
    unused: u16,
    /// `MIB_IPADDRROW.wType`: the address flags.
    w_type: u16,
}

/// `MIB_IPADDRROW.wType` flags from `ipmib.h`. A transient, deleted, or
/// disconnected address cannot carry traffic for the interface. Counting one as
/// usable could keep a stale address alive after the link lost its lease.
const MIB_IPADDR_DISCONNECTED: u16 = 0x0008;
const MIB_IPADDR_DELETED: u16 = 0x0040;
const MIB_IPADDR_TRANSIENT: u16 = 0x0080;

/// The largest IPv4 address table that the observer accepts. A normal table is a
/// few kilobytes. A much larger reported size is a failed or hostile read, so
/// cap the allocation instead of trusting the API size.
const MAX_IPV4_ADDRESS_TABLE_BYTES: usize = 1 << 20;
const MAX_IPV4_ADDRESS_ROWS: usize =
    (MAX_IPV4_ADDRESS_TABLE_BYTES - 4) / mem::size_of::<MibIpAddrRow>();

// `GetIfEntry` reads and writes a fixed `MIB_IFROW`. Check the total size, the
// alignment, and the field offsets that the observer reads against the header
// on both supported architectures.
const _: () = {
    assert!(mem::size_of::<MibIfRow>() == 860);
    assert!(mem::align_of::<MibIfRow>() == 4);
    assert!(mem::offset_of!(MibIfRow, index) == 512);
    assert!(mem::offset_of!(MibIfRow, admin_status) == 540);
    assert!(mem::offset_of!(MibIfRow, oper_status) == 544);
    assert!(mem::size_of::<MibIpAddrRow>() == 24);
    assert!(mem::align_of::<MibIpAddrRow>() == 4);
    assert!(mem::offset_of!(MibIpAddrRow, address) == 0);
    assert!(mem::offset_of!(MibIpAddrRow, index) == 4);
    assert!(mem::offset_of!(MibIpAddrRow, w_type) == 22);
};

type WintunCreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const Guid) -> Handle;
type WintunCloseAdapterFn = unsafe extern "system" fn(Handle);
/// `NET_LUID` is an unsigned 64-bit value.
type WintunGetAdapterLuidFn = unsafe extern "system" fn(Handle, *mut u64);
type WintunStartSessionFn = unsafe extern "system" fn(Handle, u32) -> Handle;
type WintunEndSessionFn = unsafe extern "system" fn(Handle);
type WintunGetReadWaitEventFn = unsafe extern "system" fn(Handle) -> Handle;
type WintunReceivePacketFn = unsafe extern "system" fn(Handle, *mut u32) -> *mut u8;
type WintunReleaseReceivePacketFn = unsafe extern "system" fn(Handle, *const u8);
type WintunAllocateSendPacketFn = unsafe extern "system" fn(Handle, u32) -> *mut u8;
type WintunSendPacketFn = unsafe extern "system" fn(Handle, *const u8);

struct WintunApi {
    create_adapter: WintunCreateAdapterFn,
    close_adapter: WintunCloseAdapterFn,
    get_adapter_luid: WintunGetAdapterLuidFn,
    start_session: WintunStartSessionFn,
    end_session: WintunEndSessionFn,
    read_wait_event: WintunGetReadWaitEventFn,
    receive_packet: WintunReceivePacketFn,
    release_receive_packet: WintunReleaseReceivePacketFn,
    allocate_send_packet: WintunAllocateSendPacketFn,
    send_packet: WintunSendPacketFn,
}

// The loaded function pointers are process-wide. Wintun is thread safe after
// the adapter and session exist. The caller owns one session on one thread.
unsafe impl Send for WintunApi {}
unsafe impl Sync for WintunApi {}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetLastError() -> u32;
    fn GetModuleFileNameW(module: Handle, name: *mut u16, size: u32) -> u32;
    fn GetSystemDirectoryW(name: *mut u16, size: u32) -> u32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetBestInterface(destination: u32, index: *mut u32) -> u32;
    fn ConvertInterfaceAliasToLuid(alias: *const u16, luid: *mut u64) -> u32;
    fn ConvertInterfaceGuidToLuid(guid: *const Guid, luid: *mut u64) -> u32;
    fn ConvertInterfaceIndexToLuid(index: u32, luid: *mut u64) -> u32;
    fn ConvertInterfaceLuidToAlias(luid: *const u64, alias: *mut u16, length: usize) -> u32;
    fn ConvertInterfaceLuidToGuid(luid: *const u64, guid: *mut Guid) -> u32;
    fn ConvertInterfaceLuidToIndex(luid: *const u64, index: *mut u32) -> u32;
    fn GetIfEntry(row: *mut MibIfRow) -> u32;
    fn GetIpAddrTable(table: *mut c_void, size: *mut u32, order: i32) -> u32;
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Select the DLL path. The DLL must sit next to the executable.
///
/// The loader trusts this directory. An attacker who can write `wintun.dll`
/// there can run code as this process. Install the binary in a directory that
/// only an administrator can write.
fn wintun_path(executable: &Path) -> io::Result<PathBuf> {
    if !executable.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the executable path must be absolute",
        ));
    }
    let directory = executable
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the executable path has no directory",
            )
        })?;
    Ok(directory.join("wintun.dll"))
}

/// Return the default Wintun path next to the executable.
///
/// The path is absolute. The DLL is never bundled and is never committed to
/// the repository. The caller must install it in this directory before a
/// tunnel start.
pub fn default_wintun_path() -> io::Result<PathBuf> {
    wintun_path(&executable_path()?)
}

/// Check an explicit Wintun path.
///
/// The path must be absolute and the file name must be `wintun.dll`. This
/// keeps the loader from accepting an arbitrary DLL name. The file may be
/// absent. The load call then reports a plain not-found error.
pub fn valid_wintun_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the wintun.dll path must be absolute",
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the wintun.dll path must name a file",
            )
        })?;
    if !name.eq_ignore_ascii_case("wintun.dll") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the wintun path must name wintun.dll",
        ));
    }
    Ok(())
}

fn executable_path() -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0u16; MAX_EXECUTABLE_PATH];
    let length =
        unsafe { GetModuleFileNameW(ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize >= buffer.len() {
        return Err(io::Error::other("the executable path is too long"));
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize]));
    if !path.is_absolute() {
        return Err(io::Error::other(
            "the executable path is not absolute, so wintun.dll is not loaded",
        ));
    }
    Ok(path)
}

/// Select a tool in a trusted system directory. The tool argument must be one
/// plain file name. This prevents a current-directory or `PATH` lookup.
fn system_tool_path(tool: &str, system_directory: &Path) -> io::Result<PathBuf> {
    if !system_directory.is_absolute() || system_directory.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the system directory must be absolute",
        ));
    }
    let candidate = Path::new(tool);
    let mut components = candidate.components();
    let single = matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if tool.is_empty()
        || !tool.to_ascii_lowercase().ends_with(".exe")
        || tool.contains(':')
        || tool.chars().any(char::is_control)
        || !single
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the tool name must be one plain executable file name",
        ));
    }
    Ok(system_directory.join(tool))
}

fn system_directory() -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0u16; MAX_EXECUTABLE_PATH];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize >= buffer.len() {
        return Err(io::Error::other("the system directory path is too long"));
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize]));
    if !path.is_absolute() {
        return Err(io::Error::other(
            "the system directory path is not absolute",
        ));
    }
    Ok(path)
}

fn netsh_path() -> io::Result<PathBuf> {
    let path = system_tool_path("netsh.exe", &system_directory()?)?;
    let metadata = std::fs::metadata(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot read {}: {}", path.display(), error),
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::other("the netsh path is not a file"));
    }
    Ok(path)
}

/// Bounds for the wait until a new adapter enters the interface table.
const ADAPTER_READY_ATTEMPTS: usize = 40;
const ADAPTER_READY_DELAY: Duration = Duration::from_millis(50);

/// Convert the adapter LUID to an interface index. Retry a bounded number of
/// times while Windows registers the new adapter.
///
/// The LUID comes from the created handle. At this point it names the new
/// adapter. Do not use this lookup alone as later ownership proof: Windows can
/// reuse a LUID. The ownership check also compares the GUID. A name lookup
/// could match a different adapter that has the same name.
fn adapter_index(luid: u64) -> io::Result<u32> {
    adapter_index_with(
        luid,
        ADAPTER_READY_ATTEMPTS,
        ADAPTER_READY_DELAY,
        interface_index_from_luid,
    )
}

fn adapter_index_with<F>(
    luid: u64,
    attempts: usize,
    delay: Duration,
    mut convert: F,
) -> io::Result<u32>
where
    F: FnMut(u64) -> io::Result<u32>,
{
    let attempts = attempts.max(1);
    let mut last = None;
    for attempt in 0..attempts {
        match convert(luid) {
            Ok(index) => return Ok(index),
            Err(error) => last = Some(error),
        }
        if attempt + 1 < attempts {
            std::thread::sleep(delay);
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("the tunnel adapter has no interface index")))
}

fn interface_index_from_luid(luid: u64) -> io::Result<u32> {
    let mut index: u32 = 0;
    let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if !valid_interface_index(index) {
        return Err(io::Error::other(
            "the tunnel adapter interface index is invalid",
        ));
    }
    Ok(index)
}

/// The identity that this program retains for its adapter.
///
/// The LUID and the GUID come from the adapter that
/// `WintunCreateAdapter` returned and the deterministic GUID that this program
/// passed to that call. Windows can reuse a LUID after an adapter is removed.
/// The GUID proves that the LUID still names an adapter for this tunnel unit.
/// A new adapter for the same unit has the same GUID. This check rejects a
/// foreign adapter. It does not prove that this process created the adapter in
/// this run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AdapterOwnership {
    identity: TunnelIdentity,
    guid: Guid,
}

/// Reject an ownership value that cannot name one adapter.
fn validate_ownership(ownership: AdapterOwnership) -> io::Result<()> {
    if !valid_interface_index(ownership.identity.interface_index) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index must be a nonzero 24-bit number",
        ));
    }
    if ownership.identity.interface_luid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface LUID must be nonzero",
        ));
    }
    if ownership.guid.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface GUID must be nonzero",
        ));
    }
    Ok(())
}

/// Read the interface GUID that Windows registered for this LUID.
///
/// The lookup is read-only. `Ok(None)` means that no interface has this LUID.
/// An access or buffer error is not "absent". The caller must fail closed.
fn interface_guid_from_luid(luid: u64) -> io::Result<Option<Guid>> {
    let mut guid = Guid::ZERO;
    let status = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if !interface_lookup_result(status)? {
        return Ok(None);
    }
    Ok(Some(guid))
}

/// Return the interface index, or `Ok(None)` for a documented not-found code.
fn interface_index_lookup(luid: u64) -> io::Result<Option<u32>> {
    match interface_index_from_luid(luid) {
        Ok(index) => Ok(Some(index)),
        Err(error) if interface_is_absent(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Decide whether the two lookups prove ownership of the adapter.
///
/// Both lookups must agree. A present index with a different GUID means that
/// Windows reused the LUID for another adapter. A present index without a GUID,
/// or a present GUID without an index, is not proof of ownership. Every such
/// case fails closed, so a caller cannot delete a route on a foreign adapter.
///
/// This function is pure. It reads no interface. The caller reads the values.
fn ownership_from_lookups(
    ownership: AdapterOwnership,
    index: Option<u32>,
    guid: Option<Guid>,
) -> io::Result<Option<u32>> {
    validate_ownership(ownership)?;
    let luid = ownership.identity.interface_luid;
    match (index, guid) {
        (None, None) => Ok(None),
        (Some(index), Some(guid)) => {
            if !valid_interface_index(index) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the interface resolver returned an invalid index",
                ));
            }
            if guid != ownership.guid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the retained LUID {luid} now belongs to a different adapter; this program does not change that adapter"
                    ),
                ));
            }
            Ok(Some(index))
        }
        (Some(_), None) => Err(io::Error::other(format!(
            "cannot prove adapter ownership: the interface index for LUID {luid} exists but its GUID is not available"
        ))),
        (None, Some(_)) => Err(io::Error::other(format!(
            "cannot prove adapter ownership: the GUID for LUID {luid} exists but its interface index is not available"
        ))),
    }
}

/// Resolve the current index and prove that the retained GUID still belongs
/// to the retained LUID.
///
/// The resolver reads both values from Windows. A mismatch or an incomplete
/// answer is an error, so the caller must not run a command for this adapter.
fn resolve_owned_index(
    resolver: &dyn InterfaceResolver,
    ownership: AdapterOwnership,
) -> io::Result<Option<u32>> {
    validate_ownership(ownership)?;
    let luid = ownership.identity.interface_luid;
    let index = resolver.index_for_luid(luid)?;
    let guid = resolver.guid_for_luid(luid)?;
    ownership_from_lookups(ownership, index, guid)
}

/// Fail when an interface already uses this name.
///
/// `WintunCreateAdapter` renames another adapter when the requested name is in
/// use. This program must not rename an adapter that it does not own. Check the
/// name first and fail closed.
fn ensure_no_interface_named_with<F>(name: &str, mut exists: F) -> io::Result<()>
where
    F: FnMut(&str) -> io::Result<bool>,
{
    if exists(name)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "an interface named {name} already exists; this program does not rename or remove it, so remove it or start the tunnel with another unit"
            ),
        ));
    }
    Ok(())
}

/// Fail when an adapter with this GUID already exists.
///
/// The GUID is derived from the unit name. A match means that an adapter for
/// this unit is still present, usually after a crash. This program did not
/// create that adapter in this run, so it must not close or rename it.
fn ensure_no_adapter_with_guid_with<F>(name: &str, mut exists: F) -> io::Result<()>
where
    F: FnMut() -> io::Result<bool>,
{
    if exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "an adapter with the saved GUID for {name} already exists; this program does not remove it, so remove it before you start the tunnel"
            ),
        ));
    }
    Ok(())
}

/// Interpret the result of an interface-table lookup.
///
/// Microsoft documents `ERROR_INVALID_PARAMETER` for these lookups and does
/// not document a separate not-found code. The name, LUID, and GUID are valid
/// before the call. Treat that code as "no interface with this value". Do not
/// treat an access or buffer error as "free": a present interface returns
/// status 0, so any other error stops the operation.
fn interface_lookup_result(status: u32) -> io::Result<bool> {
    match status {
        0 => Ok(true),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_NOT_FOUND | ERROR_INVALID_PARAMETER => {
            Ok(false)
        }
        _ => Err(io::Error::from_raw_os_error(status as i32)),
    }
}

fn interface_alias_luid(name: &str) -> io::Result<Option<u64>> {
    let name = wide(name);
    let mut luid: u64 = 0;
    let status = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) };
    if !interface_lookup_result(status)? {
        return Ok(None);
    }
    if luid == 0 {
        return Err(io::Error::other("the interface alias has a zero LUID"));
    }
    Ok(Some(luid))
}

fn interface_alias_exists(name: &str) -> io::Result<bool> {
    interface_alias_luid(name).map(|luid| luid.is_some())
}

fn interface_guid_exists(guid: &Guid) -> io::Result<bool> {
    let mut luid: u64 = 0;
    let status = unsafe { ConvertInterfaceGuidToLuid(guid, &mut luid) };
    if !interface_lookup_result(status)? {
        return Ok(false);
    }
    if luid == 0 {
        return Err(io::Error::other("the interface GUID has a zero LUID"));
    }
    Ok(true)
}

/// Read the alias that Windows registered for this LUID.
///
/// The LUID comes from the created adapter handle and never from a name. The
/// answer is used to prove that the name and the LUID identify one adapter.
fn interface_alias_from_luid(luid: u64) -> io::Result<String> {
    let mut buffer = vec![0u16; MAX_INTERFACE_ALIAS];
    let status = unsafe { ConvertInterfaceLuidToAlias(&luid, buffer.as_mut_ptr(), buffer.len()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

/// Validate the adapter that `WintunCreateAdapter` returned.
///
/// `actual_alias` is the alias that the interface table reports for the
/// retained LUID. `actual_guid` is the GUID that the table reports for the same
/// LUID. `named_luid` is the LUID that the table reports for the requested
/// name. The three values must agree with the ownership state.
///
/// This function is pure. It reads no interface. The caller reads the values.
fn verify_created_adapter(
    requested: &str,
    ownership: AdapterOwnership,
    actual_alias: Option<&str>,
    named_luid: Option<u64>,
    actual_guid: Option<&Guid>,
) -> io::Result<()> {
    validate_ownership(ownership)?;
    let luid = ownership.identity.interface_luid;
    let Some(actual_alias) = actual_alias else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the created adapter has no interface alias",
        ));
    };
    if !actual_alias.eq_ignore_ascii_case(requested) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "Windows registered the new adapter as {actual_alias}, not {requested}; the program closed the new adapter. Wintun can rename an adapter that holds the requested name"
            ),
        ));
    }
    let Some(actual_guid) = actual_guid else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the created adapter has no interface GUID; the program closed the new adapter",
        ));
    };
    if *actual_guid != ownership.guid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the created adapter has a different GUID from the saved GUID; the program closed the new adapter",
        ));
    }
    if named_luid != Some(luid) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "the interface name {requested} does not map back to the new adapter; the program closed the new adapter. Wintun can rename an adapter that holds the requested name"
            ),
        ));
    }
    Ok(())
}

/// Return the interface index that currently belongs to the retained adapter.
///
/// The LUID and the GUID are stable for the life of the adapter. The index is
/// not. Windows can change the index after a link change, and it can reuse an
/// old index or LUID for another adapter. Every operation must resolve both
/// values again and compare the GUID with the retained GUID.
fn current_index_for_ownership(ownership: AdapterOwnership) -> io::Result<Option<u32>> {
    resolve_owned_index(&SystemResolver, ownership)
}

/// Return true when Windows reports that the retained LUID names no interface.
///
/// Microsoft documents `ERROR_INVALID_PARAMETER` for an invalid LUID. The
/// ownership check still requires both the index and the GUID lookup to report
/// absence before it clears a record, so this result never authorizes a delete.
fn interface_is_absent(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == ERROR_FILE_NOT_FOUND as i32
            || code == ERROR_PATH_NOT_FOUND as i32
            || code == ERROR_NOT_FOUND as i32
            || code == ERROR_INVALID_PARAMETER as i32
    )
}

/// A DLL load failure that can be cached and reported again.
struct ApiError {
    kind: io::ErrorKind,
    message: String,
}

impl ApiError {
    fn from_io(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

/// Keep the original cause of a load failure. A missing file, a permission
/// error, and a wrong-architecture DLL are different problems. Do not report
/// all of them as a missing file.
fn dll_error_kind(code: u32) -> io::ErrorKind {
    match code {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_MOD_NOT_FOUND => {
            io::ErrorKind::NotFound
        }
        ERROR_ACCESS_DENIED => io::ErrorKind::PermissionDenied,
        ERROR_BAD_EXE_FORMAT => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    }
}

fn dll_load_error(path: &Path, code: u32) -> ApiError {
    let error = io::Error::from_raw_os_error(code as i32);
    ApiError {
        kind: dll_error_kind(code),
        message: format!("cannot load {}: {}", path.display(), error),
    }
}

unsafe fn resolve<T: Copy>(module: Handle, name: &'static [u8]) -> Result<T, ApiError> {
    let address = GetProcAddress(module, name.as_ptr());
    if address.is_null() {
        return Err(ApiError {
            kind: io::ErrorKind::NotFound,
            message: format!(
                "wintun.dll does not export {}",
                String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
            ),
        });
    }
    Ok(mem::transmute_copy(&address))
}

unsafe fn load_api(path: &Path) -> Result<WintunApi, ApiError> {
    valid_wintun_path(path).map_err(ApiError::from_io)?;
    let name = wide_path(path);
    let module = LoadLibraryExW(name.as_ptr(), ptr::null_mut(), SECURE_LOAD_FLAGS);
    if module.is_null() {
        return Err(dll_load_error(path, unsafe { GetLastError() }));
    }
    let result = (|| {
        Ok(WintunApi {
            create_adapter: resolve(module, b"WintunCreateAdapter\0")?,
            close_adapter: resolve(module, b"WintunCloseAdapter\0")?,
            get_adapter_luid: resolve(module, b"WintunGetAdapterLuid\0")?,
            start_session: resolve(module, b"WintunStartSession\0")?,
            end_session: resolve(module, b"WintunEndSession\0")?,
            read_wait_event: resolve(module, b"WintunGetReadWaitEvent\0")?,
            receive_packet: resolve(module, b"WintunReceivePacket\0")?,
            release_receive_packet: resolve(module, b"WintunReleaseReceivePacket\0")?,
            allocate_send_packet: resolve(module, b"WintunAllocateSendPacket\0")?,
            send_packet: resolve(module, b"WintunSendPacket\0")?,
        })
    })();
    if result.is_err() {
        FreeLibrary(module);
    }
    result
}

/// Load Wintun from one explicit absolute path.
///
/// The module stays loaded for the life of the process. A failed load keeps
/// no handle. The error names the path and the Windows cause. A missing file
/// is `io::ErrorKind::NotFound`.
fn api_at(path: &Path) -> io::Result<&'static WintunApi> {
    static API: OnceLock<Mutex<Option<(PathBuf, &'static WintunApi)>>> = OnceLock::new();
    let cache = API.get_or_init(|| Mutex::new(None));
    let mut guard = cache
        .lock()
        .map_err(|_| io::Error::other("the Wintun loader lock is poisoned"))?;
    if let Some((loaded, api)) = guard.as_ref() {
        if loaded == path {
            return Ok(api);
        }
    }
    let api = unsafe { load_api(path) }
        .map_err(|error| io::Error::new(error.kind, error.message.clone()))?;
    // The function pointers stay valid while the DLL stays loaded. The
    // process keeps the module for its whole life, so the boxed table can be
    // shared as a static value.
    let api: &'static WintunApi = Box::leak(Box::new(api));
    *guard = Some((path.to_path_buf(), api));
    Ok(api)
}

/// Load the Wintun exports from one explicit absolute path.
///
/// This call creates no adapter and changes no route. The start path uses it
/// to report a missing or incompatible DLL before it checks the source device.
pub fn load_wintun(path: &Path) -> io::Result<()> {
    api_at(path).map(|_| ())
}

/// Return the adapter name for a tunnel unit.
///
/// The name must not use the shape that the Wintun suffix code makes. Wintun
/// renames a colliding adapter to `"<Name> <number>"`, with a space before the
/// number. These names use a hyphen and no space, so no Wintun rename of one
/// unit name can equal another unit name. The Wintun GUID check can then find
/// a leftover adapter for the exact unit.
pub fn adapter_name(unit: u32) -> String {
    const BASE: &str = "HotspotShade-Tunnel";
    if unit == 0 {
        BASE.to_owned()
    } else {
        format!("{BASE}-{unit}")
    }
}

/// Reject names that the Windows adapter manager cannot hold.
///
/// Wintun accepts at most 127 characters, because `MAX_ADAPTER_NAME` is 128
/// and the name needs a terminating zero. Allow only the characters that this
/// program generates, so a name cannot change a `netsh` argument or carry a
/// control character.
pub fn valid_ifname(name: &str) -> bool {
    let length = name.chars().count();
    length > 0
        && length <= 127
        && name != "."
        && name != ".."
        && !name.starts_with(' ')
        && !name.ends_with(' ')
        && !name.ends_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
}

/// Return a stable GUID for one adapter name. The GUID influences the Windows
/// network profile. It does not make Wintun reuse an existing adapter.
fn adapter_guid(name: &str) -> Guid {
    let mut first: u64 = 0xcbf2_9ce4_8422_2325;
    let mut second: u64 = 0x8422_2325_cbf2_9ce4;
    for byte in name.as_bytes() {
        first ^= u64::from(*byte);
        first = first.wrapping_mul(0x0000_0100_0000_01b3);
        second ^= u64::from(*byte).rotate_left(3);
        second = second.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&first.to_be_bytes());
    bytes[8..].copy_from_slice(&second.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Guid {
        data1: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_be_bytes([bytes[4], bytes[5]]),
        data3: u16::from_be_bytes([bytes[6], bytes[7]]),
        data4: [
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ],
    }
}

/// Run a system command without a shell. The program must be an absolute path
/// in a trusted system directory.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &Path, args: &[String]) -> io::Result<()>;
}

struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &Path, args: &[String]) -> io::Result<()> {
        use std::os::windows::process::CommandExt;
        let output = system_command(program, args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "{} failed: {}",
                program.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

/// Build a child command that cannot inherit the source device token.
///
/// The CLI reads `HOTSPOTSHADE_PHONE_TOKEN` and removes it from the process
/// environment. This function removes it again for every child, so a route or
/// link command never receives the token even when a caller still holds it in
/// the environment. `netsh` needs no part of it.
fn system_command(program: &Path, args: &[String]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command.env_remove(PHONE_TOKEN_ENV);
    command
}

/// Owns one adapter handle.
///
/// `WintunCloseAdapter` removes an adapter that `WintunCreateAdapter` created.
/// This guard closes only the handle that this program created. The guard runs
/// on every error path, so a failed start does not leave a new adapter behind.
struct AdapterHandle {
    api: &'static WintunApi,
    handle: Handle,
}

impl AdapterHandle {
    fn new(api: &'static WintunApi, handle: Handle) -> Self {
        Self { api, handle }
    }

    fn raw(&self) -> Handle {
        self.handle
    }

    /// Read the LUID from the handle. This is the one authoritative LUID for
    /// the adapter. Do not replace it with a lookup by name.
    fn luid(&self) -> io::Result<u64> {
        let mut luid: u64 = 0;
        unsafe { (self.api.get_adapter_luid)(self.handle, &mut luid) };
        if luid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the created adapter has no LUID",
            ));
        }
        Ok(luid)
    }
}

impl Drop for AdapterHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.api.close_adapter)(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

/// Owns one Wintun session.
///
/// The read-wait event belongs to the session. Do not close it.
struct SessionHandle {
    api: &'static WintunApi,
    handle: Handle,
}

impl SessionHandle {
    fn start(api: &'static WintunApi, adapter: Handle) -> io::Result<Self> {
        let handle = unsafe { (api.start_session)(adapter, SESSION_CAPACITY) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { api, handle })
    }

    fn raw(&self) -> Handle {
        self.handle
    }

    fn read_wait_event(&self) -> io::Result<Handle> {
        let event = unsafe { (self.api.read_wait_event)(self.handle) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(event)
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.api.end_session)(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

/// A Wintun adapter and its packet session. The session reads and writes raw
/// IP packets without a link-layer header.
///
/// The field order is the cleanup order. The session ends before the adapter
/// closes. The LUID and the GUID come from the created adapter and never
/// change.
pub struct Utun {
    session: SessionHandle,
    /// Holds the adapter handle open and closes it after the session ends.
    #[allow(dead_code)]
    adapter: AdapterHandle,
    api: &'static WintunApi,
    event: Handle,
    ifname: String,
    ifindex: u32,
    ownership: AdapterOwnership,
    mtu: usize,
}

// SAFETY: Wintun documents the packet functions and its handles as thread
// safe. `Utun` is not `Sync`, so only one thread uses the session at a time.
// Moving the single owner to another thread is safe.
unsafe impl Send for Utun {}

impl Utun {
    /// Create the adapter for this unit and start one session.
    ///
    /// The Wintun path is the default next to the executable. Use
    /// [`Utun::open_with_dll`] to name an explicit absolute path.
    pub fn open(unit: u32) -> io::Result<Self> {
        let path = default_wintun_path()?;
        Self::open_with_dll(unit, &path)
    }

    /// Create the adapter for this unit from one explicit Wintun path.
    ///
    /// The path must be absolute and must name `wintun.dll`. The file is not
    /// bundled with the program. A missing file is a plain `NotFound` error
    /// that names the path.
    ///
    /// This function calls `WintunCreateAdapter`, which creates a new adapter.
    /// It never opens an existing adapter. It rejects a name or a GUID that an
    /// interface already uses, because Wintun renames the other adapter in the
    /// name case.
    ///
    /// After the create call, the function reads the LUID from the new handle
    /// and proves that the requested name maps back to that LUID. It also reads
    /// the GUID from the LUID and compares it with the deterministic GUID. A
    /// mismatch closes the adapter that this call created. This program does
    /// not rename or delete another adapter. Wintun can rename an adapter that
    /// holds the requested name, so a failed create is not proof that no other
    /// adapter changed.
    ///
    /// An adapter that a crash left behind also blocks the start. A person
    /// must remove it. This function never deletes an adapter that it did not
    /// create.
    pub fn open_with_dll(unit: u32, dll: &Path) -> io::Result<Self> {
        if unit > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tunnel unit must be 0 to 255",
            ));
        }
        let ifname = adapter_name(unit);
        if !valid_ifname(&ifname) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid tunnel adapter name",
            ));
        }
        let api = api_at(dll)?;
        // The lookup and the create are separate calls. A foreign adapter can
        // take the name between them, and Wintun then renames that adapter.
        // The Wintun API has no create call that fails on a duplicate name.
        // The post-create check below stops this program from using a name
        // that does not map to its own LUID.
        ensure_no_interface_named_with(&ifname, interface_alias_exists)?;
        let guid = adapter_guid(&ifname);
        ensure_no_adapter_with_guid_with(&ifname, || interface_guid_exists(&guid))?;
        let name = wide(&ifname);
        let tunnel_type = wide("HotspotShade");
        let handle = unsafe { (api.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), &guid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let adapter = AdapterHandle::new(api, handle);
        let luid = adapter.luid()?;
        let ifindex = adapter_index(luid)?;
        let ownership = AdapterOwnership {
            identity: TunnelIdentity {
                interface_index: ifindex,
                interface_luid: luid,
            },
            guid,
        };
        let actual_alias = interface_alias_from_luid(luid)?;
        let actual_guid = interface_guid_from_luid(luid)?;
        let named_luid = interface_alias_luid(&ifname)?;
        verify_created_adapter(
            &ifname,
            ownership,
            Some(&actual_alias),
            named_luid,
            actual_guid.as_ref(),
        )?;
        let session = SessionHandle::start(api, adapter.raw())?;
        let event = session.read_wait_event()?;
        Ok(Self {
            session,
            adapter,
            api,
            event,
            ifname,
            ifindex,
            ownership,
            mtu: TUNNEL_MTU,
        })
    }

    /// Return the validated adapter name that Windows registered.
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Return the interface index at creation.
    ///
    /// Resolve the current index after a link change with
    /// [`Utun::current_index`].
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Resolve the current interface index from the retained ownership.
    ///
    /// The index at creation can be stale after a link change. Use this value
    /// for a new outer socket pin. `Ok(None)` means that the adapter is gone.
    /// A LUID that now names another adapter is an error.
    pub fn current_index(&self) -> io::Result<Option<u32>> {
        current_index_for_ownership(self.ownership)
    }

    /// Return the LUID obtained from this adapter when it was created.
    ///
    /// The value never changes. Resolve the interface index and GUID from this
    /// LUID again after a link change. Do not resolve the LUID from the name.
    pub fn luid(&self) -> u64 {
        self.ownership.identity.interface_luid
    }

    /// Return the ownership state for a route manager.
    fn ownership(&self) -> AdapterOwnership {
        self.ownership
    }

    /// Return the identity that a route check must prove.
    pub fn identity(&self) -> TunnelIdentity {
        TunnelIdentity {
            interface_index: self.ifindex,
            interface_luid: self.ownership.identity.interface_luid,
        }
    }

    /// Return the retained identity in the native route form.
    ///
    /// The route boundary checks the same LUID and GUID before every create
    /// and delete. A zero value cannot occur because the constructor validated
    /// the ownership state.
    pub fn native_route_identity(
        &self,
    ) -> io::Result<crate::windows_native_routes::AdapterIdentity> {
        let guid = self.ownership.guid;
        let native_guid = crate::windows_native_routes::AdapterGuid::new(
            guid.data1, guid.data2, guid.data3, guid.data4,
        );
        crate::windows_native_routes::AdapterIdentity::new(
            self.ownership.identity.interface_luid,
            native_guid,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
    }

    /// Return one IP packet without a link-layer header.
    pub fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut size: u32 = 0;
        let packet = unsafe { (self.api.receive_packet)(self.session.raw(), &mut size) };
        if packet.is_null() {
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_ITEMS {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let bytes = unsafe { std::slice::from_raw_parts(packet, size as usize) }.to_vec();
        unsafe { (self.api.release_receive_packet)(self.session.raw(), packet) };
        validate_inbound_packet(&bytes)?;
        Ok(bytes)
    }

    /// Write one IP packet. Return its byte count.
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        validate_outbound_packet(packet, self.mtu)?;
        let buffer =
            unsafe { (self.api.allocate_send_packet)(self.session.raw(), packet.len() as u32) };
        if buffer.is_null() {
            let code = unsafe { GetLastError() };
            if code == ERROR_BUFFER_OVERFLOW {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        unsafe {
            ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
            (self.api.send_packet)(self.session.raw(), buffer);
        }
        Ok(packet.len())
    }

    /// Wait until a read packet can be available. The relay loop uses this
    /// event instead of a Unix poll of the device descriptor.
    pub fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        let millis = timeout.as_millis().min(u32::MAX as u128) as u32;
        match unsafe { WaitForSingleObject(self.event, millis) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected Wintun wait result")),
        }
    }
}

fn validate_inbound_packet(packet: &[u8]) -> io::Result<()> {
    let Some(version) = packet.first().map(|byte| byte >> 4) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty Wintun packet",
        ));
    };
    match version {
        4 => {
            if packet.len() < 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short IPv4 packet",
                ));
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header < 20 || header > packet.len() || total < header || total > packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid IPv4 packet length",
                ));
            }
            Ok(())
        }
        6 => {
            if packet.len() < 40 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short IPv6 packet",
                ));
            }
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if 40 + payload > packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid IPv6 packet length",
                ));
            }
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Wintun IP version",
        )),
    }
}

fn validate_outbound_packet(packet: &[u8], mtu: usize) -> io::Result<()> {
    if packet.is_empty() || packet.len() > mtu {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid packet length",
        ));
    }
    validate_inbound_packet(packet)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
}

fn peer_in_subnet(addr: Ipv4Addr) -> io::Result<Ipv4Addr> {
    if addr.octets()[0] == 0
        || addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_multicast()
        || addr.is_broadcast()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tunnel address must be a unicast host in a /30",
        ));
    }
    let mut octets = addr.octets();
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

/// Configure the static IPv4 address and MTU on the Wintun adapter.
///
/// The command uses the interface index that the retained LUID resolves to.
/// It does not select the adapter by name. A name can move to another adapter,
/// and Windows can reuse an index or a LUID, so the function also compares the
/// GUID from the same LUID with the retained GUID. The lookups are read-only.
///
/// The command uses `store=active`, so a crash does not persist the change.
/// Closing the adapter removes the address and the interface.
///
/// The ownership check and the `netsh` command are separate. Windows can
/// remove the adapter and reuse the LUID between them. This function does not
/// claim atomic ownership.
pub fn configure_link(tun: &Utun, addr: Ipv4Addr, mtu: u32) -> io::Result<()> {
    let netsh = netsh_path()?;
    configure_link_for_ownership(
        tun.ownership(),
        &SystemResolver,
        &SystemRunner,
        &netsh,
        addr,
        mtu,
    )
}

fn configure_link_for_ownership(
    ownership: AdapterOwnership,
    resolver: &dyn InterfaceResolver,
    runner: &dyn CommandRunner,
    netsh: &Path,
    addr: Ipv4Addr,
    mtu: u32,
) -> io::Result<()> {
    let ifindex = resolve_owned_index(resolver, ownership)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the tunnel adapter is gone; the link is not configured",
        )
    })?;
    configure_link_with(runner, netsh, ifindex, addr, mtu)
}

fn configure_link_with(
    runner: &dyn CommandRunner,
    netsh: &Path,
    ifindex: u32,
    addr: Ipv4Addr,
    mtu: u32,
) -> io::Result<()> {
    if !netsh.is_absolute()
        || !valid_interface_index(ifindex)
        || !(576..=65535).contains(&mtu)
        || peer_in_subnet(addr).is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid tunnel index, address, or MTU",
        ));
    }
    runner.run(
        netsh,
        &[
            "interface".into(),
            "ipv4".into(),
            "set".into(),
            "address".into(),
            format!("name={ifindex}"),
            "source=static".into(),
            format!("address={addr}"),
            "mask=255.255.255.252".into(),
            "store=active".into(),
        ],
    )?;
    runner.run(
        netsh,
        &[
            "interface".into(),
            "ipv4".into(),
            "set".into(),
            "subinterface".into(),
            format!("interface={ifindex}"),
            format!("mtu={mtu}"),
            "store=active".into(),
        ],
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    FirstHalf,
    SecondHalf,
    Ipv6Block,
}

fn valid_interface_index(index: u32) -> bool {
    index != 0 && index <= 0x00ff_ffff
}

/// Reads the current index and GUID for a retained LUID.
///
/// The LUID and the GUID are stable for the life of the adapter. The index is
/// not. Windows can change the index after a link change, and it can reuse an
/// old index or LUID for another adapter. Every route command must resolve both
/// values again and compare the GUID with the retained GUID.
pub(crate) trait InterfaceResolver: Send + Sync {
    /// Return the current index, or `Ok(None)` when no interface has this LUID.
    fn index_for_luid(&self, luid: u64) -> io::Result<Option<u32>>;
    /// Return the current GUID, or `Ok(None)` when no interface has this LUID.
    fn guid_for_luid(&self, luid: u64) -> io::Result<Option<Guid>>;
}

struct SystemResolver;

impl InterfaceResolver for SystemResolver {
    fn index_for_luid(&self, luid: u64) -> io::Result<Option<u32>> {
        interface_index_lookup(luid)
    }

    fn guid_for_luid(&self, luid: u64) -> io::Result<Option<Guid>> {
        interface_guid_from_luid(luid)
    }
}

/// Tracks only routes created by this instance.
///
/// The manager retains the adapter LUID and GUID from the created device. Both
/// values never change. The manager holds the current interface index and
/// refreshes it from the LUID and GUID before each operation. The manager never
/// replaces the LUID with a lookup by name.
///
/// Every delete uses the index that the retained LUID resolves to at that
/// moment. When the adapter is gone, the manager sends no delete command.
/// Windows removed the routes with the adapter, and the old index can belong to
/// another adapter. When the LUID now names a different GUID, the manager fails
/// closed and keeps the route record for a later attempt.
///
/// [`RouteManager::verify`] is a read-only `GetBestRoute2` check for both `/1`
/// prefixes and the IPv6 policy. It needs a live Windows host. A successful
/// [`RouteManager::install`] alone is not proof that Windows sends the traffic
/// through the tunnel. The tunnel stays disabled until a person verifies it.
pub struct RouteManager {
    /// The LUID and GUID read from the created adapter. Both are immutable.
    ownership: AdapterOwnership,
    /// The current interface index. The manager refreshes it from the ownership
    /// before an install or a remove. It is never resolved from the name.
    ifindex: u32,
    ipv6_block: bool,
    netsh: PathBuf,
    runner: Arc<dyn CommandRunner>,
    resolver: Arc<dyn InterfaceResolver>,
    installed: Vec<Route>,
}

impl RouteManager {
    /// Create a manager for the adapter that this device created.
    ///
    /// The constructor takes the device, not a name or a lone index. The
    /// identity and the deterministic GUID therefore come from the handle that
    /// `WintunCreateAdapter` returned.
    pub fn new(tun: &Utun, ipv6_block: bool) -> io::Result<Self> {
        Self::with_runner(
            tun.ownership(),
            ipv6_block,
            netsh_path()?,
            Arc::new(SystemRunner),
            Arc::new(SystemResolver),
        )
    }

    fn with_runner(
        ownership: AdapterOwnership,
        ipv6_block: bool,
        netsh: PathBuf,
        runner: Arc<dyn CommandRunner>,
        resolver: Arc<dyn InterfaceResolver>,
    ) -> io::Result<Self> {
        validate_ownership(ownership)?;
        if !netsh.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the netsh path must be absolute",
            ));
        }
        Ok(Self {
            ownership,
            ifindex: ownership.identity.interface_index,
            ipv6_block,
            netsh,
            runner,
            resolver,
            installed: Vec::new(),
        })
    }

    /// Return the retained identity. The LUID is the value from the created
    /// adapter. The index is the most recent value that the LUID resolved to.
    pub fn identity(&self) -> TunnelIdentity {
        TunnelIdentity {
            interface_index: self.ifindex,
            interface_luid: self.ownership.identity.interface_luid,
        }
    }

    /// Resolve the current index and prove that the retained GUID still
    /// belongs to the retained LUID.
    fn resolve_index(&self) -> io::Result<Option<u32>> {
        resolve_owned_index(self.resolver.as_ref(), self.ownership)
    }

    /// Return the current index or fail when the adapter is not provable.
    fn resolve_required_index(&self, message: &'static str) -> io::Result<u32> {
        self.resolve_index()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, message))
    }

    /// Remove routes after an install error. Keep any route that cleanup
    /// cannot remove.
    fn remove_after_error(&mut self, error: io::Error) -> io::Result<()> {
        match self.remove() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(io::Error::new(
                error.kind(),
                format!("{}; route cleanup failed: {}", error, cleanup),
            )),
        }
    }

    fn add_args(&self, route: Route, ifindex: u32) -> Vec<String> {
        let prefix = match route {
            Route::FirstHalf => "0.0.0.0/1",
            Route::SecondHalf => "128.0.0.0/1",
            Route::Ipv6Block => "2000::/3",
        };
        let family = if route == Route::Ipv6Block {
            "ipv6"
        } else {
            "ipv4"
        };
        vec![
            "interface".into(),
            family.into(),
            "add".into(),
            "route".into(),
            format!("prefix={prefix}"),
            format!("interface={ifindex}"),
            "store=active".into(),
        ]
    }

    fn delete_args(&self, route: Route, ifindex: u32) -> Vec<String> {
        let prefix = match route {
            Route::FirstHalf => "0.0.0.0/1",
            Route::SecondHalf => "128.0.0.0/1",
            Route::Ipv6Block => "2000::/3",
        };
        let family = if route == Route::Ipv6Block {
            "ipv6"
        } else {
            "ipv4"
        };
        vec![
            "interface".into(),
            family.into(),
            "delete".into(),
            "route".into(),
            format!("prefix={prefix}"),
            format!("interface={ifindex}"),
            "store=active".into(),
        ]
    }

    /// Install the two IPv4 routes and, when requested, the IPv6 block.
    /// On failure, remove the routes that this instance added.
    ///
    /// The IPv6 block route sends `2000::/3` to the tunnel adapter. The relay
    /// drops those packets. It never leaves the tunnel.
    ///
    /// The method resolves the interface index and proves the GUID match again
    /// before each add. It fails when the adapter is gone or the LUID now names
    /// another adapter. It never adds a route to an index that the retained
    /// ownership does not prove.
    pub fn install(&mut self) -> io::Result<()> {
        if !self.installed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "routes already installed or cleanup incomplete",
            ));
        }
        let mut routes = vec![Route::FirstHalf, Route::SecondHalf];
        if self.ipv6_block {
            routes.push(Route::Ipv6Block);
        }
        for route in routes {
            let index = match self.resolve_index() {
                Ok(Some(index)) => index,
                Ok(None) => {
                    let error = io::Error::new(
                        io::ErrorKind::NotFound,
                        "the tunnel adapter is gone; routes are not installed",
                    );
                    return self.remove_after_error(error);
                }
                Err(error) => {
                    let error = io::Error::new(
                        error.kind(),
                        format!("cannot check route ownership: {error}"),
                    );
                    return self.remove_after_error(error);
                }
            };
            self.ifindex = index;
            let args = self.add_args(route, index);
            if let Err(error) = self.runner.run(&self.netsh, &args) {
                return self.remove_after_error(error);
            }
            self.installed.push(route);
        }
        Ok(())
    }

    /// Remove all recorded routes. Retain failed routes for another attempt.
    ///
    /// The method resolves the index and proves the GUID match again before
    /// each delete. When the adapter is gone, it clears the record and sends no
    /// delete command. A failed or unproven ownership check keeps every
    /// remaining route for another attempt.
    ///
    /// A `netsh` error is not parsed for "not found". The text is localized,
    /// and a broad match could hide a different failure. The route stays
    /// recorded, so a later attempt can retry it. The record is not used to
    /// delete a route on another adapter.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.installed.is_empty() {
            return Ok(());
        }
        let mut remaining = std::mem::take(&mut self.installed);
        let mut failed = Vec::new();
        let mut last_error = None;
        while let Some(route) = remaining.pop() {
            let index = match self.resolve_index() {
                Ok(Some(index)) => {
                    self.ifindex = index;
                    index
                }
                Ok(None) => {
                    // The adapter is gone. Windows removed all its routes. Do
                    // not use a stale index: another adapter can own it now.
                    return Ok(());
                }
                Err(error) => {
                    // Keep the unvisited routes, then the current route, then
                    // the routes whose delete failed. The result is the install
                    // order for a later attempt.
                    remaining.push(route);
                    failed.reverse();
                    remaining.append(&mut failed);
                    self.installed = remaining;
                    return Err(io::Error::new(
                        error.kind(),
                        format!("cannot check route ownership: {error}"),
                    ));
                }
            };
            let args = self.delete_args(route, index);
            if let Err(error) = self.runner.run(&self.netsh, &args) {
                last_error = Some(error);
                failed.push(route);
            }
        }
        failed.reverse();
        self.installed = failed;
        match last_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Build a verification policy for the current adapter location.
    ///
    /// The index is resolved again, because the creation index can be stale
    /// after a link change. The GUID must still match the retained GUID.
    fn verify_policy(&self) -> io::Result<VerifyPolicy> {
        let index =
            self.resolve_required_index("the tunnel adapter is gone; the routes are not verified")?;
        let ipv6 = if self.ipv6_block {
            Ipv6RoutePolicy::Block
        } else {
            Ipv6RoutePolicy::Inherit
        };
        Ok(VerifyPolicy::new(
            TunnelIdentity {
                interface_index: index,
                interface_luid: self.ownership.identity.interface_luid,
            },
            ipv6,
        ))
    }

    /// Prove the installed routes and the IPv6 policy with read-only API calls.
    ///
    /// Call this after [`RouteManager::install`]. This function changes no
    /// route. When it returns an error, the caller must call
    /// [`RouteManager::remove`] and must not start the relay.
    ///
    /// The function resolves the current index and checks the GUID before it
    /// reads a route. The function fails closed for the inherit policy, because
    /// that policy has no tunnel route to prove.
    pub fn verify(&self) -> Result<RouteProof, RouteVerifyError> {
        let policy = self.verify_policy().map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => RouteVerifyError::InvalidTunnelIdentity(
                "the tunnel adapter is gone, so the routes are not verified",
            ),
            io::ErrorKind::InvalidData => RouteVerifyError::InvalidTunnelIdentity(
                "the retained LUID does not resolve to the tunnel adapter, so the routes are not verified",
            ),
            _ => RouteVerifyError::InvalidTunnelIdentity(
                "the adapter ownership check did not complete, so the routes are not verified",
            ),
        })?;
        crate::windows_route_verify::verify_live(&policy)
    }

    pub fn has_installed_routes(&self) -> bool {
        !self.installed.is_empty()
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            eprintln!("[route] cleanup failed: {}", error);
        }
    }
}

/// Owns the IPv6 address and route that an explicit forward policy needs.
///
/// Install this only when the user selected IPv6 forwarding. A block policy
/// uses the `Ipv6Block` route in [`RouteManager`] instead.
///
/// The tunnel retains the adapter LUID and GUID. Every command resolves the
/// interface index and GUID again from the LUID, so a stale index or a reused
/// LUID cannot target another adapter. A failed check keeps the change record
/// for another attempt.
pub struct Ipv6Tunnel {
    /// The LUID and GUID read from the created adapter. Both are immutable.
    ownership: AdapterOwnership,
    address: Ipv6Addr,
    netsh: PathBuf,
    runner: Arc<dyn CommandRunner>,
    resolver: Arc<dyn InterfaceResolver>,
    has_address: bool,
    has_route: bool,
}

impl Ipv6Tunnel {
    /// Create the IPv6 guard for the adapter that this device created.
    pub fn new(tun: &Utun) -> io::Result<Self> {
        Self::with_runner(
            tun.ownership(),
            netsh_path()?,
            Arc::new(SystemRunner),
            Arc::new(SystemResolver),
        )
    }

    fn with_runner(
        ownership: AdapterOwnership,
        netsh: PathBuf,
        runner: Arc<dyn CommandRunner>,
        resolver: Arc<dyn InterfaceResolver>,
    ) -> io::Result<Self> {
        validate_ownership(ownership)?;
        if !netsh.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the netsh path must be absolute",
            ));
        }
        let unit = (ownership.identity.interface_index & 0xffff) as u16;
        Ok(Self {
            ownership,
            address: Ipv6Addr::new(0xfd42, 0x6873, 0x6861, unit, 0, 0, 0, 1),
            netsh,
            runner,
            resolver,
            has_address: false,
            has_route: false,
        })
    }

    fn resolve_index(&self) -> io::Result<Option<u32>> {
        resolve_owned_index(self.resolver.as_ref(), self.ownership)
    }

    fn resolve_required_index(&self, message: &'static str) -> io::Result<u32> {
        self.resolve_index()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, message))
    }

    pub fn install(&mut self) -> io::Result<()> {
        if self.has_address || self.has_route {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "IPv6 tunnel already installed",
            ));
        }
        let result = (|| {
            let index = self.resolve_required_index(
                "the tunnel adapter is gone; the IPv6 route is not installed",
            )?;
            self.runner.run(
                &self.netsh,
                &[
                    "interface".into(),
                    "ipv6".into(),
                    "add".into(),
                    "address".into(),
                    format!("interface={index}"),
                    format!("address={}/128", self.address),
                    "store=active".into(),
                ],
            )?;
            self.has_address = true;
            let index = self.resolve_required_index(
                "the tunnel adapter is gone; the IPv6 route is not installed",
            )?;
            self.runner.run(
                &self.netsh,
                &[
                    "interface".into(),
                    "ipv6".into(),
                    "add".into(),
                    "route".into(),
                    "prefix=2000::/3".into(),
                    format!("interface={index}"),
                    "store=active".into(),
                ],
            )?;
            self.has_route = true;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => match self.remove() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::new(
                    error.kind(),
                    format!("{}; IPv6 cleanup failed: {}", error, cleanup),
                )),
            },
        }
    }

    pub fn has_changes(&self) -> bool {
        self.has_address || self.has_route
    }

    /// Route verification needs a `GetBestRoute2` check. The ownership check
    /// runs first, so an error also reports an absent adapter or a reused LUID.
    /// Until the live check is wired, fail closed so a caller cannot treat this
    /// guard as verified.
    pub fn verify(&self) -> io::Result<()> {
        self.resolve_required_index("the tunnel adapter is gone; the IPv6 route is not verified")?;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv6 route verification is not implemented on Windows",
        ))
    }

    pub fn remove(&mut self) -> io::Result<()> {
        if !self.has_address && !self.has_route {
            return Ok(());
        }
        let mut error = None;
        if self.has_route {
            match self.resolve_index() {
                Ok(Some(index)) => match self.runner.run(
                    &self.netsh,
                    &[
                        "interface".into(),
                        "ipv6".into(),
                        "delete".into(),
                        "route".into(),
                        "prefix=2000::/3".into(),
                        format!("interface={index}"),
                        "store=active".into(),
                    ],
                ) {
                    Ok(()) => self.has_route = false,
                    Err(failure) => error = Some(failure),
                },
                Ok(None) => {
                    // The adapter is gone, and Windows removed its address and
                    // route. Do not use a stale index.
                    self.has_address = false;
                    self.has_route = false;
                    return Ok(());
                }
                Err(failure) => {
                    return Err(io::Error::new(
                        failure.kind(),
                        format!("cannot check IPv6 route ownership: {failure}"),
                    ))
                }
            }
        }
        if self.has_address && !self.has_route {
            match self.resolve_index() {
                Ok(Some(index)) => match self.runner.run(
                    &self.netsh,
                    &[
                        "interface".into(),
                        "ipv6".into(),
                        "delete".into(),
                        "address".into(),
                        format!("interface={index}"),
                        format!("address={}", self.address),
                        "store=active".into(),
                    ],
                ) {
                    Ok(()) => self.has_address = false,
                    Err(failure) => error = Some(failure),
                },
                Ok(None) => {
                    self.has_address = false;
                    self.has_route = false;
                    return Ok(());
                }
                Err(failure) => {
                    return Err(io::Error::new(
                        failure.kind(),
                        format!("cannot check IPv6 route ownership: {failure}"),
                    ))
                }
            }
        }
        match error {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

impl Drop for Ipv6Tunnel {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            eprintln!("[route] IPv6 cleanup failed: {}", error);
        }
    }
}

/// Return the interface index that Windows uses for the default IPv4 path.
/// The lookup changes nothing.
///
/// Call this before you install the tunnel routes. After the two `/1` routes
/// point at the tunnel adapter, the lookup returns the tunnel adapter. An
/// outer socket pinned to that index would send its traffic back into the
/// tunnel. Resolve the index again after a link change, because Windows can
/// change an index when an adapter is re-enabled.
pub fn default_interface_index() -> io::Result<u32> {
    let mut index: u32 = 0;
    // 8.8.8.8 in network byte order. The value is symmetric, so the host byte
    // order of this constant does not matter.
    let status = unsafe { GetBestInterface(u32::from_be_bytes([8, 8, 8, 8]), &mut index) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if !valid_interface_index(index) {
        return Err(io::Error::other("default interface index is invalid"));
    }
    Ok(index)
}

/// Return the current default IPv4 gateway and its interface index.
///
/// The lookup is read-only. It uses the best route to a public destination, so
/// it names the same adapter that [`default_interface_index`] selects. Use it
/// before installing the two `/1` routes. After those routes point at the
/// tunnel adapter, the lookup names the tunnel and a caller must reject it.
pub fn default_ipv4_gateway() -> io::Result<(Ipv4Addr, u32)> {
    crate::windows_route_verify::default_ipv4_gateway()
        .map_err(|_| io::Error::other("default IPv4 gateway lookup failed"))
}

/// Return true when the current process token has the Administrators group
/// enabled.
///
/// An elevated process has the group enabled. A filtered UAC token does not.
/// The check reads the token and changes nothing. A failed check reports
/// false, so a caller cannot start a tunnel without proof of elevation.
pub fn is_elevated() -> bool {
    #[repr(C, align(8))]
    struct SidBuffer([u8; SECURITY_MAX_SID_SIZE]);
    #[link(name = "advapi32")]
    extern "system" {
        fn CreateWellKnownSid(
            sid_type: i32,
            domain_sid: *mut c_void,
            sid: *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn CheckTokenMembership(
            token: *mut c_void,
            sid_to_check: *const c_void,
            is_member: *mut i32,
        ) -> i32;
    }
    /// `WinBuiltinAdministratorsSid`.
    const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;
    /// `SECURITY_MAX_SID_SIZE`.
    const SECURITY_MAX_SID_SIZE: usize = 68;
    let mut sid = SidBuffer([0; SECURITY_MAX_SID_SIZE]);
    let mut size = SECURITY_MAX_SID_SIZE as u32;
    let created = unsafe {
        CreateWellKnownSid(
            WIN_BUILTIN_ADMINISTRATORS_SID,
            ptr::null_mut(),
            (&mut sid as *mut SidBuffer).cast(),
            &mut size,
        )
    };
    if created == 0 {
        return false;
    }
    let mut member: i32 = 0;
    let checked = unsafe {
        CheckTokenMembership(
            ptr::null_mut(),
            (&sid as *const SidBuffer).cast(),
            &mut member,
        )
    };
    checked != 0 && member != 0
}

// ---------------------------------------------------------------------------
// Physical interface link observation
// ---------------------------------------------------------------------------

/// The current LUID for an interface index, or `Ok(None)` when Windows reports
/// that no interface has this index.
fn interface_luid_from_index(index: u32) -> io::Result<Option<u64>> {
    if !valid_interface_index(index) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index must be a nonzero 24-bit number",
        ));
    }
    let mut luid: u64 = 0;
    let status = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
    if !interface_lookup_result(status)? {
        return Ok(None);
    }
    if luid == 0 {
        return Err(io::Error::other("the interface index has a zero LUID"));
    }
    Ok(Some(luid))
}

/// Map the legacy `MIB_IFROW.dwAdminStatus` value.
///
/// `1` is up and `2` is down. `3` is the testing state, and any other value is
/// not a documented administrative state. Both are unknown, not down, because
/// the observer must not invent link loss from a value it does not understand.
fn admin_status_state(value: u32) -> LinkStatus {
    match value {
        MIB_IF_ADMIN_STATUS_UP => LinkStatus::Up,
        MIB_IF_ADMIN_STATUS_DOWN => LinkStatus::Down,
        _ => LinkStatus::Unknown,
    }
}

/// Map the legacy `MIB_IFROW.dwOperStatus` value.
///
/// `GetIfEntry` uses `MIB_IF_OPER_STATUS_*` from `ipmib.h`, not
/// `IF_OPER_STATUS` from `ifdef.h`. `4` (connected) and `5` (operational) are
/// up. `0` (non-operational), `1` (unreachable), and `2` (disconnected) are
/// down. `3` (connecting) is transient, and any other value is not a documented
/// operational state, so both are unknown. A healthy interface reports `5`, not
/// `1`.
fn oper_status_state(value: u32) -> LinkStatus {
    match value {
        MIB_IF_OPER_STATUS_CONNECTED | MIB_IF_OPER_STATUS_OPERATIONAL => LinkStatus::Up,
        MIB_IF_OPER_STATUS_NON_OPERATIONAL
        | MIB_IF_OPER_STATUS_UNREACHABLE
        | MIB_IF_OPER_STATUS_DISCONNECTED => LinkStatus::Down,
        MIB_IF_OPER_STATUS_CONNECTING => LinkStatus::Unknown,
        _ => LinkStatus::Unknown,
    }
}

/// Read the administrative and operational state of one interface index.
///
/// `GetIfEntry` fills a `MIB_IFROW`. The function returns `Ok(None)` only for
/// the documented not-found codes. Any other error is returned, because a
/// failed read is not evidence that the interface is down.
fn read_interface_status(index: u32) -> io::Result<Option<InterfaceStatus>> {
    if !valid_interface_index(index) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index must be a nonzero 24-bit number",
        ));
    }
    // The API writes every field, but start from zero so a partial write
    // cannot expose stack data or an old status.
    let mut row: MibIfRow = unsafe { mem::zeroed() };
    row.index = index;
    let status = unsafe { GetIfEntry(&mut row) };
    if status != 0 {
        return match status {
            // Microsoft documents ERROR_NOT_FOUND when the interface index
            // does not name an entry. Do not treat ERROR_INVALID_PARAMETER as
            // absence: a wrong request shape is an unknown read, not proof
            // that the interface is gone.
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
            _ => Err(io::Error::from_raw_os_error(status as i32)),
        };
    }
    if row.index != index {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GetIfEntry returned another interface index",
        ));
    }
    Ok(Some(InterfaceStatus {
        admin: admin_status_state(row.admin_status),
        oper: oper_status_state(row.oper_status),
    }))
}

/// Read the IPv4 address table as rows with the interface index and flags.
///
/// The table is not evidence about one interface until the caller filters by
/// index. A missing table, buffer error, or layout error cannot prove that an
/// interface has no address and is reported as an inconclusive observation.
fn ipv4_address_table() -> io::Result<Vec<Ipv4AddressEntry>> {
    let mut size: u32 = 0;
    let status = unsafe { GetIpAddrTable(ptr::null_mut(), &mut size, 0) };
    if status == ERROR_NO_DATA {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if status != ERROR_INSUFFICIENT_BUFFER {
        if status == 0 && size == 0 {
            return Err(io::Error::other("empty IPv4 address table response"));
        }
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // The table can grow between the size query and the read. Retry a bounded
    // number of times, then report an inconclusive read.
    for _ in 0..3 {
        if size < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the IPv4 address table size is invalid",
            ));
        }
        if size as usize > MAX_IPV4_ADDRESS_TABLE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the IPv4 address table is too large",
            ));
        }
        // Allocate 4-byte words. `GetIpAddrTable` writes a `MIB_IPADDRTABLE`
        // through this pointer, so a byte buffer's alignment is not enough.
        let words = (size as usize).div_ceil(4);
        let mut buffer = vec![0u32; words];
        let mut filled = size;
        let status = unsafe { GetIpAddrTable(buffer.as_mut_ptr().cast(), &mut filled, 0) };
        match status {
            0 => {
                // SAFETY: `buffer` owns `words * 4` initialized bytes.
                let bytes = unsafe {
                    std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len() * 4)
                };
                // Some Windows versions leave `pdwSize` at its input value or
                // report padding beyond the last row. The parser accepts a
                // reported size with safe slack, and it never reads past the
                // buffer.
                let reported = if filled == 0 { size } else { filled };
                return parse_ipv4_address_table(bytes, reported);
            }
            ERROR_NO_DATA => return Err(io::Error::from_raw_os_error(status as i32)),
            ERROR_INSUFFICIENT_BUFFER if filled > size => {
                if filled as usize > MAX_IPV4_ADDRESS_TABLE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the IPv4 address table is too large",
                    ));
                }
                size = filled;
            }
            code => return Err(io::Error::from_raw_os_error(code as i32)),
        }
    }
    Err(io::Error::other(
        "the IPv4 address table did not fit a bounded buffer",
    ))
}

/// One `MIB_IPADDRROW`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ipv4AddressEntry {
    index: u32,
    address: Ipv4Addr,
    flags: u16,
}

/// Parse a `MIB_IPADDRTABLE` buffer.
///
/// The 4-byte row count and the 24-byte row stride are the documented layout.
/// A reported size larger than `4 + count * 24` is accepted as safe slack: the
/// API can report padding beyond the last row. A reported size smaller than the
/// rows need, or larger than the buffer, is a layout mismatch, not an empty
/// table. The row count is capped before any allocation. Rows are read with
/// `read_unaligned` so parsing does not depend on the caller's alignment.
fn parse_ipv4_address_table(buffer: &[u8], reported: u32) -> io::Result<Vec<Ipv4AddressEntry>> {
    let reported = reported as usize;
    if reported < 4 || reported > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the IPv4 address table reported size is outside its buffer",
        ));
    }
    let Some(header) = buffer.get(..4) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the IPv4 address table is shorter than its header",
        ));
    };
    let count = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if count > MAX_IPV4_ADDRESS_ROWS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the IPv4 address row count is too large",
        ));
    }
    let stride = mem::size_of::<MibIpAddrRow>();
    let needed = 4usize
        .checked_add(count.checked_mul(stride).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the IPv4 address row count is too large",
            )
        })?)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the IPv4 address table is too large",
            )
        })?;
    if needed > reported {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the IPv4 address table layout does not match the documented row size",
        ));
    }
    let mut rows = Vec::with_capacity(count);
    for position in 0..count {
        let offset = 4 + position * stride;
        // SAFETY: `offset + stride <= needed <= reported <= buffer.len()`.
        // The pointer comes from a byte buffer, and `read_unaligned` accepts
        // it.
        let row =
            unsafe { ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<MibIpAddrRow>()) };
        rows.push(Ipv4AddressEntry {
            index: row.index,
            address: Ipv4Addr::from(row.address.to_ne_bytes()),
            flags: row.w_type,
        });
    }
    Ok(rows)
}

/// True when an address can carry traffic on the physical interface.
///
/// The classifier rejects the `0.0.0.0/8` "this network" range, loopback
/// (`127.0.0.0/8`), the limited broadcast address, multicast, and the APIPA
/// range `169.254.0.0/16`. A link-local APIPA address means DHCP did not
/// complete. It is not a usable hotspot address.
fn usable_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && address.octets()[0] != 0
        && !address.is_loopback()
        && !address.is_broadcast()
        && !address.is_multicast()
        && !(address.octets()[0] == 169 && address.octets()[1] == 254)
}

/// True when the address row is live and usable.
///
/// A transient, deleted, or disconnected address is stale. A primary, dynamic,
/// or DNS-eligible address is usable when the address itself passes
/// [`usable_ipv4`].
fn usable_ipv4_entry(entry: &Ipv4AddressEntry) -> bool {
    entry.flags & (MIB_IPADDR_TRANSIENT | MIB_IPADDR_DELETED | MIB_IPADDR_DISCONNECTED) == 0
        && usable_ipv4(entry.address)
}

/// The identity that one observation resolved from an interface alias or
/// index, or that a retained observer kept from its binding.
///
/// A one-shot read uses the target once to resolve this pair. A retained
/// observer keeps the pair and never resolves the alias again. Every later read
/// proves this LUID and GUID. The observer never selects an interface by its up
/// state, and it never keeps an index as identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PhysicalIdentity {
    luid: u64,
    guid: Guid,
}

/// The administrative and operational state of one interface row.
///
/// Each field is the already-mapped legacy enum. `Unknown` keeps a transient or
/// undocumented raw value from becoming link loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InterfaceStatus {
    admin: LinkStatus,
    oper: LinkStatus,
}

/// One interface row that an observation proved for the retained identity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct IdentifiedRow {
    index: u32,
    luid: u64,
    guid: Guid,
    status: InterfaceStatus,
    ipv4: Vec<Ipv4AddressEntry>,
}

/// The evidence from one read of the Windows interface tables.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LinkProbe {
    /// An API call failed, or the reads disagreed. Unknown is not link loss.
    Unavailable,
    /// The requested alias or index did not resolve, or it resolved to more
    /// than one interface. A one-shot read cannot prove that this is the same
    /// interface that an earlier sample saw. Unknown is not link loss.
    Unresolved,
    /// A retained LUID and GUID no longer name an interface. Removal is
    /// conclusive only when both lookups report absence, or the GUID proves
    /// that Windows reused the LUID for another adapter.
    Removed,
    /// The tables proved one row for the identity that the alias or index
    /// resolved to.
    Identified {
        identity: PhysicalIdentity,
        row: IdentifiedRow,
    },
}

/// The three states that the auto-stop policy can use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkStatus {
    Up,
    Down,
    Unknown,
}

/// The interface table reads that one observation needs.
///
/// The real implementation calls `iphlpapi.dll`. A test implementation returns
/// fixed values and creates no device and no route.
trait LinkTables {
    fn luid_for_alias(&self, alias: &str) -> io::Result<Option<u64>>;
    fn index_for_luid(&self, luid: u64) -> io::Result<Option<u32>>;
    fn luid_for_index(&self, index: u32) -> io::Result<Option<u64>>;
    fn guid_for_luid(&self, luid: u64) -> io::Result<Option<Guid>>;
    fn interface_status(&self, index: u32) -> io::Result<Option<InterfaceStatus>>;
    fn ipv4_addresses(&self) -> io::Result<Vec<Ipv4AddressEntry>>;
}

struct SystemLinkTables;

impl LinkTables for SystemLinkTables {
    fn luid_for_alias(&self, alias: &str) -> io::Result<Option<u64>> {
        interface_alias_luid(alias)
    }

    fn index_for_luid(&self, luid: u64) -> io::Result<Option<u32>> {
        interface_index_lookup(luid)
    }

    fn luid_for_index(&self, index: u32) -> io::Result<Option<u64>> {
        interface_luid_from_index(index)
    }

    fn guid_for_luid(&self, luid: u64) -> io::Result<Option<Guid>> {
        interface_guid_from_luid(luid)
    }

    fn interface_status(&self, index: u32) -> io::Result<Option<InterfaceStatus>> {
        read_interface_status(index)
    }

    fn ipv4_addresses(&self) -> io::Result<Vec<Ipv4AddressEntry>> {
        ipv4_address_table()
    }
}

fn validate_link_target(target: &str) -> io::Result<()> {
    let length = target.chars().count();
    if length == 0
        || length > MAX_INTERFACE_NAME_LEN
        || target.contains('\0')
        || target.chars().any(char::is_control)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    Ok(())
}

/// Return a numeric interface index only for an all-digit target.
///
/// A numeric alias is legal on Windows. A target that parses as a number is
/// therefore not automatically an index. [`resolve_target_with`] reads both
/// forms and requires them to agree when both exist.
fn numeric_interface_index(target: &str) -> Option<u32> {
    if target.is_empty() || !target.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let index = target.parse::<u32>().ok()?;
    valid_interface_index(index).then_some(index)
}

/// Normalize one LUID lookup. A zero LUID on success is inconsistent, not an
/// absent interface, so it maps to the same failure as an API error.
fn lookup_luid(result: io::Result<Option<u64>>) -> Result<Option<u64>, ()> {
    match result {
        Ok(Some(luid)) if luid != 0 => Ok(Some(luid)),
        Ok(Some(_)) => Err(()),
        Ok(None) => Ok(None),
        Err(_) => Err(()),
    }
}

/// The result of resolving one target without selecting an interface by its
/// link state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetResolution {
    Luid(u64),
    /// No index and no alias currently names an interface.
    Absent,
    /// A numeric target names one index and a different interface alias. The
    /// caller cannot tell which interface the person meant.
    Ambiguous,
    Unavailable,
}

/// Resolve one alias or numeric index to a LUID.
///
/// A numeric target is read as both an index and an alias, because Windows
/// allows an alias made of digits. When both forms exist they must name the
/// same LUID. A disagreement is ambiguous, and an API error is unavailable.
/// Absence of both forms is not evidence that an earlier interface is gone:
/// the alias may have been renamed, or the index may have changed.
fn resolve_target_with(tables: &dyn LinkTables, target: &str) -> TargetResolution {
    let index_luid = match numeric_interface_index(target) {
        Some(index) => match lookup_luid(tables.luid_for_index(index)) {
            Ok(value) => value,
            Err(()) => return TargetResolution::Unavailable,
        },
        None => None,
    };
    let alias_luid = match lookup_luid(tables.luid_for_alias(target)) {
        Ok(value) => value,
        Err(()) => return TargetResolution::Unavailable,
    };
    match (index_luid, alias_luid) {
        (None, None) => TargetResolution::Absent,
        (Some(index), Some(alias)) if index != alias => TargetResolution::Ambiguous,
        (Some(luid), _) | (_, Some(luid)) => TargetResolution::Luid(luid),
    }
}

/// Read one LUID once and prove that the index and the GUID stayed with it for
/// the whole read.
///
/// `expected_guid` is `Some` for a retained observer. A different GUID then
/// proves that Windows reused the LUID for another adapter, so the retained
/// interface is gone and the other adapter's status is not read. With `None`
/// the observer binds to the GUID it reads now. A disagreement between the
/// index and the GUID lookup is unknown, not removal.
fn probe_luid_with(tables: &dyn LinkTables, luid: u64, expected_guid: Option<Guid>) -> LinkProbe {
    if luid == 0 {
        return LinkProbe::Unavailable;
    }
    let index = match tables.index_for_luid(luid) {
        Ok(value) => value,
        Err(_) => return LinkProbe::Unavailable,
    };
    let guid = match tables.guid_for_luid(luid) {
        Ok(value) => value,
        Err(_) => return LinkProbe::Unavailable,
    };
    let (index, guid) = match (index, guid) {
        (None, None) => return LinkProbe::Removed,
        (Some(index), Some(guid)) => (index, guid),
        // One lookup found the LUID and the other did not. The tables disagree,
        // so the answer is unknown.
        (None, Some(_)) | (Some(_), None) => return LinkProbe::Unavailable,
    };
    if !valid_interface_index(index) || guid.is_zero() {
        return LinkProbe::Unavailable;
    }
    if let Some(expected) = expected_guid {
        if guid != expected {
            // The retained LUID now names another adapter. The interface this
            // observer bound to is gone. Do not read the other adapter's
            // status or addresses and present them as the retained interface.
            return LinkProbe::Removed;
        }
    }
    let identity = PhysicalIdentity { luid, guid };
    let reverse_luid = match tables.luid_for_index(index) {
        Ok(Some(value)) if value == luid => value,
        // The index now names another interface, or the table did not answer.
        Ok(_) => return LinkProbe::Unavailable,
        Err(_) => return LinkProbe::Unavailable,
    };
    let status = match tables.interface_status(index) {
        Ok(Some(status)) => status,
        // The index is in the LUID table but not the status table. That is an
        // inconsistent read, not proof of link loss.
        Ok(None) => return LinkProbe::Unavailable,
        Err(_) => return LinkProbe::Unavailable,
    };
    let ipv4 = match tables.ipv4_addresses() {
        Ok(rows) => rows.into_iter().filter(|row| row.index == index).collect(),
        Err(_) => return LinkProbe::Unavailable,
    };
    // Prove the identity again after the address read. This catches a removed
    // adapter and a reused index or LUID during the observation.
    match tables.luid_for_index(index) {
        Ok(Some(value)) if value == luid => {}
        _ => return LinkProbe::Unavailable,
    }
    let final_guid = match tables.guid_for_luid(luid) {
        Ok(Some(value)) if value == guid => value,
        _ => return LinkProbe::Unavailable,
    };
    LinkProbe::Identified {
        identity,
        row: IdentifiedRow {
            index,
            luid: reverse_luid,
            guid: final_guid,
            status,
            ipv4,
        },
    }
}

/// Resolve and read one target once. A target that no longer resolves is
/// unknown, because a one-shot read cannot tell a rename from a removal.
fn probe_with(tables: &dyn LinkTables, target: &str) -> LinkProbe {
    match resolve_target_with(tables, target) {
        TargetResolution::Luid(luid) => probe_luid_with(tables, luid, None),
        TargetResolution::Absent | TargetResolution::Ambiguous => LinkProbe::Unresolved,
        TargetResolution::Unavailable => LinkProbe::Unavailable,
    }
}

/// One retained link observation with the live index.
///
/// A caller that pinned an interface index at start must compare the
/// `interface_index` field with that pin. The observer follows the retained
/// LUID and GUID, so a link change can move the same adapter to a new index.
/// The pinned index then names no adapter, or it names another adapter after
/// Windows reuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedLinkSample {
    /// True for a conclusive up link, false for a conclusive down link.
    pub up: bool,
    /// The live index for the retained identity, or `None` when the retained
    /// identity is gone.
    pub interface_index: Option<u32>,
}

/// A retained interface identity for repeated link observations.
///
/// Bind once after the tunnel selects the physical interface, then call
/// [`observe`](Self::observe) for every sample of that tunnel's lifetime. The
/// observer resolves the index and the status from the retained LUID and GUID.
/// It never resolves the alias again, so a rename does not look like a removed
/// interface, and a reused alias does not select another interface. A caller
/// that also pinned an index must use [`observe_sample`](Self::observe_sample)
/// and stop when the live index differs from its pin, because the pin does not
/// follow the adapter.
///
/// The Windows direct start binds [`bind_retained`](Self::bind_retained) with
/// the exact index, LUID, and GUID from its outer adapter proof. That path does
/// not resolve an alias. It stays behind the closed direct evidence gate. The
/// CLI and GUI do not use this observer, because `autostop::link_observation`
/// returns `Unsupported` on Windows. Windows auto-stop therefore stays off
/// until an independent review and a native Windows test pass. Do not describe
/// Windows auto-stop as working.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedPhysicalLinkObserver {
    identity: PhysicalIdentity,
}

impl RetainedPhysicalLinkObserver {
    /// Bind to one interface by alias or numeric index.
    ///
    /// An absent, ambiguous, or unreadable target is an error. The observer
    /// holds no address or token. A production direct start must not use this
    /// path: it must retain the exact identity from its outer adapter proof and
    /// call [`bind_retained`](Self::bind_retained) instead.
    pub fn bind(target: &str) -> io::Result<Self> {
        Self::bind_with(&SystemLinkTables, target)
    }

    /// Bind to one exact retained adapter identity.
    ///
    /// The caller must retain the index, LUID, and GUID from the same proof
    /// that selected the physical outer adapter. This function reads the live
    /// index and GUID for the retained LUID once and fails closed when either
    /// differs from the retained value. It never resolves an alias and never
    /// selects an interface by its link state. Later observations follow the
    /// retained LUID and GUID, so an index change for the same adapter is not
    /// link loss here. A caller that pinned the returned index must compare
    /// [`observe_sample`](Self::observe_sample) with that pin and stop when the
    /// index differs.
    pub fn bind_retained(identity: RetainedAdapterIdentity) -> io::Result<Self> {
        Self::bind_retained_with(&SystemLinkTables, identity)
    }

    /// Observe the retained interface. A conclusive down state returns
    /// `Ok(false)`. An inconclusive read returns `Err`.
    pub fn observe(&self) -> io::Result<bool> {
        self.observe_with(&SystemLinkTables)
    }

    /// Observe the retained interface and return its live index.
    ///
    /// A caller that pinned an index at start must compare the returned index
    /// with that pin. The observer follows the retained LUID and GUID, so a link
    /// change can move the same adapter to a new index. Continuing to use the
    /// old pin would then send outer traffic to no adapter, or to another
    /// adapter after Windows reuses the index. An absent index means the
    /// retained identity is gone. An inconclusive read returns `Err`.
    pub fn observe_sample(&self) -> io::Result<RetainedLinkSample> {
        self.observe_sample_with(&SystemLinkTables)
    }

    fn bind_with(tables: &dyn LinkTables, target: &str) -> io::Result<Self> {
        validate_link_target(target)?;
        match resolve_target_with(tables, target) {
            TargetResolution::Luid(luid) => {
                let guid = match tables.guid_for_luid(luid) {
                    Ok(Some(guid)) if !guid.is_zero() => guid,
                    Ok(_) => {
                        return Err(io::Error::other("the interface identity is unavailable"));
                    }
                    Err(_) => {
                        return Err(io::Error::other("the interface identity is unavailable"));
                    }
                };
                Ok(Self {
                    identity: PhysicalIdentity { luid, guid },
                })
            }
            TargetResolution::Absent => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the interface is not present",
            )),
            TargetResolution::Ambiguous => {
                Err(io::Error::other("the interface target is ambiguous"))
            }
            TargetResolution::Unavailable => {
                Err(io::Error::other("the interface identity is unavailable"))
            }
        }
    }

    fn bind_retained_with(
        tables: &dyn LinkTables,
        retained: RetainedAdapterIdentity,
    ) -> io::Result<Self> {
        let unavailable = || io::Error::other("the retained interface identity is unavailable");
        // Read the live identity for the retained LUID. The retained GUID is
        // compared below, after the read proves that the index and LUID still
        // describe one row.
        let probe = probe_luid_with(tables, retained.interface_luid(), None);
        let LinkProbe::Identified { row, .. } = probe else {
            return Err(unavailable());
        };
        retained
            .matches(LiveAdapterIdentity {
                interface_index: row.index,
                interface_guid: row.guid.route_verify_guid(),
            })
            .map_err(|_| unavailable())?;
        // The match above proved that the live GUID is the retained GUID, so
        // the observer can keep the live value without another conversion.
        Ok(Self {
            identity: PhysicalIdentity {
                luid: retained.interface_luid(),
                guid: row.guid,
            },
        })
    }

    fn observe_with(&self, tables: &dyn LinkTables) -> io::Result<bool> {
        self.observe_sample_with(tables).map(|sample| sample.up)
    }

    fn observe_sample_with(&self, tables: &dyn LinkTables) -> io::Result<RetainedLinkSample> {
        let probe = probe_luid_with(tables, self.identity.luid, Some(self.identity.guid));
        let interface_index = match &probe {
            LinkProbe::Identified { row, .. } => Some(row.index),
            LinkProbe::Removed => None,
            LinkProbe::Unavailable | LinkProbe::Unresolved => {
                return Err(io::Error::other("the physical link state is unknown"))
            }
        };
        match classify_link(&probe) {
            LinkStatus::Up => Ok(RetainedLinkSample {
                up: true,
                interface_index,
            }),
            LinkStatus::Down => Ok(RetainedLinkSample {
                up: false,
                interface_index,
            }),
            LinkStatus::Unknown => Err(io::Error::other("the physical link state is unknown")),
        }
    }
}

/// Classify one probe. This function is pure and reads no interface.
///
/// A row counts only when its index is valid, its LUID matches the identity,
/// and its GUID matches the identity. A mismatch means the table moved under
/// the observation, so the answer is unknown. A present row that is
/// administratively or operationally down is a conclusive down. A transient or
/// undocumented raw status is unknown. A present, up row without a live usable
/// IPv4 address is down, because the tunnel cannot use it.
fn classify_link(probe: &LinkProbe) -> LinkStatus {
    match probe {
        LinkProbe::Unavailable | LinkProbe::Unresolved => LinkStatus::Unknown,
        LinkProbe::Removed => LinkStatus::Down,
        LinkProbe::Identified { identity, row } => {
            if !valid_interface_index(row.index)
                || row.luid != identity.luid
                || row.guid != identity.guid
            {
                return LinkStatus::Unknown;
            }
            match row.status.admin {
                LinkStatus::Down => return LinkStatus::Down,
                LinkStatus::Unknown => return LinkStatus::Unknown,
                LinkStatus::Up => {}
            }
            match row.status.oper {
                LinkStatus::Down => LinkStatus::Down,
                LinkStatus::Unknown => LinkStatus::Unknown,
                LinkStatus::Up => {
                    if row.ipv4.iter().any(usable_ipv4_entry) {
                        LinkStatus::Up
                    } else {
                        LinkStatus::Down
                    }
                }
            }
        }
    }
}

/// Observe the physical interface that an alias or numeric index names.
///
/// The target is resolved once per call. It may be an interface alias or an
/// interface index, the forms that the tunnel start path accepts. The observer
/// retains the LUID and GUID for the whole read and proves them again after
/// the address read. A conclusive down state returns `Ok(false)`. An
/// inconclusive read returns `Err`, so the auto-stop policy can treat it as
/// unknown instead of link loss.
///
/// This is a one-shot observation. It resolves the target again on every call,
/// so it cannot tell an alias rename or alias reuse from a removal across
/// samples. Use [`RetainedPhysicalLinkObserver`] for a long-lived sample loop.
/// The Windows auto-stop gate is still closed, so this function does not enable
/// production auto-stop.
///
/// A link-up result with a usable IPv4 address does not prove that the
/// interface is a hotspot, that it is the hotspot that the tunnel uses, or
/// that the internet works. It proves only that the interface exists, is
/// administratively and operationally up, and has one live unicast IPv4
/// address. Never use this result to choose a physical interface or a source
/// device.
pub fn physical_link_observation(target: &str) -> io::Result<bool> {
    validate_link_target(target)?;
    match classify_link(&probe_with(&SystemLinkTables, target)) {
        LinkStatus::Up => Ok(true),
        LinkStatus::Down => Ok(false),
        LinkStatus::Unknown => Err(io::Error::other("the physical link state is unknown")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_route_verify::RouteVerifyError;
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<Vec<String>>>,
        adds: Mutex<usize>,
        fail_add_index: Mutex<Option<usize>>,
        fail_delete: Mutex<bool>,
    }

    impl CommandRunner for Fake {
        fn run(&self, program: &Path, args: &[String]) -> io::Result<()> {
            let mut call = vec![program.to_string_lossy().into_owned()];
            call.extend_from_slice(args);
            self.calls.lock().unwrap().push(call);
            let is_add = args.iter().any(|value| value == "ADD" || value == "add");
            if is_add {
                let mut adds = self.adds.lock().unwrap();
                let index = *adds;
                *adds += 1;
                if *self.fail_add_index.lock().unwrap() == Some(index) {
                    return Err(io::Error::other("add failed"));
                }
            }
            let is_delete = args
                .iter()
                .any(|value| value == "DELETE" || value == "delete");
            if is_delete && *self.fail_delete.lock().unwrap() {
                return Err(io::Error::other("delete failed"));
            }
            Ok(())
        }
    }

    const TEST_INDEX: u32 = 7;
    const TEST_LUID: u64 = 0x0000_6000_0000_0007;

    fn test_identity() -> TunnelIdentity {
        TunnelIdentity::new(TEST_INDEX, TEST_LUID).unwrap()
    }

    fn identity_at(index: u32) -> TunnelIdentity {
        TunnelIdentity::new(index, TEST_LUID).unwrap()
    }

    fn test_guid() -> Guid {
        adapter_guid(&adapter_name(0))
    }

    fn other_guid() -> Guid {
        adapter_guid(&adapter_name(1))
    }

    fn test_ownership() -> AdapterOwnership {
        AdapterOwnership {
            identity: test_identity(),
            guid: test_guid(),
        }
    }

    /// Returns fixed interface values for the retained LUID. It creates no
    /// interface and changes no route.
    struct FakeResolver {
        current: Mutex<Option<u32>>,
        guid: Mutex<Option<Guid>>,
        fail: Mutex<bool>,
    }

    impl Default for FakeResolver {
        fn default() -> Self {
            Self {
                current: Mutex::new(Some(TEST_INDEX)),
                guid: Mutex::new(Some(test_guid())),
                fail: Mutex::new(false),
            }
        }
    }

    impl FakeResolver {
        fn at(index: u32) -> Arc<Self> {
            let resolver = Self::default();
            *resolver.current.lock().unwrap() = Some(index);
            Arc::new(resolver)
        }

        fn absent() -> Arc<Self> {
            let resolver = Self::default();
            *resolver.current.lock().unwrap() = None;
            *resolver.guid.lock().unwrap() = None;
            Arc::new(resolver)
        }

        fn recycled(index: u32, guid: Guid) -> Arc<Self> {
            let resolver = Self::default();
            *resolver.current.lock().unwrap() = Some(index);
            *resolver.guid.lock().unwrap() = Some(guid);
            Arc::new(resolver)
        }
    }

    impl InterfaceResolver for FakeResolver {
        fn index_for_luid(&self, luid: u64) -> io::Result<Option<u32>> {
            assert_eq!(luid, TEST_LUID);
            if *self.fail.lock().unwrap() {
                return Err(io::Error::other("resolver failed"));
            }
            Ok(*self.current.lock().unwrap())
        }

        fn guid_for_luid(&self, luid: u64) -> io::Result<Option<Guid>> {
            assert_eq!(luid, TEST_LUID);
            if *self.fail.lock().unwrap() {
                return Err(io::Error::other("resolver failed"));
            }
            Ok(*self.guid.lock().unwrap())
        }
    }

    fn test_netsh() -> PathBuf {
        PathBuf::from(r"C:\Windows\System32\netsh.exe")
    }

    /// Records the device cleanup calls. The fake function pointers never
    /// dereference a handle, so this test creates no device.
    static DROP_ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    unsafe extern "system" fn record_end_session(_: Handle) {
        DROP_ORDER.lock().unwrap().push("session");
    }

    unsafe extern "system" fn record_close_adapter(_: Handle) {
        DROP_ORDER.lock().unwrap().push("adapter");
    }

    unsafe extern "system" fn unused_create_adapter(
        _: *const u16,
        _: *const u16,
        _: *const Guid,
    ) -> Handle {
        panic!("the drop-order test must not create an adapter")
    }

    unsafe extern "system" fn unused_get_adapter_luid(_: Handle, _: *mut u64) {
        panic!("the drop-order test must not read a LUID")
    }

    unsafe extern "system" fn unused_start_session(_: Handle, _: u32) -> Handle {
        panic!("the drop-order test must not start a session")
    }

    unsafe extern "system" fn unused_read_wait_event(_: Handle) -> Handle {
        panic!("the drop-order test must not read an event")
    }

    unsafe extern "system" fn unused_receive_packet(_: Handle, _: *mut u32) -> *mut u8 {
        panic!("the drop-order test must not receive a packet")
    }

    unsafe extern "system" fn unused_release_receive_packet(_: Handle, _: *const u8) {
        panic!("the drop-order test must not release a packet")
    }

    unsafe extern "system" fn unused_allocate_send_packet(_: Handle, _: u32) -> *mut u8 {
        panic!("the drop-order test must not allocate a packet")
    }

    unsafe extern "system" fn unused_send_packet(_: Handle, _: *const u8) {
        panic!("the drop-order test must not send a packet")
    }

    static DROP_TEST_API: WintunApi = WintunApi {
        create_adapter: unused_create_adapter,
        close_adapter: record_close_adapter,
        get_adapter_luid: unused_get_adapter_luid,
        start_session: unused_start_session,
        end_session: record_end_session,
        read_wait_event: unused_read_wait_event,
        receive_packet: unused_receive_packet,
        release_receive_packet: unused_release_receive_packet,
        allocate_send_packet: unused_allocate_send_packet,
        send_packet: unused_send_packet,
    };

    #[test]
    fn the_session_ends_before_the_adapter_closes() {
        DROP_ORDER.lock().unwrap().clear();
        {
            let _device = Utun {
                session: SessionHandle {
                    api: &DROP_TEST_API,
                    handle: 1 as Handle,
                },
                adapter: AdapterHandle {
                    api: &DROP_TEST_API,
                    handle: 2 as Handle,
                },
                api: &DROP_TEST_API,
                event: 3 as Handle,
                ifname: adapter_name(0),
                ifindex: TEST_INDEX,
                ownership: test_ownership(),
                mtu: TUNNEL_MTU,
            };
        }
        assert_eq!(*DROP_ORDER.lock().unwrap(), ["session", "adapter"]);
    }

    fn route_manager(
        ipv6_block: bool,
        fake: &Arc<Fake>,
        resolver: Arc<FakeResolver>,
    ) -> RouteManager {
        RouteManager::with_runner(
            test_ownership(),
            ipv6_block,
            test_netsh(),
            fake.clone(),
            resolver,
        )
        .unwrap()
    }

    fn ipv6_tunnel(fake: &Arc<Fake>, resolver: Arc<FakeResolver>) -> Ipv6Tunnel {
        Ipv6Tunnel::with_runner(test_ownership(), test_netsh(), fake.clone(), resolver).unwrap()
    }

    fn ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[9] = 17;
        packet
    }

    fn ipv6_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = 59;
        packet[7] = 64;
        packet
    }

    #[test]
    fn adapter_names_are_stable_and_valid() {
        assert_eq!(adapter_name(0), "HotspotShade-Tunnel");
        assert_eq!(adapter_name(7), "HotspotShade-Tunnel-7");
        assert!(valid_ifname(&adapter_name(255)));
        assert!(!valid_ifname(""));
        assert!(!valid_ifname("."));
        assert!(!valid_ifname("a/b"));
        assert!(!valid_ifname("a\\b"));
        assert!(!valid_ifname("bad\nname"));
        assert!(!valid_ifname("name=other"));
        assert!(!valid_ifname("name\"quoted"));
        assert!(!valid_ifname(" leading"));
        assert!(!valid_ifname("trailing "));
        assert!(!valid_ifname("trailing."));
        assert!(!valid_ifname("caf\u{e9}"));
        assert!(valid_ifname(&"a".repeat(127)));
        assert!(!valid_ifname(&"a".repeat(128)));
    }

    #[test]
    fn adapter_names_cannot_collide_with_a_wintun_suffix() {
        // Wintun renames a colliding adapter to "<Name> <number>". A suffix
        // always adds a space. No generated unit name may equal that shape.
        let names: Vec<String> = (0..=255).map(adapter_name).collect();
        let unique: HashSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
        for name in &names {
            assert!(valid_ifname(name), "{name}");
            assert!(!name.contains(' '), "{name}");
            for suffix in 1..=1000 {
                let renamed = format!("{name} {suffix}");
                assert!(!unique.contains(&renamed), "{renamed}");
            }
        }
    }

    #[test]
    fn adapter_index_waits_for_registration_with_a_bound() {
        let mut attempts = 0;
        let index = adapter_index_with(0x1234, 4, Duration::ZERO, |luid| {
            assert_eq!(luid, 0x1234);
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from_raw_os_error(1168))
            } else {
                Ok(7)
            }
        })
        .unwrap();
        assert_eq!(index, 7);
        assert_eq!(attempts, 3);

        let mut attempts = 0;
        let error = adapter_index_with(0x1234, 2, Duration::ZERO, |_| {
            attempts += 1;
            Err(io::Error::other("not ready"))
        })
        .unwrap_err();
        assert_eq!(attempts, 2);
        assert_eq!(error.kind(), io::ErrorKind::Other);

        // A zero attempt count still tries once. A caller cannot skip the
        // check and accept an unknown index.
        let mut attempts = 0;
        assert!(adapter_index_with(1, 0, Duration::ZERO, |_| {
            attempts += 1;
            Ok(1)
        })
        .is_ok());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn an_existing_interface_name_stops_the_create() {
        let name = adapter_name(0);
        ensure_no_interface_named_with(&name, |requested| {
            assert_eq!(requested, name);
            Ok(false)
        })
        .unwrap();

        let error = ensure_no_interface_named_with(&name, |_| Ok(true)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains("does not rename or remove"));

        let error = ensure_no_interface_named_with(&name, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "lookup failed",
            ))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_saved_guid_stops_the_create() {
        ensure_no_adapter_with_guid_with("HotspotShade-Tunnel", || Ok(false)).unwrap();

        let error =
            ensure_no_adapter_with_guid_with("HotspotShade-Tunnel", || Ok(true)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains("does not remove it"));

        let error = ensure_no_adapter_with_guid_with("HotspotShade-Tunnel", || {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "lookup failed",
            ))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn interface_lookup_errors_do_not_block_the_tunnel() {
        assert!(interface_lookup_result(0).unwrap());
        for code in [
            ERROR_FILE_NOT_FOUND,
            ERROR_PATH_NOT_FOUND,
            ERROR_NOT_FOUND,
            ERROR_INVALID_PARAMETER,
        ] {
            assert!(!interface_lookup_result(code).unwrap(), "{code}");
        }
        assert_eq!(
            interface_lookup_result(ERROR_ACCESS_DENIED)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn documented_invalid_luid_codes_mean_the_adapter_is_absent() {
        // Microsoft documents ERROR_INVALID_PARAMETER for an invalid LUID.
        // The ownership check requires both the index and the GUID lookup to
        // report absence before it clears a route record. It never deletes on
        // this result.
        for code in [
            ERROR_FILE_NOT_FOUND,
            ERROR_PATH_NOT_FOUND,
            ERROR_NOT_FOUND,
            ERROR_INVALID_PARAMETER,
        ] {
            assert!(
                interface_is_absent(&io::Error::from_raw_os_error(code as i32)),
                "{code}"
            );
        }
        assert!(!interface_is_absent(&io::Error::from_raw_os_error(
            ERROR_ACCESS_DENIED as i32
        )));
        assert!(!interface_is_absent(&io::Error::other("lookup failed")));
    }

    #[test]
    fn a_created_adapter_must_keep_the_requested_name_luid_and_guid() {
        let name = adapter_name(0);
        let ownership = test_ownership();
        let guid = test_guid();
        verify_created_adapter(&name, ownership, Some(&name), Some(TEST_LUID), Some(&guid))
            .unwrap();

        // Windows interface names are case-insensitive. A case-only difference
        // still names the same adapter.
        let lower = name.to_ascii_lowercase();
        verify_created_adapter(&name, ownership, Some(&lower), Some(TEST_LUID), Some(&guid))
            .unwrap();

        // Wintun gave the new adapter a suffix, so the requested name belongs
        // to another adapter. Refuse it.
        let suffixed = format!("{name} 1");
        let error = verify_created_adapter(
            &name,
            ownership,
            Some(&suffixed),
            Some(TEST_LUID),
            Some(&guid),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

        // The requested name maps to a different LUID. Refuse it.
        let error = verify_created_adapter(
            &name,
            ownership,
            Some(&name),
            Some(TEST_LUID + 1),
            Some(&guid),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

        // The LUID maps to a different GUID. Refuse it.
        let other = other_guid();
        let error =
            verify_created_adapter(&name, ownership, Some(&name), Some(TEST_LUID), Some(&other))
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("different GUID"));

        let error = verify_created_adapter(&name, ownership, None, Some(TEST_LUID), Some(&guid))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);

        let error = verify_created_adapter(&name, ownership, Some(&name), Some(TEST_LUID), None)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);

        // A bad index or a zero LUID fails before the name check.
        let bad_index = AdapterOwnership {
            identity: TunnelIdentity {
                interface_index: 0,
                interface_luid: TEST_LUID,
            },
            guid,
        };
        let error =
            verify_created_adapter(&name, bad_index, Some(&name), Some(TEST_LUID), Some(&guid))
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let zero_luid = AdapterOwnership {
            identity: TunnelIdentity {
                interface_index: TEST_INDEX,
                interface_luid: 0,
            },
            guid,
        };
        let error = verify_created_adapter(&name, zero_luid, Some(&name), Some(0), Some(&guid))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let zero_guid = AdapterOwnership {
            identity: test_identity(),
            guid: Guid::ZERO,
        };
        let error =
            verify_created_adapter(&name, zero_guid, Some(&name), Some(TEST_LUID), Some(&guid))
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn an_unused_interface_alias_does_not_exist() {
        // The lookup is read-only. The name is long and unique so it cannot
        // match a real adapter on the test host.
        assert!(!interface_alias_exists("HotspotShade-test-alias-8f3c1d7e").unwrap());
    }

    #[test]
    fn the_tunnel_owner_can_move_to_the_relay_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<Utun>();
    }

    #[test]
    fn dll_load_errors_keep_their_cause() {
        assert_eq!(
            dll_error_kind(ERROR_FILE_NOT_FOUND),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            dll_error_kind(ERROR_PATH_NOT_FOUND),
            io::ErrorKind::NotFound
        );
        assert_eq!(dll_error_kind(ERROR_MOD_NOT_FOUND), io::ErrorKind::NotFound);
        assert_eq!(
            dll_error_kind(ERROR_ACCESS_DENIED),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            dll_error_kind(ERROR_BAD_EXE_FORMAT),
            io::ErrorKind::InvalidData
        );
        assert_eq!(dll_error_kind(1234), io::ErrorKind::Other);

        let path = Path::new(r"C:\App\wintun.dll");
        let missing = dll_load_error(path, ERROR_MOD_NOT_FOUND);
        assert_eq!(missing.kind, io::ErrorKind::NotFound);
        assert!(missing.message.contains(r"C:\App\wintun.dll"));
        let wrong_arch = dll_load_error(path, ERROR_BAD_EXE_FORMAT);
        assert_eq!(wrong_arch.kind, io::ErrorKind::InvalidData);
        assert_ne!(wrong_arch.message, missing.message);
    }

    #[test]
    fn interface_indices_are_24_bit_and_nonzero() {
        assert!(valid_interface_index(1));
        assert!(valid_interface_index(0x00ff_ffff));
        assert!(!valid_interface_index(0));
        assert!(!valid_interface_index(0x0100_0000));
    }

    #[test]
    fn adapter_guid_is_deterministic_and_unique() {
        let first = adapter_guid(&adapter_name(0));
        let again = adapter_guid(&adapter_name(0));
        let other = adapter_guid(&adapter_name(1));
        assert_eq!(first, again);
        assert_ne!(first.data1, other.data1);
        assert_eq!(first.data3 >> 12, 4);
        assert_eq!(first.data4[0] >> 6, 2);
    }

    #[test]
    fn packet_lengths_are_checked_before_a_device_call() {
        assert!(validate_inbound_packet(&ipv4_packet()).is_ok());
        assert!(validate_inbound_packet(&ipv6_packet()).is_ok());
        assert!(validate_outbound_packet(&ipv4_packet(), TUNNEL_MTU).is_ok());
        assert!(validate_outbound_packet(&ipv4_packet(), 19).is_err());
        assert!(validate_inbound_packet(&[]).is_err());
        assert!(validate_inbound_packet(&[0x45; 19]).is_err());
        assert!(validate_inbound_packet(&[0x35; 20]).is_err());
        let mut bad_v4 = ipv4_packet();
        bad_v4[2..4].copy_from_slice(&21u16.to_be_bytes());
        assert!(validate_inbound_packet(&bad_v4).is_err());
        let mut bad_v6 = ipv6_packet();
        bad_v6[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert!(validate_inbound_packet(&bad_v6).is_err());
    }

    #[test]
    fn route_failure_rolls_back_only_created_routes() {
        let fake = Arc::new(Fake::default());
        *fake.fail_add_index.lock().unwrap() = Some(1);
        let mut routes = route_manager(true, &fake, Arc::new(FakeResolver::default()));
        assert!(routes.install().is_err());
        assert!(!routes.has_installed_routes());
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[2].contains(&"delete".to_string()));
        assert!(calls[2].contains(&"prefix=0.0.0.0/1".to_string()));
    }

    #[test]
    fn a_failed_later_route_removes_the_earlier_routes_in_reverse_order() {
        let fake = Arc::new(Fake::default());
        *fake.fail_add_index.lock().unwrap() = Some(2);
        let mut routes = route_manager(true, &fake, Arc::new(FakeResolver::default()));
        assert!(routes.install().is_err());
        assert!(!routes.has_installed_routes());
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 5);
        assert!(calls[3].contains(&"delete".to_string()));
        assert!(calls[3].contains(&"prefix=128.0.0.0/1".to_string()));
        assert!(calls[4].contains(&"delete".to_string()));
        assert!(calls[4].contains(&"prefix=0.0.0.0/1".to_string()));
    }

    #[test]
    fn block_installs_the_ipv6_route_and_removes_it_first() {
        let fake = Arc::new(Fake::default());
        let mut routes = route_manager(true, &fake, Arc::new(FakeResolver::default()));
        routes.install().unwrap();
        routes.remove().unwrap();
        routes.remove().unwrap();
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 6);
        assert!(calls[2].contains(&"prefix=2000::/3".to_string()));
        assert!(calls[3].contains(&"prefix=2000::/3".to_string()));
        assert!(calls[3].contains(&"delete".to_string()));
    }

    #[test]
    fn failed_cleanup_is_recorded_and_can_be_retried() {
        let fake = Arc::new(Fake::default());
        let mut routes = route_manager(true, &fake, Arc::new(FakeResolver::default()));
        routes.install().unwrap();
        *fake.fail_delete.lock().unwrap() = true;
        assert!(routes.remove().is_err());
        assert!(routes.has_installed_routes());
        *fake.fail_delete.lock().unwrap() = false;
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn inherit_has_no_ipv6_route() {
        let fake = Arc::new(Fake::default());
        let mut routes = route_manager(false, &fake, Arc::new(FakeResolver::default()));
        routes.install().unwrap();
        assert_eq!(fake.calls.lock().unwrap().len(), 2);
        routes.remove().unwrap();
    }

    #[test]
    fn routes_reject_bad_identities_and_relative_tools() {
        let ownership = |interface_index, interface_luid| AdapterOwnership {
            identity: TunnelIdentity {
                interface_index,
                interface_luid,
            },
            guid: test_guid(),
        };
        for bad in [
            ownership(0, TEST_LUID),
            ownership(u32::MAX, TEST_LUID),
            ownership(TEST_INDEX, 0),
            AdapterOwnership {
                identity: test_identity(),
                guid: Guid::ZERO,
            },
        ] {
            assert!(RouteManager::with_runner(
                bad,
                false,
                test_netsh(),
                Arc::new(Fake::default()),
                Arc::new(FakeResolver::default()),
            )
            .is_err());
        }
        assert!(RouteManager::with_runner(
            test_ownership(),
            false,
            PathBuf::from("netsh.exe"),
            Arc::new(Fake::default()),
            Arc::new(FakeResolver::default()),
        )
        .is_err());
    }

    #[test]
    fn route_commands_use_an_absolute_system_tool_path() {
        let fake = Arc::new(Fake::default());
        let mut routes = route_manager(true, &fake, Arc::new(FakeResolver::default()));
        routes.install().unwrap();
        let calls = fake.calls.lock().unwrap();
        for call in calls.iter() {
            assert_eq!(call[0], r"C:\Windows\System32\netsh.exe");
            assert!(call.contains(&"interface=7".to_string()));
            assert!(call.contains(&"store=active".to_string()));
        }
        assert!(calls[0].contains(&"prefix=0.0.0.0/1".to_string()));
        assert!(calls[1].contains(&"prefix=128.0.0.0/1".to_string()));
        assert!(calls[2].contains(&"prefix=2000::/3".to_string()));
    }

    #[test]
    fn routes_keep_the_creation_luid_when_the_index_changes() {
        let fake = Arc::new(Fake::default());
        let mut routes = route_manager(false, &fake, FakeResolver::at(9));
        assert_eq!(routes.identity(), test_identity());
        routes.install().unwrap();
        assert_eq!(routes.identity(), identity_at(9));
        let calls = fake.calls.lock().unwrap();
        for call in calls.iter() {
            assert!(call.contains(&"interface=9".to_string()));
        }
    }

    #[test]
    fn routes_do_not_install_when_the_adapter_is_gone() {
        let fake = Arc::new(Fake::default());
        let mut routes = route_manager(false, &fake, FakeResolver::absent());
        let error = routes.install().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(fake.calls.lock().unwrap().is_empty());
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn cleanup_skips_a_reused_index_when_the_adapter_is_gone() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut routes = route_manager(true, &fake, resolver.clone());
        routes.install().unwrap();
        let installed_calls = fake.calls.lock().unwrap().len();

        // The adapter is gone, and another adapter can own index 7 now. Both
        // lookups must report absence. Do not send a delete command.
        *resolver.current.lock().unwrap() = None;
        *resolver.guid.lock().unwrap() = None;
        routes.remove().unwrap();
        assert_eq!(fake.calls.lock().unwrap().len(), installed_calls);
        assert!(!routes.has_installed_routes());
        assert_eq!(routes.identity().interface_luid, TEST_LUID);
    }

    #[test]
    fn cleanup_uses_the_current_index_after_a_link_change() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut routes = route_manager(true, &fake, resolver.clone());
        routes.install().unwrap();
        *resolver.current.lock().unwrap() = Some(9);
        routes.remove().unwrap();

        let calls = fake.calls.lock().unwrap();
        for call in calls[3..].iter() {
            assert!(call.contains(&"delete".to_string()));
            assert!(call.contains(&"interface=9".to_string()));
        }
        assert!(!routes.has_installed_routes());
        assert_eq!(routes.identity().interface_luid, TEST_LUID);
    }

    #[test]
    fn a_failed_ownership_check_keeps_the_routes() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut routes = route_manager(false, &fake, resolver.clone());
        routes.install().unwrap();
        let installed_calls = fake.calls.lock().unwrap().len();

        *resolver.fail.lock().unwrap() = true;
        assert!(routes.remove().is_err());
        assert_eq!(fake.calls.lock().unwrap().len(), installed_calls);
        assert!(routes.has_installed_routes());

        // A later attempt can still remove the routes.
        *resolver.fail.lock().unwrap() = false;
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn an_invalid_resolved_index_keeps_the_routes() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut routes = route_manager(false, &fake, resolver.clone());
        routes.install().unwrap();
        let installed_calls = fake.calls.lock().unwrap().len();

        *resolver.current.lock().unwrap() = Some(0);
        assert!(routes.remove().is_err());
        assert_eq!(fake.calls.lock().unwrap().len(), installed_calls);
        assert!(routes.has_installed_routes());

        // A later resolution can still remove the routes.
        *resolver.current.lock().unwrap() = Some(TEST_INDEX);
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn ownership_requires_the_index_and_the_guid() {
        let ownership = test_ownership();
        assert_eq!(
            ownership_from_lookups(ownership, Some(9), Some(test_guid())).unwrap(),
            Some(9)
        );
        assert!(ownership_from_lookups(ownership, Some(9), Some(other_guid())).is_err());
        assert!(ownership_from_lookups(ownership, Some(9), None).is_err());
        assert!(ownership_from_lookups(ownership, None, Some(test_guid())).is_err());
        assert_eq!(ownership_from_lookups(ownership, None, None).unwrap(), None);
        assert!(ownership_from_lookups(ownership, Some(0), Some(test_guid())).is_err());
    }

    #[test]
    fn a_recycled_luid_does_not_delete_routes() {
        // The LUID is reused, with the old index and with a new index.
        for index in [TEST_INDEX, 11] {
            let fake = Arc::new(Fake::default());
            let resolver = Arc::new(FakeResolver::default());
            let mut routes = route_manager(true, &fake, resolver.clone());
            routes.install().unwrap();
            let installed_calls = fake.calls.lock().unwrap().len();

            *resolver.current.lock().unwrap() = Some(index);
            *resolver.guid.lock().unwrap() = Some(other_guid());
            let error = routes.remove().unwrap_err();
            assert!(error.to_string().contains("different adapter"), "{error}");
            assert_eq!(fake.calls.lock().unwrap().len(), installed_calls);
            assert!(routes.has_installed_routes());

            // The ownership check can succeed again on a later attempt.
            *resolver.guid.lock().unwrap() = Some(test_guid());
            routes.remove().unwrap();
            assert!(!routes.has_installed_routes());
            let calls = fake.calls.lock().unwrap();
            for call in calls[installed_calls..].iter() {
                assert!(call.contains(&"delete".to_string()));
                assert!(call.contains(&format!("interface={index}")));
            }
        }
    }

    #[test]
    fn install_refuses_a_recycled_luid() {
        let fake = Arc::new(Fake::default());
        let mut routes = route_manager(
            true,
            &fake,
            FakeResolver::recycled(TEST_INDEX, other_guid()),
        );
        let error = routes.install().unwrap_err();
        assert!(error.to_string().contains("different adapter"), "{error}");
        assert!(fake.calls.lock().unwrap().is_empty());
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn an_unverified_guid_lookup_keeps_the_routes() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut routes = route_manager(false, &fake, resolver.clone());
        routes.install().unwrap();
        let installed_calls = fake.calls.lock().unwrap().len();

        // The index exists, but the GUID lookup does not answer.
        *resolver.guid.lock().unwrap() = None;
        let error = routes.remove().unwrap_err();
        assert!(
            error.to_string().contains("GUID is not available"),
            "{error}"
        );
        assert_eq!(fake.calls.lock().unwrap().len(), installed_calls);
        assert!(routes.has_installed_routes());

        *resolver.guid.lock().unwrap() = Some(test_guid());
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn an_inconsistent_absent_lookup_keeps_the_routes() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut routes = route_manager(false, &fake, resolver.clone());
        routes.install().unwrap();
        let installed_calls = fake.calls.lock().unwrap().len();

        // The GUID exists, but the index lookup does not answer. This is not
        // proof that the adapter is absent.
        *resolver.current.lock().unwrap() = None;
        let error = routes.remove().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("interface index is not available"),
            "{error}"
        );
        assert_eq!(fake.calls.lock().unwrap().len(), installed_calls);
        assert!(routes.has_installed_routes());

        *resolver.current.lock().unwrap() = Some(TEST_INDEX);
        routes.remove().unwrap();
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn verification_uses_the_current_index() {
        let fake = Arc::new(Fake::default());
        let routes = route_manager(false, &fake, FakeResolver::at(9));
        let policy = routes.verify_policy().unwrap();
        assert_eq!(policy.tunnel, identity_at(9));
        assert_eq!(policy.tunnel.interface_luid, TEST_LUID);
        assert_eq!(policy.ipv6, Ipv6RoutePolicy::Inherit);
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn verification_refuses_a_recycled_luid() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let routes = route_manager(true, &fake, resolver.clone());
        *resolver.guid.lock().unwrap() = Some(other_guid());
        let error = routes.verify().unwrap_err();
        assert!(
            matches!(error, RouteVerifyError::InvalidTunnelIdentity(_)),
            "{error:?}"
        );
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn route_verification_fails_closed_for_the_inherit_policy() {
        let routes = RouteManager::with_runner(
            test_ownership(),
            false,
            test_netsh(),
            Arc::new(Fake::default()),
            Arc::new(FakeResolver::default()),
        )
        .unwrap();
        assert_eq!(
            routes.verify().unwrap_err(),
            RouteVerifyError::Ipv6InheritNotVerifiable
        );
    }

    #[test]
    fn system_tool_path_accepts_one_plain_name_only() {
        let system = Path::new(r"C:\Windows\System32");
        assert_eq!(
            system_tool_path("netsh.exe", system).unwrap(),
            PathBuf::from(r"C:\Windows\System32\netsh.exe")
        );
        for tool in [
            "",
            "netsh",
            r"..\netsh.exe",
            r"sub\netsh.exe",
            r"C:\Windows\System32\netsh.exe",
            "netsh.exe:stream",
        ] {
            assert!(system_tool_path(tool, system).is_err(), "{tool}");
        }
        assert!(system_tool_path("netsh.exe", Path::new("System32")).is_err());
    }

    #[test]
    fn wintun_is_loaded_only_beside_the_executable() {
        let executable = Path::new(r"C:\Program Files\HotspotShade\hotspotshade.exe");
        assert_eq!(
            wintun_path(executable).unwrap(),
            PathBuf::from(r"C:\Program Files\HotspotShade\wintun.dll")
        );
        assert!(wintun_path(Path::new("hotspotshade.exe")).is_err());
    }

    #[test]
    fn secure_load_flags_do_not_search_user_directories() {
        assert_eq!(
            SECURE_LOAD_FLAGS & LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
        );
        assert_eq!(
            SECURE_LOAD_FLAGS & LOAD_LIBRARY_SEARCH_SYSTEM32,
            LOAD_LIBRARY_SEARCH_SYSTEM32
        );
        // LOAD_LIBRARY_SEARCH_USER_DIRS. Do not add it.
        assert_eq!(SECURE_LOAD_FLAGS & 0x0000_0400, 0);
    }

    #[test]
    fn link_configuration_uses_the_tunnel_subnet_and_active_store() {
        let fake = Fake::default();
        configure_link_with(
            &fake,
            &test_netsh(),
            TEST_INDEX,
            "198.18.0.5".parse().unwrap(),
            1500,
        )
        .unwrap();
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[0][0], r"C:\Windows\System32\netsh.exe");
        assert!(calls[0].contains(&"name=7".to_string()));
        assert!(calls[0].contains(&"address=198.18.0.5".to_string()));
        assert!(calls[0].contains(&"mask=255.255.255.252".to_string()));
        assert!(calls[0].contains(&"store=active".to_string()));
        assert!(calls[1].contains(&"interface=7".to_string()));
        assert!(calls[1].contains(&"mtu=1500".to_string()));
        assert!(
            configure_link_with(&fake, &test_netsh(), 0, "198.18.0.5".parse().unwrap(), 1500)
                .is_err()
        );
        assert!(configure_link_with(
            &fake,
            &test_netsh(),
            TEST_INDEX,
            "198.18.0.0".parse().unwrap(),
            1500
        )
        .is_err());
        assert!(configure_link_with(
            &fake,
            &test_netsh(),
            TEST_INDEX,
            "198.18.0.1".parse().unwrap(),
            0
        )
        .is_err());
        assert!(configure_link_with(
            &fake,
            Path::new("netsh.exe"),
            TEST_INDEX,
            "198.18.0.1".parse().unwrap(),
            1500
        )
        .is_err());
    }

    #[test]
    fn link_configuration_refuses_a_recycled_luid() {
        let addr = "198.18.0.5".parse().unwrap();

        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        configure_link_for_ownership(
            test_ownership(),
            &*resolver,
            &*fake,
            &test_netsh(),
            addr,
            1500,
        )
        .unwrap();
        assert_eq!(fake.calls.lock().unwrap().len(), 2);

        let fake = Arc::new(Fake::default());
        let resolver = FakeResolver::recycled(11, other_guid());
        let error = configure_link_for_ownership(
            test_ownership(),
            &*resolver,
            &*fake,
            &test_netsh(),
            addr,
            1500,
        )
        .unwrap_err();
        assert!(error.to_string().contains("different adapter"), "{error}");
        assert!(fake.calls.lock().unwrap().is_empty());

        let fake = Arc::new(Fake::default());
        let resolver = FakeResolver::absent();
        let error = configure_link_for_ownership(
            test_ownership(),
            &*resolver,
            &*fake,
            &test_netsh(),
            addr,
            1500,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(fake.calls.lock().unwrap().is_empty());

        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        *resolver.guid.lock().unwrap() = None;
        let error = configure_link_for_ownership(
            test_ownership(),
            &*resolver,
            &*fake,
            &test_netsh(),
            addr,
            1500,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("GUID is not available"),
            "{error}"
        );
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn ipv6_rollback_removes_the_address_after_a_route_failure() {
        let fake = Arc::new(Fake::default());
        *fake.fail_add_index.lock().unwrap() = Some(1);
        let mut tunnel = ipv6_tunnel(&fake, Arc::new(FakeResolver::default()));
        assert!(tunnel.install().is_err());
        assert!(!tunnel.has_changes());
        let calls = fake.calls.lock().unwrap();
        assert!(calls.last().unwrap().contains(&"address".to_string()));
        assert!(calls.last().unwrap().contains(&"delete".to_string()));
    }

    #[test]
    fn ipv6_cleanup_removes_the_route_before_the_address() {
        let fake = Arc::new(Fake::default());
        let mut tunnel = ipv6_tunnel(&fake, Arc::new(FakeResolver::default()));
        tunnel.install().unwrap();
        tunnel.remove().unwrap();
        let calls = fake.calls.lock().unwrap();
        assert!(calls[2].contains(&"route".to_string()));
        assert!(calls[2].contains(&"delete".to_string()));
        assert!(calls[3].contains(&"address".to_string()));
        assert!(calls[3].contains(&"delete".to_string()));
        assert!(calls[0][0].ends_with(r"System32\netsh.exe"));
        assert!(tunnel.verify().is_err());
        assert!(!tunnel.has_changes());
    }

    #[test]
    fn ipv6_cleanup_skips_a_reused_index_when_the_adapter_is_gone() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut tunnel = ipv6_tunnel(&fake, resolver.clone());
        tunnel.install().unwrap();
        let installed_calls = fake.calls.lock().unwrap().len();

        *resolver.current.lock().unwrap() = None;
        *resolver.guid.lock().unwrap() = None;
        tunnel.remove().unwrap();
        assert_eq!(fake.calls.lock().unwrap().len(), installed_calls);
        assert!(!tunnel.has_changes());
    }

    #[test]
    fn ipv6_cleanup_refuses_a_recycled_luid() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut tunnel = ipv6_tunnel(&fake, resolver.clone());
        tunnel.install().unwrap();
        let installed_calls = fake.calls.lock().unwrap().len();

        *resolver.current.lock().unwrap() = Some(11);
        *resolver.guid.lock().unwrap() = Some(other_guid());
        let error = tunnel.remove().unwrap_err();
        assert!(error.to_string().contains("different adapter"), "{error}");
        assert_eq!(fake.calls.lock().unwrap().len(), installed_calls);
        assert!(tunnel.has_changes());

        *resolver.guid.lock().unwrap() = Some(test_guid());
        tunnel.remove().unwrap();
        assert!(!tunnel.has_changes());
    }

    #[test]
    fn ipv6_verification_checks_ownership_first() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let tunnel = ipv6_tunnel(&fake, resolver.clone());
        assert_eq!(
            tunnel.verify().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        *resolver.guid.lock().unwrap() = Some(other_guid());
        assert_eq!(
            tunnel.verify().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        *resolver.guid.lock().unwrap() = None;
        assert_eq!(tunnel.verify().unwrap_err().kind(), io::ErrorKind::Other);
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn ipv6_cleanup_uses_the_current_index_after_a_link_change() {
        let fake = Arc::new(Fake::default());
        let resolver = Arc::new(FakeResolver::default());
        let mut tunnel = ipv6_tunnel(&fake, resolver.clone());
        tunnel.install().unwrap();
        *resolver.current.lock().unwrap() = Some(9);
        tunnel.remove().unwrap();
        let calls = fake.calls.lock().unwrap();
        for call in calls[2..].iter() {
            assert!(call.contains(&"delete".to_string()));
            assert!(call.contains(&"interface=9".to_string()));
        }
    }

    #[test]
    fn ipv6_rejects_a_zero_luid_and_a_zero_index() {
        for ownership in [
            AdapterOwnership {
                identity: TunnelIdentity {
                    interface_index: 0,
                    interface_luid: TEST_LUID,
                },
                guid: test_guid(),
            },
            AdapterOwnership {
                identity: TunnelIdentity {
                    interface_index: TEST_INDEX,
                    interface_luid: 0,
                },
                guid: test_guid(),
            },
            AdapterOwnership {
                identity: test_identity(),
                guid: Guid::ZERO,
            },
        ] {
            assert!(Ipv6Tunnel::with_runner(
                ownership,
                test_netsh(),
                Arc::new(Fake::default()),
                Arc::new(FakeResolver::default()),
            )
            .is_err());
        }
    }

    #[test]
    fn wintun_path_must_be_absolute_and_named_wintun_dll() {
        assert!(valid_wintun_path(Path::new(r"C:\tools\wintun.dll")).is_ok());
        assert!(valid_wintun_path(Path::new(r"C:\tools\WINTUN.DLL")).is_ok());
        assert!(valid_wintun_path(Path::new(r"wintun.dll")).is_err());
        assert!(valid_wintun_path(Path::new(r"C:\tools\other.dll")).is_err());
        assert!(valid_wintun_path(Path::new(r"C:\tools")).is_err());
    }

    #[test]
    fn the_default_wintun_path_is_next_to_the_test_executable() {
        let path = default_wintun_path().unwrap();
        assert!(path.is_absolute(), "{}", path.display());
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("wintun.dll")
        );
        assert!(path.parent().is_some());
    }

    #[test]
    fn a_missing_wintun_dll_fails_before_adapter_creation() {
        let missing = Path::new(r"C:\hotspotshade-test\missing\wintun.dll");
        let error = Utun::open_with_dll(0, missing).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        assert!(error.to_string().contains("wintun.dll"), "{error}");
        assert!(error.to_string().contains("missing"), "{error}");
    }

    #[test]
    fn the_system_command_cannot_inherit_the_phone_token() {
        assert_eq!(PHONE_TOKEN_ENV, "HOTSPOTSHADE_PHONE_TOKEN");
        let command = system_command(&test_netsh(), &["interface".into(), "ipv4".into()]);
        assert_eq!(command.get_program(), test_netsh().as_os_str());
        let removed = command
            .get_envs()
            .filter(|(name, value)| *name == OsStr::new(PHONE_TOKEN_ENV) && value.is_none())
            .count();
        assert_eq!(removed, 1);
    }

    #[test]
    fn interface_table_layouts_match_the_windows_headers() {
        // Both structures are fixed on x86 and x64. A wrong field list would
        // read an operational status or an address from the wrong offset.
        assert_eq!(mem::size_of::<MibIfRow>(), 860);
        assert_eq!(mem::align_of::<MibIfRow>(), 4);
        assert_eq!(mem::size_of::<MibIpAddrRow>(), 24);
        assert_eq!(mem::align_of::<MibIpAddrRow>(), 4);
        assert_eq!(mem::offset_of!(MibIfRow, index), 512);
        assert_eq!(mem::offset_of!(MibIfRow, admin_status), 540);
        assert_eq!(mem::offset_of!(MibIfRow, oper_status), 544);
        assert_eq!(mem::offset_of!(MibIpAddrRow, w_type), 22);
    }

    fn ipv4_table_buffer(rows: &[(Ipv4Addr, u32, u16)]) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(rows.len() as u32).to_ne_bytes());
        for (address, index, flags) in rows {
            let mut row = [0u8; 24];
            row[..4].copy_from_slice(&address.octets());
            row[4..8].copy_from_slice(&index.to_ne_bytes());
            row[22..24].copy_from_slice(&flags.to_ne_bytes());
            buffer.extend_from_slice(&row);
        }
        buffer
    }

    #[test]
    fn the_address_table_parser_reads_the_documented_layout() {
        let buffer = ipv4_table_buffer(&[
            (Ipv4Addr::new(192, 168, 1, 20), 7, 0),
            (Ipv4Addr::new(169, 254, 1, 1), 9, 0),
        ]);
        let rows = parse_ipv4_address_table(&buffer, buffer.len() as u32).unwrap();
        assert_eq!(
            rows,
            vec![
                Ipv4AddressEntry {
                    index: 7,
                    address: Ipv4Addr::new(192, 168, 1, 20),
                    flags: 0,
                },
                Ipv4AddressEntry {
                    index: 9,
                    address: Ipv4Addr::new(169, 254, 1, 1),
                    flags: 0,
                },
            ]
        );

        // A reported size smaller than the rows need, or larger than the
        // buffer, is a layout error, not an empty table.
        assert!(parse_ipv4_address_table(&buffer, buffer.len() as u32 - 1).is_err());
        assert!(parse_ipv4_address_table(&buffer, buffer.len() as u32 + 1).is_err());
        let mut shortened = buffer.clone();
        shortened.pop();
        assert!(parse_ipv4_address_table(&shortened, shortened.len() as u32).is_err());

        // The API can report padding beyond the last row. Safe slack is not a
        // layout error, and the parser reads only the rows the count names.
        let mut padded = buffer.clone();
        padded.extend_from_slice(&[0xff; 16]);
        assert_eq!(
            parse_ipv4_address_table(&padded, padded.len() as u32).unwrap(),
            rows
        );

        // An empty table is valid.
        let empty = 0u32.to_ne_bytes();
        assert!(parse_ipv4_address_table(&empty, 4).unwrap().is_empty());
        assert!(parse_ipv4_address_table(&[], 0).is_err());
    }

    #[test]
    fn the_address_table_parser_keeps_the_address_flags() {
        let buffer = ipv4_table_buffer(&[
            (Ipv4Addr::new(192, 168, 1, 20), 7, 0),
            (Ipv4Addr::new(192, 168, 1, 21), 7, MIB_IPADDR_TRANSIENT),
            (Ipv4Addr::new(192, 168, 1, 22), 7, MIB_IPADDR_DELETED),
        ]);
        let rows = parse_ipv4_address_table(&buffer, buffer.len() as u32).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].flags, 0);
        assert_eq!(rows[1].flags, MIB_IPADDR_TRANSIENT);
        assert_eq!(rows[2].flags, MIB_IPADDR_DELETED);
    }

    #[test]
    fn the_address_table_parser_rejects_an_unbounded_row_count() {
        let mut buffer = ((MAX_IPV4_ADDRESS_ROWS + 1) as u32).to_ne_bytes().to_vec();
        buffer.extend_from_slice(&[0; 4]);
        assert!(parse_ipv4_address_table(&buffer, buffer.len() as u32).is_err());
    }

    /// Fixed interface table values for the link observer. It creates no
    /// device and changes no route.
    struct FakeLinkTables {
        alias: Result<Option<u64>, ()>,
        index: Result<Option<u32>, ()>,
        reverse_luid: Result<Option<u64>, ()>,
        /// The first `luid_for_index` answer for a numeric target. `None` uses
        /// `reverse_luid`, which keeps the older single-index tests simple.
        numeric_luid: Option<Result<Option<u64>, ()>>,
        luid_for_index_reads: Mutex<usize>,
        guid: Result<Option<Guid>, ()>,
        guid_after: Option<Guid>,
        guid_reads: Mutex<usize>,
        status: Result<Option<InterfaceStatus>, ()>,
        addresses: Result<Vec<Ipv4AddressEntry>, ()>,
    }

    impl Default for FakeLinkTables {
        fn default() -> Self {
            Self {
                alias: Ok(Some(TEST_LUID)),
                index: Ok(Some(TEST_INDEX)),
                reverse_luid: Ok(Some(TEST_LUID)),
                numeric_luid: None,
                luid_for_index_reads: Mutex::new(0),
                guid: Ok(Some(test_guid())),
                guid_after: None,
                guid_reads: Mutex::new(0),
                status: Ok(Some(InterfaceStatus {
                    admin: LinkStatus::Up,
                    oper: LinkStatus::Up,
                })),
                addresses: Ok(vec![Ipv4AddressEntry {
                    index: TEST_INDEX,
                    address: Ipv4Addr::new(192, 168, 1, 20),
                    flags: 0,
                }]),
            }
        }
    }

    fn fake_error() -> io::Error {
        io::Error::other("fake API failure")
    }

    impl LinkTables for FakeLinkTables {
        fn luid_for_alias(&self, _: &str) -> io::Result<Option<u64>> {
            self.alias.map_err(|_| fake_error())
        }

        fn index_for_luid(&self, _: u64) -> io::Result<Option<u32>> {
            self.index.map_err(|_| fake_error())
        }

        fn luid_for_index(&self, _: u32) -> io::Result<Option<u64>> {
            let mut reads = self.luid_for_index_reads.lock().unwrap();
            let first = *reads == 0;
            *reads += 1;
            let result = if first {
                self.numeric_luid.unwrap_or(self.reverse_luid)
            } else {
                self.reverse_luid
            };
            result.map_err(|_| fake_error())
        }

        fn guid_for_luid(&self, _: u64) -> io::Result<Option<Guid>> {
            let mut reads = self.guid_reads.lock().unwrap();
            let after = *reads > 0;
            *reads += 1;
            match (&self.guid, self.guid_after) {
                (Err(()), _) => Err(fake_error()),
                (Ok(_), Some(guid)) if after => Ok(Some(guid)),
                (Ok(value), _) => Ok(*value),
            }
        }

        fn interface_status(&self, _: u32) -> io::Result<Option<InterfaceStatus>> {
            self.status.map_err(|_| fake_error())
        }

        fn ipv4_addresses(&self) -> io::Result<Vec<Ipv4AddressEntry>> {
            self.addresses.clone().map_err(|_| fake_error())
        }
    }

    fn link_status(tables: &FakeLinkTables) -> LinkStatus {
        classify_link(&probe_with(tables, "Ethernet"))
    }

    fn address_entry(index: u32, address: &str) -> Ipv4AddressEntry {
        address_entry_with_flags(index, address, 0)
    }

    fn address_entry_with_flags(index: u32, address: &str, flags: u16) -> Ipv4AddressEntry {
        Ipv4AddressEntry {
            index,
            address: address.parse().unwrap(),
            flags,
        }
    }

    fn up_status() -> InterfaceStatus {
        InterfaceStatus {
            admin: LinkStatus::Up,
            oper: LinkStatus::Up,
        }
    }

    #[test]
    fn usable_ipv4_rejects_non_unicast_and_unconfigured_addresses() {
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
            assert!(!usable_ipv4(unusable.parse().unwrap()), "{unusable}");
        }
        for usable in ["10.0.0.2", "172.20.10.2", "192.168.1.20", "100.64.0.2"] {
            assert!(usable_ipv4(usable.parse().unwrap()), "{usable}");
        }
    }

    #[test]
    fn the_legacy_operational_status_enum_maps_to_the_right_state() {
        // GetIfEntry uses the legacy MIB_IF_OPER_STATUS_* values. A healthy
        // interface reports 5, and 4 is connected. The old code compared
        // against IF_OPER_STATUS 1, which is unreachable here, so it marked a
        // healthy link down.
        assert_eq!(
            oper_status_state(MIB_IF_OPER_STATUS_NON_OPERATIONAL),
            LinkStatus::Down
        );
        assert_eq!(
            oper_status_state(MIB_IF_OPER_STATUS_UNREACHABLE),
            LinkStatus::Down
        );
        assert_eq!(
            oper_status_state(MIB_IF_OPER_STATUS_DISCONNECTED),
            LinkStatus::Down
        );
        assert_eq!(
            oper_status_state(MIB_IF_OPER_STATUS_CONNECTING),
            LinkStatus::Unknown
        );
        assert_eq!(
            oper_status_state(MIB_IF_OPER_STATUS_CONNECTED),
            LinkStatus::Up
        );
        assert_eq!(
            oper_status_state(MIB_IF_OPER_STATUS_OPERATIONAL),
            LinkStatus::Up
        );
        assert_eq!(oper_status_state(6), LinkStatus::Unknown);
        assert_eq!(oper_status_state(u32::MAX), LinkStatus::Unknown);
    }

    #[test]
    fn the_administrative_status_enum_maps_to_the_right_state() {
        assert_eq!(admin_status_state(MIB_IF_ADMIN_STATUS_UP), LinkStatus::Up);
        assert_eq!(
            admin_status_state(MIB_IF_ADMIN_STATUS_DOWN),
            LinkStatus::Down
        );
        // Testing is not a usable administrative state. An undocumented value
        // is unknown, not down.
        assert_eq!(admin_status_state(3), LinkStatus::Unknown);
        assert_eq!(admin_status_state(0), LinkStatus::Unknown);
        assert_eq!(admin_status_state(4), LinkStatus::Unknown);
    }

    #[test]
    fn a_connected_or_operational_interface_with_a_usable_address_is_up() {
        for oper in [MIB_IF_OPER_STATUS_CONNECTED, MIB_IF_OPER_STATUS_OPERATIONAL] {
            let tables = FakeLinkTables {
                status: Ok(Some(InterfaceStatus {
                    admin: LinkStatus::Up,
                    oper: oper_status_state(oper),
                })),
                ..FakeLinkTables::default()
            };
            assert_eq!(link_status(&tables), LinkStatus::Up, "{oper}");
        }
    }

    #[test]
    fn a_present_up_interface_with_a_usable_address_is_up() {
        let tables = FakeLinkTables::default();
        assert_eq!(link_status(&tables), LinkStatus::Up);
    }

    #[test]
    fn a_down_or_disabled_interface_is_down() {
        for status in [
            InterfaceStatus {
                admin: LinkStatus::Up,
                oper: LinkStatus::Down,
            },
            InterfaceStatus {
                admin: LinkStatus::Down,
                oper: LinkStatus::Up,
            },
            InterfaceStatus {
                admin: LinkStatus::Down,
                oper: LinkStatus::Down,
            },
        ] {
            let tables = FakeLinkTables {
                status: Ok(Some(status)),
                ..FakeLinkTables::default()
            };
            assert_eq!(link_status(&tables), LinkStatus::Down);
        }
    }

    #[test]
    fn a_transient_administrative_or_operational_state_is_unknown() {
        for status in [
            InterfaceStatus {
                admin: LinkStatus::Unknown,
                oper: LinkStatus::Up,
            },
            InterfaceStatus {
                admin: LinkStatus::Up,
                oper: LinkStatus::Unknown,
            },
        ] {
            let tables = FakeLinkTables {
                status: Ok(Some(status)),
                ..FakeLinkTables::default()
            };
            assert_eq!(link_status(&tables), LinkStatus::Unknown);
        }
    }

    #[test]
    fn an_up_interface_without_a_usable_ipv4_address_is_down() {
        for address in [
            "169.254.10.20",
            "127.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "227.1.1.1",
            "255.255.255.255",
        ] {
            let tables = FakeLinkTables {
                addresses: Ok(vec![address_entry(TEST_INDEX, address)]),
                ..FakeLinkTables::default()
            };
            assert_eq!(link_status(&tables), LinkStatus::Down, "{address}");
        }
        let tables = FakeLinkTables {
            addresses: Ok(Vec::new()),
            ..FakeLinkTables::default()
        };
        assert_eq!(link_status(&tables), LinkStatus::Down);
    }

    #[test]
    fn one_usable_address_among_unusable_ones_is_up() {
        let tables = FakeLinkTables {
            addresses: Ok(vec![
                address_entry(TEST_INDEX, "169.254.10.20"),
                address_entry(TEST_INDEX, "192.168.1.20"),
            ]),
            ..FakeLinkTables::default()
        };
        assert_eq!(link_status(&tables), LinkStatus::Up);
    }

    #[test]
    fn a_transient_deleted_or_disconnected_address_is_not_usable() {
        for flags in [
            MIB_IPADDR_TRANSIENT,
            MIB_IPADDR_DELETED,
            MIB_IPADDR_DISCONNECTED,
        ] {
            let tables = FakeLinkTables {
                addresses: Ok(vec![address_entry_with_flags(
                    TEST_INDEX,
                    "192.168.1.20",
                    flags,
                )]),
                ..FakeLinkTables::default()
            };
            assert_eq!(link_status(&tables), LinkStatus::Down, "{flags:#06x}");
        }

        // A primary or dynamic address without a stale flag is usable.
        for flags in [0x0001, 0x0004, 0x0100] {
            let tables = FakeLinkTables {
                addresses: Ok(vec![address_entry_with_flags(
                    TEST_INDEX,
                    "192.168.1.20",
                    flags,
                )]),
                ..FakeLinkTables::default()
            };
            assert_eq!(link_status(&tables), LinkStatus::Up, "{flags:#06x}");
        }
    }

    #[test]
    fn a_target_that_no_longer_resolves_is_unknown_not_down() {
        // A one-shot read cannot tell a renamed alias or a changed index from
        // a removed interface. Unknown keeps the policy from inventing loss.
        for tables in [
            FakeLinkTables {
                alias: Ok(None),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                alias: Ok(None),
                reverse_luid: Ok(None),
                ..FakeLinkTables::default()
            },
        ] {
            assert_eq!(link_status(&tables), LinkStatus::Unknown);
        }
        let numeric = FakeLinkTables {
            alias: Ok(None),
            reverse_luid: Ok(None),
            ..FakeLinkTables::default()
        };
        assert_eq!(
            classify_link(&probe_with(&numeric, "7")),
            LinkStatus::Unknown
        );
    }

    #[test]
    fn a_retained_interface_that_is_gone_is_down() {
        for tables in [
            FakeLinkTables {
                index: Ok(None),
                guid: Ok(None),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                guid: Ok(Some(other_guid())),
                ..FakeLinkTables::default()
            },
        ] {
            let observer =
                RetainedPhysicalLinkObserver::bind_with(&FakeLinkTables::default(), "Ethernet")
                    .unwrap();
            assert!(!observer.observe_with(&tables).unwrap());
        }
    }

    #[test]
    fn an_api_failure_is_unknown_not_link_loss() {
        let failures: Vec<FakeLinkTables> = vec![
            FakeLinkTables {
                alias: Err(()),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                guid: Err(()),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                guid: Ok(None),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                index: Err(()),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                reverse_luid: Err(()),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                reverse_luid: Ok(None),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                status: Err(()),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                status: Ok(None),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                addresses: Err(()),
                ..FakeLinkTables::default()
            },
        ];
        for tables in failures {
            assert_eq!(link_status(&tables), LinkStatus::Unknown);
        }
    }

    #[test]
    fn a_recycled_index_is_unknown() {
        // The index that the retained LUID resolves to now belongs to another
        // interface. The row cannot prove that it is the retained interface.
        let tables = FakeLinkTables {
            reverse_luid: Ok(Some(TEST_LUID + 1)),
            ..FakeLinkTables::default()
        };
        assert_eq!(link_status(&tables), LinkStatus::Unknown);
    }

    #[test]
    fn a_recycled_luid_is_unknown() {
        // The alias still resolves, but the LUID changes to another GUID
        // during the observation.
        let tables = FakeLinkTables {
            guid_after: Some(other_guid()),
            ..FakeLinkTables::default()
        };
        assert_eq!(link_status(&tables), LinkStatus::Unknown);
    }

    #[test]
    fn a_zero_index_or_luid_is_unknown() {
        for tables in [
            FakeLinkTables {
                index: Ok(Some(0)),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                alias: Ok(Some(0)),
                ..FakeLinkTables::default()
            },
        ] {
            assert_eq!(link_status(&tables), LinkStatus::Unknown);
        }
    }

    #[test]
    fn a_numeric_target_uses_the_interface_index() {
        // The CLI can name the physical interface by index. When no alias of
        // the same name exists, the index supplies the LUID.
        let tables = FakeLinkTables {
            alias: Ok(None),
            ..FakeLinkTables::default()
        };
        assert_eq!(classify_link(&probe_with(&tables, "7")), LinkStatus::Up);
    }

    #[test]
    fn a_missing_numeric_index_and_alias_is_unknown() {
        let tables = FakeLinkTables {
            alias: Ok(None),
            reverse_luid: Ok(None),
            ..FakeLinkTables::default()
        };
        assert_eq!(
            classify_link(&probe_with(&tables, "7")),
            LinkStatus::Unknown
        );
    }

    #[test]
    fn a_numeric_alias_is_used_when_the_index_is_absent() {
        // Windows permits an alias made of digits. If no index has that
        // number, the alias still names a real interface.
        let tables = FakeLinkTables {
            alias: Ok(Some(TEST_LUID)),
            numeric_luid: Some(Ok(None)),
            index: Ok(Some(9)),
            addresses: Ok(vec![address_entry(9, "192.168.1.20")]),
            ..FakeLinkTables::default()
        };
        assert_eq!(classify_link(&probe_with(&tables, "7")), LinkStatus::Up);
    }

    #[test]
    fn a_numeric_index_and_alias_that_disagree_are_ambiguous() {
        // The same digit string names one index and a different alias. The
        // observer must not choose one silently.
        let tables = FakeLinkTables {
            alias: Ok(Some(TEST_LUID + 1)),
            ..FakeLinkTables::default()
        };
        assert_eq!(
            classify_link(&probe_with(&tables, "7")),
            LinkStatus::Unknown
        );
    }

    #[test]
    fn an_index_change_keeps_the_same_identity() {
        // A link change can assign a new index. The LUID and GUID still name
        // the same interface, so the observation follows it.
        let tables = FakeLinkTables {
            index: Ok(Some(9)),
            addresses: Ok(vec![address_entry(9, "192.168.1.20")]),
            ..FakeLinkTables::default()
        };
        assert_eq!(link_status(&tables), LinkStatus::Up);
    }

    #[test]
    fn addresses_are_read_only_for_the_observed_index() {
        // An address on another interface never makes this interface up.
        let tables = FakeLinkTables {
            index: Ok(Some(9)),
            addresses: Ok(vec![address_entry(TEST_INDEX, "192.168.1.20")]),
            ..FakeLinkTables::default()
        };
        assert_eq!(link_status(&tables), LinkStatus::Down);
    }

    #[test]
    fn the_classifier_rejects_a_row_with_a_foreign_identity() {
        let identity = PhysicalIdentity {
            luid: TEST_LUID,
            guid: test_guid(),
        };
        for row in [
            IdentifiedRow {
                index: TEST_INDEX,
                luid: TEST_LUID + 1,
                guid: test_guid(),
                status: up_status(),
                ipv4: vec![address_entry(TEST_INDEX, "192.168.1.20")],
            },
            IdentifiedRow {
                index: TEST_INDEX,
                luid: TEST_LUID,
                guid: other_guid(),
                status: up_status(),
                ipv4: vec![address_entry(TEST_INDEX, "192.168.1.20")],
            },
            IdentifiedRow {
                index: 0,
                luid: TEST_LUID,
                guid: test_guid(),
                status: up_status(),
                ipv4: vec![address_entry(TEST_INDEX, "192.168.1.20")],
            },
        ] {
            let probe = LinkProbe::Identified {
                identity,
                row: row.clone(),
            };
            assert_eq!(classify_link(&probe), LinkStatus::Unknown, "{row:?}");
        }
    }

    #[test]
    fn a_retained_observer_follows_the_luid_after_an_alias_rename() {
        // Bind once. A later sample does not read the alias, so a renamed
        // alias cannot look like a removed interface.
        let observer =
            RetainedPhysicalLinkObserver::bind_with(&FakeLinkTables::default(), "Ethernet")
                .unwrap();
        let renamed = FakeLinkTables {
            alias: Err(()),
            ..FakeLinkTables::default()
        };
        assert!(observer.observe_with(&renamed).unwrap());
    }

    #[test]
    fn a_retained_observer_follows_an_index_change() {
        // The LUID and GUID survive a link change that assigns a new index.
        let observer =
            RetainedPhysicalLinkObserver::bind_with(&FakeLinkTables::default(), "Ethernet")
                .unwrap();
        let tables = FakeLinkTables {
            index: Ok(Some(9)),
            addresses: Ok(vec![address_entry(9, "192.168.1.20")]),
            ..FakeLinkTables::default()
        };
        assert!(observer.observe_with(&tables).unwrap());
    }

    #[test]
    fn a_retained_sample_reports_the_live_index() {
        // The sample must carry the index that the retained LUID resolves to,
        // so a caller can detect that its start pin is stale.
        let observer =
            RetainedPhysicalLinkObserver::bind_with(&FakeLinkTables::default(), "Ethernet")
                .unwrap();
        assert_eq!(
            observer
                .observe_sample_with(&FakeLinkTables::default())
                .unwrap(),
            RetainedLinkSample {
                up: true,
                interface_index: Some(TEST_INDEX),
            }
        );
        let moved = FakeLinkTables {
            index: Ok(Some(9)),
            addresses: Ok(vec![address_entry(9, "192.168.1.20")]),
            ..FakeLinkTables::default()
        };
        assert_eq!(
            observer.observe_sample_with(&moved).unwrap(),
            RetainedLinkSample {
                up: true,
                interface_index: Some(9),
            }
        );
    }

    #[test]
    fn a_removed_retained_identity_has_no_live_index() {
        let observer =
            RetainedPhysicalLinkObserver::bind_with(&FakeLinkTables::default(), "Ethernet")
                .unwrap();
        let removed = FakeLinkTables {
            index: Ok(None),
            guid: Ok(None),
            ..FakeLinkTables::default()
        };
        assert_eq!(
            observer.observe_sample_with(&removed).unwrap(),
            RetainedLinkSample {
                up: false,
                interface_index: None,
            }
        );
        let reused = FakeLinkTables {
            guid: Ok(Some(other_guid())),
            ..FakeLinkTables::default()
        };
        assert_eq!(
            observer.observe_sample_with(&reused).unwrap(),
            RetainedLinkSample {
                up: false,
                interface_index: None,
            }
        );
    }

    #[test]
    fn a_retained_sample_api_failure_is_unknown() {
        let observer =
            RetainedPhysicalLinkObserver::bind_with(&FakeLinkTables::default(), "Ethernet")
                .unwrap();
        let failed = FakeLinkTables {
            index: Err(()),
            ..FakeLinkTables::default()
        };
        assert!(observer.observe_sample_with(&failed).is_err());
    }

    #[test]
    fn a_retained_observer_does_not_read_a_reused_alias_or_luid() {
        // The alias now names another interface. The retained observer ignores
        // the alias and sees the retained LUID with a different GUID. It
        // reports the retained interface gone instead of reading the other
        // adapter's status as up.
        let observer =
            RetainedPhysicalLinkObserver::bind_with(&FakeLinkTables::default(), "Ethernet")
                .unwrap();
        let reused = FakeLinkTables {
            alias: Ok(Some(TEST_LUID + 1)),
            index: Ok(Some(9)),
            guid: Ok(Some(other_guid())),
            addresses: Ok(vec![address_entry(9, "192.168.1.20")]),
            ..FakeLinkTables::default()
        };
        assert!(!observer.observe_with(&reused).unwrap());
    }

    #[test]
    fn a_retained_observer_api_failure_is_unknown() {
        let observer =
            RetainedPhysicalLinkObserver::bind_with(&FakeLinkTables::default(), "Ethernet")
                .unwrap();
        let failed = FakeLinkTables {
            index: Err(()),
            ..FakeLinkTables::default()
        };
        assert!(observer.observe_with(&failed).is_err());
    }

    fn retained_test_identity() -> RetainedAdapterIdentity {
        let guid = test_guid();
        RetainedAdapterIdentity::new(
            TEST_INDEX,
            TEST_LUID,
            crate::windows_route_verify::AdapterGuid::new(
                guid.data1, guid.data2, guid.data3, guid.data4,
            ),
        )
        .unwrap()
    }

    #[test]
    fn a_retained_binding_uses_the_exact_identity_without_an_alias_lookup() {
        // The alias lookup fails. The exact binding still succeeds because it
        // reads only the retained LUID, GUID, and index.
        let tables = FakeLinkTables {
            alias: Err(()),
            ..FakeLinkTables::default()
        };
        let observer =
            RetainedPhysicalLinkObserver::bind_retained_with(&tables, retained_test_identity())
                .unwrap();
        assert!(observer.observe_with(&tables).unwrap());
    }

    #[test]
    fn a_retained_binding_rejects_a_changed_index_guid_or_luid() {
        // The retained identity is one exact triple. A different live index or
        // GUID, an absent LUID, or a failed read must fail closed at bind.
        for tables in [
            FakeLinkTables {
                index: Ok(Some(TEST_INDEX + 1)),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                guid: Ok(Some(other_guid())),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                index: Ok(None),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                index: Err(()),
                ..FakeLinkTables::default()
            },
            FakeLinkTables {
                reverse_luid: Ok(Some(TEST_LUID + 1)),
                ..FakeLinkTables::default()
            },
        ] {
            assert!(RetainedPhysicalLinkObserver::bind_retained_with(
                &tables,
                retained_test_identity()
            )
            .is_err());
        }
    }

    #[test]
    fn a_retained_observer_rejects_an_absent_or_ambiguous_binding() {
        let absent = FakeLinkTables {
            alias: Ok(None),
            ..FakeLinkTables::default()
        };
        assert_eq!(
            RetainedPhysicalLinkObserver::bind_with(&absent, "Ethernet")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );

        let ambiguous = FakeLinkTables {
            alias: Ok(Some(TEST_LUID + 1)),
            ..FakeLinkTables::default()
        };
        assert!(RetainedPhysicalLinkObserver::bind_with(&ambiguous, "7").is_err());

        let failed = FakeLinkTables {
            alias: Err(()),
            ..FakeLinkTables::default()
        };
        assert!(RetainedPhysicalLinkObserver::bind_with(&failed, "Ethernet").is_err());
    }

    #[test]
    fn the_link_observer_rejects_an_invalid_target_before_a_call() {
        for target in ["", "bad\0name", "bad\nname"] {
            let error = physical_link_observation(target).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{target:?}");
        }
        let long = "a".repeat(MAX_INTERFACE_NAME_LEN + 1);
        assert_eq!(
            physical_link_observation(&long).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
