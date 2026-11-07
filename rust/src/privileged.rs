//! Private local IPC for the administrator-owned phone service.
//!
//! The GUI creates a private listener and accepts only the expected helper
//! UID. The helper verifies the listener owner and peer UID before reading a
//! request. Credentials travel only in framed messages over that connection.
//! The caller owns authorization, signal handling, and service implementation.
#![cfg(unix)]
#[cfg(any(target_os = "macos", test))]
use serde_json::json;
use serde_json::Value;
#[cfg(any(target_os = "macos", test))]
use std::fs;
#[cfg(test)]
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
#[cfg(test)]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
#[cfg(any(target_os = "macos", test))]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(test)]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
#[cfg(any(target_os = "macos", test))]
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
#[cfg(any(target_os = "macos", test))]
use std::sync::{atomic::Ordering, Arc};
#[cfg(any(target_os = "macos", test))]
use std::thread;
#[cfg(any(target_os = "macos", test))]
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

pub const MAX_MESSAGE: usize = 262_144;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Read a bounded length-prefixed JSON object. Never include input in errors.
pub fn receive(stream: &mut UnixStream) -> io::Result<Value> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err(invalid("invalid helper message length"));
    }
    let mut data = vec![0; length];
    stream.read_exact(&mut data)?;
    let object: Value =
        serde_json::from_slice(&data).map_err(|_| invalid("invalid helper message"))?;
    if !object.is_object() {
        return Err(invalid("helper message must be an object"));
    }
    Ok(object)
}

pub fn send(stream: &mut UnixStream, object: &Value) -> io::Result<()> {
    if !object.is_object() {
        return Err(invalid("helper message must be an object"));
    }
    let data = serde_json::to_vec(object).map_err(|_| invalid("invalid helper message"))?;
    if data.is_empty() || data.len() > MAX_MESSAGE {
        return Err(invalid("invalid helper message length"));
    }
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    stream.write_all(&data)
}

/// Ask the kernel for the UID of the process at the other end.
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(uid as u32)
    }
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else if len as usize != std::mem::size_of::<libc::ucred>() {
        Err(invalid("invalid peer credentials"))
    } else {
        Ok(cred.uid)
    }
}

#[cfg(target_os = "macos")]
pub use macos_helper::{
    macos_peer_identity, macos_requirement, macos_signing_flags_ok, root_helper_metadata_ok,
    verify_macos_peer, verify_macos_root_helper_install, verify_macos_static_code, MacCallerPolicy,
    MacPeerIdentity,
};

/// macOS peer identity and code signing checks for a root helper.
///
/// A Unix socket peer UID alone is not a trust boundary. Every process of the
/// same user can connect. The protected path uses the peer audit token,
/// `SecCodeCopyGuestWithAttributes`, and a Developer ID requirement. An
/// ad-hoc, user-owned, or differently signed call starts no service.
#[cfg(target_os = "macos")]
mod macos_helper {
    use super::*;
    use std::ffi::{c_char, c_int, c_void, CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;

    type CFAllocatorRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFIndex = isize;
    type CFStringRef = *const c_void;
    type CFTypeRef = *const c_void;
    type CFURLRef = *const c_void;
    type SecCodeRef = *const c_void;
    type SecRequirementRef = *const c_void;
    type SecStaticCodeRef = *const c_void;

    // The dictionary uses the standard CF callbacks. With null callbacks the
    // dictionary does not retain the audit token data, and the Security call
    // would read freed memory after this function returns.
    #[repr(C)]
    struct CFDictionaryKeyCallBacks {
        version: CFIndex,
        retain: Option<unsafe extern "C" fn(CFAllocatorRef, *const c_void) -> *const c_void>,
        release: Option<unsafe extern "C" fn(CFAllocatorRef, *const c_void)>,
        copy_description: Option<unsafe extern "C" fn(*const c_void) -> CFStringRef>,
        equal: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> u8>,
        hash: Option<unsafe extern "C" fn(*const c_void) -> usize>,
    }
    #[repr(C)]
    struct CFDictionaryValueCallBacks {
        version: CFIndex,
        retain: Option<unsafe extern "C" fn(CFAllocatorRef, *const c_void) -> *const c_void>,
        release: Option<unsafe extern "C" fn(CFAllocatorRef, *const c_void)>,
        copy_description: Option<unsafe extern "C" fn(*const c_void) -> CFStringRef>,
    }

    const LOCAL_PEERPID: c_int = 0x002;
    const LOCAL_PEERTOKEN: c_int = 0x006;
    const SOL_LOCAL: c_int = 0;
    const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
    // Static code signing flags. A Developer ID build uses the hardened
    // runtime. A development build usually lacks it and often carries
    // get-task-allow.
    const CS_ADHOC: u32 = 0x0000_0002;
    const CS_RUNTIME: u32 = 0x0001_0000;
    const DEVELOPER_ID_INTERMEDIATE: &str = "1.2.840.113635.100.6.2.6";
    const DEVELOPER_ID_APPLICATION: &str = "1.2.840.113635.100.6.1.13";

    // ACL constants from <sys/acl.h>. The Rust libc crate has no ACL
    // bindings, so declare the small surface used by the install check.
    const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    const ACL_EXTENDED_ALLOW: u32 = 1;
    const ACL_WRITE_DATA: u32 = 1 << 2;
    const ACL_DELETE: u32 = 1 << 4;
    const ACL_APPEND_DATA: u32 = 1 << 5;
    const ACL_DELETE_CHILD: u32 = 1 << 6;
    const ACL_WRITE_ATTRIBUTES: u32 = 1 << 8;
    const ACL_WRITE_EXTATTRIBUTES: u32 = 1 << 10;
    const ACL_WRITE_SECURITY: u32 = 1 << 12;
    const ACL_CHANGE_OWNER: u32 = 1 << 13;
    const K_CF_NUMBER_SINT64_TYPE: c_int = 4;

    #[link(name = "System")]
    extern "C" {
        fn acl_get_file(path: *const c_char, acl_type: u32) -> *mut c_void;
        fn acl_free(object: *mut c_void) -> c_int;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut u32) -> c_int;
        fn acl_get_permset(entry: *mut c_void, permset: *mut *mut c_void) -> c_int;
        fn acl_get_perm_np(permset: *mut c_void, perm: u32) -> c_int;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
        fn CFDictionaryCreate(
            allocator: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            num_values: CFIndex,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFDictionaryRef;
        fn CFStringCreateWithCString(
            allocator: CFAllocatorRef,
            c_str: *const c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFStringGetCString(
            string: CFStringRef,
            buffer: *mut c_char,
            buffer_size: CFIndex,
            encoding: u32,
        ) -> u8;
        fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const c_void) -> *const c_void;
        fn CFURLCreateFromFileSystemRepresentation(
            allocator: CFAllocatorRef,
            buffer: *const u8,
            buffer_length: CFIndex,
            is_directory: u8,
        ) -> CFURLRef;
        static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
        static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
        fn CFRelease(value: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributeAudit: CFStringRef;
        static kSecCodeInfoIdentifier: CFStringRef;
        static kSecCodeInfoTeamIdentifier: CFStringRef;
        static kSecCodeInfoFlags: CFStringRef;
        fn SecRequirementCreateWithString(
            text: CFStringRef,
            flags: u32,
            requirement: *mut SecRequirementRef,
        ) -> i32;
        fn SecCodeCopyGuestWithAttributes(
            host: SecCodeRef,
            attributes: CFDictionaryRef,
            flags: u32,
            guest: *mut SecCodeRef,
        ) -> i32;
        fn SecCodeCheckValidity(
            code: SecCodeRef,
            flags: u32,
            requirement: SecRequirementRef,
        ) -> i32;
        fn SecStaticCodeCreateWithPath(
            path: CFURLRef,
            flags: u32,
            code: *mut SecStaticCodeRef,
        ) -> i32;
        fn SecStaticCodeCheckValidity(
            code: SecStaticCodeRef,
            flags: u32,
            requirement: SecRequirementRef,
        ) -> i32;
        fn SecCodeCopySigningInformation(
            code: SecStaticCodeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
        fn CFNumberGetValue(number: CFTypeRef, the_type: c_int, value: *mut c_void) -> u8;
    }

    struct CfRelease(*const c_void);
    impl Drop for CfRelease {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    struct AclFree(*mut c_void);
    impl Drop for AclFree {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    acl_free(self.0);
                }
            }
        }
    }

    fn denied(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }

    fn valid_identifier(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    }

    fn valid_team(value: &str) -> bool {
        value.len() == 10 && value.bytes().all(|b| b.is_ascii_alphanumeric())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct MacPeerIdentity {
        pub uid: u32,
        pub pid: i32,
        pub audit_token: [u8; 32],
    }

    /// Read the peer UID, PID, and audit token from the kernel. The token is
    /// never read from a message or a file.
    pub fn macos_peer_identity(stream: &UnixStream) -> io::Result<MacPeerIdentity> {
        let uid = peer_uid(stream)?;
        let fd = stream.as_raw_fd();
        let mut pid: libc::pid_t = 0;
        let mut pid_len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                &mut pid as *mut _ as *mut c_void,
                &mut pid_len,
            )
        };
        if rc != 0 || pid_len as usize != std::mem::size_of::<libc::pid_t>() || pid <= 0 {
            return Err(denied("peer pid unavailable"));
        }
        let mut token = [0u8; 32];
        let mut token_len = token.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                token.as_mut_ptr() as *mut c_void,
                &mut token_len,
            )
        };
        if rc != 0 || token_len as usize != token.len() {
            return Err(denied("peer audit token unavailable"));
        }
        Ok(MacPeerIdentity {
            uid,
            pid: pid as i32,
            audit_token: token,
        })
    }

    /// The policy for one protected helper. It requires an exact caller UID
    /// and an exact Developer ID team and signing identifier. Root is a valid
    /// caller when the GUI itself runs as root. There is no UID-only fallback.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct MacCallerPolicy {
        expected_uid: u32,
        team_identifier: String,
        identifier: String,
    }

    impl MacCallerPolicy {
        pub fn new(
            expected_uid: u32,
            team_identifier: impl Into<String>,
            identifier: impl Into<String>,
        ) -> io::Result<Self> {
            let team_identifier = team_identifier.into();
            let identifier = identifier.into();
            if !valid_team(&team_identifier) || !valid_identifier(&identifier) {
                return Err(denied("invalid helper caller policy"));
            }
            Ok(Self {
                expected_uid,
                team_identifier,
                identifier,
            })
        }

        pub fn expected_uid(&self) -> u32 {
            self.expected_uid
        }

        pub fn requirement(&self) -> String {
            macos_requirement(&self.identifier, &self.team_identifier)
                .unwrap_or_else(|_| String::new())
        }
    }

    /// Build one exact requirement. The caller values are allowlisted so a
    /// quote or a requirement operator cannot be injected. `anchor apple
    /// generic` alone also accepts an Apple Development or Apple Distribution
    /// certificate, so the requirement names both Developer ID markers and
    /// rejects the debugger entitlement.
    pub fn macos_requirement(identifier: &str, team_identifier: &str) -> io::Result<String> {
        if !valid_identifier(identifier) || !valid_team(team_identifier) {
            return Err(denied("invalid signing requirement"));
        }
        Ok(format!(
            "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team_identifier}\" and certificate 1[field.{DEVELOPER_ID_INTERMEDIATE}] exists and certificate leaf[field.{DEVELOPER_ID_APPLICATION}] exists and !entitlement[\"com.apple.security.get-task-allow\"]"
        ))
    }

    /// A Developer ID build carries the hardened runtime flag and is not
    /// ad-hoc. A development build usually lacks one or both.
    pub fn macos_signing_flags_ok(flags: u32) -> bool {
        flags & CS_ADHOC == 0 && flags & CS_RUNTIME != 0
    }

    fn cfstring(value: &str) -> io::Result<CfRelease> {
        let value = CString::new(value).map_err(|_| denied("invalid signing requirement"))?;
        let string = unsafe {
            CFStringCreateWithCString(ptr::null(), value.as_ptr(), CF_STRING_ENCODING_UTF8)
        };
        if string.is_null() {
            Err(denied("signing requirement unavailable"))
        } else {
            Ok(CfRelease(string))
        }
    }

    fn requirement(value: &str) -> io::Result<CfRelease> {
        let text = cfstring(value)?;
        let mut created: SecRequirementRef = ptr::null();
        let status = unsafe { SecRequirementCreateWithString(text.0, 0, &mut created) };
        if status != 0 || created.is_null() {
            Err(denied("signing requirement rejected"))
        } else {
            Ok(CfRelease(created))
        }
    }

    fn audit_dictionary(token: &[u8; 32]) -> io::Result<CfRelease> {
        let data = unsafe { CFDataCreate(ptr::null(), token.as_ptr(), token.len() as CFIndex) };
        if data.is_null() {
            return Err(denied("peer audit token rejected"));
        }
        let data = CfRelease(data);
        let keys = [unsafe { kSecGuestAttributeAudit }];
        let values = [data.0];
        let key_callbacks = ptr::addr_of!(kCFTypeDictionaryKeyCallBacks);
        let value_callbacks = ptr::addr_of!(kCFTypeDictionaryValueCallBacks);
        let dict = unsafe {
            CFDictionaryCreate(
                ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                key_callbacks.cast(),
                value_callbacks.cast(),
            )
        };
        if dict.is_null() {
            Err(denied("peer attributes rejected"))
        } else {
            Ok(CfRelease(dict))
        }
    }

    fn string_from_dictionary(dict: CFDictionaryRef, key: CFStringRef) -> Option<String> {
        let value = unsafe { CFDictionaryGetValue(dict, key) };
        if value.is_null() {
            return None;
        }
        let mut buffer = [0 as c_char; 256];
        let ok = unsafe {
            CFStringGetCString(
                value,
                buffer.as_mut_ptr(),
                buffer.len() as CFIndex,
                CF_STRING_ENCODING_UTF8,
            )
        };
        if ok == 0 {
            return None;
        }
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_str()
            .ok()
            .map(str::to_owned)
    }

    fn signing_identity(code: SecStaticCodeRef) -> io::Result<(String, String, u32)> {
        let mut information: CFDictionaryRef = ptr::null();
        let status = unsafe {
            SecCodeCopySigningInformation(code, SEC_CS_SIGNING_INFORMATION, &mut information)
        };
        if status != 0 || information.is_null() {
            return Err(denied("signing information unavailable"));
        }
        let information = CfRelease(information);
        let identifier = string_from_dictionary(information.0, unsafe { kSecCodeInfoIdentifier })
            .ok_or_else(|| denied("signing identifier unavailable"))?;
        let team = string_from_dictionary(information.0, unsafe { kSecCodeInfoTeamIdentifier })
            .ok_or_else(|| denied("signing team unavailable"))?;
        if identifier.is_empty() || team.is_empty() {
            return Err(denied("signing identity incomplete"));
        }
        let flags_value = unsafe { CFDictionaryGetValue(information.0, kSecCodeInfoFlags) };
        let mut flags: i64 = 0;
        if flags_value.is_null()
            || unsafe {
                CFNumberGetValue(
                    flags_value,
                    K_CF_NUMBER_SINT64_TYPE,
                    (&mut flags as *mut i64).cast(),
                )
            } == 0
        {
            return Err(denied("signing flags unavailable"));
        }
        Ok((identifier, team, flags as u32))
    }

    fn verify_static_code(
        path: &Path,
        requirement_text: &str,
    ) -> io::Result<(String, String, u32)> {
        let path_bytes = path.as_os_str().as_bytes();
        let url = unsafe {
            CFURLCreateFromFileSystemRepresentation(
                ptr::null(),
                path_bytes.as_ptr(),
                path_bytes.len() as CFIndex,
                0,
            )
        };
        if url.is_null() {
            return Err(denied("helper path rejected"));
        }
        let url = CfRelease(url);
        let mut code: SecStaticCodeRef = ptr::null();
        let status = unsafe { SecStaticCodeCreateWithPath(url.0, 0, &mut code) };
        if status != 0 || code.is_null() {
            return Err(denied("helper code unavailable"));
        }
        let code = CfRelease(code);
        let requirement = requirement(requirement_text)?;
        let status = unsafe { SecStaticCodeCheckValidity(code.0, 0, requirement.0) };
        if status != 0 {
            return Err(denied("helper signature rejected"));
        }
        signing_identity(code.0)
    }

    /// Verify a root helper with the peer audit token and an exact Developer ID
    /// requirement. A failed lookup, an ad-hoc signature, another team, or
    /// another identifier is a permission error.
    pub fn verify_macos_peer(
        stream: &UnixStream,
        policy: &MacCallerPolicy,
    ) -> io::Result<MacPeerIdentity> {
        let peer = macos_peer_identity(stream)?;
        if peer.uid != policy.expected_uid {
            return Err(denied("unexpected helper peer"));
        }
        let requirement_text = policy.requirement();
        if requirement_text.is_empty() {
            return Err(denied("invalid helper caller policy"));
        }
        let requirement = requirement(&requirement_text)?;
        let attributes = audit_dictionary(&peer.audit_token)?;
        let mut code: SecCodeRef = ptr::null();
        let status =
            unsafe { SecCodeCopyGuestWithAttributes(ptr::null(), attributes.0, 0, &mut code) };
        if status != 0 || code.is_null() {
            return Err(denied("peer code unavailable"));
        }
        let code = CfRelease(code);
        let status = unsafe { SecCodeCheckValidity(code.0, 0, requirement.0) };
        if status != 0 {
            return Err(denied("peer signature rejected"));
        }
        let (identifier, team, flags) = signing_identity(code.0)?;
        if identifier != policy.identifier
            || team != policy.team_identifier
            || !macos_signing_flags_ok(flags)
        {
            return Err(denied("peer identity mismatch"));
        }
        Ok(peer)
    }

    /// Verify one static code object against the exact Developer ID. The path
    /// is not checked here; the caller must use a protected install path.
    pub fn verify_macos_static_code(
        path: &Path,
        team_identifier: &str,
        identifier: &str,
    ) -> io::Result<()> {
        let requirement = macos_requirement(identifier, team_identifier)?;
        let (actual_identifier, actual_team, flags) = verify_static_code(path, &requirement)?;
        if actual_identifier != identifier
            || actual_team != team_identifier
            || !macos_signing_flags_ok(flags)
        {
            return Err(denied("signature identity mismatch"));
        }
        Ok(())
    }

    /// The helper checks its own install path before it opens a listener.
    /// Root ownership, root group, the exact protected root, no group or other
    /// write bit, and the same Developer ID are all required.
    pub fn verify_macos_root_helper_install(
        path: &Path,
        team_identifier: &str,
        identifier: &str,
    ) -> io::Result<()> {
        if !valid_team(team_identifier) || !valid_identifier(identifier) {
            return Err(denied("invalid helper install policy"));
        }
        let canonical = fs::canonicalize(path)?;
        if canonical != path
            || canonical.parent() != Some(Path::new("/Library/PrivilegedHelperTools"))
        {
            return Err(denied("helper is not in the protected install root"));
        }
        let metadata = fs::symlink_metadata(&canonical)?;
        if !root_helper_metadata_allowed(
            metadata.uid(),
            metadata.gid(),
            metadata.permissions().mode(),
            metadata.file_type().is_file(),
            metadata.file_type().is_symlink(),
        ) {
            return Err(denied("helper install metadata is not protected"));
        }
        for directory in ["/Library/PrivilegedHelperTools", "/Library", "/"] {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(denied("helper parent is not protected"));
            }
            if has_write_acl(Path::new(directory))? {
                return Err(denied("helper parent has a write ACL"));
            }
        }
        if has_write_acl(&canonical)? {
            return Err(denied("helper has a write ACL"));
        }
        let requirement = macos_requirement(identifier, team_identifier)?;
        let (actual_identifier, actual_team, flags) = verify_static_code(&canonical, &requirement)?;
        if actual_identifier != identifier
            || actual_team != team_identifier
            || !macos_signing_flags_ok(flags)
        {
            return Err(denied("helper signature identity mismatch"));
        }
        Ok(())
    }

    // Reject any allow ACL that can write. The qualifier is not resolved to a
    // user here; an installed helper has no extended ACL in the normal package.
    fn has_write_acl(path: &Path) -> io::Result<bool> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| denied("helper ACL path rejected"))?;
        let acl = unsafe { acl_get_file(path.as_ptr(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(denied("helper ACL unavailable"));
        }
        let acl = AclFree(acl);
        let mut entry: *mut c_void = ptr::null_mut();
        let mut entry_id = ACL_FIRST_ENTRY;
        while unsafe { acl_get_entry(acl.0, entry_id, &mut entry) } == 0 {
            entry_id = ACL_NEXT_ENTRY;
            let mut tag = 0u32;
            if unsafe { acl_get_tag_type(entry, &mut tag) } == 0 && tag == ACL_EXTENDED_ALLOW {
                let mut permissions: *mut c_void = ptr::null_mut();
                if unsafe { acl_get_permset(entry, &mut permissions) } == 0 {
                    for permission in [
                        ACL_WRITE_DATA,
                        ACL_DELETE,
                        ACL_APPEND_DATA,
                        ACL_DELETE_CHILD,
                        ACL_WRITE_ATTRIBUTES,
                        ACL_WRITE_EXTATTRIBUTES,
                        ACL_WRITE_SECURITY,
                        ACL_CHANGE_OWNER,
                    ] {
                        if unsafe { acl_get_perm_np(permissions, permission) } == 1 {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Pure metadata rule. It is public so a test can exercise every rejected
    /// combination without root and without changing a real helper.
    pub fn root_helper_metadata_ok(
        uid: u32,
        gid: u32,
        mode: u32,
        is_file: bool,
        is_symlink: bool,
    ) -> bool {
        uid == 0 && gid == 0 && is_file && !is_symlink && mode & 0o100 != 0 && mode & 0o022 == 0
    }

    fn root_helper_metadata_allowed(
        uid: u32,
        gid: u32,
        mode: u32,
        is_file: bool,
        is_symlink: bool,
    ) -> bool {
        root_helper_metadata_ok(uid, gid, mode, is_file, is_symlink)
    }
}

/// A private listener owned by the unprivileged GUI process.
///
/// The production macOS app uses the XPC helper instead. This type stays for
/// the hermetic Unix helper tests only, so the UID-only socket cannot become a
/// production boundary again by accident.
#[cfg(test)]
pub struct PrivateListener {
    listener: UnixListener,
    directory: PathBuf,
    path: PathBuf,
}
#[cfg(test)]
impl PrivateListener {
    /// Create a 0700 directory under /tmp. Failure never removes an existing path.
    pub fn create() -> io::Result<Self> {
        let uid = unsafe { libc::geteuid() } as u32;
        let mut random = File::open("/dev/urandom")?;
        for _ in 0..16 {
            let mut bytes = [0u8; 12];
            random.read_exact(&mut bytes)?;
            let suffix: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let directory = PathBuf::from("/tmp").join(format!("hs-{}", suffix));
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => {
                    let path = directory.join("control");
                    match UnixListener::bind(&path) {
                        Ok(listener) => {
                            if let Err(e) = listener.set_nonblocking(true) {
                                let _ = fs::remove_file(&path);
                                let _ = fs::remove_dir(&directory);
                                return Err(e);
                            }
                            if let Err(e) = verify_path(&path, uid) {
                                let _ = fs::remove_file(&path);
                                let _ = fs::remove_dir(&directory);
                                return Err(e);
                            }
                            return Ok(Self {
                                listener,
                                directory,
                                path,
                            });
                        }
                        Err(e) => {
                            let _ = fs::remove_dir(&directory);
                            return Err(e);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot create a private helper directory",
        ))
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Accept only a peer with `expected_uid`. Call before sending any secret.
    pub fn accept(&self, expected_uid: u32, timeout: Duration) -> io::Result<UnixStream> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper connection timed out",
                ));
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if peer_uid(&stream)? == expected_uid {
                        // macOS inherits the listener's O_NONBLOCK on accept.
                        // Framed reads need blocking I/O and an explicit timeout.
                        stream.set_nonblocking(false)?;
                        return Ok(stream);
                    }
                    // An untrusted local process must not receive a request.
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "helper connection timed out",
                        ));
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}
#[cfg(test)]
impl Drop for PrivateListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(all(test, target_os = "macos"))]
impl PrivateListener {
    /// Accept only a peer that satisfies the code signing policy. A wrong UID
    /// or a failed signature is dropped without a reply, and the listener
    /// keeps waiting until the timeout. This is the protected macOS path; the
    /// older `accept` checks the UID only.
    pub fn accept_verified(
        &self,
        policy: &MacCallerPolicy,
        timeout: Duration,
    ) -> io::Result<UnixStream> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper connection timed out",
                ));
            }
            match self.listener.accept() {
                Ok((stream, _)) => match macos_helper::verify_macos_peer(&stream, policy) {
                    Ok(_) => {
                        stream.set_nonblocking(false)?;
                        return Ok(stream);
                    }
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        // An untrusted local process receives no request and no
                        // error detail. Close it and wait for the real caller.
                    }
                    Err(error) => return Err(error),
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "helper connection timed out",
                        ));
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Validate the socket and its 0700 parent without following their final links.
#[cfg(test)]
pub fn verify_path(path: &Path, owner: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("invalid helper socket path"))?;
    let dir = fs::symlink_metadata(parent)?;
    let socket = fs::symlink_metadata(path)?;
    if !dir.file_type().is_dir()
        || dir.uid() != owner
        || dir.permissions().mode() & 0o7777 != 0o700
        || !socket.file_type().is_socket()
        || socket.uid() != owner
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper socket is not private",
        ));
    }
    Ok(())
}

/// Connect as root only after checking the private path and expected peer.
#[cfg(test)]
pub fn connect_as_root(path: &Path, owner: u32) -> io::Result<UnixStream> {
    if unsafe { libc::geteuid() } != 0 || owner == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper requires administrator privileges",
        ));
    }
    verify_path(path, owner)?;
    let stream = UnixStream::connect(path)?;
    if peer_uid(&stream)? != owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected helper peer",
        ));
    }
    Ok(stream)
}

/// Service methods must not return credentials in their result or status.
pub trait PrivilegedService {
    fn start(
        &mut self,
        phone: &Value,
        experimental_icmp: bool,
        experimental_icmp_persistent: bool,
        cancel: &AtomicBool,
    ) -> Result<Value, String>;
    fn status(&mut self) -> Result<Value, String>;
    /// Failed source device setups for the current tunnel. It holds no token.
    fn failures(&mut self) -> Result<Value, String> {
        Ok(crate::failures::empty_snapshot())
    }
    /// The bounded relay counters and timing reservoirs. It holds no address.
    fn diagnostics(&mut self) -> Result<Value, String> {
        Ok(crate::diagnostics::empty())
    }
    fn stop(&mut self) -> Result<Value, String>;
}
#[cfg(any(target_os = "macos", test))]
struct StopOnDrop<'a, T: PrivilegedService>(&'a mut T);
#[cfg(any(target_os = "macos", test))]
impl<T: PrivilegedService> Drop for StopOnDrop<'_, T> {
    fn drop(&mut self) {
        let _ = self.0.stop();
    }
}

// Do not consume the next IPC message. Detect a closed peer while start is
// running so authentication can be cancelled before route setup.
#[cfg(any(target_os = "macos", test))]
fn watch_disconnect(stream: UnixStream, cancel: Arc<AtomicBool>, finished: Arc<AtomicBool>) {
    let mut p = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    while !finished.load(Ordering::Acquire) {
        p.revents = 0;
        let rc = unsafe { libc::poll(&mut p, 1, 100) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            cancel.store(true, Ordering::Release);
            break;
        }
        if p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            cancel.store(true, Ordering::Release);
            break;
        }
        if p.revents & libc::POLLIN != 0 {
            let mut byte = 0u8;
            let n = unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            if n == 0 {
                cancel.store(true, Ordering::Release);
                break;
            }
            if n < 0 {
                let e = io::Error::last_os_error();
                if !matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    cancel.store(true, Ordering::Release);
                    break;
                }
            } else {
                // A pipelined request stays queued for the serving thread.
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
struct DisconnectWatch {
    finished: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
#[cfg(any(target_os = "macos", test))]
impl Drop for DisconnectWatch {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Serve one verified client. Stop the service on stop, EOF, error, or unwind.
/// The caller must call `shutdown` on a cloned stream when SIGINT or SIGTERM
/// arrives. This unblocks receive and runs the cleanup guard.
#[cfg(any(target_os = "macos", test))]
fn serve_connection<T: PrivilegedService>(
    mut stream: UnixStream,
    expected_uid: u32,
    service: &mut T,
) -> io::Result<()> {
    if peer_uid(&stream)? != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected helper peer",
        ));
    }
    let service = StopOnDrop(service);
    loop {
        let request = match receive(&mut stream) {
            Ok(v) => v,
            Err(e)
                if e.kind() == io::ErrorKind::UnexpectedEof
                    || e.kind() == io::ErrorKind::ConnectionReset =>
            {
                return Ok(())
            }
            Err(e) => return Err(e),
        };
        match request.get("action").and_then(Value::as_str) {
            Some("start") => {
                let phone = request
                    .get("phone")
                    .filter(|p| p.is_array() && p.as_array().map(|v| v.len()) == Some(4));
                let experimental_icmp = match request.get("experimental_icmp") {
                    None => Some(false),
                    Some(Value::Bool(value)) => Some(*value),
                    _ => None,
                };
                let persistent = match request.get("experimental_icmp_persistent") {
                    None => Some(false),
                    Some(Value::Bool(value)) => Some(*value),
                    _ => None,
                };
                let result = match (phone, experimental_icmp, persistent) {
                    (Some(p), Some(enabled), Some(persistent)) if !persistent || enabled => {
                        let watched = stream.try_clone()?;
                        let cancel = Arc::new(AtomicBool::new(false));
                        let finished = Arc::new(AtomicBool::new(false));
                        let (watch_cancel, watch_finished) = (cancel.clone(), finished.clone());
                        let watcher = thread::Builder::new()
                            .name("helper-start-watch".into())
                            .spawn(move || {
                                watch_disconnect(watched, watch_cancel, watch_finished)
                            })?;
                        let guard = DisconnectWatch {
                            finished,
                            worker: Some(watcher),
                        };
                        let result = service.0.start(p, enabled, persistent, &cancel);
                        drop(guard);
                        result
                    }
                    _ => Err("invalid source device settings".into()),
                };
                let response = match result {
                    Ok(result) => match service.0.status() {
                        Ok(status) => json!({"ok":true,"result":result,"status":status}),
                        Err(_) => json!({"ok":false,"error":"The service status is unavailable."}),
                    },
                    Err(code) => {
                        let safe_code = match code.as_str() {
                            "phone_auth" => "phone_auth",
                            "route_setup" => "route_setup",
                            "tunnel_setup" => "tunnel_setup",
                            _ => "service_start",
                        };
                        json!({"ok":false,"error_code":safe_code,"error":"The tunnel could not start."})
                    }
                };
                send(&mut stream, &response)?;
            }
            Some("status") => {
                let response = match service.0.status() {
                    Ok(status) => json!({"ok":true,"status":status}),
                    Err(_) => json!({"ok":false,"error":"The service status is unavailable."}),
                };
                send(&mut stream, &response)?;
            }
            Some("failures") => {
                let response = match service.0.failures() {
                    Ok(value) => json!({"ok":true,"failures":value}),
                    Err(_) => json!({"ok":false,"error":"The failure record is unavailable."}),
                };
                send(&mut stream, &response)?;
            }
            Some("diagnostics") => {
                let response = match service.0.diagnostics() {
                    Ok(value) => json!({"ok":true,"diagnostics":value}),
                    Err(_) => json!({"ok":false,"error":"The diagnostics are unavailable."}),
                };
                send(&mut stream, &response)?;
            }
            Some("stop") => {
                let response = match service.0.stop() {
                    Ok(result) => match service.0.status() {
                        Ok(status) => json!({"ok":true,"result":result,"status":status}),
                        Err(_) => json!({"ok":false,"error":"The service status is unavailable."}),
                    },
                    Err(_) => json!({"ok":false,"error":"The service could not stop."}),
                };
                send(&mut stream, &response)?;
                return Ok(());
            }
            _ => return Err(invalid("unknown helper action")),
        }
    }
}

/// Serve one macOS client only after the audit token and Developer ID check.
/// Stop the service on stop, EOF, error, or unwind. The caller must close a
/// cloned stream on SIGINT or SIGTERM, exactly as with `serve_connection`.
#[cfg(target_os = "macos")]
pub fn serve_connection_verified<T: PrivilegedService>(
    stream: UnixStream,
    policy: &MacCallerPolicy,
    service: &mut T,
) -> io::Result<()> {
    macos_helper::verify_macos_peer(&stream, policy)?;
    serve_connection(stream, policy.expected_uid(), service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Fake(Arc<AtomicUsize>);
    impl PrivilegedService for Fake {
        fn start(&mut self, _: &Value, _: bool, _: bool, _: &AtomicBool) -> Result<Value, String> {
            Ok(json!({"started":true}))
        }
        fn status(&mut self) -> Result<Value, String> {
            Ok(json!({"running":true}))
        }
        fn stop(&mut self) -> Result<Value, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"stopped":true}))
        }
    }
    #[test]
    fn framed_messages_enforce_limits_and_objects() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        send(&mut a, &json!({"action":"status"})).unwrap();
        assert_eq!(receive(&mut b).unwrap()["action"], "status");
        a.write_all(&((MAX_MESSAGE + 1) as u32).to_be_bytes())
            .unwrap();
        assert_eq!(
            receive(&mut b).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(send(&mut a, &json!([1, 2])).is_err());
    }
    #[test]
    fn disconnect_stops_service() {
        let (mut a, b) = UnixStream::pair().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = Arc::clone(&n);
        let uid = unsafe { libc::geteuid() } as u32;
        let t = thread::spawn(move || serve_connection(b, uid, &mut Fake(n2)).unwrap());
        send(
            &mut a,
            &json!({"action":"start","phone":["127.0.0.1",1080,"user","private"]}),
        )
        .unwrap();
        assert_eq!(receive(&mut a).unwrap()["ok"], true);
        drop(a);
        t.join().unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn failures_action_returns_an_empty_record() {
        let (mut a, b) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::geteuid() } as u32;
        let worker = thread::spawn(move || {
            serve_connection(b, uid, &mut Fake(Arc::new(AtomicUsize::new(0)))).unwrap()
        });
        send(&mut a, &json!({"action":"failures"})).unwrap();
        let response = receive(&mut a).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["failures"]["ok"], true);
        assert_eq!(response["failures"]["total"], 0);
        drop(a);
        worker.join().unwrap();
    }
    #[test]
    fn diagnostics_action_returns_the_empty_shape() {
        let (mut a, b) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::geteuid() } as u32;
        let worker = thread::spawn(move || {
            serve_connection(b, uid, &mut Fake(Arc::new(AtomicUsize::new(0)))).unwrap()
        });
        send(&mut a, &json!({"action":"diagnostics"})).unwrap();
        let response = receive(&mut a).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["diagnostics"], crate::diagnostics::empty());
        drop(a);
        worker.join().unwrap();
    }
    #[test]
    fn experimental_icmp_requires_explicit_boolean_over_ipc() {
        use std::sync::Mutex;
        struct Capture(Arc<Mutex<Vec<(bool, bool)>>>);
        impl PrivilegedService for Capture {
            fn start(
                &mut self,
                _: &Value,
                enabled: bool,
                persistent: bool,
                _: &AtomicBool,
            ) -> Result<Value, String> {
                self.0.lock().unwrap().push((enabled, persistent));
                Ok(json!({}))
            }
            fn status(&mut self) -> Result<Value, String> {
                Ok(json!({"running":false}))
            }
            fn stop(&mut self) -> Result<Value, String> {
                Ok(json!({}))
            }
        }
        let (mut client, server) = UnixStream::pair().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let copy = Arc::clone(&seen);
        let uid = unsafe { libc::geteuid() } as u32;
        let worker =
            thread::spawn(move || serve_connection(server, uid, &mut Capture(copy)).unwrap());
        for request in [
            json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"]}),
            json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"],"experimental_icmp":true}),
            json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"],"experimental_icmp":"true"}),
            json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"],"experimental_icmp":true,"experimental_icmp_persistent":true}),
            json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"],"experimental_icmp_persistent":true}),
            json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"],"experimental_icmp":true,"experimental_icmp_persistent":"true"}),
        ] {
            send(&mut client, &request).unwrap();
            let response = receive(&mut client).unwrap();
            if request["experimental_icmp"].is_string()
                || request["experimental_icmp_persistent"].is_string()
                || (request["experimental_icmp_persistent"] == true
                    && request["experimental_icmp"] != true)
            {
                assert_eq!(response["ok"], false);
            } else {
                assert_eq!(response["ok"], true);
            }
        }
        drop(client);
        worker.join().unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(false, false), (true, false), (true, true)]
        );
    }
    #[test]
    fn disconnect_cancels_start_before_service_commits() {
        use std::sync::mpsc;
        struct Starting {
            entered: mpsc::Sender<()>,
            cancelled: Arc<AtomicBool>,
            stops: Arc<AtomicUsize>,
        }
        impl PrivilegedService for Starting {
            fn start(
                &mut self,
                _: &Value,
                _: bool,
                _: bool,
                cancel: &AtomicBool,
            ) -> Result<Value, String> {
                self.entered.send(()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                while !cancel.load(Ordering::Acquire) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(5));
                }
                if cancel.load(Ordering::Acquire) {
                    self.cancelled.store(true, Ordering::Release);
                    Err("cancelled".into())
                } else {
                    Err("cancellation timed out".into())
                }
            }
            fn status(&mut self) -> Result<Value, String> {
                Ok(json!({"running":false}))
            }
            fn stop(&mut self) -> Result<Value, String> {
                self.stops.fetch_add(1, Ordering::AcqRel);
                Ok(json!({}))
            }
        }
        let (mut client, server) = UnixStream::pair().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let stops = Arc::new(AtomicUsize::new(0));
        let (c, s) = (cancelled.clone(), stops.clone());
        let uid = unsafe { libc::geteuid() } as u32;
        let worker = thread::spawn(move || {
            let _ = serve_connection(
                server,
                uid,
                &mut Starting {
                    entered: entered_tx,
                    cancelled: c,
                    stops: s,
                },
            );
            done_tx.send(()).unwrap();
        });
        send(
            &mut client,
            &json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"]}),
        )
        .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(client);
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(stops.load(Ordering::Acquire), 1);
    }
    #[test]
    fn disconnect_interrupts_stalled_phone_auth_before_route_stage() {
        use crate::{normalization::Audit, phone::PhoneProxy};
        use std::net::TcpListener;
        use std::sync::mpsc;
        struct AuthStart {
            phone: PhoneProxy,
            route_stage: Arc<AtomicBool>,
        }
        impl PrivilegedService for AuthStart {
            fn start(
                &mut self,
                _: &Value,
                _: bool,
                _: bool,
                cancel: &AtomicBool,
            ) -> Result<Value, String> {
                self.phone
                    .check_cancellable(&Audit::default(), cancel)
                    .map_err(|_| "cancelled".to_string())?;
                self.route_stage.store(true, Ordering::Release);
                Ok(json!({}))
            }
            fn status(&mut self) -> Result<Value, String> {
                Ok(json!({"running":false}))
            }
            fn stop(&mut self) -> Result<Value, String> {
                Ok(json!({}))
            }
        }
        let phone_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = phone_listener.local_addr().unwrap();
        let (hello_tx, hello_rx) = mpsc::channel();
        let phone = thread::spawn(move || {
            let (mut stream, _) = phone_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0u8; 3];
            stream.read_exact(&mut hello).unwrap();
            hello_tx.send(()).unwrap();
            let mut byte = [0u8; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });
        let (mut client, server) = UnixStream::pair().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let route_stage = Arc::new(AtomicBool::new(false));
        let stage = route_stage.clone();
        let uid = unsafe { libc::geteuid() } as u32;
        let helper = thread::spawn(move || {
            let phone = PhoneProxy {
                address,
                username: "hotspotshade".into(),
                token: "test".into(),
                iface: None,
                timeout: Duration::from_secs(10),
            };
            let _ = serve_connection(
                server,
                uid,
                &mut AuthStart {
                    phone,
                    route_stage: stage,
                },
            );
            done_tx.send(()).unwrap();
        });
        send(
            &mut client,
            &json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"]}),
        )
        .unwrap();
        hello_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(client);
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        helper.join().unwrap();
        phone.join().unwrap();
        assert!(!route_stage.load(Ordering::Acquire));
    }
    #[test]
    fn untrusted_peer_is_rejected_before_service_starts() {
        let (a, b) = UnixStream::pair().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let uid = unsafe { libc::geteuid() } as u32;
        assert!(serve_connection(b, uid.wrapping_add(1), &mut Fake(Arc::clone(&n))).is_err());
        drop(a);
        assert_eq!(n.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn listener_path_is_private_and_removed() {
        let path;
        let directory;
        {
            let listener = PrivateListener::create().unwrap();
            path = listener.path().to_owned();
            directory = path.parent().unwrap().to_owned();
            let uid = unsafe { libc::geteuid() } as u32;
            verify_path(&path, uid).unwrap();
            assert!(verify_path(&path, uid.wrapping_add(1)).is_err());
        }
        assert!(!path.exists());
        assert!(!directory.exists());
    }
    #[test]
    fn accepted_peer_is_blocking_and_waits_for_a_delayed_reply() {
        let listener = PrivateListener::create().unwrap();
        let path = listener.path().to_owned();
        let t = thread::spawn(move || {
            let mut peer = UnixStream::connect(path).unwrap();
            thread::sleep(Duration::from_millis(100));
            send(&mut peer, &json!({"ok":true})).unwrap();
        });
        let uid = unsafe { libc::geteuid() } as u32;
        let mut stream = listener.accept(uid, Duration::from_secs(2)).unwrap();
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_NONBLOCK, 0);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(receive(&mut stream).unwrap()["ok"], true);
        t.join().unwrap();
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_signing_requirement_rejects_injected_values() {
        assert_eq!(
            macos_requirement("dev.hotspotshade.mac", "ABCDEFGHIJ").unwrap(),
            "anchor apple generic and identifier \"dev.hotspotshade.mac\" and certificate leaf[subject.OU] = \"ABCDEFGHIJ\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and !entitlement[\"com.apple.security.get-task-allow\"]"
        );
        assert!(macos_requirement("dev.hotspotshade.mac\" or true", "ABCDEFGHIJ").is_err());
        assert!(macos_requirement("dev.hotspotshade.mac", "ABCDEFGHI\"").is_err());
        assert!(macos_requirement("", "ABCDEFGHIJ").is_err());
        assert!(MacCallerPolicy::new(501, "SHORT", "dev.hotspotshade.mac").is_err());
        // A root GUI is a valid caller. The old policy refused it even though
        // the GUI accepts root with a per-launch token.
        assert!(MacCallerPolicy::new(0, "ABCDEFGHIJ", "dev.hotspotshade.mac").is_ok());
        assert!(MacCallerPolicy::new(501, "ABCDEFGHIJ", "dev.hotspotshade.mac").is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_signing_flags_require_developer_id_and_hardened_runtime() {
        // Hardened runtime, not ad-hoc.
        assert!(macos_signing_flags_ok(0x0001_0000));
        // A development or distribution signature without the runtime.
        assert!(!macos_signing_flags_ok(0));
        // An ad-hoc signature with the runtime bit.
        assert!(!macos_signing_flags_ok(0x0001_0002));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_peer_identity_comes_from_the_kernel() {
        let (a, b) = UnixStream::pair().unwrap();
        let peer = macos_peer_identity(&b).unwrap();
        assert_eq!(peer.pid, std::process::id() as i32);
        assert_eq!(peer.uid, unsafe { libc::geteuid() } as u32);
        assert_ne!(peer.audit_token, [0u8; 32]);
        drop(a);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_ad_hoc_caller_is_rejected() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (a, b) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::geteuid() } as u32;
        let policy = MacCallerPolicy::new(uid, "AAAAAAAAAA", "dev.hotspotshade.mac").unwrap();
        // The cargo test binary is ad-hoc or unsigned. A team requirement must
        // fail before the helper reads a request.
        assert!(verify_macos_peer(&b, &policy).is_err());
        drop(a);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_verified_connection_rejects_before_the_service_starts() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (a, b) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::geteuid() } as u32;
        let policy = MacCallerPolicy::new(uid, "AAAAAAAAAA", "dev.hotspotshade.mac").unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let result = serve_connection_verified(b, &policy, &mut Fake(Arc::clone(&n)));
        drop(a);
        assert!(result.is_err());
        assert_eq!(n.load(Ordering::SeqCst), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_static_ad_hoc_code_is_rejected() {
        let executable = std::env::current_exe().unwrap();
        assert!(
            verify_macos_static_code(&executable, "AAAAAAAAAA", "dev.hotspotshade.mac").is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_root_helper_metadata_rule() {
        assert!(root_helper_metadata_ok(0, 0, 0o755, true, false));
        assert!(root_helper_metadata_ok(0, 0, 0o555, true, false));
        assert!(!root_helper_metadata_ok(501, 0, 0o755, true, false));
        assert!(!root_helper_metadata_ok(0, 20, 0o755, true, false));
        assert!(!root_helper_metadata_ok(0, 0, 0o775, true, false));
        assert!(!root_helper_metadata_ok(0, 0, 0o757, true, false));
        assert!(!root_helper_metadata_ok(0, 0, 0o755, false, false));
        assert!(!root_helper_metadata_ok(0, 0, 0o755, true, true));
        assert!(!root_helper_metadata_ok(0, 0, 0o644, true, false));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_root_helper_install_rejects_a_user_path() {
        let path = std::env::temp_dir().join(format!(
            "hs-helper-install-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, b"not a helper").unwrap();
        let result =
            verify_macos_root_helper_install(&path, "AAAAAAAAAA", "dev.hotspotshade.mac.helper");
        let _ = fs::remove_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn only_allowlisted_start_codes_cross_the_ipc_boundary() {
        struct Failing(&'static str);
        impl PrivilegedService for Failing {
            fn start(
                &mut self,
                _: &Value,
                _: bool,
                _: bool,
                _: &AtomicBool,
            ) -> Result<Value, String> {
                Err(self.0.into())
            }
            fn status(&mut self) -> Result<Value, String> {
                Ok(json!({}))
            }
            fn stop(&mut self) -> Result<Value, String> {
                Ok(json!({}))
            }
        }
        for (code, expected) in [
            ("phone_auth", "phone_auth"),
            ("secret-token-in-error", "service_start"),
        ] {
            let (mut a, b) = UnixStream::pair().unwrap();
            let uid = unsafe { libc::geteuid() } as u32;
            let t = thread::spawn(move || serve_connection(b, uid, &mut Failing(code)).unwrap());
            send(
                &mut a,
                &json!({"action":"start","phone":["172.20.10.1",1080,"hotspotshade","test"]}),
            )
            .unwrap();
            let response = receive(&mut a).unwrap();
            assert_eq!(response["error_code"], expected);
            assert!(!response.to_string().contains("secret-token-in-error"));
            drop(a);
            t.join().unwrap();
        }
    }
}
