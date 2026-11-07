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
//! the family, prefix, source, TOS, table, protocol, type, scope, output
//! interface, metric, preferred source, flow, and route shape match. It deletes
//! a rule only when the family, prefix lengths, destination, source, TOS, table,
//! priority, action, flags, input and output interface names, goto target,
//! protocol, mark, mask, flow, tunnel id, suppress values, l3mdev, uid range,
//! IP protocol, port ranges, port masks, DSCP, DSCP mask, and flow label match.
//! The encoded delete request carries fewer selectors than that full record. A
//! route delete writes the family, prefix, table, protocol, type, scope, and
//! the output interface and metric when the record has one. It writes a zero
//! TOS and a zero source length, and it sends no source address, preferred
//! source, or flow class. A rule delete writes the family, priority, table,
//! action, protocol, and the output interface name when the record has one. It
//! writes zero prefix lengths, TOS, and flags.
//!
//! The kernel may treat a zero or omitted delete selector as a wildcard. This
//! module has no kernel evidence that any of those selectors narrows the
//! match. The selector model is therefore conservative: a live route that
//! differs in TOS or source length, and a live rule that differs in prefix
//! lengths, destination, source, TOS, or flags, is still a candidate. A live
//! route or rule with an attribute that this module does not model is also a
//! candidate. The IPv6 parser accepts the kernel's `RTA_CACHEINFO` attribute,
//! which `rt6_fill_node` always reports, and validates its fixed size. That
//! attribute holds cache counters and a signed expiry, not a selector. The
//! counters are ignored. A nonzero expiry marks the route unclean and keeps it
//! as a candidate, because this module never installs an expiring route. A zero
//! or absent expiry is not ownership evidence either; it only leaves the shape
//! clean, and every recorded field must still match. Both route parsers also
//! mark a route with `RTM_F_CLONED` unclean and keep it as a candidate. A
//! resolved or cached exception is not a plain FIB entry, so a future /128
//! route must not adopt one. Both route parsers mark every other unknown
//! attribute instead of ignoring it. A route whose IPv6 preference is not the
//! default stays a candidate and is never the record. A candidate that is not
//! the record makes the request ambiguous.
//!
//! The route selector follows the kernel delete path, not only the request
//! bytes. That path ignores `rtm_type` for IPv6, and a route with a nexthop
//! object can ignore the output interface, so a route type and an interface
//! are not filters here. A live route that differs in type, protocol, scope, or
//! output interface therefore stays a candidate, and the request is ambiguous
//! until the full record comparison proves the single selected object. The
//! candidate set is a superset of the routes that the kernel can delete, so a
//! wider model can refuse a delete, never delete a foreign route. It also means
//! that a blackhole and a unicast route at one IPv6 prefix are not separable by
//! the delete request. A route that the kernel can match more than once, such
//! as an IPv6 ECMP group with sibling entries, may lose more than one entry to
//! one delete. The cleanup refuses such a request before it sends it, because
//! it never sends a request that selects two entries.
//!
//! Cleanup selects the live objects that the encoded request can match. It
//! sends the delete only when a second read selects exactly one object and
//! every recorded field matches it. Two recorded objects can share a priority
//! or a prefix when their request bytes differ in a field that the selector
//! still compares, such as two outer rules with different interface names or
//! two routes with different metrics. A request that
//! can match two live objects, a selected object that is not the record, an
//! unknown selector or attribute, or a failed read blocks the delete, keeps the
//! record, and keeps the claim. An absent object is never deleted, because a
//! dump can omit a stable object. The cleanup rereads the list and treats a
//! recorded object as gone only after two consecutive complete rounds agree
//! that no request for it selects a live object. A round in which any read,
//! including a delete confirmation read, showed a selected object is not an
//! absence round.
//!
//! An add can be applied before its acknowledgement arrives. A kernel answer,
//! or a failure before the request left this process, is definite and drops
//! the record. Any other add failure, such as an ACK timeout or a lost answer,
//! has an unknown outcome. The manager keeps the record without a read, because
//! one read that omits the object is not proof that the add failed. The
//! rollback then deletes the object only when two reads show the exact record,
//! and drops the record only after the absence agreement.
//!
//! Every dump message is checked for `NLM_F_DUMP_INTR`, including
//! `NLMSG_DONE`. The kernel can set the flag when another process changed the
//! routing state during the dump. A flagged list is not complete, so it is
//! never proof that an object is absent. The reader drains the dump to
//! `NLMSG_DONE` and retries it three times. A list that is still flagged fails
//! the read. A cleanup or recovery then keeps every record and the route claim,
//! and reports an inconclusive result.
//!
//! The absence of the flag is not proof either. Under concurrent churn a
//! kernel dump can omit a stable object without setting `NLM_F_DUMP_INTR`. One
//! complete dump is therefore never proof that an object is absent. A cleanup
//! or recovery that does not see a recorded object does not delete that object
//! and does not release the route claim. It reads again, and it treats the
//! object as gone only after two consecutive complete reads agree that it is
//! absent. That agreement is evidence, not a guarantee: a kernel that omits the
//! object on every read can still hide it. A record that is still unconfirmed
//! after the bounded rounds keeps the claim in place and makes the result
//! inconclusive.
//!
//! A route read asks for one table when the kernel supports strict checking
//! (`NETLINK_GET_STRICT_CHK`, Linux 4.20 and later). The kernel then returns
//! only that table and marks the reply `NLM_F_DUMP_FILTERED`. The reader
//! requires the mark before it relies on the filter. If the socket option is
//! missing or the reply is not marked, it reads the whole family and filters
//! the reported table in this process. A whole-family dump is capped at 4096
//! messages. A larger family makes the read fail rather than return a partial
//! list. On a kernel before 4.20 there is no table filter for a route dump, so
//! that cap covers every table and a very large host can make cleanup
//! inconclusive; the claim and the records stay in place. Linux 4.20 and later
//! filter the dedicated table, so the cap covers only that table.
//!
//! The filter is the delete table. A route delete carries the same table id,
//! and the kernel selects the route inside that table, so an object in another
//! table is never a delete target. Dropping a reply whose reported table
//! differs therefore cannot hide a route that this request could remove. A
//! discarded route is still not evidence that the table is empty; the absence
//! rules above decide that.
//!
//! A strict table read treats a table as absent only when the kernel ends the
//! dump with `NLMSG_DONE` carrying `-ENOENT`, the reply held no data message,
//! and no message carried `NLM_F_DUMP_INTR`. An `NLMSG_ERROR` with `ENOENT`, a
//! done status that follows a data message, or a flagged reply is a failed
//! read, not an empty table. An empty table does not prove that a foreign
//! route cannot appear after the read.
//!
//! # Crash recovery
//!
//! A crash that skips cleanup closes the TUN descriptor. The kernel then removes
//! the device, its address, and its device-bound routes. The policy rules are
//! not bound to the device, so both priorities for both families survive. In
//! block mode the `2000::/3` blackhole in the tunnel table also survives, so
//! IPv6 stays blocked. The next start previously refused while the priorities
//! were in use, and an operator had to delete the rules by hand.
//!
//! The manager now writes a claim to [`ROUTE_CLAIM_PATH`] before the first add
//! and removes it only after the last proven delete. The claim names the kernel
//! boot, the network namespace, the tunnel name and index, the outer interface
//! name, the IPv6 policy, and the writer pid. It can also name predecessor
//! tunnel records, so a replacement claim keeps the selectors of the record it
//! replaces. A union above four predecessors drops the oldest predecessor only
//! after a completed two-absence recovery; without that proof the start refuses
//! and leaves the old claim in place. The rule and route selectors are
//! rebuilt from the module constants, so a claim cannot widen its own match.
//! The file lives on the volatile `/run` mount, so a reboot clears it together
//! with the kernel objects.
//!
//! [`RouteManager::claim_start`] takes the claim before the caller creates a TUN
//! device or changes a link address. A start that loses the claim therefore
//! changes no host state. [`RouteManager::install_verified`] also takes the
//! claim itself when the caller skipped that step, so a direct test call keeps
//! the old behavior.
//!
//! A start opens the claim and takes an exclusive `flock` on the descriptor
//! before it reads the file. A held lock refuses the start without a retry.
//! The holder is usually a running tunnel, but [`inspect_route_claim`] and
//! [`clear_corrupt_route_claim`] also take the lock for a moment, so a refusal
//! is not proof of a live owner. A free lock means the writer is gone, because
//! the kernel drops the lock on any process exit, including `SIGKILL`. The
//! lock alone is not proof: another process can unlink the path between the
//! open and the lock, so the start also compares the device and inode of the
//! locked descriptor with the path under the lock and requires exactly one
//! link. A hard link would let another path change the locked file, so the
//! start refuses it. A mismatch closes the descriptor and retries a bounded
//! number of times. The start then adopts the claim only when every condition
//! holds:
//!
//! - The locked descriptor is still the file at the claim path.
//! - The claim file is a private regular file of the service account. A FIFO,
//!   socket, device, or directory at the path is refused before any read, so a
//!   corrupt path cannot block the process.
//! - The claim parses under the current format version.
//! - The recorded boot id is the current boot id. A kernel object cannot
//!   survive a reboot, so a claim from an earlier boot is discarded without
//!   touching a route or a rule.
//! - The recorded network namespace is the current network namespace. Netlink
//!   route and rule state is per namespace, so a claim from another namespace
//!   is left in place and refused rather than adopted.
//! - The lookup of every claimed tunnel name succeeded and proved the name
//!   absent. Only `ENODEV` and `ENXIO` prove absence, and any other error is
//!   inconclusive. The recorded index must also be free. Linux reuses interface
//!   indexes, so a free name whose old index now belongs to another interface
//!   is inconclusive: a recorded route names the index.
//! - Every live rule at the two reserved priorities is an exact match for one
//!   of the recorded rules, and no recorded rule's delete request can match a
//!   rule that is not its record.
//! - Every live route in the dedicated table is an exact match for one of the
//!   recorded routes, and no recorded route's delete request can match a route
//!   that is not its record. Two live routes can share a prefix when their
//!   delete selectors differ in a field that the model still compares. The
//!   IPv6 delete path ignores the route type, so a blackhole and a unicast
//!   route at one prefix are ambiguous, not two separable records.
//!
//! The decision is all or nothing. An inconclusive result deletes no object,
//! leaves the claim in place, and returns an error. A conclusive result deletes
//! only a recorded object that a read shows as an exact match, then reads
//! again. It repeats until two consecutive rounds delete nothing and show no
//! recorded object. A round that showed an object on one read and omitted it
//! on the confirmation read does not count. A failed delete, a foreign object,
//! a read failure, or an unstable list stops the recovery with the remaining
//! objects still recorded.
//!
//! After a successful recovery the recovered record stays in the claim file.
//! `claim_start` never clears it: its later read of the table and both reserved
//! priorities is one snapshot, and a dump can omit a stable rule or route. The
//! install runs the same read again, then writes and syncs a replacement that
//! absorbs the recovered record as a predecessor before the first add. A union
//! that would exceed four predecessors keeps the newest four because the
//! recovery just completed two complete absence reads over every selector.
//! Without that proof the install refuses and leaves the old claim. If the
//! read, the write, or a later add fails, the file still holds a record that
//! covers the retained and new selectors, and a release or drop keeps it. A
//! dropped oldest predecessor is still adopted into this run's cleanup record,
//! so this run reads and keeps it when the reads do not agree. The next start
//! adopts the retained record again. An empty claim names no object, and a
//! release removes it under the lock. A failed replacement write restores the
//! previous bytes; if that restore also fails, the file is marked with invalid
//! text and is kept so a later start fails closed instead of reading an empty
//! claim.
//!
//! The delete request carries the encoded selectors, not a creator identity,
//! and it carries fewer selectors than the full record. The kernel can match a
//! foreign object that carries the same request selectors. The recovery
//! therefore reads the key again immediately before it deletes, and it sends
//! the delete only when both reads select one object that matches every
//! recorded field. A request that selects two objects, or one that is not the
//! record, blocks the delete. It never deletes an object that a read did not
//! show. A read, a comparison, and a delete are still separate calls, and a
//! privileged process can replace the object between them. Two agreeing reads
//! reduce the chance of a dump omission; they do not guarantee completeness.
//!
//! A cleanup that cannot prove every delete reports the failure, keeps the claim
//! file as the record for the next start, and keeps its lock until this process
//! exits. A second start therefore refuses while the process lives. When the
//! process exits, the kernel releases the lock and the next start can adopt the
//! record under the same exact-match rules.
//!
//! [`inspect_route_claim`] reports the claim without changing it, including a
//! damaged file and a namespace or boot mismatch. [`clear_corrupt_route_claim`]
//! removes only an empty file or a valid record from an earlier boot. A
//! non-empty damaged file may still name live objects, so it is refused for
//! manual inspection. The operator path never deletes a route or a rule.
//!
//! Linux gives an object no creator identity. A privileged process can write a
//! claim and create identical objects, and a run from a build before this claim
//! existed leaves objects with no claim. Both cases keep the old refusal. Do not
//! describe the recovery as complete ownership proof. `docs/LINUX_ROUTE_RECOVERY.md`
//! holds the operator view, the proof, and the limits.
//!
//! # Packet bounds
//!
//! [`PacketBuffer`] holds one allocation for the configured MTU. A read never
//! returns more than the MTU. A write rejects an empty packet, an oversize
//! packet, a malformed IP packet, and a packet with a length that disagrees
//! with its IP header.

#[cfg(test)]
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
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
const RTM_F_CLONED: u32 = 0x200;

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
const NLMSG_OVERRUN: u16 = 4;
#[cfg(test)]
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;

/// The kernel could not produce a consistent dump. Any message in the dump,
/// including `NLMSG_DONE`, can carry this flag. A dump with this flag is not a
/// complete list, so it is never proof that an object is absent.
const NLM_F_DUMP_INTR: u16 = 0x10;

/// The kernel applied the dump filter that the request named. A strict table
/// dump without this flag may have returned every table.
const NLM_F_DUMP_FILTERED: u16 = 0x20;

/// Route attribute types. The values are from `linux/rtnetlink.h`.
const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_FLOW: u16 = 11;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;
const RTA_PREF: u16 = 20;
const RTA_NH_ID: u16 = 30;
const RTA_ENCAP: u16 = 22;
const RTA_ENCAP_TYPE: u16 = 21;

/// The default IPv6 route preference, in the `RTA_PREF` attribute.
///
/// An IPv6 route reply reports the preference for every route. The default
/// medium preference is zero, which is the only value that this module adds. A
/// different value is not this module's route.
const RTA_PREF_MEDIUM: u8 = 0;

/// The kernel size of one `RTA_CACHEINFO` value.
///
/// `rt6_fill_node` passes `RTA_CACHEINFO` to `rtnl_put_cacheinfo`, which always
/// writes one `struct rta_cacheinfo`. The structure holds eight 32-bit fields.
/// The values are live cache counters and an expiry, not route selectors.
/// A nonzero expiry marks the route as unowned by this manager.
const RTA_CACHEINFO_LEN: usize = 32;

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

/// The crash-recovery claim for the tunnel routes and rules.
///
/// The manager writes this file before it adds an object and removes it only
/// after every recorded object is proven gone. A replacement record keeps the
/// selectors of the record that it replaces as predecessors. The parent
/// directory is on the volatile `/run` mount, so a reboot clears the claim
/// together with the kernel objects that it describes. The claim is private to
/// the service account and is held under an exclusive `flock` while the owner
/// runs. A later start uses the lock, the exact selectors, and an
/// all-or-nothing match to decide whether a leftover object belongs to a
/// crashed run. See the crash recovery section in the module documentation.
pub const ROUTE_CLAIM_PATH: &str = "/run/hotspotshade/route-claim";

/// The first line of a route claim. The number is the claim format version.
///
/// Version 2 adds the kernel boot id and the network namespace id. Version 1 is
/// refused: it cannot prove that its objects are in this namespace. Version 3
/// adds predecessor records, so a replacement claim keeps the selectors of the
/// record that it replaces until cleanup proves the older objects gone.
const CLAIM_HEADER: &str = "hotspotshade-route-claim 3";

/// The version 2 header. A record without predecessor lines is still readable
/// and is upgraded to version 3 the next time a run writes its own record.
const CLAIM_HEADER_V2: &str = "hotspotshade-route-claim 2";

/// The largest number of predecessor records that one claim can carry. A start
/// that would need more keeps the newest records only after the recovery read
/// every recorded selector and saw it absent on two complete rounds. Without
/// that proof it refuses and leaves the old claim in place.
const MAX_CLAIM_PRIORS: usize = 4;

/// The largest route claim that this module reads or writes.
const MAX_CLAIM_BYTES: usize = 4096;

/// Content that a failed replacement leaves behind when it cannot restore the
/// previous claim. The text is deliberately invalid: a later start fails
/// closed instead of reading an empty claim while old objects may survive.
const DAMAGED_CLAIM_TEXT: &str = "hotspotshade-route-claim damaged\n";

/// The network namespace of this process. The kernel identifies a namespace by
/// the device and inode of its `nsfs` file.
const NETNS_PATH: &str = "/proc/self/ns/net";

/// The kernel boot id. The value is stable for one boot and changes on reboot.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

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
const IFLA_LINK: u16 = 5;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_LINK_NETNSID: u16 = 37;
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

/// The netlink reply deadline. A slow reply is inconclusive.
const NETLINK_TIMEOUT: Duration = Duration::from_secs(2);

/// The largest netlink reply that this module accepts. A route dump covers
/// every table. A busy host can return several entries after a device appears.
const MAX_NETLINK_REPLY: usize = 256 * 1024;

/// The largest number of messages that one dump may return.
///
/// A strict table dump returns only the named table. The tunnel table holds
/// three recorded routes, so this bound leaves room for a large foreign set and
/// still fails instead of returning a silently truncated list. A host whose
/// family dump exceeds this bound keeps its record and its route claim, and the
/// cleanup reports a failed read. That is the safe result, not an absence.
const MAX_DUMP_MESSAGES: usize = 4096;

/// The number of complete attempts for a dump that reports
/// `NLM_F_DUMP_INTR`. A kernel can report the flag while another process
/// changes a route. A bounded retry can read a consistent list. After the last
/// attempt the read is inconclusive, so no caller treats it as an absence.
const DUMP_ATTEMPTS: usize = 3;

/// The number of consecutive complete reads that must agree before a recorded
/// object that a dump did not show is treated as gone. A kernel dump can omit a
/// stable object without setting `NLM_F_DUMP_INTR` under concurrent churn, so
/// one read is not enough. Two agreeing reads are evidence, not proof: a kernel
/// that omits the object on every read can still hide it.
const ABSENCE_READS: usize = 2;

/// The largest number of cleanup or recovery rounds. Each round reads the live
/// state and deletes only a recorded object that the read shows as an exact
/// match. A round counts toward [`ABSENCE_READS`] only when it deletes nothing
/// and no read in it, including a delete confirmation read, shows a recorded
/// object. A recorded object that one read shows and the next read omits
/// therefore never counts as absent. A list
/// that keeps changing uses the bound and then fails closed with every record
/// and the route claim still in place.
const REMOVAL_ROUNDS: usize = 4;

/// The netlink socket option that enables strict GET validation and the
/// `RTA_TABLE` filter for a route dump. Linux 4.20 added both. An older kernel
/// returns `ENOPROTOOPT`, and the reader falls back to a full family dump.
const NETLINK_GET_STRICT_CHK: libc::c_int = 12;

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

/// Return the interface name that currently owns one index.
///
/// A missing index returns the kernel's `ENXIO`. Do not cache the answer: an
/// index can be reused after a device disappears.
fn interface_name(index: u32) -> io::Result<String> {
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index must be nonzero",
        ));
    }
    let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
    let name = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) };
    if name.is_null() {
        return Err(io::Error::last_os_error());
    }
    let name = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    name.to_str()
        .map(str::to_owned)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "interface name is not text"))
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
    let output = Command::new(program)
        .args(args)
        .env_remove(crate::secret_env::PHONE_TOKEN_ENV)
        .output()?;
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

/// Evidence that an outer interface is a live physical outer link.
///
/// Only [`RouteManager::verify_outer_pin`] can create this value. It proves
/// the interface index, name, link state, type and sysfs association. It does
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
    /// Lower link, master, and cross-namespace link metadata.
    pub lower: Option<u32>,
    pub master: Option<u32>,
    pub link_netnsid: Option<i32>,
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
    /// The `rtm_scope` value. An IPv4 route with an output interface and no
    /// gateway uses `RT_SCOPE_LINK`.
    pub scope: u8,
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
    /// True when the reply carried an attribute that this module does not
    /// model. Cleanup must not treat such a route as the recorded object.
    pub unexpected: bool,
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
    /// The `rtm_scope` value. An IPv6 route usually uses `RT_SCOPE_UNIVERSE`.
    pub scope: u8,
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
    /// True when the reply carried an attribute that this module does not
    /// model. Cleanup must not treat such a route as the recorded object.
    pub unexpected: bool,
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
    if link.hardware_type != libc::ARPHRD_ETHER {
        return Err(RouteVerifyError::OuterLinkMismatch(
            "the outer link is not Ethernet",
        ));
    }
    if link.kind.is_some()
        || link.lower.is_some_and(|v| v != link.ifindex)
        || link.master.is_some_and(|v| v != link.ifindex)
        || link.link_netnsid.is_some()
    {
        return Err(RouteVerifyError::OuterLinkMismatch(
            "the outer link has virtual or stacked link metadata",
        ));
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
#[derive(Debug)]
enum ReplyError {
    Kernel(i32),
    Unavailable {
        operation: &'static str,
        errno: i32,
    },
    Malformed(&'static str),
    /// A dump stayed inconsistent after every bounded retry. The list is not a
    /// complete observation, so the caller must keep its record.
    Inconsistent,
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
        ReplyError::Inconsistent => RouteVerifyError::Unavailable {
            operation: "netlink dump",
            errno: libc::EAGAIN,
        },
    }
}

/// The complete messages of one dump.
struct DumpReply {
    messages: Vec<Vec<u8>>,
    /// The kernel marked the reply `NLM_F_DUMP_FILTERED`, so it applied the
    /// requested table filter.
    filtered: bool,
}

/// One finished dump attempt.
enum DumpAttempt {
    Complete(DumpReply),
    /// The kernel ended the dump with `NLMSG_DONE` carrying `-ENOENT`, the
    /// attempt held no data message, and no message carried
    /// `NLM_F_DUMP_INTR`. Only a strict table dump may read this shape as an
    /// absent table. Every other shape is a failed read.
    EmptyTable,
    /// The kernel ended the dump with `NLMSG_DONE` carrying a negative status
    /// that is not an accepted empty-table shape. The value is the positive
    /// errno.
    Failed(i32),
    /// At least one message carried `NLM_F_DUMP_INTR`, so the attempt is not a
    /// complete observation even when it reached `NLMSG_DONE`.
    Inconsistent,
}

/// The accumulated state of one dump attempt.
///
/// An inconsistent attempt is still read through `NLMSG_DONE`. A netlink
/// socket carries one dump at a time, and a new request before the old dump
/// ends fails with `EBUSY`.
#[derive(Default)]
struct DumpState {
    messages: Vec<Vec<u8>>,
    filtered: bool,
    inconsistent: bool,
    done: bool,
    /// The negative status that `NLMSG_DONE` carried. An older kernel sends no
    /// payload, which leaves this as `None`.
    done_status: Option<i32>,
}

impl DumpState {
    /// Read every netlink message in one datagram.
    ///
    /// The sequence number selects this dump. A message with another sequence
    /// is ignored, as the existing request reader does. `NLM_F_DUMP_INTR` is
    /// checked on every message, including `NLMSG_DONE`, because the kernel can
    /// set it on the last message after an earlier message looked complete.
    fn consume(&mut self, datagram: &[u8], sequence: u32, expected: u16) -> Result<(), ReplyError> {
        let mut offset = 0usize;
        while offset + NLMSG_HDRLEN <= datagram.len() {
            let total = read_u32(&datagram[offset..offset + 4]) as usize;
            if total < NLMSG_HDRLEN || offset + total > datagram.len() {
                return Err(ReplyError::Malformed("invalid netlink reply length"));
            }
            let kind = read_u16(&datagram[offset + 4..offset + 6]);
            let flags = read_u16(&datagram[offset + 6..offset + 8]);
            if read_u32(&datagram[offset + 8..offset + 12]) == sequence {
                if flags & NLM_F_DUMP_INTR != 0 {
                    self.inconsistent = true;
                }
                if flags & NLM_F_DUMP_FILTERED != 0 {
                    self.filtered = true;
                }
                match kind {
                    NLMSG_ERROR => {
                        if total < NLMSG_HDRLEN + 4 {
                            return Err(ReplyError::Malformed("short netlink error"));
                        }
                        let errno =
                            read_i32(&datagram[offset + NLMSG_HDRLEN..offset + NLMSG_HDRLEN + 4]);
                        if errno < 0 {
                            return Err(ReplyError::Kernel(-errno));
                        }
                        return Err(ReplyError::Malformed("unexpected netlink acknowledgement"));
                    }
                    NLMSG_DONE => {
                        // Linux 4.20 and later put the dump status in the done
                        // payload. An older kernel sends no payload. A negative
                        // value is a kernel status, not an empty list. Only the
                        // strict table reader may accept one shape of it as an
                        // absent table, and only in `finish`.
                        if total >= NLMSG_HDRLEN + 4 {
                            let status = read_i32(
                                &datagram[offset + NLMSG_HDRLEN..offset + NLMSG_HDRLEN + 4],
                            );
                            if status > 0 {
                                return Err(ReplyError::Malformed(
                                    "unexpected netlink dump status",
                                ));
                            }
                            if status < 0 {
                                self.done_status = Some(status);
                            }
                        }
                        self.done = true;
                    }
                    NLMSG_OVERRUN => return Err(ReplyError::Malformed("netlink dump was overrun")),
                    kind if kind == expected => {
                        if self.messages.len() >= MAX_DUMP_MESSAGES {
                            return Err(ReplyError::Malformed("netlink dump is too large"));
                        }
                        self.messages
                            .push(datagram[offset..offset + total].to_vec());
                    }
                    _ => {}
                }
            }
            let aligned = (total + 3) & !3;
            if offset + aligned > datagram.len() {
                return Err(ReplyError::Malformed("unaligned netlink reply"));
            }
            offset += aligned;
        }
        Ok(())
    }

    fn finish(self) -> DumpAttempt {
        if self.inconsistent {
            return DumpAttempt::Inconsistent;
        }
        if let Some(status) = self.done_status {
            let errno = -status;
            // The accepted absent-table shape is exact: the dump ended with
            // `NLMSG_DONE`, the status is `ENOENT`, the attempt held no data
            // message, and no message carried `NLM_F_DUMP_INTR`. An `ENOENT`
            // that arrives with data, or that arrived as an `NLMSG_ERROR`, is
            // not accepted. The caller falls back or fails closed.
            if errno == libc::ENOENT && self.messages.is_empty() {
                return DumpAttempt::EmptyTable;
            }
            return DumpAttempt::Failed(errno);
        }
        DumpAttempt::Complete(DumpReply {
            messages: self.messages,
            filtered: self.filtered,
        })
    }
}

/// Run complete dump attempts until one is consistent or the bound is spent.
///
/// An attempt that reports `NLM_F_DUMP_INTR` has already drained to
/// `NLMSG_DONE`, so the next attempt can reuse the socket. A kernel error or a
/// malformed reply stops the retries immediately: those are not transient
/// inconsistency.
fn retry_dump(
    mut attempt: impl FnMut() -> Result<DumpAttempt, ReplyError>,
) -> Result<DumpAttempt, ReplyError> {
    for _ in 0..DUMP_ATTEMPTS {
        match attempt()? {
            DumpAttempt::Inconsistent => {}
            result => return Ok(result),
        }
    }
    Err(ReplyError::Inconsistent)
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
///
/// A delete writes the family, prefix length, destination, table, protocol,
/// route type, and scope. It writes a zero TOS and a zero source length, and it
/// sends no source address, preferred source, or flow class. It sends the
/// output interface and the metric only when the record has one, so an IPv4
/// route with the default metric sends no priority attribute. The record
/// constructors hold zero TOS and no source. The kernel may treat those zero or
/// omitted fields as wildcards, and its IPv6 delete path ignores the route
/// type, so [`RouteKey::delete_selects`] keeps a live route that differs in
/// them, and a route of another type at the same prefix, as a candidate. A
/// blackhole record has no output interface, and its delete request therefore
/// selects no device. The ownership check compares the full record before it
/// relies on this wider request.
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
    if let Some(metric) = key.metric {
        push_attr(&mut message, RTA_PRIORITY, &metric.to_ne_bytes());
    }
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    message
}

/// Build one `RTM_NEWRULE` or `RTM_DELRULE` request for a recorded key.
///
/// A delete carries the output interface name and the non-zero protocol. A
/// missing device leaves the rule detached, and `rule_find` compares the stored
/// name and protocol. The delete also writes zero prefix lengths, TOS, and
/// flags. The kernel may treat those zero or omitted selectors as wildcards, so
/// [`RuleKey::delete_selects`] keeps a live rule that differs in them as a
/// candidate. The rule priority and the table are the other delete keys. The
/// ownership check runs before the delete and proves the full rule from the
/// reply.
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
    if rule.protocol != 0 {
        push_attr(&mut message, FRA_PROTOCOL, &[rule.protocol]);
    }
    if let Some(oif) = rule.oif.as_deref() {
        let mut name = oif.as_bytes().to_vec();
        name.push(0);
        push_attr(&mut message, FRA_OIFNAME, &name);
    }
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    message
}

/// Build one `RTM_GETROUTE` dump request for a family.
///
/// Without a strict-check kernel the request dumps every table of the family.
/// [`NetlinkRoute::table_routes`] filters the replies by their reported table.
fn encode_route_dump(sequence: u32, family: u8) -> Vec<u8> {
    let mut message = begin_netlink(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, sequence, 12);
    message[NLMSG_HDRLEN] = family;
    message
}

/// Build one `RTM_GETROUTE` dump request for one family and table.
///
/// A strict-check kernel applies `RTA_TABLE` and returns only that table. A
/// kernel without strict checking ignores the attribute. The reader requires
/// `NLM_F_DUMP_FILTERED` before it relies on the filter.
fn encode_route_table_dump(sequence: u32, family: u8, table: u32) -> Vec<u8> {
    let mut message = encode_route_dump(sequence, family);
    push_attr(&mut message, RTA_TABLE, &table.to_ne_bytes());
    let length = message.len() as u32;
    write_u32(&mut message[0..4], length);
    message
}

/// Build one `RTM_GETRULE` dump request for a family.
fn encode_rule_dump(sequence: u32, family: u8) -> Vec<u8> {
    let mut message = begin_netlink(RTM_GETRULE, NLM_F_REQUEST | NLM_F_DUMP, sequence, 12);
    message[NLMSG_HDRLEN] = family;
    message
}

/// Parse route replies and keep only the named family and table.
///
/// A strict table dump already contains one table. A full family dump contains
/// every table, so the reported table selects the dedicated one. A reply that
/// does not parse fails the read; the caller keeps its record. A reply with an
/// attribute that this module does not model is carried with `unexpected` set,
/// so cleanup refuses to treat that route as the recorded object.
fn select_route_table(
    replies: Vec<Vec<u8>>,
    family: u8,
    table: u32,
) -> Result<Vec<ObservedRouteKey>, RouteVerifyError> {
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
                unexpected: route.unexpected,
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
                unexpected: route.unexpected || route.cloned,
            });
        }
    }
    Ok(routes)
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
    let scope = payload[6];
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
    let mut unexpected = flags & RTM_F_CLONED != 0;
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
            _ => unexpected = true,
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
        scope,
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
        unexpected,
    })
}

fn ipv6_from_bytes(value: &[u8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&value[..16]);
    Ipv6Addr::from(octets)
}

/// Convert one `RTM_NEWROUTE` IPv6 reply into an observed route.
///
/// The kernel's `rt6_fill_node` always reports `RTA_CACHEINFO` through
/// `rtnl_put_cacheinfo`. The parser accepts exactly one value of the kernel
/// size and ignores its cache counters. A nonzero expiry marks the route
/// unexpected because this manager never creates an expiring route. Expiry is
/// not a delete selector, so an expiring route remains a candidate. Every
/// other attribute that this module does not model also sets `unexpected`.
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
    let scope = payload[6];
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
    let mut preference = None;
    let mut cacheinfo_seen = false;
    let mut unexpected = false;
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
            RTA_PREF => {
                if value.len() != 1 {
                    return Err(RouteVerifyError::MalformedReply(
                        "IPv6 route preference attribute has the wrong length",
                    ));
                }
                if preference.replace(value[0]).is_some() {
                    return Err(RouteVerifyError::MalformedReply(
                        "route message has two preference attributes",
                    ));
                }
            }
            RTA_CACHEINFO => {
                // `rt6_fill_node` always adds this attribute. It reports
                // cache counters and an expiry, not a selector. Accept the
                // one kernel shape. A nonzero expiry does not match a route
                // this manager creates, even though it is not a selector. A different
                // length or a duplicate is not a reply that this parser can
                // model, so the read fails instead of guessing.
                if value.len() != RTA_CACHEINFO_LEN {
                    return Err(RouteVerifyError::MalformedReply(
                        "IPv6 route cacheinfo attribute has the wrong length",
                    ));
                }
                if cacheinfo_seen {
                    return Err(RouteVerifyError::MalformedReply(
                        "route message has two cacheinfo attributes",
                    ));
                }
                cacheinfo_seen = true;
                if read_u32(&value[8..12]) != 0 {
                    unexpected = true;
                }
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
            _ => unexpected = true,
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
    // Every IPv6 route reply reports the preference. This module adds only the
    // default medium value. A non-default value means that the route is not
    // the recorded object: keep it as a delete candidate and let the full
    // ownership comparison refuse the delete. A malformed or duplicate
    // attribute is a failed read above, so no caller treats the dump as
    // complete.
    if preference.is_some_and(|value| value != RTA_PREF_MEDIUM) {
        unexpected = true;
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
        scope,
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
        unexpected,
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
    let mut linkinfo_seen = false;
    let mut lower = None;
    let mut master = None;
    let mut link_netnsid = None;
    visit_attrs(&payload[16..], |attribute, value| {
        match attribute {
            IFLA_IFNAME => {
                if name.is_some() {
                    return Err(RouteVerifyError::MalformedReply("duplicate link name"));
                }
                let text = cstr_text(value)?;
                if text.is_empty()
                    || value.last() != Some(&0)
                    || value[text.len()..].iter().any(|byte| *byte != 0)
                {
                    return Err(RouteVerifyError::MalformedReply(
                        "link message has an empty interface name",
                    ));
                }
                name = Some(text.to_owned());
            }
            IFLA_LINKINFO => {
                if linkinfo_seen {
                    return Err(RouteVerifyError::MalformedReply(
                        "duplicate link information",
                    ));
                }
                linkinfo_seen = true;
                visit_attrs(value, |nested, nested_value| {
                    if nested == IFLA_INFO_KIND {
                        let text = cstr_text(nested_value)?;
                        if kind.is_some()
                            || text.is_empty()
                            || nested_value.last() != Some(&0)
                            || nested_value[text.len()..].iter().any(|byte| *byte != 0)
                        {
                            return Err(RouteVerifyError::MalformedReply(
                                "invalid or duplicate link kind",
                            ));
                        }
                        kind = Some(text.to_owned());
                    }
                    Ok(())
                })?;
            }
            IFLA_LINK | IFLA_MASTER | IFLA_LINK_NETNSID => {
                if value.len() != 4 {
                    return Err(RouteVerifyError::MalformedReply(
                        "invalid link relationship",
                    ));
                }
                let v = read_u32(value);
                let slot = match attribute {
                    IFLA_LINK => &mut lower,
                    IFLA_MASTER => &mut master,
                    _ => &mut link_netnsid,
                };
                if slot.replace(v).is_some() {
                    return Err(RouteVerifyError::MalformedReply(
                        "duplicate link relationship",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    if linkinfo_seen && kind.is_none() {
        return Err(RouteVerifyError::MalformedReply(
            "link information has no kind",
        ));
    }
    let name = name.ok_or(RouteVerifyError::MalformedReply(
        "link message has no interface name",
    ))?;
    Ok(ObservedLink {
        ifindex: index as u32,
        name,
        kind,
        lower,
        master,
        link_netnsid: link_netnsid.map(|v| v as i32),
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
/// Every field is part of the add request and the record. The kernel returns
/// the scope in an IPv4 or IPv6 route dump, so [`RouteKey::same_key`] compares
/// it as well.
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

    /// Compare every recorded field.
    ///
    /// A blackhole route has no real output interface. The kernel reports the
    /// loopback interface for it, so the output interface is not a selector for
    /// a blackhole route. The caller also checks the route shape and any
    /// unmodeled attribute through [`ObservedRouteKey::is_clean`].
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
            && self.scope == other.scope
            && (self.route_type == RTN_BLACKHOLE || self.oif == other.oif)
            && self.metric == other.metric
            && self.prefsrc == other.prefsrc
            && self.flow == other.flow
    }

    /// Return true when the encoded `RTM_DELROUTE` request for `self` can match
    /// the live route `live`.
    ///
    /// This models the candidate set of the request, not full equality. The
    /// request carries the family, prefix length, destination, table, protocol,
    /// type, and scope. It always sends a zero TOS and a zero source length and
    /// no source address. It sends the output interface only when the record
    /// has one, and the metric only when the record has one.
    ///
    /// The candidate set must be a superset of the routes that the kernel can
    /// delete. A filter that is narrower than the kernel hides a foreign route,
    /// and the cleanup then sends a delete that removes it. The review of the
    /// Linux delete path found two differences from the request bytes:
    ///
    /// - The IPv6 delete path ignores `rtm_type`. A unicast route, a blackhole,
    ///   or any other type at the same prefix is therefore a candidate. IPv4
    ///   compares the type. Keeping another type as a candidate is a
    ///   conservative over-approximation that can refuse a delete, never widen
    ///   one.
    /// - A route that uses a nexthop object can ignore the output interface,
    ///   and a multipath route keeps a separate interface for each nexthop.
    ///   Both stay candidates whatever output interface the dump reports.
    ///
    /// The model also keeps a live route that differs in protocol or scope as
    /// a candidate. The IPv6 delete path compares the protocol when the
    /// request carries a nonzero one, and the IPv4 delete path compares a
    /// nonzero scope, so a filter on either would match the kernel more
    /// closely. A wider candidate set can refuse a delete; it never widens
    /// one. The model does not filter on TOS or source either, because the
    /// request leaves both at zero. The model has no kernel evidence that a
    /// zero or omitted field narrows the match, and a field that the kernel
    /// ignores would otherwise hide a candidate. The metric filters only when
    /// the record has one, because the request then carries `RTA_PRIORITY`.
    /// Preferred source and flow class are not in the request and never
    /// filter.
    ///
    /// The cleanup calls a delete only after [`route_is_recorded`] proves that
    /// exactly one live route is selected, that it has the clean shape, and
    /// that it matches every recorded field, so this wider set is the second
    /// line of defense against a race that swaps the object.
    fn delete_selects(&self, live: &ObservedRouteKey) -> bool {
        self.family == live.key.family
            && self.destination == live.key.destination
            && self.length == live.key.length
            && self.table == live.key.table
            && match self.oif {
                Some(ifindex) => live.nexthop || live.multipath || live.key.oif == Some(ifindex),
                None => true,
            }
            && match self.metric {
                Some(metric) => live.key.metric == Some(metric),
                None => true,
            }
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
            scope: route.scope,
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
            scope: route.scope,
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
    /// True when the dump carried an attribute that this module does not
    /// model. The key may still equal the record, but the extra attribute can
    /// change how the kernel matches or selects the route.
    unexpected: bool,
}

impl ObservedRouteKey {
    /// Return true when the route has the simple shape that this manager adds.
    fn is_clean(&self) -> bool {
        !self.gateway && !self.multipath && !self.encap && !self.nexthop && !self.unexpected
    }
}

/// One policy rule key that this process created.
///
/// Every selector field is compared before a delete. The kernel fills some
/// selector attributes with a default value, so the constructors and the parser
/// use the same normalized form. An unknown selector sets `unexpected`. The
/// delete selector model keeps such a live rule as a candidate, and the full
/// ownership comparison refuses it.
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
            protocol: ROUTE_PROTOCOL_ID,
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

    /// Return true when the encoded `RTM_DELRULE` request for `self` can match
    /// `live`.
    ///
    /// The request carries the family, zero destination and source lengths,
    /// zero TOS, zero flags, the table, the action, the priority, the protocol
    /// when nonzero, and the output interface name when the record has one. The
    /// kernel compares the stored name even when the device is gone. A tunnel
    /// rule has no output interface, and the request then carries no name, so
    /// the kernel does not compare one. The kernel may treat a zero or omitted
    /// selector as a wildcard; this module has no kernel evidence that it
    /// narrows the match. The model therefore keeps a live rule that differs in
    /// prefix lengths, destination, source, TOS, or flags, and a live rule with
    /// an unknown selector, as a candidate. The cleanup calls a delete only
    /// after [`rule_is_recorded`] proves full equality, so a candidate that is
    /// not the record blocks the delete.
    fn delete_selects(&self, live: &RuleKey) -> bool {
        self.family == live.family
            && self.table == live.table
            && self.priority == live.priority
            && self.action == live.action
            && (self.protocol == 0 || live.protocol == self.protocol)
            && match self.oif.as_deref() {
                Some(name) => live.oif.as_deref() == Some(name),
                None => true,
            }
    }
}

/// Return the live routes that the encoded delete request for `key` can match.
///
/// More than one recorded route can share a prefix or a priority. The kernel
/// selects by the delete request bytes, not by the broad prefix alone, so this
/// list is the set that a delete could act on.
fn routes_selected_by<'a>(
    observed: &'a [ObservedRouteKey],
    key: &RouteKey,
) -> Vec<&'a ObservedRouteKey> {
    observed
        .iter()
        .filter(|item| key.delete_selects(item))
        .collect()
}

/// Return the live rules that the encoded delete request for `rule` can match.
fn rules_selected_by<'a>(observed: &'a [RuleKey], rule: &RuleKey) -> Vec<&'a RuleKey> {
    observed
        .iter()
        .filter(|item| rule.delete_selects(item))
        .collect()
}

/// Return true when the delete request for `key` can match exactly one live
/// route, that route has the clean shape, and every recorded field matches.
///
/// A second live route at the same prefix is allowed when the delete selector
/// still tells the two apart, for example two routes with different metrics, or
/// two plain unicast routes on different tunnel indexes. A route that differs
/// in a field the selector does not compare, such as the type, the protocol, or
/// the output interface of a nexthop-object route, is a candidate too and makes
/// the request ambiguous. A request that can match more than one live route is
/// ambiguous, and the caller must not send it.
fn route_is_recorded(observed: &[ObservedRouteKey], key: &RouteKey) -> bool {
    let selected = routes_selected_by(observed, key);
    selected.len() == 1 && selected[0].is_clean() && key.same_key(&selected[0].key)
}

/// Return true when the delete request for `rule` can match exactly one live
/// rule and every recorded field matches.
///
/// Two outer rules can share a priority when their output interface names
/// differ, because the encoded delete carries the name. A request that can
/// match two live rules is ambiguous, and the caller must not send it.
fn rule_is_recorded(observed: &[RuleKey], rule: &RuleKey) -> bool {
    let selected = rules_selected_by(observed, rule);
    selected.len() == 1 && selected[0] == rule
}

/// Return true when one live route is selected by, and fully equal to, some
/// record in `records`.
///
/// Cleanup uses this to tell an absent record from a foreign object at the same
/// prefix. A live route that another record owns is not a reason to keep this
/// record, but an object that no record owns is.
fn route_belongs_to_record(
    observed: &[ObservedRouteKey],
    route: &ObservedRouteKey,
    records: &[RouteKey],
) -> bool {
    records
        .iter()
        .any(|record| record.delete_selects(route) && route_is_recorded(observed, record))
}

/// Return true when one live rule is selected by, and fully equal to, some
/// record in `records`.
fn rule_belongs_to_record(observed: &[RuleKey], rule: &RuleKey, records: &[RuleKey]) -> bool {
    records
        .iter()
        .any(|record| record.delete_selects(rule) && rule_is_recorded(observed, record))
}

/// What a second read says about a delete candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeleteConfirmation {
    /// The second read selects exactly one live object, the recorded one.
    Confirmed,
    /// The second read selects no live object.
    Absent,
    /// The second read selects two objects or one that is not the record.
    Ambiguous,
}

/// Read the table again and classify the recorded route.
///
/// The cleanup and the recovery call this after a first read selects the exact
/// recorded route, and before they send a delete. A kernel dump can omit a
/// stable route, so one read does not prove that the encoded request selects
/// only the recorded object. A second read reduces the chance that the delete
/// selector matches a foreign object. It is evidence, not proof: a dump that
/// omits the same object on both reads still hides it.
fn confirm_route_present(
    control: &dyn RouteControl,
    key: &RouteKey,
) -> io::Result<DeleteConfirmation> {
    let observed = control.table_routes(key.family, key.table)?;
    let selected = routes_selected_by(&observed, key);
    if selected.is_empty() {
        return Ok(DeleteConfirmation::Absent);
    }
    if selected.len() == 1 && selected[0].is_clean() && key.same_key(&selected[0].key) {
        return Ok(DeleteConfirmation::Confirmed);
    }
    Ok(DeleteConfirmation::Ambiguous)
}

/// Read the rule list again and classify the recorded rule.
fn confirm_rule_present(
    control: &dyn RouteControl,
    rule: &RuleKey,
) -> io::Result<DeleteConfirmation> {
    let observed = control.rules(rule.family)?;
    let selected = rules_selected_by(&observed, rule);
    if selected.is_empty() {
        return Ok(DeleteConfirmation::Absent);
    }
    if selected.len() == 1 && selected[0] == rule {
        return Ok(DeleteConfirmation::Confirmed);
    }
    Ok(DeleteConfirmation::Ambiguous)
}

/// Return the per-family rule list for one address family.
fn rules_in_family(family_rules: &[Vec<RuleKey>], family: u8) -> &[RuleKey] {
    let index = if family == libc::AF_INET as u8 { 0 } else { 1 };
    family_rules
        .get(index)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Return true when a write failed because the kernel did not answer before
/// the netlink deadline. The write can still be applied.
fn is_ack_timeout(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::TimedOut || error.raw_os_error() == Some(libc::ETIMEDOUT)
}

/// A write whose request may have reached the kernel, but whose answer was
/// lost or could not be read. The kernel can have applied the change.
#[derive(Debug)]
struct UnknownWriteOutcome(io::Error);

impl std::fmt::Display for UnknownWriteOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; the kernel may have applied the change",
            self.0
        )
    }
}

impl std::error::Error for UnknownWriteOutcome {}

/// Map a failed add from the netlink layer to an I/O error.
///
/// A kernel answer, and a failure before the request left this process, are
/// definite: the kernel did not apply the change. Every other failure happened
/// after the send, so the outcome is unknown and the error carries
/// [`UnknownWriteOutcome`].
fn add_error_to_io(error: RouteVerifyError) -> io::Error {
    let definite = matches!(
        &error,
        RouteVerifyError::Unavailable { operation, .. }
            if matches!(
                *operation,
                "route control" | "netlink socket" | "netlink bind" | "netlink send"
            )
    );
    let error = route_error_to_io(error);
    if definite {
        return error;
    }
    io::Error::new(error.kind(), UnknownWriteOutcome(error))
}

/// Return true when a failed add may still have been applied.
///
/// The caller keeps the record in that case. It never drops the record from one
/// read that does not show the object, because a dump can omit a stable object.
/// The ordinary cleanup then removes the object only when a read shows it, or
/// drops the record after the absence agreement.
fn write_outcome_unknown(error: &io::Error) -> bool {
    is_ack_timeout(error)
        || error
            .get_ref()
            .is_some_and(|inner| inner.is::<UnknownWriteOutcome>())
}

/// The kernel identity that a claim describes.
///
/// Netlink route and rule state belongs to one network namespace, and every
/// kernel object is rebuilt on boot. A claim that does not match both values
/// cannot describe a live object in this process. The start resolves this value
/// before it reads or changes an object.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClaimIdentity {
    netns_dev: u64,
    netns_ino: u64,
    boot_id: String,
}

impl ClaimIdentity {
    /// Read the identity of the calling process from procfs.
    ///
    /// A failure is an error. Guessing a namespace or a boot would weaken the
    /// check that keeps one namespace from adopting another claim.
    fn current() -> io::Result<Self> {
        let meta = std::fs::metadata(NETNS_PATH).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot identify the network namespace {NETNS_PATH}: {error}"),
            )
        })?;
        let boot = std::fs::read_to_string(BOOT_ID_PATH).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot read the kernel boot id {BOOT_ID_PATH}: {error}"),
            )
        })?;
        Self::new(meta.dev(), meta.ino(), &boot)
    }

    /// Validate one identity value.
    ///
    /// A malformed boot id or a zero namespace inode is an error, so an
    /// unreadable kernel value stops the start instead of weakening the check.
    fn new(netns_dev: u64, netns_ino: u64, boot_id: &str) -> io::Result<Self> {
        let boot_id = boot_id.trim();
        if netns_ino == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the network namespace inode is zero",
            ));
        }
        let shaped = boot_id.len() == 36
            && boot_id
                .bytes()
                .enumerate()
                .all(|(index, byte)| match index {
                    8 | 13 | 18 | 23 => byte == b'-',
                    _ => byte.is_ascii_hexdigit(),
                });
        if !shaped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the kernel boot id is not a UUID",
            ));
        }
        Ok(Self {
            netns_dev,
            netns_ino,
            boot_id: boot_id.to_owned(),
        })
    }
}

/// One tunnel record that a recovered claim already named.
///
/// A replacement record keeps every older tunnel and policy until cleanup has
/// proven the older objects gone. The selectors are rebuilt from the module
/// constants, exactly as for the current record.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClaimPrior {
    tun: String,
    ifindex: u32,
    outer: String,
    ipv6: Ipv6Policy,
}

impl ClaimPrior {
    fn from_record(record: &ClaimRecord) -> Self {
        Self {
            tun: record.tun.clone(),
            ifindex: record.ifindex,
            outer: record.outer.clone(),
            ipv6: record.ipv6,
        }
    }
}

/// The exact set of objects that one run installed.
///
/// The record holds only the values that the manager cannot derive from the
/// module constants: the kernel identity, the tunnel name and index, the outer
/// interface name, and the IPv6 policy. The rule and route selectors themselves
/// come from the constants, so a claim cannot widen its own match.
///
/// A record that replaces a recovered record also carries the recovered tunnel
/// records as predecessors. Their selectors therefore stay covered until the
/// cleanup proves them gone, even when the new run uses a different index,
/// outer interface, or IPv6 policy. The predecessor list is bounded. A union
/// above the bound drops the oldest predecessor only after the recovery
/// completed two complete absence reads over every recorded selector.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClaimRecord {
    identity: ClaimIdentity,
    pid: u32,
    tun: String,
    ifindex: u32,
    outer: String,
    ipv6: Ipv6Policy,
    prior: Vec<ClaimPrior>,
}

impl ClaimRecord {
    fn new(
        tun: &str,
        ifindex: u32,
        outer: &str,
        ipv6: Ipv6Policy,
        identity: ClaimIdentity,
    ) -> Self {
        Self {
            identity,
            pid: std::process::id(),
            tun: tun.to_owned(),
            ifindex,
            outer: outer.to_owned(),
            ipv6,
            prior: Vec::new(),
        }
    }

    /// Keep the record that a replacement replaces, and every predecessor that
    /// record already carried. A duplicate selector is kept once.
    ///
    /// This strict form refuses a fifth distinct predecessor, because dropping
    /// a predecessor without an absence proof could orphan its objects.
    #[cfg(test)]
    fn absorb_predecessor(&mut self, previous: &ClaimRecord) -> io::Result<()> {
        self.absorb_predecessor_with_proof(previous, false)
    }

    /// Keep a predecessor after a recovery that completed two consecutive
    /// complete absence reads over every recorded object.
    ///
    /// The four-predecessor cap cannot grow without bound. When the union would
    /// exceed it, this form keeps the newest [`MAX_CLAIM_PRIORS`] records and
    /// drops the oldest. That is allowed only because the caller passed
    /// `absence_proven`: the just-completed recovery read every dropped
    /// selector and saw no live object on two complete reads. The proof is
    /// evidence, not a guarantee. A kernel that omits a stable object on every
    /// read can still hide it, so a hidden dropped object can survive this
    /// handover. The same run still adopts every predecessor key into its
    /// cleanup record, so an ordinary cleanup reads the dropped key and keeps
    /// it when the reads do not agree. Without the proof the call refuses and
    /// leaves the replacement record unchanged.
    fn absorb_recovered_predecessor(
        &mut self,
        previous: &ClaimRecord,
        absence_proven: bool,
    ) -> io::Result<()> {
        self.absorb_predecessor_with_proof(previous, absence_proven)
    }

    fn absorb_predecessor_with_proof(
        &mut self,
        previous: &ClaimRecord,
        absence_proven: bool,
    ) -> io::Result<()> {
        let mut candidates = Vec::with_capacity(previous.prior.len() + 1 + self.prior.len());
        candidates.push(ClaimPrior::from_record(previous));
        candidates.extend(previous.prior.iter().cloned());
        candidates.extend(self.prior.iter().cloned());
        let mut kept = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if self.tun == candidate.tun
                && self.ifindex == candidate.ifindex
                && self.outer == candidate.outer
                && self.ipv6 == candidate.ipv6
            {
                continue;
            }
            if kept.contains(&candidate) {
                continue;
            }
            kept.push(candidate);
        }
        if kept.len() > MAX_CLAIM_PRIORS {
            if !absence_proven {
                return Err(invalid_claim(
                    "would keep too many predecessor records; the claim was left in place",
                ));
            }
            kept.truncate(MAX_CLAIM_PRIORS);
        }
        self.prior = kept;
        Ok(())
    }

    /// Return every tunnel name and index that the claim can still describe.
    fn tunnels(&self) -> Vec<(&str, u32)> {
        let mut tunnels = vec![(self.tun.as_str(), self.ifindex)];
        for prior in &self.prior {
            if !tunnels
                .iter()
                .any(|(name, index)| *name == prior.tun && *index == prior.ifindex)
            {
                tunnels.push((prior.tun.as_str(), prior.ifindex));
            }
        }
        tunnels
    }

    /// Encode the record as one small text file. The format is strict and
    /// versioned so a damaged file can only make the recovery inconclusive.
    fn encode(&self) -> String {
        let mut text = format!(
            "{CLAIM_HEADER}\nboot {}\nnetns {} {}\npid {}\ntun {} {}\nouter {}\nipv6 {}\n",
            self.identity.boot_id,
            self.identity.netns_dev,
            self.identity.netns_ino,
            self.pid,
            self.tun,
            self.ifindex,
            self.outer,
            policy_name(self.ipv6)
        );
        for prior in &self.prior {
            text.push_str(&format!(
                "prior {} {} {} {}\n",
                prior.tun,
                prior.ifindex,
                prior.outer,
                policy_name(prior.ipv6)
            ));
        }
        text
    }

    /// Parse a claim. An unknown line, a duplicate value, or a value outside
    /// the accepted range is an error. The caller then leaves every object in
    /// place.
    fn parse(text: &str) -> io::Result<Self> {
        if text.len() > MAX_CLAIM_BYTES {
            return Err(invalid_claim("is too large"));
        }
        let mut lines = text.lines();
        let header = lines.next().ok_or_else(|| invalid_claim("is empty"))?;
        if header != CLAIM_HEADER && header != CLAIM_HEADER_V2 {
            return Err(invalid_claim("has no current version header"));
        }
        let mut boot = None;
        let mut netns = None;
        let mut pid = None;
        let mut tun = None;
        let mut outer = None;
        let mut ipv6 = None;
        let mut prior = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split(' ');
            let key = parts.next().unwrap_or_default();
            let rest: Vec<&str> = parts.collect();
            match key {
                "boot" => {
                    if rest.len() != 1 {
                        return Err(invalid_claim("has a malformed boot line"));
                    }
                    if boot.replace(rest[0].to_owned()).is_some() {
                        return Err(invalid_claim("has two boot lines"));
                    }
                }
                "netns" => {
                    if rest.len() != 2 {
                        return Err(invalid_claim("has a malformed network namespace line"));
                    }
                    let dev = rest[0]
                        .parse::<u64>()
                        .map_err(|_| invalid_claim("has a malformed network namespace line"))?;
                    let ino = rest[1]
                        .parse::<u64>()
                        .map_err(|_| invalid_claim("has a malformed network namespace line"))?;
                    if netns.replace((dev, ino)).is_some() {
                        return Err(invalid_claim("has two network namespace lines"));
                    }
                }
                "pid" => {
                    if rest.len() != 1 {
                        return Err(invalid_claim("has a malformed pid line"));
                    }
                    let value = rest[0]
                        .parse::<u32>()
                        .map_err(|_| invalid_claim("has a malformed pid line"))?;
                    if pid.replace(value).is_some() {
                        return Err(invalid_claim("has two pid lines"));
                    }
                }
                "tun" => {
                    if rest.len() != 2 || !valid_ifname(rest[0]) {
                        return Err(invalid_claim("has a malformed tunnel line"));
                    }
                    let index = rest[1]
                        .parse::<u32>()
                        .map_err(|_| invalid_claim("has a malformed tunnel line"))?;
                    if index == 0 {
                        return Err(invalid_claim("has a zero tunnel index"));
                    }
                    if tun.replace((rest[0].to_owned(), index)).is_some() {
                        return Err(invalid_claim("has two tunnel lines"));
                    }
                }
                "outer" => {
                    if rest.len() != 1 || !valid_ifname(rest[0]) {
                        return Err(invalid_claim("has a malformed outer line"));
                    }
                    if outer.replace(rest[0].to_owned()).is_some() {
                        return Err(invalid_claim("has two outer lines"));
                    }
                }
                "ipv6" => {
                    let policy = parse_policy(&rest)
                        .ok_or_else(|| invalid_claim("has a malformed IPv6 line"))?;
                    if ipv6.replace(policy).is_some() {
                        return Err(invalid_claim("has two IPv6 lines"));
                    }
                }
                "prior" => {
                    if rest.len() != 4
                        || !valid_ifname(rest[0])
                        || !valid_ifname(rest[2])
                        || rest[0] == rest[2]
                    {
                        return Err(invalid_claim("has a malformed predecessor line"));
                    }
                    let index = rest[1]
                        .parse::<u32>()
                        .map_err(|_| invalid_claim("has a malformed predecessor line"))?;
                    if index == 0 {
                        return Err(invalid_claim("has a zero predecessor index"));
                    }
                    let policy = parse_policy(&rest[3..])
                        .ok_or_else(|| invalid_claim("has a malformed predecessor line"))?;
                    let record = ClaimPrior {
                        tun: rest[0].to_owned(),
                        ifindex: index,
                        outer: rest[2].to_owned(),
                        ipv6: policy,
                    };
                    if prior.contains(&record) {
                        return Err(invalid_claim("has two identical predecessor lines"));
                    }
                    if prior.len() >= MAX_CLAIM_PRIORS {
                        return Err(invalid_claim("has too many predecessor lines"));
                    }
                    prior.push(record);
                }
                _ => return Err(invalid_claim("has an unknown line")),
            }
        }
        let boot = boot.ok_or_else(|| invalid_claim("has no boot line"))?;
        let (netns_dev, netns_ino) =
            netns.ok_or_else(|| invalid_claim("has no network namespace line"))?;
        let identity = ClaimIdentity::new(netns_dev, netns_ino, &boot)?;
        let (tun, ifindex) = tun.ok_or_else(|| invalid_claim("has no tunnel line"))?;
        let outer = outer.ok_or_else(|| invalid_claim("has no outer line"))?;
        let ipv6 = ipv6.ok_or_else(|| invalid_claim("has no IPv6 line"))?;
        if tun == outer {
            return Err(invalid_claim("names the tunnel as the outer interface"));
        }
        if prior.iter().any(|record| {
            record.tun == tun
                && record.ifindex == ifindex
                && record.outer == outer
                && record.ipv6 == ipv6
        }) {
            return Err(invalid_claim("names the current record as a predecessor"));
        }
        Ok(Self {
            identity,
            pid: pid.unwrap_or(0),
            tun,
            ifindex,
            outer,
            ipv6,
            prior,
        })
    }

    /// Rebuild the policy rules for this record and every predecessor.
    fn rules(&self) -> Vec<RuleKey> {
        let mut rules = rules_for(&self.outer);
        for prior in &self.prior {
            for rule in rules_for(&prior.outer) {
                if !rules.contains(&rule) {
                    rules.push(rule);
                }
            }
        }
        rules
    }

    /// Rebuild the routes for this record and every predecessor.
    fn routes(&self) -> Vec<RouteKey> {
        let mut routes = routes_for(self.ifindex, self.ipv6);
        for prior in &self.prior {
            for route in routes_for(prior.ifindex, prior.ipv6) {
                if !routes.contains(&route) {
                    routes.push(route);
                }
            }
        }
        routes
    }
}

/// Name the IPv6 policy in the claim file.
fn policy_name(policy: Ipv6Policy) -> &'static str {
    match policy {
        Ipv6Policy::Block => "block",
        Ipv6Policy::Forward => "forward",
        Ipv6Policy::Inherit => "inherit",
    }
}

/// Parse one IPv6 policy value from a claim line.
fn parse_policy(parts: &[&str]) -> Option<Ipv6Policy> {
    match parts {
        ["block"] => Some(Ipv6Policy::Block),
        ["forward"] => Some(Ipv6Policy::Forward),
        _ => None,
    }
}

/// Rebuild the four policy rules for one outer interface.
fn rules_for(outer: &str) -> Vec<RuleKey> {
    vec![
        RuleKey::outer(libc::AF_INET as u8, outer),
        RuleKey::tunnel(libc::AF_INET as u8),
        RuleKey::outer(libc::AF_INET6 as u8, outer),
        RuleKey::tunnel(libc::AF_INET6 as u8),
    ]
}

/// Rebuild the routes for one tunnel index and IPv6 policy.
fn routes_for(ifindex: u32, ipv6: Ipv6Policy) -> Vec<RouteKey> {
    let mut routes = vec![
        RouteKey::ipv4(IPV4_FIRST_HALF, ifindex),
        RouteKey::ipv4(IPV4_SECOND_HALF, ifindex),
    ];
    match ipv6 {
        Ipv6Policy::Forward => routes.push(RouteKey::ipv6(IPV6_GLOBAL_UNICAST, ifindex)),
        Ipv6Policy::Block => routes.push(RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST)),
        Ipv6Policy::Inherit => {}
    }
    routes
}

fn invalid_claim(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the route claim {reason}"),
    )
}

fn inconclusive_claim(reason: String) -> io::Error {
    io::Error::other(format!(
        "the stale route claim is not recoverable: {reason}; the claim is kept for the next start"
    ))
}

/// Name the claim path in a file error. The path holds no secret.
fn claim_error(path: &Path, action: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "cannot {action} the route claim {}: {error}",
            path.display()
        ),
    )
}

/// The number of times that [`RouteClaim::acquire`] retries when the claim
/// path changes between the open and the lock. A replacement is a normal race
/// with a stop, not a reason to loop forever.
const CLAIM_ACQUIRE_ATTEMPTS: u32 = 4;

/// An exclusive handle on the route claim file.
///
/// The handle holds an `flock` for as long as it lives. A live process therefore
/// keeps a later start from adopting its objects. The kernel releases the lock
/// when the process exits, including on a fatal signal, so a free lock is the
/// liveness test for a crashed run.
///
/// A lock on an inode is not proof that the path still names that inode.
/// Another process can unlink the path between the open and the lock. Every
/// handle therefore proves that the locked descriptor and the path are the same
/// file before it reads, writes, or removes the claim.
#[derive(Debug)]
struct RouteClaim {
    path: PathBuf,
    file: File,
    identity: ClaimIdentity,
    stale: Option<ClaimRecord>,
    boot_stale: bool,
    written: bool,
    /// The file still holds a record that this handle recovered and has not
    /// safely replaced. The record stays on disk until this run writes and
    /// syncs its own record immediately before the first add, and the install
    /// completes. A release keeps the file in that state.
    recovered: bool,
    /// The record that a recovered claim named, kept until the replacement
    /// write succeeds. The replacement record absorbs it as a predecessor.
    recovered_record: Option<ClaimRecord>,
    /// The file could be left in an unknown state by a failed write. It must
    /// not be unlinked by a release, even when it reads as empty.
    preserve: bool,
    /// Test-only write failure injection. Production builds have no seam.
    #[cfg(test)]
    write_failure: Option<ClaimWriteFailure>,
}

/// A test-only claim write failure.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimWriteFailure {
    /// Write part of the new record, then fail.
    Partial,
    /// Fail the restore of the previous record as well.
    PartialRestore,
}

#[cfg(test)]
type ClaimOpenHook = RefCell<Option<Box<dyn Fn(&Path)>>>;

#[cfg(test)]
thread_local! {
    /// A test seam that runs after `acquire` opens the claim and before it
    /// takes the lock. A test uses it to replace the path at that exact point.
    static CLAIM_OPEN_HOOK: ClaimOpenHook = const { RefCell::new(None) };
}

/// Run the test seam that replaces the claim path between the open and the
/// lock. Production builds have no seam.
#[cfg(not(test))]
fn claim_open_hook(_path: &Path) {}

#[cfg(test)]
fn claim_open_hook(path: &Path) {
    let hook = CLAIM_OPEN_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

/// The bounded failure when the claim path keeps naming another file.
fn claim_retry_error(path: &Path) -> io::Error {
    io::Error::other(format!(
        "cannot lock the route claim {}: the file was replaced or is not a private single-link file",
        path.display()
    ))
}

impl RouteClaim {
    /// Open or create the claim and take its exclusive lock.
    ///
    /// The read of the stored record happens under the lock, and only after the
    /// locked descriptor is proven to be the file at the path. A held lock is a
    /// live owner, not a crash, and returns `WouldBlock`.
    ///
    /// A file at the path that is not a regular file is refused before any read.
    /// Without that check a FIFO would accept the open and then block the read.
    /// A claim written in another network namespace is left in place: this
    /// process cannot recover objects that belong to another namespace. A claim
    /// written before the current boot is discarded, because no kernel object
    /// survives a reboot.
    fn acquire(path: &Path, strict: bool, identity: &ClaimIdentity) -> io::Result<Self> {
        prepare_claim_dir(path, strict)?;
        if strict {
            verify_claim_dir(path)?;
        }
        let mut attempts = 0;
        loop {
            attempts += 1;
            let file = match open_claim(path, true) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    match open_claim(path, false) {
                        Ok(file) => file,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            if attempts < CLAIM_ACQUIRE_ATTEMPTS {
                                continue;
                            }
                            return Err(claim_retry_error(path));
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            };
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the route claim {} is not a regular file", path.display()),
                ));
            }
            claim_open_hook(path);
            lock_claim(&file)?;
            if !claim_file_is_current(path, &file)? {
                // The path was replaced under the open, the file was
                // unlinked, or another link makes it not private. A lock on
                // this inode protects nothing, so close it and take the file
                // that the path names now.
                drop(file);
                if attempts >= CLAIM_ACQUIRE_ATTEMPTS {
                    return Err(claim_retry_error(path));
                }
                continue;
            }
            if strict {
                verify_claim_file(&file)?;
            }
            let mut stale = read_claim(&file)?;
            let mut boot_stale = false;
            if let Some(record) = stale.as_ref() {
                if record.identity.boot_id != identity.boot_id {
                    // The route and rule tables are rebuilt at boot, so a
                    // record from an earlier boot names no live object. Clear
                    // the unusable record without touching the kernel.
                    clear_file(&file)?;
                    stale = None;
                    boot_stale = true;
                } else if record.identity.netns_dev != identity.netns_dev
                    || record.identity.netns_ino != identity.netns_ino
                {
                    return Err(io::Error::other(format!(
                        "the route claim {} belongs to another network namespace; it was left in place",
                        path.display()
                    )));
                }
            }
            return Ok(Self {
                path: path.to_owned(),
                file,
                identity: identity.clone(),
                stale,
                boot_stale,
                written: false,
                recovered: false,
                recovered_record: None,
                preserve: false,
                #[cfg(test)]
                write_failure: None,
            });
        }
    }

    /// Return the record that a previous run left, when the file held one.
    fn stale(&self) -> Option<&ClaimRecord> {
        self.stale.as_ref()
    }

    /// Return true when this handle discarded a record from an earlier boot.
    fn discarded_previous_boot(&self) -> bool {
        self.boot_stale
    }

    /// Return the recovered record that this handle must keep covered.
    fn recovered_record(&self) -> Option<&ClaimRecord> {
        self.recovered_record.as_ref()
    }

    /// Record the objects before any add. The write goes to the same inode that
    /// holds the lock, which the acquire proved is the file at the path. The
    /// write is synced before the caller sends the first add.
    ///
    /// The write replaces a recovered record that is still on disk. The caller
    /// writes only after a complete read of the table and both reserved
    /// priorities showed no object, and it first builds a record that absorbs
    /// the recovered record as a predecessor. A failed write restores the
    /// previous bytes instead of leaving the file empty. If that restore also
    /// fails, the file is marked with invalid text and is kept for the next
    /// start, which then fails closed.
    fn write(&mut self, record: &ClaimRecord) -> io::Result<()> {
        let text = record.encode();
        let previous = match read_claim_bytes(&self.file) {
            Ok(previous) => previous,
            Err(error) => {
                // The file may still hold a record that this handle cannot
                // read. Do not let a later release unlink it.
                self.preserve = true;
                return Err(error);
            }
        };
        let written = match self.injected_write_failure() {
            #[cfg(test)]
            Some(ClaimWriteFailure::Partial | ClaimWriteFailure::PartialRestore) => {
                let half = text.len() / 2;
                write_partial_claim(&self.file, &text.as_bytes()[..half])
            }
            _ => write_claim_bytes(&self.file, text.as_bytes()),
        };
        if let Err(error) = written {
            let restored = match self.injected_write_failure() {
                #[cfg(test)]
                Some(ClaimWriteFailure::PartialRestore) => {
                    Err(io::Error::other("injected claim restore failure"))
                }
                _ => write_claim_bytes(&self.file, &previous),
            };
            if let Err(restore) = restored {
                // The old bytes are gone or unreadable. Leave invalid text so
                // the next start refuses instead of treating the claim as
                // empty and orphaning a surviving object.
                self.preserve = true;
                let _ = write_claim_bytes(&self.file, DAMAGED_CLAIM_TEXT.as_bytes());
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "cannot write the route claim: {error}; cannot restore the previous claim: {restore}; the claim was kept and marked damaged"
                    ),
                ));
            }
            return Err(error);
        }
        self.written = true;
        Ok(())
    }

    /// Test-only write failure injection. Production builds always write.
    #[cfg(test)]
    fn injected_write_failure(&self) -> Option<ClaimWriteFailure> {
        self.write_failure
    }

    #[cfg(not(test))]
    fn injected_write_failure(&self) -> Option<std::convert::Infallible> {
        None
    }

    /// Keep a recovered record on disk while the lock stays with this handle.
    ///
    /// The recovery agreed that the recorded objects are gone, but a kernel dump
    /// can omit a stable object without setting `NLM_F_DUMP_INTR`. The record
    /// therefore stays in the file until this run safely replaces it with a
    /// record that absorbs it, or until a release leaves it for the next start.
    fn keep_recovered(&mut self, record: ClaimRecord) {
        self.stale = None;
        self.boot_stale = false;
        self.recovered = true;
        self.recovered_record = Some(record);
    }

    /// Mark the replacement record as written and the recovery as replaced.
    ///
    /// The caller runs this only after every add succeeded. The file already
    /// holds the new record, which covers the recovered predecessors too. A
    /// later ordinary cleanup can then remove the claim after it proves every
    /// recorded object gone.
    fn finish_recovered(&mut self) {
        self.recovered = false;
        self.recovered_record = None;
        self.stale = None;
        self.boot_stale = false;
    }

    /// Remove the claim file and release the lock. An absent file is clean.
    ///
    /// The path is removed only when it still names the file that this handle
    /// locked. A replacement claim that another process made at the path is
    /// left in place and reported. A compliant peer cannot replace the path
    /// while this handle holds the lock, because it takes the same lock before
    /// it unlinks.
    fn unlink(self) -> io::Result<()> {
        unlink_claim_file(&self.path, &self.file)
    }

    /// Release a claim whose run wrote no live record or proved its record
    /// gone.
    ///
    /// A file that still holds a recovered record, or that a failed write left
    /// in an unknown state, is kept and only the lock is released. Every other
    /// file is removed under the rules of [`RouteClaim::unlink`].
    fn release(self) -> io::Result<()> {
        if self.recovered || self.preserve {
            eprintln!(
                "[route] kept the route claim {} for the next start",
                self.path.display()
            );
            return Ok(());
        }
        self.unlink()
    }
}

/// Claims whose owner could not finish cleanup.
///
/// This process keeps the file descriptor and its `flock` until exit. A later
/// start in another process therefore cannot adopt a record that this live
/// process might still own. The kernel releases every lock at process exit,
/// including after a fatal signal. The list is bounded by the service's
/// `cleanup_blocked` gate: one process refuses further starts after the first
/// failed cleanup.
fn retained_claims() -> &'static Mutex<Vec<RouteClaim>> {
    static CLAIMS: OnceLock<Mutex<Vec<RouteClaim>>> = OnceLock::new();
    CLAIMS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Release one retained claim lock in a test. Production processes never call
/// this; the kernel releases the locks at process exit.
#[cfg(test)]
fn release_retained_claim(path: &Path) {
    retained_claims()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .retain(|claim| claim.path != path);
}

/// Remove the claim path only while it still names the locked descriptor and
/// that descriptor still has exactly one link.
///
/// The caller must hold the claim lock. A replacement, a symlink, a second
/// link, or a different file at the path is refused and left in place. A second
/// hard link would let another path change the file that the lock covers, so a
/// handle that gained one after the open is not a private claim.
fn unlink_claim_file(path: &Path, file: &File) -> io::Result<()> {
    let held = file.metadata().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot inspect the route claim {}: {error}", path.display()),
        )
    })?;
    match std::fs::symlink_metadata(path) {
        Ok(at_path) => {
            if !at_path.is_file()
                || at_path.file_type().is_symlink()
                || held.nlink() != 1
                || at_path.nlink() != 1
                || at_path.dev() != held.dev()
                || at_path.ino() != held.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "the route claim {} is not the private single-link file that this process locked; it was left in place",
                        path.display()
                    ),
                ));
            }
            std::fs::remove_file(path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("cannot inspect the route claim {}: {error}", path.display()),
        )),
    }
}

/// Prove that the locked descriptor is still the file at the claim path.
///
/// The open and the lock are separate calls, and another process can unlink
/// the path between them. A lock on an unlinked inode protects nothing: a
/// second process can create a new claim file and lock that one. The caller
/// must compare the identity under the lock, require exactly one link, and
/// retry when either check fails. A second link would let another path change
/// the file that the lock covers, so it is not a private claim. A false result
/// is safe to act on. A read failure is not.
fn claim_file_is_current(path: &Path, file: &File) -> io::Result<bool> {
    let held = file.metadata()?;
    if !held.is_file() || held.nlink() != 1 {
        return Ok(false);
    }
    match std::fs::symlink_metadata(path) {
        Ok(at_path) => {
            if !at_path.is_file() || at_path.file_type().is_symlink() {
                return Ok(false);
            }
            Ok(at_path.dev() == held.dev() && at_path.ino() == held.ino())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// What a stale-claim recovery found and removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Policy rules removed from the rule list.
    pub removed_rules: usize,
    /// Routes removed from the tunnel table.
    pub removed_routes: usize,
    /// The pid that wrote the stale claim. Zero when the claim named none.
    pub stale_pid: u32,
}

impl RecoveryReport {
    /// Return true when the recovery removed a kernel object.
    pub fn removed_any(&self) -> bool {
        self.removed_rules > 0 || self.removed_routes > 0
    }
}

/// Create the claim directory.
///
/// The production directory must be private to the service account. A test path
/// skips the ownership check because its parent is a test-owned temporary
/// directory.
fn prepare_claim_dir(path: &Path, strict: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "claim path has no parent"))?;
    if !strict {
        return std::fs::create_dir_all(parent);
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(parent)
}

/// Prove that the claim directory belongs to the service account and no other
/// account can write it.
fn verify_claim_dir(path: &Path) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "claim path has no parent"))?;
    let meta = std::fs::symlink_metadata(dir)?;
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the route claim directory is not a directory",
        ));
    }
    if meta.uid() != euid || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the route claim directory is not private to the service account",
        ));
    }
    Ok(())
}

/// Prove that the claim file is a private regular file of the service account.
fn verify_claim_file(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    let euid = unsafe { libc::geteuid() };
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the route claim is not a regular file",
        ));
    }
    if meta.uid() != euid || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the route claim file is not private to the service account",
        ));
    }
    Ok(())
}

/// Open the claim with no symlink following, no blocking read, and no
/// descriptor leak into a child process.
///
/// `O_NONBLOCK` matters for a path that is a FIFO or another special file. The
/// caller also requires a regular file, so a FIFO is refused instead of read.
fn open_claim(path: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    if create {
        options.create_new(true);
    }
    options.open(path)
}

/// Truncate and sync a claim file that this handle already holds under the
/// lock. The truncate is used for a boot-stale record, whose objects cannot
/// survive the reboot.
fn clear_file(file: &File) -> io::Result<()> {
    file.set_len(0)?;
    file.sync_all()
}

/// Write and sync one complete claim image. The truncate happens after the
/// write, so an interrupted replacement leaves stale trailing text that fails
/// the strict parser instead of an empty claim. An empty claim would tell the
/// next start that no object survived.
fn write_claim_bytes(file: &File, bytes: &[u8]) -> io::Result<()> {
    let mut handle = file;
    handle.seek(SeekFrom::Start(0))?;
    handle.write_all(bytes)?;
    handle.set_len(bytes.len() as u64)?;
    handle.sync_all()
}

/// Write part of a record and fail. Test builds only.
#[cfg(test)]
fn write_partial_claim(file: &File, bytes: &[u8]) -> io::Result<()> {
    let mut handle = file;
    handle.seek(SeekFrom::Start(0))?;
    handle.write_all(bytes)?;
    handle.sync_all()?;
    Err(io::Error::other("injected claim write failure"))
}

/// Take one nonblocking exclusive lock.
///
/// A held lock means that a live open file description holds it, not a crashed
/// run. That holder is usually a running tunnel. It can also be a read-only
/// status inspection or a damaged-claim clear, which take the same lock for a
/// moment. A start that meets a held lock refuses and does not retry, so a
/// refusal is not proof that a tunnel is running. A later start can succeed.
fn lock_claim(file: &File) -> io::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "another process holds the route claim lock; a tunnel may be running, or a status check held the lock for a moment",
        ));
    }
    Err(error)
}

/// Read the stored claim under the lock. An empty file is not a record.
fn read_claim(file: &File) -> io::Result<Option<ClaimRecord>> {
    let buffer = read_claim_bytes(file)?;
    if buffer.is_empty() {
        return Ok(None);
    }
    let text = String::from_utf8(buffer).map_err(|_| invalid_claim("is not text"))?;
    Ok(Some(ClaimRecord::parse(&text)?))
}

/// Read at most one more byte than a valid claim can hold.
fn read_claim_bytes(file: &File) -> io::Result<Vec<u8>> {
    let mut handle = file;
    handle.seek(SeekFrom::Start(0))?;
    let mut buffer = Vec::new();
    handle
        .take((MAX_CLAIM_BYTES + 1) as u64)
        .read_to_end(&mut buffer)?;
    if buffer.len() > MAX_CLAIM_BYTES {
        return Err(invalid_claim("is too large"));
    }
    Ok(buffer)
}

/// Open the claim path for a read-only inspection.
fn open_claim_readonly(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

/// The read-only state of the crash-recovery claim.
///
/// The value holds no address, token, or key. It reports whether a claim is
/// present, whether a live process holds it, whether the file and directory
/// are private to the service account, and whether the record matches the
/// current boot and network namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteClaimInspection {
    /// A file or another object exists at the claim path.
    pub present: bool,
    /// A live process holds the claim lock.
    pub locked: bool,
    /// The file is private to the service account and has one link.
    pub private: bool,
    /// The file is empty or parses under the current format version.
    pub usable: bool,
    /// The record names the current kernel boot. None when unreadable.
    pub same_boot: Option<bool>,
    /// The record names the current network namespace. None when unreadable.
    pub same_namespace: Option<bool>,
    /// The writer pid from the record, when it parses.
    pub stale_pid: Option<u32>,
    /// Why the claim cannot be adopted or cleared, when a reason is known.
    pub problem: Option<String>,
}

/// Report the claim state without changing it.
///
/// This is the read-only diagnostic entry point. It takes the lock only to
/// learn whether a live process holds it. It never deletes a route, a rule, or
/// the claim. A damaged file, a foreign boot, and a foreign network namespace
/// are reported rather than repaired.
pub fn inspect_route_claim() -> RouteClaimInspection {
    let identity = ClaimIdentity::current();
    let mut result = inspect_claim_file(Path::new(ROUTE_CLAIM_PATH), identity.as_ref().ok());
    if let Err(error) = identity {
        if result.problem.is_none() {
            result.problem = Some(error.to_string());
        }
    }
    result
}

/// Remove a claim file that cannot describe a live object.
///
/// This is the safe operator path for a damaged claim. It removes only the
/// claim file. It never deletes a route or a rule.
///
/// The call removes the file only when all of these hold:
///
/// - No live process holds the claim lock.
/// - The path is a regular single-link file, and the locked descriptor is still
///   the file at the claim path.
/// - The content is empty, or it is a valid record from an earlier boot.
///   Objects from an earlier boot cannot survive, so that record names nothing.
///
/// A valid record from the current boot and network namespace can describe a
/// live object, so it is refused even when its owner or mode is wrong. The next
/// start must recover it. A valid record from another network namespace is left
/// in place. A non-empty file that does not parse may still name live objects,
/// so it is refused for manual inspection instead of being removed. A return
/// value of true means that the file was removed.
pub fn clear_corrupt_route_claim() -> io::Result<bool> {
    let identity = ClaimIdentity::current()?;
    clear_corrupt_claim_file(Path::new(ROUTE_CLAIM_PATH), &identity)
}

fn inspect_claim_file(path: &Path, identity: Option<&ClaimIdentity>) -> RouteClaimInspection {
    let mut result = RouteClaimInspection::default();
    let at_path = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return result,
        Err(error) => {
            result.problem = Some(format!("cannot inspect {}: {error}", path.display()));
            return result;
        }
    };
    result.present = true;
    if !at_path.is_file() || at_path.file_type().is_symlink() {
        result.problem = Some(format!(
            "the route claim {} is not a regular file",
            path.display()
        ));
        return result;
    }
    let file = match open_claim_readonly(path) {
        Ok(file) => file,
        Err(error) => {
            result.problem = Some(format!("cannot open {}: {error}", path.display()));
            return result;
        }
    };
    let held = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            result.problem = Some(format!("cannot inspect {}: {error}", path.display()));
            return result;
        }
    };
    let euid = unsafe { libc::geteuid() };
    result.private = held.nlink() == 1 && held.uid() == euid && held.mode() & 0o077 == 0;
    if !result.private {
        result.problem = Some(format!(
            "the route claim {} is not a private single-link file of the service account",
            path.display()
        ));
        return result;
    }
    match lock_claim(&file) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            result.locked = true;
            result.problem = Some("a process holds the route claim lock".into());
            return result;
        }
        Err(error) => {
            result.problem = Some(format!("cannot lock {}: {error}", path.display()));
            return result;
        }
    }
    match claim_file_is_current(path, &file) {
        Ok(true) => {}
        Ok(false) => {
            result.problem = Some(format!(
                "the route claim {} is not the file at the path",
                path.display()
            ));
            return result;
        }
        Err(error) => {
            result.problem = Some(format!("cannot inspect {}: {error}", path.display()));
            return result;
        }
    }
    match read_claim(&file) {
        Ok(None) => result.usable = true,
        Ok(Some(record)) => {
            result.usable = true;
            result.stale_pid = Some(record.pid);
            if let Some(identity) = identity {
                result.same_boot = Some(record.identity.boot_id == identity.boot_id);
                result.same_namespace = Some(
                    record.identity.netns_dev == identity.netns_dev
                        && record.identity.netns_ino == identity.netns_ino,
                );
                if result.same_boot == Some(false) {
                    result.problem =
                        Some("the route claim was written before the current boot".into());
                } else if result.same_namespace == Some(false) {
                    result.problem =
                        Some("the route claim belongs to another network namespace".into());
                }
            }
        }
        Err(error) => {
            result.problem = Some(error.to_string());
        }
    }
    result
}

fn clear_corrupt_claim_file(path: &Path, identity: &ClaimIdentity) -> io::Result<bool> {
    let at_path = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotConnected
            ) =>
        {
            return Ok(false)
        }
        Err(error) => return Err(claim_error(path, "inspect", error)),
    };
    if !at_path.is_file() || at_path.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the route claim {} is not a regular file", path.display()),
        ));
    }
    let file = open_claim_readonly(path).map_err(|error| claim_error(path, "open", error))?;
    let held = file
        .metadata()
        .map_err(|error| claim_error(path, "inspect", error))?;
    // A hard link makes the path and the locked descriptor disagree about which
    // file the caller may remove. Keep the single-link rule. The content rule
    // below decides whether the record can name a live object, whatever the
    // owner or mode says.
    if held.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the route claim {} is not a single-link file",
                path.display()
            ),
        ));
    }
    match lock_claim(&file) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Err(io::Error::other(format!(
                "the route claim {} is held by a live process; it was left in place",
                path.display()
            )));
        }
        Err(error) => return Err(claim_error(path, "lock", error)),
    }
    if !claim_file_is_current(path, &file).map_err(|error| claim_error(path, "inspect", error))? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "the route claim {} is not the file at the path; it was left in place",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    let mut handle = &file;
    handle
        .seek(SeekFrom::Start(0))
        .map_err(|error| claim_error(path, "read", error))?;
    handle
        .take((MAX_CLAIM_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| claim_error(path, "read", error))?;
    if bytes.is_empty() {
        // An empty claim names no object and no record.
        unlink_claim_file(path, &file)?;
        return Ok(true);
    }
    if bytes.len() > MAX_CLAIM_BYTES {
        return Err(io::Error::other(format!(
            "the route claim {} is too large to read; it may describe live objects and was left in place",
            path.display()
        )));
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return Err(io::Error::other(format!(
            "the route claim {} is not text; it may describe live objects and was left in place",
            path.display()
        )));
    };
    let record = match ClaimRecord::parse(&text) {
        Ok(record) => record,
        Err(error) => {
            // A damaged record can still name live objects. Removing it would
            // orphan them, because a later start would find no claim and no
            // selectors to recover. The operator must inspect the routing
            // table before removing a non-empty damaged file by hand.
            return Err(io::Error::other(format!(
                "the route claim {} cannot be parsed ({error}); it may describe live objects and was left in place",
                path.display()
            )));
        }
    };
    if record.identity.boot_id != identity.boot_id {
        // The route and rule tables are rebuilt at boot, so no object from an
        // earlier boot can survive, whatever namespace wrote the record.
        unlink_claim_file(path, &file)?;
        return Ok(true);
    }
    if record.identity.netns_dev != identity.netns_dev
        || record.identity.netns_ino != identity.netns_ino
    {
        return Err(io::Error::other(format!(
            "the route claim {} belongs to another network namespace; it was left in place",
            path.display()
        )));
    }
    Err(io::Error::other(format!(
        "the route claim {} can describe live objects; start the tunnel to recover them",
        path.display()
    )))
}

/// Return a claim path that no other test and no production run uses.
#[cfg(test)]
fn unique_test_claim_path() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hotspotshade-route-claim-test-{}-{sequence}",
        std::process::id()
    ))
}

/// A fixed boot id for tests. It is a fixed public value, not a secret.
#[cfg(test)]
const TEST_BOOT_ID: &str = "11111111-2222-3333-4444-555555555555";

/// A second, older boot id for the previous-boot recovery test.
#[cfg(test)]
const OLD_BOOT_ID: &str = "99999999-8888-7777-6666-555555555555";

/// A fixed claim identity for tests. A test never reads the host namespace or
/// boot id, so the result is deterministic and needs no procfs.
#[cfg(test)]
fn test_claim_identity() -> ClaimIdentity {
    ClaimIdentity::new(4, 4_026_531_840, TEST_BOOT_ID).unwrap()
}

/// The answer from one lookup of a claimed tunnel device.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ClaimedDevice {
    /// The lookup proved that no device uses the claimed name or index.
    Absent,
    /// A device uses the claimed name at this index.
    Present(u32),
    /// The claimed name is free, but another device now owns the recorded
    /// index. A route that names the old index would act on that device.
    IndexReused { ifindex: u32, name: String },
}

/// Look up one claimed tunnel device by name and by recorded index.
///
/// Only `ENODEV` and `ENXIO` prove that a name or index is absent. Any other
/// error is inconclusive: a lookup that failed for another reason cannot show
/// that the name is free, so the recovery must not act on it. A free name is
/// not enough. Linux reuses interface indexes, and a recorded route names the
/// index, not the name. If another device now owns that index, the recovery
/// cannot tell whether a recorded route would name the crashed tunnel or the
/// new device, so it refuses.
fn probe_claimed_device(
    name_probe: fn(&str) -> io::Result<u32>,
    index_probe: fn(u32) -> io::Result<String>,
    name: &str,
    ifindex: u32,
) -> io::Result<ClaimedDevice> {
    match name_probe(name) {
        Ok(index) => return Ok(ClaimedDevice::Present(index)),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENODEV) | Some(libc::ENXIO)) => {}
        Err(error) => return Err(error),
    }
    match index_probe(ifindex) {
        Ok(name) => Ok(ClaimedDevice::IndexReused { ifindex, name }),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENODEV) | Some(libc::ENXIO)) => {
            Ok(ClaimedDevice::Absent)
        }
        Err(error) => Err(error),
    }
}

/// Name the tunnel and index in a failed claim device lookup.
fn claimed_device_error(name: &str, index: u32, error: &io::Error) -> io::Error {
    inconclusive_claim(format!(
        "cannot look up the claimed tunnel device {name} at index {index}: {error}"
    ))
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
        netlink.add_route(key).map_err(add_error_to_io)
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
        netlink.add_rule(rule).map_err(add_error_to_io)
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
    /// The socket accepts strict GET validation and the `RTA_TABLE` dump
    /// filter. `setsockopt` proves only that the option exists, so a table
    /// reader also requires `NLM_F_DUMP_FILTERED` in the reply before it relies
    /// on the filter.
    strict_check: bool,
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
        // Linux 4.20 and later accept this option. An older kernel returns
        // ENOPROTOOPT or EINVAL. A missing option is not an error: the table
        // reader then uses a full family dump.
        let enabled: libc::c_int = 1;
        let strict_check = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_NETLINK,
                NETLINK_GET_STRICT_CHK,
                (&enabled as *const libc::c_int).cast(),
                mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } == 0;
        Ok(Self { fd, strict_check })
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
                ReplyError::Inconsistent => RouteVerifyError::Unavailable {
                    operation: "netlink dump",
                    errno: libc::EAGAIN,
                },
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
                    ReplyError::Inconsistent => RouteVerifyError::Unavailable {
                        operation: "netlink dump",
                        errno: libc::EAGAIN,
                    },
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
                    ReplyError::Inconsistent => RouteVerifyError::Unavailable {
                        operation: "netlink dump",
                        errno: libc::EAGAIN,
                    },
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
            Err(ReplyError::Inconsistent) => {
                return Err(RouteVerifyError::Unavailable {
                    operation: "netlink dump",
                    errno: libc::EAGAIN,
                })
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
    ///
    /// A dump that reports `NLM_F_DUMP_INTR` is retried a bounded number of
    /// times. When every attempt is inconsistent, this returns
    /// [`ReplyError::Inconsistent`]. The caller must not treat that result as
    /// an empty list: an object that the partial list omitted may still exist.
    /// An accepted absent-table shape from a strict table dump is reported as
    /// [`ReplyError::Malformed`] here, because this method names no table.
    fn dump(&self, message: &[u8], sequence: u32, expected: u16) -> Result<DumpReply, ReplyError> {
        match self.dump_attempt(message, sequence, expected)? {
            DumpAttempt::Complete(reply) => Ok(reply),
            DumpAttempt::EmptyTable => Err(ReplyError::Malformed(
                "the kernel reported an absent table for a dump that named no table",
            )),
            DumpAttempt::Failed(errno) => Err(ReplyError::Kernel(errno)),
            DumpAttempt::Inconsistent => Err(ReplyError::Inconsistent),
        }
    }

    fn dump_attempt(
        &self,
        message: &[u8],
        sequence: u32,
        expected: u16,
    ) -> Result<DumpAttempt, ReplyError> {
        retry_dump(|| {
            self.send_message(message)?;
            let deadline = Instant::now() + NETLINK_TIMEOUT;
            let mut state = DumpState::default();
            loop {
                let (buffer, size) = self.receive(deadline)?;
                state.consume(&buffer[..size], sequence, expected)?;
                if state.done {
                    return Ok(state.finish());
                }
            }
        })
    }

    /// Read the route messages of one table.
    ///
    /// A kernel with strict table filtering returns only the named table and
    /// sets `NLM_F_DUMP_FILTERED` on the reply. A kernel without that support,
    /// or one that accepted the option but did not mark the reply, falls back
    /// to a full family dump. The caller filters the reported table in either
    /// case, so a missing filter never widens the ownership proof.
    ///
    /// A strict table read treats the table as absent only when the kernel ends
    /// the dump with `NLMSG_DONE` carrying `-ENOENT`, the attempt held no data
    /// message, and no message carried `NLM_F_DUMP_INTR`. An `NLMSG_ERROR` with
    /// `ENOENT`, an `ENOENT` with an earlier data message, or a flagged reply is
    /// a failed read, not an empty table. A strict-check kernel that rejects the
    /// table attribute falls back to a full family dump. Every other error is
    /// returned, so a missing table never hides a foreign object.
    fn table_route_replies(&self, family: u8, table: u32) -> Result<Vec<Vec<u8>>, ReplyError> {
        if self.strict_check {
            let sequence = next_sequence();
            let message = encode_route_table_dump(sequence, family, table);
            match self.dump_attempt(&message, sequence, RTM_NEWROUTE) {
                Ok(DumpAttempt::Complete(reply)) if reply.filtered => return Ok(reply.messages),
                Ok(DumpAttempt::Complete(_)) => {}
                Ok(DumpAttempt::EmptyTable) => return Ok(Vec::new()),
                Ok(DumpAttempt::Inconsistent) => return Err(ReplyError::Inconsistent),
                Ok(DumpAttempt::Failed(errno)) => match errno {
                    // An early strict-check kernel may reject the table
                    // attribute. Anything else, including an `ENOENT` that did
                    // not arrive in the accepted empty-table shape, stays a
                    // failed read.
                    libc::EINVAL | libc::EOPNOTSUPP => {}
                    _ => return Err(ReplyError::Kernel(errno)),
                },
                // A negative `NLMSG_DONE` status is reported as `Failed` above.
                // An `NLMSG_ERROR` still returns a kernel error from `consume`.
                Err(ReplyError::Kernel(errno))
                    if errno == libc::EINVAL || errno == libc::EOPNOTSUPP => {}
                Err(error) => return Err(error),
            }
        }
        let sequence = next_sequence();
        let message = encode_route_dump(sequence, family);
        self.dump(&message, sequence, RTM_NEWROUTE)
            .map(|reply| reply.messages)
    }

    /// Read the routes of one family and table. The request sends no packet.
    ///
    /// The method keeps only the replies whose reported table matches. A full
    /// family dump is used when the kernel has no strict table filter. The
    /// `MAX_DUMP_MESSAGES` bound applies to the whole family in that case, and
    /// an over-limit dump is a failed read, never a partial list.
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
        let replies = self
            .table_route_replies(family, table)
            .map_err(write_error)?;
        select_route_table(replies, family, table)
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
            .map_err(write_error)?
            .messages;
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
///
/// The manager also owns the route claim at [`ROUTE_CLAIM_PATH`] or at a test
/// path. It writes the claim before the first add and removes it after the last
/// proven delete. A later start adopts the claim only when no live process holds
/// its lock and every recorded object matches. See [`RouteManager::recover_stale`].
pub struct RouteManager {
    ifname: String,
    ipv6: Ipv6Policy,
    table: u32,
    routes: Vec<RouteKey>,
    rules: Vec<RuleKey>,
    control: Arc<dyn RouteControl>,
    identity: Arc<()>,
    claim_path: PathBuf,
    claim_strict: bool,
    claim_identity: Option<ClaimIdentity>,
    claim: Option<RouteClaim>,
    cleanup_failed: bool,
    recovery: Option<RecoveryReport>,
    probe_device_index: fn(&str) -> io::Result<u32>,
    probe_device_name: fn(u32) -> io::Result<String>,
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
            claim_path: PathBuf::from(ROUTE_CLAIM_PATH),
            claim_strict: true,
            claim_identity: None,
            claim: None,
            cleanup_failed: false,
            recovery: None,
            probe_device_index: interface_index,
            probe_device_name: interface_name,
        })
    }

    /// Create a manager with a test control layer.
    ///
    /// The claim path is a unique temporary path, so a test never reads or
    /// writes the production claim. The device probe is inert, so a test never
    /// resolves a host interface name.
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
            claim_path: unique_test_claim_path(),
            claim_strict: false,
            claim_identity: Some(test_claim_identity()),
            claim: None,
            cleanup_failed: false,
            recovery: None,
            probe_device_index: |_| Err(io::Error::from_raw_os_error(libc::ENODEV)),
            probe_device_name: |_| Err(io::Error::from_raw_os_error(libc::ENXIO)),
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

    /// Return the claim identity for this process.
    ///
    /// Production resolves the current network namespace and boot id. A test
    /// uses a fixed value.
    fn claim_identity(&self) -> io::Result<ClaimIdentity> {
        match &self.claim_identity {
            Some(identity) => Ok(identity.clone()),
            None => ClaimIdentity::current(),
        }
    }

    /// Refuse to read or replace a claim after the kernel identity changed.
    ///
    /// The claim names one network namespace and one boot. A process that
    /// changed its namespace after it took the claim can no longer prove which
    /// objects the record describes, so it must keep the record for a process
    /// in the recorded namespace. A boot change cannot happen while this
    /// process lives, but the same check makes the rule explicit.
    fn require_claim_identity(&self) -> io::Result<()> {
        let Some(claim) = self.claim.as_ref() else {
            return Ok(());
        };
        let current = self.claim_identity()?;
        if current != claim.identity {
            return Err(io::Error::other(
                "the network namespace or boot identity changed after the route claim was taken; the claim was kept",
            ));
        }
        Ok(())
    }

    /// Take the route claim and prove that the shared objects are free.
    ///
    /// The caller runs this before it opens the TUN device, adds a link
    /// address, or uses a source device token. A start that loses the claim,
    /// because another process holds it or because the claim is inconclusive,
    /// therefore changes no device, no address, and no route. The method first
    /// takes the claim and recovers a stale record under the rules in
    /// [`RouteManager::recover_stale`], with the same locked file. It then reads
    /// the tunnel table and both reserved rule priorities. A foreign object, a
    /// used priority, or a failed read refuses the start. The read changes
    /// nothing. The method is idempotent for one manager: a second call takes
    /// no new claim and only reads again.
    ///
    /// The claim file after a refusal depends on what it held:
    ///
    /// - An empty claim holds no record and names no object. The manager keeps
    ///   it while it lives. When the caller drops the manager, the ordinary
    ///   cleanup finds no record and removes the empty file under the lock.
    ///   The service log carries the refusal reason; the file does not.
    /// - A recovered record stays in the file, whether this read succeeds or
    ///   refuses the start. The recovery agreed that the recorded objects are
    ///   gone, but a dump can omit a stable object, and this read is only one
    ///   snapshot. The manager keeps the record on disk and releases only the
    ///   lock, so the next start adopts it again under the exact-match rules.
    ///
    /// The method never clears a recovered record. [`RouteManager::install_verified`]
    /// proves the same conditions again immediately before the first add,
    /// because another process can change the table between these two calls.
    /// That proof is also a snapshot. The install then writes and syncs a
    /// replacement record that absorbs the recovered record as a predecessor.
    /// A dump can omit an object on every read, so the predecessor stays
    /// covered until a cleanup proves every key gone.
    pub fn claim_start(&mut self) -> io::Result<()> {
        self.claim_start_with_check(&|| Ok(()))
    }

    /// Recheck the retained physical outer identity before each stale-object
    /// deletion during start. Ordinary cleanup remains independent of the link.
    pub fn claim_start_with_outer(&mut self, outer: &PhysicalOuterIdentity) -> io::Result<()> {
        self.claim_start_with_check(&|| outer.recheck())
    }

    fn claim_start_with_check(&mut self, recheck: &dyn Fn() -> io::Result<()>) -> io::Result<()> {
        self.ensure_claim_with_check(recheck)?;
        self.require_claim_identity()?;
        let control = Arc::clone(&self.control);
        self.require_empty_table(control.as_ref())?;
        self.require_free_priorities(control.as_ref())?;
        // Do not clear a recovered record here. This read is one snapshot, and
        // a kernel dump can omit a stable rule or route. Only install_verified
        // replaces the record, after another complete read, with durable
        // write-ahead text that absorbs the recovered record as a predecessor.
        Ok(())
    }

    /// Return the held claim, taking it and recovering a stale record first when
    /// the caller did not run [`RouteManager::claim_start`].
    ///
    /// A recovered record stays in the file until a later read agrees. See
    /// [`RouteManager::claim_start`].
    fn ensure_claim(&mut self) -> io::Result<()> {
        self.ensure_claim_with_check(&|| Ok(()))
    }

    fn ensure_claim_with_check(&mut self, recheck: &dyn Fn() -> io::Result<()>) -> io::Result<()> {
        if self.claim.is_some() {
            return Ok(());
        }
        if self.cleanup_failed {
            return Err(io::Error::other(
                "route cleanup failed; inspect routes before restarting",
            ));
        }
        if !self.routes.is_empty() || !self.rules.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "routes already installed or cleanup incomplete",
            ));
        }
        let identity = self.claim_identity()?;
        let mut claim = RouteClaim::acquire(&self.claim_path, self.claim_strict, &identity)
            .map_err(|error| claim_error(&self.claim_path, "open", error))?;
        if claim.discarded_previous_boot() {
            eprintln!(
                "[route] discarded the route claim {} because it was written before the current boot",
                self.claim_path.display()
            );
        }
        if let Some(record) = claim.stale().cloned() {
            let report = self.recover_claim_with_check(&record, recheck)?;
            claim.keep_recovered(record);
            self.record_recovery(report);
        }
        self.claim = Some(claim);
        Ok(())
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
    /// The method takes the route claim before it changes anything, unless the
    /// caller already ran [`RouteManager::claim_start`]. A claim that a previous
    /// run left behind is first adopted under the rules in
    /// [`RouteManager::recover_stale`]. The method then reads the dedicated
    /// table and the rule list. An object in that table, or a rule at either
    /// reserved priority, is an inconclusive ownership state, and the method
    /// changes nothing. Every add uses `NLM_F_EXCL`. A failed add removes the
    /// objects that are already recorded.
    ///
    /// A recovered record is never cleared before this read. After the read the
    /// method writes and syncs a replacement record that absorbs the recovered
    /// record as a predecessor, then sends the first add. The recovered record
    /// is present only after a completed two-absence recovery, so a union above
    /// the predecessor cap may drop its oldest record. Without that proof the
    /// method refuses and keeps the old claim. A failed write restores the
    /// previous record, or marks the file damaged, and keeps it. A
    /// failed add rolls back the recorded objects and keeps the file, so no
    /// path releases a record that a dump may have hidden.
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
        self.ensure_claim()?;
        self.require_claim_identity()?;
        let identity = self
            .claim
            .as_ref()
            .map(|claim| claim.identity.clone())
            .ok_or_else(|| io::Error::other("the route claim is not held"))?;
        let control = Arc::clone(&self.control);
        let previous = self
            .claim
            .as_ref()
            .and_then(|claim| claim.recovered_record().cloned());
        let mut record = ClaimRecord::new(
            proof.ifname(),
            proof.ifindex(),
            outer_ifname,
            self.ipv6,
            identity,
        );
        if let Some(previous) = &previous {
            // A recovered record is present only after `recover_claim` read
            // every recorded selector and saw no live object on two complete
            // rounds. Only that proof permits the cap to drop an older
            // predecessor. A missing proof refuses and keeps the old claim.
            let absence_proven = self
                .claim
                .as_ref()
                .is_some_and(|claim| claim.recovered_record().is_some());
            record
                .absorb_recovered_predecessor(previous, absence_proven)
                .map_err(|error| claim_error(&self.claim_path, "replace", error))?;
        }
        let prepared = (|| -> io::Result<()> {
            self.require_empty_table(control.as_ref())?;
            self.require_free_priorities(control.as_ref())?;
            if let Some(claim) = self.claim.as_mut() {
                claim.write(&record)?;
            }
            if let Some(previous) = &previous {
                // The file now records both this run and the recovered run.
                // Adopt the predecessor keys into this run's cleanup record so
                // a hidden predecessor object is still read, confirmed, and
                // kept when the reads do not agree.
                self.adopt_recovered_objects(previous);
            }
            self.add_objects(control.as_ref(), outer_ifname, proof.ifindex())
        })();
        match prepared {
            Ok(()) => {
                if let Some(claim) = self.claim.as_mut() {
                    claim.finish_recovered();
                }
                Ok(())
            }
            Err(error) => {
                let written = self.claim.as_ref().is_some_and(|claim| claim.written);
                if written {
                    Err(self.rollback(error))
                } else {
                    // No record of this run reached the file. An empty claim is
                    // removed; a recovered record stays for the next start.
                    if let Some(claim) = self.claim.take() {
                        let path = claim.path.clone();
                        if let Err(cleanup) = claim.release() {
                            eprintln!(
                                "[route] cannot remove the unused route claim {}: {cleanup}",
                                path.display()
                            );
                        }
                    }
                    Err(error)
                }
            }
        }
    }

    /// Adopt the objects that a previous run recorded but did not remove.
    ///
    /// This method changes nothing unless every condition holds:
    ///
    /// - The claim file exists, is a private regular file of the service
    ///   account, and is not empty.
    /// - No live process holds its exclusive lock. The kernel drops the lock on
    ///   any process exit, including a fatal signal.
    /// - The locked descriptor is still the file at the claim path. A claim
    ///   that another process replaced or unlinked is not adopted.
    /// - The claim parses under the current format version.
    /// - The recorded network namespace and boot id match this process. A
    ///   claim from another namespace is left in place. A claim from an earlier
    ///   boot names no live object and is discarded.
    /// - The lookup of every claimed tunnel name succeeds, and every recorded
    ///   index is free. Only `ENODEV` and `ENXIO` prove absence. This call has
    ///   no new device, so a claimed device that still exists at any index is
    ///   inconclusive. So is a free name whose recorded index now belongs to a
    ///   different interface, because a recorded route names the index.
    /// - Every live route in the dedicated table, and every live rule at the two
    ///   reserved priorities, is an exact match for the claim. Each live object
    ///   must be selected by exactly one recorded delete request, and each
    ///   recorded request must select only its own object. Two live objects can
    ///   share a priority or a prefix when their request bytes differ. A read
    ///   failure, a foreign object, an ambiguous request, or an object that
    ///   names a surviving tunnel device makes the result inconclusive.
    ///
    /// The decision is all or nothing. An inconclusive result deletes no object
    /// and leaves the claim in place. A conclusive result deletes only a
    /// recorded object that a read shows as an exact match, then reads again.
    /// It repeats until a round deletes nothing and two consecutive complete
    /// reads agree that every recorded object is absent. That agreement is
    /// evidence, not proof: a dump can omit a stable object on every read. The
    /// recovered record therefore stays in the claim file for the next start,
    /// which adopts it again or replaces it with a durable write-ahead record.
    /// A delete that fails partway leaves the rest recorded, so the next start
    /// can try again. A recorded object that a read does not show is not
    /// deleted and is not treated as gone from that read alone.
    ///
    /// Linux gives an object no creator identity. A privileged process can
    /// write a claim and create identical objects. The private directory, the
    /// lock, the exact selectors, and the empty-table precondition reduce that
    /// risk. They do not prove the creator. Do not describe this recovery as
    /// complete ownership proof.
    pub fn recover_stale(&mut self) -> io::Result<RecoveryReport> {
        if self.cleanup_failed {
            return Err(io::Error::other(
                "route cleanup failed; inspect routes before restarting",
            ));
        }
        if !self.routes.is_empty() || !self.rules.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "routes are installed by this manager",
            ));
        }
        let identity = self.claim_identity()?;
        let claim = RouteClaim::acquire(&self.claim_path, self.claim_strict, &identity)
            .map_err(|error| claim_error(&self.claim_path, "open", error))?;
        if claim.discarded_previous_boot() {
            eprintln!(
                "[route] discarded the route claim {} because it was written before the current boot",
                self.claim_path.display()
            );
        }
        let Some(record) = claim.stale().cloned() else {
            let path = claim.path.clone();
            if let Err(error) = claim.unlink() {
                eprintln!(
                    "[route] cannot remove the empty route claim {}: {error}",
                    path.display()
                );
            }
            return Ok(RecoveryReport::default());
        };
        let report = self.recover_claim(&record)?;
        eprintln!(
            "[route] kept the recovered route claim {} for the next start",
            claim.path.display()
        );
        self.record_recovery(report.clone());
        Ok(report)
    }

    /// Add the recovered keys to this run's cleanup record.
    ///
    /// The predecessor record covers objects that the recovery agreed were
    /// gone. That agreement is evidence, not proof, so an ordinary cleanup must
    /// still read every predecessor key before it releases the claim. A key
    /// that the current run also owns is kept once.
    fn adopt_recovered_objects(&mut self, previous: &ClaimRecord) {
        for route in previous.routes() {
            if !self.routes.contains(&route) {
                self.routes.push(route);
            }
        }
        for rule in previous.rules() {
            if !self.rules.contains(&rule) {
                self.rules.push(rule);
            }
        }
    }

    /// Return the last recovery that removed an object.
    pub fn last_recovery(&self) -> Option<&RecoveryReport> {
        self.recovery.as_ref()
    }

    /// Store the report and print one line for the service log when the
    /// recovery changed the kernel state.
    fn record_recovery(&mut self, report: RecoveryReport) {
        if report.removed_any() {
            eprintln!(
                "[route] recovered {} route(s) and {} rule(s) from a run that did not clean up",
                report.removed_routes, report.removed_rules
            );
        }
        self.recovery = Some(report);
    }

    /// Apply the claim rules against the live kernel state.
    ///
    /// Each round reads the rules and the tunnel table and refuses any object
    /// that the claim does not record. It deletes a recorded object only when
    /// the encoded delete request selects exactly one live object, that object
    /// matches every recorded field, and a second read selects the same object
    /// again. A recorded object that a read omits is not deleted and not
    /// treated as gone. The recovery succeeds only when a round
    /// deletes nothing and [`ABSENCE_READS`] consecutive complete reads agree
    /// that every recorded object is absent. That agreement is evidence, not
    /// proof, because a kernel dump can omit a stable object without setting
    /// `NLM_F_DUMP_INTR`. A list that keeps changing, a foreign object, or a
    /// failed read stops the recovery and keeps the claim.
    fn recover_claim(&self, record: &ClaimRecord) -> io::Result<RecoveryReport> {
        self.recover_claim_with_check(record, &|| Ok(()))
    }

    fn recover_claim_with_check(
        &self,
        record: &ClaimRecord,
        recheck: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<RecoveryReport> {
        // A tunnel that still exists under a claimed name is an ambiguous
        // state. The crash closed its descriptor, so a live device means that
        // another process kept the device or made a new one. A free name is not
        // enough either: Linux reuses interface indexes, and a recorded route
        // names the index. If another device now owns a recorded index, a
        // delete could act on that device. Do not touch the recorded rules in
        // either case. A lookup failure is inconclusive: it cannot show that
        // the name or index is free. The caller takes the claim before it
        // creates a device, so this start has no device that could be the
        // claimed one.
        for (name, index) in record.tunnels() {
            let claimed =
                probe_claimed_device(self.probe_device_index, self.probe_device_name, name, index)
                    .map_err(|error| claimed_device_error(name, index, &error))?;
            match claimed {
                ClaimedDevice::Absent => {}
                ClaimedDevice::Present(actual) => {
                    return Err(inconclusive_claim(format!(
                        "names a tunnel device that still exists at index {actual}"
                    )))
                }
                ClaimedDevice::IndexReused { ifindex, name } => {
                    return Err(inconclusive_claim(format!(
                        "records tunnel index {ifindex}, which now belongs to interface {name}"
                    )))
                }
            }
        }
        let expected_rules = record.rules();
        let expected_routes = record.routes();
        let mut report = RecoveryReport {
            stale_pid: record.pid,
            ..RecoveryReport::default()
        };
        let mut confirmations = 0usize;
        for _ in 0..REMOVAL_ROUNDS {
            let (family_rules, live_routes) = self.recovery_state(record)?;
            let mut changed = false;
            // A recorded object that any read of this round showed. Such a
            // round is not an absence read, even when no delete was sent.
            let mut seen = false;
            // Remove routes before rules, as the ordinary cleanup does.
            for expected in expected_routes.iter().rev() {
                if !route_is_recorded(&live_routes, expected) {
                    // A dump can omit a stable route. Leave it for a later
                    // read instead of calling it gone or deleting blindly.
                    continue;
                }
                match confirm_route_present(self.control.as_ref(), expected) {
                    Ok(DeleteConfirmation::Confirmed) => {}
                    // The second read omitted the object. Do not delete it
                    // and do not count the record as gone. The first read
                    // showed it, so this round is not an absence read.
                    Ok(DeleteConfirmation::Absent) => {
                        seen = true;
                        continue;
                    }
                    Ok(DeleteConfirmation::Ambiguous) => {
                        return Err(inconclusive_claim(format!(
                            "the route {} is not the recorded object on both reads",
                            describe_prefix(expected)
                        )))
                    }
                    Err(error) => {
                        return Err(inconclusive_claim(format!(
                            "cannot read routing table {}: {error}",
                            self.table
                        )))
                    }
                }
                recheck().map_err(|error| {
                    inconclusive_claim(format!(
                        "outer interface recheck before route cleanup failed: {error}"
                    ))
                })?;
                match self.control.delete_route(expected) {
                    Ok(()) => {
                        report.removed_routes += 1;
                        changed = true;
                    }
                    Err(error) if is_missing(&error) => changed = true,
                    Err(error) => {
                        return Err(io::Error::other(format!(
                            "cannot delete the recorded route {}: {error}",
                            describe_prefix(expected)
                        )))
                    }
                }
            }
            for expected in expected_rules.iter().rev() {
                if !rule_is_recorded(rules_in_family(&family_rules, expected.family), expected) {
                    continue;
                }
                match confirm_rule_present(self.control.as_ref(), expected) {
                    Ok(DeleteConfirmation::Confirmed) => {}
                    Ok(DeleteConfirmation::Absent) => {
                        seen = true;
                        continue;
                    }
                    Ok(DeleteConfirmation::Ambiguous) => {
                        return Err(inconclusive_claim(format!(
                            "the rule at priority {} is not the recorded object on both reads",
                            expected.priority
                        )))
                    }
                    Err(error) => {
                        return Err(inconclusive_claim(format!(
                            "cannot read the policy rule list: {error}"
                        )))
                    }
                }
                recheck().map_err(|error| {
                    inconclusive_claim(format!(
                        "outer interface recheck before rule cleanup failed: {error}"
                    ))
                })?;
                match self.control.delete_rule(expected) {
                    Ok(()) => {
                        report.removed_rules += 1;
                        changed = true;
                    }
                    Err(error) if is_missing(&error) => changed = true,
                    Err(error) => {
                        return Err(io::Error::other(format!(
                            "cannot delete the recorded rule at priority {}: {error}",
                            expected.priority
                        )))
                    }
                }
            }
            if changed || seen {
                confirmations = 0;
                continue;
            }
            confirmations += 1;
            if confirmations >= ABSENCE_READS {
                return Ok(report);
            }
        }
        Err(inconclusive_claim(format!(
            "cannot confirm that every recorded object is gone after {REMOVAL_ROUNDS} reads"
        )))
    }

    /// Read the live rules and routes and refuse any object that the claim does
    /// not record.
    ///
    /// The read is one observation, not proof of absence. A recorded object
    /// that this observation omits is left to the next round. An unrecorded
    /// object at a reserved priority, an unrecorded route in the tunnel table,
    /// a delete selector that can match two live objects, a selected object
    /// that is not the recorded one, or a failed read makes the whole result
    /// inconclusive. Two recorded objects can share a priority or a prefix
    /// when their delete selectors differ in a field the model still compares,
    /// such as two outer rules with different interface names or two routes
    /// with different metrics. The IPv6 delete path ignores the route type, so
    /// a blackhole and a unicast route at one prefix are ambiguous.
    fn recovery_state(
        &self,
        record: &ClaimRecord,
    ) -> io::Result<(Vec<Vec<RuleKey>>, Vec<ObservedRouteKey>)> {
        let expected_rules = record.rules();
        let expected_routes = record.routes();
        let families = [libc::AF_INET as u8, libc::AF_INET6 as u8];
        let mut family_rules = Vec::new();
        for family in families {
            family_rules.push(self.control.rules(family).map_err(|error| {
                inconclusive_claim(format!("cannot read the policy rule list: {error}"))
            })?);
        }
        let mut live_routes = Vec::new();
        for family in families {
            live_routes.extend(
                self.control
                    .table_routes(family, self.table)
                    .map_err(|error| {
                        inconclusive_claim(format!(
                            "cannot read routing table {}: {error}",
                            self.table
                        ))
                    })?,
            );
        }
        for rules in &family_rules {
            for rule in rules {
                let reserved =
                    rule.priority == OUTER_RULE_PRIORITY || rule.priority == TUNNEL_RULE_PRIORITY;
                if reserved && !expected_rules.iter().any(|expected| expected == rule) {
                    return Err(inconclusive_claim(format!(
                        "the rule at priority {} is not the recorded object",
                        rule.priority
                    )));
                }
            }
        }
        for route in &live_routes {
            let recorded = expected_routes
                .iter()
                .any(|expected| route.is_clean() && expected.same_key(&route.key));
            if !recorded {
                return Err(inconclusive_claim(format!(
                    "the route {} in table {} is not the recorded object",
                    describe_prefix(&route.key),
                    self.table
                )));
            }
        }
        for expected in &expected_rules {
            let rules = rules_in_family(&family_rules, expected.family);
            let selected = rules_selected_by(rules, expected);
            if selected.len() > 1 {
                return Err(inconclusive_claim(format!(
                    "the delete selector for the rule at priority {} can match {} live rules; the recorded object is ambiguous",
                    expected.priority,
                    selected.len()
                )));
            }
            if let Some(live) = selected.first() {
                if *live != expected {
                    return Err(inconclusive_claim(format!(
                        "the delete selector for the rule at priority {} can match a live rule that is not the recorded object",
                        expected.priority
                    )));
                }
            }
        }
        for expected in &expected_routes {
            let selected = routes_selected_by(&live_routes, expected);
            if selected.len() > 1 {
                return Err(inconclusive_claim(format!(
                    "the delete selector for the route {} in table {} can match {} live routes; the recorded object is ambiguous",
                    describe_prefix(expected),
                    self.table,
                    selected.len()
                )));
            }
            if let Some(live) = selected.first() {
                if !live.is_clean() || !expected.same_key(&live.key) {
                    return Err(inconclusive_claim(format!(
                        "the delete selector for the route {} in table {} can match a live route that is not the recorded object",
                        describe_prefix(expected),
                        self.table
                    )));
                }
            }
        }
        for rules in &family_rules {
            for rule in rules {
                let reserved =
                    rule.priority == OUTER_RULE_PRIORITY || rule.priority == TUNNEL_RULE_PRIORITY;
                if !reserved {
                    continue;
                }
                let selected = expected_rules
                    .iter()
                    .filter(|expected| expected.delete_selects(rule))
                    .count();
                if selected == 0 {
                    return Err(inconclusive_claim(format!(
                        "no recorded delete selector can match the live rule at priority {}",
                        rule.priority
                    )));
                }
                if selected > 1 {
                    return Err(inconclusive_claim(format!(
                        "more than one recorded delete selector can match the live rule at priority {}",
                        rule.priority
                    )));
                }
            }
        }
        for route in &live_routes {
            let selected = expected_routes
                .iter()
                .filter(|expected| expected.delete_selects(route))
                .count();
            if selected == 0 {
                return Err(inconclusive_claim(format!(
                    "no recorded delete selector can match the live route {} in table {}",
                    describe_prefix(&route.key),
                    self.table
                )));
            }
            if selected > 1 {
                return Err(inconclusive_claim(format!(
                    "more than one recorded delete selector can match the live route {} in table {}",
                    describe_prefix(&route.key),
                    self.table
                )));
            }
        }
        Ok((family_rules, live_routes))
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

    /// Record a rule before the add. A definite failure drops the record,
    /// because the kernel did not apply the rule. A failure with an unknown
    /// outcome, such as an ACK timeout or a lost answer, keeps the record
    /// without a read: a dump can omit a stable rule, so one read that does
    /// not show it is not proof that the add was not applied. The rollback then
    /// deletes the rule only when a read shows the exact record, and drops the
    /// record only after the absence agreement.
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
                if !write_outcome_unknown(&error) {
                    self.rules.remove(index);
                }
                Err(add_error(operation, &error))
            }
        }
    }

    /// Record a route before the add. The record rules are the same as for
    /// [`RouteManager::add_rule_recorded`].
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
                if !write_outcome_unknown(&error) {
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
    /// matching object is deleted, but only after a second read also selects
    /// exactly that object for the encoded request. A request that selects two
    /// live objects, a selected object that is not the record, or a failed read
    /// is left in place, kept in the record, and reported. An object that a
    /// read does not select is never deleted, and one read is not enough to
    /// call it gone: a kernel dump can omit a stable object without setting
    /// `NLM_F_DUMP_INTR`. The call repeats until a round deletes nothing and
    /// [`ABSENCE_READS`] consecutive complete reads select no object for every
    /// record. That agreement is evidence, not proof. A record that is still
    /// unconfirmed after [`REMOVAL_ROUNDS`] keeps the claim and the record and
    /// makes the call fail. The call is idempotent. The route claim is removed
    /// only after every record is proven gone under that rule.
    ///
    /// A failure keeps the claim file as the record for the next start and keeps
    /// its lock for the rest of this process. A second start therefore refuses
    /// while this process lives, and the kernel releases the lock when the
    /// process exits. The next start then reads the same record and adopts it
    /// under the exact-match rules. The service sets `cleanup_blocked` at the
    /// same time, so a restart in this process also refuses. An explicit retry
    /// on this manager may still succeed while it holds the lock; success clears
    /// the block only after every record is confirmed gone.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.routes.is_empty() && self.rules.is_empty() {
            self.cleanup_failed = false;
            return self.clear_claim();
        }
        let control = Arc::clone(&self.control);
        let mut routes = std::mem::take(&mut self.routes);
        let mut rules = std::mem::take(&mut self.rules);
        let mut confirmations = 0usize;
        for _ in 0..REMOVAL_ROUNDS {
            let mut failures = Vec::new();
            let mut keep_routes = vec![false; routes.len()];
            let mut keep_rules = vec![false; rules.len()];
            let mut changed = false;
            // A recorded object that a read of this round showed. Such a round
            // is not an absence read, even when no delete was sent.
            let mut seen = false;
            for index in (0..routes.len()).rev() {
                let key = routes[index].clone();
                match control.table_routes(key.family, key.table) {
                    Ok(observed) => {
                        let selected = routes_selected_by(&observed, &key);
                        if selected.is_empty() {
                            // No live route is selected by this delete request.
                            // Another recorded route at the same prefix is not
                            // this record. A live object that no record owns
                            // is a foreign shape, not an absence.
                            let unowned = observed.iter().any(|item| {
                                item.key.family == key.family
                                    && item.key.destination == key.destination
                                    && item.key.length == key.length
                                    && !route_belongs_to_record(&observed, item, &routes)
                            });
                            if unowned {
                                failures.push(format!(
                                    "route {} in table {} is not the recorded object; it was left in place",
                                    describe_prefix(&key),
                                    key.table
                                ));
                            }
                            // A dump can omit a stable route, so do not call
                            // the record clean from this read; keep it for a
                            // later round.
                            keep_routes[index] = true;
                        } else if route_is_recorded(&observed, &key) {
                            match confirm_route_present(control.as_ref(), &key) {
                                Ok(DeleteConfirmation::Confirmed) => {
                                    match control.delete_route(&key) {
                                        Ok(()) => changed = true,
                                        // The object vanished between the read
                                        // and the delete. Read again instead of
                                        // counting this round as stable.
                                        Err(error) if is_missing(&error) => changed = true,
                                        Err(error) => {
                                            failures.push(format!(
                                                "cannot delete route {} from table {}: {error}",
                                                describe_prefix(&key),
                                                key.table
                                            ));
                                            keep_routes[index] = true;
                                        }
                                    }
                                }
                                Ok(DeleteConfirmation::Absent) => {
                                    // The second read omitted the object. Keep
                                    // the record; a later round decides. The
                                    // first read showed it, so this round is
                                    // not an absence read.
                                    keep_routes[index] = true;
                                    seen = true;
                                }
                                Ok(DeleteConfirmation::Ambiguous) => {
                                    failures.push(format!(
                                        "route {} in table {} is not the recorded object on both reads; it was left in place",
                                        describe_prefix(&key),
                                        key.table
                                    ));
                                    keep_routes[index] = true;
                                }
                                Err(error) => {
                                    failures.push(format!(
                                        "cannot prove route {} in table {}: {error}",
                                        describe_prefix(&key),
                                        key.table
                                    ));
                                    keep_routes[index] = true;
                                }
                            }
                        } else {
                            failures.push(format!(
                                "route {} in table {} is not the recorded object; the delete selector matches {} live route(s), so it was left in place",
                                describe_prefix(&key),
                                key.table,
                                selected.len()
                            ));
                            keep_routes[index] = true;
                        }
                    }
                    Err(error) => {
                        failures.push(format!(
                            "cannot prove route {} in table {}: {error}",
                            describe_prefix(&key),
                            key.table
                        ));
                        keep_routes[index] = true;
                    }
                }
            }
            for index in (0..rules.len()).rev() {
                let rule = rules[index].clone();
                match control.rules(rule.family) {
                    Ok(observed) => {
                        let selected = rules_selected_by(&observed, &rule);
                        if selected.is_empty() {
                            // No live rule is selected by this delete request.
                            // Another recorded rule at the same priority is not
                            // this record. A live object that no record owns
                            // is a foreign shape, not an absence.
                            let unowned = observed.iter().any(|item| {
                                item.priority == rule.priority
                                    && !rule_belongs_to_record(&observed, item, &rules)
                            });
                            if unowned {
                                failures.push(format!(
                                    "the policy rule at priority {} is not the recorded object; it was left in place",
                                    rule.priority
                                ));
                            }
                            // The record stays until a later read or the clean
                            // agreement.
                            keep_rules[index] = true;
                        } else if rule_is_recorded(&observed, &rule) {
                            match confirm_rule_present(control.as_ref(), &rule) {
                                Ok(DeleteConfirmation::Confirmed) => {
                                    match control.delete_rule(&rule) {
                                        Ok(()) => changed = true,
                                        Err(error) if is_missing(&error) => changed = true,
                                        Err(error) => {
                                            failures.push(format!(
                                                "cannot delete the policy rule at priority {}: {error}",
                                                rule.priority
                                            ));
                                            keep_rules[index] = true;
                                        }
                                    }
                                }
                                Ok(DeleteConfirmation::Absent) => {
                                    keep_rules[index] = true;
                                    seen = true;
                                }
                                Ok(DeleteConfirmation::Ambiguous) => {
                                    failures.push(format!(
                                        "the policy rule at priority {} is not the recorded object on both reads; it was left in place",
                                        rule.priority
                                    ));
                                    keep_rules[index] = true;
                                }
                                Err(error) => {
                                    failures.push(format!(
                                        "cannot prove the policy rule at priority {}: {error}",
                                        rule.priority
                                    ));
                                    keep_rules[index] = true;
                                }
                            }
                        } else {
                            failures.push(format!(
                                "the policy rule at priority {} is not the recorded object; the delete selector matches {} live rule(s), so it was left in place",
                                rule.priority,
                                selected.len()
                            ));
                            keep_rules[index] = true;
                        }
                    }
                    Err(error) => {
                        failures.push(format!(
                            "cannot prove the policy rule at priority {}: {error}",
                            rule.priority
                        ));
                        keep_rules[index] = true;
                    }
                }
            }
            routes = routes
                .into_iter()
                .zip(keep_routes)
                .filter_map(|(key, keep)| keep.then_some(key))
                .collect();
            rules = rules
                .into_iter()
                .zip(keep_rules)
                .filter_map(|(rule, keep)| keep.then_some(rule))
                .collect();
            if !failures.is_empty() {
                self.routes = routes;
                self.rules = rules;
                self.cleanup_failed = true;
                self.note_cleanup_failure();
                return Err(io::Error::other(failures.join("; ")));
            }
            if changed || seen {
                confirmations = 0;
                continue;
            }
            confirmations += 1;
            if confirmations >= ABSENCE_READS {
                // Every remaining record was absent from this read and from
                // the preceding agreeing read. Drop the records with the claim.
                self.routes.clear();
                self.rules.clear();
                self.cleanup_failed = false;
                return self.clear_claim();
            }
        }
        self.routes = routes;
        self.rules = rules;
        self.cleanup_failed = true;
        self.note_cleanup_failure();
        Err(io::Error::other(format!(
            "route cleanup could not confirm that every recorded object is gone after {REMOVAL_ROUNDS} reads; the records and the route claim are kept"
        )))
    }

    /// Keep this manager's claim and report the failure. The claim stays in
    /// this manager so an explicit retry can still use the lock. If the manager
    /// is dropped instead, [`Drop`] moves the claim into the process-wide
    /// retained list.
    fn note_cleanup_failure(&self) {
        if let Some(claim) = self.claim.as_ref() {
            eprintln!(
                "[route] cleanup failed; the route claim {} and its lock are kept",
                claim.path.display()
            );
        }
    }

    /// Remove the claim after every recorded object is proven gone.
    ///
    /// The claim is what lets a later start adopt a crashed run. It must stay in
    /// place while any record remains, so a failed cleanup keeps it. An unlink
    /// failure after a clean route and rule removal is reported, but it does not
    /// fail the stop. The file is either empty or still holds the record that
    /// this run wrote. The next start reads an empty file as a clean claim and
    /// removes it. A non-empty file is a stale claim: the next start adopts it
    /// only under the same exact-match rules, finds no recorded object, and
    /// removes it. If the path was replaced or cannot be read, the next start
    /// refuses instead.
    ///
    /// A recovered record stays in the file when no later complete read of the
    /// table and the reserved priorities showed them free, for example when
    /// that read refused the start. Only the lock is released. See
    /// [`RouteClaim::release`].
    fn clear_claim(&mut self) -> io::Result<()> {
        let Some(claim) = self.claim.take() else {
            return Ok(());
        };
        let path = claim.path.clone();
        match claim.release() {
            Ok(()) => Ok(()),
            Err(error) => {
                eprintln!(
                    "[route] cannot remove the route claim {}: {error}",
                    path.display()
                );
                Ok(())
            }
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
    /// link type, relationships, and physical sysfs association. These checks
    /// are evidence and may reject legitimate drivers. They do not prove that
    /// a socket is bound to the interface.
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
        capture_physical_outer(ifname, ifindex).map_err(|error| RouteVerifyError::Unavailable {
            operation: "outer interface physical evidence",
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

    /// Return true while a route or rule is recorded as installed, or while a
    /// failed cleanup still holds a record.
    pub fn has_installed_routes(&self) -> bool {
        self.cleanup_failed || !self.routes.is_empty() || !self.rules.is_empty()
    }
}

/// Read the IPv4 route that the kernel selects for one numeric destination.
///
/// The call creates one netlink socket and sends a read-only `RTM_GETROUTE`
/// request. It changes no route. The reply names the selected output interface,
/// gateway, prefix, and table. The caller decides whether that route proves the
/// intended destination.
pub fn route_to_ipv4(destination: Ipv4Addr) -> Result<ObservedRoute, RouteVerifyError> {
    NetlinkRoute::open()?.route(destination)
}

// A sysfs device association is evidence, not proof, of a physical device.
// It intentionally rejects physical drivers that lack this association and
// stacked devices. Resolve both paths under the trusted sysfs root.
#[derive(Clone, Debug)]
pub struct PhysicalOuterIdentity {
    link: OuterLinkIdentity,
    link_path: std::path::PathBuf,
    device_path: std::path::PathBuf,
    link_handle: Arc<File>,
    device_handle: Arc<File>,
}

fn physical_sysfs_evidence(
    root: &Path,
    identity: &OuterLinkIdentity,
) -> io::Result<PhysicalOuterIdentity> {
    let class = root.join("class/net").join(identity.name());
    let link = std::fs::canonicalize(&class)?;
    let device = std::fs::canonicalize(class.join("device"))?;
    let devices = root.join("devices");
    if !link.starts_with(&devices)
        || !device.starts_with(&devices)
        || !link.starts_with(&device)
        || link.starts_with(devices.join("virtual"))
        || device.starts_with(devices.join("virtual"))
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "outer interface has no physical device association",
        ));
    }
    let link_handle = Arc::new(File::open(&link)?);
    let device_handle = Arc::new(File::open(&device)?);
    let index: u32 = std::fs::read_to_string(class.join("ifindex"))?
        .trim()
        .parse()
        .map_err(|_| io::Error::other("invalid sysfs interface index"))?;
    if index != identity.ifindex() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "outer interface changed during verification",
        ));
    }
    if std::fs::canonicalize(&class)? != link
        || std::fs::canonicalize(class.join("device"))? != device
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "outer interface changed during verification",
        ));
    }
    Ok(PhysicalOuterIdentity {
        link: identity.clone(),
        link_path: link,
        device_path: device,
        link_handle,
        device_handle,
    })
}

impl PhysicalOuterIdentity {
    fn same_device(&self, other: &Self) -> io::Result<bool> {
        fn same(a: &File, b: &File) -> io::Result<bool> {
            let (a, b) = (a.metadata()?, b.metadata()?);
            Ok((a.dev(), a.ino()) == (b.dev(), b.ino()))
        }
        Ok(self.link == other.link
            && self.link_path == other.link_path
            && self.device_path == other.device_path
            && same(&self.link_handle, &other.link_handle)?
            && same(&self.device_handle, &other.device_handle)?)
    }

    pub fn recheck(&self) -> io::Result<()> {
        let current = capture_physical_outer(self.link.name(), self.link.ifindex())?;
        self.check_retained(&current)
    }

    fn check_retained(&self, current: &Self) -> io::Result<()> {
        if !self.same_device(current)? {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "outer_interface_changed",
            ));
        }
        Ok(())
    }
}

/// Check current netlink and sysfs evidence for the frozen outer interface.
/// This is read-only and can reject legitimate physical or stacked devices.
pub fn capture_physical_outer(ifname: &str, ifindex: u32) -> io::Result<PhysicalOuterIdentity> {
    let identity = OuterLinkIdentity::new(ifindex, ifname)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let netlink = NetlinkRoute::open().map_err(route_error_to_io)?;
    let link = netlink.link(ifindex).map_err(route_error_to_io)?;
    prove_outer_link(&link, &identity).map_err(route_error_to_io)?;
    let physical = physical_sysfs_evidence(Path::new("/sys"), &identity)?;
    let again = netlink.link(ifindex).map_err(route_error_to_io)?;
    if link != again || interface_index(ifname)? != ifindex {
        return Err(io::Error::other(
            "outer interface changed during verification",
        ));
    }
    Ok(physical)
}

/// Return true when the named link is up and has a usable IPv4 address.
///
/// This read-only check uses `RTM_GETLINK` for the link state and `getifaddrs`
/// for the address. It starts no process and changes no route. A missing link is
/// a down link, not an error. A netlink read failure is an error, so the caller
/// does not count an unknown state as link loss.
pub fn link_ready_for(identity: &PhysicalOuterIdentity) -> io::Result<bool> {
    link_ready_with(
        identity,
        interface_index,
        |index| {
            let netlink = NetlinkRoute::open()?;
            netlink.link(index)
        },
        |link| physical_sysfs_evidence(Path::new("/sys"), link),
        crate::autostop::link_observation,
    )
}

fn link_ready_with(
    identity: &PhysicalOuterIdentity,
    index_for: impl FnOnce(&str) -> io::Result<u32>,
    read_link: impl FnOnce(u32) -> Result<ObservedLink, RouteVerifyError>,
    read_physical: impl FnOnce(&OuterLinkIdentity) -> io::Result<PhysicalOuterIdentity>,
    read_address: impl FnOnce(&str) -> io::Result<bool>,
) -> io::Result<bool> {
    let ifname = identity.link.name();
    if !valid_ifname(ifname) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    let index = match index_for(ifname) {
        Ok(index) => index,
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => return Ok(false),
        Err(error) => return Err(error),
    };
    if index != identity.link.ifindex() {
        return Ok(false);
    }
    let link = match read_link(index) {
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
    if prove_outer_link(&link, &identity.link).is_err() {
        return Ok(false);
    }
    let current = match read_physical(&identity.link) {
        Ok(current) => current,
        // Missing sysfs data can be incomplete evidence rather than link loss.
        Err(error) if error.kind() == io::ErrorKind::NotConnected => return Ok(false),
        Err(error) => return Err(error),
    };
    if !identity.same_device(&current)? {
        return Ok(false);
    }
    read_address(ifname)
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
        if self.cleanup_failed {
            // The claim lock and file stay until this process exits. Move the
            // handle to the process-wide list instead of letting the field drop
            // release the lock. A second attempt here would only repeat the
            // failed deletes.
            if let Some(claim) = self.claim.take() {
                retained_claims()
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(claim);
            }
            return;
        }
        if let Err(error) = self.remove() {
            eprintln!("[route] cleanup failed: {}", error);
        }
        if self.cleanup_failed {
            if let Some(claim) = self.claim.take() {
                retained_claims()
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(claim);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
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
        fail_delete: Mutex<bool>,
        /// A stored route that a test hides from the next `reads` dumps of its
        /// family and table. This models a kernel dump that omits a stable
        /// entry without setting `NLM_F_DUMP_INTR`. The delete path still sees
        /// the stored entry, so a test can prove that the cleanup waits for a
        /// second read instead of deleting a blind selector.
        hidden_route: Mutex<Option<(RouteKey, usize)>>,
        /// The rule equivalent of `hidden_route`.
        hidden_rule: Mutex<Option<(RuleKey, usize)>>,
        /// A route that a test recreates after every successful delete. Models
        /// a concurrent writer that keeps replacing the object, so no round is
        /// stable.
        reinsert_route: Mutex<Option<RouteKey>>,
        /// A stored route that a test hides from every second dump of its
        /// family and table, counted from the call that set it. A delete
        /// confirmation read that follows a visible read therefore omits it on
        /// every round. This models a dump that keeps omitting a stable entry
        /// in a pattern, without `NLM_F_DUMP_INTR`.
        flicker_route: Mutex<Option<(RouteKey, usize)>>,
        /// The rule equivalent of `flicker_route`.
        flicker_rule: Mutex<Option<(RuleKey, usize)>>,
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

        /// Fail the next delete call once. This exercises the cleanup failure
        /// policy: the caller must keep the claim file and release its lock.
        fn fail_next_delete(&self) {
            *self.fail_delete.lock().unwrap() = true;
        }

        fn take_injected_delete(&self) -> bool {
            std::mem::take(&mut *self.fail_delete.lock().unwrap())
        }

        /// Hide one stored route from the next `reads` dumps of its family and
        /// table. A count of zero hides nothing.
        fn hide_route_for(&self, key: RouteKey, reads: usize) {
            *self.hidden_route.lock().unwrap() = Some((key, reads));
        }

        /// Hide one stored rule from the next `reads` dumps of its family.
        fn hide_rule_for(&self, rule: RuleKey, reads: usize) {
            *self.hidden_rule.lock().unwrap() = Some((rule, reads));
        }

        /// Recreate this route after every successful delete of it.
        /// Hide this route from every second dump of its family and table.
        fn flicker_route(&self, key: RouteKey) {
            *self.flicker_route.lock().unwrap() = Some((key, 0));
        }

        /// Hide this rule from every second dump of its family.
        fn flicker_rule(&self, rule: RuleKey) {
            *self.flicker_rule.lock().unwrap() = Some((rule, 0));
        }

        /// Stop every flicker, so every later dump is complete.
        fn stop_flicker(&self) {
            *self.flicker_route.lock().unwrap() = None;
            *self.flicker_rule.lock().unwrap() = None;
        }

        fn take_flicker_route(&self, family: u8, table: u32) -> Option<RouteKey> {
            let mut flicker = self.flicker_route.lock().unwrap();
            let (key, reads) = flicker.as_mut()?;
            if key.family != family || key.table != table {
                return None;
            }
            *reads += 1;
            (*reads % 2 == 0).then(|| key.clone())
        }

        fn take_flicker_rule(&self, family: u8) -> Option<RuleKey> {
            let mut flicker = self.flicker_rule.lock().unwrap();
            let (rule, reads) = flicker.as_mut()?;
            if rule.family != family {
                return None;
            }
            *reads += 1;
            (*reads % 2 == 0).then(|| rule.clone())
        }

        fn reinsert_route(&self, key: RouteKey) {
            *self.reinsert_route.lock().unwrap() = Some(key);
        }

        fn take_hidden_route(&self, family: u8, table: u32) -> Option<RouteKey> {
            let mut hidden = self.hidden_route.lock().unwrap();
            let (key, remaining) = hidden.as_mut()?;
            if key.family != family || key.table != table || *remaining == 0 {
                return None;
            }
            *remaining -= 1;
            Some(key.clone())
        }

        fn take_hidden_rule(&self, family: u8) -> Option<RuleKey> {
            let mut hidden = self.hidden_rule.lock().unwrap();
            let (rule, remaining) = hidden.as_mut()?;
            if rule.family != family || *remaining == 0 {
                return None;
            }
            *remaining -= 1;
            Some(rule.clone())
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
                unexpected: false,
            });
        }

        fn put_foreign_route(&self, key: RouteKey) {
            self.routes.lock().unwrap().push(ObservedRouteKey {
                key,
                gateway: true,
                multipath: false,
                encap: false,
                nexthop: false,
                unexpected: false,
            });
        }

        /// Store one route observation exactly, including an unmodeled
        /// attribute that a test wants the cleanup to see.
        fn put_route_observed(&self, route: ObservedRouteKey) {
            self.routes.lock().unwrap().push(route);
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
            // Both seams run on every read so each one counts its own reads.
            let hidden: Vec<RouteKey> = [
                self.take_hidden_route(family, table),
                self.take_flicker_route(family, table),
            ]
            .into_iter()
            .flatten()
            .collect();
            // Model the real reader's accepted result, not its wire request. A
            // strict table dump and a filtered full dump both reach this shape:
            // only the named family and table, and an absent table is empty.
            // The fake therefore cannot expose a foreign table as this table.
            Ok(self
                .routes
                .lock()
                .unwrap()
                .iter()
                .filter(|item| item.key.family == family && item.key.table == table)
                .filter(|item| !hidden.iter().any(|key| item.key.same_key(key)))
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
                unexpected: false,
            });
            Ok(())
        }

        fn delete_route(&self, key: &RouteKey) -> io::Result<()> {
            let index = self.record(format!("delete-route {}", describe_prefix(key)));
            self.injected(index)?;
            if self.take_injected_delete() {
                return Err(io::Error::other("injected delete failure"));
            }
            let mut routes = self.routes.lock().unwrap();
            // The kernel deletes the first route that the request matches. An
            // IPv6 ECMP group can hold sibling entries, and one delete can
            // remove more than one sibling. This fake holds one entry per
            // observed route, so it removes exactly one entry and does not
            // model a sibling group. The cleanup refuses a request that selects
            // more than one entry, so a group is never a delete target here.
            let Some(position) = routes.iter().position(|item| key.delete_selects(item)) else {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            };
            routes.remove(position);
            if let Some(reinsert) = self.reinsert_route.lock().unwrap().as_ref() {
                let observed = ObservedRouteKey {
                    key: reinsert.clone(),
                    gateway: false,
                    multipath: false,
                    encap: false,
                    nexthop: false,
                    unexpected: false,
                };
                if key.delete_selects(&observed) {
                    routes.push(observed);
                }
            }
            Ok(())
        }

        fn rules(&self, family: u8) -> io::Result<Vec<RuleKey>> {
            self.record(format!("read-rules {family}"));
            if *self.read_error.lock().unwrap() {
                return Err(io::Error::other("injected read failure"));
            }
            let hidden: Vec<RuleKey> = [
                self.take_hidden_rule(family),
                self.take_flicker_rule(family),
            ]
            .into_iter()
            .flatten()
            .collect();
            Ok(self
                .rules
                .lock()
                .unwrap()
                .iter()
                .filter(|item| item.family == family)
                .filter(|item| !hidden.iter().any(|rule| *item == rule))
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
            // The kernel allows distinct rules at one priority when their
            // selectors differ. `NLM_F_EXCL` rejects only the exact rule that a
            // dump would report again, so two outer rules with different
            // output interfaces can coexist at priority 17000.
            if rules.iter().any(|item| item == rule) {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            rules.push(rule.clone());
            Ok(())
        }

        fn delete_rule(&self, rule: &RuleKey) -> io::Result<()> {
            let index = self.record(format!("delete-rule {}", rule.priority));
            self.injected(index)?;
            if self.take_injected_delete() {
                return Err(io::Error::other("injected delete failure"));
            }
            let mut rules = self.rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|item| !rule.delete_selects(item));
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

    /// Build the plain observation shape for a recorded route: no gateway, no
    /// multipath, no encapsulation, no nexthop object, and no unmodeled
    /// attribute.
    fn plain_observed(key: RouteKey) -> ObservedRouteKey {
        ObservedRouteKey {
            key,
            gateway: false,
            multipath: false,
            encap: false,
            nexthop: false,
            unexpected: false,
        }
    }

    fn test_link() -> ObservedLink {
        ObservedLink {
            ifindex: TEST_IFINDEX,
            name: TEST_IFNAME.to_owned(),
            kind: Some("tun".to_owned()),
            lower: None,
            master: None,
            link_netnsid: None,
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
            scope: RT_SCOPE_LINK,
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
            unexpected: false,
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
            lower: None,
            master: None,
            link_netnsid: None,
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
            scope: RT_SCOPE_UNIVERSE,
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
            unexpected: false,
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
        test_netlink_message_flags(kind, 0, sequence, payload)
    }

    fn test_netlink_message_flags(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; NLMSG_HDRLEN + payload.len()];
        let length = message.len() as u32;
        write_u32(&mut message[0..4], length);
        write_u16(&mut message[4..6], kind);
        write_u16(&mut message[6..8], flags);
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

    /// One `RTA_CACHEINFO` value with the kernel size.
    ///
    /// `rt6_fill_node` always adds this attribute through
    /// `rtnl_put_cacheinfo`. Its signed expiry is not a delete selector, but a
    /// nonzero value is not a shape this manager owns.
    fn test_cacheinfo(expires: i32) -> Vec<u8> {
        let mut value = Vec::with_capacity(RTA_CACHEINFO_LEN);
        value.extend_from_slice(&1u32.to_ne_bytes()); // rta_clntref
        value.extend_from_slice(&0u32.to_ne_bytes()); // rta_lastuse
        value.extend_from_slice(&expires.to_ne_bytes()); // rta_expires
        value.extend_from_slice(&0u32.to_ne_bytes()); // rta_error
        value.extend_from_slice(&0u32.to_ne_bytes()); // rta_used
        value.extend_from_slice(&0u32.to_ne_bytes()); // rta_id
        value.extend_from_slice(&0u32.to_ne_bytes()); // rta_ts
        value.extend_from_slice(&0u32.to_ne_bytes()); // rta_tsage
        test_attr(RTA_CACHEINFO, &value)
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
        scope: u8,
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
        payload[6] = spec.scope;
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
                scope: RT_SCOPE_UNIVERSE,
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
        assert_eq!(RTM_F_CLONED, 0x200);
        assert_eq!(RTM_F_CLONED, libc::RTM_F_CLONED);
        assert_eq!(RTA_SRC, 2);
        assert_eq!(RTA_DST, 1);
        assert_eq!(RTA_OIF, 4);
        assert_eq!(RTA_PRIORITY, 6);
        assert_eq!(RTA_CACHEINFO, 12);
        assert_eq!(RTA_TABLE, 15);
        assert_eq!(RTA_PREF, 20);
        assert_eq!(RTA_CACHEINFO_LEN, 32);
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
            capture_physical_outer("", 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        // A missing link is a down link, not an unknown state.
        assert!(capture_physical_outer("hs-missing0", 1).is_err());
        // The loopback link is not a physical outer link.
        assert!(capture_physical_outer("lo", 1).is_err());
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
    fn cleanup_keeps_a_recorded_route_and_a_foreign_candidate() {
        for variant in ["tos", "source"] {
            let control = Arc::new(FakeControl::default());
            let mut routes =
                RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone())
                    .unwrap();
            let tun = fake_tun();
            let proof = routes
                .verify_interface_with(&tun, &FakeObserver::good())
                .unwrap();
            routes
                .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
                .unwrap();
            control.clear_objects();
            let recorded = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
            let mut foreign = recorded.clone();
            // The delete request writes a zero TOS and a zero source length.
            // A zero selector may be a wildcard, so the foreign route stays a
            // candidate even though the recorded route is also present. A
            // model that compared those live fields literally would hide the
            // foreign candidate and send the delete.
            match variant {
                "tos" => foreign.tos = 16,
                "source" => {
                    foreign.source_length = 8;
                    foreign.source = Some(vec![10, 0, 0, 0]);
                }
                _ => unreachable!(),
            }
            control.put_route(recorded.clone());
            control.put_route(foreign.clone());

            let error = routes.remove().unwrap_err();

            assert!(
                error.to_string().contains("delete selector matches 2"),
                "{variant}: {error}"
            );
            assert!(routes.has_installed_routes());
            assert_eq!(control.route_count(), 2);
            assert!(!control
                .calls()
                .iter()
                .any(|call| call == &format!("delete-route {}", describe_prefix(&recorded))));
        }
    }

    #[test]
    fn cleanup_keeps_a_recorded_rule_and_a_foreign_candidate() {
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
        let recorded = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
        let mut foreign = recorded.clone();
        // The delete request writes zero flags. A zero selector may be a
        // wildcard, so the foreign rule stays a candidate. The full equality
        // check still rejects it, and the cleanup must not send the delete.
        foreign.flags = FIB_RULE_INVERT;
        control.put_rule(recorded);
        control.put_rule(foreign);

        let error = routes.remove().unwrap_err();

        assert!(
            error.to_string().contains("delete selector matches 2"),
            "{error}"
        );
        assert!(routes.has_installed_routes());
        assert_eq!(control.rule_count(), 2);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == "delete-rule 17000"));
    }

    #[test]
    fn cleanup_keeps_a_route_with_an_unmodeled_attribute() {
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
        control.put_route_observed(ObservedRouteKey {
            key: key.clone(),
            gateway: false,
            multipath: false,
            encap: false,
            nexthop: false,
            unexpected: true,
        });

        let error = routes.remove().unwrap_err();

        assert!(
            error.to_string().contains("not the recorded object"),
            "{error}"
        );
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 1);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-route {}", describe_prefix(&key))));
    }

    #[test]
    fn cleanup_keeps_a_route_with_a_foreign_ipv6_scope() {
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
        let recorded = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
        let mut live = recorded.clone();
        live.scope = RT_SCOPE_LINK;
        control.put_route(live);

        let error = routes.remove().unwrap_err();

        assert!(
            error.to_string().contains("not the recorded object"),
            "{error}"
        );
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 1);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-route {}", describe_prefix(&recorded))));
    }

    #[test]
    fn cleanup_removes_the_owned_block_route_from_a_kernel_shaped_dump() {
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
        control.clear_objects();
        // Model the reply that a kernel sends for the recorded blackhole: the
        // loopback output interface, the default preference attribute, and the
        // cacheinfo attribute that `rt6_fill_node` always adds.
        let extra = [
            test_cacheinfo(0),
            test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
            test_attr(RTA_PRIORITY, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_BLACKHOLE,
            0,
            Some(1),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 49, &payload);
        let live = select_route_table(vec![message], libc::AF_INET6 as u8, TUNNEL_TABLE).unwrap();
        assert_eq!(live.len(), 1);
        control.put_route_observed(live[0].clone());
        let block = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);

        routes.remove().unwrap();

        assert!(!routes.has_installed_routes());
        assert!(
            control
                .calls()
                .iter()
                .any(|call| call == &format!("delete-route {}", describe_prefix(&block))),
            "the recorded block route is deleted"
        );
    }

    #[test]
    fn cleanup_keeps_expiring_or_cloned_block_route() {
        for (expires, flags) in [(1, 0), (-1, 0), (0, 0x200)] {
            let control = Arc::new(FakeControl::default());
            let mut routes =
                RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Block, control.clone())
                    .unwrap();
            let tun = fake_tun();
            let proof = routes
                .verify_interface_with(&tun, &FakeObserver::good())
                .unwrap();
            routes
                .install_verified(&proof, &tun, TEST_OUTER_IFNAME)
                .unwrap();
            control.clear_objects();
            let extra = [
                test_cacheinfo(expires),
                test_attr(20, &[0]),
                test_attr(6, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
            ];
            let payload = test_ipv6_route_payload(
                IPV6_GLOBAL_UNICAST,
                TUNNEL_TABLE,
                ROUTE_PROTOCOL_ID,
                RTN_BLACKHOLE,
                flags,
                Some(1),
                &extra,
            );
            let live = select_route_table(
                vec![test_netlink_message(RTM_NEWROUTE, 49, &payload)],
                libc::AF_INET6 as u8,
                TUNNEL_TABLE,
            )
            .unwrap();
            control.put_route_observed(live[0].clone());
            let block = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
            assert!(routes.remove().is_err(), "expiry {expires}, flags {flags}");
            assert!(routes.has_installed_routes());
            assert_eq!(control.route_count(), 1);
            assert!(!control
                .calls()
                .iter()
                .any(|call| call == &format!("delete-route {}", describe_prefix(&block))));
        }
    }

    #[test]
    fn cleanup_keeps_the_record_when_a_route_type_is_ambiguous() {
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
        control.clear_objects();
        // The recorded blackhole reports the loopback interface, the default
        // preference, and the cacheinfo attribute. A unicast route now shares
        // the prefix in the dedicated table. The IPv6 delete path ignores the
        // route type, so one request can select both entries and the cleanup
        // must not send it.
        let extra = [
            test_cacheinfo(0),
            test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
            test_attr(RTA_PRIORITY, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_BLACKHOLE,
            0,
            Some(1),
            &extra,
        );
        let live = select_route_table(
            vec![test_netlink_message(RTM_NEWROUTE, 50, &payload)],
            libc::AF_INET6 as u8,
            TUNNEL_TABLE,
        )
        .unwrap();
        assert_eq!(live.len(), 1);
        control.put_route_observed(live[0].clone());
        let mut foreign = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
        foreign.metric = Some(IPV6_DEFAULT_METRIC);
        control.put_route(foreign);
        let block = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);

        let error = routes.remove().unwrap_err();

        assert!(
            error.to_string().contains("delete selector matches 2"),
            "{error}"
        );
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 2);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-route {}", describe_prefix(&block))));
    }

    #[test]
    fn cleanup_keeps_the_record_when_a_nexthop_route_ignores_the_interface() {
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
        let recorded = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
        let mut foreign = recorded.clone();
        // A route that uses a nexthop object can ignore the output interface,
        // so the request can select it even though the dump reports none.
        foreign.oif = None;
        control.put_route_observed(ObservedRouteKey {
            key: foreign,
            gateway: false,
            multipath: false,
            encap: false,
            nexthop: true,
            unexpected: false,
        });

        let error = routes.remove().unwrap_err();

        assert!(
            error.to_string().contains("not the recorded object"),
            "{error}"
        );
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 1);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-route {}", describe_prefix(&recorded))));
    }

    #[test]
    fn cleanup_leaves_a_foreign_route_at_the_block_prefix() {
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
        control.clear_objects();
        // The recorded block route is gone and a unicast route now owns the
        // prefix in the dedicated table. The block delete request would select
        // it, so the cleanup must keep the record and send no delete.
        let mut foreign = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
        foreign.metric = Some(IPV6_DEFAULT_METRIC);
        control.put_route(foreign);
        let block = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);

        let error = routes.remove().unwrap_err();

        assert!(
            error.to_string().contains("not the recorded object"),
            "{error}"
        );
        assert!(routes.has_installed_routes());
        assert_eq!(control.route_count(), 1);
        assert!(!control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-route {}", describe_prefix(&block))));
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
    fn install_timeout_after_apply_with_every_dump_omitting_the_route_records_the_all_omission_window(
    ) {
        let control = Arc::new(FakeControl::default());
        // Calls zero to three are the empty-table and free-priority reads.
        // Call eight adds the first route. The fake applies it and then reports
        // a timeout.
        control.timeout_call(8, true);
        let key = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
        // One empty-table read before the add, then every rollback read. The
        // rollback deletes the rules in its first round, so it needs two more
        // absent rounds before it accepts the route as gone.
        control.hide_route_for(key.clone(), 1 + REMOVAL_ROUNDS);
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
        assert!(
            !routes.has_installed_routes(),
            "the two absent reads release the record"
        );
        assert_eq!(
            control.route_count(),
            1,
            "the fake still holds the route that the add may have applied"
        );
        assert!(
            !control
                .calls()
                .iter()
                .any(|call| call == &format!("delete-route {}", describe_prefix(&key))),
            "the rollback must not delete a route that no read showed"
        );
        assert!(
            !routes.claim_path.exists(),
            "the claim is released after the absence agreement"
        );
        // The fake cannot prove that a real dump omits a stable route every
        // time. Do not describe this result as an absence proof. This is the
        // all-omission window that the cleanup docs name: a route hidden from
        // every dump survives after the claim is gone.
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
    fn cleanup_does_not_release_a_route_that_one_dump_omitted() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        routes.install_for_test().unwrap();
        let key = routes.routes[0].clone();
        routes.routes = vec![key.clone()];
        control.put_route(key.clone());
        // One complete read omits the stable route. A single-dump cleanup
        // would call the record clean and release the claim with the route
        // still installed. The cleanup must read again and delete it.
        control.hide_route_for(key.clone(), 1);

        routes.remove().unwrap();

        assert_eq!(control.route_count(), 0, "the omitted route was deleted");
        assert!(control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-route {}", describe_prefix(&key))));
        assert!(!routes.has_installed_routes());
    }

    #[test]
    fn cleanup_does_not_release_a_rule_that_one_dump_omitted() {
        let control = Arc::new(FakeControl::default());
        let mut routes =
            RouteManager::with_control(TEST_IFNAME, Ipv6Policy::Forward, control.clone()).unwrap();
        routes.install_for_test().unwrap();
        routes.routes.clear();
        let rule = RuleKey::tunnel(libc::AF_INET as u8);
        routes.rules = vec![rule.clone()];
        control.put_rule(rule.clone());
        control.hide_rule_for(rule.clone(), 1);

        routes.remove().unwrap();

        assert_eq!(control.rule_count(), 0, "the omitted rule was deleted");
        assert!(control
            .calls()
            .iter()
            .any(|call| call == &format!("delete-rule {}", rule.priority)));
        assert!(!routes.has_installed_routes());
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
        // The delete carries the output interface name. The kernel compares the
        // stored name even when the device is gone, so a rule at the same
        // priority and table with another output interface cannot match.
        assert!(message
            .windows(TEST_OUTER_IFNAME.len())
            .any(|window| window == TEST_OUTER_IFNAME.as_bytes()));
        let mut reply = message.clone();
        write_u16(&mut reply[4..6], RTM_NEWRULE);
        assert_eq!(parse_rule_reply(&reply).unwrap(), outer);
        assert_eq!(outer.protocol, ROUTE_PROTOCOL_ID);

        let message = encode_rule_change(10, &tunnel, true);
        assert!(!message
            .windows(TEST_OUTER_IFNAME.len())
            .any(|window| window == TEST_OUTER_IFNAME.as_bytes()));
        let mut reply = message.clone();
        write_u16(&mut reply[4..6], RTM_NEWRULE);
        assert_eq!(parse_rule_reply(&reply).unwrap(), tunnel);
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
        let mut priority = None;
        visit_attrs(&message[NLMSG_HDRLEN + 12..], |kind, value| {
            if kind == RTA_PRIORITY && value.len() == 4 {
                priority = Some(read_u32(value));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            priority, None,
            "an IPv4 route with the default metric sends none"
        );

        let v6 = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
        let message = encode_route_change(13, &v6, false);
        let payload = &message[NLMSG_HDRLEN..];
        assert_eq!(payload[0], libc::AF_INET6 as u8);
        assert_eq!(payload[1], 3);
        assert_eq!(payload[7], RTN_BLACKHOLE);
        let mut oif = None;
        let mut priority = None;
        visit_attrs(&payload[12..], |kind, value| {
            match kind {
                RTA_OIF if value.len() == 4 => oif = Some(read_u32(value)),
                RTA_PRIORITY if value.len() == 4 => priority = Some(read_u32(value)),
                _ => {}
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(oif, None, "a blackhole route names no device");
        assert_eq!(priority, Some(IPV6_DEFAULT_METRIC));

        // The IPv6 delete carries the metric, so the kernel cannot match a
        // route with a different priority at the same prefix.
        let message = encode_route_change(14, &v6, true);
        let mut priority = None;
        visit_attrs(&message[NLMSG_HDRLEN + 12..], |kind, value| {
            if kind == RTA_PRIORITY && value.len() == 4 {
                priority = Some(read_u32(value));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(priority, Some(IPV6_DEFAULT_METRIC));
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
    fn table_dump_request_names_the_table_attribute() {
        let table = encode_route_table_dump(16, libc::AF_INET as u8, TUNNEL_TABLE);
        assert_eq!(read_u16(&table[4..6]), RTM_GETROUTE);
        assert_eq!(read_u16(&table[6..8]) & NLM_F_DUMP, NLM_F_DUMP);
        let payload = &table[NLMSG_HDRLEN..];
        assert_eq!(payload[0], libc::AF_INET as u8);
        assert_eq!(payload[4], 0, "the table selector is an attribute");
        let mut observed = None;
        visit_attrs(&payload[12..], |kind, value| {
            if kind == RTA_TABLE {
                assert_eq!(value.len(), 4);
                observed = Some(read_u32(value));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(observed, Some(TUNNEL_TABLE));
    }

    #[test]
    fn dump_state_accepts_a_filtered_complete_reply() {
        let sequence = 17;
        let route = test_netlink_message_flags(
            RTM_NEWROUTE,
            NLM_F_MULTI | NLM_F_DUMP_FILTERED,
            sequence,
            &[],
        );
        let done = test_netlink_message_flags(
            NLMSG_DONE,
            NLM_F_MULTI | NLM_F_DUMP_FILTERED,
            sequence,
            &0i32.to_ne_bytes(),
        );
        let datagram = [route, done].concat();
        let mut state = DumpState::default();
        state.consume(&datagram, sequence, RTM_NEWROUTE).unwrap();
        assert!(state.done);
        match state.finish() {
            DumpAttempt::Complete(reply) => {
                assert!(reply.filtered);
                assert_eq!(reply.messages.len(), 1);
            }
            _ => panic!("a complete dump must finish as a complete reply"),
        }
    }

    #[test]
    fn dump_state_flags_an_interrupt_on_a_data_message() {
        let sequence = 18;
        let route =
            test_netlink_message_flags(RTM_NEWROUTE, NLM_F_MULTI | NLM_F_DUMP_INTR, sequence, &[]);
        let done =
            test_netlink_message_flags(NLMSG_DONE, NLM_F_MULTI, sequence, &0i32.to_ne_bytes());
        let mut state = DumpState::default();
        state.consume(&route, sequence, RTM_NEWROUTE).unwrap();
        assert!(!state.done);
        state.consume(&done, sequence, RTM_NEWROUTE).unwrap();
        assert!(state.done);
        assert!(matches!(state.finish(), DumpAttempt::Inconsistent));
    }

    #[test]
    fn dump_state_flags_an_interrupt_on_done() {
        let sequence = 19;
        let done = test_netlink_message_flags(
            NLMSG_DONE,
            NLM_F_MULTI | NLM_F_DUMP_INTR,
            sequence,
            &0i32.to_ne_bytes(),
        );
        let mut state = DumpState::default();
        state.consume(&done, sequence, RTM_NEWROUTE).unwrap();
        assert!(state.done);
        assert!(matches!(state.finish(), DumpAttempt::Inconsistent));
    }

    #[test]
    fn dump_state_accepts_an_absent_table_only_from_a_bare_done_status() {
        let sequence = 20;
        let done = test_netlink_message(NLMSG_DONE, sequence, &(-libc::ENOENT).to_ne_bytes());
        let mut state = DumpState::default();
        state.consume(&done, sequence, RTM_NEWROUTE).unwrap();
        assert!(state.done);
        assert!(matches!(state.finish(), DumpAttempt::EmptyTable));
    }

    #[test]
    fn dump_state_refuses_an_absent_table_after_a_data_message() {
        let sequence = 21;
        let route = test_netlink_message_flags(RTM_NEWROUTE, NLM_F_MULTI, sequence, &[]);
        let done = test_netlink_message(NLMSG_DONE, sequence, &(-libc::ENOENT).to_ne_bytes());
        let datagram = [route, done].concat();
        let mut state = DumpState::default();
        state.consume(&datagram, sequence, RTM_NEWROUTE).unwrap();
        assert!(state.done);
        assert!(matches!(
            state.finish(),
            DumpAttempt::Failed(errno) if errno == libc::ENOENT
        ));
    }

    #[test]
    fn dump_state_refuses_an_absent_table_when_the_dump_was_interrupted() {
        let sequence = 22;
        let done = test_netlink_message_flags(
            NLMSG_DONE,
            NLM_F_MULTI | NLM_F_DUMP_INTR,
            sequence,
            &(-libc::ENOENT).to_ne_bytes(),
        );
        let mut state = DumpState::default();
        state.consume(&done, sequence, RTM_NEWROUTE).unwrap();
        assert!(state.done);
        assert!(matches!(state.finish(), DumpAttempt::Inconsistent));
    }

    #[test]
    fn dump_state_does_not_accept_an_error_message_as_an_absent_table() {
        let sequence = 23;
        let error = test_netlink_message(NLMSG_ERROR, sequence, &(-libc::ENOENT).to_ne_bytes());
        let mut state = DumpState::default();
        let error = state.consume(&error, sequence, RTM_NEWROUTE).unwrap_err();
        assert!(matches!(error, ReplyError::Kernel(errno) if errno == libc::ENOENT));
        assert!(!state.done);
    }

    #[test]
    fn dump_state_reports_another_negative_done_status() {
        let sequence = 24;
        let done = test_netlink_message(NLMSG_DONE, sequence, &(-libc::EPERM).to_ne_bytes());
        let mut state = DumpState::default();
        state.consume(&done, sequence, RTM_NEWROUTE).unwrap();
        assert!(state.done);
        assert!(matches!(
            state.finish(),
            DumpAttempt::Failed(errno) if errno == libc::EPERM
        ));
    }

    #[test]
    fn dump_state_refuses_a_list_over_the_bound() {
        let sequence = 25;
        let mut state = DumpState {
            messages: vec![Vec::new(); MAX_DUMP_MESSAGES],
            ..DumpState::default()
        };
        let route = test_netlink_message(RTM_NEWROUTE, sequence, &[]);
        let error = state.consume(&route, sequence, RTM_NEWROUTE).unwrap_err();
        assert!(
            matches!(error, ReplyError::Malformed(message) if message == "netlink dump is too large")
        );
    }

    #[test]
    fn select_route_table_keeps_only_the_named_table() {
        let sequence = 22;
        let recorded = test_netlink_message(
            RTM_NEWROUTE,
            sequence,
            &test_route_payload(
                IPV4_FIRST_HALF,
                TUNNEL_TABLE,
                ROUTE_PROTOCOL_ID,
                RTN_UNICAST,
                0,
                Some(TEST_IFINDEX),
                &[],
            ),
        );
        let foreign = test_netlink_message(
            RTM_NEWROUTE,
            sequence,
            &test_route_payload(
                IPV4_SECOND_HALF,
                RT_TABLE_MAIN,
                ROUTE_PROTOCOL_ID,
                RTN_UNICAST,
                0,
                Some(TEST_IFINDEX),
                &[],
            ),
        );
        let selected =
            select_route_table(vec![recorded, foreign], libc::AF_INET as u8, TUNNEL_TABLE).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].key.table, TUNNEL_TABLE);
        assert_eq!(
            selected[0].key.destination,
            IPV4_FIRST_HALF.address().octets().to_vec()
        );
    }

    #[test]
    fn dump_retry_is_bounded_and_stops_on_a_kernel_error() {
        let attempts = Cell::new(0);
        let result = retry_dump(|| {
            attempts.set(attempts.get() + 1);
            Ok(DumpAttempt::Inconsistent)
        });
        assert!(matches!(result, Err(ReplyError::Inconsistent)));
        assert_eq!(attempts.get(), DUMP_ATTEMPTS);

        let attempts = Cell::new(0);
        let result = retry_dump(|| {
            let attempt = attempts.get();
            attempts.set(attempt + 1);
            if attempt == 0 {
                Ok(DumpAttempt::Inconsistent)
            } else {
                Ok(DumpAttempt::Complete(DumpReply {
                    messages: Vec::new(),
                    filtered: true,
                }))
            }
        });
        match result.unwrap() {
            DumpAttempt::Complete(reply) => {
                assert!(reply.filtered);
                assert!(reply.messages.is_empty());
            }
            _ => panic!("a consistent complete attempt must win"),
        }
        assert_eq!(attempts.get(), 2);

        let attempts = Cell::new(0);
        let result = retry_dump(|| {
            attempts.set(attempts.get() + 1);
            Err(ReplyError::Kernel(libc::EINVAL))
        });
        assert!(matches!(result, Err(ReplyError::Kernel(errno)) if errno == libc::EINVAL));
        assert_eq!(attempts.get(), 1);
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
        assert_eq!(parsed.protocol, ROUTE_PROTOCOL_ID);
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
            unexpected: false,
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
            unexpected: false,
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
            unexpected: false,
        };
        observed.key.oif = Some(1);
        assert!(route_is_recorded(&[observed], &key));
        let mut other = ObservedRouteKey {
            key: key.clone(),
            gateway: false,
            multipath: false,
            encap: false,
            nexthop: false,
            unexpected: false,
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
            lower: None,
            master: None,
            link_netnsid: None,
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
        assert_eq!(route.scope, RT_SCOPE_UNIVERSE);
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
        assert!(!route.unexpected);
    }

    #[test]
    fn ipv6_route_reply_accepts_the_default_preference_and_cacheinfo() {
        // A kernel IPv6 reply reports RTA_CACHEINFO and RTA_PREF on every
        // route, and a blackhole in the dedicated table reports the loopback
        // interface. The owned block route must stay clean so that cleanup and
        // the start gate can accept it.
        let extra = [
            test_cacheinfo(0),
            test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
            test_attr(RTA_PRIORITY, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_BLACKHOLE,
            0,
            Some(1),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 45, &payload);
        let route = parse_ipv6_route_reply(&message).unwrap();
        assert_eq!(route.priority, Some(IPV6_DEFAULT_METRIC));
        assert!(
            !route.unexpected,
            "the default preference and cacheinfo are not unmodeled attributes"
        );
        let selected =
            select_route_table(vec![message], libc::AF_INET6 as u8, TUNNEL_TABLE).unwrap();
        let key = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].is_clean());
        assert!(
            route_is_recorded(&selected, &key),
            "the owned block route is removable"
        );
    }

    #[test]
    fn ipv6_route_reply_reads_a_kernel_shaped_forward_reply() {
        // The reply carries the attributes that `rt6_fill_node` writes for a
        // plain unicast route in the tunnel table: destination, output
        // interface, metric, preference, and cacheinfo. The cache counters are
        // arbitrary live values; an owned route has no expiry.
        let extra = [
            test_cacheinfo(0),
            test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
            test_attr(RTA_PRIORITY, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 51, &payload);
        let route = parse_ipv6_route_reply(&message).unwrap();
        assert_eq!(route.prefix, IPV6_GLOBAL_UNICAST);
        assert_eq!(route.ifindex, Some(TEST_IFINDEX));
        assert_eq!(route.priority, Some(IPV6_DEFAULT_METRIC));
        assert!(
            !route.unexpected,
            "the kernel cacheinfo attribute is modeled and benign"
        );
        let selected =
            select_route_table(vec![message], libc::AF_INET6 as u8, TUNNEL_TABLE).unwrap();
        let key = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
        assert_eq!(selected.len(), 1);
        assert!(selected[0].is_clean());
        assert!(
            route_is_recorded(&selected, &key),
            "the owned forward route is removable"
        );
    }

    #[test]
    fn ipv6_route_reply_rejects_a_malformed_cacheinfo() {
        // The kernel always writes one `struct rta_cacheinfo`. A shorter,
        // longer, or duplicate value is not a shape that this parser models,
        // so the read fails instead of guessing.
        for value in [&[][..], &[0u8; 4][..], &[0u8; 28][..], &[0u8; 36][..]] {
            let extra = [test_attr(RTA_CACHEINFO, value)];
            let payload = test_ipv6_route_payload(
                IPV6_GLOBAL_UNICAST,
                TUNNEL_TABLE,
                ROUTE_PROTOCOL_ID,
                RTN_UNICAST,
                0,
                Some(TEST_IFINDEX),
                &extra,
            );
            let message = test_netlink_message(RTM_NEWROUTE, 52, &payload);
            assert_eq!(
                parse_ipv6_route_reply(&message).unwrap_err(),
                RouteVerifyError::MalformedReply(
                    "IPv6 route cacheinfo attribute has the wrong length"
                ),
                "a cacheinfo attribute of {} bytes is not a valid read",
                value.len()
            );
        }
        let extra = [test_cacheinfo(0), test_cacheinfo(0)];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 53, &payload);
        assert_eq!(
            parse_ipv6_route_reply(&message).unwrap_err(),
            RouteVerifyError::MalformedReply("route message has two cacheinfo attributes")
        );
    }

    #[test]
    fn ipv6_route_reply_keeps_expiring_routes_as_unowned_candidates() {
        for expires in [i32::MIN, -1, 0, 1, i32::MAX] {
            let extra = [
                test_cacheinfo(expires),
                test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
                test_attr(RTA_PRIORITY, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
            ];
            let payload = test_ipv6_route_payload(
                IPV6_GLOBAL_UNICAST,
                TUNNEL_TABLE,
                ROUTE_PROTOCOL_ID,
                RTN_BLACKHOLE,
                0,
                Some(1),
                &extra,
            );
            let message = test_netlink_message(RTM_NEWROUTE, 54, &payload);
            let selected =
                select_route_table(vec![message], libc::AF_INET6 as u8, TUNNEL_TABLE).unwrap();
            let key = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
            assert_eq!(selected.len(), 1);
            assert!(
                key.delete_selects(&selected[0]),
                "expiry {expires} remains a candidate"
            );
            assert_eq!(selected[0].is_clean(), expires == 0, "expiry {expires}");
            assert_eq!(
                route_is_recorded(&selected, &key),
                expires == 0,
                "expiry {expires}"
            );
        }
    }

    #[test]
    fn ipv6_cacheinfo_wire_layout_uses_the_expiry_field() {
        // Linux UAPI rta_cacheinfo has eight 32-bit fields. Build this wire
        // value independently of the parser constants and fixture helper.
        for expires in [0_i32, -1, 1] {
            let mut attribute = [0u8; 36];
            attribute[0..2].copy_from_slice(&36u16.to_ne_bytes());
            attribute[2..4].copy_from_slice(&12u16.to_ne_bytes());
            attribute[4..8].copy_from_slice(&7u32.to_ne_bytes());
            attribute[12..16].copy_from_slice(&expires.to_ne_bytes());
            attribute[32..36].copy_from_slice(&9u32.to_ne_bytes());
            let extra = [
                attribute.to_vec(),
                test_attr(20, &[0]),
                test_attr(6, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
            ];
            let payload = test_ipv6_route_payload(
                IPV6_GLOBAL_UNICAST,
                TUNNEL_TABLE,
                ROUTE_PROTOCOL_ID,
                RTN_UNICAST,
                0,
                Some(TEST_IFINDEX),
                &extra,
            );
            let message = test_netlink_message(RTM_NEWROUTE, 54, &payload);
            let selected =
                select_route_table(vec![message], libc::AF_INET6 as u8, TUNNEL_TABLE).unwrap();
            let key = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
            assert!(key.delete_selects(&selected[0]));
            assert_eq!(route_is_recorded(&selected, &key), expires == 0);
        }
    }

    #[test]
    fn cloned_ipv6_route_is_a_candidate_but_not_owned() {
        let extra = [
            test_cacheinfo(0),
            test_attr(20, &[0]),
            test_attr(6, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_BLACKHOLE,
            0x200,
            Some(1),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 54, &payload);
        let selected =
            select_route_table(vec![message], libc::AF_INET6 as u8, TUNNEL_TABLE).unwrap();
        let key = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
        assert!(key.delete_selects(&selected[0]));
        assert!(!selected[0].is_clean());
        assert!(!route_is_recorded(&selected, &key));
    }

    #[test]
    fn cloned_ipv4_route_is_a_candidate_but_not_owned() {
        let payload = test_route_payload(
            IPV4_FIRST_HALF,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0x200,
            Some(TEST_IFINDEX),
            &[],
        );
        let message = test_netlink_message(RTM_NEWROUTE, 55, &payload);
        let selected =
            select_route_table(vec![message], libc::AF_INET as u8, TUNNEL_TABLE).unwrap();
        let key = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
        assert!(key.delete_selects(&selected[0]));
        assert!(!selected[0].is_clean());
        assert!(!route_is_recorded(&selected, &key));
    }

    #[test]
    fn ipv6_block_selection_accepts_a_kernel_shaped_recorded_route() {
        // The block gate takes `route_recorded` from `route_is_recorded` over
        // the parsed dedicated table. A kernel-shaped blackhole reply with
        // cacheinfo must satisfy that input.
        let extra = [
            test_cacheinfo(0),
            test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
            test_attr(RTA_PRIORITY, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_BLACKHOLE,
            0,
            Some(1),
            &extra,
        );
        let live = select_route_table(
            vec![test_netlink_message(RTM_NEWROUTE, 55, &payload)],
            libc::AF_INET6 as u8,
            TUNNEL_TABLE,
        )
        .unwrap();
        let mut observation = good_ipv6_block_observation();
        observation.route_recorded =
            route_is_recorded(&live, &RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST));
        let proof =
            verify_ipv6_block_selection_in(&observation, &test_identity(), TUNNEL_TABLE).unwrap();
        assert_eq!(proof.prefix, IPV6_GLOBAL_UNICAST);
        assert_eq!(proof.probes_checked, DEFAULT_IPV6_PROBES.len());

        // A malformed cacheinfo is a failed read. The observer cannot produce
        // an observation, so the gate fails closed instead of calling the
        // route absent or foreign.
        let extra = [test_attr(RTA_CACHEINFO, &[0u8; 4])];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_BLACKHOLE,
            0,
            Some(1),
            &extra,
        );
        assert!(matches!(
            select_route_table(
                vec![test_netlink_message(RTM_NEWROUTE, 56, &payload)],
                libc::AF_INET6 as u8,
                TUNNEL_TABLE,
            ),
            Err(RouteVerifyError::MalformedReply(
                "IPv6 route cacheinfo attribute has the wrong length"
            ))
        ));
    }

    #[test]
    fn ipv6_route_reply_keeps_a_nondefault_preference_as_a_candidate() {
        for preference in [1u8, 3u8] {
            let extra = [
                test_cacheinfo(0),
                test_attr(RTA_PREF, &[preference]),
                test_attr(RTA_PRIORITY, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
            ];
            let payload = test_ipv6_route_payload(
                IPV6_GLOBAL_UNICAST,
                TUNNEL_TABLE,
                ROUTE_PROTOCOL_ID,
                RTN_BLACKHOLE,
                0,
                Some(1),
                &extra,
            );
            let message = test_netlink_message(RTM_NEWROUTE, 46, &payload);
            let route = parse_ipv6_route_reply(&message).unwrap();
            assert!(
                route.unexpected,
                "preference {preference} is not the value that this module adds"
            );
            let selected =
                select_route_table(vec![message], libc::AF_INET6 as u8, TUNNEL_TABLE).unwrap();
            let key = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
            assert!(!selected[0].is_clean());
            assert!(!route_is_recorded(&selected, &key));
            assert_eq!(
                routes_selected_by(&selected, &key).len(),
                1,
                "the route stays a delete candidate"
            );
        }
    }

    #[test]
    fn ipv6_route_reply_rejects_a_malformed_preference() {
        for value in [&[][..], &[0u8, 0][..]] {
            let extra = [test_attr(RTA_PREF, value)];
            let payload = test_ipv6_route_payload(
                IPV6_GLOBAL_UNICAST,
                TUNNEL_TABLE,
                ROUTE_PROTOCOL_ID,
                RTN_UNICAST,
                0,
                Some(TEST_IFINDEX),
                &extra,
            );
            let message = test_netlink_message(RTM_NEWROUTE, 47, &payload);
            assert_eq!(
                parse_ipv6_route_reply(&message).unwrap_err(),
                RouteVerifyError::MalformedReply(
                    "IPv6 route preference attribute has the wrong length"
                ),
                "a preference attribute of {} bytes is not a valid read",
                value.len()
            );
        }
    }

    #[test]
    fn ipv6_route_reply_rejects_a_duplicate_preference() {
        let extra = [
            test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
            test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
        ];
        let payload = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &extra,
        );
        let message = test_netlink_message(RTM_NEWROUTE, 48, &payload);
        assert_eq!(
            parse_ipv6_route_reply(&message).unwrap_err(),
            RouteVerifyError::MalformedReply("route message has two preference attributes")
        );
    }

    #[test]
    fn route_reply_parsers_mark_an_unmodeled_attribute() {
        let ipv4_extra = [test_attr(31, &[0u8; 4])];
        let ipv4 = test_route_payload(
            IPV4_FIRST_HALF,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &ipv4_extra,
        );
        let ipv4 = parse_route_reply(&test_netlink_message(RTM_NEWROUTE, 40, &ipv4)).unwrap();
        assert!(ipv4.unexpected);
        let selected = select_route_table(
            vec![test_netlink_message(
                RTM_NEWROUTE,
                40,
                &test_route_payload(
                    IPV4_FIRST_HALF,
                    TUNNEL_TABLE,
                    ROUTE_PROTOCOL_ID,
                    RTN_UNICAST,
                    0,
                    Some(TEST_IFINDEX),
                    &ipv4_extra,
                ),
            )],
            libc::AF_INET as u8,
            TUNNEL_TABLE,
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
        assert!(!selected[0].is_clean());

        let ipv6_extra = [test_attr(31, &[0u8; 4])];
        let ipv6 = test_ipv6_route_payload(
            IPV6_GLOBAL_UNICAST,
            TUNNEL_TABLE,
            ROUTE_PROTOCOL_ID,
            RTN_UNICAST,
            0,
            Some(TEST_IFINDEX),
            &ipv6_extra,
        );
        let ipv6 = parse_ipv6_route_reply(&test_netlink_message(RTM_NEWROUTE, 41, &ipv6)).unwrap();
        assert!(ipv6.unexpected);
    }

    #[test]
    fn ipv6_route_reply_keeps_a_nonzero_scope() {
        let payload = test_ipv6_route_payload_raw(
            TestIpv6RouteSpec {
                destination: Some(IPV6_GLOBAL_UNICAST.address()),
                destination_length: 3,
                source: None,
                source_length: 0,
                scope: RT_SCOPE_LINK,
                table: TUNNEL_TABLE,
                protocol: ROUTE_PROTOCOL_ID,
                route_type: RTN_UNICAST,
                flags: 0,
                ifindex: Some(TEST_IFINDEX),
            },
            &[],
        );
        let message = test_netlink_message(RTM_NEWROUTE, 42, &payload);
        let route = parse_ipv6_route_reply(&message).unwrap();
        assert_eq!(route.scope, RT_SCOPE_LINK);
        let selected =
            select_route_table(vec![message], libc::AF_INET6 as u8, TUNNEL_TABLE).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].key.scope, RT_SCOPE_LINK);
        let recorded = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
        assert!(
            !route_is_recorded(&selected, &recorded),
            "the IPv6 scope is part of the recorded key"
        );
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
                scope: RT_SCOPE_UNIVERSE,
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
                    scope: RT_SCOPE_UNIVERSE,
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
                    scope: RT_SCOPE_UNIVERSE,
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
                    scope: RT_SCOPE_UNIVERSE,
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
    fn physical_outer_rejects_renamed_virtual_and_stacked_links() {
        let identity = test_outer();
        let base = test_outer_link();
        assert!(prove_outer_link(&base, &identity).is_ok());
        for kind in ["bridge", "veth", "vlan", "dummy"] {
            let mut link = base.clone();
            link.kind = Some(kind.into());
            assert!(prove_outer_link(&link, &identity).is_err());
        }
        for field in 0..5 {
            let mut link = base.clone();
            match field {
                0 => link.lower = Some(identity.ifindex() + 1),
                1 => link.master = Some(identity.ifindex() + 1),
                2 => link.link_netnsid = Some(0),
                3 => link.ifindex += 1,
                _ => link.name = "renamed".into(),
            }
            assert!(prove_outer_link(&link, &identity).is_err());
        }
    }

    #[test]
    fn physical_sysfs_evidence_rejects_virtual_and_changed_index() {
        use std::os::unix::fs::symlink;
        static NEXT_TEST_DIR: AtomicU32 = AtomicU32::new(1);
        let root = std::env::temp_dir().join(format!(
            "hotspotshade-sysfs-{}-{}",
            std::process::id(),
            NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let device = root.join("devices/pci0000/adapter");
        let link = device.join("net/wlan0");
        std::fs::create_dir_all(&link).unwrap();
        std::fs::create_dir_all(root.join("class/net")).unwrap();
        symlink(&link, root.join("class/net/wlan0")).unwrap();
        symlink(&device, link.join("device")).unwrap();
        std::fs::write(link.join("ifindex"), "9\n").unwrap();
        let original = physical_sysfs_evidence(&root, &test_outer()).unwrap();
        let same = physical_sysfs_evidence(&root, &test_outer()).unwrap();
        assert!(original.same_device(&same).unwrap());
        assert!(original.check_retained(&same).is_ok());
        let observe = |read_physical: &dyn Fn() -> io::Result<PhysicalOuterIdentity>| {
            link_ready_with(
                &original,
                |_| Ok(TEST_OUTER_IFINDEX),
                |_| Ok(test_outer_link()),
                |_| read_physical(),
                |_| Ok(true),
            )
        };
        assert!(observe(&|| physical_sysfs_evidence(&root, &test_outer())).unwrap());
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::Other,
        ] {
            assert_eq!(
                observe(&|| Err(io::Error::new(kind, "unreadable")))
                    .unwrap_err()
                    .kind(),
                kind
            );
        }
        assert!(!observe(&|| Err(io::Error::new(io::ErrorKind::NotConnected, "changed"))).unwrap());
        assert!(!link_ready_with(
            &original,
            |_| Err(io::Error::from_raw_os_error(libc::ENODEV)),
            |_| panic!("link read"),
            |_| panic!("sysfs read"),
            |_| panic!("address read")
        )
        .unwrap());
        assert_eq!(
            link_ready_with(
                &original,
                |_| Err(io::Error::from_raw_os_error(libc::EIO)),
                |_| panic!("link read"),
                |_| panic!("sysfs read"),
                |_| panic!("address read")
            )
            .unwrap_err()
            .raw_os_error(),
            Some(libc::EIO)
        );
        assert!(!link_ready_with(
            &original,
            |_| Ok(TEST_OUTER_IFINDEX),
            |_| Err(RouteVerifyError::LinkMissing {
                ifindex: TEST_OUTER_IFINDEX
            }),
            |_| panic!("sysfs read"),
            |_| panic!("address read")
        )
        .unwrap());
        assert!(link_ready_with(
            &original,
            |_| Ok(TEST_OUTER_IFINDEX),
            |_| Err(RouteVerifyError::MalformedReply("bad link")),
            |_| panic!("sysfs read"),
            |_| panic!("address read")
        )
        .is_err());
        assert!(!link_ready_with(
            &original,
            |_| Ok(TEST_OUTER_IFINDEX + 1),
            |_| panic!("link read"),
            |_| panic!("sysfs read"),
            |_| panic!("address read")
        )
        .unwrap());
        assert!(!link_ready_with(
            &original,
            |_| Ok(TEST_OUTER_IFINDEX),
            |_| {
                let mut link = test_outer_link();
                link.flags = 0;
                Ok(link)
            },
            |_| panic!("sysfs read"),
            |_| panic!("address read")
        )
        .unwrap());
        assert_eq!(
            link_ready_with(
                &original,
                |_| Ok(TEST_OUTER_IFINDEX),
                |_| Ok(test_outer_link()),
                |_| physical_sysfs_evidence(&root, &test_outer()),
                |_| Err(io::Error::from_raw_os_error(libc::EIO))
            )
            .unwrap_err()
            .raw_os_error(),
            Some(libc::EIO)
        );
        // Recreate the link at the same path with the same name and index.
        // Open descriptors retain the old inode while the new one is read.
        let old_link = device.join("net/old-wlan0");
        std::fs::rename(&link, &old_link).unwrap();
        std::fs::create_dir(&link).unwrap();
        symlink(&device, link.join("device")).unwrap();
        std::fs::write(link.join("ifindex"), "9\n").unwrap();
        let replacement = physical_sysfs_evidence(&root, &test_outer()).unwrap();
        assert!(!original.same_device(&replacement).unwrap());
        assert_eq!(
            original.check_retained(&replacement).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(!observe(&|| physical_sysfs_evidence(&root, &test_outer())).unwrap());
        std::fs::write(link.join("ifindex"), "invalid\n").unwrap();
        assert!(observe(&|| physical_sysfs_evidence(&root, &test_outer())).is_err());
        std::fs::write(link.join("ifindex"), "10\n").unwrap();
        assert!(physical_sysfs_evidence(&root, &test_outer()).is_err());
        std::fs::remove_file(link.join("device")).unwrap();
        assert!(physical_sysfs_evidence(&root, &test_outer()).is_err());
        let virtual_device = root.join("devices/virtual/net/wlan0");
        std::fs::create_dir_all(&virtual_device).unwrap();
        symlink(&virtual_device, link.join("device")).unwrap();
        assert!(physical_sysfs_evidence(&root, &test_outer()).is_err());
        // Replacing the entire device keeps the path, name, and index but
        // changes the retained device directory as well as the link.
        std::fs::rename(&device, root.join("devices/pci0000/old-adapter")).unwrap();
        std::fs::create_dir_all(&link).unwrap();
        symlink(&device, link.join("device")).unwrap();
        std::fs::write(link.join("ifindex"), "9\n").unwrap();
        let replacement_device = physical_sysfs_evidence(&root, &test_outer()).unwrap();
        assert_ne!(
            original.device_handle.metadata().unwrap().ino(),
            replacement_device.device_handle.metadata().unwrap().ino()
        );
        assert_eq!(original.device_path, replacement_device.device_path);
        assert!(original.check_retained(&replacement_device).is_err());
        std::fs::remove_dir_all(root).unwrap();
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
    fn netlink_link_reply_rejects_duplicate_and_malformed_metadata() {
        for attrs in [
            vec![test_attr(IFLA_IFNAME, b"wlan0\0")],
            vec![test_attr(IFLA_LINK, &[1, 2])],
            vec![
                test_attr(IFLA_LINK, &9u32.to_ne_bytes()),
                test_attr(IFLA_LINK, &9u32.to_ne_bytes()),
            ],
            vec![test_attr(
                IFLA_LINKINFO,
                &test_attr(IFLA_INFO_KIND, b"veth"),
            )],
            vec![test_attr(IFLA_LINKINFO, &[])],
            vec![
                test_attr(IFLA_LINKINFO, &test_attr(IFLA_INFO_KIND, b"veth\0")),
                test_attr(IFLA_LINKINFO, &test_attr(IFLA_INFO_KIND, b"veth\0")),
            ],
        ] {
            let mut payload = test_link_payload(
                TEST_OUTER_IFINDEX,
                TEST_OUTER_IFNAME,
                None,
                libc::ARPHRD_ETHER,
                IFF_UP,
            );
            for attr in attrs {
                payload.extend_from_slice(&attr);
            }
            let message = test_netlink_message(RTM_NEWLINK, 4, &payload);
            assert!(parse_link_reply(&message).is_err());
        }
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

    /// Hermetic tests for the crash-time route claim. They use the fake control
    /// layer and a temporary claim file. They create no device, change no route,
    /// and resolve no host interface.
    mod route_recovery {
        use super::*;

        const STALE_PID: u32 = 4242;

        fn claim_record(tun: &str, ifindex: u32, outer: &str, policy: Ipv6Policy) -> ClaimRecord {
            ClaimRecord::new(tun, ifindex, outer, policy, test_claim_identity())
        }

        fn acquire(path: &Path) -> io::Result<RouteClaim> {
            RouteClaim::acquire(path, false, &test_claim_identity())
        }

        fn write_stale_claim(path: &Path, policy: Ipv6Policy) -> ClaimRecord {
            let mut record = claim_record(TEST_IFNAME, TEST_IFINDEX, TEST_OUTER_IFNAME, policy);
            record.pid = STALE_PID;
            std::fs::write(path, record.encode()).unwrap();
            record
        }

        /// Write a claim with the private mode that production uses. The
        /// operator path refuses a group- or world-readable file.
        fn write_private_claim(path: &Path, text: &str) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn put_recorded(control: &FakeControl, record: &ClaimRecord) {
            for rule in record.rules() {
                control.put_rule(rule);
            }
            for route in record.routes() {
                control.put_route(route);
            }
        }

        /// A stale record with the current record plus four distinct
        /// predecessors. This is the largest list that the strict format
        /// accepts. A replacement that adds one more needs the absence proof.
        fn claim_with_four_priors() -> ClaimRecord {
            let mut record = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
            );
            record.pid = STALE_PID;
            // Every predecessor uses forward mode. A block record and a
            // forward record at one prefix have the same IPv6 delete selector,
            // and the recovery would refuse that ambiguous pair before it can
            // exercise compaction. Distinct tunnel indexes keep each forward
            // selector exact.
            let priors = [
                claim_record(
                    TEST_IFNAME,
                    TEST_IFINDEX + 1,
                    TEST_OUTER_IFNAME,
                    Ipv6Policy::Forward,
                ),
                claim_record(TEST_IFNAME, TEST_IFINDEX + 2, "eth0", Ipv6Policy::Forward),
                claim_record(TEST_IFNAME, TEST_IFINDEX + 3, "eth1", Ipv6Policy::Forward),
                claim_record(
                    TEST_IFNAME,
                    TEST_IFINDEX + 4,
                    TEST_OUTER_IFNAME,
                    Ipv6Policy::Forward,
                ),
            ];
            for prior in priors {
                record.absorb_predecessor(&prior).unwrap();
            }
            assert_eq!(record.prior.len(), MAX_CLAIM_PRIORS);
            record
        }

        fn manager(policy: Ipv6Policy, control: &Arc<FakeControl>, path: &Path) -> RouteManager {
            let mut routes =
                RouteManager::with_control(TEST_IFNAME, policy, control.clone()).unwrap();
            routes.claim_path = path.to_owned();
            routes
        }

        fn install(routes: &mut RouteManager) -> io::Result<()> {
            install_at(routes, TEST_IFINDEX)
        }

        fn install_at(routes: &mut RouteManager, ifindex: u32) -> io::Result<()> {
            let tun = fake_tun_named(ifindex, TEST_IFNAME);
            let mut observation = good_observation();
            observation.link.ifindex = ifindex;
            let proof = routes
                .verify_interface_with(&tun, &FakeObserver::from_observation(observation))
                .unwrap();
            routes.install_verified(&proof, &tun, TEST_OUTER_IFNAME)
        }

        fn assert_unchanged(control: &FakeControl) {
            assert!(control
                .calls()
                .iter()
                .all(|call| !call.starts_with("delete-") && !call.starts_with("add-")));
        }

        fn deletes(control: &FakeControl) -> Vec<String> {
            control
                .calls()
                .into_iter()
                .filter(|call| call.starts_with("delete-"))
                .collect()
        }

        #[test]
        fn route_recovery_adopts_a_crashed_forward_claim() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            install(&mut routes).unwrap();

            let report = routes.last_recovery().unwrap();
            assert_eq!(report.removed_rules, 4);
            assert_eq!(report.removed_routes, 3);
            assert_eq!(report.stale_pid, STALE_PID);
            assert_eq!(
                deletes(&control),
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
            // The new run owns the claim, and it holds its own objects.
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains(&format!("pid {}", std::process::id())));
            assert!(!text.contains(&format!("pid {STALE_PID}")));
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);

            routes.remove().unwrap();
            assert!(!path.exists());
            assert_eq!(control.route_count(), 0);
            assert_eq!(control.rule_count(), 0);
        }

        #[test]
        fn route_recovery_clears_a_crashed_block_blackhole() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Block);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Block, &control, &path);

            install(&mut routes).unwrap();

            assert_eq!(
                deletes(&control),
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
            assert_eq!(routes.last_recovery().unwrap().removed_routes, 3);
            assert_eq!(control.route_count(), 3);
            assert!(control
                .route_keys()
                .iter()
                .any(|key| key.route_type == RTN_BLACKHOLE));
        }

        #[test]
        fn route_recovery_refuses_a_claim_held_by_a_live_owner() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let held = acquire(&path).unwrap();
            assert!(held.stale().is_some());
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains(&format!("pid {STALE_PID}")));
            drop(held);
        }

        #[test]
        fn route_recovery_refuses_a_foreign_route_in_the_tunnel_table() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let foreign = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24).unwrap();
            control.put_route(RouteKey::ipv4(foreign, TEST_IFINDEX));
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not recoverable"));
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 4, "the foreign route was left");
            assert_eq!(control.rule_count(), 4);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_refuses_a_rule_with_a_foreign_selector() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            control.put_rule(RuleKey::outer(libc::AF_INET as u8, "eth0"));
            control.put_rule(RuleKey::tunnel(libc::AF_INET as u8));
            control.put_rule(RuleKey::outer(libc::AF_INET6 as u8, TEST_OUTER_IFNAME));
            control.put_rule(RuleKey::tunnel(libc::AF_INET6 as u8));
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not recoverable"));
            assert_unchanged(&control);
            assert_eq!(control.rule_count(), 4);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_refuses_a_damaged_claim() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            std::fs::write(&path, "hotspotshade-route-claim 1\nbogus value\n").unwrap();
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_unchanged(&control);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_refuses_a_claim_behind_a_symlink() {
            let control = Arc::new(FakeControl::default());
            let target = unique_test_claim_path();
            let record = write_stale_claim(&target, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let link = unique_test_claim_path();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let mut routes = manager(Ipv6Policy::Forward, &control, &link);

            let error = install(&mut routes).unwrap_err();

            assert!(!error.to_string().is_empty());
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 3);
            assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        }

        #[test]
        fn route_recovery_refuses_an_inconclusive_read() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            control.fail_reads();
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not recoverable"));
            assert!(control
                .calls()
                .iter()
                .all(|call| !call.starts_with("delete-")));
            assert_eq!(control.route_count(), 3);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_accepts_an_empty_claim() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            write_private_claim(&path, "");
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            install(&mut routes).unwrap();

            assert!(deletes(&control).is_empty());
            assert!(routes.last_recovery().is_none());
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            assert!(path.exists());
            routes.remove().unwrap();
            assert!(!path.exists());
        }

        #[test]
        fn route_claim_rejects_a_file_replaced_before_the_lock() {
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            let replaced = path.clone();
            CLAIM_OPEN_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |hook_path: &Path| {
                    assert_eq!(hook_path, replaced);
                    // The exact window that the identity check covers: the
                    // handle was opened, then the path was unlinked and a new
                    // claim file was created before the lock was taken.
                    std::fs::remove_file(&replaced).unwrap();
                    std::fs::write(&replaced, "").unwrap();
                }));
            });

            let claim = acquire(&path).unwrap();

            let at_path = std::fs::metadata(&path).unwrap();
            let held = claim.file.metadata().unwrap();
            assert_eq!(held.dev(), at_path.dev());
            assert_eq!(held.ino(), at_path.ino());
            assert_eq!(held.nlink(), 1, "the locked file is still linked");
            assert!(claim.stale().is_none(), "the replacement file is empty");
            // A second handle cannot take the same claim file.
            let error = acquire(&path).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            drop(claim);
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_unlink_leaves_a_replacement_in_place() {
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            let claim = acquire(&path).unwrap();
            assert!(claim.stale().is_some());
            // An uncooperative process replaces the path while the lock is
            // held. A compliant peer takes the lock first and cannot do this,
            // but the unlink must not remove the new file either way.
            std::fs::remove_file(&path).unwrap();
            let mut replacement = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Block,
            );
            replacement.pid = STALE_PID + 1;
            std::fs::write(&path, replacement.encode()).unwrap();

            let error = claim.unlink().unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            assert!(error.to_string().contains("left in place"));
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                replacement.encode()
            );
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_unlink_accepts_an_absent_path() {
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            let claim = acquire(&path).unwrap();
            std::fs::remove_file(&path).unwrap();

            claim.unlink().unwrap();

            assert!(!path.exists());
        }

        #[test]
        fn route_claim_recreates_a_path_removed_before_the_lock() {
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            let removed = path.clone();
            CLAIM_OPEN_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |hook_path: &Path| {
                    assert_eq!(hook_path, removed);
                    // Only the first attempt is disturbed. The retry creates
                    // the claim again and must not keep the unlinked inode.
                    std::fs::remove_file(&removed).unwrap();
                }));
            });

            let claim = acquire(&path).unwrap();

            let held = claim.file.metadata().unwrap();
            let at_path = std::fs::metadata(&path).unwrap();
            assert_eq!(held.dev(), at_path.dev());
            assert_eq!(held.ino(), at_path.ino());
            assert_eq!(held.nlink(), 1);
            assert!(claim.stale().is_none(), "the removed record is gone");
            drop(claim);
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_takes_a_nonempty_replacement_record() {
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            let mut replacement = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Block,
            );
            replacement.pid = STALE_PID + 1;
            let replacement_at = path.clone();
            let replacement_text = replacement.encode();
            CLAIM_OPEN_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |hook_path: &Path| {
                    assert_eq!(hook_path, replacement_at);
                    // The old inode held a forward-mode record. The path now
                    // names a new inode with a different record. The handle
                    // must adopt the new one, never the stale inode it locked.
                    std::fs::remove_file(&replacement_at).unwrap();
                    std::fs::write(&replacement_at, &replacement_text).unwrap();
                }));
            });

            let claim = acquire(&path).unwrap();

            assert_eq!(claim.stale(), Some(&replacement));
            let held = claim.file.metadata().unwrap();
            let at_path = std::fs::metadata(&path).unwrap();
            assert_eq!(held.dev(), at_path.dev());
            assert_eq!(held.ino(), at_path.ino());
            assert_eq!(held.nlink(), 1);
            let error = acquire(&path).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            drop(claim);
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_refuses_a_hardlinked_file() {
            let path = unique_test_claim_path();
            let other = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            std::fs::hard_link(&path, &other).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);

            let error = acquire(&path).unwrap_err();

            assert!(
                error.to_string().contains("single-link"),
                "the refusal names the link rule: {error}"
            );
            assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);
            assert!(path.exists());
            assert!(other.exists());
            std::fs::remove_file(&path).unwrap();
            std::fs::remove_file(&other).unwrap();
        }

        #[test]
        fn route_claim_device_probe_maps_only_missing_errors_to_absent() {
            fn present(_name: &str) -> io::Result<u32> {
                Ok(TEST_IFINDEX)
            }
            fn enodev(_name: &str) -> io::Result<u32> {
                Err(io::Error::from_raw_os_error(libc::ENODEV))
            }
            fn enxio(_name: &str) -> io::Result<u32> {
                Err(io::Error::from_raw_os_error(libc::ENXIO))
            }
            fn eio(_name: &str) -> io::Result<u32> {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
            fn eperm(_name: &str) -> io::Result<u32> {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            }
            fn not_found(_name: &str) -> io::Result<u32> {
                // A library error with no kernel errno is not proof that the
                // name is free.
                Err(io::Error::new(io::ErrorKind::NotFound, "lookup failed"))
            }
            fn enoent(_name: &str) -> io::Result<u32> {
                // Only ENODEV and ENXIO are proof. ENOENT is not.
                Err(io::Error::from_raw_os_error(libc::ENOENT))
            }
            fn absent_index(_index: u32) -> io::Result<String> {
                Err(io::Error::from_raw_os_error(libc::ENXIO))
            }
            fn present_index(_index: u32) -> io::Result<String> {
                Ok("eth9".to_owned())
            }
            fn failed_index(_index: u32) -> io::Result<String> {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }

            assert_eq!(
                probe_claimed_device(present, absent_index, TEST_IFNAME, TEST_IFINDEX).unwrap(),
                ClaimedDevice::Present(TEST_IFINDEX)
            );
            assert_eq!(
                probe_claimed_device(enodev, absent_index, TEST_IFNAME, TEST_IFINDEX).unwrap(),
                ClaimedDevice::Absent
            );
            assert_eq!(
                probe_claimed_device(enxio, absent_index, TEST_IFNAME, TEST_IFINDEX).unwrap(),
                ClaimedDevice::Absent
            );
            assert_eq!(
                probe_claimed_device(enodev, present_index, TEST_IFNAME, TEST_IFINDEX).unwrap(),
                ClaimedDevice::IndexReused {
                    ifindex: TEST_IFINDEX,
                    name: "eth9".to_owned(),
                }
            );
            for probe in [eio, eperm, not_found, enoent] {
                assert!(
                    probe_claimed_device(probe, absent_index, TEST_IFNAME, TEST_IFINDEX).is_err(),
                    "only ENODEV and ENXIO prove absence"
                );
            }
            assert!(
                probe_claimed_device(enodev, failed_index, TEST_IFNAME, TEST_IFINDEX).is_err(),
                "an index read failure is not proof that the index is free"
            );
        }

        #[test]
        fn route_recovery_refuses_a_reused_tunnel_index() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            // The name is free, but the recorded index now belongs to another
            // interface. A recorded route names the index, so a delete could
            // act on that device.
            routes.probe_device_index = |_| Err(io::Error::from_raw_os_error(libc::ENODEV));
            routes.probe_device_name = |_| Ok("eth9".to_owned());

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("now belongs to"), "{error}");
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_refuses_an_inconclusive_index_lookup() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.probe_device_index = |_| Err(io::Error::from_raw_os_error(libc::ENODEV));
            routes.probe_device_name = |_| Err(io::Error::from_raw_os_error(libc::EIO));

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("cannot look up"), "{error}");
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_refuses_a_surviving_tunnel_device() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.probe_device_index = |_| Ok(TEST_IFINDEX + 1);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("still exists"));
            assert_unchanged(&control);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_refuses_an_inconclusive_device_lookup() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.probe_device_index = |_| Err(io::Error::from_raw_os_error(libc::EIO));

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not recoverable"));
            assert!(
                error
                    .to_string()
                    .contains("cannot look up the claimed tunnel device"),
                "{error}"
            );
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_treats_enxio_as_an_absent_device() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.probe_device_index = |_| Err(io::Error::from_raw_os_error(libc::ENXIO));

            install(&mut routes).unwrap();

            let report = routes.last_recovery().unwrap();
            assert_eq!(report.removed_rules, 4);
            assert_eq!(report.removed_routes, 3);
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
        }

        #[test]
        fn route_recovery_stale_call_refuses_a_surviving_device() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            // `recover_stale` has no new device, so any live device is
            // ambiguous, even at the recorded index.
            routes.probe_device_index = |_| Ok(TEST_IFINDEX);

            let error = routes.recover_stale().unwrap_err();

            assert!(error.to_string().contains("still exists"), "{error}");
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_stale_call_refuses_an_inconclusive_device_lookup() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.probe_device_index = |_| Err(io::Error::from_raw_os_error(libc::EIO));

            let error = routes.recover_stale().unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("cannot look up the claimed tunnel device"),
                "{error}"
            );
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_removes_a_partial_claim() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            control.put_rule(RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME));
            control.put_rule(RuleKey::tunnel(libc::AF_INET as u8));
            control.put_route(RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX));
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            install(&mut routes).unwrap();

            let report = routes.last_recovery().unwrap();
            assert_eq!(report.removed_rules, 2);
            assert_eq!(report.removed_routes, 1);
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
        }

        #[test]
        fn route_recovery_deletes_a_recorded_route_that_one_dump_omitted() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let hidden = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
            // The first complete read omits a stable route. The recovery must
            // not treat the record as gone from that read alone.
            control.hide_route_for(hidden.clone(), 1);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            install(&mut routes).unwrap();

            let report = routes.last_recovery().unwrap();
            assert_eq!(report.removed_routes, 3);
            assert_eq!(report.removed_rules, 4);
            // The new install would fail with EEXIST if the omitted route had
            // survived the recovery.
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            assert_eq!(
                deletes(&control)
                    .iter()
                    .filter(|call| *call == &format!("delete-route {}", describe_prefix(&hidden)))
                    .count(),
                1,
                "the omitted route is deleted on a later read, not blindly"
            );
        }

        #[test]
        fn route_recovery_deletes_a_recorded_rule_that_one_dump_omitted() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let hidden = RuleKey::outer(libc::AF_INET6 as u8, TEST_OUTER_IFNAME);
            control.hide_rule_for(hidden.clone(), 1);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            install(&mut routes).unwrap();

            let report = routes.last_recovery().unwrap();
            assert_eq!(report.removed_rules, 4);
            assert_eq!(report.removed_routes, 3);
            // A surviving recorded rule would make the new add fail with
            // EEXIST for its family and priority, so a successful install
            // proves the omitted rule was deleted.
            assert_eq!(control.rule_count(), 4);
        }

        #[test]
        fn route_recovery_refuses_a_foreign_route_that_appears_after_a_read() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let foreign = RouteKey::ipv4(
                Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24).unwrap(),
                TEST_IFINDEX,
            );
            control.put_foreign_route(foreign.clone());
            // The first read hides the foreign route, so the first round
            // accepts the recorded set. A later read shows it. The recovery
            // must revalidate every read and keep the claim instead of
            // releasing it on the first agreeing snapshot.
            control.hide_route_for(foreign.clone(), 1);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not recoverable"), "{error}");
            assert!(error.to_string().contains("198.51.100.0/24"), "{error}");
            assert!(
                path.exists(),
                "the claim stays after a foreign object appears on a later read"
            );
            assert_eq!(control.route_count(), 1, "the foreign route is left");
        }

        #[test]
        fn route_recovery_refuses_a_foreign_rule_that_appears_after_a_read() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut foreign = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
            // The delete request carries protocol 196, so a rule with another
            // protocol survives that delete. It differs in a delete selector,
            // not only in a selector that the request omits.
            foreign.protocol = 100;
            control.put_rule(foreign.clone());
            control.hide_rule_for(foreign.clone(), 1);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not recoverable"), "{error}");
            assert!(
                error
                    .to_string()
                    .contains(&format!("priority {}", OUTER_RULE_PRIORITY)),
                "{error}"
            );
            assert!(path.exists());
            // The recorded IPv4 outer rule is removed because its delete
            // request carries protocol 196 and cannot match the foreign rule.
            // The foreign rule remains, and the later read still refuses the
            // recovery because no recorded delete selector covers it.
            assert_eq!(control.rule_count(), 1);
            assert_eq!(control.rule_keys()[0].protocol, 100);
        }

        #[test]
        fn route_recovery_fails_closed_when_an_object_keeps_returning() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            // A concurrent privileged process recreates the route after every
            // delete. No round is stable, so the bounded rounds must fail
            // closed and keep the claim instead of reporting a clean recovery.
            control.reinsert_route(RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX));
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("cannot confirm"), "{error}");
            assert!(
                path.exists(),
                "the claim stays when the list keeps changing"
            );
            assert_eq!(control.route_count(), 1);
        }

        #[test]
        fn route_recovery_refuses_a_mismatched_policy_route() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Block);
            for rule in claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Block,
            )
            .rules()
            {
                control.put_rule(rule);
            }
            control.put_route(RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX));
            let mut routes = manager(Ipv6Policy::Block, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not recoverable"));
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 1);
        }

        #[test]
        fn route_recovery_leaves_no_claim_after_a_refused_install() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            control.put_route(RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX));
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not empty"));
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 1);
            assert!(!path.exists(), "the unused claim was removed");
        }

        #[test]
        fn route_recovery_refuses_a_public_claim_directory() {
            use std::os::unix::fs::PermissionsExt;

            let control = Arc::new(FakeControl::default());
            let dir = unique_test_claim_path();
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let path = dir.join("route-claim");
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.claim_strict = true;

            let error = install(&mut routes).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_unchanged(&control);
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn route_recovery_refuses_a_public_claim_file() {
            use std::os::unix::fs::PermissionsExt;

            let control = Arc::new(FakeControl::default());
            let dir = unique_test_claim_path();
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = dir.join("route-claim");
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.claim_strict = true;

            let error = install(&mut routes).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_unchanged(&control);
            assert_eq!(control.route_count(), 3);
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn route_recovery_exposes_the_public_recovery_call() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Block);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Block, &control, &path);

            let report = routes.recover_stale().unwrap();

            assert_eq!(report.removed_rules, 4);
            assert_eq!(report.removed_routes, 3);
            assert_eq!(report.stale_pid, STALE_PID);
            assert_eq!(control.route_count(), 0);
            assert_eq!(control.rule_count(), 0);
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                record.encode(),
                "the recovered record stays for the next start"
            );
            assert!(!routes.recover_stale().unwrap().removed_any());
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                record.encode(),
                "a clean recovery still keeps the selectors"
            );
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_recovery_removes_a_kernel_shaped_cached_block_route() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Block);
            for rule in record.rules() {
                control.put_rule(rule);
            }
            // The kernel reply for the recorded blackhole carries the loopback
            // output interface, the default preference, and RTA_CACHEINFO.
            // Parse that shape rather than storing a clean synthetic route, so
            // the recovery exercises the real parser.
            let extra = [
                test_cacheinfo(0),
                test_attr(RTA_PREF, &[RTA_PREF_MEDIUM]),
                test_attr(RTA_PRIORITY, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
            ];
            let payload = test_ipv6_route_payload(
                IPV6_GLOBAL_UNICAST,
                TUNNEL_TABLE,
                ROUTE_PROTOCOL_ID,
                RTN_BLACKHOLE,
                0,
                Some(1),
                &extra,
            );
            let live = select_route_table(
                vec![test_netlink_message(RTM_NEWROUTE, 57, &payload)],
                libc::AF_INET6 as u8,
                TUNNEL_TABLE,
            )
            .unwrap();
            for route in record.routes() {
                if route.family == libc::AF_INET6 as u8 && route.route_type == RTN_BLACKHOLE {
                    assert_eq!(live.len(), 1);
                    control.put_route_observed(live[0].clone());
                } else {
                    control.put_route(route);
                }
            }
            let mut routes = manager(Ipv6Policy::Block, &control, &path);

            let report = routes.recover_stale().unwrap();

            assert_eq!(report.removed_rules, 4);
            assert_eq!(report.removed_routes, 3);
            assert_eq!(report.stale_pid, STALE_PID);
            assert_eq!(control.route_count(), 0);
            assert_eq!(control.rule_count(), 0);
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                record.encode(),
                "the recovered record stays for the next start"
            );
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_recovery_keeps_claim_for_expiring_or_cloned_block_route() {
            for (expires, flags) in [(1, 0), (-1, 0), (0, 0x200)] {
                let control = Arc::new(FakeControl::default());
                let path = unique_test_claim_path();
                let record = write_stale_claim(&path, Ipv6Policy::Block);
                for rule in record.rules() {
                    control.put_rule(rule);
                }
                let extra = [
                    test_cacheinfo(expires),
                    test_attr(20, &[0]),
                    test_attr(6, &IPV6_DEFAULT_METRIC.to_ne_bytes()),
                ];
                let payload = test_ipv6_route_payload(
                    IPV6_GLOBAL_UNICAST,
                    TUNNEL_TABLE,
                    ROUTE_PROTOCOL_ID,
                    RTN_BLACKHOLE,
                    flags,
                    Some(1),
                    &extra,
                );
                let live = select_route_table(
                    vec![test_netlink_message(RTM_NEWROUTE, 57, &payload)],
                    libc::AF_INET6 as u8,
                    TUNNEL_TABLE,
                )
                .unwrap();
                for route in record.routes() {
                    if route.family == libc::AF_INET6 as u8 && route.route_type == RTN_BLACKHOLE {
                        control.put_route_observed(live[0].clone());
                    } else {
                        control.put_route(route);
                    }
                }
                let mut routes = manager(Ipv6Policy::Block, &control, &path);
                assert!(
                    routes.recover_stale().is_err(),
                    "expiry {expires}, flags {flags}"
                );
                assert_eq!(std::fs::read_to_string(&path).unwrap(), record.encode());
                assert!(!control
                    .calls()
                    .iter()
                    .any(|call| call.starts_with("delete-")));
                std::fs::remove_file(&path).unwrap();
            }
        }

        #[test]
        fn route_claim_format_is_strict() {
            let record = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Block,
            );
            let text = record.encode();
            assert_eq!(ClaimRecord::parse(&text).unwrap(), record);
            let base = format!(
                "{CLAIM_HEADER}\nboot 11111111-2222-3333-4444-555555555555\nnetns 4 4026531840\npid 1\ntun {TEST_IFNAME} {TEST_IFINDEX}\nouter {TEST_OUTER_IFNAME}\nipv6 block\n"
            );
            assert_eq!(
                ClaimRecord::parse(&base).unwrap().identity,
                test_claim_identity()
            );
            // A version 2 record without predecessors is still readable. A
            // version 3 record keeps every predecessor selector.
            let version_two = base.replace(CLAIM_HEADER, CLAIM_HEADER_V2);
            assert_eq!(
                ClaimRecord::parse(&version_two).unwrap(),
                ClaimRecord::parse(&base).unwrap()
            );
            let mut replaced = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX + 1,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
            );
            replaced
                .absorb_predecessor(&claim_record(
                    TEST_IFNAME,
                    TEST_IFINDEX,
                    TEST_OUTER_IFNAME,
                    Ipv6Policy::Block,
                ))
                .unwrap();
            let text = replaced.encode();
            assert!(text.contains("prior "), "{text}");
            let parsed = ClaimRecord::parse(&text).unwrap();
            assert_eq!(parsed, replaced);
            assert!(parsed
                .routes()
                .contains(&RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX)));
            assert!(parsed
                .routes()
                .contains(&RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX + 1)));
            assert_eq!(
                parsed
                    .tunnels()
                    .iter()
                    .filter(|(name, index)| {
                        *name == TEST_IFNAME
                            && (*index == TEST_IFINDEX || *index == TEST_IFINDEX + 1)
                    })
                    .count(),
                2
            );
            // A duplicate or malformed predecessor is not a claim.
            assert!(ClaimRecord::parse(&format!(
                "{text}prior {TEST_IFNAME} {} {TEST_OUTER_IFNAME} forward\n",
                TEST_IFINDEX + 1
            ))
            .is_err());
            assert!(ClaimRecord::parse(&format!(
                "{CLAIM_HEADER}\nboot 11111111-2222-3333-4444-555555555555\nnetns 4 4026531840\npid 1\ntun {TEST_IFNAME} {TEST_IFINDEX}\nouter {TEST_OUTER_IFNAME}\nipv6 block\nprior {TEST_IFNAME} 0 {TEST_OUTER_IFNAME} block\n"
            ))
            .is_err());
            // A version 1 claim has no boot or namespace line and cannot be
            // adopted. A damaged header is refused the same way.
            assert!(ClaimRecord::parse(
                "hotspotshade-route-claim 1\npid 1\ntun hs-tun0 7\nouter wlan0\nipv6 block\n"
            )
            .is_err());
            assert!(ClaimRecord::parse("hotspotshade-route-claim 2\n").is_err());
            assert!(ClaimRecord::parse("pid 1\n").is_err());
            assert!(ClaimRecord::parse(&format!(
                "{CLAIM_HEADER}\nboot 11111111-2222-3333-4444-555555555555\nnetns 4 4026531840\npid 1\ntun {TEST_IFNAME} {TEST_IFINDEX}\nouter {TEST_OUTER_IFNAME}\nipv6 inherit\n"
            ))
            .is_err());
            assert!(ClaimRecord::parse(&format!(
                "{CLAIM_HEADER}\nboot 11111111-2222-3333-4444-555555555555\nnetns 4 4026531840\npid 1\ntun {TEST_IFNAME} {TEST_IFINDEX}\nouter {TEST_IFNAME}\nipv6 block\n"
            ))
            .is_err());
            assert!(ClaimRecord::parse(&format!(
                "{CLAIM_HEADER}\nboot 11111111-2222-3333-4444-555555555555\nnetns 4 4026531840\npid 1\ntun {TEST_IFNAME} {TEST_IFINDEX}\ntun {TEST_IFNAME} {TEST_IFINDEX}\nouter {TEST_OUTER_IFNAME}\nipv6 block\n"
            ))
            .is_err());
            assert!(ClaimRecord::parse(&format!(
                "{CLAIM_HEADER}\nboot 11111111-2222-3333-4444-555555555555\nnetns 4 4026531840\npid 1\ntun {TEST_IFNAME} 0\nouter {TEST_OUTER_IFNAME}\nipv6 block\n"
            ))
            .is_err());
            assert!(ClaimRecord::parse(&format!(
                "{CLAIM_HEADER}\nboot 11111111-2222-3333-4444-555555555555\nnetns 4 4026531840\npid 1\ntun {TEST_IFNAME} {TEST_IFINDEX}\nouter {TEST_OUTER_IFNAME}\nipv6 block\nextra 1\n"
            ))
            .is_err());
            // An unknown or twice-written identity line is not a claim.
            assert!(ClaimRecord::parse(&base.replace("boot ", "booty ")).is_err());
            assert!(ClaimRecord::parse(&format!(
                "{base}boot 11111111-2222-3333-4444-555555555555\n"
            ))
            .is_err());
            assert!(ClaimRecord::parse(&format!("{base}netns 4 4026531840\n")).is_err());
            assert!(ClaimRecord::parse(&base.replace("netns 4 4026531840", "netns 4 0")).is_err());
            assert!(ClaimRecord::parse(
                &base.replace("11111111-2222-3333-4444-555555555555", "not-a-uuid")
            )
            .is_err());
        }

        #[test]
        fn route_claim_inspection_reports_identity_and_damage() {
            let path = unique_test_claim_path();
            let mut record = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
            );
            record.pid = STALE_PID;
            write_private_claim(&path, &record.encode());

            let inspection = inspect_claim_file(&path, Some(&test_claim_identity()));
            assert!(inspection.present);
            assert!(!inspection.locked);
            assert!(inspection.private);
            assert!(inspection.usable);
            assert_eq!(inspection.same_boot, Some(true));
            assert_eq!(inspection.same_namespace, Some(true));
            assert_eq!(inspection.stale_pid, Some(STALE_PID));
            assert!(inspection.problem.is_none());

            write_private_claim(&path, "damaged claim\n");
            let inspection = inspect_claim_file(&path, Some(&test_claim_identity()));
            assert!(inspection.present);
            assert!(!inspection.usable);
            assert!(inspection.problem.is_some());
            assert!(inspection.stale_pid.is_none());
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_inspection_names_a_foreign_namespace_and_boot() {
            let path = unique_test_claim_path();
            let mut record = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
            );
            record.pid = STALE_PID;
            write_private_claim(&path, &record.encode());

            let namespace = ClaimIdentity::new(5, 4_026_531_840, TEST_BOOT_ID).unwrap();
            let inspection = inspect_claim_file(&path, Some(&namespace));
            assert_eq!(inspection.same_boot, Some(true));
            assert_eq!(inspection.same_namespace, Some(false));
            assert!(inspection
                .problem
                .as_deref()
                .is_some_and(|text| text.contains("another network namespace")));

            let boot = ClaimIdentity::new(4, 4_026_531_840, OLD_BOOT_ID).unwrap();
            let inspection = inspect_claim_file(&path, Some(&boot));
            assert_eq!(inspection.same_boot, Some(false));
            assert!(inspection
                .problem
                .as_deref()
                .is_some_and(|text| text.contains("before the current boot")));
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_refuses_another_namespace_and_discards_an_earlier_boot() {
            let path = unique_test_claim_path();
            let foreign = ClaimIdentity::new(5, 4_026_531_840, TEST_BOOT_ID).unwrap();
            let mut record = ClaimRecord::new(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
                foreign,
            );
            record.pid = STALE_PID;
            write_private_claim(&path, &record.encode());
            let error = acquire(&path).unwrap_err();
            assert!(
                error.to_string().contains("another network namespace"),
                "{error}"
            );
            assert!(path.exists(), "a foreign claim is left in place");

            let old = ClaimIdentity::new(4, 4_026_531_840, OLD_BOOT_ID).unwrap();
            let mut record = ClaimRecord::new(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
                old,
            );
            record.pid = STALE_PID;
            write_private_claim(&path, &record.encode());
            let claim = acquire(&path).unwrap();
            assert!(claim.discarded_previous_boot());
            assert!(claim.stale().is_none());
            assert_eq!(claim.file.metadata().unwrap().len(), 0);
            drop(claim);
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn clear_route_claim_removes_only_a_file_that_cannot_name_live_objects() {
            let path = unique_test_claim_path();
            // A non-empty damaged claim can still name a live object. Removing
            // it would orphan that object, so the operator path refuses it.
            write_private_claim(&path, "damaged claim\n");
            let error = clear_corrupt_claim_file(&path, &test_claim_identity()).unwrap_err();
            assert!(
                error.to_string().contains("may describe live objects"),
                "{error}"
            );
            assert!(path.exists());

            std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
            let error = clear_corrupt_claim_file(&path, &test_claim_identity()).unwrap_err();
            assert!(error.to_string().contains("not text"), "{error}");
            assert!(path.exists());

            // An empty claim names nothing and is safe to remove, even when
            // its mode is wrong. A valid current record is refused below
            // regardless of its mode.
            std::fs::write(&path, "").unwrap();
            assert!(clear_corrupt_claim_file(&path, &test_claim_identity()).unwrap());
            assert!(!path.exists());

            let mut record = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
            );
            record.pid = STALE_PID;
            write_private_claim(&path, &record.encode());
            let error = clear_corrupt_claim_file(&path, &test_claim_identity()).unwrap_err();
            assert!(
                error.to_string().contains("can describe live objects"),
                "{error}"
            );
            assert!(path.exists(), "a current record is left for the start");

            let old = ClaimIdentity::new(4, 4_026_531_840, OLD_BOOT_ID).unwrap();
            let mut old_record = ClaimRecord::new(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
                old,
            );
            old_record.pid = STALE_PID;
            write_private_claim(&path, &old_record.encode());
            assert!(clear_corrupt_claim_file(&path, &test_claim_identity()).unwrap());
            assert!(!path.exists());

            let foreign = ClaimIdentity::new(5, 4_026_531_840, TEST_BOOT_ID).unwrap();
            let mut foreign_record = ClaimRecord::new(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
                foreign,
            );
            foreign_record.pid = STALE_PID;
            write_private_claim(&path, &foreign_record.encode());
            let error = clear_corrupt_claim_file(&path, &test_claim_identity()).unwrap_err();
            assert!(
                error.to_string().contains("another network namespace"),
                "{error}"
            );
            assert!(path.exists(), "a foreign claim is left in place");
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn clear_route_claim_refuses_a_live_owner() {
            let path = unique_test_claim_path();
            let record = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
            );
            write_private_claim(&path, &record.encode());
            let held = acquire(&path).unwrap();
            let error = clear_corrupt_claim_file(&path, &test_claim_identity()).unwrap_err();
            assert!(error.to_string().contains("live process"), "{error}");
            assert!(path.exists());
            drop(held);
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_refuses_a_fifo_without_blocking_the_start() {
            use std::os::unix::ffi::OsStrExt;
            let path = unique_test_claim_path();
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            let error = acquire(&path).unwrap_err();
            assert!(error.to_string().contains("not a regular file"), "{error}");
            let inspection = inspect_claim_file(&path, Some(&test_claim_identity()));
            assert!(inspection.present);
            assert!(!inspection.usable);
            assert!(inspection.problem.is_some());
            let error = clear_corrupt_claim_file(&path, &test_claim_identity()).unwrap_err();
            assert!(error.to_string().contains("not a regular file"));
            assert!(path.exists());
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_start_is_idempotent_and_blocks_a_second_manager() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let mut first = manager(Ipv6Policy::Forward, &control, &path);
            first.claim_start().unwrap();
            first.claim_start().unwrap();

            let mut second = manager(Ipv6Policy::Forward, &control, &path);
            let error = second.claim_start().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert_unchanged(&control);

            drop(first);
            second.claim_start().unwrap();
            second.remove().unwrap();
            assert!(!path.exists());
        }

        #[test]
        fn failed_cleanup_keeps_the_lock_until_the_process_drops_the_manager() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let mut first = manager(Ipv6Policy::Forward, &control, &path);
            install(&mut first).unwrap();
            control.fail_next_delete();

            let error = first.remove().unwrap_err();
            assert!(error.to_string().contains("injected delete failure"));
            assert!(first.has_installed_routes());
            assert!(path.exists());

            let mut second = manager(Ipv6Policy::Forward, &control, &path);
            let error = second.claim_start().unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::WouldBlock,
                "a live manager keeps its claim lock after a failed cleanup"
            );

            drop(first);
            let error = second.claim_start().unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::WouldBlock,
                "the dropped manager retains its claim lock in this process"
            );
            // A process exit releases the lock. Model that exit so the next
            // manager can recover the remaining recorded route.
            release_retained_claim(&path);
            second.claim_start().unwrap();
            assert!(second.last_recovery().is_some());
            assert_eq!(control.route_count(), 0);
            assert_eq!(control.rule_count(), 0);
            assert!(
                path.exists(),
                "the recovered record stays until a replacement is written"
            );
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.contains(&format!("pid {}", std::process::id())),
                "{text}"
            );
            assert!(text.contains("hotspotshade-route-claim"), "{text}");
            drop(second);
            // A release keeps the recovered record. The operator call proves
            // the objects gone but still keeps the selectors for the next
            // start.
            let mut cleanup = manager(Ipv6Policy::Forward, &control, &path);
            cleanup.recover_stale().unwrap();
            assert!(path.exists());
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains("hotspotshade-route-claim"), "{text}");
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_delete_selector_models_the_kernel_request() {
            let v6 = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
            let mut live = plain_observed(v6.clone());
            assert!(v6.delete_selects(&live));
            live.key.metric = Some(IPV6_DEFAULT_METRIC + 1);
            assert!(!v6.delete_selects(&live), "the IPv6 metric is a selector");
            live = plain_observed(v6.clone());
            live.key.oif = None;
            assert!(
                !v6.delete_selects(&live),
                "the output interface of a plain IPv6 route is a selector"
            );
            live = plain_observed(v6.clone());
            live.nexthop = true;
            live.key.oif = None;
            assert!(
                v6.delete_selects(&live),
                "a nexthop object can ignore the output interface"
            );
            live = plain_observed(v6.clone());
            live.multipath = true;
            live.key.oif = Some(TEST_IFINDEX + 1);
            assert!(
                v6.delete_selects(&live),
                "a multipath route keeps one interface per nexthop"
            );
            live = plain_observed(v6.clone());
            live.key.table = RT_TABLE_MAIN;
            assert!(!v6.delete_selects(&live), "the table is a selector");
            live = plain_observed(v6.clone());
            live.key.scope = RT_SCOPE_LINK;
            assert!(
                v6.delete_selects(&live),
                "the model keeps another scope as a candidate"
            );
            live = plain_observed(v6.clone());
            live.key.protocol = 0;
            assert!(
                v6.delete_selects(&live),
                "the model keeps another protocol as a conservative candidate"
            );
            live = plain_observed(v6.clone());
            live.key.route_type = RTN_BLACKHOLE;
            assert!(
                v6.delete_selects(&live),
                "the IPv6 delete path ignores the route type"
            );

            let v4 = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
            let mut live = plain_observed(v4.clone());
            assert!(v4.delete_selects(&live));
            live.key.scope = RT_SCOPE_UNIVERSE;
            assert!(
                v4.delete_selects(&live),
                "the model keeps another scope as a candidate"
            );
            live = plain_observed(v4.clone());
            live.key.metric = Some(1000);
            assert!(
                v4.delete_selects(&live),
                "an IPv4 record with the default metric sends no metric selector"
            );
            live = plain_observed(v4.clone());
            live.key.tos = 16;
            assert!(
                v4.delete_selects(&live),
                "a zero TOS in the request is modeled as a wildcard, so a nonzero live TOS stays a candidate"
            );
            live = plain_observed(v4.clone());
            live.key.source_length = 8;
            live.key.source = Some(vec![10, 0, 0, 0]);
            assert!(
                v4.delete_selects(&live),
                "a zero source length in the request is modeled as a wildcard, so a source route stays a candidate"
            );
            live = plain_observed(v4.clone());
            live.key.route_type = RTN_BLACKHOLE;
            assert!(
                v4.delete_selects(&live),
                "IPv4 compares the route type, and a wider model is a conservative over-approximation"
            );

            let block = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
            let forward = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
            let block_live = plain_observed(block.clone());
            let forward_live = plain_observed(forward.clone());
            assert!(block.delete_selects(&block_live));
            assert!(forward.delete_selects(&forward_live));
            assert!(
                block.delete_selects(&forward_live),
                "the block request also selects a unicast route at the prefix, because the IPv6 delete path ignores the type"
            );
            assert!(
                !forward.delete_selects(&block_live),
                "the unicast request carries the tunnel index, and the blackhole reports none"
            );
        }

        #[test]
        fn rule_delete_selector_models_the_kernel_request() {
            let rule = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
            let mut live = rule.clone();
            assert!(rule.delete_selects(&live));
            live.protocol = 0;
            assert!(!rule.delete_selects(&live), "the protocol is a selector");
            live = rule.clone();
            live.oif = Some("eth0".into());
            assert!(!rule.delete_selects(&live), "the device name is a selector");
            live = rule.clone();
            live.table = TUNNEL_TABLE;
            assert!(!rule.delete_selects(&live), "the table is a selector");

            live = rule.clone();
            live.destination_length = 8;
            assert!(
                rule.delete_selects(&live),
                "a zero destination length is modeled as a wildcard"
            );
            live = rule.clone();
            live.source_length = 8;
            assert!(
                rule.delete_selects(&live),
                "a zero source length is modeled as a wildcard"
            );
            live = rule.clone();
            live.tos = 16;
            assert!(
                rule.delete_selects(&live),
                "a zero TOS is modeled as a wildcard"
            );
            live = rule.clone();
            live.flags = FIB_RULE_INVERT;
            assert!(
                rule.delete_selects(&live),
                "zero flags are modeled as a wildcard"
            );
            live = rule.clone();
            live.unexpected = true;
            assert!(
                rule.delete_selects(&live),
                "a rule with an unknown selector stays a candidate"
            );
            assert!(
                !rule_is_recorded(&[live], &rule),
                "the full equality check still rejects a candidate that is not the record"
            );

            let tunnel = RuleKey::tunnel(libc::AF_INET as u8);
            let mut live = tunnel.clone();
            assert!(tunnel.delete_selects(&live));
            live.oif = Some(TEST_OUTER_IFNAME.into());
            assert!(
                tunnel.delete_selects(&live),
                "a tunnel rule sends no device name, so the kernel ignores it"
            );
        }

        #[test]
        fn cleanup_refuses_a_rule_with_another_protocol() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            install(&mut routes).unwrap();
            control.clear_objects();
            let mut foreign = RuleKey::tunnel(libc::AF_INET as u8);
            foreign.protocol = 0;
            control.put_rule(foreign);

            let error = routes.remove().unwrap_err();

            assert!(error.to_string().contains("not the recorded object"));
            assert!(routes.has_installed_routes());
            assert_eq!(control.rule_count(), 1);
            assert!(!control
                .calls()
                .iter()
                .any(|call| call == "delete-rule 17001"));
            assert!(path.exists());
        }

        #[test]
        fn route_recovery_keeps_the_claim_when_a_confirm_read_keeps_omitting_a_route() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let flicker = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
            // Every round reads the route and then omits it on the delete
            // confirmation read. The route is never deleted, and a round that
            // showed it must not count as an absence read.
            control.flicker_route(flicker.clone());
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("cannot confirm"), "{error}");
            assert!(
                path.exists(),
                "the claim stays while a read shows the route"
            );
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains(&format!("pid {STALE_PID}")));
            assert_eq!(control.route_keys(), vec![flicker.clone()]);
            assert!(!deletes(&control).contains(&"delete-route 2000::/3".to_owned()));
            assert!(!control.calls().iter().any(|call| call.starts_with("add-")));

            // A later start with complete reads adopts the same record.
            control.stop_flicker();
            let mut next = manager(Ipv6Policy::Forward, &control, &path);
            install(&mut next).unwrap();
            assert_eq!(next.last_recovery().unwrap().removed_routes, 1);
            assert_eq!(control.route_count(), 3);
            next.remove().unwrap();
            assert!(!path.exists());
        }

        #[test]
        fn cleanup_keeps_the_claim_when_a_confirm_read_keeps_omitting_a_route() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            install(&mut routes).unwrap();
            let flicker = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
            control.flicker_route(flicker.clone());

            let error = routes.remove().unwrap_err();

            assert!(error.to_string().contains("could not confirm"), "{error}");
            assert!(routes.has_installed_routes(), "the IPv6 record is kept");
            assert!(
                path.exists(),
                "the claim stays while a read shows the route"
            );
            assert_eq!(control.route_keys(), vec![flicker]);
            assert_eq!(control.rule_count(), 0);

            // An explicit retry with complete reads removes the route and the
            // claim, and clears the failure.
            control.stop_flicker();
            routes.remove().unwrap();
            assert!(!routes.has_installed_routes());
            assert_eq!(control.route_count(), 0);
            assert!(!path.exists());
        }

        #[test]
        fn cleanup_keeps_the_claim_when_a_confirm_read_keeps_omitting_a_rule() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            install(&mut routes).unwrap();
            let flicker = RuleKey::outer(libc::AF_INET6 as u8, TEST_OUTER_IFNAME);
            control.flicker_rule(flicker.clone());

            let error = routes.remove().unwrap_err();

            assert!(error.to_string().contains("could not confirm"), "{error}");
            assert!(path.exists());
            assert_eq!(control.rule_keys(), vec![flicker]);
            assert_eq!(control.route_count(), 0);

            control.stop_flicker();
            routes.remove().unwrap();
            assert_eq!(control.rule_count(), 0);
            assert!(!path.exists());
        }

        #[test]
        fn install_timeout_keeps_the_record_when_one_read_omits_the_rule() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            // Calls zero to three are the empty-table and free-priority reads.
            // Call four adds the first rule. The fake applies it and then
            // reports a timeout.
            control.timeout_call(4, true);
            let applied = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
            // The first IPv4 rule read is the free-priority check. The second
            // one omits the applied rule. A record dropped on that read would
            // leave the rule behind with no claim.
            control.hide_rule_for(applied, 2);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(!routes.has_installed_routes());
            assert_eq!(control.rule_count(), 0, "the applied rule is removed");
            assert!(deletes(&control).contains(&"delete-rule 17000".to_owned()));
            assert!(!path.exists());
        }

        #[test]
        fn add_errors_separate_a_definite_failure_from_an_unknown_outcome() {
            let definite = [
                RouteVerifyError::Unavailable {
                    operation: "route control",
                    errno: libc::EEXIST,
                },
                RouteVerifyError::Unavailable {
                    operation: "netlink socket",
                    errno: libc::EMFILE,
                },
                RouteVerifyError::Unavailable {
                    operation: "netlink bind",
                    errno: libc::EPERM,
                },
                RouteVerifyError::Unavailable {
                    operation: "netlink send",
                    errno: libc::ENOBUFS,
                },
            ];
            for error in definite {
                let errno = match &error {
                    RouteVerifyError::Unavailable { errno, .. } => *errno,
                    _ => unreachable!(),
                };
                let mapped = add_error_to_io(error);
                assert!(!write_outcome_unknown(&mapped), "{mapped}");
                assert_eq!(mapped.raw_os_error(), Some(errno));
            }
            let unknown = [
                RouteVerifyError::Unavailable {
                    operation: "netlink reply",
                    errno: libc::ETIMEDOUT,
                },
                RouteVerifyError::Unavailable {
                    operation: "netlink receive",
                    errno: libc::ENOBUFS,
                },
                RouteVerifyError::Unavailable {
                    operation: "netlink poll",
                    errno: libc::EIO,
                },
                RouteVerifyError::MalformedReply("short netlink error"),
            ];
            for error in unknown {
                let mapped = add_error_to_io(error);
                assert!(write_outcome_unknown(&mapped), "{mapped}");
                assert!(mapped.to_string().contains("may have applied"));
            }
        }

        #[test]
        fn recovery_rechecks_outer_before_every_delete_and_preserves_failed_claim() {
            for policy in [Ipv6Policy::Forward, Ipv6Policy::Block] {
                let sample = claim_record(TEST_IFNAME, TEST_IFINDEX, TEST_OUTER_IFNAME, policy);
                let total = sample.routes().len() + sample.rules().len();
                assert!(total > 0);
                for failure in [io::ErrorKind::NotConnected, io::ErrorKind::PermissionDenied] {
                    for stop_at in 0..total {
                        let control = Arc::new(FakeControl::default());
                        let path = unique_test_claim_path();
                        let record = write_stale_claim(&path, policy);
                        put_recorded(&control, &record);
                        let mut routes = manager(policy, &control, &path);
                        let checks = std::cell::Cell::new(0);
                        let error = routes
                            .claim_start_with_check(&|| {
                                let n = checks.get();
                                checks.set(n + 1);
                                if n == stop_at {
                                    let message = if failure == io::ErrorKind::NotConnected {
                                        "outer_interface_changed"
                                    } else {
                                        "injected observation error"
                                    };
                                    Err(io::Error::new(failure, message))
                                } else {
                                    Ok(())
                                }
                            })
                            .unwrap_err();
                        assert!(
                            error.to_string().contains("outer interface recheck"),
                            "{error}"
                        );
                        let expected = if failure == io::ErrorKind::NotConnected {
                            "outer_interface_changed"
                        } else {
                            "injected observation error"
                        };
                        assert!(error.to_string().contains(expected), "{error}");
                        assert_eq!(checks.get(), stop_at + 1);
                        assert_eq!(deletes(&control).len(), stop_at);
                        assert_eq!(std::fs::read_to_string(&path).unwrap(), record.encode());
                        drop(routes);
                        assert!(path.exists());
                        // Operator cleanup does not depend on the failed outer link.
                        // It keeps the selectors for the next start even after
                        // the absence rounds agree.
                        let mut cleanup = manager(policy, &control, &path);
                        cleanup.recover_stale().unwrap();
                        assert_eq!(std::fs::read_to_string(&path).unwrap(), record.encode());
                        assert_eq!(control.route_count(), 0);
                        assert_eq!(control.rule_count(), 0);
                        std::fs::remove_file(&path).unwrap();
                    }
                }
            }
        }

        #[test]
        fn route_recovery_keeps_a_recovered_record_when_a_later_read_shows_an_object() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let hidden = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
            // The three recovery reads of the IPv6 table omit the route, so
            // the recovery agrees that it is gone. The start's own empty-table
            // read then shows it.
            control.hide_route_for(hidden.clone(), 3);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = routes.claim_start().unwrap_err();
            assert!(error.to_string().contains("not empty"), "{error}");
            drop(routes);

            assert!(path.exists(), "the recovered record is kept");
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains(&format!("pid {STALE_PID}")), "{text}");
            assert_eq!(control.route_keys(), vec![hidden]);
            assert!(!deletes(&control).contains(&"delete-route 2000::/3".to_owned()));

            // The next start adopts the record again and removes the route.
            // The recovered record stays in the file until the install writes
            // its replacement before the first add.
            let mut next = manager(Ipv6Policy::Forward, &control, &path);
            next.claim_start().unwrap();
            assert_eq!(next.last_recovery().unwrap().removed_routes, 1);
            assert_eq!(control.route_count(), 0);
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains(&format!("pid {STALE_PID}")), "{text}");
            install(&mut next).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.contains(&format!("pid {}", std::process::id())),
                "{text}"
            );
            assert!(!text.contains(&format!("pid {STALE_PID}")), "{text}");
            next.remove().unwrap();
            assert!(!path.exists());
        }

        #[test]
        fn route_recovery_keeps_a_recovered_record_after_a_refused_install() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let hidden = RuleKey::tunnel(libc::AF_INET as u8);
            // Recovery reads the IPv4 rules four times: the first round reads
            // the list and confirms the outer rule, and two clean rounds read
            // it once each. The tunnel rule is omitted each time. The
            // install's free-priority read then shows it.
            control.hide_rule_for(hidden.clone(), 4);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("already exists"), "{error}");
            assert!(path.exists(), "the recovered record is kept");
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains(&format!("pid {STALE_PID}")), "{text}");
            assert_eq!(control.rule_keys(), vec![hidden]);
            assert!(!control.calls().iter().any(|call| call.starts_with("add-")));
        }

        #[test]
        fn route_recovery_keeps_a_rule_hidden_for_five_dumps() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            let hidden = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
            // Only the stale rule survives. Recovery reads the IPv4 rule list
            // twice, and the start and install read it once each. The fifth
            // dump is the rollback read. Every read in the start misses the
            // rule, so the install reaches its first add.
            control.put_rule(hidden.clone());
            control.hide_rule_for(hidden.clone(), 5);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            routes.claim_start().unwrap();
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                record.encode(),
                "claim_start does not clear the recovered record"
            );
            assert_eq!(control.rule_keys(), vec![hidden.clone()]);

            // The add sees the stored rule through the kernel, not the dump.
            let error = install(&mut routes).unwrap_err();
            assert!(
                error.to_string().contains("File exists")
                    || error.to_string().contains("already exists"),
                "{error}"
            );
            assert!(
                path.exists(),
                "a failed install keeps a record for the surviving rule"
            );
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.contains(&format!("pid {}", std::process::id())),
                "{text}"
            );
            assert!(
                !text.contains(&format!("pid {STALE_PID}")),
                "the replacement is the current record: {text}"
            );
            drop(routes);
            assert!(path.exists(), "a drop keeps the recovered claim");
            assert_eq!(control.rule_count(), 0);

            let mut next = manager(Ipv6Policy::Forward, &control, &path);
            install(&mut next).unwrap();
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            next.remove().unwrap();
            assert!(!path.exists());
        }

        #[test]
        fn route_recovery_repeated_claim_start_keeps_the_recovered_record() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            routes.claim_start().unwrap();
            routes.claim_start().unwrap();

            assert_eq!(std::fs::read_to_string(&path).unwrap(), record.encode());
            assert_eq!(control.route_count(), 0);
            assert_eq!(control.rule_count(), 0);
            // The repeated call adopted the same record once. The install now
            // replaces it before its first add.
            install(&mut routes).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.contains(&format!("pid {}", std::process::id())),
                "{text}"
            );
            assert!(!text.contains(&format!("pid {STALE_PID}")), "{text}");
        }

        #[test]
        fn route_recovery_refuses_a_replacement_after_an_identity_change() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.claim_start().unwrap();
            let before = std::fs::read_to_string(&path).unwrap();
            assert_eq!(before, record.encode());

            routes.claim_identity =
                Some(ClaimIdentity::new(5, 4_026_531_840, TEST_BOOT_ID).unwrap());
            let error = routes.claim_start().unwrap_err();
            assert!(error.to_string().contains("identity changed"), "{error}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
            let error = install(&mut routes).unwrap_err();
            assert!(error.to_string().contains("identity changed"), "{error}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
            drop(routes);
            assert!(path.exists());
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_recovery_restores_the_record_after_a_failed_replacement_write() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.claim_start().unwrap();
            routes.claim.as_mut().unwrap().write_failure = Some(ClaimWriteFailure::Partial);

            let error = install(&mut routes).unwrap_err();
            assert!(
                error.to_string().contains("injected claim write failure"),
                "{error}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                record.encode(),
                "the previous record is restored"
            );
            assert!(!control.calls().iter().any(|call| call.starts_with("add-")));

            let mut next = manager(Ipv6Policy::Forward, &control, &path);
            install(&mut next).unwrap();
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            next.remove().unwrap();
            assert!(!path.exists());
        }

        #[test]
        fn route_recovery_marks_a_claim_damaged_when_the_restore_fails() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Forward);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.claim_start().unwrap();
            routes.claim.as_mut().unwrap().write_failure = Some(ClaimWriteFailure::PartialRestore);

            let error = install(&mut routes).unwrap_err();
            assert!(error.to_string().contains("marked damaged"), "{error}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), DAMAGED_CLAIM_TEXT);
            drop(routes);
            assert!(path.exists(), "a damaged claim is never released");

            let mut next = manager(Ipv6Policy::Forward, &control, &path);
            let error = next.claim_start().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(path.exists());
            assert!(clear_corrupt_claim_file(&path, &test_claim_identity()).is_err());
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_recovery_absorbs_a_predecessor_with_another_index_and_policy() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = write_stale_claim(&path, Ipv6Policy::Block);
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);
            routes.claim_start().unwrap();
            assert_eq!(control.route_count(), 0);

            install_at(&mut routes, TEST_IFINDEX + 5).unwrap();

            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.contains(&format!("tun {TEST_IFNAME} {}", TEST_IFINDEX + 5)),
                "{text}"
            );
            assert!(
                text.contains(&format!(
                    "prior {TEST_IFNAME} {TEST_IFINDEX} {TEST_OUTER_IFNAME} block"
                )),
                "{text}"
            );
            assert!(routes
                .routes
                .iter()
                .any(|route| route.oif == Some(TEST_IFINDEX)));
            assert!(routes
                .routes
                .iter()
                .any(|route| route.oif == Some(TEST_IFINDEX + 5)));
            routes.remove().unwrap();
            assert_eq!(control.route_count(), 0);
            assert_eq!(control.rule_count(), 0);
            assert!(!path.exists());
        }

        #[test]
        fn route_recovery_removes_an_empty_claim_after_a_refused_start() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            control.put_rule(RuleKey::tunnel(libc::AF_INET as u8));
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = routes.claim_start().unwrap_err();
            assert!(error.to_string().contains("already exists"), "{error}");
            // The manager holds the empty claim while it lives.
            assert!(path.exists());
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
            drop(routes);

            // The empty claim names no object, so the release removes it.
            assert!(!path.exists());
            assert_unchanged(&control);
            assert_eq!(control.rule_count(), 1);
        }

        #[test]
        fn fake_control_applies_the_recorded_delete_selectors() {
            let control = FakeControl::default();
            let outer = RuleKey::outer(libc::AF_INET as u8, TEST_OUTER_IFNAME);
            let other = RuleKey::outer(libc::AF_INET as u8, "eth0");
            control.add_rule(&outer).unwrap();
            control.add_rule(&other).unwrap();
            assert_eq!(
                control.rule_count(),
                2,
                "distinct rules can share one priority"
            );
            assert!(
                control.add_rule(&outer).is_err(),
                "only the exact rule is a duplicate for NLM_F_EXCL"
            );
            control.delete_rule(&outer).unwrap();
            assert_eq!(control.rule_keys(), vec![other]);

            let block = RouteKey::ipv6_block(IPV6_GLOBAL_UNICAST);
            let forward = RouteKey::ipv6(IPV6_GLOBAL_UNICAST, TEST_IFINDEX);
            control.add_route(&block).unwrap();
            control.add_route(&forward).unwrap();
            assert_eq!(
                control.route_count(),
                2,
                "the kernel allows a blackhole and a unicast route at one prefix"
            );
            // The IPv6 delete path ignores the route type, so one request can
            // match both entries. This fake removes the first match, as the
            // kernel does. The cleanup never depends on that order: it refuses
            // a request that selects two live entries.
            let live = control
                .table_routes(libc::AF_INET6 as u8, TUNNEL_TABLE)
                .unwrap();
            assert_eq!(routes_selected_by(&live, &block).len(), 2);
            control.delete_route(&block).unwrap();
            assert_eq!(control.route_keys(), vec![forward.clone()]);
            control.delete_route(&forward).unwrap();
            assert_eq!(control.route_count(), 0);
        }

        #[test]
        fn fake_delete_route_removes_one_entry_per_request() {
            let control = FakeControl::default();
            let first = RouteKey::ipv4(IPV4_FIRST_HALF, TEST_IFINDEX);
            let mut second = first.clone();
            second.metric = Some(1000);
            control.add_route(&first).unwrap();
            control.add_route(&second).unwrap();
            assert_eq!(control.route_count(), 2);

            control.delete_route(&first).unwrap();

            assert_eq!(
                control.route_count(),
                1,
                "the fake removes one entry per request; a real IPv6 sibling group can remove more, so the cleanup refuses an ambiguous selector"
            );
            assert_eq!(control.route_keys(), vec![second]);
        }

        #[test]
        fn route_recovery_adopts_two_outer_rules_at_one_priority() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let mut record = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
            );
            record.pid = STALE_PID;
            record
                .absorb_predecessor(&claim_record(
                    TEST_IFNAME,
                    TEST_IFINDEX,
                    "eth0",
                    Ipv6Policy::Forward,
                ))
                .unwrap();
            std::fs::write(&path, record.encode()).unwrap();
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            install(&mut routes).unwrap();

            let report = routes.last_recovery().unwrap();
            assert_eq!(report.removed_rules, 6);
            assert_eq!(report.removed_routes, 3);
            assert_eq!(control.rule_count(), 4);
            let rules = control.rule_keys();
            assert!(rules
                .iter()
                .any(|rule| rule.oif.as_deref() == Some(TEST_OUTER_IFNAME)));
            assert!(
                !rules.iter().any(|rule| rule.oif.as_deref() == Some("eth0")),
                "the predecessor outer rule is gone"
            );
            // The predecessor outer keys are still in this run's cleanup
            // record. The live rule at the same priority belongs to the new
            // outer interface, so the old selector must not block the cleanup.
            routes.remove().unwrap();
            assert_eq!(control.route_count(), 0);
            assert_eq!(control.rule_count(), 0);
            assert!(!path.exists());
        }

        #[test]
        fn route_recovery_refuses_an_ambiguous_block_and_forward_prefix() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let mut record = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Block,
            );
            record.pid = STALE_PID;
            record
                .absorb_predecessor(&claim_record(
                    TEST_IFNAME,
                    TEST_IFINDEX,
                    TEST_OUTER_IFNAME,
                    Ipv6Policy::Forward,
                ))
                .unwrap();
            std::fs::write(&path, record.encode()).unwrap();
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Block, &control, &path);

            let error = install(&mut routes).unwrap_err();

            // The IPv6 delete path ignores the route type. A block record and a
            // forward record at one prefix have the same delete selector, so
            // recovery cannot prove which object a delete removes.
            let message = error.to_string();
            assert!(message.contains("not recoverable"), "{message}");
            assert!(message.contains("can match 2 live routes"), "{message}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                record.encode(),
                "the ambiguous claim is kept in place"
            );
            assert_eq!(control.route_count(), 4);
            assert_eq!(control.rule_count(), 4);
            assert!(
                deletes(&control).is_empty(),
                "an ambiguous selector sends no delete"
            );
            assert!(!control.calls().iter().any(|call| call.starts_with("add-")));
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_recovery_compacts_a_fifth_predecessor_after_absence_proof() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = claim_with_four_priors();
            std::fs::write(&path, record.encode()).unwrap();
            put_recorded(&control, &record);
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            install_at(&mut routes, TEST_IFINDEX + 20).unwrap();

            let text = std::fs::read_to_string(&path).unwrap();
            let parsed = ClaimRecord::parse(&text).unwrap();
            assert_eq!(parsed.ifindex, TEST_IFINDEX + 20);
            assert_eq!(parsed.prior.len(), MAX_CLAIM_PRIORS);
            assert!(parsed
                .prior
                .iter()
                .any(|prior| prior.ifindex == TEST_IFINDEX));
            assert!(
                !parsed
                    .prior
                    .iter()
                    .any(|prior| prior.ifindex == TEST_IFINDEX + 1),
                "the first predecessor is the oldest and is dropped after the proof: {text}"
            );
            assert!(parsed
                .prior
                .iter()
                .any(|prior| prior.ifindex == TEST_IFINDEX + 2));
            assert!(parsed
                .prior
                .iter()
                .any(|prior| prior.ifindex == TEST_IFINDEX + 3));
            assert!(parsed
                .prior
                .iter()
                .any(|prior| prior.ifindex == TEST_IFINDEX + 4));
            assert_eq!(control.route_count(), 3);
            assert_eq!(control.rule_count(), 4);
            routes.remove().unwrap();
            assert_eq!(control.route_count(), 0);
            assert_eq!(control.rule_count(), 0);
            assert!(!path.exists());
        }

        #[test]
        fn route_claim_requires_absence_proof_to_drop_a_fifth_predecessor() {
            let previous = claim_with_four_priors();
            let mut replacement = claim_record(
                TEST_IFNAME,
                TEST_IFINDEX + 20,
                TEST_OUTER_IFNAME,
                Ipv6Policy::Forward,
            );

            let error = replacement
                .absorb_recovered_predecessor(&previous, false)
                .unwrap_err();
            assert!(error.to_string().contains("too many"), "{error}");
            assert!(
                replacement.prior.is_empty(),
                "a refused absorb leaves the replacement record unchanged"
            );

            replacement
                .absorb_recovered_predecessor(&previous, true)
                .unwrap();
            assert_eq!(replacement.prior.len(), MAX_CLAIM_PRIORS);
        }

        #[test]
        fn route_recovery_keeps_a_full_claim_when_the_absence_proof_fails() {
            let control = Arc::new(FakeControl::default());
            let path = unique_test_claim_path();
            let record = claim_with_four_priors();
            std::fs::write(&path, record.encode()).unwrap();
            put_recorded(&control, &record);
            let routes_before = control.route_count();
            let rules_before = control.rule_count();
            control.fail_reads();
            let mut routes = manager(Ipv6Policy::Forward, &control, &path);

            let error = install(&mut routes).unwrap_err();

            assert!(error.to_string().contains("not recoverable"), "{error}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                record.encode(),
                "without two absence reads the old claim is preserved"
            );
            assert_eq!(control.route_count(), routes_before);
            assert_eq!(control.rule_count(), rules_before);
            assert!(!control.calls().iter().any(|call| call.starts_with("add-")));
            control.allow_reads();
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        fn route_claim_unlink_refuses_a_second_link() {
            let path = unique_test_claim_path();
            write_stale_claim(&path, Ipv6Policy::Forward);
            let claim = acquire(&path).unwrap();
            let second = unique_test_claim_path();
            std::fs::hard_link(&path, &second).unwrap();

            let error = claim.unlink().unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            assert!(error.to_string().contains("single-link"), "{error}");
            assert!(path.exists(), "the claim path is left in place");
            assert!(second.exists(), "the second link is left in place");
            std::fs::remove_file(&second).unwrap();
            std::fs::remove_file(&path).unwrap();
        }
    }
}
