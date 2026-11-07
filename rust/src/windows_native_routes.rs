//! Native Windows route mutation boundary.
//!
//! This module is the replacement foundation for the route part of the
//! `netsh` path. It calls `CreateIpForwardEntry2` and `DeleteIpForwardEntry2`
//! with the exact route identity. It starts no child process. It resolves no
//! interface index before a command.
//!
//! The source device proxy tunnel uses this boundary on Windows. A live
//! Windows tunnel test is still needed. Do not read the compile result or the
//! hermetic tests as proof that a live Windows tunnel works.
//!
//! # Ownership model
//!
//! A managed route has one identity: the adapter LUID, the destination prefix,
//! and the next hop. Microsoft documents these facts:
//!
//! 1. `CreateIpForwardEntry2` fails with `ERROR_OBJECT_ALREADY_EXISTS` when the
//!    destination prefix and the next hop already exist on the interface.
//! 2. `DeleteIpForwardEntry2` deletes only a route with the same destination
//!    prefix and the same next hop on the interface.
//! 3. `DeleteIpForwardEntry2` fails when no such route exists.
//!
//! The create call is an atomic claim on one route identity. A successful
//! create proves that the route did not exist on this adapter before the call.
//! This module never adopts a route that already exists. It records only the
//! routes that its own create calls added. Cleanup deletes by route identity.
//! Another process can replace a route with the same identity. The API cannot
//! distinguish that replacement from this run's route.
//!
//! The route identity contains the retained LUID. The row sets
//! `InterfaceIndex` to zero, so Windows uses the LUID and never a stale index.
//!
//! # Adapter identity
//!
//! Before every create and every delete, the module reads the GUID for the
//! retained LUID with `ConvertInterfaceLuidToGuid`. A different GUID stops the
//! operation. A matching GUID identifies the adapter unit, but does not prove
//! that the current adapter was created by this run.
//!
//! The GUID read and the route call are two calls. Microsoft provides no
//! atomic compare-and-delete that includes the interface GUID. Windows can
//! remove an adapter and can assign its LUID to another adapter later. This
//! module narrows that window and fails closed on a mismatch. It does not prove
//! that the pair is atomic. Do not describe the pair as atomic.
//!
//! # IPv6 policy
//!
//! [`Ipv6RoutePolicy::Block`] and [`Ipv6RoutePolicy::Forward`] both install the
//! `2000::/3` route on the tunnel adapter. The relay enforces the difference:
//! block drops the inner packets and forward uses the selected relay mode.
//! [`Ipv6RoutePolicy::Inherit`] installs no IPv6 route. [`RoutePlan`] retains
//! the exact policy value, so a caller cannot turn one explicit policy into
//! another by accident. More-specific routes and other IPv6 ranges can bypass
//! this route. Inherit is an explicit leak path.
//!
//! # Cleanup
//!
//! [`RouteBoundary`] removes its routes on drop. An explicit
//! [`RouteBoundary::remove`] call gives a report. A failed delete stays in the
//! record with an attempt count and the last error. This module never retries
//! without a bound. After [`MAX_DELETE_ATTEMPTS`] attempts, the route stays in
//! the record for a report or a manual cleanup, and the module makes no more
//! delete calls for it.
//!
//! If the adapter check is inconclusive, the boundary stops and keeps every
//! record. The caller must report the failure and close the owned device.
//! Windows then removes the routes that are bound to that device. Do not retry
//! a delete on an adapter that the boundary cannot prove. The route identity
//! carries the adapter LUID, so every managed route is bound to the device.
//!
//! # Microsoft references
//!
//! - `CreateIpForwardEntry2`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2>
//! - `DeleteIpForwardEntry2`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2>
//! - `MIB_IPFORWARD_ROW2`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2>
//! - `ConvertInterfaceLuidToGuid`:
//!   <https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoguid>
//! - `NET_LUID`:
//!   <https://learn.microsoft.com/windows/win32/api/ifdef/ns-ifdef-net_luid_lh>

use crate::windows_route_verify::{Ipv6RoutePolicy, RoutePrefix, IPV4_ROUTES, IPV6_TUNNEL_ROUTE};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The number of delete attempts for one route record.
///
/// One [`RouteBoundary::remove`] call makes at most one attempt per route. The
/// count stays on the record across calls. After this many attempts, the route
/// is retained for a report and the module makes no more delete calls for it.
pub const MAX_DELETE_ATTEMPTS: u32 = 3;

/// The largest managed route set.
///
/// The set has two IPv4 routes and, for a managed IPv6 policy, one IPv6 route.
pub const MAX_MANAGED_ROUTES: usize = 3;

const ERROR_SUCCESS: u32 = 0;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

/// A 16-byte Windows GUID.
///
/// The layout matches the Windows `GUID` type. `ConvertInterfaceLuidToGuid`
/// writes one value of this type.
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

    /// Return the equivalent read-only route verification GUID.
    ///
    /// The two modules keep separate ABI types. This conversion is the one
    /// bridge, so a caller can bind a native route identity to the retained
    /// identity check without reading or rebuilding the GUID fields.
    pub(crate) fn route_verify_guid(self) -> crate::windows_route_verify::AdapterGuid {
        crate::windows_route_verify::AdapterGuid::new(
            self.data1, self.data2, self.data3, self.data4,
        )
    }
}

const _: () = {
    assert!(std::mem::size_of::<AdapterGuid>() == 16);
    assert!(std::mem::align_of::<AdapterGuid>() == 4);
};

/// The retained identity of one adapter.
///
/// The LUID names the adapter for a route operation. The GUID checks that the
/// LUID still has the expected adapter identity. It does not prove who created
/// the adapter. Both values must be nonzero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterIdentity {
    luid: u64,
    guid: AdapterGuid,
}

impl AdapterIdentity {
    /// Build an adapter identity.
    ///
    /// Return an error for a zero LUID or a zero GUID. Windows does not use a
    /// zero LUID for a real interface and does not return a zero GUID for one.
    pub fn new(luid: u64, guid: AdapterGuid) -> Result<Self, RouteError> {
        if luid == 0 {
            return Err(RouteError::InvalidIdentity(
                "the interface LUID must be nonzero",
            ));
        }
        if guid.is_zero() {
            return Err(RouteError::InvalidIdentity(
                "the interface GUID must be nonzero",
            ));
        }
        Ok(Self { luid, guid })
    }

    /// Return the retained LUID.
    pub fn luid(self) -> u64 {
        self.luid
    }

    /// Return the retained GUID.
    pub fn guid(self) -> AdapterGuid {
        self.guid
    }
}

/// One route that the tunnel manages.
///
/// The constructor is private. Only [`RoutePlan`] builds a value. The fields
/// are one of the fixed managed prefixes and the unspecified next hop of the
/// same address family. A caller cannot use this type to delete an unrelated
/// route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedRoute {
    prefix: RoutePrefix,
    next_hop: IpAddr,
}

impl ManagedRoute {
    fn new(prefix: RoutePrefix, next_hop: IpAddr) -> Self {
        debug_assert!(prefix.is_valid());
        debug_assert!(next_hop.is_unspecified());
        debug_assert!(next_hop.is_ipv4() == prefix.address.is_ipv4());
        Self { prefix, next_hop }
    }

    /// Return the destination prefix.
    pub fn prefix(self) -> RoutePrefix {
        self.prefix
    }

    /// Return the next hop. It is the unspecified address of the same family.
    pub fn next_hop(self) -> IpAddr {
        self.next_hop
    }

    /// Return true for the IPv6 route.
    pub fn is_ipv6(self) -> bool {
        self.prefix.address.is_ipv6()
    }

    fn key(self, luid: u64) -> RouteKey {
        RouteKey {
            luid,
            prefix: self.prefix,
            next_hop: self.next_hop,
        }
    }
}

/// The exact identity of one route operation.
///
/// The identity is the LUID, the destination prefix, and the next hop. The
/// metric and the protocol are not part of the identity. A route record never
/// uses them to select a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RouteKey {
    luid: u64,
    prefix: RoutePrefix,
    next_hop: IpAddr,
}

/// The routes for one explicit IPv6 policy.
///
/// The plan keeps the policy value. [`Ipv6RoutePolicy::Block`] and
/// [`Ipv6RoutePolicy::Forward`] have the same routes and different meanings for
/// the relay. [`Ipv6RoutePolicy::Inherit`] has no IPv6 route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePlan {
    policy: Ipv6RoutePolicy,
    routes: Vec<ManagedRoute>,
}

impl RoutePlan {
    /// Build the plan for one explicit IPv6 policy.
    ///
    /// The plan always has the two IPv4 `/1` routes. A managed IPv6 policy adds
    /// the `2000::/3` route. The inherit policy adds no IPv6 route.
    pub fn for_policy(policy: Ipv6RoutePolicy) -> Self {
        let mut routes = Vec::with_capacity(MAX_MANAGED_ROUTES);
        routes.push(ManagedRoute::new(
            IPV4_ROUTES[0],
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ));
        routes.push(ManagedRoute::new(
            IPV4_ROUTES[1],
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ));
        if policy.is_managed() {
            routes.push(ManagedRoute::new(
                IPV6_TUNNEL_ROUTE,
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ));
        }
        debug_assert!(routes.len() <= MAX_MANAGED_ROUTES);
        Self { policy, routes }
    }

    /// Return the exact policy that this plan installs.
    pub fn policy(&self) -> Ipv6RoutePolicy {
        self.policy
    }

    /// Return the routes in install order.
    pub fn routes(&self) -> &[ManagedRoute] {
        &self.routes
    }

    /// Return the number of routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return true when the plan has no route. A valid plan is never empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// A Windows status from one route call, reduced to the cases that matter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStatus {
    Success,
    AlreadyExists,
    NotFound,
    AccessDenied,
    NotSupported,
    InvalidParameter,
    Other(u32),
}

/// Map a documented Windows status to an action for the state machine.
///
/// The values are the documented return codes of `CreateIpForwardEntry2` and
/// `DeleteIpForwardEntry2`. Every other code is kept for a report.
fn classify_status(code: u32) -> NativeStatus {
    match code {
        ERROR_SUCCESS => NativeStatus::Success,
        ERROR_OBJECT_ALREADY_EXISTS => NativeStatus::AlreadyExists,
        ERROR_NOT_FOUND => NativeStatus::NotFound,
        ERROR_ACCESS_DENIED => NativeStatus::AccessDenied,
        ERROR_NOT_SUPPORTED => NativeStatus::NotSupported,
        ERROR_INVALID_PARAMETER => NativeStatus::InvalidParameter,
        other => NativeStatus::Other(other),
    }
}

/// The result of one GUID lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuidLookup {
    Found(AdapterGuid),
    Absent,
    ZeroGuid,
    Failed(u32),
}

/// Map a `ConvertInterfaceLuidToGuid` status to a native ownership answer.
///
/// Microsoft documents `ERROR_INVALID_PARAMETER` for an invalid LUID.
/// `ERROR_NOT_FOUND` is the common not-found code from the same interface
/// table. Both mean that the LUID names no interface. Any other code is an
/// error, because it does not prove absence.
fn classify_guid_status(code: u32, guid: AdapterGuid) -> GuidLookup {
    match code {
        ERROR_SUCCESS if guid.is_zero() => GuidLookup::ZeroGuid,
        ERROR_SUCCESS => GuidLookup::Found(guid),
        ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND => GuidLookup::Absent,
        other => GuidLookup::Failed(other),
    }
}

/// A reason that the route boundary did not change a route or did not finish.
///
/// Every variant is a failure. The caller must not show a success state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// The adapter identity is not usable.
    InvalidIdentity(&'static str),
    /// The boundary still holds route records.
    RoutesActive,
    /// The retained LUID names no interface.
    AdapterMissing,
    /// The retained LUID now names a different adapter.
    AdapterReplaced,
    /// The GUID lookup failed with a Windows error.
    AdapterCheckFailed(u32),
    /// The GUID lookup reported success but returned the zero GUID.
    AdapterGuidMissing,
    /// The exact route already exists on the adapter and this program did not
    /// create it.
    RouteAlreadyExists {
        /// The existing prefix.
        prefix: RoutePrefix,
    },
    /// The call needs Administrator rights.
    AccessDenied {
        /// The API call.
        operation: &'static str,
        /// The route prefix.
        prefix: RoutePrefix,
    },
    /// The address family or the interface does not support routes.
    NotSupported {
        /// The API call.
        operation: &'static str,
        /// The route prefix.
        prefix: RoutePrefix,
        /// The Windows error code.
        code: u32,
    },
    /// The API rejected the route row.
    InvalidRoute {
        /// The API call.
        operation: &'static str,
        /// The route prefix.
        prefix: RoutePrefix,
        /// The Windows error code.
        code: u32,
    },
    /// The API returned a status that this call cannot use.
    UnexpectedStatus {
        /// The API call.
        operation: &'static str,
        /// The route prefix.
        prefix: RoutePrefix,
        /// The Windows error code.
        code: u32,
    },
    /// Any other Windows API failure.
    Api {
        /// The API call.
        operation: &'static str,
        /// The route prefix.
        prefix: RoutePrefix,
        /// The Windows error code.
        code: u32,
    },
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(message) => {
                write!(formatter, "invalid adapter identity: {message}")
            }
            Self::RoutesActive => write!(
                formatter,
                "this boundary still holds route records; remove them before install"
            ),
            Self::AdapterMissing => write!(formatter, "the tunnel adapter is gone"),
            Self::AdapterReplaced => write!(
                formatter,
                "the retained LUID now names a different adapter; this program changes no route on it"
            ),
            Self::AdapterCheckFailed(code) => write!(
                formatter,
                "cannot check the tunnel adapter identity: Windows error {code}"
            ),
            Self::AdapterGuidMissing => {
                write!(formatter, "the adapter GUID lookup returned the zero GUID")
            }
            Self::RouteAlreadyExists { prefix } => write!(
                formatter,
                "the {prefix} route already exists on the tunnel adapter; this run did not create it and does not remove it"
            ),
            Self::AccessDenied { operation, prefix } => write!(
                formatter,
                "{operation} for the {prefix} route needs Administrator rights"
            ),
            Self::NotSupported {
                operation,
                prefix,
                code,
            } => write!(
                formatter,
                "{operation} for the {prefix} route is not supported: Windows error {code}"
            ),
            Self::InvalidRoute {
                operation,
                prefix,
                code,
            } => write!(
                formatter,
                "{operation} rejected the {prefix} route: Windows error {code}"
            ),
            Self::UnexpectedStatus {
                operation,
                prefix,
                code,
            } => write!(
                formatter,
                "{operation} returned unexpected status {code} for the {prefix} route"
            ),
            Self::Api {
                operation,
                prefix,
                code,
            } => write!(
                formatter,
                "{operation} failed for the {prefix} route with Windows error {code}"
            ),
        }
    }
}

impl std::error::Error for RouteError {}

/// One route record that cleanup did not remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupRecord {
    /// The retained interface LUID.
    pub luid: u64,
    /// The destination prefix.
    pub prefix: RoutePrefix,
    /// The next hop.
    pub next_hop: IpAddr,
    /// The number of delete attempts.
    pub attempts: u32,
    /// The last failure. A retained record always has one.
    pub last_error: Option<RouteError>,
}

/// The result of one cleanup pass.
///
/// `removed` counts every route that is gone after the pass. A route that
/// `DeleteIpForwardEntry2` reports as not found is gone. A route on an adapter
/// that disappeared is gone. Both count as removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// The number of route records that are gone after this pass.
    pub removed: usize,
    /// True when Windows removed the adapter and its routes.
    pub adapter_gone: bool,
    /// The reason that the pass stopped before every route was attempted.
    pub stopped: Option<RouteError>,
    /// The held route records with a reported cleanup error.
    pub retained: Vec<CleanupRecord>,
}

impl CleanupReport {
    /// Return true when no cleanup error remains and the pass did not stop.
    pub fn is_complete(&self) -> bool {
        self.retained.is_empty() && self.stopped.is_none()
    }
}

/// An install failure with the result of the rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallFailure {
    /// The cause of the failure.
    pub error: RouteError,
    /// The result of the bounded rollback.
    ///
    /// For [`RouteError::RoutesActive`], no rollback runs. The report records
    /// that cleanup stopped and includes any prior cleanup failures.
    pub cleanup: CleanupReport,
}

impl fmt::Display for InstallFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "route install failed: {}", self.error)?;
        if !self.cleanup.retained.is_empty() {
            write!(
                formatter,
                "; {} route records remain",
                self.cleanup.retained.len()
            )?;
        }
        if let Some(reason) = &self.cleanup.stopped {
            write!(formatter, "; route cleanup stopped: {reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for InstallFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The small native surface that the ownership state machine needs.
///
/// The Windows implementation calls the IP Helper API. The tests use an
/// in-memory fake. No test calls a real route function.
trait RouteApi: Send {
    /// Read the GUID for one LUID. Return a Windows status.
    fn adapter_guid(&self, luid: u64, guid: &mut AdapterGuid) -> u32;
    /// Call `CreateIpForwardEntry2` for one exact route identity.
    fn create(&self, route: &RouteKey) -> u32;
    /// Call `DeleteIpForwardEntry2` for one exact route identity.
    fn delete(&self, route: &RouteKey) -> u32;
}

/// One route that this boundary created and still owns.
struct TrackedRoute {
    route: ManagedRoute,
    attempts: u32,
    last_error: Option<RouteError>,
}

/// The ownership answer from one adapter lookup.
enum AdapterState {
    Owned,
    Absent,
    Unproven(RouteError),
}

/// Owns one bounded set of native routes for one adapter.
///
/// The boundary validates the adapter GUID before each mutation. It creates
/// only the routes in its [`RoutePlan`]. It deletes only records that its own
/// create calls added. It never deletes a route that existed before the create.
///
/// Drop this boundary before you close the adapter. When the adapter is gone,
/// Windows removed its routes and the boundary sends no delete. A wrong drop
/// order therefore leaves no command that can hit another adapter.
///
/// A failed install rolls back the routes that this call created. A failed
/// cleanup keeps the records for a later call or for a report.
///
/// The source device proxy tunnel uses this boundary. A live Windows tunnel
/// test is still needed. Do not describe the Windows tunnel as verified.
pub struct RouteBoundary {
    api: Box<dyn RouteApi>,
    identity: AdapterIdentity,
    plan: RoutePlan,
    routes: Vec<TrackedRoute>,
}

impl RouteBoundary {
    /// Open the boundary for one adapter and one explicit IPv6 policy.
    ///
    /// This function uses the native IP Helper API. It creates no route until
    /// [`RouteBoundary::install`] runs. The Windows source device proxy start
    /// path calls it after it opens the adapter. A live Windows hotspot test is
    /// still needed.
    #[cfg(windows)]
    pub fn open(identity: AdapterIdentity, policy: Ipv6RoutePolicy) -> Self {
        Self::with_api(Box::new(abi::SystemRouteApi), identity, policy)
    }

    fn with_api(
        api: Box<dyn RouteApi>,
        identity: AdapterIdentity,
        policy: Ipv6RoutePolicy,
    ) -> Self {
        Self {
            api,
            identity,
            plan: RoutePlan::for_policy(policy),
            routes: Vec::new(),
        }
    }

    /// Return the retained adapter identity.
    pub fn identity(&self) -> AdapterIdentity {
        self.identity
    }

    /// Return the exact IPv6 policy of this boundary.
    pub fn policy(&self) -> Ipv6RoutePolicy {
        self.plan.policy()
    }

    /// Return true when the boundary holds route records.
    ///
    /// A record can be an installed route or a route whose cleanup failed.
    pub fn has_routes(&self) -> bool {
        !self.routes.is_empty()
    }

    /// Return the route records whose cleanup failed.
    ///
    /// A normal installed route is not in this list. A failed delete is.
    pub fn pending_cleanup(&self) -> Vec<CleanupRecord> {
        self.snapshot()
    }

    /// Install the plan.
    ///
    /// The function creates each route in plan order. Before each create, it
    /// proves that the retained LUID still names the retained adapter. On a
    /// late create failure, it rolls back the routes that this call created, in
    /// reverse order, inside one bounded [`RouteBoundary::remove`] pass.
    ///
    /// A route that already exists is never adopted and never deleted. The
    /// function returns [`RouteError::RouteAlreadyExists`] and rolls back only
    /// its own earlier routes.
    pub fn install(&mut self) -> Result<(), InstallFailure> {
        if !self.routes.is_empty() {
            return Err(InstallFailure {
                error: RouteError::RoutesActive,
                cleanup: CleanupReport {
                    stopped: Some(RouteError::RoutesActive),
                    retained: self.snapshot(),
                    ..CleanupReport::default()
                },
            });
        }
        let plan = self.plan.routes().to_vec();
        for route in plan {
            match self.check_adapter() {
                AdapterState::Owned => {}
                AdapterState::Absent => {
                    return Err(self.fail_and_rollback(RouteError::AdapterMissing))
                }
                AdapterState::Unproven(error) => {
                    return Err(self.fail_and_rollback(error));
                }
            }
            let key = route.key(self.identity.luid);
            let status = classify_status(self.api.create(&key));
            match status {
                NativeStatus::Success => self.routes.push(TrackedRoute {
                    route,
                    attempts: 0,
                    last_error: None,
                }),
                NativeStatus::AlreadyExists => {
                    return Err(self.fail_and_rollback(RouteError::RouteAlreadyExists {
                        prefix: route.prefix(),
                    }))
                }
                NativeStatus::NotFound => {
                    return Err(self.fail_and_rollback(RouteError::AdapterMissing))
                }
                NativeStatus::AccessDenied => {
                    return Err(self.fail_and_rollback(RouteError::AccessDenied {
                        operation: "CreateIpForwardEntry2",
                        prefix: route.prefix(),
                    }))
                }
                NativeStatus::NotSupported => {
                    return Err(self.fail_and_rollback(RouteError::NotSupported {
                        operation: "CreateIpForwardEntry2",
                        prefix: route.prefix(),
                        code: ERROR_NOT_SUPPORTED,
                    }))
                }
                NativeStatus::InvalidParameter => {
                    return Err(self.fail_and_rollback(RouteError::InvalidRoute {
                        operation: "CreateIpForwardEntry2",
                        prefix: route.prefix(),
                        code: ERROR_INVALID_PARAMETER,
                    }))
                }
                NativeStatus::Other(code) => {
                    return Err(self.fail_and_rollback(RouteError::Api {
                        operation: "CreateIpForwardEntry2",
                        prefix: route.prefix(),
                        code,
                    }))
                }
            }
        }
        Ok(())
    }

    /// Remove the route records. This method is idempotent.
    ///
    /// The function validates the adapter once before the pass and again
    /// before each delete. When the adapter is gone, it clears the records
    /// without a delete, because Windows removed the device-bound routes with
    /// the adapter. When the LUID names a different adapter, it stops and
    /// keeps every record. It never deletes a route on an adapter that it
    /// cannot prove. The caller must report that failure and close the owned
    /// device so that Windows removes its device-bound routes.
    ///
    /// A delete that reports `ERROR_NOT_FOUND` counts as removed. A delete
    /// failure stays in the record with an incremented attempt count. After
    /// [`MAX_DELETE_ATTEMPTS`] attempts, the record is retained and the module
    /// makes no more delete calls for it.
    pub fn remove(&mut self) -> CleanupReport {
        let mut report = CleanupReport::default();
        if self.routes.is_empty() {
            return report;
        }
        match self.check_adapter() {
            AdapterState::Owned => {}
            AdapterState::Absent => {
                report.removed = self.routes.len();
                report.adapter_gone = true;
                self.routes.clear();
                return report;
            }
            AdapterState::Unproven(error) => {
                report.stopped = Some(error.clone());
                for record in &mut self.routes {
                    record.last_error = Some(error.clone());
                }
                report.retained = self.snapshot();
                return report;
            }
        }

        let mut kept = Vec::new();
        while let Some(mut record) = self.routes.pop() {
            if record.attempts >= MAX_DELETE_ATTEMPTS {
                kept.push(record);
                continue;
            }
            match self.check_adapter() {
                AdapterState::Owned => {}
                AdapterState::Absent => {
                    // The adapter is gone. Windows removed every route on it,
                    // including the kept records that an earlier delete failed
                    // to remove.
                    report.adapter_gone = true;
                    report.removed += 1 + self.routes.len() + kept.len();
                    self.routes.clear();
                    kept.clear();
                    report.retained = self.snapshot();
                    return report;
                }
                AdapterState::Unproven(error) => {
                    record.last_error = Some(error.clone());
                    kept.push(record);
                    for mut rest in self.routes.drain(..).rev() {
                        rest.last_error = Some(error.clone());
                        kept.push(rest);
                    }
                    report.stopped = Some(error);
                    kept.reverse();
                    self.routes = kept;
                    report.retained = self.snapshot();
                    return report;
                }
            }
            record.attempts += 1;
            let key = record.route.key(self.identity.luid);
            match classify_status(self.api.delete(&key)) {
                NativeStatus::Success | NativeStatus::NotFound => {
                    report.removed += 1;
                }
                status => {
                    record.last_error = Some(delete_error(record.route, status));
                    kept.push(record);
                }
            }
        }
        kept.reverse();
        self.routes = kept;
        report.retained = self.snapshot();
        report
    }

    fn fail_and_rollback(&mut self, error: RouteError) -> InstallFailure {
        let cleanup = self.remove();
        InstallFailure { error, cleanup }
    }

    fn check_adapter(&self) -> AdapterState {
        let mut guid = AdapterGuid::ZERO;
        let status = self.api.adapter_guid(self.identity.luid, &mut guid);
        match classify_guid_status(status, guid) {
            GuidLookup::Found(found) if found == self.identity.guid => AdapterState::Owned,
            GuidLookup::Found(_) => AdapterState::Unproven(RouteError::AdapterReplaced),
            GuidLookup::Absent => AdapterState::Absent,
            GuidLookup::ZeroGuid => AdapterState::Unproven(RouteError::AdapterGuidMissing),
            GuidLookup::Failed(code) => {
                AdapterState::Unproven(RouteError::AdapterCheckFailed(code))
            }
        }
    }

    fn snapshot(&self) -> Vec<CleanupRecord> {
        self.routes
            .iter()
            .filter(|record| record.last_error.is_some())
            .map(|record| CleanupRecord {
                luid: self.identity.luid,
                prefix: record.route.prefix(),
                next_hop: record.route.next_hop(),
                attempts: record.attempts,
                last_error: record.last_error.clone(),
            })
            .collect()
    }
}

impl Drop for RouteBoundary {
    fn drop(&mut self) {
        let report = self.remove();
        if !report.is_complete() {
            eprintln!(
                "[route] native cleanup incomplete: {} route records remain",
                report.retained.len()
            );
        }
    }
}

fn delete_error(route: ManagedRoute, status: NativeStatus) -> RouteError {
    const OPERATION: &str = "DeleteIpForwardEntry2";
    match status {
        NativeStatus::AccessDenied => RouteError::AccessDenied {
            operation: OPERATION,
            prefix: route.prefix(),
        },
        NativeStatus::NotSupported => RouteError::NotSupported {
            operation: OPERATION,
            prefix: route.prefix(),
            code: ERROR_NOT_SUPPORTED,
        },
        NativeStatus::InvalidParameter => RouteError::InvalidRoute {
            operation: OPERATION,
            prefix: route.prefix(),
            code: ERROR_INVALID_PARAMETER,
        },
        NativeStatus::AlreadyExists => RouteError::UnexpectedStatus {
            operation: OPERATION,
            prefix: route.prefix(),
            code: ERROR_OBJECT_ALREADY_EXISTS,
        },
        NativeStatus::Other(code) => RouteError::Api {
            operation: OPERATION,
            prefix: route.prefix(),
            code,
        },
        NativeStatus::Success | NativeStatus::NotFound => RouteError::UnexpectedStatus {
            operation: OPERATION,
            prefix: route.prefix(),
            code: ERROR_SUCCESS,
        },
    }
}

/// The Windows ABI layer.
///
/// The raw structures are compiled on Windows and on 64-bit test hosts. The
/// layout is the Windows MSVC layout for both x86 and x64. The layout checks are
/// compile-time constants, so a wrong field offset stops the build.
///
/// The function declarations are Windows only. Tests never call them.
#[cfg(any(windows, target_pointer_width = "64"))]
mod abi {
    #[cfg(windows)]
    use super::AdapterGuid;
    use super::{RouteKey, RoutePrefix};
    use std::mem::{align_of, offset_of, size_of};
    use std::net::IpAddr;

    /// The Windows `AF_INET` value.
    pub(super) const AF_INET: u16 = 2;
    /// The Windows `AF_INET6` value. This is not the Linux value.
    pub(super) const AF_INET6: u16 = 23;
    /// `MIB_IPPROTO_NETMGMT`: a static route added by network management.
    pub(super) const MIB_IPPROTO_NETMGMT: i32 = 3;
    /// `NlroManual`: a result of manual configuration.
    pub(super) const NL_ROUTE_ORIGIN_MANUAL: i32 = 0;
    /// The infinite lifetime value for `ValidLifetime` and `PreferredLifetime`.
    pub(super) const INFINITE_LIFETIME: u32 = u32::MAX;

    // The fields mirror the Windows `SOCKADDR_IN` header. Port is zero for a
    // route prefix and a next hop.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct RawSockaddrIn {
        pub(super) family: u16,
        pub(super) port: u16,
        pub(super) address: [u8; 4],
        pub(super) zero: [u8; 8],
    }

    // The fields mirror the Windows `SOCKADDR_IN6` header.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct RawSockaddrIn6 {
        pub(super) family: u16,
        pub(super) port: u16,
        pub(super) flow_info: u32,
        pub(super) address: [u8; 16],
        pub(super) scope_id: u32,
    }

    // The union mirrors `SOCKADDR_INET`. Every member starts with the family.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) union RawSockaddrInet {
        pub(super) family: u16,
        pub(super) v4: RawSockaddrIn,
        pub(super) v6: RawSockaddrIn6,
    }

    #[cfg(test)]
    impl RawSockaddrInet {
        /// Read the address family. The family is the first `u16` of every
        /// member, so this read is valid for any initialized value.
        pub(super) fn family(&self) -> u16 {
            // SAFETY: The caller passes a value built by `raw_sockaddr` or by
            // `zeroed_sockaddr`. Every member starts with one `u16` family
            // field.
            unsafe { self.family }
        }

        /// Read the IPv4 address. The caller checks the family first.
        pub(super) fn v4_address(&self) -> [u8; 4] {
            // SAFETY: The caller checks that the active member is `v4`. The
            // field is an array of bytes with no invalid values.
            unsafe { self.v4.address }
        }

        /// Read the IPv6 address. The caller checks the family first.
        pub(super) fn v6_address(&self) -> [u8; 16] {
            // SAFETY: The caller checks that the active member is `v6`. The
            // field is an array of bytes with no invalid values.
            unsafe { self.v6.address }
        }
    }

    // The fields mirror the Windows `IP_ADDRESS_PREFIX` header.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct RawIpAddressPrefix {
        pub(super) prefix: RawSockaddrInet,
        pub(super) prefix_length: u8,
    }

    /// The Windows `MIB_IPFORWARD_ROW2` layout.
    // The fields mirror the Windows headers. The route identity uses the LUID,
    // the destination prefix, and the next hop. The other fields are set to
    // documented values for a static route.
    #[allow(dead_code)]
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct RawMibIpForwardRow2 {
        pub(super) interface_luid: u64,
        pub(super) interface_index: u32,
        pub(super) destination_prefix: RawIpAddressPrefix,
        pub(super) next_hop: RawSockaddrInet,
        pub(super) site_prefix_length: u8,
        pub(super) valid_lifetime: u32,
        pub(super) preferred_lifetime: u32,
        pub(super) metric: u32,
        pub(super) protocol: i32,
        pub(super) loopback: u8,
        pub(super) autoconfigure_address: u8,
        pub(super) publish: u8,
        pub(super) immortal: u8,
        pub(super) age: u32,
        pub(super) origin: i32,
    }

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
        assert!(size_of::<RawMibIpForwardRow2>().is_multiple_of(align_of::<RawMibIpForwardRow2>()));
    };

    /// Build the zero value for one raw route row.
    ///
    /// All fields are integers, arrays of bytes, or structures of those types.
    /// An all-zero byte pattern is valid for each one. The zero value also
    /// clears the alignment padding, so no uninitialized byte crosses the FFI
    /// boundary. The functions below take fixed types. Do not replace them with
    /// one generic function: a caller could then pass a type that has no valid
    /// all-zero value.
    fn zeroed_row() -> RawMibIpForwardRow2 {
        // SAFETY: Every field accepts the all-zero pattern.
        unsafe { std::mem::zeroed() }
    }

    fn zeroed_prefix() -> RawIpAddressPrefix {
        // SAFETY: Every field accepts the all-zero pattern.
        unsafe { std::mem::zeroed() }
    }

    fn zeroed_sockaddr() -> RawSockaddrInet {
        // SAFETY: Every union member accepts the all-zero pattern.
        unsafe { std::mem::zeroed() }
    }

    fn raw_sockaddr(address: IpAddr) -> RawSockaddrInet {
        let mut value = zeroed_sockaddr();
        match address {
            IpAddr::V4(address) => {
                value.v4 = RawSockaddrIn {
                    family: AF_INET,
                    port: 0,
                    address: address.octets(),
                    zero: [0; 8],
                };
            }
            IpAddr::V6(address) => {
                value.v6 = RawSockaddrIn6 {
                    family: AF_INET6,
                    port: 0,
                    flow_info: 0,
                    address: address.octets(),
                    scope_id: 0,
                };
            }
        }
        value
    }

    fn raw_prefix(prefix: RoutePrefix) -> RawIpAddressPrefix {
        let mut value = zeroed_prefix();
        value.prefix = raw_sockaddr(prefix.address);
        value.prefix_length = prefix.length;
        value
    }

    /// Build the exact `MIB_IPFORWARD_ROW2` for one route identity.
    ///
    /// The row sets `InterfaceIndex` to zero. Microsoft uses the LUID first
    /// when it is nonzero. A stale index can therefore never select a different
    /// adapter. The metric and the protocol are set to fixed values. They are
    /// not part of the route identity.
    pub(super) fn raw_row(route: &RouteKey) -> RawMibIpForwardRow2 {
        let mut row = zeroed_row();
        row.interface_luid = route.luid;
        row.interface_index = 0;
        row.destination_prefix = raw_prefix(route.prefix);
        row.next_hop = raw_sockaddr(route.next_hop);
        row.site_prefix_length = 0;
        row.valid_lifetime = INFINITE_LIFETIME;
        row.preferred_lifetime = INFINITE_LIFETIME;
        row.metric = 0;
        row.protocol = MIB_IPPROTO_NETMGMT;
        row.loopback = 0;
        row.autoconfigure_address = 0;
        row.publish = 0;
        row.immortal = 1;
        row.age = 0;
        row.origin = NL_ROUTE_ORIGIN_MANUAL;
        row
    }

    #[cfg(windows)]
    #[link(name = "iphlpapi")]
    extern "system" {
        fn ConvertInterfaceLuidToGuid(luid: *const u64, guid: *mut AdapterGuid) -> u32;
        fn CreateIpForwardEntry2(row: *const RawMibIpForwardRow2) -> u32;
        fn DeleteIpForwardEntry2(row: *const RawMibIpForwardRow2) -> u32;
    }

    /// The real IP Helper implementation of [`super::RouteApi`].
    #[cfg(windows)]
    pub(super) struct SystemRouteApi;

    #[cfg(windows)]
    impl super::RouteApi for SystemRouteApi {
        fn adapter_guid(&self, luid: u64, guid: &mut AdapterGuid) -> u32 {
            // SAFETY: `luid` points to one initialized `NET_LUID` value and
            // `guid` points to one writable `GUID` value with the documented
            // layout. Both pointers are valid for the call.
            unsafe { ConvertInterfaceLuidToGuid(&luid, guid) }
        }

        fn create(&self, route: &RouteKey) -> u32 {
            let row = raw_row(route);
            // SAFETY: `row` is one fully initialized `MIB_IPFORWARD_ROW2`
            // value with the documented layout. The pointer is valid for the
            // call. The API does not keep it.
            unsafe { CreateIpForwardEntry2(&row) }
        }

        fn delete(&self, route: &RouteKey) -> u32 {
            let row = raw_row(route);
            // SAFETY: `row` is one fully initialized `MIB_IPFORWARD_ROW2`
            // value with the documented layout. The pointer is valid for the
            // call. The API does not keep it.
            unsafe { DeleteIpForwardEntry2(&row) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_route_verify::{Ipv6RoutePolicy, IPV4_ROUTES, IPV6_TUNNEL_ROUTE};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const TEST_LUID: u64 = 0x0000_6000_0000_0007;
    const OTHER_LUID: u64 = 0x0000_6000_0000_0008;

    fn test_guid() -> AdapterGuid {
        AdapterGuid::new(
            0x1122_3344,
            0x5566,
            0x7788,
            [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00],
        )
    }

    fn other_guid() -> AdapterGuid {
        AdapterGuid::new(
            0x0a0b_0c0d,
            0x0e0f,
            0x1011,
            [0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19],
        )
    }

    fn identity() -> AdapterIdentity {
        AdapterIdentity::new(TEST_LUID, test_guid()).unwrap()
    }

    fn unspecified_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }

    fn unspecified_v6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RouteIdentity {
        luid: u64,
        prefix: RoutePrefix,
        next_hop: IpAddr,
    }

    impl RouteIdentity {
        fn from_key(key: &RouteKey) -> Self {
            Self {
                luid: key.luid,
                prefix: key.prefix,
                next_hop: key.next_hop,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum FakeCall {
        Guid { luid: u64 },
        Create(RouteIdentity),
        Delete(RouteIdentity),
    }

    struct FakeState {
        guid: AdapterGuid,
        guid_status: u32,
        replace_guid_after_create: Option<(usize, AdapterGuid)>,
        create_plan: VecDeque<u32>,
        delete_plan: VecDeque<u32>,
        delete_fail_code: Option<u32>,
        table: Vec<RouteIdentity>,
        create_calls: usize,
        calls: Vec<FakeCall>,
    }

    /// An in-memory replacement for the IP Helper route API.
    ///
    /// It models the exact route identity. A create for an existing identity
    /// returns `ERROR_OBJECT_ALREADY_EXISTS`. A delete for an absent identity
    /// returns `ERROR_NOT_FOUND`. No test calls a real Windows function.
    #[derive(Clone)]
    struct FakeApi {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeApi {
        fn new(guid: AdapterGuid) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeState {
                    guid,
                    guid_status: ERROR_SUCCESS,
                    replace_guid_after_create: None,
                    create_plan: VecDeque::new(),
                    delete_plan: VecDeque::new(),
                    delete_fail_code: None,
                    table: Vec::new(),
                    create_calls: 0,
                    calls: Vec::new(),
                })),
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.state.lock().unwrap()
        }

        fn calls(&self) -> Vec<FakeCall> {
            self.lock().calls.clone()
        }

        fn creates(&self) -> Vec<RouteIdentity> {
            self.calls()
                .into_iter()
                .filter_map(|call| match call {
                    FakeCall::Create(route) => Some(route),
                    _ => None,
                })
                .collect()
        }

        fn deletes(&self) -> Vec<RouteIdentity> {
            self.calls()
                .into_iter()
                .filter_map(|call| match call {
                    FakeCall::Delete(route) => Some(route),
                    _ => None,
                })
                .collect()
        }

        fn table(&self) -> Vec<RouteIdentity> {
            self.lock().table.clone()
        }

        fn add_existing(&self, route: RouteIdentity) {
            self.lock().table.push(route);
        }

        fn remove_existing(&self, route: RouteIdentity) {
            let mut state = self.lock();
            if let Some(index) = state.table.iter().position(|entry| *entry == route) {
                state.table.remove(index);
            }
        }

        fn set_guid(&self, guid: AdapterGuid) {
            self.lock().guid = guid;
        }

        fn set_guid_status(&self, status: u32) {
            self.lock().guid_status = status;
        }

        fn set_create_plan(&self, codes: &[u32]) {
            self.lock().create_plan = codes.iter().copied().collect();
        }

        fn set_delete_plan(&self, codes: &[u32]) {
            self.lock().delete_plan = codes.iter().copied().collect();
        }

        fn set_delete_fail_code(&self, code: Option<u32>) {
            self.lock().delete_fail_code = code;
        }

        fn replace_guid_after_create(&self, after: usize, guid: AdapterGuid) {
            self.lock().replace_guid_after_create = Some((after, guid));
        }
    }

    impl RouteApi for FakeApi {
        fn adapter_guid(&self, luid: u64, guid: &mut AdapterGuid) -> u32 {
            let mut state = self.lock();
            state.calls.push(FakeCall::Guid { luid });
            if state.guid_status == ERROR_SUCCESS {
                *guid = state.guid;
            }
            state.guid_status
        }

        fn create(&self, route: &RouteKey) -> u32 {
            let identity = RouteIdentity::from_key(route);
            let mut state = self.lock();
            state.calls.push(FakeCall::Create(identity));
            state.create_calls += 1;
            let code = match state.create_plan.pop_front() {
                Some(code) => code,
                None if state.table.contains(&identity) => ERROR_OBJECT_ALREADY_EXISTS,
                None => ERROR_SUCCESS,
            };
            if code == ERROR_SUCCESS && !state.table.contains(&identity) {
                state.table.push(identity);
            }
            if let Some((after, guid)) = state.replace_guid_after_create {
                if state.create_calls == after {
                    state.guid = guid;
                    state.replace_guid_after_create = None;
                }
            }
            code
        }

        fn delete(&self, route: &RouteKey) -> u32 {
            let identity = RouteIdentity::from_key(route);
            let mut state = self.lock();
            state.calls.push(FakeCall::Delete(identity));
            let planned = state
                .delete_fail_code
                .or_else(|| state.delete_plan.pop_front());
            if let Some(code) = planned {
                if code == ERROR_SUCCESS {
                    if let Some(index) = state.table.iter().position(|entry| *entry == identity) {
                        state.table.remove(index);
                    }
                }
                return code;
            }
            match state.table.iter().position(|entry| *entry == identity) {
                Some(index) => {
                    state.table.remove(index);
                    ERROR_SUCCESS
                }
                None => ERROR_NOT_FOUND,
            }
        }
    }

    fn boundary(api: &FakeApi, policy: Ipv6RoutePolicy) -> RouteBoundary {
        RouteBoundary::with_api(Box::new(api.clone()), identity(), policy)
    }

    fn prefix_list(routes: &[RouteIdentity]) -> Vec<RoutePrefix> {
        routes.iter().map(|route| route.prefix).collect()
    }

    #[test]
    fn the_plan_preserves_the_explicit_ipv6_policy() {
        let block = RoutePlan::for_policy(Ipv6RoutePolicy::Block);
        assert_eq!(block.policy(), Ipv6RoutePolicy::Block);
        assert_eq!(block.len(), 3);
        assert!(!block.is_empty());
        assert_eq!(
            block
                .routes()
                .iter()
                .map(|r| r.prefix())
                .collect::<Vec<_>>(),
            vec![IPV4_ROUTES[0], IPV4_ROUTES[1], IPV6_TUNNEL_ROUTE]
        );
        assert_eq!(block.routes()[0].next_hop(), unspecified_v4());
        assert_eq!(block.routes()[1].next_hop(), unspecified_v4());
        assert_eq!(block.routes()[2].next_hop(), unspecified_v6());

        let forward = RoutePlan::for_policy(Ipv6RoutePolicy::Forward);
        assert_eq!(forward.policy(), Ipv6RoutePolicy::Forward);
        assert_eq!(forward.routes(), block.routes());

        let inherit = RoutePlan::for_policy(Ipv6RoutePolicy::Inherit);
        assert_eq!(inherit.policy(), Ipv6RoutePolicy::Inherit);
        assert_eq!(inherit.len(), 2);
        assert!(inherit.routes().iter().all(|route| !route.is_ipv6()));
        assert_eq!(
            inherit
                .routes()
                .iter()
                .map(|route| route.prefix())
                .collect::<Vec<_>>(),
            vec![IPV4_ROUTES[0], IPV4_ROUTES[1]]
        );
        assert!(block.len() <= MAX_MANAGED_ROUTES);
        assert!(forward.len() <= MAX_MANAGED_ROUTES);
        assert!(inherit.len() <= MAX_MANAGED_ROUTES);
    }

    #[test]
    fn install_uses_the_retained_luid_and_the_exact_route_identity() {
        let fake = FakeApi::new(test_guid());
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        routes.install().unwrap();

        let expected = vec![
            RouteIdentity {
                luid: TEST_LUID,
                prefix: IPV4_ROUTES[0],
                next_hop: unspecified_v4(),
            },
            RouteIdentity {
                luid: TEST_LUID,
                prefix: IPV4_ROUTES[1],
                next_hop: unspecified_v4(),
            },
            RouteIdentity {
                luid: TEST_LUID,
                prefix: IPV6_TUNNEL_ROUTE,
                next_hop: unspecified_v6(),
            },
        ];
        assert_eq!(fake.creates(), expected);
        assert!(fake.deletes().is_empty());
        assert!(routes.has_routes());
        assert!(routes.pending_cleanup().is_empty());
        assert_eq!(routes.identity(), identity());
        assert_eq!(routes.policy(), Ipv6RoutePolicy::Block);
        assert_eq!(
            fake.table()
                .iter()
                .map(|route| route.luid)
                .collect::<Vec<_>>(),
            vec![TEST_LUID, TEST_LUID, TEST_LUID]
        );
    }

    #[test]
    fn a_partial_create_rolls_back_only_the_created_routes() {
        let fake = FakeApi::new(test_guid());
        fake.set_create_plan(&[ERROR_SUCCESS, ERROR_ACCESS_DENIED]);
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);

        let failure = routes.install().unwrap_err();
        assert_eq!(
            failure.error,
            RouteError::AccessDenied {
                operation: "CreateIpForwardEntry2",
                prefix: IPV4_ROUTES[1],
            }
        );
        assert_eq!(failure.cleanup.removed, 1);
        assert!(failure.cleanup.retained.is_empty());
        assert!(!failure.cleanup.adapter_gone);
        assert_eq!(fake.creates().len(), 2);
        assert_eq!(prefix_list(&fake.deletes()), vec![IPV4_ROUTES[0]]);
        assert!(fake.table().is_empty());
        assert!(!routes.has_routes());
        assert!(routes.pending_cleanup().is_empty());
    }

    #[test]
    fn a_failed_rollback_retains_the_record_and_is_bounded() {
        let fake = FakeApi::new(test_guid());
        fake.set_create_plan(&[ERROR_SUCCESS, ERROR_ACCESS_DENIED]);
        fake.set_delete_fail_code(Some(ERROR_ACCESS_DENIED));
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);

        let failure = routes.install().unwrap_err();
        assert_eq!(
            failure.error,
            RouteError::AccessDenied {
                operation: "CreateIpForwardEntry2",
                prefix: IPV4_ROUTES[1],
            }
        );
        assert_eq!(failure.cleanup.removed, 0);
        assert_eq!(failure.cleanup.retained.len(), 1);
        let record = &failure.cleanup.retained[0];
        assert_eq!(record.luid, TEST_LUID);
        assert_eq!(record.prefix, IPV4_ROUTES[0]);
        assert_eq!(record.next_hop, unspecified_v4());
        assert_eq!(record.attempts, 1);
        assert_eq!(
            record.last_error,
            Some(RouteError::AccessDenied {
                operation: "DeleteIpForwardEntry2",
                prefix: IPV4_ROUTES[0],
            })
        );
        assert!(routes.has_routes());
        assert_eq!(routes.pending_cleanup().len(), 1);

        let report = routes.remove();
        assert_eq!(report.retained[0].attempts, 2);
        assert_eq!(report.removed, 0);

        let report = routes.remove();
        assert_eq!(report.retained[0].attempts, 3);
        assert_eq!(report.removed, 0);

        let calls_before = fake.deletes().len();
        let report = routes.remove();
        assert_eq!(report.retained[0].attempts, 3);
        assert_eq!(fake.deletes().len(), calls_before);
        assert_eq!(calls_before, 3);
        assert!(!report.is_complete());
    }

    #[test]
    fn a_failed_delete_can_be_retried_before_the_cap() {
        let fake = FakeApi::new(test_guid());
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        routes.install().unwrap();

        fake.set_delete_fail_code(Some(ERROR_ACCESS_DENIED));
        let report = routes.remove();
        assert_eq!(report.retained.len(), 3);
        assert!(report.retained.iter().all(|record| record.attempts == 1));
        assert!(routes.has_routes());

        fake.set_delete_fail_code(None);
        let report = routes.remove();
        assert!(report.is_complete());
        assert_eq!(report.removed, 3);
        assert!(!routes.has_routes());
        assert!(routes.pending_cleanup().is_empty());
        assert!(fake.table().is_empty());
    }

    #[test]
    fn an_identity_mismatch_never_deletes_a_route() {
        let fake = FakeApi::new(test_guid());
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        routes.install().unwrap();
        let creates_before = fake.creates().len();

        fake.set_guid(other_guid());
        let report = routes.remove();

        assert_eq!(report.stopped, Some(RouteError::AdapterReplaced));
        assert_eq!(report.removed, 0);
        assert_eq!(report.retained.len(), 3);
        assert!(report.retained.iter().all(|record| record.attempts == 0));
        assert!(report
            .retained
            .iter()
            .all(|record| record.last_error == Some(RouteError::AdapterReplaced)));
        assert!(fake.deletes().is_empty());
        assert_eq!(fake.creates().len(), creates_before);
        assert!(routes.has_routes());
        assert_eq!(routes.pending_cleanup().len(), 3);
    }

    #[test]
    fn an_identity_mismatch_during_install_rolls_back_without_a_delete() {
        let fake = FakeApi::new(test_guid());
        fake.replace_guid_after_create(1, other_guid());
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);

        let failure = routes.install().unwrap_err();
        assert_eq!(failure.error, RouteError::AdapterReplaced);
        assert_eq!(failure.cleanup.retained.len(), 1);
        assert_eq!(fake.creates().len(), 1);
        assert!(fake.deletes().is_empty());
        assert!(routes.has_routes());
        assert_eq!(
            routes.pending_cleanup()[0].last_error,
            Some(RouteError::AdapterReplaced)
        );
    }

    #[test]
    fn a_missing_adapter_stops_install_and_clears_records_on_remove() {
        let fake = FakeApi::new(test_guid());
        fake.set_guid_status(ERROR_INVALID_PARAMETER);
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        let failure = routes.install().unwrap_err();
        assert_eq!(failure.error, RouteError::AdapterMissing);
        assert!(failure.cleanup.is_complete());
        assert!(fake.creates().is_empty());
        assert!(!routes.has_routes());

        let fake = FakeApi::new(test_guid());
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        routes.install().unwrap();
        fake.set_guid_status(ERROR_INVALID_PARAMETER);
        let report = routes.remove();
        assert!(report.adapter_gone);
        assert_eq!(report.removed, 3);
        assert!(report.is_complete());
        assert!(fake.deletes().is_empty());
        assert!(!routes.has_routes());
    }

    #[test]
    fn an_existing_route_is_not_adopted_or_deleted() {
        let existing = RouteIdentity {
            luid: TEST_LUID,
            prefix: IPV4_ROUTES[0],
            next_hop: unspecified_v4(),
        };
        let fake = FakeApi::new(test_guid());
        fake.add_existing(existing);
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);

        let failure = routes.install().unwrap_err();
        assert_eq!(
            failure.error,
            RouteError::RouteAlreadyExists {
                prefix: IPV4_ROUTES[0]
            }
        );
        assert!(failure.cleanup.is_complete());
        assert!(fake.deletes().is_empty());
        assert_eq!(fake.table(), vec![existing]);
        assert!(!routes.has_routes());
    }

    #[test]
    fn foreign_routes_with_the_same_prefix_are_not_deleted() {
        let foreign_luid = RouteIdentity {
            luid: OTHER_LUID,
            prefix: IPV4_ROUTES[0],
            next_hop: unspecified_v4(),
        };
        let foreign_hop = RouteIdentity {
            luid: TEST_LUID,
            prefix: IPV4_ROUTES[1],
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let fake = FakeApi::new(test_guid());
        fake.add_existing(foreign_luid);
        fake.add_existing(foreign_hop);
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);

        routes.install().unwrap();
        let report = routes.remove();
        assert!(report.is_complete());

        let table = fake.table();
        assert!(table.contains(&foreign_luid));
        assert!(table.contains(&foreign_hop));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn the_inherit_policy_never_touches_the_ipv6_route() {
        let ipv6_route = RouteIdentity {
            luid: TEST_LUID,
            prefix: IPV6_TUNNEL_ROUTE,
            next_hop: unspecified_v6(),
        };
        let fake = FakeApi::new(test_guid());
        fake.add_existing(ipv6_route);
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Inherit);

        routes.install().unwrap();
        assert_eq!(fake.creates().len(), 2);
        assert!(fake
            .creates()
            .iter()
            .all(|route| route.prefix != IPV6_TUNNEL_ROUTE));
        let report = routes.remove();
        assert!(report.is_complete());
        assert_eq!(fake.deletes().len(), 2);
        assert!(fake.table().contains(&ipv6_route));
    }

    #[test]
    fn a_blocked_ipv6_route_rolls_back_the_ipv4_routes() {
        let ipv6_route = RouteIdentity {
            luid: TEST_LUID,
            prefix: IPV6_TUNNEL_ROUTE,
            next_hop: unspecified_v6(),
        };
        let fake = FakeApi::new(test_guid());
        fake.add_existing(ipv6_route);
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);

        let failure = routes.install().unwrap_err();
        assert_eq!(
            failure.error,
            RouteError::RouteAlreadyExists {
                prefix: IPV6_TUNNEL_ROUTE
            }
        );
        assert_eq!(failure.cleanup.removed, 2);
        assert_eq!(fake.table(), vec![ipv6_route]);
        assert!(!routes.has_routes());
    }

    #[test]
    fn a_delete_that_reports_not_found_counts_as_removed() {
        let fake = FakeApi::new(test_guid());
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        routes.install().unwrap();
        fake.remove_existing(RouteIdentity {
            luid: TEST_LUID,
            prefix: IPV4_ROUTES[0],
            next_hop: unspecified_v4(),
        });

        let report = routes.remove();
        assert!(report.is_complete());
        assert_eq!(report.removed, 3);
        assert!(!routes.has_routes());
        assert!(fake.table().is_empty());
    }

    #[test]
    fn one_delete_failure_does_not_stop_the_other_routes() {
        let fake = FakeApi::new(test_guid());
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        routes.install().unwrap();
        // Remove order is IPv6, 128.0.0.0/1, 0.0.0.0/1.
        fake.set_delete_plan(&[ERROR_SUCCESS, ERROR_ACCESS_DENIED, ERROR_SUCCESS]);

        let report = routes.remove();
        assert_eq!(report.removed, 2);
        assert_eq!(report.retained.len(), 1);
        assert_eq!(report.retained[0].prefix, IPV4_ROUTES[1]);
        assert_eq!(report.retained[0].attempts, 1);
        assert_eq!(
            report.retained[0].last_error,
            Some(RouteError::AccessDenied {
                operation: "DeleteIpForwardEntry2",
                prefix: IPV4_ROUTES[1],
            })
        );
        assert_eq!(fake.table().len(), 1);
        assert_eq!(fake.table()[0].prefix, IPV4_ROUTES[1]);

        let report = routes.remove();
        assert!(report.is_complete());
        assert!(fake.table().is_empty());
    }

    #[test]
    fn install_refuses_while_records_remain() {
        let fake = FakeApi::new(test_guid());
        fake.set_delete_fail_code(Some(ERROR_ACCESS_DENIED));
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        routes.install().unwrap();
        let report = routes.remove();
        assert!(!report.is_complete());
        let creates_before = fake.creates().len();

        let failure = routes.install().unwrap_err();
        assert_eq!(failure.error, RouteError::RoutesActive);
        assert_eq!(fake.creates().len(), creates_before);
        assert!(!failure.cleanup.is_complete());
        assert_eq!(failure.cleanup.stopped, Some(RouteError::RoutesActive));
        assert_eq!(failure.cleanup.retained.len(), 3);
    }

    #[test]
    fn repeated_install_does_not_report_active_routes_as_cleaned() {
        let fake = FakeApi::new(test_guid());
        let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
        routes.install().unwrap();
        let failure = routes.install().unwrap_err();
        assert_eq!(failure.error, RouteError::RoutesActive);
        assert!(!failure.cleanup.is_complete());
        assert_eq!(failure.cleanup.stopped, Some(RouteError::RoutesActive));
        assert!(fake.deletes().is_empty());
    }

    #[test]
    fn drop_removes_the_installed_routes() {
        let fake = FakeApi::new(test_guid());
        {
            let mut routes = boundary(&fake, Ipv6RoutePolicy::Block);
            routes.install().unwrap();
            assert!(routes.has_routes());
        }
        assert!(fake.table().is_empty());
        assert_eq!(fake.deletes().len(), 3);
    }

    #[test]
    fn an_identity_rejects_zero_values() {
        assert_eq!(
            AdapterIdentity::new(0, test_guid()).unwrap_err(),
            RouteError::InvalidIdentity("the interface LUID must be nonzero")
        );
        assert_eq!(
            AdapterIdentity::new(TEST_LUID, AdapterGuid::ZERO).unwrap_err(),
            RouteError::InvalidIdentity("the interface GUID must be nonzero")
        );
        assert!(AdapterIdentity::new(TEST_LUID, test_guid()).is_ok());
        assert!(!test_guid().is_zero());
    }

    #[test]
    fn the_boundary_can_move_to_another_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<RouteBoundary>();
    }

    #[test]
    fn documented_status_codes_map_to_the_state_machine() {
        assert_eq!(classify_status(0), NativeStatus::Success);
        assert_eq!(
            classify_status(ERROR_OBJECT_ALREADY_EXISTS),
            NativeStatus::AlreadyExists
        );
        assert_eq!(classify_status(ERROR_NOT_FOUND), NativeStatus::NotFound);
        assert_eq!(
            classify_status(ERROR_ACCESS_DENIED),
            NativeStatus::AccessDenied
        );
        assert_eq!(
            classify_status(ERROR_NOT_SUPPORTED),
            NativeStatus::NotSupported
        );
        assert_eq!(
            classify_status(ERROR_INVALID_PARAMETER),
            NativeStatus::InvalidParameter
        );
        assert_eq!(classify_status(0xdead), NativeStatus::Other(0xdead));
    }

    #[test]
    fn guid_lookup_status_separates_absence_from_failure() {
        assert_eq!(
            classify_guid_status(ERROR_SUCCESS, test_guid()),
            GuidLookup::Found(test_guid())
        );
        assert_eq!(
            classify_guid_status(ERROR_SUCCESS, AdapterGuid::ZERO),
            GuidLookup::ZeroGuid
        );
        assert_eq!(
            classify_guid_status(ERROR_INVALID_PARAMETER, AdapterGuid::ZERO),
            GuidLookup::Absent
        );
        assert_eq!(
            classify_guid_status(ERROR_NOT_FOUND, AdapterGuid::ZERO),
            GuidLookup::Absent
        );
        assert_eq!(
            classify_guid_status(ERROR_ACCESS_DENIED, AdapterGuid::ZERO),
            GuidLookup::Failed(ERROR_ACCESS_DENIED)
        );
    }

    #[test]
    fn error_text_names_the_route_and_the_cause() {
        let missing = RouteError::RouteAlreadyExists {
            prefix: IPV4_ROUTES[0],
        };
        assert!(missing.to_string().contains("already exists"));
        assert!(missing.to_string().contains("0.0.0.0/1"));
        assert!(RouteError::AdapterReplaced
            .to_string()
            .contains("different adapter"));
        let denied = RouteError::AccessDenied {
            operation: "CreateIpForwardEntry2",
            prefix: IPV4_ROUTES[1],
        };
        assert!(denied.to_string().contains("Administrator"));
        let api = RouteError::Api {
            operation: "DeleteIpForwardEntry2",
            prefix: IPV4_ROUTES[0],
            code: 1234,
        };
        assert!(api.to_string().contains("1234"));
    }

    #[test]
    fn install_failure_reports_a_stopped_cleanup_without_retained_errors() {
        let failure = InstallFailure {
            error: RouteError::AdapterMissing,
            cleanup: CleanupReport {
                stopped: Some(RouteError::AdapterReplaced),
                ..CleanupReport::default()
            },
        };
        let message = failure.to_string();
        assert!(message.contains("route cleanup stopped"));
        assert!(message.contains("different adapter"));
        assert!(!failure.cleanup.is_complete());
    }

    #[cfg(any(windows, target_pointer_width = "64"))]
    #[test]
    fn the_route_row_layout_matches_the_windows_headers() {
        use std::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<abi::RawSockaddrIn>(), 16);
        assert_eq!(size_of::<abi::RawSockaddrIn6>(), 28);
        assert_eq!(size_of::<abi::RawSockaddrInet>(), 28);
        assert_eq!(align_of::<abi::RawSockaddrInet>(), 4);
        assert_eq!(size_of::<abi::RawIpAddressPrefix>(), 32);
        assert_eq!(offset_of!(abi::RawIpAddressPrefix, prefix_length), 28);
        assert_eq!(size_of::<abi::RawMibIpForwardRow2>(), 104);
        assert_eq!(align_of::<abi::RawMibIpForwardRow2>(), 8);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, interface_luid), 0);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, interface_index), 8);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, destination_prefix), 12);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, next_hop), 44);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, site_prefix_length), 72);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, valid_lifetime), 76);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, preferred_lifetime), 80);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, metric), 84);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, protocol), 88);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, loopback), 92);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, age), 96);
        assert_eq!(offset_of!(abi::RawMibIpForwardRow2, origin), 100);
    }

    #[cfg(any(windows, target_pointer_width = "64"))]
    #[test]
    fn an_ipv4_row_uses_af_inet_and_an_unspecified_next_hop() {
        let plan = RoutePlan::for_policy(Ipv6RoutePolicy::Block);
        let key = plan.routes()[0].key(TEST_LUID);
        let row = abi::raw_row(&key);

        assert_eq!(row.interface_luid, TEST_LUID);
        assert_eq!(row.interface_index, 0);
        assert_eq!(row.destination_prefix.prefix.family(), abi::AF_INET);
        assert_eq!(row.destination_prefix.prefix.v4_address(), [0, 0, 0, 0]);
        assert_eq!(row.destination_prefix.prefix_length, 1);
        assert_eq!(row.next_hop.family(), abi::AF_INET);
        assert_eq!(row.next_hop.v4_address(), [0, 0, 0, 0]);
        assert_eq!(row.site_prefix_length, 0);
        assert_eq!(row.valid_lifetime, u32::MAX);
        assert_eq!(row.preferred_lifetime, u32::MAX);
        assert_eq!(row.metric, 0);
        assert_eq!(row.protocol, abi::MIB_IPPROTO_NETMGMT);
        assert_eq!(row.loopback, 0);
        assert_eq!(row.autoconfigure_address, 0);
        assert_eq!(row.publish, 0);
        assert_eq!(row.immortal, 1);
        assert_eq!(row.age, 0);
        assert_eq!(row.origin, abi::NL_ROUTE_ORIGIN_MANUAL);

        let key = plan.routes()[1].key(TEST_LUID);
        let row = abi::raw_row(&key);
        assert_eq!(row.destination_prefix.prefix.v4_address(), [128, 0, 0, 0]);
        assert_eq!(row.destination_prefix.prefix_length, 1);
    }

    #[cfg(any(windows, target_pointer_width = "64"))]
    #[test]
    fn an_ipv6_row_uses_af_inet6_and_an_unspecified_next_hop() {
        let plan = RoutePlan::for_policy(Ipv6RoutePolicy::Block);
        let key = plan.routes()[2].key(TEST_LUID);
        let row = abi::raw_row(&key);

        assert_eq!(row.interface_luid, TEST_LUID);
        assert_eq!(row.interface_index, 0);
        assert_eq!(row.destination_prefix.prefix.family(), abi::AF_INET6);
        let mut expected = [0u8; 16];
        expected[0] = 0x20;
        assert_eq!(row.destination_prefix.prefix.v6_address(), expected);
        assert_eq!(row.destination_prefix.prefix_length, 3);
        assert_eq!(row.next_hop.family(), abi::AF_INET6);
        assert_eq!(row.next_hop.v6_address(), [0u8; 16]);
        assert_eq!(row.protocol, abi::MIB_IPPROTO_NETMGMT);
        assert_eq!(row.immortal, 1);
    }

    #[test]
    fn the_plan_builds_only_managed_prefixes() {
        // The only constructor is `RoutePlan`. The plan produces the managed
        // prefixes and the unspecified next hop. This test records that the
        // boundary cannot be pointed at another route through a public type.
        let plan = RoutePlan::for_policy(Ipv6RoutePolicy::Block);
        for route in plan.routes() {
            assert!(route.prefix().is_valid());
            assert!(route.next_hop().is_unspecified());
            assert_eq!(route.next_hop().is_ipv4(), route.prefix().address.is_ipv4());
            let key = route.key(TEST_LUID);
            assert_eq!(key.luid, TEST_LUID);
            assert_eq!(key.prefix, route.prefix());
            assert_eq!(key.next_hop, route.next_hop());
        }
    }
}
