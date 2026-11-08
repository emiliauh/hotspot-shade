//! Host tests for the Windows physical adapter and gateway evidence module.
//!
//! This test target loads the module with `#[path]`, so the fixed-data checks
//! run in their own crate. The pure layer runs on every host. The
//! Windows ABI types and row parsing also compile under `cfg(test)`, so this
//! target runs the `MIB_UNICASTIPADDRESS_ROW` layout assertion, the multi-row
//! 80-byte stride test, and the usable-address policy tests without a Windows
//! host. The FFI declarations and the live reader stay gated to Windows. No
//! test here creates an adapter, changes a route, opens a TUN device, reads a
//! token, or sends a packet.
//!
//! The route verifier is loaded as a sibling module because the physical path
//! proof uses its retained identity, route prefix, and local subnet types. That
//! keeps the host test close to the real integration shape.
//!
//! This target loads the module into its own test crate. That is why a
//! test-only `verify` wrapper exists and why the observation types stay crate
//! private: the path-included tests must still build fixed observations for the
//! pure checks. Production code cannot call `verify`, and `prove` is private to
//! the module, so `observe` is the only production proof producer. This test
//! can still mint a proof from invented values. The token gate never accepts a
//! proof from a caller; it runs the live reads itself. Do not read a proof
//! here as live Windows evidence.
//!
//! The adapter read-order seam tests live inside the Win32 module's host tests,
//! because the seam is intentionally private. Those tests prove the identity
//! recheck runs after the unicast address table and that a mismatch stops the
//! read.

#[path = "../src/windows_route_verify.rs"]
#[allow(dead_code, unused_imports)]
mod windows_route_verify;

#[path = "../src/windows_physical_path.rs"]
mod windows_physical_path;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_physical_path::{
    verify, GatewayObservation, PhysicalAdapterObservation, PhysicalPathError,
    PhysicalPathObservation, GATEWAY_PROBES,
};
use windows_route_verify::{
    AdapterGuid, BestRouteProbe, Ipv6RoutePolicy, Ipv6Stack, ObservedRoute,
    RetainedAdapterIdentity, RouteObservation, RoutePrefix, TunnelIdentity, VerifyPolicy,
    IPV4_ROUTES, IPV6_TUNNEL_ROUTE,
};

const INDEX: u32 = 17;
const LUID: u64 = 0x0000_6000_0000_0011;
const NETWORK: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 0);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 1);
const LOCAL: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 2);
const BROADCAST: Ipv4Addr = Ipv4Addr::new(172, 20, 10, 15);
const PREFIX_LENGTH: u8 = 28;

fn guid() -> AdapterGuid {
    AdapterGuid::new(
        0x0011_2233,
        0x4455,
        0x6677,
        [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
    )
}

fn prefix(address: Ipv4Addr, length: u8) -> RoutePrefix {
    RoutePrefix::new(IpAddr::V4(address), length).unwrap()
}

fn route(
    destination: RoutePrefix,
    next_hop: IpAddr,
    protocol: u32,
    loopback: bool,
) -> ObservedRoute {
    ObservedRoute {
        prefix: destination,
        interface_index: INDEX,
        interface_luid: LUID,
        next_hop,
        metric: 0,
        protocol,
        loopback,
    }
}

fn gateway_probe(destination: Ipv4Addr, gateway: Ipv4Addr) -> BestRouteProbe {
    BestRouteProbe {
        destination: IpAddr::V4(destination),
        best_interface_index: INDEX,
        route: route(
            prefix(Ipv4Addr::UNSPECIFIED, 0),
            IpAddr::V4(gateway),
            3,
            false,
        ),
    }
}

fn gateway_observation(gateway: Ipv4Addr) -> GatewayObservation {
    GatewayObservation {
        probes: [
            gateway_probe(GATEWAY_PROBES[0], gateway),
            gateway_probe(GATEWAY_PROBES[1], gateway),
        ],
    }
}

fn destination_probe(destination: Ipv4Addr) -> BestRouteProbe {
    BestRouteProbe {
        destination: IpAddr::V4(destination),
        best_interface_index: INDEX,
        route: route(
            prefix(NETWORK, PREFIX_LENGTH),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            3,
            false,
        ),
    }
}

fn adapter(address: Ipv4Addr) -> PhysicalAdapterObservation {
    PhysicalAdapterObservation {
        identity: RetainedAdapterIdentity::new(INDEX, LUID, guid()).unwrap(),
        interface_type: 71,
        oper_status: 1,
        admin_status: 1,
        media_connect_state: 1,
        access_type: 2,
        tunnel_type: 0,
        hardware_interface: true,
        filter_interface: false,
        physical_address_length: 6,
        physical_address_nonzero: true,
        ipv4_address: address,
        on_link_prefix_length: PREFIX_LENGTH,
        usable_ipv4_address_count: 1,
    }
}

fn observation(gateway: Ipv4Addr, adapter_address: Ipv4Addr) -> PhysicalPathObservation {
    let adapter = adapter(adapter_address);
    PhysicalPathObservation {
        adapter_before: adapter,
        adapter_after: adapter,
        gateway_before: gateway_observation(gateway),
        gateway_after: gateway_observation(gateway),
        destination_route: destination_probe(gateway),
        destination_address: gateway,
    }
}

#[test]
fn the_gateway_probes_cover_the_two_managed_halves() {
    use windows_route_verify::IPV4_ROUTES;

    assert!(IPV4_ROUTES[0].contains(IpAddr::V4(GATEWAY_PROBES[0])));
    assert!(IPV4_ROUTES[1].contains(IpAddr::V4(GATEWAY_PROBES[1])));
}

#[test]
fn a_complete_public_observation_is_proven() {
    let proof = verify(&observation(GATEWAY, LOCAL)).unwrap();
    assert_eq!(proof.gateway(), GATEWAY);
    assert_eq!(proof.local_address(), LOCAL);
    assert_eq!(proof.local_prefix(), prefix(NETWORK, PREFIX_LENGTH));
    assert_eq!(proof.adapter().interface_index(), INDEX);
    assert_eq!(proof.adapter().interface_luid(), LUID);
}

#[test]
fn the_physical_subnet_proof_is_applied_by_the_route_verifier() {
    let physical = verify(&observation(GATEWAY, LOCAL)).unwrap();
    let subnet = physical.proven_local_subnet().unwrap();
    let tunnel_index = INDEX + 1;
    let tunnel_luid = LUID + 1;
    let policy = VerifyPolicy::new(
        TunnelIdentity::new(tunnel_index, tunnel_luid).unwrap(),
        Ipv6RoutePolicy::Block,
    )
    .with_local_subnet(subnet);
    let tunnel_route = |prefix: RoutePrefix| ObservedRoute {
        prefix,
        interface_index: tunnel_index,
        interface_luid: tunnel_luid,
        next_hop: match prefix.address {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        metric: 0,
        protocol: 10006,
        loopback: false,
    };
    let probes = policy
        .ipv4_probes
        .iter()
        .map(|address| {
            let destination = IpAddr::V4(*address);
            let prefix = *IPV4_ROUTES
                .iter()
                .find(|prefix| prefix.contains(destination))
                .unwrap();
            BestRouteProbe {
                destination,
                best_interface_index: tunnel_index,
                route: tunnel_route(prefix),
            }
        })
        .chain(policy.ipv6_probes.iter().map(|address| BestRouteProbe {
            destination: IpAddr::V6(*address),
            best_interface_index: tunnel_index,
            route: tunnel_route(IPV6_TUNNEL_ROUTE),
        }))
        .collect();
    let mut routes = RouteObservation {
        ipv4_routes: vec![
            tunnel_route(IPV4_ROUTES[0]),
            tunnel_route(IPV4_ROUTES[1]),
            destination_probe(GATEWAY).route,
        ],
        ipv6_routes: vec![tunnel_route(IPV6_TUNNEL_ROUTE)],
        ipv6_stack: Ipv6Stack::Present,
        probes,
    };
    assert!(windows_route_verify::verify(&routes, &policy)
        .unwrap()
        .warnings
        .is_empty());
    routes.ipv4_routes[2].interface_luid += 2;
    assert!(windows_route_verify::verify(&routes, &policy).is_err());
}

#[test]
fn a_gateway_that_is_the_adapter_address_is_refused() {
    let error = verify(&observation(GATEWAY, GATEWAY)).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::GatewayUnusable("the gateway is the adapter address")
    );
}

#[test]
fn a_gateway_on_the_subnet_network_address_is_refused() {
    let error = verify(&observation(NETWORK, LOCAL)).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::GatewayUnusable("the gateway is the subnet network address")
    );
}

#[test]
fn a_gateway_on_the_subnet_broadcast_address_is_refused() {
    let error = verify(&observation(BROADCAST, LOCAL)).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::GatewayUnusable("the gateway is the subnet broadcast address")
    );
}

#[test]
fn an_observation_with_two_usable_addresses_is_refused() {
    let mut observation = observation(GATEWAY, LOCAL);
    observation.adapter_before.usable_ipv4_address_count = 2;
    observation.adapter_after.usable_ipv4_address_count = 2;
    let error = verify(&observation).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::AdapterAddressUnusable(
            "the adapter must report exactly one usable IPv4 address"
        )
    );
}

#[test]
fn an_apipa_adapter_address_is_refused() {
    // A link-local APIPA address means DHCP did not complete. The Win32 reader
    // does not count it as usable, and the pure layer refuses it as the adapter
    // address even when the observation says the count is one.
    let apipa = Ipv4Addr::new(169, 254, 10, 20);
    let error = verify(&observation(GATEWAY, apipa)).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::AdapterAddressUnusable("the adapter address is not private or shared")
    );
}

#[test]
fn an_error_text_does_not_name_the_gateway_or_the_adapter_address() {
    let mut observation = observation(GATEWAY, LOCAL);
    observation.destination_address = Ipv4Addr::new(172, 20, 10, 3);
    let text = verify(&observation).unwrap_err().to_string();
    assert!(!text.contains("172.20.10.1"));
    assert!(!text.contains("172.20.10.2"));
    assert!(!text.contains("600000000011"));
    assert!(!text.contains(&LUID.to_string()));
}

#[test]
fn an_observation_with_no_usable_address_is_refused() {
    let mut observation = observation(GATEWAY, LOCAL);
    observation.adapter_before.usable_ipv4_address_count = 0;
    observation.adapter_after.usable_ipv4_address_count = 0;
    let error = verify(&observation).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::AdapterAddressUnusable(
            "the adapter must report exactly one usable IPv4 address"
        )
    );
}

#[test]
fn a_public_adapter_address_is_refused() {
    let error = verify(&observation(GATEWAY, Ipv4Addr::new(8, 8, 4, 4))).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::AdapterAddressUnusable("the adapter address is not private or shared")
    );
}

#[test]
fn a_prefix_broader_than_the_hotspot_bound_is_refused() {
    let mut observation = observation(GATEWAY, LOCAL);
    observation.adapter_before.on_link_prefix_length = 15;
    observation.adapter_after.on_link_prefix_length = 15;
    let error = verify(&observation).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::AdapterAddressUnusable(
            "the on-link prefix is too broad for one hotspot link"
        )
    );
}

#[test]
fn a_gateway_on_another_adapter_is_refused() {
    let mut observation = observation(GATEWAY, LOCAL);
    for gateway in [
        &mut observation.gateway_before,
        &mut observation.gateway_after,
    ] {
        for probe in &mut gateway.probes {
            probe.best_interface_index = INDEX + 1;
            probe.route.interface_index = INDEX + 1;
        }
    }
    assert_eq!(
        verify(&observation).unwrap_err(),
        PhysicalPathError::AdapterIdentityChanged
    );
}

#[test]
fn a_non_ipv4_destination_route_prefix_is_refused() {
    let mut observation = observation(GATEWAY, LOCAL);
    observation.destination_route.route.prefix =
        RoutePrefix::new(IpAddr::V6("2001:db8::".parse().unwrap()), 32).unwrap();
    let error = verify(&observation).unwrap_err();
    assert_eq!(
        error,
        PhysicalPathError::DestinationRouteUnusable(
            "the destination route does not contain the destination"
        )
    );
}

#[test]
fn the_debug_output_redacts_the_gateway_and_adapter_identity() {
    let observation = observation(GATEWAY, LOCAL);
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
    }
}

#[test]
fn the_token_gate_refuses_with_one_fixed_code() {
    // The live gate runs the evidence reads. The shape check refuses an
    // IPv6 destination and a missing pin before any read, and a failed
    // observation becomes the same fixed code with no address in it.
    let destination: std::net::SocketAddr = "172.20.10.1:1080".parse().unwrap();
    let error = windows_route_verify::require_token_destination_with(destination, None, |_, _| {
        panic!("no read without a pin")
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "source_gateway_unproven");
    let error =
        windows_route_verify::require_token_destination_with(destination, Some(17), |_, _| {
            Err(PhysicalPathError::DestinationMismatch)
        })
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
    assert_eq!(error.to_string(), "source_gateway_unproven");
}

#[cfg(windows)]
#[test]
fn the_windows_observer_has_a_read_only_evidence_signature() {
    let observe: fn(
        std::net::Ipv4Addr,
    ) -> Result<
        windows_physical_path::PhysicalPathProof,
        windows_physical_path::PhysicalPathError,
    > = windows_physical_path::observe;
    let _ = observe;
}

#[cfg(windows)]
#[test]
fn the_windows_default_physical_route_is_read_only() {
    let default_physical_route: fn() -> Result<(u32, Ipv4Addr), PhysicalPathError> =
        windows_physical_path::default_physical_route;
    let _ = default_physical_route;
}

#[cfg(windows)]
#[test]
fn the_windows_idle_token_gate_is_read_only() {
    let observe: fn(
        Ipv4Addr,
        u32,
    ) -> Result<windows_physical_path::PhysicalPathProof, PhysicalPathError> =
        windows_physical_path::observe_token_destination_idle;
    let _ = observe;
}
