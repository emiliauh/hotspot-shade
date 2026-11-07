use hotspotshade::normalization::{self, Audit};
use hotspotshade::phone::PhoneProxy;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6, TcpListener};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[test]
fn mapped_addresses_are_rejected_before_socket_creation() {
    let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
    for iface in [None, Some(1)] {
        for (flow, scope) in [(0, 0), (1, 0), (0, 1)] {
            let addr = SocketAddr::V6(SocketAddrV6::new(mapped, 9, flow, scope));
            let audit = Audit::default();
            assert_eq!(
                normalization::tcp_start(addr, iface, &audit)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                normalization::tcp_connect(addr, iface, &audit, Duration::from_secs(1))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                normalization::tcp_connect_cancellable(
                    addr,
                    iface,
                    &audit,
                    Duration::from_secs(1),
                    None
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                normalization::udp_socket(IpAddr::V6(mapped), iface, &audit)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(audit.snapshot(), (0, 0));
        }
    }
}

#[test]
fn ipv4_loopback_uses_audited_ipv4_sockets() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let audit = Audit::default();
    let stream = normalization::tcp_connect(
        listener.local_addr().unwrap(),
        None,
        &audit,
        Duration::from_secs(2),
    )
    .unwrap();
    let _accepted = listener.accept().unwrap();
    let udp = normalization::udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), None, &audit).unwrap();
    assert!(stream.local_addr().unwrap().is_ipv4());
    assert!(udp.local_addr().unwrap().is_ipv4());
    assert_eq!(stream.ttl().unwrap(), 65);
    assert_eq!(udp.ttl().unwrap(), 65);
    assert_eq!(audit.snapshot(), (2, 0));
}

#[test]
fn native_ipv6_scope_and_flow_information_are_rejected() {
    let audit = Audit::default();
    for (flow, scope) in [(1, 0), (0, 1), (1, 1)] {
        let addr = SocketAddr::V6(SocketAddrV6::new("::1".parse().unwrap(), 9, flow, scope));
        assert_eq!(
            normalization::tcp_start(addr, None, &audit)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            normalization::tcp_connect(addr, None, &audit, Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(audit.snapshot(), (0, 0));
    let udp = normalization::udp_socket("::1".parse().unwrap(), None, &audit).unwrap();
    udp.connect("[::1]:9".parse().unwrap()).unwrap();
    for (flow, scope) in [(1, 0), (0, 1), (1, 1)] {
        let addr = SocketAddr::V6(SocketAddrV6::new("::1".parse().unwrap(), 9, flow, scope));
        assert_eq!(
            udp.connect(addr).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            udp.send_to(b"x", addr).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(audit.snapshot(), (1, 0));
}

#[test]
fn phone_proxy_rejects_mapped_outer_address_for_both_check_paths() {
    let proxy = PhoneProxy {
        address: "[::ffff:127.0.0.1]:9".parse().unwrap(),
        username: "test".into(),
        token: "test".into(),
        iface: None,
        timeout: Duration::from_secs(1),
    };
    let audit = Audit::default();
    assert_eq!(
        proxy.check(&audit).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        proxy
            .check_cancellable(&audit, &AtomicBool::new(false))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(audit.snapshot(), (0, 0));
}

#[test]
fn normalized_udp_rejects_mapped_destinations_after_creation() {
    use std::net::{Ipv6Addr, UdpSocket};

    let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    v4.set_nonblocking(true).unwrap();
    let v6 = UdpSocket::bind("[::1]:0").unwrap();
    v6.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mapped = SocketAddr::V6(SocketAddrV6::new(
        Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
        v4.local_addr().unwrap().port(),
        0,
        0,
    ));
    let audit = Audit::default();
    let socket = normalization::udp_socket(IpAddr::V6(Ipv6Addr::LOCALHOST), None, &audit).unwrap();
    let debug = format!("{socket:?}");
    assert!(!debug.contains("fd"));
    assert!(!debug.contains("socket:"));
    socket.set_nonblocking(true).unwrap();
    assert_eq!(
        socket.send_to(b"bad", mapped).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        socket.connect(mapped).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        socket
            .send_to(b"bad", v4.local_addr().unwrap())
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        socket.connect(v4.local_addr().unwrap()).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let mut buf = [0; 16];
    assert_eq!(
        v4.recv_from(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        socket.send_to(b"native", v6.local_addr().unwrap()).unwrap(),
        6
    );
    let (n, _) = v6.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"native");
    socket.connect(v6.local_addr().unwrap()).unwrap();
    for (flow, scope) in [(0, 0), (1, 0), (0, 1)] {
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            v4.local_addr().unwrap().port(),
            flow,
            scope,
        ));
        assert_eq!(
            socket.send_to(b"bad", scoped).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            socket.connect(scoped).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(socket.send(b"connected").unwrap(), 9);
    let (n, _) = v6.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"connected");
    assert_eq!(audit.snapshot(), (1, 0));

    let ipv4 = normalization::udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), None, &audit).unwrap();
    assert_eq!(
        ipv4.send_to(b"bad", v6.local_addr().unwrap())
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        ipv4.connect(v6.local_addr().unwrap()).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    v4.set_nonblocking(false).unwrap();
    v4.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    ipv4.connect(v4.local_addr().unwrap()).unwrap();
    ipv4.send(b"ipv4").unwrap();
    let (n, _) = v4.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ipv4");
    assert_eq!(audit.snapshot(), (2, 0));
}
