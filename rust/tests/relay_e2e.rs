//! Hermetic tests for the public relay API. No tunnel or routes are created.
//!
//! These tests use loopback sockets only. They run on macOS, Linux, and
//! Windows. A Windows run does not prove that a live tunnel works.

use hotspotshade::{
    packet,
    relay::{Relay, RelayConfig},
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const TOTAL: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct Flow {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    client_next: u32,
    server_next: Option<u32>,
    payload: Vec<u8>,
    received: Vec<u8>,
    syn_done: bool,
    fin_seen: bool,
}
impl Flow {
    fn tcp(&self, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        match (self.src, self.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => packet::build_tcp(&packet::TcpBuild {
                src,
                dst,
                sport: self.sport,
                dport: self.dport,
                seq,
                ack,
                flags,
                window: 65535,
                payload: data,
                options: if flags & packet::SYN != 0 {
                    &[2, 4, 5, 120]
                } else {
                    &[]
                },
                ttl: 64,
                ident: 0,
            })
            .unwrap(),
            (IpAddr::V6(src), IpAddr::V6(dst)) => packet::build_tcp_v6(&packet::TcpBuildV6 {
                src,
                dst,
                sport: self.sport,
                dport: self.dport,
                seq,
                ack,
                flags,
                window: 65535,
                payload: data,
                options: if flags & packet::SYN != 0 {
                    &[2, 4, 5, 120]
                } else {
                    &[]
                },
                hop_limit: 64,
            })
            .unwrap(),
            _ => panic!("mismatched address family"),
        }
    }
    fn udp(&self, data: &[u8]) -> Vec<u8> {
        match (self.src, self.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                packet::build_udp(src, dst, self.sport, self.dport, data, 64, 0).unwrap()
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                packet::build_udp_v6(src, dst, self.sport, self.dport, data, 64).unwrap()
            }
            _ => panic!("mismatched address family"),
        }
    }
}
fn flow(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, tag: u8) -> Flow {
    Flow {
        src,
        dst,
        sport,
        dport,
        client_next: 1000,
        server_next: None,
        payload: (0..TOTAL)
            .map(|n| (n as u8).wrapping_mul(31).wrapping_add(tag))
            .collect(),
        received: Vec::new(),
        syn_done: false,
        fin_seen: false,
    }
}
fn tcp_echo(listener: TcpListener, count: usize) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut handlers = Vec::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            handlers.push(thread::spawn(move || {
                stream.set_read_timeout(Some(TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(TIMEOUT)).unwrap();
                let mut buf = vec![0; TOTAL];
                stream.read_exact(&mut buf).unwrap();
                stream.write_all(&buf).unwrap();
                stream.shutdown(Shutdown::Write).unwrap();
            }));
        }
        for handler in handlers {
            handler.join().unwrap();
        }
    })
}
fn udp_echo(socket: UdpSocket, count: usize) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut data = [0u8; 2048];
        for _ in 0..count {
            let (n, peer) = socket.recv_from(&mut data).unwrap();
            socket.send_to(&data[..n], peer).unwrap();
        }
    })
}

#[test]
fn concurrent_ipv4_ipv6_tcp_bulk_and_udp_flows() {
    let v4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let v6 = TcpListener::bind("[::1]:0").unwrap();
    let udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp6 = UdpSocket::bind("[::1]:0").unwrap();
    let (p4, p6, u4, u6) = (
        v4.local_addr().unwrap().port(),
        v6.local_addr().unwrap().port(),
        udp4.local_addr().unwrap().port(),
        udp6.local_addr().unwrap().port(),
    );
    let tcp_tasks = [tcp_echo(v4, 2), tcp_echo(v6, 2)];
    let udp_tasks = [udp_echo(udp4, 2), udp_echo(udp6, 2)];
    let mut relay = Relay::start(RelayConfig {
        allow_unpinned: true,
        ipv6_forward: true,
        workers: 4,
        ..RelayConfig::default()
    })
    .unwrap();
    let mut flows = vec![
        flow(
            Ipv4Addr::new(198, 18, 0, 2).into(),
            Ipv4Addr::LOCALHOST.into(),
            21001,
            p4,
            1,
        ),
        flow(
            Ipv4Addr::new(198, 18, 0, 2).into(),
            Ipv4Addr::LOCALHOST.into(),
            21002,
            p4,
            2,
        ),
        flow(
            "fd42::2".parse().unwrap(),
            Ipv6Addr::LOCALHOST.into(),
            21003,
            p6,
            3,
        ),
        flow(
            "fd42::2".parse().unwrap(),
            Ipv6Addr::LOCALHOST.into(),
            21004,
            p6,
            4,
        ),
    ];
    let udp_flows = [
        flow(
            Ipv4Addr::new(198, 18, 0, 2).into(),
            Ipv4Addr::LOCALHOST.into(),
            22001,
            u4,
            5,
        ),
        flow(
            Ipv4Addr::new(198, 18, 0, 2).into(),
            Ipv4Addr::LOCALHOST.into(),
            22002,
            u4,
            6,
        ),
        flow(
            "fd42::2".parse().unwrap(),
            Ipv6Addr::LOCALHOST.into(),
            22003,
            u6,
            7,
        ),
        flow(
            "fd42::2".parse().unwrap(),
            Ipv6Addr::LOCALHOST.into(),
            22004,
            u6,
            8,
        ),
    ];
    for f in &flows {
        relay
            .dispatch(f.tcp(f.client_next, 0, packet::SYN, &[]))
            .unwrap();
    }
    for f in &udp_flows {
        relay.dispatch(f.udp(&f.payload[..128])).unwrap();
    }
    let mut udp_seen = [false; 4];
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline
        && (flows
            .iter()
            .any(|f| !f.fin_seen || f.received.len() != TOTAL)
            || udp_seen.iter().any(|v| !v))
    {
        let raw = match relay.recv_timeout(Duration::from_millis(100)) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let ip = packet::parse_ip(&raw).expect("valid IP packet");
        match ip.protocol {
            packet::PROTO_UDP => {
                let seg = packet::parse_udp(ip.payload).unwrap();
                let index = udp_flows
                    .iter()
                    .position(|f| f.sport == seg.dport)
                    .expect("known UDP flow");
                let f = &udp_flows[index];
                assert_eq!((ip.src, ip.dst, seg.sport), (f.dst, f.src, f.dport));
                assert_eq!(seg.data, &f.payload[..128]);
                udp_seen[index] = true;
            }
            packet::PROTO_TCP => {
                let seg = packet::parse_tcp(ip.payload).unwrap();
                let index = flows
                    .iter()
                    .position(|f| f.sport == seg.dport)
                    .expect("known TCP flow");
                let f = &mut flows[index];
                assert_eq!((ip.src, ip.dst, seg.sport), (f.dst, f.src, f.dport));
                assert_eq!(seg.flags & packet::RST, 0, "relay reset flow {index}");
                if !f.syn_done
                    && seg.flags & (packet::SYN | packet::ACK) == (packet::SYN | packet::ACK)
                {
                    f.syn_done = true;
                    f.client_next += 1;
                    f.server_next = Some(seg.seq.wrapping_add(1));
                    relay
                        .dispatch(f.tcp(f.client_next, f.server_next.unwrap(), packet::ACK, &[]))
                        .unwrap();
                    for chunk in f.payload.chunks(1024) {
                        relay
                            .dispatch(f.tcp(
                                f.client_next,
                                f.server_next.unwrap(),
                                packet::ACK | packet::PSH,
                                chunk,
                            ))
                            .unwrap();
                        f.client_next = f.client_next.wrapping_add(chunk.len() as u32);
                    }
                } else if f.syn_done {
                    let expected = f.server_next.unwrap();
                    if !seg.data.is_empty() {
                        if seg.seq == expected {
                            f.received.extend_from_slice(seg.data);
                            f.server_next = Some(expected.wrapping_add(seg.data.len() as u32));
                        } else {
                            assert!(
                                seg.seq.wrapping_sub(expected) > 0x8000_0000,
                                "out-of-order data"
                            );
                        }
                    }
                    if seg.flags & packet::FIN != 0
                        && seg.seq.wrapping_add(seg.data.len() as u32) == f.server_next.unwrap()
                    {
                        f.server_next = Some(f.server_next.unwrap().wrapping_add(1));
                        f.fin_seen = true;
                    }
                    if !seg.data.is_empty() || seg.flags & packet::FIN != 0 {
                        relay
                            .dispatch(f.tcp(
                                f.client_next,
                                f.server_next.unwrap(),
                                packet::ACK,
                                &[],
                            ))
                            .unwrap();
                    }
                }
            }
            _ => panic!("unexpected protocol"),
        }
    }
    for (i, f) in flows.iter().enumerate() {
        assert!(f.syn_done, "flow {i} handshake");
        assert!(f.fin_seen, "flow {i} FIN");
        assert_eq!(f.received, f.payload, "flow {i} payload");
    }
    assert!(udp_seen.iter().all(|v| *v), "all UDP replies");
    let stats = relay.stats();
    assert_eq!(stats.tcp_flows, 4);
    assert_eq!(stats.udp_datagrams_in, 4);
    assert_eq!(stats.udp_datagrams_out, 4);
    assert_eq!(stats.ttl_bad, 0);
    assert_eq!(stats.flow_errors, 0);
    assert_eq!(stats.queue_dropped, 0);
    assert_eq!(stats.send_dropped, 0);
    relay.stop();
    assert!(!relay.is_running());
    for task in tcp_tasks.into_iter().chain(udp_tasks) {
        task.join().unwrap();
    }
}

#[test]
fn stop_closes_an_active_outer_socket_and_rejects_packets() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        tx.send(()).unwrap();
        let mut b = [0; 1];
        assert_eq!(stream.read(&mut b).unwrap(), 0);
    });
    let mut relay = Relay::start(RelayConfig {
        allow_unpinned: true,
        workers: 2,
        ..RelayConfig::default()
    })
    .unwrap();
    let f = flow(
        Ipv4Addr::new(198, 18, 0, 2).into(),
        address.ip(),
        23001,
        address.port(),
        9,
    );
    relay
        .dispatch(f.tcp(f.client_next, 0, packet::SYN, &[]))
        .unwrap();
    rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let raw = relay.recv_timeout(Duration::from_secs(3)).unwrap();
    let p = packet::parse_ip(&raw).unwrap();
    assert_eq!(
        packet::parse_tcp(p.payload).unwrap().flags & (packet::SYN | packet::ACK),
        packet::SYN | packet::ACK
    );
    let start = Instant::now();
    relay.stop();
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(!relay.is_running());
    assert!(relay
        .dispatch(f.tcp(f.client_next, 0, packet::SYN, &[]))
        .is_err());
    assert_eq!(relay.stats().ttl_bad, 0);
    server.join().unwrap();
}
