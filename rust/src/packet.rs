//! IP and transport packet codecs for the target device relay.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_ICMPV6: u8 = 58;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}
fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// Return the Internet checksum in host byte order.
pub fn checksum(data: &[u8]) -> u16 {
    let (chunks, remainder) = data.as_chunks::<2>();
    let mut sum: u64 = chunks.iter().map(|c| u16::from_be_bytes(*c) as u64).sum();
    if let Some(&last) = remainder.first() {
        sum += (last as u64) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Debug, PartialEq, Eq)]
pub struct IpPacket<'a> {
    pub version: u8,
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ttl: u8,
    pub fragmented: bool,
    pub payload: &'a [u8],
}

pub fn parse_ip(raw: &[u8]) -> Option<IpPacket<'_>> {
    if raw.len() < 20 {
        return None;
    }
    match raw[0] >> 4 {
        4 => {
            let ihl = (raw[0] as usize & 15) * 4;
            if ihl < 20 || raw.len() < ihl {
                return None;
            }
            let declared = u16_at(raw, 2) as usize;
            let total = if declared == 0 || declared > raw.len() {
                raw.len()
            } else {
                declared
            };
            if total < ihl {
                return None;
            }
            Some(IpPacket {
                version: 4,
                protocol: raw[9],
                src: IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15])),
                dst: IpAddr::V4(Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19])),
                ttl: raw[8],
                fragmented: u16_at(raw, 6) & 0x3fff != 0,
                payload: &raw[ihl..total],
            })
        }
        6 if raw.len() >= 40 => {
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).ok()?);
            let end = 40 + u16_at(raw, 4) as usize;
            if end > raw.len() {
                return None;
            }
            let mut next = raw[6];
            let mut offset = 40;
            let mut fragmented = false;
            for _ in 0..16 {
                let size = match next {
                    0 | 43 | 60 => {
                        if offset + 2 > end {
                            return None;
                        }
                        (raw[offset + 1] as usize + 1) * 8
                    }
                    51 => {
                        if offset + 2 > end {
                            return None;
                        }
                        (raw[offset + 1] as usize + 2) * 4
                    }
                    44 => {
                        fragmented = true;
                        8
                    }
                    _ => {
                        return Some(IpPacket {
                            version: 6,
                            protocol: next,
                            src: src.into(),
                            dst: dst.into(),
                            ttl: raw[7],
                            fragmented,
                            payload: &raw[offset..end],
                        })
                    }
                };
                if offset + size > end {
                    return None;
                }
                next = raw[offset];
                offset += size;
            }
            None
        }
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: &'a [u8],
    pub data: &'a [u8],
}
pub fn parse_tcp(data: &[u8]) -> Option<TcpSegment<'_>> {
    if data.len() < 20 {
        return None;
    }
    let offset = ((data[12] >> 4) as usize) * 4;
    if offset < 20 || offset > data.len() {
        return None;
    }
    Some(TcpSegment {
        sport: u16_at(data, 0),
        dport: u16_at(data, 2),
        seq: u32_at(data, 4),
        ack: u32_at(data, 8),
        flags: data[13] & 0x3f,
        window: u16_at(data, 14),
        options: &data[20..offset],
        data: &data[offset..],
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct UdpSegment<'a> {
    pub sport: u16,
    pub dport: u16,
    pub data: &'a [u8],
}
pub fn parse_udp(data: &[u8]) -> Option<UdpSegment<'_>> {
    if data.len() < 8 {
        return None;
    }
    let length = u16_at(data, 4) as usize;
    let end = if length >= 8 {
        data.len().min(length)
    } else {
        data.len()
    };
    Some(UdpSegment {
        sport: u16_at(data, 0),
        dport: u16_at(data, 2),
        data: &data[8..end],
    })
}

fn pseudo(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> Result<Vec<u8>, &'static str> {
    let len = u16::try_from(len).map_err(|_| "transport segment too large")?;
    let mut data = Vec::with_capacity(12 + len as usize);
    data.extend_from_slice(&src.octets());
    data.extend_from_slice(&dst.octets());
    data.extend_from_slice(&[0, proto]);
    data.extend_from_slice(&len.to_be_bytes());
    Ok(data)
}

/// Build a non-fragmented IPv4 packet. `ident` is supplied by the caller.
pub fn build_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    payload: &[u8],
    ttl: u8,
    ident: u16,
) -> Result<Vec<u8>, &'static str> {
    let len = payload
        .len()
        .checked_add(20)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or("IPv4 packet too large")?;
    let mut packet = Vec::with_capacity(len as usize);
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(&ident.to_be_bytes());
    packet.extend_from_slice(&0x4000u16.to_be_bytes());
    packet.extend_from_slice(&[ttl, proto, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub struct TcpBuild<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
    pub options: &'a [u8],
    pub ttl: u8,
    pub ident: u16,
}
pub fn build_tcp(fields: &TcpBuild<'_>) -> Result<Vec<u8>, &'static str> {
    let opt_len = (fields.options.len() + 3) & !3;
    if opt_len > 40 {
        return Err("TCP options too long");
    }
    let seg_len = 20usize
        .checked_add(opt_len)
        .and_then(|n| n.checked_add(fields.payload.len()))
        .ok_or("TCP segment too large")?;
    if seg_len + 20 > u16::MAX as usize {
        return Err("IPv4 packet too large");
    }
    let mut seg = Vec::with_capacity(seg_len);
    seg.extend_from_slice(&fields.sport.to_be_bytes());
    seg.extend_from_slice(&fields.dport.to_be_bytes());
    seg.extend_from_slice(&fields.seq.to_be_bytes());
    seg.extend_from_slice(&fields.ack.to_be_bytes());
    let off_flags = (((20 + opt_len) as u16 / 4) << 12) | (fields.flags as u16 & 0x3f);
    seg.extend_from_slice(&off_flags.to_be_bytes());
    seg.extend_from_slice(&fields.window.to_be_bytes());
    seg.extend_from_slice(&[0; 4]);
    seg.extend_from_slice(fields.options);
    seg.resize(20 + opt_len, 1);
    seg.extend_from_slice(fields.payload);
    let mut sum_data = pseudo(fields.src, fields.dst, PROTO_TCP, seg.len())?;
    sum_data.extend_from_slice(&seg);
    let sum = checksum(&sum_data);
    seg[16..18].copy_from_slice(&sum.to_be_bytes());
    build_ipv4(
        fields.src,
        fields.dst,
        PROTO_TCP,
        &seg,
        fields.ttl,
        fields.ident,
    )
}

pub fn build_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
    ttl: u8,
    ident: u16,
) -> Result<Vec<u8>, &'static str> {
    let len = payload
        .len()
        .checked_add(8)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or("UDP datagram too large")?;
    if len as usize + 20 > u16::MAX as usize {
        return Err("IPv4 packet too large");
    }
    let mut seg = Vec::with_capacity(len as usize);
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&len.to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(payload);
    let mut sum_data = pseudo(src, dst, PROTO_UDP, seg.len())?;
    sum_data.extend_from_slice(&seg);
    let sum = checksum(&sum_data);
    seg[6..8].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    build_ipv4(src, dst, PROTO_UDP, &seg, ttl, ident)
}
pub fn mss_option(mss: u16) -> [u8; 4] {
    let b = mss.to_be_bytes();
    [2, 4, b[0], b[1]]
}

fn pseudo_v6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, len: usize) -> Result<Vec<u8>, &'static str> {
    let len = u32::try_from(len).map_err(|_| "transport segment too large")?;
    let mut data = Vec::with_capacity(40 + len as usize);
    data.extend_from_slice(&src.octets());
    data.extend_from_slice(&dst.octets());
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(&[0, 0, 0, proto]);
    Ok(data)
}

/// Build an IPv6 packet without extension headers. Jumbograms are not supported.
pub fn build_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    proto: u8,
    payload: &[u8],
    hop_limit: u8,
) -> Result<Vec<u8>, &'static str> {
    let len = u16::try_from(payload.len()).map_err(|_| "IPv6 packet too large")?;
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(&[proto, hop_limit]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub struct TcpBuildV6<'a> {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
    pub options: &'a [u8],
    pub hop_limit: u8,
}
pub fn build_tcp_v6(fields: &TcpBuildV6<'_>) -> Result<Vec<u8>, &'static str> {
    let opt_len = fields
        .options
        .len()
        .checked_add(3)
        .ok_or("TCP options too long")?
        & !3;
    if opt_len > 40 {
        return Err("TCP options too long");
    }
    let seg_len = 20usize
        .checked_add(opt_len)
        .and_then(|n| n.checked_add(fields.payload.len()))
        .ok_or("TCP segment too large")?;
    if seg_len > u16::MAX as usize {
        return Err("TCP segment too large");
    }
    let mut seg = Vec::with_capacity(seg_len);
    seg.extend_from_slice(&fields.sport.to_be_bytes());
    seg.extend_from_slice(&fields.dport.to_be_bytes());
    seg.extend_from_slice(&fields.seq.to_be_bytes());
    seg.extend_from_slice(&fields.ack.to_be_bytes());
    let off_flags = (((20 + opt_len) as u16 / 4) << 12) | (fields.flags as u16 & 0x3f);
    seg.extend_from_slice(&off_flags.to_be_bytes());
    seg.extend_from_slice(&fields.window.to_be_bytes());
    seg.extend_from_slice(&[0; 4]);
    seg.extend_from_slice(fields.options);
    seg.resize(20 + opt_len, 1);
    seg.extend_from_slice(fields.payload);
    let mut sum_data = pseudo_v6(fields.src, fields.dst, PROTO_TCP, seg.len())?;
    sum_data.extend_from_slice(&seg);
    let sum = checksum(&sum_data);
    seg[16..18].copy_from_slice(&sum.to_be_bytes());
    build_ipv6(fields.src, fields.dst, PROTO_TCP, &seg, fields.hop_limit)
}

pub fn build_udp_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
    hop_limit: u8,
) -> Result<Vec<u8>, &'static str> {
    let len = payload
        .len()
        .checked_add(8)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or("UDP datagram too large")?;
    let mut seg = Vec::with_capacity(len as usize);
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&len.to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(payload);
    let mut sum_data = pseudo_v6(src, dst, PROTO_UDP, seg.len())?;
    sum_data.extend_from_slice(&seg);
    let sum = checksum(&sum_data);
    seg[6..8].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    build_ipv6(src, dst, PROTO_UDP, &seg, hop_limit)
}

/// Build an ICMPv6 destination unreachable message. The message holds as much
/// of the invoking packet as the minimum IPv6 MTU allows.
pub fn build_icmpv6_unreachable(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    code: u8,
    invoking: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let keep = invoking.len().min(1232);
    let mut message = vec![1, code, 0, 0];
    message.extend_from_slice(&invoking[..keep]);
    let mut data = pseudo_v6(src, dst, PROTO_ICMPV6, message.len())?;
    data.extend_from_slice(&message);
    let sum = checksum(&data);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    build_ipv6(src, dst, PROTO_ICMPV6, &message, 64)
}

/// An authenticated phone echo carries only `data`; keep ID and sequence here.
pub struct IcmpEcho<'a> {
    pub identifier: u16,
    pub sequence: u16,
    pub data: &'a [u8],
}

/// Accept only complete, unfragmented echo requests with a valid checksum.
pub fn parse_echo_request<'a>(ip: &'a IpPacket<'a>) -> Option<IcmpEcho<'a>> {
    let p = ip.payload;
    if ip.fragmented || p.len() < 8 || p.len() > 1208 || p[1] != 0 {
        return None;
    }
    match (ip.src, ip.dst, ip.protocol) {
        (IpAddr::V4(_), IpAddr::V4(_), PROTO_ICMP) if p[0] == 8 && checksum(p) == 0 => (),
        (IpAddr::V6(src), IpAddr::V6(dst), PROTO_ICMPV6) if p[0] == 128 => {
            let mut data = pseudo_v6(src, dst, PROTO_ICMPV6, p.len()).ok()?;
            data.extend_from_slice(p);
            if checksum(&data) != 0 {
                return None;
            }
        }
        _ => return None,
    }
    Some(IcmpEcho {
        identifier: u16_at(p, 4),
        sequence: u16_at(p, 6),
        data: &p[8..],
    })
}

/// Construct an echo reply with the inner request's identifier and sequence.
pub fn build_echo_reply(
    src: IpAddr,
    dst: IpAddr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if payload.len() > 1200 {
        return Err("ICMP echo payload too large");
    }
    let mut message = vec![0u8; 8];
    message[4..6].copy_from_slice(&identifier.to_be_bytes());
    message[6..8].copy_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(payload);
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let sum = checksum(&message);
            message[2..4].copy_from_slice(&sum.to_be_bytes());
            build_ipv4(src, dst, PROTO_ICMP, &message, 64, 0)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            message[0] = 129;
            let mut pseudo = pseudo_v6(src, dst, PROTO_ICMPV6, message.len())?;
            pseudo.extend_from_slice(&message);
            let sum = checksum(&pseudo);
            message[2..4].copy_from_slice(&sum.to_be_bytes());
            build_ipv6(src, dst, PROTO_ICMPV6, &message, 64)
        }
        _ => Err("ICMP address family mismatch"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn echo_reply_known_checksums_and_identity() {
        let v4 = build_echo_reply(
            "203.0.113.5".parse().unwrap(),
            "198.18.0.2".parse().unwrap(),
            0x1234,
            7,
            b"hello",
        )
        .unwrap();
        assert_eq!(&v4[20..33], b"\x00\x00\xa9\xf2\x12\x34\x00\x07hello");
        let v6 = build_echo_reply(
            "2001:db8::5".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            0x1234,
            7,
            b"hello",
        )
        .unwrap();
        assert_eq!(&v6[40..53], b"\x81\x00\xfd\xe9\x12\x34\x00\x07hello");
    }
    #[test]
    fn icmpv6_unreachable_has_a_valid_checksum() {
        let src = "2001:db8::5".parse::<Ipv6Addr>().unwrap();
        let dst = "fd00::2".parse::<Ipv6Addr>().unwrap();
        let invoking = build_udp_v6(dst, src, 5555, 443, b"hello", 64).unwrap();
        let raw = build_icmpv6_unreachable(src, dst, 1, &invoking).unwrap();
        let ip = parse_ip(&raw).unwrap();
        assert_eq!(ip.version, 6);
        assert_eq!(ip.protocol, PROTO_ICMPV6);
        assert_eq!(ip.src, IpAddr::V6(src));
        assert_eq!(ip.dst, IpAddr::V6(dst));
        assert_eq!(&ip.payload[..2], &[1, 1]);
        assert_eq!(&ip.payload[4..], &invoking[..]);
        let mut data = pseudo_v6(src, dst, PROTO_ICMPV6, ip.payload.len()).unwrap();
        data.extend_from_slice(ip.payload);
        assert_eq!(checksum(&data), 0);
    }
    #[test]
    fn checksums_and_roundtrip() {
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let b = Ipv4Addr::new(198, 51, 100, 2);
        let pkt = build_tcp(&TcpBuild {
            src: a,
            dst: b,
            sport: 123,
            dport: 443,
            seq: 9,
            ack: 8,
            flags: SYN | ACK,
            window: 500,
            payload: b"abc",
            options: &[2, 4, 5],
            ttl: 64,
            ident: 4,
        })
        .unwrap();
        assert_eq!(checksum(&pkt[..20]), 0);
        let ip = parse_ip(&pkt).unwrap();
        let tcp = parse_tcp(ip.payload).unwrap();
        assert_eq!(tcp.data, b"abc");
        assert_eq!(tcp.options, &[2, 4, 5, 1]);
        let mut data = pseudo(a, b, PROTO_TCP, ip.payload.len()).unwrap();
        data.extend_from_slice(ip.payload);
        assert_eq!(checksum(&data), 0);
        let pkt = build_udp(a, b, 123, 53, b"test", 64, 0).unwrap();
        let ip = parse_ip(&pkt).unwrap();
        assert_eq!(parse_udp(ip.payload).unwrap().data, b"test");
        let mut data = pseudo(a, b, PROTO_UDP, ip.payload.len()).unwrap();
        data.extend_from_slice(ip.payload);
        assert_eq!(checksum(&data), 0);
    }
    #[test]
    fn malformed_packets_are_rejected() {
        assert!(parse_ip(&[0x45; 19]).is_none());
        assert!(parse_tcp(&[0; 20]).is_none());
        assert!(parse_udp(&[0; 7]).is_none());
        assert!(build_udp(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            1,
            2,
            &vec![0; 65535],
            64,
            0
        )
        .is_err());
    }
    #[test]
    fn ipv6_tcp_and_udp_roundtrip_checksums() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = build_tcp_v6(&TcpBuildV6 {
            src,
            dst,
            sport: 1000,
            dport: 443,
            seq: 123,
            ack: 456,
            flags: ACK,
            window: 4000,
            payload: b"abc",
            options: &[1],
            hop_limit: 64,
        })
        .unwrap();
        assert_eq!(&packet[56..58], &[0x66, 0x6e]);
        let ip = parse_ip(&packet).unwrap();
        assert_eq!(ip.version, 6);
        assert!(!ip.fragmented);
        let tcp = parse_tcp(ip.payload).unwrap();
        assert_eq!(tcp.data, b"abc");
        assert_eq!(tcp.options, &[1, 1, 1, 1]);
        let mut check = pseudo_v6(src, dst, PROTO_TCP, ip.payload.len()).unwrap();
        check.extend_from_slice(ip.payload);
        assert_eq!(checksum(&check), 0);
        let packet = build_udp_v6(src, dst, 1000, 53, b"odd", 64).unwrap();
        let ip = parse_ip(&packet).unwrap();
        assert_eq!(parse_udp(ip.payload).unwrap().data, b"odd");
        let mut check = pseudo_v6(src, dst, PROTO_UDP, ip.payload.len()).unwrap();
        check.extend_from_slice(ip.payload);
        assert_eq!(checksum(&check), 0);
        assert!(build_udp_v6(src, dst, 1, 2, &vec![0; 65528], 64).is_err());
    }
    #[test]
    fn ipv6_extensions_and_fragments_are_bounded() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        let udp = build_udp_v6(src, dst, 1, 2, b"payload", 64).unwrap();
        let mut extension = vec![PROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
        extension.extend_from_slice(&udp[40..]);
        let ip = build_ipv6(src, dst, 0, &extension, 64).unwrap();
        let parsed = parse_ip(&ip).unwrap();
        assert_eq!(parsed.protocol, PROTO_UDP);
        assert!(!parsed.fragmented);
        assert_eq!(parse_udp(parsed.payload).unwrap().data, b"payload");
        let mut fragment = extension.clone();
        fragment[0] = PROTO_UDP;
        let ip = build_ipv6(src, dst, 44, &fragment, 64).unwrap();
        assert!(parse_ip(&ip).unwrap().fragmented);
        let mut truncated = ip;
        truncated.pop();
        assert!(parse_ip(&truncated).is_none());
        let ip = build_ipv6(src, dst, 0, &[PROTO_UDP, 1, 0, 0, 0, 0, 0, 0], 64).unwrap();
        assert!(parse_ip(&ip).is_none());
    }
}
