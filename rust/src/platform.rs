//! macOS utun and route lifecycle.
//!
//! The caller owns the relay loop. Keep the tunnel and route manager alive
//! for the full relay lifetime. Stop the relay before dropping them.

use std::io;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;

/// Run a system command without a shell.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[String]) -> io::Result<()>;
}

struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String]) -> io::Result<()> {
        let out = Command::new(program)
            .args(args)
            .env_remove(crate::secret_env::PHONE_TOKEN_ENV)
            .output()?;
        if out.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "{} failed: {}",
                program,
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }
}

fn valid_ifname(name: &str) -> bool {
    name.strip_prefix("utun")
        .map(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

/// Configure the point-to-point IPv4 address and MTU on a utun.
/// Closing the device removes the address.
pub fn configure_link(ifname: &str, addr: Ipv4Addr, mtu: u32) -> io::Result<()> {
    configure_link_with(&SystemRunner, ifname, addr, mtu)
}

fn configure_link_with(
    runner: &dyn CommandRunner,
    ifname: &str,
    addr: Ipv4Addr,
    mtu: u32,
) -> io::Result<()> {
    if !valid_ifname(ifname) || !(576..=65535).contains(&mtu) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid tunnel name or MTU",
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
    runner.run(
        "/sbin/ifconfig",
        &[
            ifname.into(),
            addr.to_string(),
            Ipv4Addr::from(octets).to_string(),
        ],
    )?;
    runner.run(
        "/sbin/ifconfig",
        &[ifname.into(), "mtu".into(), mtu.to_string()],
    )
}

/// Tracks only routes created by this instance.
pub struct RouteManager {
    ifname: String,
    ipv6_block: bool,
    runner: Arc<dyn CommandRunner>,
    installed: Vec<Vec<String>>,
}

impl RouteManager {
    pub fn new(ifname: &str, ipv6_block: bool) -> io::Result<Self> {
        Self::with_runner(ifname, ipv6_block, Arc::new(SystemRunner))
    }

    pub fn with_runner(
        ifname: &str,
        ipv6_block: bool,
        runner: Arc<dyn CommandRunner>,
    ) -> io::Result<Self> {
        if !valid_ifname(ifname) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid utun name",
            ));
        }
        Ok(Self {
            ifname: ifname.into(),
            ipv6_block,
            runner,
            installed: Vec::new(),
        })
    }

    /// Install the two IPv4 routes and, when requested, the IPv6 block.
    /// On failure, remove the routes that this instance added.
    pub fn install(&mut self) -> io::Result<()> {
        if !self.installed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "routes already installed or cleanup incomplete",
            ));
        }
        let mut routes = vec![
            vec![
                "-inet".into(),
                "0.0.0.0/1".into(),
                "-interface".into(),
                self.ifname.clone(),
            ],
            vec![
                "-inet".into(),
                "128.0.0.0/1".into(),
                "-interface".into(),
                self.ifname.clone(),
            ],
        ];
        if self.ipv6_block {
            routes.push(vec![
                "-inet6".into(),
                "2000::/3".into(),
                "::1".into(),
                "-blackhole".into(),
            ]);
        }
        for args in routes {
            let mut command = vec!["-n".into(), "add".into()];
            command.extend(args.iter().cloned());
            if let Err(error) = self.runner.run("/sbin/route", &command) {
                return match self.remove() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(io::Error::new(
                        error.kind(),
                        format!("{}; route cleanup failed: {}", error, cleanup),
                    )),
                };
            }
            self.installed.push(args);
        }
        Ok(())
    }

    /// Remove all recorded routes. Retain failed routes for another attempt.
    pub fn remove(&mut self) -> io::Result<()> {
        let mut failed = Vec::new();
        let mut last_error = None;
        for args in self.installed.drain(..).rev() {
            let mut command = vec!["-n".into(), "delete".into()];
            command.extend(args.iter().cloned());
            if let Err(error) = self.runner.run("/sbin/route", &command) {
                last_error = Some(error);
                failed.push(args);
            }
        }
        failed.reverse();
        self.installed = failed;
        match last_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
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

#[cfg(target_os = "macos")]
mod darwin {
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    const AF_SYSTEM: libc::c_int = 32;
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    const CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [libc::c_char; 96],
    }
    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    /// A frame is a four-byte address family and one IP packet.
    /// The configured tunnel MTU is at most 65535 bytes.
    pub const MAX_FRAME: usize = 4 + 65535;

    /// A reusable buffer for one utun frame.
    /// Allocate one buffer and pass it to `Utun::read_packet` for every packet.
    /// This keeps the large frame allocation out of the packet path.
    pub struct FrameBuffer {
        data: Vec<u8>,
    }

    impl FrameBuffer {
        pub fn new() -> Self {
            Self {
                data: vec![0u8; MAX_FRAME],
            }
        }
    }

    impl Default for FrameBuffer {
        fn default() -> Self {
            Self::new()
        }
    }

    /// One system call layer for frame reads and writes.
    /// Tests use a fake layer to send frames without a utun.
    trait FrameIo {
        fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
        fn writev(&self, iov: &[libc::iovec]) -> io::Result<usize>;
    }

    struct FdIo(RawFd);

    impl FrameIo for FdIo {
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            let n = unsafe { libc::read(self.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        fn writev(&self, iov: &[libc::iovec]) -> io::Result<usize> {
            let n = unsafe { libc::writev(self.0, iov.as_ptr(), iov.len() as libc::c_int) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }

    /// Read one frame and return its IP packet.
    /// The frame buffer keeps its allocation for the next read.
    fn read_frame(io: &dyn FrameIo, frame: &mut FrameBuffer) -> io::Result<Vec<u8>> {
        let n = io.read(&mut frame.data)?;
        if n < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short utun frame",
            ));
        }
        let af = u32::from_be_bytes([frame.data[0], frame.data[1], frame.data[2], frame.data[3]]);
        let version = frame.data[4] >> 4;
        if !((af == libc::AF_INET as u32 && version == 4)
            || (af == libc::AF_INET6 as u32 && version == 6))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid utun address family",
            ));
        }
        Ok(frame.data[4..n].to_vec())
    }

    /// Write one IP packet as one frame.
    /// One `writev` call sends the prefix and the packet as one datagram.
    /// The wrapper does not copy the packet before the system call.
    fn write_frame(io: &dyn FrameIo, packet: &[u8], mtu: usize) -> io::Result<usize> {
        if packet.is_empty() || packet.len() > mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid packet length",
            ));
        }
        let af = match packet[0] >> 4 {
            4 => libc::AF_INET as u32,
            6 => libc::AF_INET6 as u32,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid IP version",
                ))
            }
        };
        let prefix = af.to_be_bytes();
        let iov = [
            libc::iovec {
                iov_base: prefix.as_ptr() as *mut libc::c_void,
                iov_len: prefix.len(),
            },
            libc::iovec {
                iov_base: packet.as_ptr() as *mut libc::c_void,
                iov_len: packet.len(),
            },
        ];
        let n = io.writev(&iov)?;
        if n != packet.len() + prefix.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial utun write",
            ));
        }
        Ok(packet.len())
    }

    /// A nonblocking macOS utun control socket.
    pub struct Utun {
        fd: OwnedFd,
        ifname: String,
        mtu: usize,
    }

    impl Utun {
        /// Open unit 0 for an automatically assigned device.
        pub fn open(unit: u32) -> io::Result<Self> {
            let raw = unsafe { libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // Own the descriptor before any operation that can fail.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0; 96],
            };
            for (dst, src) in info.ctl_name.iter_mut().zip(CONTROL_NAME.iter()) {
                *dst = *src as libc::c_char;
            }
            if unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if info.ctl_id == 0 {
                return Err(io::Error::other("utun control id is zero"));
            }
            let sc = SockaddrCtl {
                sc_len: mem::size_of::<SockaddrCtl>() as u8,
                sc_family: AF_SYSTEM as u8,
                ss_sysaddr: SYSPROTO_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };
            if unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    &sc as *const _ as *const libc::sockaddr,
                    mem::size_of::<SockaddrCtl>() as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut name = [0 as libc::c_char; 64];
            let mut len = name.len() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    SYSPROTO_CONTROL,
                    UTUN_OPT_IFNAME,
                    name.as_mut_ptr() as *mut libc::c_void,
                    &mut len,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            // Preserve a terminator even if the kernel returns a full buffer.
            name[63] = 0;
            let ifname = unsafe { CStr::from_ptr(name.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            if !super::valid_ifname(&ifname) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected utun interface name",
                ));
            }
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                fd,
                ifname,
                mtu: 1500,
            })
        }

        pub fn ifname(&self) -> &str {
            &self.ifname
        }

        /// Return one IP packet without the four-byte address-family prefix.
        /// Pass the same frame buffer again for the next packet.
        pub fn read_packet(&self, frame: &mut FrameBuffer) -> io::Result<Vec<u8>> {
            read_frame(&FdIo(self.fd.as_raw_fd()), frame)
        }

        /// Write one IP packet. Return its byte count without the prefix.
        pub fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
            write_frame(&FdIo(self.fd.as_raw_fd()), packet, self.mtu)
        }
    }

    impl AsRawFd for Utun {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::VecDeque;
        use std::sync::Mutex;
        use std::time::Instant;

        /// A fake frame source and sink. It sends queued frames and records
        /// every written datagram. It creates no device and changes no route.
        #[derive(Default)]
        struct FakeIo {
            reads: Mutex<VecDeque<Vec<u8>>>,
            read_error: Mutex<Option<io::ErrorKind>>,
            datagrams: Mutex<Vec<Vec<u8>>>,
            iov_lens: Mutex<Vec<Vec<usize>>>,
            write_return: Mutex<Option<usize>>,
            write_error: Mutex<Option<io::ErrorKind>>,
        }

        impl FakeIo {
            fn with_reads(frames: Vec<Vec<u8>>) -> Self {
                let io = Self::default();
                *io.reads.lock().unwrap() = frames.into();
                io
            }
        }

        impl FrameIo for FakeIo {
            fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
                if let Some(kind) = *self.read_error.lock().unwrap() {
                    return Err(io::Error::from(kind));
                }
                let frame = self
                    .reads
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("no frame queued");
                assert!(frame.len() <= buf.len());
                buf[..frame.len()].copy_from_slice(&frame);
                Ok(frame.len())
            }

            fn writev(&self, iov: &[libc::iovec]) -> io::Result<usize> {
                if let Some(kind) = *self.write_error.lock().unwrap() {
                    return Err(io::Error::from(kind));
                }
                let mut datagram = Vec::new();
                let mut lens = Vec::new();
                for part in iov {
                    let len = part.iov_len;
                    lens.push(len);
                    let bytes =
                        unsafe { std::slice::from_raw_parts(part.iov_base as *const u8, len) };
                    datagram.extend_from_slice(bytes);
                }
                self.iov_lens.lock().unwrap().push(lens);
                self.datagrams.lock().unwrap().push(datagram.clone());
                Ok(self.write_return.lock().unwrap().unwrap_or(datagram.len()))
            }
        }

        fn ipv4_frame(len: usize) -> Vec<u8> {
            let mut packet = vec![0u8; len];
            packet[0] = 0x45;
            let mut frame = 2u32.to_be_bytes().to_vec();
            frame.extend_from_slice(&packet);
            frame
        }

        #[test]
        fn read_strips_prefix_and_reuses_the_frame_buffer() {
            let frame_bytes = ipv4_frame(40);
            let io = FakeIo::with_reads(vec![frame_bytes.clone(), frame_bytes.clone()]);
            let mut frame = FrameBuffer::new();
            let address = frame.data.as_ptr();
            let first = read_frame(&io, &mut frame).unwrap();
            let second = read_frame(&io, &mut frame).unwrap();
            assert_eq!(first, frame_bytes[4..]);
            assert_eq!(second, frame_bytes[4..]);
            assert_eq!(frame.data.as_ptr(), address);
            assert_eq!(frame.data.len(), MAX_FRAME);
        }

        #[test]
        fn read_rejects_a_short_frame() {
            let io = FakeIo::with_reads(vec![2u32.to_be_bytes().to_vec()]);
            let mut frame = FrameBuffer::new();
            let error = read_frame(&io, &mut frame).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }

        #[test]
        fn read_rejects_a_mismatched_address_family() {
            let mut ipv6_version = 2u32.to_be_bytes().to_vec();
            ipv6_version.push(0x60);
            let mut ipv4_version = 30u32.to_be_bytes().to_vec();
            ipv4_version.push(0x45);
            let io = FakeIo::with_reads(vec![ipv6_version, ipv4_version]);
            let mut frame = FrameBuffer::new();
            for _ in 0..2 {
                let error = read_frame(&io, &mut frame).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }

        #[test]
        fn read_propagates_would_block() {
            let io = FakeIo::default();
            *io.read_error.lock().unwrap() = Some(io::ErrorKind::WouldBlock);
            let mut frame = FrameBuffer::new();
            let error = read_frame(&io, &mut frame).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }

        #[test]
        fn write_sends_the_prefix_and_packet_as_two_iovecs() {
            let io = FakeIo::default();
            let mut packet = vec![0u8; 40];
            packet[0] = 0x45;
            assert_eq!(write_frame(&io, &packet, 1500).unwrap(), 40);
            let datagrams = io.datagrams.lock().unwrap();
            assert_eq!(datagrams.len(), 1);
            assert_eq!(&datagrams[0][..4], &2u32.to_be_bytes());
            assert_eq!(&datagrams[0][4..], &packet[..]);
            assert_eq!(*io.iov_lens.lock().unwrap(), vec![vec![4, 40]]);
        }

        #[test]
        fn write_uses_family_30_for_ipv6() {
            let io = FakeIo::default();
            let mut packet = vec![0u8; 40];
            packet[0] = 0x60;
            assert_eq!(write_frame(&io, &packet, 1500).unwrap(), 40);
            let datagrams = io.datagrams.lock().unwrap();
            assert_eq!(&datagrams[0][..4], &30u32.to_be_bytes());
        }

        #[test]
        fn write_rejects_an_empty_packet_an_oversize_packet_and_a_bad_version() {
            let io = FakeIo::default();
            assert_eq!(
                write_frame(&io, &[], 1500).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            let oversize = vec![0u8; 1501];
            assert_eq!(
                write_frame(&io, &oversize, 1500).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                write_frame(&io, &[0x10], 1500).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert!(io.datagrams.lock().unwrap().is_empty());
        }

        #[test]
        fn write_reports_a_partial_write_and_propagates_would_block() {
            let io = FakeIo::default();
            *io.write_return.lock().unwrap() = Some(3);
            let mut packet = vec![0u8; 40];
            packet[0] = 0x45;
            let error = write_frame(&io, &packet, 1500).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);

            let io = FakeIo::default();
            *io.write_error.lock().unwrap() = Some(io::ErrorKind::WouldBlock);
            let error = write_frame(&io, &packet, 1500).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }

        /// Exercise the real descriptor path with a Unix datagram socket pair.
        /// This is a fake frame source. It creates no utun.
        #[test]
        fn fd_io_round_trips_prefix_and_packet() {
            let mut fds = [0 as libc::c_int; 2];
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
            let device = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            let mut packet = vec![0u8; 40];
            packet[0] = 0x45;

            let written = write_frame(&FdIo(device.as_raw_fd()), &packet, 1500).unwrap();
            assert_eq!(written, 40);
            let mut buf = [0u8; 64];
            let got =
                unsafe { libc::recv(peer.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            assert_eq!(got, 44);
            assert_eq!(&buf[..4], &2u32.to_be_bytes());
            assert_eq!(&buf[4..44], &packet[..]);

            let sent = unsafe { libc::send(peer.as_raw_fd(), buf.as_ptr().cast(), 44, 0) };
            assert_eq!(sent, 44);
            let mut frame = FrameBuffer::new();
            assert_eq!(
                read_frame(&FdIo(device.as_raw_fd()), &mut frame).unwrap(),
                packet
            );
        }

        /// Local microbenchmark only. It compares the old fixed 65539-byte
        /// allocation for each packet and the old frame copy for each write
        /// with one reused frame buffer and a two-part write. It does not
        /// measure live throughput.
        #[test]
        #[ignore = "manual microbenchmark, run in release mode"]
        fn frame_buffer_microbenchmark() {
            const PACKETS: usize = 10_000;
            const PACKET: usize = 1500;
            let mut source = vec![0u8; PACKET];
            source[0] = 0x45;

            let start = Instant::now();
            for _ in 0..PACKETS {
                let buffer = vec![0u8; MAX_FRAME];
                std::hint::black_box(&buffer);
                let packet = buffer[4..4 + PACKET].to_vec();
                std::hint::black_box(&packet);
            }
            let fixed = start.elapsed();

            let mut frame = FrameBuffer::new();
            let start = Instant::now();
            for _ in 0..PACKETS {
                frame.data[..4].copy_from_slice(&2u32.to_be_bytes());
                frame.data[4..4 + PACKET].copy_from_slice(&source);
                std::hint::black_box(&frame.data);
                let packet = frame.data[4..4 + PACKET].to_vec();
                std::hint::black_box(&packet);
            }
            let reused = start.elapsed();

            let start = Instant::now();
            for _ in 0..PACKETS {
                let mut copy = Vec::with_capacity(PACKET + 4);
                copy.extend_from_slice(&2u32.to_be_bytes());
                copy.extend_from_slice(&source);
                std::hint::black_box(&copy);
            }
            let copied = start.elapsed();

            let start = Instant::now();
            for _ in 0..PACKETS {
                let prefix = 2u32.to_be_bytes();
                let iov = [
                    libc::iovec {
                        iov_base: prefix.as_ptr() as *mut libc::c_void,
                        iov_len: prefix.len(),
                    },
                    libc::iovec {
                        iov_base: source.as_ptr() as *mut libc::c_void,
                        iov_len: source.len(),
                    },
                ];
                std::hint::black_box(&iov);
            }
            let parts = start.elapsed();

            assert_eq!(frame.data.capacity(), MAX_FRAME);
            eprintln!(
                "frame buffer microbenchmark: {} packets, fixed buffer {:?} ({:.0} ns/packet), reused buffer {:?} ({:.0} ns/packet)",
                PACKETS,
                fixed,
                fixed.as_nanos() as f64 / PACKETS as f64,
                reused,
                reused.as_nanos() as f64 / PACKETS as f64
            );
            eprintln!(
                "frame write microbenchmark: {} packets, copied frame {:?} ({:.0} ns/packet), two-part iovec {:?} ({:.0} ns/packet)",
                PACKETS,
                copied,
                copied.as_nanos() as f64 / PACKETS as f64,
                parts,
                parts.as_nanos() as f64 / PACKETS as f64
            );
        }
    }
}

#[cfg(target_os = "macos")]
pub use darwin::{FrameBuffer, Utun};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<Vec<String>>>,
        fail_add: Mutex<Option<String>>,
        fail_delete: Mutex<bool>,
    }
    impl CommandRunner for Fake {
        fn run(&self, program: &str, args: &[String]) -> io::Result<()> {
            let mut call = vec![program.to_string()];
            call.extend_from_slice(args);
            self.calls.lock().unwrap().push(call);
            if args.iter().any(|a| a == "add")
                && self
                    .fail_add
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|x| args.contains(x))
                    .unwrap_or(false)
            {
                return Err(io::Error::other("add failed"));
            }
            if args.iter().any(|a| a == "delete") && *self.fail_delete.lock().unwrap() {
                return Err(io::Error::other("delete failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn route_failure_rolls_back_only_created_routes() {
        let fake = Arc::new(Fake::default());
        *fake.fail_add.lock().unwrap() = Some("128.0.0.0/1".into());
        let mut rm = RouteManager::with_runner("utun8", true, fake.clone()).unwrap();
        assert!(rm.install().is_err());
        assert!(!rm.has_installed_routes());
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[2].contains(&"delete".to_string()));
        assert!(calls[2].contains(&"0.0.0.0/1".to_string()));
    }

    #[test]
    fn block_installs_blackhole_and_removes_it_first() {
        let fake = Arc::new(Fake::default());
        let mut rm = RouteManager::with_runner("utun9", true, fake.clone()).unwrap();
        rm.install().unwrap();
        rm.remove().unwrap();
        rm.remove().unwrap();
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 6);
        assert!(calls[2].contains(&"-blackhole".to_string()));
        assert!(calls[3].contains(&"2000::/3".to_string()));
        assert!(calls[3].contains(&"delete".to_string()));
    }

    #[test]
    fn failed_cleanup_is_recorded_and_can_be_retried() {
        let fake = Arc::new(Fake::default());
        let mut rm = RouteManager::with_runner("utun9", true, fake.clone()).unwrap();
        rm.install().unwrap();
        *fake.fail_delete.lock().unwrap() = true;
        assert!(rm.remove().is_err());
        assert!(rm.has_installed_routes());
        *fake.fail_delete.lock().unwrap() = false;
        rm.remove().unwrap();
        assert!(!rm.has_installed_routes());
    }

    #[test]
    fn inherit_has_no_ipv6_route() {
        let fake = Arc::new(Fake::default());
        let mut rm = RouteManager::with_runner("utun9", false, fake.clone()).unwrap();
        rm.install().unwrap();
        assert_eq!(fake.calls.lock().unwrap().len(), 2);
        rm.remove().unwrap();
    }

    #[test]
    fn link_configuration_uses_other_host_in_same_subnet() {
        let fake = Fake::default();
        configure_link_with(&fake, "utun6", "198.18.0.5".parse().unwrap(), 1500).unwrap();
        assert_eq!(fake.calls.lock().unwrap()[0][3], "198.18.0.6");
        assert!(configure_link_with(&fake, "en0", "198.18.0.1".parse().unwrap(), 1500).is_err());
    }
}

#[cfg(test)]
mod phone_token_env_tests {
    use super::*;

    #[test]
    fn system_runner_child_does_not_inherit_the_phone_token() {
        // The shell exits non-zero when the variable is set, so a successful
        // run proves the child did not inherit it.
        std::env::set_var(crate::secret_env::PHONE_TOKEN_ENV, "public-test-token");
        let result = SystemRunner.run(
            "/bin/sh",
            &[
                "-c".to_string(),
                "test -z \"${HOTSPOTSHADE_PHONE_TOKEN+x}\"".to_string(),
            ],
        );
        assert!(result.is_ok(), "child inherited the token: {result:?}");
    }
}
