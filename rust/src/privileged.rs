//! Private local IPC for the administrator-owned phone service.
//!
//! The GUI creates a private listener and accepts only the expected helper
//! UID. The helper verifies the listener owner and peer UID before reading a
//! request. Credentials travel only in framed messages over that connection.
//! The caller owns authorization, signal handling, and service implementation.
#![cfg(unix)]
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

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

/// A private listener owned by the unprivileged GUI process.
pub struct PrivateListener {
    listener: UnixListener,
    directory: PathBuf,
    path: PathBuf,
}
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
impl Drop for PrivateListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.directory);
    }
}

/// Validate the socket and its 0700 parent without following their final links.
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
struct StopOnDrop<'a, T: PrivilegedService>(&'a mut T);
impl<T: PrivilegedService> Drop for StopOnDrop<'_, T> {
    fn drop(&mut self) {
        let _ = self.0.stop();
    }
}

// Do not consume the next IPC message. Detect a closed peer while start is
// running so authentication can be cancelled before route setup.
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

struct DisconnectWatch {
    finished: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
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
pub fn serve_connection<T: PrivilegedService>(
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
