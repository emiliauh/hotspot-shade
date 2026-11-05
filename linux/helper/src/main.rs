// HotspotShade root helper.
//
// pkexec starts this program as root. It accepts no arguments. It reads one
// short request from stdin, starts the packaged engine with the per-launch
// secret on descriptor 3, and holds descriptor 4 open until stdin closes.
//
// The helper never prints the secret. It does not accept a path, a command, or
// an argument from the app or the page. The engine path is fixed at build time.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_ENGINE: &str = "/opt/hotspotshade/resources/engine/hotspotshade";
const ENGINE_HOME: &str = "/var/lib/hotspotshade";
const START_TIMEOUT: Duration = Duration::from_secs(10);
const EOF_GRACE: Duration = Duration::from_secs(8);
const TERM_GRACE: Duration = Duration::from_secs(3);

fn fail(message: &str) -> ! {
    eprintln!("hotspotshade-helper: {message}");
    std::process::exit(1);
}

fn engine_path() -> &'static str {
    option_env!("HS_ENGINE_PATH").unwrap_or(DEFAULT_ENGINE)
}

fn read_line(reader: &mut fs::File, limit: usize) -> io::Result<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let count = reader.read(&mut byte)?;
        if count == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if buffer.len() >= limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        buffer.push(byte[0]);
    }
    String::from_utf8(buffer).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line is not text"))
}

fn validate_engine(path: &str) {
    let metadata = fs::metadata(path).unwrap_or_else(|_| fail("The packaged engine is missing."));
    if !metadata.is_file() {
        fail("The packaged engine path is not a file.");
    }
    if metadata.uid() != 0 {
        fail("The packaged engine is not owned by root.");
    }
    if metadata.mode() & 0o022 != 0 {
        fail("The packaged engine is writable by another user.");
    }
    if metadata.mode() & 0o111 == 0 {
        fail("The packaged engine is not executable.");
    }
}

fn make_temp_directory() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    for attempt in 0..100u128 {
        let path = PathBuf::from("/tmp").join(format!(
            "hotspotshade-helper-{}-{}",
            std::process::id(),
            nanos + attempt
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
                return path;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => fail("The helper temporary directory could not be created."),
        }
    }
    fail("The helper temporary directory could not be created.")
}

fn remove_directory(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn prepare_engine_home() {
    if let Err(error) = fs::create_dir_all(ENGINE_HOME) {
        if error.kind() != io::ErrorKind::AlreadyExists {
            fail("The engine home directory could not be created.");
        }
    }
    let metadata = fs::metadata(ENGINE_HOME).unwrap_or_else(|_| fail("The engine home directory is not available."));
    if !metadata.is_dir() || metadata.uid() != 0 {
        fail("The engine home directory is not owned by root.");
    }
    let _ = fs::set_permissions(ENGINE_HOME, fs::Permissions::from_mode(0o700));
}

fn lift_fd(fd: i32) -> io::Result<i32> {
    if fd >= 10 {
        return Ok(fd);
    }
    let lifted = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if lifted < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        libc::close(fd);
    }
    Ok(lifted)
}

fn move_fd(fd: i32, target: i32) -> io::Result<()> {
    if unsafe { libc::dup2(fd, target) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn valid_secret(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn main() {
    if env::args_os().len() != 1 {
        fail("The helper takes no arguments.");
    }
    let _invoking_uid = env::var("PKEXEC_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value != 0)
        .unwrap_or_else(|| fail("The helper must run through pkexec."));

    let engine = engine_path();
    validate_engine(engine);

    let stdin = unsafe { fs::File::from_raw_fd(0) };
    let mut request = stdin;
    let version = read_line(&mut request, 16).unwrap_or_else(|_| fail("The helper request is not valid."));
    if version != "HS1" {
        fail("The helper request is not valid.");
    }
    let secret = read_line(&mut request, 128).unwrap_or_else(|_| fail("The helper request is not valid."));
    if !valid_secret(&secret) {
        fail("The helper request is not valid.");
    }

    let (token_reader, mut token_writer) = UnixStream::pair().unwrap_or_else(|_| fail("The helper pipes could not be created."));
    let (parent_reader, parent_writer) = UnixStream::pair().unwrap_or_else(|_| fail("The helper pipes could not be created."));
    token_writer
        .write_all(secret.as_bytes())
        .and_then(|_| token_writer.write_all(b"\n"))
        .unwrap_or_else(|_| fail("The helper token pipe could not be written."));
    token_writer
        .flush()
        .unwrap_or_else(|_| fail("The helper token pipe could not be written."));

    let token_fd = lift_fd(token_reader.into_raw_fd()).unwrap_or_else(|_| fail("The helper pipes could not be prepared."));
    let parent_fd = lift_fd(parent_reader.into_raw_fd()).unwrap_or_else(|_| fail("The helper pipes could not be prepared."));

    let directory = make_temp_directory();
    let port_path = directory.join("port");
    prepare_engine_home();

    let mut command = Command::new(engine);
    command
        .env_clear()
        .env("HOME", ENGINE_HOME)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .env("TMPDIR", "/tmp")
        .arg("gui")
        .arg("--no-open")
        .arg("--port")
        .arg("0")
        .arg("--port-file")
        .arg(&port_path)
        .arg("--token-fd")
        .arg("3")
        .arg("--parent-fd")
        .arg("4")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            move_fd(token_fd, 3)?;
            move_fd(parent_fd, 4)?;
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap_or_else(|_| {
        remove_directory(&directory);
        fail("The packaged engine did not start.");
    });
    drop(token_writer);
    unsafe {
        libc::close(token_fd);
        libc::close(parent_fd);
    }

    let port = wait_for_port(&mut child, &port_path).unwrap_or_else(|| {
        terminate(&mut child);
        remove_directory(&directory);
        fail("The packaged engine did not report a port.");
    });
    remove_directory(&directory);
    println!("HS_PORT {port}");
    let _ = io::stdout().flush();

    /* Keep stdin open until the app closes it. The helper stops the engine when
     * stdin closes. This is the stop path and the parent-loss path. */
    let (closed_tx, closed_rx) = mpsc::channel();
    let _reader = thread::spawn(move || {
        let mut request = request;
        let mut buffer = [0u8; 64];
        loop {
            match request.read(&mut buffer) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let _ = closed_tx.send(());
    });

    let mut parent_writer = Some(parent_writer);
    let mut closed_at: Option<Instant> = None;
    loop {
        if closed_at.is_none() && closed_rx.try_recv().is_ok() {
            closed_at = Some(Instant::now());
            drop(parent_writer.take());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                remove_directory(&directory);
                std::process::exit(status.code().unwrap_or(0));
            }
            Ok(None) => {}
            Err(_) => {
                terminate(&mut child);
                remove_directory(&directory);
                fail("The packaged engine state could not be read.");
            }
        }
        if let Some(started) = closed_at {
            if started.elapsed() >= EOF_GRACE {
                terminate(&mut child);
                remove_directory(&directory);
                std::process::exit(1);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_port(child: &mut std::process::Child, port_path: &Path) -> Option<u16> {
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(value) = fs::read_to_string(port_path) {
            if let Ok(port) = value.trim().parse::<u16>() {
                if port > 0 {
                    return Some(port);
                }
            }
        }
        match child.try_wait() {
            Ok(Some(_)) => return None,
            Ok(None) => {}
            Err(_) => return None,
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

fn terminate(child: &mut std::process::Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGKILL);
    }
    let _ = child.wait();
}
