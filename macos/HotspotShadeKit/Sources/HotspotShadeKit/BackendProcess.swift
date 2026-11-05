import Foundation
import Security
import Darwin

public final class BackendProcess {
    private let executable: URL
    private let demo: Bool
    private var pid: pid_t = 0
    private var parentWrite: Int32 = -1
    private var directory: URL?
    private var attempts = 0
    public private(set) var secret = ""
    public private(set) var port: UInt16?
    public init(executable: URL, demo: Bool = false) { self.executable = executable; self.demo = demo }
    public var isRunning: Bool {
        guard pid > 0 else { return false }
        var status: Int32 = 0
        if waitpid(pid, &status, WNOHANG) == pid { pid = 0; return false }
        return true
    }
    // Reset the restart budget after the engine ran without a fault.
    public func markHealthy() { attempts = 0 }
    public func start(timeout: TimeInterval = 10) async throws {
        guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw BackendError.missingEngine }
        // A write to a pipe with no reader must return EPIPE, not kill the app.
        signal(SIGPIPE, SIG_IGN)
        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else { throw BackendError.response("Cannot create an engine secret.") }
        secret = random.map { String(format: "%02x", $0) }.joined()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hotspotshade-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); directory = dir
        let portFile = dir.appendingPathComponent("port")
        var token = [Int32](repeating: -1, count: 2), parent = [Int32](repeating: -1, count: 2)
        guard pipe(&token) == 0 else { throw BackendError.response("Cannot create engine pipes.") }
        guard pipe(&parent) == 0 else { close(token[0]); close(token[1]); throw BackendError.response("Cannot create engine pipes.") }
        let tokenRead = fcntl(token[0], F_DUPFD_CLOEXEC, 10)
        let parentRead = fcntl(parent[0], F_DUPFD_CLOEXEC, 10)
        close(token[0]); close(parent[0])
        guard tokenRead >= 0, parentRead >= 0 else { close(token[1]); close(parent[1]); close(tokenRead); close(parentRead); throw BackendError.response("Cannot create engine pipes.") }
        _ = fcntl(token[1], F_SETFD, FD_CLOEXEC); _ = fcntl(parent[1], F_SETFD, FD_CLOEXEC)
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        // The child needs only these descriptors. The spawn closes the others.
        for fd in Int32(0)..<3 where fcntl(fd, F_GETFD) != -1 { posix_spawn_file_actions_addinherit_np(&actions, fd) }
        posix_spawn_file_actions_adddup2(&actions, tokenRead, 3)
        posix_spawn_file_actions_adddup2(&actions, parentRead, 4)
        posix_spawn_file_actions_addclose(&actions, tokenRead); posix_spawn_file_actions_addclose(&actions, parentRead)
        let args = [executable.path, "gui", "--no-open", "--port", "0", "--port-file", portFile.path, "--token-fd", "3", "--parent-fd", "4"] + (demo ? ["--demo"] : [])
        let argv = args.map { strdup($0) } + [nil]
        defer { for arg in argv { free(arg) }; posix_spawn_file_actions_destroy(&actions); if tokenRead >= 0 { close(tokenRead) }; if parentRead >= 0 { close(parentRead) } }
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        var defaults = sigset_t()
        sigemptyset(&defaults); sigaddset(&defaults, SIGTERM); sigaddset(&defaults, SIGINT)
        posix_spawnattr_setsigdefault(&attributes, &defaults)
        var mask = sigset_t(); sigemptyset(&mask)
        posix_spawnattr_setsigmask(&attributes, &mask)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT))
        defer { posix_spawnattr_destroy(&attributes) }
        var child: pid_t = 0
        let result = posix_spawn(&child, executable.path, &actions, &attributes, argv, environ)
        guard result == 0 else { close(token[1]); close(parent[1]); throw BackendError.response("Cannot start the engine.") }
        pid = child; parentWrite = parent[1]
        let bytes = Array((secret + "\n").utf8)
        var sent = 0, failure: Int32 = 0
        while sent < bytes.count {
            let written = bytes.withUnsafeBytes { write(token[1], $0.baseAddress!.advanced(by: sent), bytes.count - sent) }
            if written > 0 { sent += written; continue }
            if written < 0 && errno == EINTR { continue }
            failure = written == 0 ? EPIPE : errno
            break
        }
        close(token[1])
        guard failure == 0 else { await stop(); throw failure == EPIPE ? BackendError.exited : BackendError.response("Cannot send the engine secret.") }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let text = try? String(contentsOf: portFile, encoding: .utf8), let value = UInt16(text.trimmingCharacters(in: .whitespacesAndNewlines)), value > 0 { port = value; return }
            if !isRunning { await stop(); throw BackendError.exited }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        await stop(); throw BackendError.timeout
    }
    public func restartOnce() async throws { guard attempts == 0 else { throw BackendError.exited }; attempts += 1; await stop(); try await start() }
    public func stop() async {
        if isRunning { kill(pid, SIGTERM) }
        let deadline = Date().addingTimeInterval(60)
        while isRunning && Date() < deadline { try? await Task.sleep(nanoseconds: 50_000_000) }
        if parentWrite >= 0 { close(parentWrite); parentWrite = -1 }
        port = nil
        if !isRunning { if let directory { try? FileManager.default.removeItem(at: directory) }; directory = nil }
    }
    func closeParentPipe() { if parentWrite >= 0 { close(parentWrite); parentWrite = -1 } }
    deinit { closeParentPipe() }
}
