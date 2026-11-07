import Foundation
import Darwin
import Security

// The root helper starts the engine itself. The engine path is root-owned and
// signed. The helper passes the per-launch secret on descriptor 3 and keeps
// descriptor 4 open as the liveness channel. Closing descriptor 4 is the
// parent-loss signal that the engine uses to remove its routes and device.
public struct RootEnginePaths: Sendable {
    public let enginePath: String
    public let engineInstallRoot: String
    public let engineIdentifier: String
    public let homeDirectory: String

    public init(
        enginePath: String = "/Library/Application Support/HotspotShade/engine/hotspotshade",
        engineInstallRoot: String = "/Library/Application Support/HotspotShade/engine",
        engineIdentifier: String = HelperRequirement.engineIdentifier,
        homeDirectory: String = "/var/lib/hotspotshade"
    ) {
        self.enginePath = enginePath
        self.engineInstallRoot = engineInstallRoot
        self.engineIdentifier = engineIdentifier
        self.homeDirectory = homeDirectory
    }
}

// Write the per-launch secret to the engine's descriptor. The engine can exit
// between spawn and this write, so a write must never raise SIGPIPE: SIGPIPE
// would end the root helper in the middle of a start and leave the engine
// unowned. The descriptor disables SIGPIPE itself, and a failed or short write
// returns false so the caller stops the child it already spawned.
public enum HelperPipeWriter {
    @discardableResult
    public static func writeAll(descriptor: Int32, bytes: [UInt8]) -> Bool {
        guard descriptor >= 0 else { return false }
        _ = fcntl(descriptor, F_SETNOSIGPIPE, 1)
        var sent = 0
        while sent < bytes.count {
            let written = bytes.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                return write(descriptor, base.advanced(by: sent), bytes.count - sent)
            }
            if written > 0 {
                sent += written
                continue
            }
            if written < 0 && errno == EINTR { continue }
            return false
        }
        return true
    }
}

public final class RootEngineLauncher: HelperEngineLaunching, @unchecked Sendable {
    private let paths: RootEnginePaths
    private let teamIdentifier: String
    private let verifier: RootOwnedExecutableVerifier
    private let runtimeParentPath: String
    private let intentStore: HelperLaunchIntentStoring
    private let lock = NSLock()

    public init(
        paths: RootEnginePaths = RootEnginePaths(),
        teamIdentifier: String,
        verifier: RootOwnedExecutableVerifier = RootOwnedExecutableVerifier(),
        runtimeParentPath: String = RootEngineRuntimeDirectory.defaultParentPath,
        intentStore: HelperLaunchIntentStoring = RootLaunchIntentStore()
    ) {
        self.paths = paths
        self.teamIdentifier = teamIdentifier
        self.verifier = verifier
        self.runtimeParentPath = runtimeParentPath
        self.intentStore = intentStore
    }

    public func launch(holding exclusion: HelperStartExclusionHandoff?) throws -> RunningHelperEngine {
        try launch(holding: exclusion, credentials: nil)
    }

    public func launch(
        holding exclusion: HelperStartExclusionHandoff?,
        credentials: Int32?
    ) throws -> RunningHelperEngine {
        // The session controller writes and syncs the durable launch intent
        // before it calls this method. Check it again here, next to the spawn,
        // so no production path can create an engine without the intent. Do not
        // add another path that spawns an engine.
        guard geteuid() == 0 else { throw HelperTrustError.requiresRoot }
        // A start without the exclusion handoff is not a protected start. The
        // helper never spawns an engine on the direct command line path.
        guard let exclusion else { throw HelperTrustError.engineStartFailed }
        do {
            try exclusion.verify()
        } catch {
            throw HelperTrustError.engineStartFailed
        }
        do {
            guard try intentStore.isPresent() else {
                throw HelperTrustError.engineStartFailed
            }
        } catch let error as HelperTrustError {
            throw error
        } catch {
            throw HelperTrustError.engineStartFailed
        }
        let engine = try verifier.verify(
            RootOwnedExecutablePolicy(
                path: paths.enginePath,
                trustedRoot: paths.engineInstallRoot,
                identifier: paths.engineIdentifier,
                teamIdentifier: teamIdentifier
            )
        )
        try prepareHomeDirectory()

        // Every descriptor the child inherits is first duplicated above every
        // target number, so no dup2 in the file action list can land on a
        // source that a later dup2 still needs. The credentials descriptor
        // comes from XPC before this method creates its pipes, so in a fresh
        // helper it often has a low number such as 3 or 4. The 2026-11-06
        // release candidate duplicated it after `dup2(token, 3)`, which put the
        // token pipe on descriptor 6 and closed descriptor 3, and every start
        // failed before the engine published its port.
        var owned: [Int32] = []
        func closeOwned() {
            for descriptor in owned { close(descriptor) }
            owned.removeAll()
        }
        func relocated(_ descriptor: Int32) -> Int32? {
            let copy = RootEngineSpawnDescriptors.relocate(descriptor)
            if let copy { owned.append(copy) }
            return copy
        }

        var tokenPipe: [Int32] = [-1, -1]
        var parentPipe: [Int32] = [-1, -1]
        var errorPipe: [Int32] = [-1, -1]
        guard pipe(&tokenPipe) == 0 else { throw HelperTrustError.engineStartFailed }
        guard pipe(&parentPipe) == 0 else {
            close(tokenPipe[0]); close(tokenPipe[1])
            throw HelperTrustError.engineStartFailed
        }
        guard pipe(&errorPipe) == 0 else {
            close(tokenPipe[0]); close(tokenPipe[1])
            close(parentPipe[0]); close(parentPipe[1])
            throw HelperTrustError.engineStartFailed
        }

        let tokenRead = relocated(tokenPipe[0])
        let parentRead = relocated(parentPipe[0])
        let errorWrite = relocated(errorPipe[1])
        let exclusionSource = relocated(exclusion.descriptor)
        let credentialSource: Int32?
        if let credentials, credentials >= 0 {
            credentialSource = relocated(credentials)
        } else {
            credentialSource = -1
        }
        close(tokenPipe[0]); close(parentPipe[0]); close(errorPipe[1])
        guard let tokenRead, let parentRead, let errorWrite, let exclusionSource,
              let credentialSource
        else {
            close(tokenPipe[1]); close(parentPipe[1]); close(errorPipe[0])
            closeOwned()
            throw HelperTrustError.engineStartFailed
        }
        let hasCredentials = credentialSource >= 0
        // A write must not raise SIGPIPE even before HelperPipeWriter runs, and
        // the parent ends must not leak into an unrelated child. A failure here
        // is a start failure, not a warning.
        guard fcntl(tokenPipe[1], F_SETFD, FD_CLOEXEC) != -1,
              fcntl(parentPipe[1], F_SETFD, FD_CLOEXEC) != -1,
              fcntl(errorPipe[0], F_SETFD, FD_CLOEXEC) != -1,
              fcntl(tokenPipe[1], F_SETNOSIGPIPE, 1) != -1,
              fcntl(parentPipe[1], F_SETNOSIGPIPE, 1) != -1
        else {
            close(tokenPipe[1]); close(parentPipe[1]); close(errorPipe[0])
            closeOwned()
            throw HelperTrustError.engineStartFailed
        }

        // Hold the parent directory and the new directory as descriptors. The
        // port file is read with openat against the held directory, never by
        // path, so a rename or a symlink swap between the check and the read
        // cannot substitute another file.
        let runtime: RootEngineRuntimeDirectory
        do {
            runtime = try RootEngineRuntimeDirectory(parentPath: runtimeParentPath)
        } catch {
            close(tokenPipe[1]); close(parentPipe[1]); close(errorPipe[0])
            closeOwned()
            throw HelperTrustError.engineStartFailed
        }

        var secretBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, secretBytes.count, &secretBytes) == errSecSuccess else {
            close(tokenPipe[1]); close(parentPipe[1]); close(errorPipe[0])
            closeOwned()
            runtime.remove()
            throw HelperTrustError.engineStartFailed
        }
        let secret = secretBytes.map { String(format: "%02x", $0) }.joined()

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        var actionsInitialized = false
        var attributesInitialized = false
        // Every setup call below can fail. A failed setup must release the
        // runtime directory and every descriptor; otherwise a later start
        // inherits a half-built spawn state or a stale runtime directory.
        func cleanupSpawnSetup() {
            if actionsInitialized {
                posix_spawn_file_actions_destroy(&actions)
                actionsInitialized = false
            }
            if attributesInitialized {
                posix_spawnattr_destroy(&attributes)
                attributesInitialized = false
            }
            close(tokenPipe[1]); close(parentPipe[1]); close(errorPipe[0])
            closeOwned()
            runtime.remove()
        }

        guard posix_spawn_file_actions_init(&actions) == 0 else {
            cleanupSpawnSetup()
            throw HelperTrustError.engineStartFailed
        }
        actionsInitialized = true
        // Standard input and output are /dev/null, never an inherited helper
        // descriptor: a helper started with 0 or 1 closed would otherwise hand
        // the engine one of its own pipes there. Standard error is the capture
        // pipe, so the helper can read the engine's one fixed startup failure
        // line.
        guard posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0) == 0
        else {
            cleanupSpawnSetup()
            throw HelperTrustError.engineStartFailed
        }
        // The token goes to 3, the liveness pipe to 4, the start-exclusion
        // lock to 5, and the pairing handoff to 6. The helper never reads the
        // handoff. A missing handoff is allowed: direct mode needs no source
        // device pairing.
        var mappings: [(source: Int32, target: Int32)] = [
            (errorWrite, 2),
            (tokenRead, 3),
            (parentRead, 4),
            (exclusionSource, HelperStartExclusionProtocol.handoffDescriptor),
        ]
        if hasCredentials {
            mappings.append((credentialSource, 6))
        }
        guard RootEngineSpawnDescriptors.addMappings(mappings, to: &actions) else {
            cleanupSpawnSetup()
            throw HelperTrustError.engineStartFailed
        }

        // Recheck the locked file next to the spawn. A replaced lock inode is
        // not the lock that the engine will validate, so spawning an engine
        // under it would not provide exclusion. The relocated descriptor
        // shares the open file description that `verify` checks.
        do {
            try exclusion.verify()
        } catch {
            cleanupSpawnSetup()
            throw HelperTrustError.engineStartFailed
        }

        guard posix_spawnattr_init(&attributes) == 0 else {
            cleanupSpawnSetup()
            throw HelperTrustError.engineStartFailed
        }
        attributesInitialized = true
        var defaults = sigset_t()
        sigemptyset(&defaults)
        sigaddset(&defaults, SIGTERM)
        sigaddset(&defaults, SIGINT)
        var mask = sigset_t()
        sigemptyset(&mask)
        guard posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &mask) == 0,
              posix_spawnattr_setflags(
                  &attributes,
                  Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT)
              ) == 0
        else {
            cleanupSpawnSetup()
            throw HelperTrustError.engineStartFailed
        }

        var arguments = [
            engine, "gui", "--no-open", "--port", "0", "--port-file", runtime.portFilePath,
            "--token-fd", "3", "--parent-fd", "4", "--grant-file", runtime.grantFilePath,
        ]
        if hasCredentials {
            arguments += ["--credentials-fd", "6"]
        }
        let environment = [
            "HOME=\(paths.homeDirectory)",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "LC_ALL=C",
            // The Rust engine validates these non-secret values against the
            // lock it opens itself. Descriptor 5 carries the inherited copy of
            // the helper's open file description.
            "HOTSPOTSHADE_START_EXCLUSION_FD=\(HelperStartExclusionProtocol.handoffDescriptor)",
            "HOTSPOTSHADE_START_EXCLUSION_VERSION=\(HelperStartExclusionProtocol.protocolVersion)",
            "HOTSPOTSHADE_START_EXCLUSION_DEVICE=\(exclusion.lockDevice)",
            "HOTSPOTSHADE_START_EXCLUSION_INODE=\(exclusion.lockInode)",
        ]
        let argv = arguments.map { strdup($0) } + [nil]
        let envp = environment.map { strdup($0) } + [nil]

        var child: pid_t = 0
        let spawned = posix_spawn(&child, engine, &actions, &attributes, argv, envp)

        posix_spawn_file_actions_destroy(&actions)
        actionsInitialized = false
        posix_spawnattr_destroy(&attributes)
        attributesInitialized = false
        for pointer in argv { free(pointer) }
        for pointer in envp { free(pointer) }
        // The child has its own copies. The helper keeps only the token and
        // liveness write ends and the capture read end.
        closeOwned()

        guard spawned == 0, child > 0 else {
            close(tokenPipe[1]); close(parentPipe[1]); close(errorPipe[0])
            runtime.remove()
            throw HelperTrustError.engineStartFailed
        }
        let capture = RootEngineStderrCapture(readDescriptor: errorPipe[0])

        // From this point the child exists. Keep one owner for it so every
        // failure path closes the liveness descriptor, sends SIGTERM, and
        // reaps the child. A throw must not leave an unowned root engine.
        let running = RunningRootEngine(
            processIdentifier: child,
            parentWrite: parentPipe[1],
            port: 0,
            secret: secret,
            runtime: runtime,
            stderrCapture: capture
        )

        let bytes = Array((secret + "\n").utf8)
        let wrote = HelperPipeWriter.writeAll(descriptor: tokenPipe[1], bytes: bytes)
        close(tokenPipe[1])
        if !wrote {
            throw stopAfterFailedLaunch(running, fallback: .secretNotDelivered)
        }

        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if let port = try? runtime.readPort() {
                running.recordPort(port)
                return running
            }
            var status: Int32 = 0
            if waitpid(child, &status, WNOHANG) == child {
                // The child is already reaped. Do not send a signal to a PID
                // that the kernel may have reused. It exited before it
                // published its port, so no session existed and the helper
                // never wrote a grant: the engine cannot have changed a
                // route. This is a failed start with the engine's reason.
                running.markExited()
                throw HelperEngineExitedBeforeGrant(
                    reason: capture.reason(waitingUpTo: 1) ?? .exitedWithoutReason
                )
            }
            usleep(50_000)
        }
        throw stopAfterFailedLaunch(running, fallback: .noPortInTime)
    }

    private func prepareHomeDirectory() throws {
        let path = paths.homeDirectory
        var status = stat()
        if lstat(path, &status) != 0 {
            guard errno == ENOENT else { throw HelperTrustError.unsafeParentDirectory }
            guard mkdir(path, mode_t(0o700)) == 0 else {
                throw HelperTrustError.unsafeParentDirectory
            }
        }
        // The engine home must be a root-owned directory, not a symlink, with
        // no group or other permission and no extended ACL. Check the opened
        // object, not only the path, so a swap cannot land after the check. A
        // failed ACL read is an error, not evidence that the directory is safe.
        let descriptor = open(
            path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else { throw HelperTrustError.unsafeParentDirectory }
        defer { close(descriptor) }
        do {
            try RootStateDirectory.verifySafeDirectory(
                descriptor,
                expectedOwner: 0
            )
        } catch {
            throw HelperTrustError.unsafeParentDirectory
        }
    }

    // Stop a child that never became ready. No session existed, so the helper
    // never wrote a grant and the engine cannot have changed a route. A reaped
    // exit, clean or not, is a failed start with a fixed reason. A stop that
    // did not end the child, or a wait status the helper could not read, is
    // not proof of anything and keeps the cleanup path.
    private func stopAfterFailedLaunch(
        _ running: RunningRootEngine,
        fallback: EngineStartFailureReason
    ) -> Error {
        let result = running.stop()
        if result == .timedOut { return HelperTrustError.engineStopTimedOut }
        guard running.exitObserved else { return HelperTrustError.engineExitUnclean }
        return HelperEngineExitedBeforeGrant(reason: running.startFailureReason ?? fallback)
    }
}

// Place inherited descriptors in a spawned child without collisions. Each
// source is first duplicated to a close-on-exec descriptor at or above
// `lowestSource`, which is above every fixed target number. The file actions
// then copy each relocated source to its target. Because no source can be a
// target, the order of the actions cannot replace a source before it is used.
public enum RootEngineSpawnDescriptors {
    public static let lowestSource: Int32 = 10

    // A close-on-exec copy of `descriptor` at or above `lowestSource`, or nil.
    public static func relocate(_ descriptor: Int32) -> Int32? {
        guard descriptor >= 0 else { return nil }
        let copy = fcntl(descriptor, F_DUPFD_CLOEXEC, lowestSource)
        return copy >= lowestSource ? copy : nil
    }

    // Add one dup2 per mapping. Every source must be a relocated descriptor
    // and every target must be below `lowestSource` and used once.
    public static func addMappings(
        _ mappings: [(source: Int32, target: Int32)],
        to actions: inout posix_spawn_file_actions_t?
    ) -> Bool {
        var targets = Set<Int32>()
        for mapping in mappings {
            guard mapping.source >= lowestSource,
                  mapping.target >= 0, mapping.target < lowestSource,
                  targets.insert(mapping.target).inserted
            else { return false }
        }
        for mapping in mappings {
            guard posix_spawn_file_actions_adddup2(&actions, mapping.source, mapping.target) == 0 else {
                return false
            }
        }
        return true
    }
}

// One private runtime directory for one engine. Both the parent directory and
// the new directory stay open as descriptors. The port file is opened with
// openat against the held directory and O_NOFOLLOW, then checked by fstat
// before its text is read. A path rename, a symlink, or a replacement directory
// cannot substitute another file between the checks. The owner, mode, inode,
// and device must match before the port is trusted.
public final class RootEngineRuntimeDirectory: @unchecked Sendable {
    // One root-owned state directory holds both the cleanup marker and the
    // per-launch runtime directories. /var/run is root:daemon 0775 on macOS,
    // so it is not used as the parent. /var/db is root:wheel and this helper
    // creates its own 0700 directory there.
    public static let defaultParentPath = "/var/db/hotspotshade"
    public static let portFileName = "port"
    // The engine publishes the port through a temporary file and a rename. An
    // interrupted publish can leave this name behind. The directory is
    // root-owned 0700 and only the engine writes here, so removing the known
    // temporary name with the rest of the runtime directory is safe.
    public static let portTempFileName = "port.tmp"
    // One administrator authorization produces one grant. The engine consumes
    // it before it changes a route. It holds no token or identity key.
    public static let grantFileName = "tunnel-grant"

    private let lock = NSLock()
    private let parentDescriptor: Int32
    private let directoryDescriptor: Int32
    private let parentPath: String
    private let name: String
    private let expectedOwner: UInt32
    private var removed = false

    public convenience init(
        parentPath: String = RootEngineRuntimeDirectory.defaultParentPath,
        namePrefix: String = "run-"
    ) throws {
        try self.init(parentPath: parentPath, namePrefix: namePrefix, expectedOwner: 0)
    }

    // The owner seam exists for the hermetic tests, which cannot run as root.
    // The public initializer always requires root.
    init(
        parentPath: String,
        namePrefix: String,
        expectedOwner: UInt32
    ) throws {
        try Self.ensureParentDirectory(parentPath, expectedOwner: expectedOwner)
        let parent = open(
            parentPath,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard parent >= 0 else { throw HelperTrustError.engineStartFailed }
        do {
            try RootStateDirectory.verifySafeDirectory(parent, expectedOwner: expectedOwner)
        } catch {
            close(parent)
            throw HelperTrustError.unsafeParentDirectory
        }
        let name = namePrefix + UUID().uuidString
        guard mkdirat(parent, name, mode_t(0o700)) == 0 else {
            close(parent)
            throw HelperTrustError.engineStartFailed
        }
        let directory = openat(
            parent,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard directory >= 0 else {
            unlinkat(parent, name, AT_REMOVEDIR)
            close(parent)
            throw HelperTrustError.engineStartFailed
        }
        do {
            try RootStateDirectory.verifySafeDirectory(directory, expectedOwner: expectedOwner)
        } catch {
            close(directory)
            unlinkat(parent, name, AT_REMOVEDIR)
            close(parent)
            throw HelperTrustError.unsafeParentDirectory
        }
        self.parentDescriptor = parent
        self.directoryDescriptor = directory
        self.parentPath = parentPath
        self.name = name
        self.expectedOwner = expectedOwner
    }

    private static func ensureParentDirectory(_ path: String, expectedOwner: UInt32) throws {
        // The runtime parent is also the state directory. Create it through the
        // shared state store so a first create syncs the parent entry and the
        // ownership, mode, and symlink checks stay in one place.
        do {
            try RootStateDirectory(path: path, expectedOwner: expectedOwner).ensure()
        } catch {
            throw HelperTrustError.unsafeParentDirectory
        }
        var status = stat()
        guard lstat(path, &status) == 0,
              RootStateDirectory.isSafeDirectory(status, expectedOwner: expectedOwner)
        else {
            throw HelperTrustError.unsafeParentDirectory
        }
    }

    public var path: String { parentPath + "/" + name }
    public var portFilePath: String { path + "/" + Self.portFileName }
    public var grantFilePath: String { path + "/" + Self.grantFileName }

    // Write one fresh grant into the held runtime directory. The engine reads
    // this file, validates its owner, mode, parent, and timestamp, and removes
    // it before the start. A leftover grant is replaced, never reused.
    public func writeTunnelGrant() throws {
        do {
            try RootStateDirectory.verifySafeDirectory(
                directoryDescriptor,
                expectedOwner: expectedOwner
            )
        } catch {
            throw HelperTrustError.grantFailed
        }
        if unlinkat(directoryDescriptor, Self.grantFileName, 0) != 0, errno != ENOENT {
            throw HelperTrustError.grantFailed
        }
        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
            throw HelperTrustError.grantFailed
        }
        let token = random.map { String(format: "%02x", $0) }.joined()
        let timestamp = UInt64(Date().timeIntervalSince1970)
        let contents = Array("\(token) \(timestamp)\n".utf8)
        let descriptor = openat(
            directoryDescriptor,
            Self.grantFileName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else { throw HelperTrustError.grantFailed }
        defer { close(descriptor) }
        var status = stat()
        let safe = fstat(descriptor, &status) == 0
            && RootStateDirectory.isSafeFile(status, expectedOwner: expectedOwner)
            && status.st_nlink == 1
            && ((try? RootStateDirectory.hasExtendedACL(descriptor)) == false)
        guard safe,
              HelperPipeWriter.writeAll(descriptor: descriptor, bytes: contents),
              fsync(descriptor) == 0,
              fsync(directoryDescriptor) == 0
        else {
            _ = unlinkat(directoryDescriptor, Self.grantFileName, 0)
            throw HelperTrustError.grantFailed
        }
    }

    // Remove any grant that the engine did not consume. The caller uses this
    // on a clean stop so a later session cannot inherit it.
    public func removeTunnelGrant() {
        _ = unlinkat(directoryDescriptor, Self.grantFileName, 0)
    }

    public func readPort() throws -> UInt16 {
        // The held directory descriptor is checked again on every read. An ACL
        // added after creation must not let another account write the port the
        // helper trusts.
        do {
            try RootStateDirectory.verifySafeDirectory(
                directoryDescriptor,
                expectedOwner: expectedOwner
            )
        } catch {
            throw HelperTrustError.engineStartFailed
        }
        let descriptor = openat(
            directoryDescriptor,
            Self.portFileName,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        )
        guard descriptor >= 0 else { throw HelperTrustError.engineStartFailed }
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == expectedOwner,
              status.st_mode & 0o022 == 0,
              status.st_size > 0,
              status.st_size <= 16
        else {
            throw HelperTrustError.engineStartFailed
        }
        do {
            guard try !RootStateDirectory.hasExtendedACL(descriptor) else {
                throw HelperTrustError.engineStartFailed
            }
        } catch {
            throw HelperTrustError.engineStartFailed
        }
        var bytes = [UInt8](repeating: 0, count: Int(status.st_size))
        let byteCount = bytes.count
        let count = bytes.withUnsafeMutableBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return read(descriptor, base, byteCount)
        }
        guard count == byteCount,
              let text = String(bytes: bytes, encoding: .utf8),
              let port = UInt16(text.trimmingCharacters(in: .whitespacesAndNewlines)),
              port > 0
        else {
            throw HelperTrustError.engineStartFailed
        }
        return port
    }

    public func remove() {
        lock.lock()
        guard !removed else { lock.unlock(); return }
        removed = true
        lock.unlock()
        _ = unlinkat(directoryDescriptor, Self.portFileName, 0)
        // A stale temp file from an interrupted port publish must not keep the
        // private runtime directory alive after the engine is gone.
        _ = unlinkat(directoryDescriptor, Self.portTempFileName, 0)
        _ = unlinkat(directoryDescriptor, Self.grantFileName, 0)
        _ = unlinkat(parentDescriptor, name, AT_REMOVEDIR)
        close(directoryDescriptor)
        close(parentDescriptor)
    }

    deinit { remove() }
}

public final class RunningRootEngine: RunningHelperEngine, @unchecked Sendable {
    private let lock = NSLock()
    private var processIdentifier: pid_t
    private var parentWrite: Int32
    private var stopped = false
    private var exitedCleanly = false
    // True only after waitpid returned this child. An unreadable wait status
    // leaves it false, so the helper cannot treat that exit as known.
    private var reaped = false
    public private(set) var port: UInt16
    public let secret: String
    private let runtime: RootEngineRuntimeDirectory
    private let stderrCapture: RootEngineStderrCapture?

    public init(
        processIdentifier: pid_t,
        parentWrite: Int32,
        port: UInt16,
        secret: String,
        runtime: RootEngineRuntimeDirectory,
        stderrCapture: RootEngineStderrCapture? = nil
    ) {
        self.processIdentifier = processIdentifier
        self.parentWrite = parentWrite
        self.port = port
        self.secret = secret
        self.runtime = runtime
        self.stderrCapture = stderrCapture
    }

    public var exitObserved: Bool {
        lock.lock(); defer { lock.unlock() }
        return reaped
    }

    // The fixed reason line from the engine, if it printed one. The wait
    // lets the last line arrive after the exit; it is bounded.
    public var startFailureReason: EngineStartFailureReason? {
        stderrCapture?.reason(waitingUpTo: exitObserved ? 1 : 0)
    }

    func recordPort(_ value: UInt16) {
        lock.lock()
        port = value
        lock.unlock()
    }

    // The helper calls this only after it verifies the administrator
    // authorization. The grant is written before the XPC reply, so the app's
    // next start request always sees it.
    public func authorizeStart() throws {
        try runtime.writeTunnelGrant()
    }

    // The child was reaped by the launcher while it waited for the port file.
    // Clear the PID so a later stop cannot signal a recycled PID. An exit
    // before the port is ready is not a clean stop.
    func markExited() {
        var descriptor: Int32 = -1
        lock.lock()
        processIdentifier = 0
        stopped = true
        exitedCleanly = false
        reaped = true
        descriptor = parentWrite
        parentWrite = -1
        lock.unlock()
        if descriptor >= 0 { close(descriptor) }
        runtime.remove()
    }

    public var description: HelperEngineDescription {
        lock.lock()
        let value = HelperEngineDescription(port: port, secret: secret)
        lock.unlock()
        return value
    }

    public var isRunning: Bool {
        lock.lock()
        guard !stopped, processIdentifier > 0 else {
            lock.unlock()
            return false
        }
        var status: Int32 = 0
        let result = waitpid(processIdentifier, &status, WNOHANG)
        if result == processIdentifier {
            processIdentifier = 0
            exitedCleanly = Self.isCleanExit(status)
            reaped = true
            lock.unlock()
            return false
        }
        if result < 0 && errno != EINTR {
            // An unknown wait status is not proof of life or a clean exit.
            processIdentifier = 0
            exitedCleanly = false
            lock.unlock()
            return false
        }
        lock.unlock()
        return true
    }

    public func stop() -> EngineStopResult {
        lock.lock()
        if stopped {
            let clean = exitedCleanly
            lock.unlock()
            return clean ? .stopped : .failed
        }
        stopped = true
        let pid = processIdentifier
        if parentWrite >= 0 {
            close(parentWrite)
            parentWrite = -1
        }
        lock.unlock()
        guard pid > 0 else {
            runtime.remove()
            return .failed
        }
        _ = kill(pid, SIGTERM)
        let deadline = Date().addingTimeInterval(HelperEngineStopDeadline.engineStop)
        while Date() < deadline {
            var status: Int32 = 0
            let result = waitpid(pid, &status, WNOHANG)
            if result == pid {
                let clean = Self.isCleanExit(status)
                lock.lock()
                processIdentifier = 0
                exitedCleanly = clean
                reaped = true
                lock.unlock()
                runtime.remove()
                return clean ? .stopped : .failed
            }
            if result < 0 && errno != EINTR {
                // The exit status is unknown. Do not claim a clean stop.
                lock.lock()
                processIdentifier = 0
                exitedCleanly = false
                lock.unlock()
                runtime.remove()
                return .failed
            }
            usleep(50_000)
        }
        // Do not send SIGKILL. The engine may still own routes. The session
        // controller records cleanupBlocked and refuses a new start.
        return .timedOut
    }

    private static func isCleanExit(_ status: Int32) -> Bool {
        // WIFEXITED: the low 7 bits are zero. WEXITSTATUS: bits 8 through 15.
        (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0
    }

    deinit {
        // Parent loss is the designed stop for a helper that exits without a
        // stop request. The engine watches descriptor 4 and cleans up. Closing
        // it here is the same signal. The helper cannot prove the engine
        // finished before this process exits, so the durable cleanup marker
        // must already be in place on every abnormal path.
        if parentWrite >= 0 { close(parentWrite) }
        runtime.remove()
    }
}
