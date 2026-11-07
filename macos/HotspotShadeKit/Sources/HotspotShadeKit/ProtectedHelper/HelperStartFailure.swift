import Foundation
import Darwin

// Why one root engine did not start. The engine prints one fixed line on
// standard error when its startup fails before it serves a request:
// `hotspotshade-start-failure: <code>` (see `StartupStage` in rust/src/main.rs).
// The helper accepts only a code from this list. It never stores, logs, or
// sends the rest of the engine's standard error, so the reason cannot carry a
// token, a key, an address, or a path.
public enum EngineStartFailureReason: String, CaseIterable, Equatable, Sendable {
    // Codes the engine prints.
    case argumentsInvalid = "arguments_invalid"
    case controlDescriptorInvalid = "control_descriptor_invalid"
    case credentialsDescriptorInvalid = "credentials_descriptor_invalid"
    case tokenInvalid = "token_invalid"
    case credentialsHandoffInvalid = "credentials_handoff_invalid"
    case listenerFailed = "listener_failed"
    case portFileFailed = "port_file_failed"
    case credentialsImportFailed = "credentials_import_failed"
    case startExclusionDescriptorInvalid = "start_exclusion_descriptor_invalid"
    // Codes the helper sets itself when the engine printed no known line.
    case exitedWithoutReason = "exited_without_reason"
    case noPortInTime = "no_port_in_time"
    case secretNotDelivered = "secret_not_delivered"

    public static let linePrefix = "hotspotshade-start-failure: "

    // The codes that may come from the engine's standard error. A helper-side
    // code printed by the engine is not accepted.
    static let engineCodes: Set<EngineStartFailureReason> = [
        .argumentsInvalid, .controlDescriptorInvalid, .credentialsDescriptorInvalid,
        .tokenInvalid, .credentialsHandoffInvalid, .listenerFailed, .portFileFailed,
        .credentialsImportFailed, .startExclusionDescriptorInvalid,
    ]

    // Read the last fixed reason line from captured engine output. Every
    // other byte is ignored. A line must be exactly the prefix and one known
    // engine code, so a near match or extra text is no reason at all.
    public static func parse(engineOutput bytes: [UInt8]) -> EngineStartFailureReason? {
        var found: EngineStartFailureReason?
        var line: [UInt8] = []
        func finishLine() {
            defer { line.removeAll(keepingCapacity: true) }
            if line.last == UInt8(ascii: "\r") { line.removeLast() }
            guard line.count <= 128,
                  let text = String(bytes: line, encoding: .ascii),
                  text.hasPrefix(linePrefix),
                  let reason = EngineStartFailureReason(rawValue: String(text.dropFirst(linePrefix.count))),
                  engineCodes.contains(reason)
            else { return }
            found = reason
        }
        for byte in bytes {
            if byte == UInt8(ascii: "\n") { finishLine() } else { line.append(byte) }
        }
        finishLine()
        return found
    }

    // One plain sentence for the dashboard. It names what failed and what to
    // do, never a path, a descriptor number, or a token.
    public var sentence: String {
        switch self {
        case .argumentsInvalid:
            return "The engine refused its start options. Reinstall HotspotShade so the app, helper, and engine match."
        case .controlDescriptorInvalid, .tokenInvalid, .startExclusionDescriptorInvalid:
            return "The protected helper did not hand the engine its private start channels. Reinstall HotspotShade so the app, helper, and engine match."
        case .credentialsDescriptorInvalid:
            return "The protected helper did not hand the engine the pairing channel. Reinstall HotspotShade so the app, helper, and engine match."
        case .credentialsHandoffInvalid:
            return "The engine did not receive a usable pairing. Turn the tunnel on again. If this repeats, pair the source device again."
        case .credentialsImportFailed:
            return "The engine could not use the pairing. Pair the source device again."
        case .listenerFailed:
            return "The engine could not open its local control port. Try again."
        case .portFileFailed:
            return "The engine could not report its control port to the protected helper. Try again."
        case .exitedWithoutReason:
            return "The engine stopped before it was ready."
        case .noPortInTime:
            return "The engine did not become ready in time. Try again."
        case .secretNotDelivered:
            return "The protected helper could not hand the engine its private start secret. Try again."
        }
    }
}

// The engine exited before the helper ever wrote a tunnel grant for it. The
// engine changes a route only after it consumes a grant, so this exit cannot
// have changed a route. The helper records a failed start with this reason,
// not a cleanup block. A launcher throws this only when it reaped the child
// and therefore knows that it exited.
public struct HelperEngineExitedBeforeGrant: Error, Equatable, Sendable {
    public let reason: EngineStartFailureReason
    public init(reason: EngineStartFailureReason) { self.reason = reason }
}

// The app-side error for a start that failed before any authorization. The
// dashboard says that the tunnel did not start and why.
public struct HelperEngineDidNotStart: Error, Equatable, Sendable, LocalizedError {
    public let reason: EngineStartFailureReason?
    public init(reason: EngineStartFailureReason?) { self.reason = reason }
    public var errorDescription: String? { Strings.tunnelDidNotStart(reason) }
}

// Drain the root engine's standard error for its whole life. The engine must
// never block on a full pipe, so the reader keeps reading to end of file and
// keeps only the most recent bytes, bounded by `limit`. Only the parsed fixed
// reason leaves this object.
public final class RootEngineStderrCapture: @unchecked Sendable {
    public static let limit = 4096
    private let condition = NSCondition()
    private var buffer: [UInt8] = []
    private var finished = false
    private let descriptor: Int32

    // Takes ownership of the read end and starts the reader thread.
    public init(readDescriptor: Int32) {
        descriptor = readDescriptor
        let thread = Thread { [self] in readUntilEnd() }
        thread.name = "hotspotshade-engine-stderr"
        thread.start()
    }

    private func readUntilEnd() {
        var chunk = [UInt8](repeating: 0, count: 1024)
        while true {
            let count = chunk.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { break }
            condition.lock()
            buffer.append(contentsOf: chunk[0..<count])
            if buffer.count > Self.limit {
                buffer.removeFirst(buffer.count - Self.limit)
            }
            condition.unlock()
        }
        close(descriptor)
        condition.lock()
        finished = true
        condition.broadcast()
        condition.unlock()
    }

    // The fixed reason in the output so far. After the engine exits, the
    // caller waits briefly for end of file so the last line is present. A
    // child of the engine that still holds the pipe cannot extend this wait
    // beyond `waitingUpTo`.
    public func reason(waitingUpTo seconds: TimeInterval = 0) -> EngineStartFailureReason? {
        let deadline = Date().addingTimeInterval(seconds)
        condition.lock()
        while !finished && seconds > 0 && condition.wait(until: deadline) {}
        let bytes = buffer
        condition.unlock()
        return EngineStartFailureReason.parse(engineOutput: bytes)
    }
}

// The last failed start, kept as one fixed code for a person who inspects the
// host. It holds no engine output.
public protocol HelperStartFailureRecording: Sendable {
    func record(_ reason: EngineStartFailureReason)
    func read() -> EngineStartFailureReason?
}

public struct NoStartFailureRecord: HelperStartFailureRecording {
    public init() {}
    public func record(_ reason: EngineStartFailureReason) { _ = reason }
    public func read() -> EngineStartFailureReason? { nil }
}

public final class InMemoryStartFailureRecord: HelperStartFailureRecording, @unchecked Sendable {
    private let lock = NSLock()
    private var value: EngineStartFailureReason?
    public init() {}
    public func record(_ reason: EngineStartFailureReason) {
        lock.lock(); value = reason; lock.unlock()
    }
    public func read() -> EngineStartFailureReason? {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

// `/var/db/hotspotshade/last-start-failure`: root-owned, mode 0600, one line
// with one fixed code. The file is replaced on each failed start and is at
// most `maximumBytes` long. It is diagnostics only: no start, stop, or
// cleanup decision reads it.
public struct RootStartFailureStore: HelperStartFailureRecording {
    public static let defaultFileName = "last-start-failure"
    public static let maximumBytes = 4096

    private let directoryPath: String
    private let fileName: String
    private let expectedOwner: UInt32

    public init(
        directoryPath: String = RootCleanupBlockStore.defaultDirectoryPath,
        fileName: String = RootStartFailureStore.defaultFileName
    ) {
        self.init(directoryPath: directoryPath, fileName: fileName, expectedOwner: 0)
    }

    // The owner seam exists for the hermetic tests, which cannot run as root.
    init(directoryPath: String, fileName: String, expectedOwner: UInt32) {
        self.directoryPath = directoryPath
        self.fileName = fileName
        self.expectedOwner = expectedOwner
    }

    private var state: RootStateDirectory {
        RootStateDirectory(path: directoryPath, expectedOwner: expectedOwner)
    }

    public func record(_ reason: EngineStartFailureReason) {
        // A failed diagnostic write never changes the start result.
        try? state.removeFile(fileName)
        try? state.createFile(fileName, contents: Array((reason.rawValue + "\n").utf8))
    }

    public func read() -> EngineStartFailureReason? {
        guard let directory = try? state.openIfPresent() else { return nil }
        defer { close(directory) }
        let descriptor = openat(directory, fileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              RootStateDirectory.isSafeFile(status, expectedOwner: expectedOwner),
              status.st_size > 0, status.st_size <= Self.maximumBytes
        else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(status.st_size))
        let count = bytes.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        guard count == bytes.count,
              let text = String(bytes: bytes, encoding: .ascii)
        else { return nil }
        return EngineStartFailureReason(rawValue: text.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}
