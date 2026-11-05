import Foundation
import Network
import Darwin

// Only the I/O owner closes the descriptor. Cancellation shuts it down while
// holding the same lock used for registration and close. This prevents a
// shutdown from targeting a reused descriptor.
final class ICMPEchoCancellation {
    private let lock = NSLock()
    private var cancelled = false
    private var descriptor: Int32?

    func open(_ create: () -> Int32) throws -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled else { throw CellularICMPEcho.EchoError.cancelled }
        guard descriptor == nil else { throw CellularICMPEcho.EchoError.busy }
        let fd = create()
        guard fd >= 0 else { throw CellularICMPEcho.EchoError.socketError(errno) }
        descriptor = fd
        return fd
    }

    func send(_ fd: Int32, packet: [UInt8]) throws -> Int {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, descriptor == fd else { throw CellularICMPEcho.EchoError.cancelled }
        return packet.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, MSG_DONTWAIT) }
    }

    func close(_ fd: Int32) {
        lock.lock()
        defer { lock.unlock() }
        guard descriptor == fd else { return }
        descriptor = nil
        Darwin.close(fd)
    }

    func cancel() {
        lock.lock()
        defer { lock.unlock() }
        cancelled = true
        if let fd = descriptor { _ = shutdown(fd, SHUT_RDWR) }
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

// Experimental cellular echo. Use it only after client authentication.
// Call this on a background queue with a current cellular interface.
enum CellularICMPEcho {
    enum EchoError: Error {
        case invalidInterface, invalidAddress, invalidPayload, busy, cancelled
        case socketError(Int32), pinFailed, timeout, invalidReply
    }

    private static let lock = NSLock()
    private static var active = 0
    private static let maximumActive = 8

    private static func socketTimeout(_ seconds: TimeInterval) throws -> timeval {
        guard seconds.isFinite, seconds >= 0.01, seconds <= 3 else { throw EchoError.timeout }
        let micros = Int(seconds * 1_000_000)
        return timeval(tv_sec: micros / 1_000_000, tv_usec: Int32(micros % 1_000_000))
    }

    // Return the reply payload. This operation does not resolve host names.
    static func send(address: String, payload: Data, interface: NWInterface,
                     cancellation: ICMPEchoCancellation = ICMPEchoCancellation(),
                     timeoutSeconds: TimeInterval = 3,
                     timing: ((UInt64, UInt64) -> Void)? = nil) throws -> Data {
        let attemptStarted = DispatchTime.now().uptimeNanoseconds
        guard let interfaceIndex = UInt32(exactly: interface.index),
              ExperimentalICMPSelection.validInterface(isCellular: interface.type == .cellular,
                index: interfaceIndex, currentIndex: if_nametoindex(interface.name)) else {
            throw EchoError.invalidInterface
        }
        guard payload.count <= 1200 else { throw EchoError.invalidPayload }
        var peer = sockaddr_in()
        peer.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        peer.sin_family = sa_family_t(AF_INET)
        guard address.withCString({ inet_pton(AF_INET, $0, &peer.sin_addr) }) == 1 else {
            throw EchoError.invalidAddress
        }
        lock.lock()
        guard active < maximumActive else { lock.unlock(); throw EchoError.busy }
        active += 1
        lock.unlock()
        defer { lock.lock(); active -= 1; lock.unlock() }

        let fd = try cancellation.open { socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) }
        defer { cancellation.close(fd) }
        var index = interfaceIndex
        guard setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index,
                         socklen_t(MemoryLayout.size(ofValue: index))) == 0 else {
            throw EchoError.pinFailed
        }
        var bound: UInt32 = 0
        var boundLength = socklen_t(MemoryLayout<UInt32>.size)
        guard getsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &bound, &boundLength) == 0,
              ExperimentalICMPSelection.validPin(expected: interfaceIndex, observed: bound,
                                                  length: Int(boundLength)) else { throw EchoError.pinFailed }
        var timeout = try socketTimeout(timeoutSeconds)
        guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                         socklen_t(MemoryLayout.size(ofValue: timeout))) == 0 else {
            throw EchoError.socketError(errno)
        }
        guard setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                         socklen_t(MemoryLayout.size(ofValue: timeout))) == 0 else {
            throw EchoError.socketError(errno)
        }
        let connected = withUnsafePointer(to: &peer) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { throw EchoError.socketError(errno) }

        // The kernel can replace the identifier on ICMP datagram sockets.
        let sequence = UInt16.random(in: 0...UInt16.max)
        let nonce = (0..<16).map { _ in UInt8.random(in: 0...UInt8.max) }
        var packet: [UInt8] = [8, 0, 0, 0, 0, 0, UInt8(sequence >> 8), UInt8(sequence & 255)]
        packet.append(contentsOf: nonce)
        packet.append(contentsOf: payload)
        let sum = checksum(packet)
        packet[2] = UInt8(sum >> 8)
        packet[3] = UInt8(sum & 255)
        guard if_nametoindex(interface.name) == interfaceIndex else { throw EchoError.invalidInterface }
        let waitStarted = DispatchTime.now().uptimeNanoseconds
        let setup = waitStarted - attemptStarted
        var timingRecorded = false
        defer {
            if !timingRecorded { timing?(setup, DispatchTime.now().uptimeNanoseconds - waitStarted) }
        }
        let sent = try cancellation.send(fd, packet: packet)
        guard sent == packet.count else { throw EchoError.socketError(sent < 0 ? errno : EIO) }
        var reply = [UInt8](repeating: 0, count: 2048)
        let count = reply.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        timing?(setup, DispatchTime.now().uptimeNanoseconds - waitStarted)
        timingRecorded = true
        guard count >= 0 else {
            if errno == EAGAIN || errno == EWOULDBLOCK { throw EchoError.timeout }
            throw EchoError.socketError(errno)
        }
        reply = Array(reply.prefix(count))
        let result = try validateReply(reply, sequence: sequence, nonce: nonce,
                                       payloadSize: payload.count)
        guard result == payload else { throw EchoError.invalidReply }
        return result
    }

    // The phone kernel computes and checks ICMPv6 checksums. This experiment
    // accepts numeric unicast addresses and pins the socket to cellular.
    static func sendIPv6(address: String, payload: Data, interface: NWInterface,
                         cancellation: ICMPEchoCancellation = ICMPEchoCancellation(),
                         timeoutSeconds: TimeInterval = 3,
                         timing: ((UInt64, UInt64) -> Void)? = nil) throws -> Data {
        let attemptStarted = DispatchTime.now().uptimeNanoseconds
        guard let interfaceIndex = UInt32(exactly: interface.index),
              ExperimentalICMPSelection.validInterface(isCellular: interface.type == .cellular,
                index: interfaceIndex, currentIndex: if_nametoindex(interface.name)) else {
            throw EchoError.invalidInterface
        }
        guard payload.count <= 1200 else { throw EchoError.invalidPayload }
        var peer = sockaddr_in6()
        peer.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        peer.sin6_family = sa_family_t(AF_INET6)
        guard address.withCString({ inet_pton(AF_INET6, $0, &peer.sin6_addr) }) == 1 else {
            throw EchoError.invalidAddress
        }
        let addressBytes = withUnsafeBytes(of: peer.sin6_addr) { Array($0) }
        // Scoped, multicast, unspecified, and loopback targets are not valid
        // for this cellular-only experiment.
        guard addressBytes[0] != 0xff,
              !(addressBytes[0] == 0xfe && (addressBytes[1] & 0xc0) == 0x80),
              addressBytes.contains(where: { $0 != 0 }),
              addressBytes != Array(repeating: UInt8(0), count: 15) + [1] else {
            throw EchoError.invalidAddress
        }
        lock.lock()
        guard active < maximumActive else { lock.unlock(); throw EchoError.busy }
        active += 1
        lock.unlock()
        defer { lock.lock(); active -= 1; lock.unlock() }

        let fd = try cancellation.open { socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) }
        defer { cancellation.close(fd) }
        var index = interfaceIndex
        guard setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index,
                         socklen_t(MemoryLayout.size(ofValue: index))) == 0 else {
            throw EchoError.pinFailed
        }
        var bound: UInt32 = 0
        var boundLength = socklen_t(MemoryLayout<UInt32>.size)
        guard getsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &bound, &boundLength) == 0,
              ExperimentalICMPSelection.validPin(expected: interfaceIndex, observed: bound,
                                                  length: Int(boundLength)) else { throw EchoError.pinFailed }
        var timeout = try socketTimeout(timeoutSeconds)
        guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                         socklen_t(MemoryLayout.size(ofValue: timeout))) == 0 else {
            throw EchoError.socketError(errno)
        }
        guard setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                         socklen_t(MemoryLayout.size(ofValue: timeout))) == 0 else {
            throw EchoError.socketError(errno)
        }
        let connected = withUnsafePointer(to: &peer) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard connected == 0 else { throw EchoError.socketError(errno) }
        let sequence = UInt16.random(in: 0...UInt16.max)
        let nonce = (0..<16).map { _ in UInt8.random(in: 0...UInt8.max) }
        var packet: [UInt8] = [128, 0, 0, 0, 0, 0, UInt8(sequence >> 8), UInt8(sequence & 255)]
        packet.append(contentsOf: nonce)
        packet.append(contentsOf: payload)
        guard if_nametoindex(interface.name) == interfaceIndex else { throw EchoError.invalidInterface }
        let waitStarted = DispatchTime.now().uptimeNanoseconds
        let setup = waitStarted - attemptStarted
        var timingRecorded = false
        defer {
            if !timingRecorded { timing?(setup, DispatchTime.now().uptimeNanoseconds - waitStarted) }
        }
        let sent = try cancellation.send(fd, packet: packet)
        guard sent == packet.count else { throw EchoError.socketError(sent < 0 ? errno : EIO) }
        var reply = [UInt8](repeating: 0, count: 2048)
        let count = reply.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        timing?(setup, DispatchTime.now().uptimeNanoseconds - waitStarted)
        timingRecorded = true
        guard count >= 0 else {
            if errno == EAGAIN || errno == EWOULDBLOCK { throw EchoError.timeout }
            throw EchoError.socketError(errno)
        }
        let result = try validateIPv6Reply(Array(reply.prefix(count)), sequence: sequence,
                                           nonce: nonce, payloadSize: payload.count)
        guard result == payload else { throw EchoError.invalidReply }
        return result
    }

    // Call this only for data returned by an ICMPv6 socket. The kernel checks
    // the IPv6 pseudo-header checksum before it delivers the reply.
    static func validateIPv6Reply(_ reply: [UInt8], sequence: UInt16,
                                  nonce: [UInt8], payloadSize: Int) throws -> Data {
        guard payloadSize >= 0, payloadSize <= 1200, nonce.count == 16,
              reply.count == 8 + nonce.count + payloadSize,
              reply[0] == 129, reply[1] == 0,
              reply[6] == UInt8(sequence >> 8), reply[7] == UInt8(sequence & 255),
              Array(reply[8..<(8 + nonce.count)]) == nonce else {
            throw EchoError.invalidReply
        }
        return Data(reply[(8 + nonce.count)...])
    }

    static func validateReply(_ reply: [UInt8], sequence: UInt16,
                              nonce: [UInt8], payloadSize: Int) throws -> Data {
        let offset: Int
        if !reply.isEmpty && reply[0] >> 4 == 4 {
            offset = Int(reply[0] & 15) * 4
            guard offset >= 20 else { throw EchoError.invalidReply }
        } else { offset = 0 }
        guard payloadSize >= 0, payloadSize <= 1200, nonce.count == 16,
              reply.count == offset + 8 + nonce.count + payloadSize,
              reply[offset] == 0, reply[offset + 1] == 0,
              reply[offset + 6] == UInt8(sequence >> 8),
              reply[offset + 7] == UInt8(sequence & 255),
              Array(reply[(offset + 8)..<(offset + 8 + nonce.count)]) == nonce,
              checksum(Array(reply[offset...])) == 0 else {
            throw EchoError.invalidReply
        }
        return Data(reply[(offset + 8 + nonce.count)...])
    }

    private static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i < bytes.count {
            let second = i + 1 < bytes.count ? UInt32(bytes[i + 1]) : 0
            sum += (UInt32(bytes[i]) << 8) | second
            i += 2
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }
}

// Experimental echo protocol. The listener authenticates the client
// before it parses this command.
enum ExperimentalICMPCommand {
    static let command: UInt8 = 0x81
    static let persistentCommand: UInt8 = 0x82
    static let maximumPayload = 1200
    enum Family: Hashable { case ipv4, ipv6 }
    enum Status: UInt8 {
        case success = 0, noCellular = 1, busy = 2, timeout = 3, failed = 4
        case pathTimeout = 5, pathUnsatisfied = 6, pathNotCellular = 7
        // Status 8 means no candidate passed cellular interface validation.
        case noCellularInterface = 8, ambiguousCellular = 9
    }
    enum ParseError: Error { case invalidTarget, invalidLength, invalidResponse }
    struct Target {
        let family: Family
        let address: String
    }
    static func isPermitted(command: UInt8, authenticated: Bool) -> Bool {
        return authenticated && (command == Self.command || command == Self.persistentCommand)
    }
    static func shouldCancel(clientDataCount: Int, eof: Bool, failed: Bool) -> Bool {
        return clientDataCount > 0 || eof || failed
    }
    static func persistentShouldClose(eof: Bool, failed: Bool) -> Bool {
        return eof || failed
    }
    // A nil result means the path has a bounded set of cellular interfaces.
    static func pathProblem(satisfied: Bool, usesCellular: Bool, cellularCount: Int) -> Status? {
        if !satisfied { return .pathUnsatisfied }
        if cellularCount == 0 { return .noCellularInterface }
        if cellularCount > 4 { return .ambiguousCellular }
        if !usesCellular { return .pathNotCellular }
        return nil
    }

    // Only numeric unicast destinations are accepted. Port zero is reserved
    // for echo. Scoped IPv6 and IPv4-mapped IPv6 addresses are not accepted.
    static func target(type: UInt8, address: [UInt8], port: UInt16) throws -> Target {
        guard port == 0 else { throw ParseError.invalidTarget }
        let family: Int32
        let version: Family
        switch type {
        case 1:
            guard address.count == 4, address[0] != 0, address[0] != 127,
                  address[0] < 224,
                  !(address[0] == 169 && address[1] == 254) else {
                throw ParseError.invalidTarget
            }
            family = AF_INET
            version = .ipv4
        case 4:
            guard address.count == 16, address[0] != 0xff,
                  !(address[0] == 0xfe && (address[1] & 0xc0) == 0x80),
                  address.contains(where: { $0 != 0 }),
                  address != Array(repeating: UInt8(0), count: 15) + [1],
                  !(Array(address.prefix(10)) == Array(repeating: UInt8(0), count: 10)
                    && address[10] == 0xff && address[11] == 0xff) else {
                throw ParseError.invalidTarget
            }
            family = AF_INET6
            version = .ipv6
        default: throw ParseError.invalidTarget
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = address.withUnsafeBytes {
            inet_ntop(family, $0.baseAddress, &buffer, socklen_t(buffer.count))
        }
        guard result != nil else { throw ParseError.invalidTarget }
        return Target(family: version, address: String(cString: buffer))
    }

    static func payloadLength(_ header: [UInt8]) throws -> Int {
        guard header.count == 2 else { throw ParseError.invalidLength }
        let length = Int(header[0]) << 8 | Int(header[1])
        guard length <= maximumPayload else { throw ParseError.invalidLength }
        return length
    }

    // A reply contains status, a big-endian u16 length, and payload. Error
    // replies have zero length. No raw platform errors leave the phone.
    static func response(status: Status, payload: Data = Data()) throws -> Data {
        guard payload.count <= maximumPayload, status == .success || payload.isEmpty else {
            throw ParseError.invalidResponse
        }
        return Data([status.rawValue, UInt8(payload.count >> 8), UInt8(payload.count & 255)] + payload)
    }
}

// One frame may be active at a time. Reject pipelined or oversized data.
final class ExperimentalICMPFrameReader {
    enum Result { case pending, frame(Data), invalid }
    private var bytes: [UInt8] = []
    private var deferred: [UInt8] = []
    private var sending = false
    private(set) var busy = false
    func receive(_ incoming: Data) -> Result {
        if busy {
            guard sending, deferred.count + incoming.count <= ExperimentalICMPCommand.maximumPayload + 2 else { return .invalid }
            deferred.append(contentsOf: incoming)
            return .pending
        }
        guard bytes.count + incoming.count <= ExperimentalICMPCommand.maximumPayload + 2 else { return .invalid }
        bytes.append(contentsOf: incoming)
        guard bytes.count >= 2 else { return .pending }
        guard let length = try? ExperimentalICMPCommand.payloadLength(Array(bytes.prefix(2))) else { return .invalid }
        guard bytes.count <= length + 2 else { return .invalid }
        guard bytes.count == length + 2 else { return .pending }
        busy = true
        let payload = Data(bytes.dropFirst(2))
        bytes.removeAll(keepingCapacity: true)
        return .frame(payload)
    }
    func responsePending() { sending = true }
    @discardableResult
    func finish() -> Result {
        busy = false
        sending = false
        let next = Data(deferred)
        deferred.removeAll(keepingCapacity: true)
        return next.isEmpty ? .pending : receive(next)
    }
}

// All cache operations run on the server queue.
final class ExperimentalICMPCache {
    private var running = false
    private var selected: [ExperimentalICMPCommand.Family: UInt32] = [:]
    func start() { running = true; selected.removeAll() }
    func stop() { running = false; selected.removeAll() }
    func preferred(for family: ExperimentalICMPCommand.Family) -> UInt32? {
        return running ? selected[family] : nil
    }
    func recordSuccess(for family: ExperimentalICMPCommand.Family, index: UInt32) {
        guard running else { return }
        selected[family] = index
    }
    func invalidate(for family: ExperimentalICMPCommand.Family, ifMatching index: UInt32?) {
        guard running, let index = index, selected[family] == index else { return }
        selected[family] = nil
    }
}

// The owner serializes all access. A changed observation gets a new
// generation. Stop and start invalidate all prior snapshots.
final class ExperimentalICMPPathState<Candidate> {
    struct Snapshot {
        let generation: UInt64
        let problem: ExperimentalICMPCommand.Status?
        let candidates: [Candidate]
    }
    private(set) var running = false
    private(set) var generation: UInt64 = 0
    private var lifecycle: UInt64 = 0
    private(set) var snapshot: Snapshot?
    var didUpdate: (() -> Void)?
    @discardableResult
    func start() -> UInt64 {
        generation &+= 1
        lifecycle = generation
        running = true
        snapshot = nil
        return lifecycle
    }
    func stop() {
        generation &+= 1
        lifecycle = generation
        running = false
        snapshot = nil
    }
    @discardableResult
    func update(lifecycle: UInt64, problem: ExperimentalICMPCommand.Status?,
                candidates: [Candidate]) -> Bool {
        guard running && self.lifecycle == lifecycle else { return false }
        // Every monitor event can represent a new cellular path, even when
        // the visible interfaces and their properties are unchanged.
        generation &+= 1
        snapshot = Snapshot(generation: generation, problem: problem, candidates: candidates)
        didUpdate?()
        return true
    }
    func contains(generation: UInt64) -> Bool {
        return running && snapshot?.generation == generation
    }
}

// The selector is owned by one proxy-server lifecycle. It does not log
// target addresses or interface names.
final class ExperimentalICMPSelector {
    private let queue: DispatchQueue
    private let log: (String) -> Void
    private var running = false
    private var generation = UUID()
    private let cache = ExperimentalICMPCache()
    private let path = ExperimentalICMPPathState<NWInterface>()
    private var monitor: NWPathMonitor?
    private var tasks: [UUID: ExperimentalICMPEchoTask] = [:]
    private var preflights: [ExperimentalICMPCommand.Family: ExperimentalICMPEchoTask] = [:]

    init(queue: DispatchQueue, log: @escaping (String) -> Void) {
        self.queue = queue
        self.log = log
        path.didUpdate = { [weak self] in
            guard let self = self else { return }
            self.cache.start()
            Array(self.tasks.values).forEach { $0.pathUpdated() }
        }
    }
    var isRunning: Bool { running }

    func start() {
        guard !running else { return }
        running = true
        cache.start()
        let pathLifecycle = path.start()
        generation = UUID()
        let current = generation
        let monitor = NWPathMonitor(requiredInterfaceType: .cellular)
        self.monitor = monitor
        monitor.pathUpdateHandler = { [weak self] update in
            guard let self = self, self.running, self.generation == current else { return }
            self.updatePath(update, lifecycle: pathLifecycle)
        }
        monitor.start(queue: queue)
        log("Cellular echo selection started.")
        let targets: [(ExperimentalICMPCommand.Family, String)] = [
            (.ipv4, "1.1.1.1"), (.ipv6, "2606:4700:4700::1111")
        ]
        for (family, address) in targets {
            let task = ExperimentalICMPEchoTask(queue: queue, selector: self)
            preflights[family] = task
            task.start(target: .init(family: family, address: address), payload: Data()) { [weak self] status, _ in
                guard let self = self, self.running, self.generation == current else { return }
                self.preflights[family] = nil
                let label = family == .ipv4 ? "IPv4" : "IPv6"
                self.log(status == .success ? "\(label) cellular echo selection ready." : "\(label) cellular echo selection unavailable.")
            }
        }
    }

    func stop() {
        running = false
        generation = UUID()
        monitor?.cancel()
        monitor = nil
        path.stop()
        let active = Array(tasks.values)
        tasks.removeAll()
        preflights.removeAll()
        cache.stop()
        active.forEach { $0.cancel() }
    }

    func preferred(for family: ExperimentalICMPCommand.Family) -> UInt32? {
        return cache.preferred(for: family)
    }
    func recordSuccess(for family: ExperimentalICMPCommand.Family, index: UInt32) {
        cache.recordSuccess(for: family, index: index)
    }
    func invalidate(for family: ExperimentalICMPCommand.Family, ifMatching index: UInt32?) {
        cache.invalidate(for: family, ifMatching: index)
    }
    func register(_ task: ExperimentalICMPEchoTask) {
        guard running else { task.cancel(); return }
        tasks[task.id] = task
        task.pathUpdated()
    }
    func unregister(_ task: ExperimentalICMPEchoTask) { tasks[task.id] = nil }
    func pathIsCurrent(_ revision: UInt64) -> Bool { path.contains(generation: revision) }
    func currentPath(for family: ExperimentalICMPCommand.Family)
        -> (UInt64, ExperimentalICMPCommand.Status?, [NWInterface])? {
        guard let snapshot = path.snapshot else { return nil }
        let preferred = cache.preferred(for: family)
        let interfaces = ExperimentalICMPSelection.ordered(snapshot.candidates, preferred: preferred) { interface in
            guard let index = UInt32(exactly: interface.index),
                  ExperimentalICMPSelection.validInterface(isCellular: interface.type == .cellular,
                    index: index, currentIndex: if_nametoindex(interface.name)) else { return nil }
            return index
        }
        if let preferred = preferred, !interfaces.contains(where: { UInt32(exactly: $0.index) == preferred }) {
            cache.invalidate(for: family, ifMatching: preferred)
        }
        let problem = snapshot.problem ?? ExperimentalICMPCommand.pathProblem(
            satisfied: true, usesCellular: true, cellularCount: interfaces.count)
        return (snapshot.generation, problem, interfaces)
    }
    private func updatePath(_ update: NWPath, lifecycle: UInt64) {
        let interfaces = ExperimentalICMPSelection.ordered(update.availableInterfaces, preferred: nil) { interface in
            guard let index = UInt32(exactly: interface.index),
                  ExperimentalICMPSelection.validInterface(isCellular: interface.type == .cellular,
                    index: index, currentIndex: if_nametoindex(interface.name)) else { return nil }
            return index
        }
        let problem = ExperimentalICMPCommand.pathProblem(satisfied: update.status == .satisfied,
            usesCellular: update.usesInterfaceType(.cellular), cellularCount: interfaces.count)
        path.update(lifecycle: lifecycle, problem: problem, candidates: interfaces)
    }
}

// Select only validated candidates. Preserve path order unless the current
// path still contains a previously successful interface.
enum ExperimentalICMPSelection {
    static func validInterface(isCellular: Bool, index: UInt32, currentIndex: UInt32) -> Bool {
        return isCellular && index > 0 && index == currentIndex
    }
    static func validPin(expected: UInt32, observed: UInt32, length: Int) -> Bool {
        return expected > 0 && expected == observed && length == MemoryLayout<UInt32>.size
    }
    static func ordered<T>(_ candidates: [T], preferred: UInt32?,
                           index: (T) -> UInt32?) -> [T] {
        var seen = Set<UInt32>()
        var result: [(UInt32, T)] = []
        for candidate in candidates {
            guard let value = index(candidate), value > 0, seen.insert(value).inserted else { continue }
            result.append((value, candidate))
        }
        if let preferred = preferred, let position = result.firstIndex(where: { $0.0 == preferred }) {
            let first = result.remove(at: position)
            result.insert(first, at: 0)
        }
        return result.map { $0.1 }
    }
}

// The callback must finish within its supplied socket timeout. The caller
// also installs a total deadline that cancels any active socket.
enum ExperimentalICMPRetry {
    enum Result<T> { case success(Data, T), timeout, failed, busy, cancelled }
    static func run<T>(_ candidates: [T], deadline: UInt64,
                       now: () -> UInt64, cancelled: () -> Bool,
                       attempt: (T, TimeInterval) throws -> Data) -> Result<T> {
        var timedOut = false
        for candidate in candidates.prefix(4) {
            if cancelled() { return .cancelled }
            let current = now()
            guard current < deadline else { return .timeout }
            let seconds = min(1.2, Double(deadline - current) / 1_000_000_000)
            guard seconds >= 0.01 else { return .timeout }
            do {
                let data = try attempt(candidate, seconds)
                if cancelled() { return .cancelled }
                guard now() < deadline else { return .timeout }
                return .success(data, candidate)
            } catch CellularICMPEcho.EchoError.cancelled {
                return .cancelled
            } catch CellularICMPEcho.EchoError.busy {
                return .busy
            } catch CellularICMPEcho.EchoError.timeout {
                timedOut = true
            } catch {
                continue
            }
        }
        if cancelled() { return .cancelled }
        return timedOut ? .timeout : .failed
    }
}

// One permit stays held until a background attempt has finished.
final class ExperimentalICMPEchoPermit {
    private static let limitLock = NSLock()
    private static var activeTasks = 0
    private static let maximumTasks = 8
    private(set) var held = false
    private var workPending = false

    func acquire() -> Bool {
        Self.limitLock.lock()
        defer { Self.limitLock.unlock() }
        guard !held, Self.activeTasks < Self.maximumTasks else { return false }
        Self.activeTasks += 1
        held = true
        return true
    }
    func beginWork() { workPending = true }
    func cancel() { if !workPending { release() } }
    func workFinished() { workPending = false; release() }
    func release() {
        Self.limitLock.lock()
        defer { Self.limitLock.unlock() }
        guard held else { return }
        Self.activeTasks -= 1
        held = false
    }
    deinit { release() }
}

// Keep only aggregate durations. Do not store targets, payloads, or tokens.
final class ExperimentalICMPTiming {
    struct Sample {
        let total: UInt64
        let setup: UInt64
        let wait: UInt64
        var other: UInt64 { total > setup + wait ? total - setup - wait : 0 }
    }
    private let lock = NSLock()
    private var setup: UInt64 = 0
    private var wait: UInt64 = 0
    func attempt(setup: UInt64, wait: UInt64) {
        lock.lock(); defer { lock.unlock() }
        self.setup = self.setup.addingReportingOverflow(setup).overflow ? UInt64.max : self.setup + setup
        self.wait = self.wait.addingReportingOverflow(wait).overflow ? UInt64.max : self.wait + wait
    }
    func sample(total: UInt64) -> Sample {
        lock.lock(); defer { lock.unlock() }
        // Bound components by total to avoid overflow and misleading averages.
        let boundedSetup = min(setup, total)
        let boundedWait = min(wait, total - boundedSetup)
        return Sample(total: total, setup: boundedSetup, wait: boundedWait)
    }
}
final class ExperimentalICMPTimingAggregate {
    private(set) var count: UInt64 = 0
    private var total: UInt64 = 0
    private var setup: UInt64 = 0
    private var wait: UInt64 = 0
    func reset() { count = 0; total = 0; setup = 0; wait = 0 }
    func add(_ sample: ExperimentalICMPTiming.Sample) -> String? {
        // Reset periodically so counters cannot grow without bound.
        if count == 1_000_000 { reset() }
        count += 1
        total += sample.total / 1_000_000
        setup += sample.setup / 1_000_000
        wait += sample.wait / 1_000_000
        guard count % 5 == 0 else { return nil }
        return "ICMP averages (\(count) replies): total \(total / count) ms, socket setup \(setup / count) ms, send/receive wait \(wait / count) ms, other \((total - setup - wait) / count) ms."
    }
}

final class ExperimentalICMPEchoTask {
    let id = UUID()
    private let queue: DispatchQueue
    private weak var selector: ExperimentalICMPSelector?
    private var timeout: DispatchWorkItem?
    private var deadlineTimer: DispatchWorkItem?
    private var started = false
    private var finished = false
    private var workStarted = false
    private var activeRevision: UInt64?
    private var onPathUpdate: (() -> Void)?
    private var triedPreferred: UInt32?
    private var lastPathProblem: ExperimentalICMPCommand.Status = .pathTimeout
    private let permit = ExperimentalICMPEchoPermit()
    private let cancellation = ICMPEchoCancellation()
    private let timing = ExperimentalICMPTiming()
    private let onTiming: ((ExperimentalICMPTiming.Sample) -> Void)?
    private var startedAt: UInt64 = 0

    init(queue: DispatchQueue, selector: ExperimentalICMPSelector? = nil,
         onTiming: ((ExperimentalICMPTiming.Sample) -> Void)? = nil) {
        self.queue = queue
        self.selector = selector
        self.onTiming = onTiming
    }

    deinit {
        timeout?.cancel()
        deadlineTimer?.cancel()
        permit.cancel()
    }

    func start(target: ExperimentalICMPCommand.Target, payload: Data,
               completion: @escaping (ExperimentalICMPCommand.Status, Data) -> Void) {
        let submittedAt = DispatchTime.now().uptimeNanoseconds
        queue.async { [self] in
            guard !self.started, !self.finished else { return }
            self.startedAt = submittedAt
            self.started = true
            guard payload.count <= ExperimentalICMPCommand.maximumPayload else {
                self.finish(.failed, Data(), completion: completion)
                return
            }
            guard self.permit.acquire() else {
                self.finish(.busy, Data(), completion: completion)
                return
            }

            // Leave time for the target device's eight-second setup and response.
            let deadline = DispatchTime.now().uptimeNanoseconds + 5_500_000_000
            let totalTimeout = DispatchWorkItem { [weak self] in
                guard let self = self, !self.finished, !self.cancellation.isCancelled else { return }
                self.selector?.invalidate(for: target.family, ifMatching: self.triedPreferred)
                self.cancellation.cancel()
                self.finish(.timeout, Data(), allowCancelled: true, completion: completion)
            }
            self.deadlineTimer = totalTimeout
            self.queue.asyncAfter(deadline: .now() + 5.5, execute: totalTimeout)

            let timeout = DispatchWorkItem { [weak self] in
                guard let self = self else { return }
                self.finish(self.lastPathProblem, Data(), completion: completion)
            }
            self.timeout = timeout
            self.queue.asyncAfter(deadline: .now() + 2, execute: timeout)
            guard let selector = self.selector, selector.isRunning else {
                self.finish(.noCellular, Data(), completion: completion)
                return
            }
            self.onPathUpdate = { [weak self] in
                guard let self = self, !self.finished, let selector = self.selector else { return }
                guard !self.cancellation.isCancelled else { return }
                if self.workStarted {
                    if let revision = self.activeRevision, !selector.pathIsCurrent(revision) {
                        self.cancellation.cancel()
                        self.finish(.failed, Data(), allowCancelled: true, completion: completion)
                    }
                    return
                }
                guard let (revision, problem, interfaces) = selector.currentPath(for: target.family) else { return }
                let preferred = selector.preferred(for: target.family)
                if let problem = problem {
                    self.lastPathProblem = problem
                    if problem == .ambiguousCellular {
                        self.finish(problem, Data(), completion: completion)
                    }
                    return
                }
                guard !interfaces.isEmpty else { return }
                self.workStarted = true
                self.activeRevision = revision
                self.triedPreferred = preferred
                self.timeout?.cancel()
                self.timeout = nil
                self.permit.beginWork()
                DispatchQueue.global(qos: .utility).async {
                    let outcome = ExperimentalICMPRetry.run(interfaces, deadline: deadline,
                        now: { DispatchTime.now().uptimeNanoseconds },
                        cancelled: { self.cancellation.isCancelled }) { interface, seconds in
                        switch target.family {
                        case .ipv4:
                            return try CellularICMPEcho.send(address: target.address, payload: payload, interface: interface,
                                                             cancellation: self.cancellation, timeoutSeconds: seconds,
                                                             timing: { self.timing.attempt(setup: $0, wait: $1) })
                        case .ipv6:
                            return try CellularICMPEcho.sendIPv6(address: target.address, payload: payload, interface: interface,
                                                                 cancellation: self.cancellation, timeoutSeconds: seconds,
                                                             timing: { self.timing.attempt(setup: $0, wait: $1) })
                        }
                    }
                    self.queue.async {
                        self.permit.workFinished()
                        if self.finished || self.cancellation.isCancelled { return }
                        guard self.selector?.pathIsCurrent(revision) == true else {
                            self.finish(.failed, Data(), completion: completion)
                            return
                        }
                        switch outcome {
                        case .success(let result, let interface):
                            if let index = UInt32(exactly: interface.index) {
                                self.selector?.recordSuccess(for: target.family, index: index)
                            }
                            self.finish(.success, result, completion: completion)
                        case .timeout:
                            self.selector?.invalidate(for: target.family, ifMatching: preferred)
                            self.finish(.timeout, Data(), completion: completion)
                        case .busy:
                            self.finish(.busy, Data(), completion: completion)
                        case .failed:
                            self.selector?.invalidate(for: target.family, ifMatching: preferred)
                            self.finish(.failed, Data(), completion: completion)
                        case .cancelled:
                            self.finish(.failed, Data(), completion: completion)
                        }
                    }
                }
            }
            selector.register(self)
        }
    }

    func pathUpdated() { onPathUpdate?() }

    func cancel() {
        cancellation.cancel()
        queue.async {
            guard !self.finished else { return }
            self.finished = true
            self.timeout?.cancel()
            self.deadlineTimer?.cancel()
            self.selector?.unregister(self)
            self.onPathUpdate = nil
            self.permit.cancel()
        }
    }

    private func finish(_ status: ExperimentalICMPCommand.Status, _ payload: Data,
                        allowCancelled: Bool = false,
                        completion: (ExperimentalICMPCommand.Status, Data) -> Void) {
        guard !finished else { return }
        let cancelled = cancellation.isCancelled
        finished = true
        timeout?.cancel()
        deadlineTimer?.cancel()
        selector?.unregister(self)
        onPathUpdate = nil
        permit.cancel()
        if status == .success && startedAt != 0 {
            onTiming?(timing.sample(total: DispatchTime.now().uptimeNanoseconds - startedAt))
        }
        if !cancelled || allowCancelled { completion(status, payload) }
    }
}
