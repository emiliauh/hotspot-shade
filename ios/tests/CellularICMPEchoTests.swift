import Foundation
import Darwin

@main
enum CellularICMPEchoTests {
    static func main() throws {
        let nonce = Array(UInt8(0)...UInt8(15))
        let reply: [UInt8] = [0, 0, 0xb1, 0xb0, 0, 1, 0, 3] + nonce + [10, 11, 12]
        let payload = try CellularICMPEcho.validateReply(reply, sequence: 3,
                                                          nonce: nonce, payloadSize: 3)
        precondition(payload == Data([10, 11, 12]))
        var corrupt = reply
        corrupt[corrupt.count - 1] ^= 1
        precondition((try? CellularICMPEcho.validateReply(corrupt, sequence: 3,
                                                           nonce: nonce, payloadSize: 3)) == nil)
        precondition((try? CellularICMPEcho.validateReply(reply, sequence: 4,
                                                           nonce: nonce, payloadSize: 3)) == nil)
        precondition((try? CellularICMPEcho.validateReply(Array(reply.dropLast()), sequence: 3,
                                                           nonce: nonce, payloadSize: 3)) == nil)
        precondition((try? CellularICMPEcho.validateReply(reply, sequence: 3,
                                                           nonce: Array(repeating: 255, count: 16), payloadSize: 3)) == nil)
        let reply6: [UInt8] = [129, 0, 0, 0, 0, 1, 0, 3] + nonce + [10, 11, 12]
        let payload6 = try CellularICMPEcho.validateIPv6Reply(reply6, sequence: 3,
                                                              nonce: nonce, payloadSize: 3)
        precondition(payload6 == Data([10, 11, 12]))
        var wrongType = reply6
        wrongType[0] = 128
        precondition((try? CellularICMPEcho.validateIPv6Reply(wrongType, sequence: 3,
                                                              nonce: nonce, payloadSize: 3)) == nil)
        precondition((try? CellularICMPEcho.validateIPv6Reply(reply6, sequence: 4,
                                                              nonce: nonce, payloadSize: 3)) == nil)
        precondition((try? CellularICMPEcho.validateIPv6Reply(Array(reply6.dropLast()), sequence: 3,
                                                              nonce: nonce, payloadSize: 3)) == nil)
        precondition((try? CellularICMPEcho.validateIPv6Reply(reply6, sequence: 3,
                                                              nonce: Array(repeating: 255, count: 16), payloadSize: 3)) == nil)
        let target4 = try ExperimentalICMPCommand.target(type: 1, address: [1, 1, 1, 1], port: 0)
        precondition(target4.address == "1.1.1.1")
        precondition(!ExperimentalICMPCommand.isPermitted(command: 0x81, authenticated: false))
        precondition(ExperimentalICMPCommand.isPermitted(command: 0x81, authenticated: true))
        precondition(!ExperimentalICMPCommand.isPermitted(command: 0x82, authenticated: false))
        precondition(ExperimentalICMPCommand.isPermitted(command: 0x82, authenticated: true))
        precondition(!ExperimentalICMPCommand.isPermitted(command: 0x80, authenticated: true))
        // EOF closes the session whether the final input is complete or partial.
        precondition(ExperimentalICMPCommand.persistentShouldClose(eof: true, failed: false))
        precondition(ExperimentalICMPCommand.persistentShouldClose(eof: false, failed: true))
        precondition(!ExperimentalICMPCommand.persistentShouldClose(eof: false, failed: false))
        let frames = ExperimentalICMPFrameReader()
        if case .pending = frames.receive(Data([0])) {} else { preconditionFailure("Expected partial header.") }
        if case .pending = frames.receive(Data([2, 7])) {} else { preconditionFailure("Expected partial payload.") }
        if case .frame(let payload) = frames.receive(Data([8])) { precondition(payload == Data([7, 8])) }
        else { preconditionFailure("Expected complete frame.") }
        if case .invalid = frames.receive(Data([0, 0])) {} else { preconditionFailure("Expected busy rejection.") }
        frames.finish()
        if case .frame(let payload) = frames.receive(Data([0, 0])) { precondition(payload.isEmpty) }
        else { preconditionFailure("Expected empty frame.") }
        frames.finish()
        if case .invalid = frames.receive(Data([0, 0, 0])) {} else { preconditionFailure("Expected pipelining rejection.") }
        let earlyNext = ExperimentalICMPFrameReader()
        if case .frame = earlyNext.receive(Data([0, 0])) {} else { preconditionFailure("Expected first frame.") }
        earlyNext.responsePending()
        if case .pending = earlyNext.receive(Data([0, 1, 42])) {} else { preconditionFailure("Expected bounded deferred frame.") }
        if case .frame(let payload) = earlyNext.finish() { precondition(payload == Data([42])) }
        else { preconditionFailure("Expected deferred frame after send completion.") }
        let deferredLimit = ExperimentalICMPFrameReader()
        if case .frame = deferredLimit.receive(Data([0, 0])) {} else { preconditionFailure("Expected first frame.") }
        deferredLimit.responsePending()
        if case .invalid = deferredLimit.receive(Data(repeating: 0, count: 1203)) {} else { preconditionFailure("Expected deferred limit.") }
        let oversized = ExperimentalICMPFrameReader()
        if case .invalid = oversized.receive(Data([4, 177])) {} else { preconditionFailure("Expected oversized rejection.") }
        let maximum = ExperimentalICMPFrameReader()
        if case .frame(let payload) = maximum.receive(Data([4, 176] + Array(repeating: UInt8(9), count: 1200))) {
            precondition(payload.count == 1200)
        } else { preconditionFailure("Expected maximum payload.") }
        precondition(ExperimentalICMPCommand.shouldCancel(clientDataCount: 0, eof: true, failed: false))
        precondition(ExperimentalICMPCommand.shouldCancel(clientDataCount: 0, eof: false, failed: true))
        precondition(ExperimentalICMPCommand.shouldCancel(clientDataCount: 1, eof: false, failed: false))
        precondition(!ExperimentalICMPCommand.shouldCancel(clientDataCount: 0, eof: false, failed: false))
        let target6 = try ExperimentalICMPCommand.target(type: 4,
            address: [0x20, 1, 0x0d, 0xb8] + Array(repeating: 0, count: 11) + [1], port: 0)
        precondition(target6.family == .ipv6)
        precondition((try? ExperimentalICMPCommand.target(type: 1, address: [127, 0, 0, 1], port: 0)) == nil)
        precondition((try? ExperimentalICMPCommand.target(type: 1, address: [1, 1, 1, 1], port: 1)) == nil)
        precondition((try? ExperimentalICMPCommand.target(type: 3, address: [1, 1, 1, 1], port: 0)) == nil)
        precondition((try? ExperimentalICMPCommand.target(type: 4,
            address: Array(repeating: 0, count: 10) + [255, 255, 127, 0, 0, 1], port: 0)) == nil)
        let limit = try ExperimentalICMPCommand.payloadLength([0x04, 0xb0])
        precondition(limit == 1200)
        precondition((try? ExperimentalICMPCommand.payloadLength([0x04, 0xb1])) == nil)
        precondition((try? ExperimentalICMPCommand.payloadLength([0])) == nil)
        let ok = try ExperimentalICMPCommand.response(status: .success, payload: Data([10, 11, 12]))
        precondition(ok == Data([0, 0, 3, 10, 11, 12]))
        let timedOut = try ExperimentalICMPCommand.response(status: .timeout)
        precondition(timedOut == Data([3, 0, 0]))
        precondition((try? ExperimentalICMPCommand.response(status: .failed, payload: Data([1]))) == nil)
        precondition(ExperimentalICMPCommand.pathProblem(satisfied: false, usesCellular: false, cellularCount: 0) == .pathUnsatisfied)
        precondition(ExperimentalICMPCommand.pathProblem(satisfied: true, usesCellular: false, cellularCount: 1) == .pathNotCellular)
        precondition(ExperimentalICMPCommand.pathProblem(satisfied: true, usesCellular: true, cellularCount: 0) == .noCellularInterface)
        precondition(ExperimentalICMPCommand.pathProblem(satisfied: true, usesCellular: false, cellularCount: 0) == .noCellularInterface)
        precondition(ExperimentalICMPCommand.pathProblem(satisfied: true, usesCellular: true, cellularCount: 2) == nil)
        precondition(ExperimentalICMPCommand.pathProblem(satisfied: true, usesCellular: false, cellularCount: 2) == .pathNotCellular)
        precondition(ExperimentalICMPCommand.pathProblem(satisfied: true, usesCellular: true, cellularCount: 5) == .ambiguousCellular)
        precondition(ExperimentalICMPCommand.pathProblem(satisfied: true, usesCellular: true, cellularCount: 1) == nil)
        for (status, code): (ExperimentalICMPCommand.Status, UInt8) in [(.pathTimeout, 5), (.pathUnsatisfied, 6),
            (.pathNotCellular, 7), (.noCellularInterface, 8), (.ambiguousCellular, 9)] {
            let frame = try ExperimentalICMPCommand.response(status: status)
            precondition(frame == Data([code, 0, 0]))
        }
        precondition(ExperimentalICMPSelection.validInterface(isCellular: true, index: 7, currentIndex: 7))
        precondition(!ExperimentalICMPSelection.validInterface(isCellular: false, index: 7, currentIndex: 7))
        precondition(!ExperimentalICMPSelection.validInterface(isCellular: true, index: 7, currentIndex: 8))
        precondition(ExperimentalICMPSelection.validPin(expected: 7, observed: 7, length: 4))
        precondition(!ExperimentalICMPSelection.validPin(expected: 7, observed: 8, length: 4))
        precondition(!ExperimentalICMPSelection.validPin(expected: 7, observed: 7, length: 2))
        let ordered = ExperimentalICMPSelection.ordered([1, 2, 2, 3], preferred: 2) { UInt32($0) }
        precondition(ordered == [2, 1, 3])
        let filtered = ExperimentalICMPSelection.ordered([1, 2, 3], preferred: 2) { $0 == 2 ? nil : UInt32($0) }
        precondition(filtered == [1, 3])
        let cache = ExperimentalICMPCache()
        cache.start()
        cache.recordSuccess(for: .ipv4, index: 1)
        cache.recordSuccess(for: .ipv6, index: 2)
        precondition(cache.preferred(for: .ipv4) == 1 && cache.preferred(for: .ipv6) == 2)
        cache.invalidate(for: .ipv4, ifMatching: 2)
        precondition(cache.preferred(for: .ipv4) == 1)
        cache.invalidate(for: .ipv4, ifMatching: 1)
        precondition(cache.preferred(for: .ipv4) == nil && cache.preferred(for: .ipv6) == 2)
        cache.stop()
        cache.start()
        precondition(cache.preferred(for: .ipv6) == nil)

        // Simulate one monitor over two proxy lifecycles. Old callbacks must
        // not publish a snapshot or make an earlier generation current.
        let path = ExperimentalICMPPathState<Int>()
        let firstLifecycle = path.start()
        precondition(path.update(lifecycle: firstLifecycle, problem: nil, candidates: [1, 2]))
        let originalGeneration = path.snapshot!.generation
        precondition(path.contains(generation: originalGeneration))
        precondition(path.update(lifecycle: firstLifecycle, problem: nil, candidates: [1, 2]))
        precondition(!path.contains(generation: originalGeneration))
        let firstGeneration = path.snapshot!.generation
        let staleWork = ICMPEchoCancellation()
        var notifications = 0
        path.didUpdate = {
            notifications += 1
            if !path.contains(generation: firstGeneration) { staleWork.cancel() }
        }
        precondition(path.update(lifecycle: firstLifecycle, problem: nil, candidates: [2]))
        precondition(notifications == 1 && staleWork.isCancelled)
        var staleCreated = false
        precondition((try? staleWork.open { staleCreated = true; return -1 }) == nil && !staleCreated)
        path.stop()
        precondition(!path.contains(generation: firstGeneration))
        let secondLifecycle = path.start()
        precondition(!path.update(lifecycle: firstLifecycle, problem: nil, candidates: [7]))
        precondition(path.snapshot == nil && notifications == 1)
        precondition(path.update(lifecycle: secondLifecycle, problem: nil, candidates: [3]))
        precondition(path.snapshot?.candidates == [3])

        var attempts: [Int] = []
        let selection = ExperimentalICMPRetry.run([1, 2, 3], deadline: 5_000_000_000,
            now: { 0 }, cancelled: { false }) { candidate, _ in
                attempts.append(candidate)
                if candidate == 1 { throw CellularICMPEcho.EchoError.pinFailed }
                return Data([8])
            }
        if case .success(let bytes, let candidate) = selection {
            precondition(bytes == Data([8]) && candidate == 2 && attempts == [1, 2])
        } else { preconditionFailure("Expected the second interface to succeed.") }
        let allFailed = ExperimentalICMPRetry.run([1, 2], deadline: 5_000_000_000,
            now: { 0 }, cancelled: { false }) { _, _ -> Data in throw CellularICMPEcho.EchoError.pinFailed }
        if case .failed = allFailed {} else { preconditionFailure("Expected all attempts to fail.") }
        var stopRetry = false
        var retryCount = 0
        let cancelledRetry = ExperimentalICMPRetry.run([1, 2], deadline: 5_000_000_000,
            now: { 0 }, cancelled: { stopRetry }) { _, _ -> Data in
                retryCount += 1
                stopRetry = true
                throw CellularICMPEcho.EchoError.pinFailed
            }
        if case .cancelled = cancelledRetry { precondition(retryCount == 1) }
        else { preconditionFailure("Expected cancellation before the next attempt.") }
        var clock: UInt64 = 0
        let expired = ExperimentalICMPRetry.run([1, 2], deadline: 1_000_000_000,
            now: { clock }, cancelled: { false }) { _, _ -> Data in
                clock = 2_000_000_000
                return Data([9])
            }
        if case .timeout = expired {} else { preconditionFailure("Expected the total deadline to win.") }
        let queued = ICMPEchoCancellation()
        queued.cancel()
        var created = false
        let queuedDescriptor = try? queued.open { created = true; return -1 }
        precondition(queuedDescriptor == nil && !created)
        let pendingPermit = ExperimentalICMPEchoPermit()
        precondition(pendingPermit.acquire())
        pendingPermit.beginWork()
        pendingPermit.cancel()
        precondition(pendingPermit.held)
        pendingPermit.workFinished()
        precondition(!pendingPermit.held)
        let idlePermit = ExperimentalICMPEchoPermit()
        precondition(idlePermit.acquire())
        idlePermit.cancel()
        precondition(!idlePermit.held)
        let slots = (0..<8).map { _ in ExperimentalICMPEchoPermit() }
        for slot in slots { precondition(slot.acquire()) }
        slots[0].beginWork()
        slots[0].cancel()
        let waitingPermit = ExperimentalICMPEchoPermit()
        precondition(!waitingPermit.acquire())
        slots[0].workFinished()
        precondition(waitingPermit.acquire())
        waitingPermit.release()
        for slot in slots { slot.release() }
        var pair = [Int32](repeating: -1, count: 2)
        precondition(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        var unrelated = [Int32](repeating: -1, count: 2)
        precondition(socketpair(AF_UNIX, SOCK_STREAM, 0, &unrelated) == 0)
        let inFlight = ICMPEchoCancellation()
        let tracked = try inFlight.open { pair[0] }
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            var byte: UInt8 = 0
            _ = recv(tracked, &byte, 1, 0)
            done.signal()
        }
        inFlight.cancel()
        precondition(done.wait(timeout: .now() + 2) == .success)
        precondition((try? inFlight.send(tracked, packet: [1])) == nil)
        var unrelatedByte: UInt8 = 42
        precondition(Darwin.send(unrelated[0], &unrelatedByte, 1, 0) == 1)
        unrelatedByte = 0
        precondition(recv(unrelated[1], &unrelatedByte, 1, 0) == 1 && unrelatedByte == 42)
        inFlight.close(tracked)
        close(pair[1])
        close(unrelated[0])
        close(unrelated[1])
        let timing = ExperimentalICMPTiming()
        timing.attempt(setup: 2_000_000, wait: 10_000_000)
        timing.attempt(setup: 1_000_000, wait: 3_000_000)
        let sample = timing.sample(total: 20_000_000)
        precondition(sample.setup == 3_000_000 && sample.wait == 13_000_000 && sample.other == 4_000_000)
        let aggregate = ExperimentalICMPTimingAggregate()
        for _ in 0..<4 { precondition(aggregate.add(sample) == nil) }
        let line = aggregate.add(sample)
        precondition(line == "ICMP averages (5 replies): total 20 ms, socket setup 3 ms, send/receive wait 13 ms, other 4 ms.")
        aggregate.reset()
        precondition(aggregate.count == 0 && aggregate.add(sample) == nil)
        let bounded = timing.sample(total: 1)
        precondition(bounded.setup + bounded.wait <= bounded.total)
        print("ICMP echo reply validation passed")
    }
}
