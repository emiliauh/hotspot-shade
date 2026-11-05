import Foundation

// Small pure helpers for one session's data flow. This file uses Foundation
// only. The tests use the types without a socket.
//
// `DatagramQueue` keeps the UDP datagrams of one direction in order. The proxy
// keeps one queue per direction per session and one writer per queue, so the
// datagrams leave in order. When the queue drops the oldest datagram, the flow
// stays open and the remaining datagrams go out in order.
// The queue never grows over `capacity`.
//
// `RelayHalfClose` keeps the half-close state of one TCP relay. A clean EOF on
// one side must not close the opposite direction.

/// A first-in, first-out datagram queue with a fixed capacity.
struct DatagramQueue: Equatable {
    /// The most datagrams one direction keeps. 64 datagrams of 1472 bytes are
    /// about 94 KB, so a full queue stays small.
    static let maximumCapacity = 64

    let capacity: Int
    private var storage: [Data] = []
    private var head = 0
    /// Datagrams dropped because the queue was full.
    private(set) var dropped = 0
    /// The largest queue length seen.
    private(set) var peak = 0
    /// The datagrams added, including the dropped ones.
    private(set) var added = 0
    /// The datagrams returned by `pop`.
    private(set) var sent = 0

    init(capacity: Int = DatagramQueue.maximumCapacity) {
        precondition(capacity > 0, "The queue needs room for one datagram.")
        precondition(capacity <= Self.maximumCapacity, "The queue stays small.")
        self.capacity = capacity
    }

    /// The datagrams that wait for the writer.
    var count: Int { storage.count - head }
    var isEmpty: Bool { count == 0 }

    /// Add one datagram. Return true when the queue dropped the oldest one.
    @discardableResult
    mutating func push(_ datagram: Data) -> Bool {
        var didDrop = false
        if count >= capacity {
            head += 1
            dropped += 1
            didDrop = true
        }
        storage.append(datagram)
        added += 1
        peak = max(peak, count)
        compactIfNeeded()
        return didDrop
    }

    /// Return the oldest datagram, or nil when the queue is empty.
    mutating func pop() -> Data? {
        guard head < storage.count else {
            storage.removeAll(keepingCapacity: true)
            head = 0
            return nil
        }
        let value = storage[head]
        head += 1
        sent += 1
        compactIfNeeded()
        return value
    }

    /// The writer stopped. Drop what waits.
    mutating func removeAll() {
        storage.removeAll(keepingCapacity: true)
        head = 0
    }

    private mutating func compactIfNeeded() {
        guard head > 0, head >= storage.count / 2, head >= 32 else { return }
        storage.removeFirst(head)
        head = 0
    }
}

/// The half-close state of one TCP relay. The relay has two directions. A
/// clean EOF on one side sends a write-side FIN to the other side. The
/// opposite direction stays open until it also finishes. Both connections
/// close only after both sides sent a clean EOF.
struct RelayHalfClose: Equatable {
    /// One end of the relay.
    enum Side: Equatable {
        /// The connection from the target device.
        case client
        /// The cellular connection to the destination.
        case destination

        /// The other end.
        var other: Side { self == .client ? .destination : .client }
    }

    /// The work for one receive event. The caller does the steps in order.
    enum Step: Equatable {
        /// No data and no EOF. Read the same side again.
        case readAgain
        /// Forward the data. Then read the same side again.
        case forward
        /// Forward the final data. Then send a write-side FIN to the other
        /// side.
        case forwardThenFinish
        /// Send a write-side FIN to the other side. There is no data.
        case finish
        /// This side already sent a clean EOF. Ignore the event.
        case ignore
    }

    /// True after a clean EOF from the target device.
    private(set) var clientReadFinished = false
    /// True after a clean EOF from the destination.
    private(set) var destinationReadFinished = false
    /// True after the stack processed the write-side FIN to the target device.
    private(set) var clientWriteFinished = false
    /// True after the stack processed the write-side FIN to the destination.
    private(set) var destinationWriteFinished = false

    /// True after a clean EOF from both sides.
    var bothReadFinished: Bool { clientReadFinished && destinationReadFinished }

    /// True after both sides sent a clean EOF and both write-side FINs left
    /// the stack. Close both connections only at this point. A close before
    /// the second FIN leaves the stack can replace it with a reset.
    var canClose: Bool {
        bothReadFinished && clientWriteFinished && destinationWriteFinished
    }

    /// True after a clean EOF from this side.
    func isReadFinished(_ side: Side) -> Bool {
        switch side {
        case .client: return clientReadFinished
        case .destination: return destinationReadFinished
        }
    }

    /// Record one receive event for `side`. Return the work for the caller.
    /// An EOF on one side keeps the opposite direction open.
    mutating func receive(hasData: Bool, eof: Bool, side: Side) -> Step {
        guard !isReadFinished(side) else { return .ignore }
        guard eof else { return hasData ? .forward : .readAgain }
        switch side {
        case .client: clientReadFinished = true
        case .destination: destinationReadFinished = true
        }
        return hasData ? .forwardThenFinish : .finish
    }

    /// Record one write-side FIN that the stack processed for `side`.
    mutating func writeFinished(_ side: Side) {
        switch side {
        case .client: clientWriteFinished = true
        case .destination: destinationWriteFinished = true
        }
    }
}
