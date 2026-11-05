import Foundation

@main
struct DatagramQueueTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func datagram(_ value: UInt8) -> Data { Data([value]) }

    static func main() {
        // The cap stays small.
        check(DatagramQueue.maximumCapacity == 64, "the maximum capacity is 64")
        check(DatagramQueue().capacity == 64, "the default capacity")

        // Order: first in, first out.
        var queue = DatagramQueue()
        check(queue.isEmpty && queue.count == 0, "an empty queue")
        check(queue.pop() == nil, "pop on an empty queue")
        for value in 1...5 {
            check(queue.push(datagram(UInt8(value))) == false, "a push under the cap drops nothing")
        }
        check(queue.count == 5 && !queue.isEmpty, "five datagrams wait")
        check(queue.peak == 5, "the peak is five")
        check(queue.added == 5 && queue.dropped == 0 && queue.sent == 0, "counts after push")
        for value in 1...5 {
            check(queue.pop() == datagram(UInt8(value)), "order at \(value)")
        }
        check(queue.sent == 5, "five sent")
        check(queue.isEmpty, "the queue is empty again")

        // The cap: drop the oldest, keep the newest.
        var capped = DatagramQueue(capacity: 4)
        for value in 1...4 {
            check(capped.push(datagram(UInt8(value))) == false, "a push to the cap drops nothing")
        }
        check(capped.push(datagram(5)) == true, "a push over the cap drops the oldest")
        check(capped.count == 4, "the queue stays at the cap")
        check(capped.dropped == 1, "one drop")
        check(capped.added == 5, "five added")
        check(capped.peak == 4, "the peak is the cap")
        check(capped.pop() == datagram(2), "the oldest datagram is gone")
        check(capped.pop() == datagram(3), "then the next one")
        check(capped.pop() == datagram(4), "then the fourth")
        check(capped.pop() == datagram(5), "the newest one is last")
        check(capped.pop() == nil, "the queue is empty")

        // A full queue with many pushes keeps the last four and counts each drop.
        var flood = DatagramQueue(capacity: 4)
        for value in 1...10 { flood.push(datagram(UInt8(value))) }
        check(flood.dropped == 6, "six drops")
        check(flood.count == 4 && flood.peak == 4, "the queue stays at the cap")
        check(flood.pop() == datagram(7), "the oldest waiting datagram is seven")
        check(flood.pop() == datagram(8), "then eight")
        check(flood.pop() == datagram(9), "then nine")
        check(flood.pop() == datagram(10), "then ten")

        // One element: each new datagram replaces the old one.
        var single = DatagramQueue(capacity: 1)
        check(single.push(datagram(1)) == false, "the first datagram fits")
        check(single.push(datagram(2)) == true, "the second replaces it")
        check(single.dropped == 1 && single.count == 1, "one element waits")
        check(single.pop() == datagram(2), "the newest datagram waits")

        // removeAll clears what waits, and the writer keeps its counts.
        var reset = DatagramQueue()
        reset.push(datagram(1))
        reset.push(datagram(2))
        reset.removeAll()
        check(reset.isEmpty && reset.count == 0, "removeAll clears the queue")
        check(reset.dropped == 0 && reset.added == 2, "removeAll keeps the counts")
        reset.push(datagram(3))
        check(reset.pop() == datagram(3), "the queue works after removeAll")

        // The default queue holds 64 datagrams and drops the 65th oldest.
        var full = DatagramQueue()
        for value in 1...65 { full.push(Data([UInt8(value), 0])) }
        check(full.dropped == 1, "the 65th push drops one")
        check(full.count == 64, "64 wait")
        check(full.pop()?.first == 2, "the first waiting datagram is the second push")

        print("Datagram queue tests passed")
    }
}
