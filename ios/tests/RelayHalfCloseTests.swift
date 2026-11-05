import Foundation

@main
struct RelayHalfCloseTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        // The relay starts with both directions open.
        let start = RelayHalfClose()
        check(!start.clientReadFinished, "the target device is open at the start")
        check(!start.destinationReadFinished, "the destination is open at the start")
        check(!start.clientWriteFinished, "the target device write side is open at the start")
        check(!start.destinationWriteFinished, "the destination write side is open at the start")
        check(!start.bothReadFinished, "the relay is open at the start")
        check(!start.canClose, "the relay cannot close at the start")
        check(!start.isReadFinished(.client), "isReadFinished for the target device")
        check(!start.isReadFinished(.destination), "isReadFinished for the destination")
        check(RelayHalfClose.Side.client.other == .destination, "the other side of the target device")
        check(RelayHalfClose.Side.destination.other == .client, "the other side of the destination")

        // Normal traffic keeps the same direction open.
        var relay = start
        check(relay.receive(hasData: true, eof: false, side: .client) == .forward,
              "data from the target device is forwarded")
        check(relay.receive(hasData: true, eof: false, side: .destination) == .forward,
              "data from the destination is forwarded")
        check(relay.receive(hasData: false, eof: false, side: .client) == .readAgain,
              "an empty event reads the same side again")
        check(!relay.bothReadFinished && !relay.canClose, "normal traffic closes nothing")

        // A clean EOF from the target device finishes only its direction. The
        // final data must go out before the write-side FIN.
        check(relay.receive(hasData: true, eof: true, side: .client) == .forwardThenFinish,
              "final data and an EOF ask for the data then the FIN")
        check(relay.clientReadFinished, "the target device finished its read")
        check(!relay.destinationReadFinished, "the destination stays open")
        check(!relay.bothReadFinished, "one EOF does not finish both reads")
        check(relay.isReadFinished(.client) && !relay.isReadFinished(.destination),
              "isReadFinished after one EOF")

        // A repeated event on the finished side does nothing.
        check(relay.receive(hasData: false, eof: true, side: .client) == .ignore,
              "a repeated EOF is ignored")
        check(relay.receive(hasData: true, eof: false, side: .client) == .ignore,
              "data after the EOF is ignored")
        check(!relay.bothReadFinished, "an ignored event closes nothing")

        // The opposite direction still carries data after the first EOF.
        check(relay.receive(hasData: true, eof: false, side: .destination) == .forward,
              "the destination still sends data after the first EOF")
        check(!relay.destinationReadFinished, "the destination is still open")

        // The second EOF finishes both reads. The FIN to the target device is
        // the second write side to finish.
        check(relay.receive(hasData: true, eof: true, side: .destination) == .forwardThenFinish,
              "the second final data and EOF ask for the data then the FIN")
        check(relay.destinationReadFinished, "the destination finished its read")
        check(relay.bothReadFinished, "both reads finished")
        check(!relay.canClose, "a close waits for both write-side FINs")
        relay.writeFinished(.destination)
        check(!relay.canClose, "a close waits for the second write-side FIN")
        relay.writeFinished(.client)
        check(relay.canClose, "both FINs finished the relay")
        relay.writeFinished(.client)
        check(relay.canClose, "a repeated write finish keeps the relay closed")

        // The destination can finish first. Its final data still goes out
        // before the FIN, and the target device direction stays open.
        var reverse = start
        check(reverse.receive(hasData: true, eof: true, side: .destination) == .forwardThenFinish,
              "the destination final data and EOF")
        check(!reverse.bothReadFinished, "the destination EOF keeps the other direction open")
        check(reverse.receive(hasData: true, eof: false, side: .client) == .forward,
              "the target device still sends data after the destination EOF")
        check(reverse.receive(hasData: false, eof: false, side: .destination) == .ignore,
              "a read on the finished destination is ignored")
        check(reverse.receive(hasData: false, eof: true, side: .client) == .finish,
              "an EOF with no data asks for the FIN alone")
        check(reverse.bothReadFinished, "both directions finished in reverse order")
        reverse.writeFinished(.client)
        check(!reverse.canClose, "one FIN is not enough in reverse order")
        reverse.writeFinished(.destination)
        check(reverse.canClose, "both FINs finished the reverse relay")

        // A write-side FIN can finish before the reads. It never closes early.
        var early = start
        early.writeFinished(.client)
        check(!early.canClose, "a write FIN alone does not close")
        check(early.receive(hasData: false, eof: true, side: .client) == .finish,
              "the read side still reports its EOF")
        check(!early.canClose, "one read and one write FIN do not close")
        check(early.receive(hasData: false, eof: true, side: .destination) == .finish,
              "the second read EOF")
        early.writeFinished(.destination)
        check(early.canClose, "the last FIN closes the relay")

        // An EOF with no data sends the FIN without a data write.
        var empty = start
        check(empty.receive(hasData: false, eof: true, side: .destination) == .finish,
              "an empty EOF from the destination")
        check(!empty.bothReadFinished, "the empty EOF keeps the other direction open")
        check(empty.receive(hasData: false, eof: true, side: .client) == .finish,
              "an empty EOF from the target device")
        check(empty.bothReadFinished, "both empty EOFs finish the reads")

        // The state is a value. One session cannot change another session.
        var first = start
        _ = first.receive(hasData: false, eof: true, side: .client)
        check(!start.clientReadFinished, "a copy does not change the original state")
        check(first != start, "a changed copy is not equal to the original")

        // A data-only event on a new state stays equal to the start state.
        var untouched = start
        _ = untouched.receive(hasData: true, eof: false, side: .destination)
        check(untouched == start, "data alone keeps the state equal")

        print("Relay half-close tests passed")
    }
}
