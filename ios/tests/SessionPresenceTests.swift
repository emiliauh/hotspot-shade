import Foundation
import Network

@main
struct SessionPresenceTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        // A long idle flow needs keepalive on the outer socket. A carrier NAT
        // can drop an idle mapping with no error at either end. Keepalive is
        // not application traffic and does not extend the 300 second idle
        // timeout.
        let tcp = makeNoDelayTCPOptions()
        check(tcp.noDelay, "Nagle is off")
        check(tcp.enableKeepalive, "keepalive is on")
        check(tcp.keepaliveIdle == 60, "keepalive idle is 60 seconds")
        check(tcp.keepaliveInterval == 10, "keepalive interval is 10 seconds")
        check(tcp.keepaliveCount == 3, "keepalive count is 3")
        // A failed socket operation belongs to the side that owns the socket.
        // A failed FIN write on the client connection is a client error.
        check(RelayHalfClose.Side.client.socketErrorEnd == .clientSocketError,
              "a client socket error stays on the target device side")
        check(RelayHalfClose.Side.destination.socketErrorEnd == .destinationSocketError,
              "a destination socket error stays on the cellular side")
        check(RelayHalfClose.Side.client.other.socketErrorEnd == .destinationSocketError,
              "a write to the other side names that side")
        // A new session is not authenticated and has no request byte.
        let fresh = SessionPresence()
        check(!fresh.authenticated, "a new session is not authenticated")
        check(!fresh.requestStarted, "a new session has no request byte")
        check(fresh.end(cleanEOF: true) == .session,
              "a clean EOF before authentication is not a presence check")
        check(fresh.end(cleanEOF: false) == .session,
              "a socket error before authentication is not a presence check")

        var dataAndEOF = SessionPresence()
        dataAndEOF.authenticationSucceeded()
        let withData = dataAndEOF.receive(hasData: true, eof: true, failed: false)
        check(withData.firstRequestByte && withData.end == .cleanEOF,
              "data is recorded before clean EOF")
        check(dataAndEOF.end(cleanEOF: true) == .session,
              "data with EOF remains visible")
        var errorAndEOF = SessionPresence()
        errorAndEOF.authenticationSucceeded()
        let failed = errorAndEOF.receive(hasData: false, eof: true, failed: true)
        check(failed.end == .error && errorAndEOF.end(cleanEOF: false) == .session,
              "error takes precedence over EOF")
        var emptyEOF = SessionPresence()
        emptyEOF.authenticationSucceeded()
        let ended = emptyEOF.receive(hasData: false, eof: true, failed: false)
        check(!ended.firstRequestByte && ended.end == .cleanEOF && emptyEOF.end(cleanEOF: true) == .presenceCheck,
              "empty clean EOF is a presence check")

        var handshake = HandshakeReadEnd()
        check(handshake.shouldReadClient, "a new client needs reads")
        check(handshake.receive(complete: false, end: .none) == .readAgain,
              "an incomplete field waits for data")
        check(handshake.receive(complete: true, end: .none) == .complete,
              "a complete field without EOF is delivered")
        check(handshake.receive(complete: true, end: .cleanEOF) == .complete,
              "a complete field is delivered with clean EOF")
        check(handshake.clientEOF, "the relay can observe the final EOF")
        check(!handshake.shouldReadClient, "the relay and echo task do not read past EOF")
        var failedAfterEOF = handshake
        check(failedAfterEOF.receive(complete: true, end: .error) == .error,
              "an error still takes precedence after EOF was recorded")
        var truncatedField = HandshakeReadEnd()
        check(truncatedField.receive(complete: false, end: .cleanEOF) == .cleanEOF,
              "an incomplete field with EOF closes")
        var failedField = HandshakeReadEnd()
        check(failedField.receive(complete: true, end: .error) == .error,
              "an error takes precedence over a complete field")
        check(!failedField.clientEOF, "an error is not a clean EOF")
        var halfClose = RelayHalfClose()
        check(halfClose.receive(hasData: false, eof: handshake.clientEOF, side: .client) == .finish,
              "the relay sends the recorded client FIN")
        check(!halfClose.isReadFinished(.destination), "the destination can still reply")

        // The presence probe: greeting, password authentication, then a clean
        // EOF with no SOCKS request. This is the only case that stays out of
        // the activity log.
        var presence = SessionPresence()
        presence.authenticationSucceeded()
        check(presence.authenticated, "a successful authentication is recorded")
        check(!presence.requestStarted, "authentication alone starts no request")
        check(presence.end(cleanEOF: true) == .presenceCheck,
              "authentication plus clean EOF is a presence check")
        check(presence.end(cleanEOF: false) == .session,
              "a reset or a timeout after authentication stays in the log")

        // A real session sends the first request byte after authentication. It
        // stays visible even when it closes with a clean EOF.
        var request = SessionPresence()
        request.authenticationSucceeded()
        request.noteRequestByte()
        check(request.requestStarted, "the first request byte is recorded")
        check(request.end(cleanEOF: true) == .session,
              "a real request keeps its activity lines")
        check(request.end(cleanEOF: false) == .session,
              "a real request with an error keeps its activity lines")

        // A truncated request still counts as a request. One byte is enough.
        // This covers a client that sends the SOCKS version and then closes.
        var truncated = SessionPresence()
        truncated.authenticationSucceeded()
        truncated.noteRequestByte()
        check(truncated.end(cleanEOF: true) == .session,
              "one request byte is not a presence check")

        // A repeated request byte changes nothing, and a later clean EOF never
        // turns a real session into a presence check.
        truncated.noteRequestByte()
        check(truncated.requestStarted, "the request flag stays set")
        check(truncated.end(cleanEOF: true) == .session,
              "a repeated byte keeps the session visible")

        // An authentication failure is never a presence check, even when the
        // client closes cleanly. Security logging stays on.
        let rejected = SessionPresence()
        check(rejected.end(cleanEOF: true) == .session,
              "a failed authentication stays in the log")

        // A request byte that arrives before authentication still marks a real
        // client. The order cannot happen in the protocol, but the state stays
        // conservative.
        var early = SessionPresence()
        early.noteRequestByte()
        early.authenticationSucceeded()
        check(early.end(cleanEOF: true) == .session,
              "a request byte before authentication keeps the session visible")

        // The state is a value. One session cannot change another session.
        var first = SessionPresence()
        first.authenticationSucceeded()
        var second = first
        second.noteRequestByte()
        check(first.end(cleanEOF: true) == .presenceCheck,
              "a copy with a request byte does not change the first state")
        check(second.end(cleanEOF: true) == .session,
              "the changed copy is a real session")
        check(first != second, "the two states differ")

        // The close record carries the decision to the server. Only the
        // presence check returns no activity line.
        let omitted = SessionClose(message: "Client disconnected during handshake.",
                                   isPresenceCheck: true)
        check(omitted.isPresenceCheck, "the presence close is marked")
        check(omitted.activityLine == nil, "the presence close omits its line")
        check(omitted.message.hasPrefix("Client disconnected"), "the message stays plain")

        let shown = SessionClose(message: "Authentication failed.", isPresenceCheck: false)
        check(!shown.isPresenceCheck, "an authentication failure is not a presence check")
        check(shown.activityLine == "Authentication failed.",
              "an authentication failure keeps its line")
        check(SessionClose(message: "Client timed out.", isPresenceCheck: false).activityLine
                == "Client timed out.", "a timeout keeps its line")

        print("Session presence tests passed")
    }
}
