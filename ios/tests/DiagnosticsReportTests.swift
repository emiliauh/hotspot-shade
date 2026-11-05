import Foundation

@main
struct DiagnosticsReportTests {
    static func check(_ condition: Bool, _ message: String, line: Int = #line) {
        if !condition {
            print("FAIL line \(line): \(message)")
            exit(1)
        }
    }

    static func main() {
        let unreachable = ConnectAttempt.Failure(errno: ENETUNREACH, description: "Network is unreachable")
        let refused = ConnectAttempt.Failure(errno: ECONNREFUSED, description: "Connection refused")

        // Every bucket boundary.
        check(ConnectDurationBucket.allCases.count == 7, "seven buckets")
        check(ConnectDurationBucket.bucket(-1) == .under100, "a negative duration is under 100 ms")
        check(ConnectDurationBucket.bucket(0) == .under100, "zero")
        check(ConnectDurationBucket.bucket(0.0999) == .under100, "99.9 ms")
        check(ConnectDurationBucket.bucket(0.1) == .under250, "100 ms starts the next bucket")
        check(ConnectDurationBucket.bucket(0.2499) == .under250, "249.9 ms")
        check(ConnectDurationBucket.bucket(0.25) == .under500, "250 ms")
        check(ConnectDurationBucket.bucket(0.4999) == .under500, "499.9 ms")
        check(ConnectDurationBucket.bucket(0.5) == .under1000, "500 ms")
        check(ConnectDurationBucket.bucket(0.9999) == .under1000, "999.9 ms")
        check(ConnectDurationBucket.bucket(1) == .under2000, "1 s")
        check(ConnectDurationBucket.bucket(1.9999) == .under2000, "1999.9 ms")
        check(ConnectDurationBucket.bucket(2) == .under4000, "2 s")
        check(ConnectDurationBucket.bucket(3.9999) == .under4000, "3999.9 ms")
        check(ConnectDurationBucket.bucket(4) == .atLeast4000, "4 s is not under 4 s")
        check(ConnectDurationBucket.bucket(60) == .atLeast4000, "60 s")
        // The labels.
        let labels = ConnectDurationBucket.allCases.map(\.label)
        check(labels == ["under 100 ms", "under 250 ms", "under 500 ms", "under 1 s",
                         "under 2 s", "under 4 s", "at 4 s or more"], "labels: \(labels)")

        // The counter type folds one run.
        var counters = DiagnosticsCounters()
        counters.recordFileLimit(.alreadyHigh(soft: 256))
        counters.record(duration: 0.05)
        counters.record(duration: 4)
        counters.recordSessionCount(2)
        counters.recordSessionCount(9)
        counters.recordSessionCount(3)
        counters.recordCapRefusal()
        counters.recordRelayRefusal()
        counters.recordEviction()
        counters.recordEviction(reason: .handshakeExpired)
        counters.recordEviction(reason: .relayGrantExpired)
        counters.recordEviction(reason: .udpIdle)
        var totals = ConnectRetryPolicy.Totals()
        var waits = ConnectRetryPolicy.WaitCounts()
        waits.record(unreachable)
        totals.waits = waits
        totals.retryStarts = 1
        totals.retrySuccesses = 1
        totals.deadlineFires = 1
        counters.record(totals, family: .ipv4, failed: true)
        counters.recordUDPQueue(peak: 4, dropped: 2)
        counters.recordUDPQueue(peak: 2, dropped: 1)
        let folded = counters.report()
        check(folded.buckets[.under100] == 1 && folded.buckets[.atLeast4000] == 1, "duration buckets")
        check(folded.waits.total == 1 && folded.waits.unreachable == 1, "waits")
        check(folded.waitsByFamily[.ipv4] == 1 && folded.failuresByFamily[.ipv4] == 1,
              "family counts")
        check(folded.retryStarts == 1 && folded.retrySuccesses == 1, "retry counts")
        check(folded.deadlineFires == 1, "deadline fires")
        check(folded.peakSessions == 9, "the peak is the largest count")
        check(folded.capRefusals == 1 && folded.relayRefusals == 1, "cap counts")
        check(folded.evictions == 4, "eviction total")
        check(folded.handshakeEvictions == 1 && folded.connectEvictions == 0
                && folded.relayGrantEvictions == 1
                && folded.udpEvictions == 1 && folded.halfClosedEvictions == 0,
              "eviction phases")
        check(folded.udpQueuePeak == 4 && folded.udpQueueDrops == 3, "UDP counts")
        check(folded.fileLimit == .alreadyHigh(soft: 256), "the file limit result")
        // reset clears the run counters and keeps the startup value.
        counters.reset()
        let cleared = counters.report()
        check(cleared.peakSessions == 0 && cleared.buckets.isEmpty && cleared.waits.total == 0,
              "reset clears the run counters")
        check(cleared.waitsByFamily.isEmpty && cleared.failuresByFamily.isEmpty,
              "reset clears the family counts")
        check(cleared.capRefusals == 0 && cleared.relayRefusals == 0
                && cleared.evictions == 0 && cleared.handshakeEvictions == 0
                && cleared.relayGrantEvictions == 0
                && cleared.udpEvictions == 0, "reset clears the capacity counts")
        check(cleared.fileLimit == .alreadyHigh(soft: 256), "reset keeps the file limit")

        // Established relay events use 10 second buckets. A bucket with no
        // relay start is not an observation. It is not a zero-loss sample.
        var established = EstablishedCounters()
        check(established.isEmpty, "a new run has no established observation")
        check(established.rows(now: 0).isEmpty, "a new run has no timeline rows")
        established.recordStart(.tcp, at: 100)
        established.recordStart(.tcp, at: 101)
        established.recordEnd(.tcp, end: .destinationSocketError, at: 104)
        established.recordEnd(.tcp, end: .clean, at: 105)
        established.recordStart(.udp, at: 115)
        established.recordEnd(.udp, end: .other, at: 116)
        check(established.tcpStarts == 2 && established.udpStarts == 1, "established starts")
        check(established.tcpDestinationErrors == 1 && established.tcpClientErrors == 0
                && established.tcpClean == 1, "established ends")
        check(established.udpEnds == 1, "UDP relay ends")
        let rows = established.rows(now: 119)
        check(rows.count == 2, "two buckets: \(rows)")
        check(rows[0].ageSeconds == 0 && rows[0].bucket.tcpStarts == 0
                && rows[0].bucket.udpStarts == 1 && rows[0].bucket.udpEnds == 1,
              "the newest bucket holds the UDP relay")
        check(rows[1].ageSeconds == 10 && rows[1].bucket.tcpStarts == 2
                && rows[1].bucket.tcpDestinationErrors == 1 && rows[1].bucket.tcpClientErrors == 0
                && rows[1].bucket.tcpClean == 1,
              "the older bucket holds the TCP relay")
        // A later bucket drops entries outside the 300 second window.
        established.recordStart(.tcp, at: 10_000)
        check(established.rows(now: 10_000).count == 1,
              "the timeline window stays bounded")
        // A late event from an expired bucket still counts in the totals. It
        // must not reinsert the bucket that the window dropped.
        established.recordEnd(.tcp, end: .other, at: 50)
        check(established.rows(now: 10_000).count == 1,
              "a late older event does not reinsert an expired bucket")
        check(established.buckets[5] == nil, "the expired bucket stays gone")
        check(established.tcpOther == 1, "the late event still counts in the totals")
        // A late event inside the window keeps its own bucket.
        established.recordEnd(.tcp, end: .idle, at: 9_999)
        let lateRows = established.rows(now: 10_000)
        check(lateRows.count == 2 && lateRows[1].ageSeconds == 10
                && lateRows[1].bucket.tcpIdle == 1,
              "a late event inside the window keeps its bucket")
        established.reset()
        check(established.isEmpty, "reset clears the established counters")

        // A copied report recomputes the bucket ages. The age at publish time
        // is stale after a wait in the Settings screen.
        var ageCounters = EstablishedCounters()
        ageCounters.recordStart(.tcp, at: 100)
        ageCounters.recordEnd(.tcp, end: .idle, at: 105)
        var ageReport = DiagnosticsReport()
        ageReport.established = ageCounters
        ageReport.refreshEstablishedRows(now: 105)
        check(ageReport.establishedRows.first?.ageSeconds == 0,
              "a fresh report starts at zero seconds")
        ageReport.refreshEstablishedRows(now: 145)
        check(ageReport.establishedRows.first?.ageSeconds == 40,
              "a copied report moves the bucket age forward")
        ageReport.refreshEstablishedRows(now: 1_000)
        check(ageReport.establishedRows.isEmpty,
              "a copied report drops buckets outside the window")

        // A destination that answered is not an established relay. The first
        // payload in either direction starts it.
        var relay = EstablishedRelay()
        check(!relay.started && relay.transport == nil,
              "a ready destination without payload is not established")
        check(relay.recordPayload(.tcp) == .tcp, "the first TCP payload starts the relay")
        check(relay.started && relay.transport == .tcp, "the relay keeps its transport")
        check(relay.recordPayload(.udp) == nil && relay.transport == .tcp,
              "a later payload does not start a second relay")

        // One session has one established record. A stop, an eviction, and an
        // asynchronous close can ask for the end. Only the first caller gets
        // it, so the report cannot count the same end twice.
        var sessionRecord = EstablishedSessionRecord()
        check(sessionRecord.takeEnd() == nil, "a session with no relay has no end")
        check(sessionRecord.recordPayload(.tcp) == .tcp, "the first payload starts the session record")
        check(sessionRecord.recordPayload(.udp) == nil, "one session has one relay")
        sessionRecord.recordEnd(.clientSocketError)
        sessionRecord.recordEnd(.destinationSocketError)
        let taken = sessionRecord.takeEnd()
        check(taken?.transport == .tcp && taken?.end == .clientSocketError,
              "the first end reason stays")
        check(sessionRecord.takeEnd() == nil, "the end is taken once")
        var stoppedRecord = EstablishedSessionRecord()
        check(stoppedRecord.recordPayload(.udp) == .udp, "a UDP relay can start")
        let stoppedEnd = stoppedRecord.takeEnd(default: .other)
        check(stoppedEnd?.transport == .udp && stoppedEnd?.end == .other,
              "a stop records an open relay as other")
        check(stoppedRecord.takeEnd() == nil, "an open relay ends once")
        // A stop can take the end while the session queue is about to mark a
        // clean end. The late mark must not count the end again.
        stoppedRecord.recordEnd(.clean)
        check(stoppedRecord.takeEnd() == nil, "a late end after the take is ignored")
        var endFirst = EstablishedSessionRecord()
        endFirst.recordEnd(.clean)
        check(endFirst.takeEnd() == nil, "an end before a payload is not a relay")

        // A capacity eviction keeps the idle end of a half-closed or UDP
        // flow. It must not record the generic other end.
        check(EstablishedEnd.capacityEviction(.halfClosedIdle) == .idle,
              "a half-closed eviction records an idle end")
        check(EstablishedEnd.capacityEviction(.udpIdle) == .idle,
              "a UDP eviction records an idle end")
        check(EstablishedEnd.capacityEviction(.connectExpired) == .other,
              "a setup eviction records the other end")
        var idleEvicted = EstablishedSessionRecord()
        _ = idleEvicted.recordPayload(.tcp)
        let idleEnd = idleEvicted.takeEnd(
            default: EstablishedEnd.capacityEviction(.halfClosedIdle))
        check(idleEnd?.end == .idle, "the evicted half-closed flow ends idle")

        // An empty report still has a header and every line.
        let empty = DiagnosticsReport()
        let emptyText = empty.text()
        let emptyLines = emptyText.split(separator: "\n").map(String.init)
        check(emptyLines.first == DiagnosticsReport.header, "the header line")
        check(DiagnosticsReport.header == "HotspotShade diagnostics", "the header text")
        check(emptyLines.contains("Connections: No connections yet."), "the empty connections line")
        check(emptyLines.contains("Waits: 0."), "the empty wait line")
        check(emptyLines.contains("Waits by family: 0 IPv4, 0 IPv6, 0 names. "
                                    + "Failures by family: 0 IPv4, 0 IPv6, 0 names."),
              "the empty family line")
        check(!emptyText.contains("Cancelled:"), "no cancelled line when nothing was cancelled")
        check(emptyLines.contains("Connect time: 0 under 100 ms, 0 under 250 ms, 0 under 500 ms, "
                                    + "0 under 1 s, 0 under 2 s, 0 under 4 s, 0 at 4 s or more."),
              "the empty connect time line")
        check(emptyLines.contains("Established: no observation."), "the empty established line")
        check(emptyLines.contains("Established ends: 0 clean, 0 client socket errors, "
                                    + "0 destination socket errors, 0 idle, 0 other, "
                                    + "0 UDP (side and reason not kept)."),
              "the empty established end line")
        check(emptyLines.contains("Established ends by 10 s bucket: none in the last 300 s."),
              "the empty established bucket line")
        check(emptyLines.contains("Sessions: peak 0 with an unknown limit. "
                                    + "Now 0 setup, 0 relays."),
              "the empty session line")
        check(emptyLines.contains("Capacity: connection refusals 0. Relay refusals 0. "
                                    + "Evicted 0: 0 handshake, 0 connect, 0 relay wait, "
                                    + "0 UDP, 0 half-closed."),
              "the empty capacity line")
        check(emptyLines.contains("File limit: unknown."), "the unknown file limit line")
        check(emptyLines.contains("Open files: estimate 3 for each session, "
                                    + "32 reserved. A stopped run counts until every close finishes."),
              "the open-file budget line")
        check(emptyLines.contains("Keep-awake: unknown."), "the unknown keep-awake line")
        var noLimit = DiagnosticsReport()
        noLimit.fileLimit = .refused(soft: 32)
        check(noLimit.sessionLine
                == "Sessions: peak 0 with no usable limit. Now 0 setup, 0 relays.",
              "a known but unusable limit is not called unknown")

        // A lower limit must be honest. The report warns below the earlier
        // 224 relay baseline and never prints the nominal 256.
        var lowReport = DiagnosticsReport()
        lowReport.sessionLimit = 202
        lowReport.relayLimit = 179
        lowReport.setupReserve = 23
        check(lowReport.capacityWarning != nil, "a low relay cap warns")
        check(lowReport.text().contains("Capacity warning:"), "the report shows the warning")
        check(lowReport.text().contains("179"), "the warning names the relay count")
        check(!lowReport.text().contains("relay cap 256"), "a low limit never claims 256")
        var fullReport = DiagnosticsReport()
        fullReport.relayLimit = 256
        check(fullReport.capacityWarning == nil, "the full relay cap has no warning")
        // A close that missed the retirement bound stays visible.
        check(!emptyText.contains("Unconfirmed closes:"),
              "a clean report has no unconfirmed close line")
        var unconfirmed = DiagnosticsReport()
        unconfirmed.unconfirmedCloses = 3
        check(unconfirmed.text().contains("Unconfirmed closes: 3."),
              "the report counts unconfirmed closes")

        // A full report, line by line.
        var connections = ConnectCounters()
        for _ in 0..<4 { connections.recordStart() }
        connections.record(ConnectConclusion(kind: .web, result: .worked, reason: nil))
        connections.record(ConnectConclusion(kind: .web, result: .slow, reason: nil))
        connections.record(ConnectConclusion(kind: .dnsLookup, result: .didNotWork, reason: .refused))
        connections.record(ConnectConclusion(kind: .udp, result: .cancelled, reason: nil))
        var report = DiagnosticsReport()
        report.connections = connections
        report.buckets = [.under100: 3, .under250: 1, .atLeast4000: 2]
        var reportWaits = ConnectRetryPolicy.WaitCounts()
        reportWaits.record(unreachable)
        reportWaits.record(unreachable)
        reportWaits.record(refused)
        report.waits = reportWaits
        report.waitsByFamily = [.ipv4: 2, .ipv6: 1]
        report.failuresByFamily = [.ipv4: 1]
        report.retryStarts = 2
        report.retrySuccesses = 1
        report.deadlineFires = 1
        report.peakSessions = 7
        report.capRefusals = 1
        report.relayRefusals = 3
        report.evictions = 2
        report.handshakeEvictions = 1
        report.connectEvictions = 1
        report.sessionLimit = 288
        report.relayLimit = 256
        report.setupReserve = 32
        report.setupSessions = 2
        report.relaySessions = 5
        report.udpQueuePeak = 8
        report.udpQueueDrops = 3
        var reportEstablished = EstablishedCounters()
        reportEstablished.recordStart(.tcp, at: 985)
        reportEstablished.recordEnd(.tcp, end: .destinationSocketError, at: 988)
        reportEstablished.recordStart(.udp, at: 995)
        reportEstablished.recordEnd(.udp, end: .other, at: 996)
        report.established = reportEstablished
        report.establishedRows = reportEstablished.rows(now: 1_000)
        report.fileLimit = .raised(soft: 4096)
        report.lowPowerMode = true
        report.thermal = .fair
        report.locationHealth = LocationHealth.keepingAwake
        report.appVersion = "1.0 (1)"
        report.systemVersion = "18.0"
        report.proxyState = "On"
        let expected = """
        HotspotShade diagnostics
        App 1.0 (1). iOS 18.0.
        Proxy: On.
        Connections: 4 attempts. 2 worked. 1 did not.
        Cancelled: 1 was cancelled by the target device.
        Connect time: 3 under 100 ms, 1 under 250 ms, 0 under 500 ms, 0 under 1 s, 0 under 2 s, 0 under 4 s, 2 at 4 s or more.
        Waits: 3 (2 unreachable, 1 refused, 0 other).
        Waits by family: 2 IPv4, 1 IPv6, 0 names. Failures by family: 1 IPv4, 0 IPv6, 0 names.
        Retries: 2 started, 1 worked.
        Deadline fires: 1.
        Sessions: peak 7 of 288 (relay cap 256, setup reserve 32). Now 2 setup, 5 relays.
        Capacity: connection refusals 1. Relay refusals 3. Evicted 2: 1 handshake, 1 connect, 0 relay wait, 0 UDP, 0 half-closed.
        UDP queue: peak 8. Dropped 3.
        Established: 1 TCP relay starts, 1 UDP relay starts.
        Established ends: 0 clean, 0 client socket errors, 1 destination socket errors, 0 idle, 0 other, 1 UDP (side and reason not kept).
        Established ends by 10 s bucket: 10 s ago: 0 clean, 0 client errors, 0 destination errors, 0 idle, 0 other, 1 UDP; 20 s ago: 0 clean, 0 client errors, 1 destination errors, 0 idle, 0 other, 0 UDP.
        File limit: 4096, raised.
        Open files: estimate 3 for each session, 32 reserved. A stopped run counts until every close finishes.
        Low Power Mode: On.
        Thermal state: Fair.
        Keep-awake: The app stays awake while the proxy runs.
        """
        check(report.text() == expected, "the full report text:\n\(report.text())")

        // The text names no destination and no token.
        let text = report.text()
        check(!text.contains("://"), "no address in the report")
        check(!text.contains("172.20.10.1"), "no hotspot address in the report")
        for word in ["token", "pairing code", "laptop", "computer"] {
            check(!text.lowercased().contains(word), "the report names no \(word)")
        }
        check(!text.contains("TCP port"), "no port label in the report")

        // A thermal state is one of four plain words.
        check(ThermalLevel.allCases.map(\.rawValue) == ["Nominal", "Fair", "Serious", "Critical"],
              "thermal words")

        print("Diagnostics report tests passed")
    }
}
