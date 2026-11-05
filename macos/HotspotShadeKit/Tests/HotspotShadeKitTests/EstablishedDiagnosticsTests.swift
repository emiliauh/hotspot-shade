import Foundation
import XCTest
@testable import HotspotShadeKit

final class EstablishedDiagnosticsTests: XCTestCase {
    private func report(_ json: String) throws -> String {
        let diagnostics = try JSONDecoder().decode(Diagnostics.self, from: Data(json.utf8))
        return DiagnosticsReport.text(diagnostics: diagnostics, failures: nil,
                                      context: DiagnosticsContext(now: Date(timeIntervalSince1970: 0)))
    }

    func testLargeDiagnosticNumbersDoNotOverflowTheReport() throws {
        let text = try report("{\"queues\":{\"output\":{\"max_age_us\":1e100}}}")
        XCTAssertTrue(text.contains("max age 1e+100 us"))
    }

    func testReportIncludesLocalRelayEventsWithoutClaimingLoss() throws {
        let text = try report("""
        {"established":{"bucket_s":1,"window_s":60,"buckets":[
          {"age_s":1,"observed":true,"tcp_retransmits":2,"window_limited_ms":7,
           "tcp_teardowns":0,"udp_teardowns":1,"udp_drops":0,"relay_drops":1,"outer_errors":0},
          {"age_s":0,"observed":false,"tcp_retransmits":0,"window_limited_ms":0,
           "tcp_teardowns":0,"udp_teardowns":0,"udp_drops":0,"relay_drops":0,"outer_errors":0}
        ]}}
        """)
        XCTAssertTrue(text.contains("1 of 2 reported buckets observed an established flow"))
        XCTAssertTrue(text.contains("Local events do not prove end-to-end loss"))
        XCTAssertTrue(text.contains("Established 1 s ago: retransmits 2, window 7 ms"))
        XCTAssertTrue(text.contains("relay drops 1"))
    }

    func testEmptyAndMissingDataDoNotClaimAHealthyPath() throws {
        let empty = try report("{\"established\":{\"buckets\":[]}}")
        XCTAssertTrue(empty.contains("Established relay: no observation."))
        let unknown = try report("{\"established\":{\"buckets\":[{}]}}")
        XCTAssertTrue(unknown.contains("observation unavailable"))
        XCTAssertTrue(unknown.contains("Established events: unavailable."))
        let older = try report("{}")
        XCTAssertFalse(older.contains("Established relay:"))
    }

    func testReportBoundsRecentEventsAndIgnoresUnexpectedFields() throws {
        let buckets = (0..<12).reversed().map { age in
            "{\"age_s\":\(age),\"observed\":true,\"tcp_retransmits\":1,\"host\":\"private.example\"}"
        }.joined(separator: ",")
        let text = try report("{\"established\":{\"buckets\":[\(buckets)]}}")
        let eventLines = text.split(separator: "\n").filter { $0.hasPrefix("Established ") && $0.contains(" s ago:") }
        XCTAssertEqual(eventLines.count, 8)
        XCTAssertTrue(eventLines.first?.contains("0 s ago") == true)
        XCTAssertFalse(text.contains("private.example"))
        XCTAssertFalse(text.contains("11 s ago"))
    }
}
