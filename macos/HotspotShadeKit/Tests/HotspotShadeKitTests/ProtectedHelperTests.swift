import XCTest
import Foundation
import Darwin
import Security
@testable import HotspotShadeKit

private final class FakeHelperFiles: HelperFileInspecting, @unchecked Sendable {
    var identities: [String: HelperFileIdentity] = [:]
    var canonical: [String: String] = [:]
    var writableACL: Set<String> = []

    func identity(atPath path: String) throws -> HelperFileIdentity {
        guard let value = identities[path] else { throw HelperTrustError.notInstalledPath }
        return value
    }

    func canonicalPath(_ path: String) throws -> String {
        guard let value = canonical[path] else { throw HelperTrustError.notInstalledPath }
        return value
    }

    func hasWriteACL(atPath path: String) throws -> Bool {
        writableACL.contains(path)
    }
}

private final class FakeHelperReader: HelperFileReading, @unchecked Sendable {
    var files: [String: Data] = [:]

    func readFile(atPath path: String, maximumBytes: Int) throws -> Data {
        guard let data = files[path] else { throw HelperTrustError.launchDaemonPlistMissing }
        guard data.count <= maximumBytes else { throw HelperTrustError.launchDaemonPlistUnsafe }
        return data
    }
}

private final class FakeHelperSigner: HelperCodeSignatureChecking, @unchecked Sendable {
    var infos: [String: HelperSigningInfo] = [:]
    var staticFailure: HelperTrustError?
    var runningFailure: HelperTrustError?
    var lastRequirement: String?
    var lastProcessIdentifier: Int32?
    var lastAuditToken: [UInt8]?
    var staticChecks: [String] = []

    func signingInfo(atPath path: String) throws -> HelperSigningInfo {
        guard let value = infos[path] else { throw HelperTrustError.signatureUnavailable }
        return value
    }

    func verifyStaticCode(atPath path: String, requirement: String) throws {
        lastRequirement = requirement
        staticChecks.append(path)
        if let staticFailure { throw staticFailure }
    }

    func verifyRunningCode(
        auditToken: [UInt8],
        processIdentifier: Int32,
        requirement: String
    ) throws {
        lastAuditToken = auditToken
        lastProcessIdentifier = processIdentifier
        lastRequirement = requirement
        if let runningFailure { throw runningFailure }
    }
}

private func file(
    owner: UInt32 = 0,
    group: UInt32 = 0,
    mode: UInt16 = 0o755,
    regular: Bool = true,
    directory: Bool = false,
    symlink: Bool = false
) -> HelperFileIdentity {
    HelperFileIdentity(
        ownerIdentifier: owner,
        groupIdentifier: group,
        mode: mode,
        isRegularFile: regular,
        isDirectory: directory,
        isSymbolicLink: symlink
    )
}

private final class FakeRunningEngine: RunningHelperEngine {
    let description: HelperEngineDescription
    var isRunning = true
    var stopResult: EngineStopResult = .stopped
    var stopCalls = 0
    var authorizeCalls = 0
    var authorizeFailure: Error?
    var duringStop: (() -> Void)?

    init(port: UInt16 = 5353, secret: String = "secret") {
        description = HelperEngineDescription(port: port, secret: secret)
    }

    func authorizeStart() throws {
        authorizeCalls += 1
        if let authorizeFailure { throw authorizeFailure }
    }

    func stop() -> EngineStopResult {
        stopCalls += 1
        duringStop?()
        isRunning = false
        return stopResult
    }
}

private final class FakeEngineLauncher: HelperEngineLaunching {
    var engine = FakeRunningEngine()
    var failure: HelperTrustError?
    var anyFailure: Error?
    var launches = 0
    var lastHandoff: HelperStartExclusionHandoff?
    var duringLaunch: (() -> Void)?

    func launch(holding exclusion: HelperStartExclusionHandoff?) throws -> RunningHelperEngine {
        launches += 1
        lastHandoff = exclusion
        duringLaunch?()
        if let anyFailure { throw anyFailure }
        if let failure { throw failure }
        return engine
    }
}

private final class TestCleanupBlockStore: HelperCleanupBlockStoring, @unchecked Sendable {
    var blocked = false
    var readFailure: Error?
    var writeFailure: Error?
    var duringRecord: (() -> Void)?
    var records: [String] = []

    func isBlocked() throws -> Bool {
        if let readFailure { throw readFailure }
        return blocked
    }

    func recordBlock(reason: String) throws {
        if let writeFailure { throw writeFailure }
        duringRecord?()
        records.append(reason)
        blocked = true
    }
}

// The durable write-ahead intent, in memory for the hermetic tests. The
// ordering is what matters: the controller creates it before it calls the
// launcher and clears it only after a verified clean stop.
private final class TestLaunchIntentStore: HelperLaunchIntentStoring, @unchecked Sendable {
    var present = false
    var readFailure: Error?
    var createFailure: Error?
    var clearFailure: Error?
    var createCalls = 0
    var clearCalls = 0
    var clearSawPresent: [Bool] = []

    func isPresent() throws -> Bool {
        if let readFailure { throw readFailure }
        return present
    }

    func create() throws {
        createCalls += 1
        if let createFailure { throw createFailure }
        guard !present else { throw HelperLaunchIntentError.alreadyPresent }
        present = true
    }

    func clearAfterVerifiedCleanStop() throws {
        clearCalls += 1
        clearSawPresent.append(present)
        if let clearFailure { throw clearFailure }
        present = false
    }
}

// The reviewed start-lock backend in memory for the lifecycle tests. The real
// store and Darwin lock semantics have their own tests in
// ProtectedHelperExclusionTests.
final class TestStartExclusion: HelperStartExclusionPreparing, @unchecked Sendable {
    var installJournalPresent = false
    var installJournalReadFailure: Error?
    var probe: HelperStartExclusionAvailability = .available
    var prepareFailure: Error?
    var prepareCalls = 0
    var prepareSessions: [UUID] = []
    var lease = TestStartExclusionLease()

    func isInstallJournalPresent() throws -> Bool {
        if let installJournalReadFailure { throw installJournalReadFailure }
        return installJournalPresent
    }

    func probeSharedAvailability() -> HelperStartExclusionAvailability {
        probe
    }

    func prepare(session: UUID) throws -> HelperStartExclusionLease {
        prepareCalls += 1
        prepareSessions.append(session)
        if let prepareFailure { throw prepareFailure }
        return lease
    }
}

final class TestStartExclusionLease: HelperStartExclusionLease, @unchecked Sendable {
    var handoff = HelperStartExclusionHandoff(
        descriptor: 12,
        lockPath: "/tmp/test-start-exclusion",
        lockDevice: 1,
        lockInode: 2
    )
    var releaseCalls = 0
    var abandonCalls = 0

    func releaseAfterCleanStop() {
        releaseCalls += 1
    }

    func abandon() {
        abandonCalls += 1
    }
}

private final class FakeStartRightChecker: HelperStartRightConfigurationChecking, @unchecked Sendable {
    var failure: HelperTrustError?
    var calls = 0

    func checkStartRight(_ name: String) throws {
        calls += 1
        if let failure { throw failure }
    }
}

private func makeController(
    _ launcher: HelperEngineLaunching,
    store: TestCleanupBlockStore = TestCleanupBlockStore(),
    intent: TestLaunchIntentStore = TestLaunchIntentStore(),
    exclusion: TestStartExclusion = TestStartExclusion()
) -> HelperSessionController {
    HelperSessionController(
        launcher: launcher,
        cleanupStore: store,
        intentStore: intent,
        exclusion: exclusion
    )
}

// A manual monotonic clock for the authorization deadline tests.
private final class ManualClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: TimeInterval = 5_000

    var now: TimeInterval {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    func advance(_ seconds: TimeInterval) {
        lock.lock(); value += seconds; lock.unlock()
    }
}

private func makeDeadlineController(
    _ launcher: HelperEngineLaunching,
    clock: ManualClock,
    store: TestCleanupBlockStore = TestCleanupBlockStore(),
    intent: TestLaunchIntentStore = TestLaunchIntentStore(),
    exclusion: TestStartExclusion = TestStartExclusion()
) -> HelperSessionController {
    HelperSessionController(
        launcher: launcher,
        cleanupStore: store,
        intentStore: intent,
        exclusion: exclusion,
        clock: { clock.now }
    )
}

private final class FakeHelperTransport: ProtectedHelperTransport, @unchecked Sendable {
    var onInvalidation: ((HelperInvalidation) -> Void)?
    var reply = HelperStartReply(port: 4444, secret: "secret")
    var failure: HelperTrustError?
    var stopFailure: HelperTrustError?
    var cancelFailure: HelperTrustError?
    var handshakeFailure: HelperTrustError?
    var handshakeReply = HelperHandshake(
        serverNonce: Data(repeating: 0x44, count: HelperHandshakeGate.nonceByteCount)
    )
    var statusReply = HelperStatus(running: false, cleanupBlocked: false)
    var stopReply = HelperStopReply(
        owned: true,
        status: HelperStatus(running: false, cleanupBlocked: false)
    )
    var statusFailure: HelperTrustError?
    var startCalls = 0
    var stopCalls = 0
    var cancelCalls = 0
    var handshakeCalls = 0
    var statusCalls = 0
    var closeCalls = 0
    var authorizeCalls = 0
    var authorizeFailure: HelperTrustError?
    var lastAuthorization: Data?
    var lastServerNonce: Data?
    var lastCredentials: Int32?
    var events: [String] = []
    var duringStatus: (() -> Void)?
    var duringStart: (() -> Void)?
    var onAuthorize: (() -> Void)?

    func handshake() throws -> HelperHandshake {
        handshakeCalls += 1
        events.append("handshake")
        if let handshakeFailure { throw handshakeFailure }
        return handshakeReply
    }

    func start(serverNonce: Data, timeout: TimeInterval, credentials: Int32?) throws -> HelperStartReply {
        startCalls += 1
        events.append("start")
        lastServerNonce = serverNonce
        lastCredentials = credentials
        duringStart?()
        if let failure { throw failure }
        return reply
    }

    func authorizeStart(authorization: Data, serverNonce: Data, timeout: TimeInterval) throws {
        authorizeCalls += 1
        events.append("authorize")
        lastAuthorization = authorization
        lastServerNonce = serverNonce
        onAuthorize?()
        if let authorizeFailure { throw authorizeFailure }
    }

    func stop() throws -> HelperStopReply {
        stopCalls += 1
        if let stopFailure { throw stopFailure }
        return stopReply
    }

    func cancel() throws {
        cancelCalls += 1
        if let cancelFailure { throw cancelFailure }
    }

    func status() throws -> HelperStatus {
        statusCalls += 1
        events.append("status")
        if let statusFailure { throw statusFailure }
        duringStatus?()
        return statusReply
    }

    func close() { closeCalls += 1 }
    func invalidate(_ reason: HelperInvalidation = .connectionLost) { onInvalidation?(reason) }
}

private final class FakeAuthorizationLease: HelperStartAuthorizationLease, @unchecked Sendable {
    let externalForm: Data
    var releases = 0

    init(form: Data) {
        self.externalForm = form
    }

    func release() { releases += 1 }
}

private final class FakeAuthorizationProvider: HelperStartAuthorizationProviding, @unchecked Sendable {
    var form = Data(repeating: 0x11, count: HelperStartAuthorizationPolicy.externalFormByteCount)
    var failure: HelperTrustError?
    var calls = 0
    var lease: FakeAuthorizationLease?

    func beginStartAuthorization() throws -> HelperStartAuthorizationLease {
        calls += 1
        if let failure { throw failure }
        let value = FakeAuthorizationLease(form: form)
        lease = value
        return value
    }
}

private final class FakeAuthorizationCreator: HelperAuthorizationFormCreating, @unchecked Sendable {
    var form = Data(repeating: 0x22, count: HelperStartAuthorizationPolicy.externalFormByteCount)
    var failure: HelperTrustError?
    var calls = 0
    var lastRight: String?
    var lastPrompt: String?
    var lease: FakeAuthorizationLease?

    func createStartAuthorization(rightName: String, prompt: String) throws -> HelperStartAuthorizationLease {
        calls += 1
        lastRight = rightName
        lastPrompt = prompt
        if let failure { throw failure }
        let value = FakeAuthorizationLease(form: form)
        lease = value
        return value
    }
}

private final class FakeAuthorizationFormChecker: HelperAuthorizationFormChecking, @unchecked Sendable {
    var failure: HelperTrustError?
    var calls = 0
    var forms: [[UInt8]] = []
    var rights: [String] = []

    func checkStartAuthorization(form: [UInt8], rightName: String) throws {
        calls += 1
        forms.append(form)
        rights.append(rightName)
        if let failure { throw failure }
    }
}

private final class Box<Value>: @unchecked Sendable {
    var value: Value?
    init(_ value: Value? = nil) { self.value = value }
}

private final class BlockingEngineLauncher: HelperEngineLaunching, @unchecked Sendable {
    let engine = FakeRunningEngine()
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    var launches = 0

    func launch(holding exclusion: HelperStartExclusionHandoff?) throws -> RunningHelperEngine {
        launches += 1
        entered.signal()
        release.wait()
        return engine
    }
}

private final class TransportFactoryCounter: @unchecked Sendable {
    var calls = 0
}

// A factory that returns one fresh fake transport per connection. A stop retry
// must open a new connection, not reuse a closed one or report a clean stop
// from a missing transport.
private final class TransportSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var transports: [FakeHelperTransport]
    private var calls = 0
    private let failAfter: Int?

    init(_ transports: [FakeHelperTransport], failAfter: Int? = nil) {
        self.transports = transports
        self.failAfter = failAfter
    }

    func next() throws -> FakeHelperTransport {
        lock.lock(); defer { lock.unlock() }
        calls += 1
        if let failAfter, calls > failAfter { throw HelperTrustError.helperUnavailable }
        guard !transports.isEmpty else { throw HelperTrustError.notConnected }
        return transports.removeFirst()
    }

    var callCount: Int { lock.lock(); defer { lock.unlock() }; return calls }
}

private func validPlist(helperPath: String) throws -> Data {
    let value: [String: Any] = [
        "Label": HelperRequirement.helperServiceName,
        "ProgramArguments": [helperPath],
        "MachServices": [HelperRequirement.helperServiceName: true],
        "RunAtLoad": false,
        "KeepAlive": false,
    ]
    return try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
}

final class ProtectedHelperTests: XCTestCase {
    #if HOTSPOTSHADE_LOCAL_PREVIEW
    private let signingClauses = "certificate 1[field.1.2.840.113635.100.6.2.1] exists and certificate leaf[field.1.2.840.113635.100.6.1.12] exists"
    #else
    private let signingClauses = "certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    #endif
    private let team = "ABCDEFGHIJ"
    private let helperPath = HelperRequirement.helperExecutablePath
    private let plistPath = HelperRequirement.launchDaemonPath
    private let root = HelperRequirement.helperInstallRoot
    private let library = "/Library"

    private func installFixture() throws -> (FakeHelperFiles, FakeHelperSigner, FakeHelperReader, HelperInstallPolicy) {
        let files = FakeHelperFiles()
        for path in [root, library, "/", "/Library/LaunchDaemons"] {
            files.identities[path] = file(mode: 0o755, regular: false, directory: true)
            files.canonical[path] = path
        }
        files.identities[helperPath] = file()
        files.canonical[helperPath] = helperPath
        files.identities[plistPath] = file(mode: 0o644)
        files.canonical[plistPath] = plistPath

        let signer = FakeHelperSigner()
        signer.infos[helperPath] = HelperSigningInfo(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: team,
            isAdHoc: false, hasHardenedRuntime: true
        )
        let reader = FakeHelperReader()
        reader.files[plistPath] = try validPlist(helperPath: helperPath)
        let policy = HelperInstallPolicy(
            layout: .rootOwnedCopy,
            helperPath: helperPath,
            launchDaemonPlistPath: plistPath,
            expectedTeamIdentifier: team
        )
        return (files, signer, reader, policy)
    }

    private func verifier(
        _ files: FakeHelperFiles,
        _ signer: FakeHelperSigner,
        _ reader: FakeHelperReader,
        _ policy: HelperInstallPolicy
    ) -> HelperInstallVerifier {
        HelperInstallVerifier(policy: policy, files: files, signatures: signer, reader: reader)
    }

    func testRootOwnedSignedHelperIsAccepted() throws {
        let (files, signer, reader, policy) = try installFixture()
        let accepted = try verifier(files, signer, reader, policy).verify()
        XCTAssertEqual(accepted.helperPath, helperPath)
        XCTAssertEqual(accepted.teamIdentifier, team)
        XCTAssertEqual(signer.staticChecks, [helperPath])
        XCTAssertEqual(
            signer.lastRequirement,
            "anchor apple generic and identifier \"dev.hotspotshade.mac.helper\" and certificate leaf[subject.OU] = \"ABCDEFGHIJ\" and \(signingClauses) and !entitlement[\"com.apple.security.get-task-allow\"] and !entitlement[\"com.apple.security.cs.disable-library-validation\"] and !entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"]"
        )
    }

    func testUserOwnedHelperIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        files.identities[helperPath] = file(owner: 501)
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .executableNotOwnedByRoot)
        }
    }

    func testGroupWritableHelperIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        files.identities[helperPath] = file(mode: 0o775)
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .executableWritable)
        }
    }

    func testSymlinkHelperIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        files.identities[helperPath] = file(regular: false, symlink: true)
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .executableNotRegularFile)
        }
    }

    func testWriteACLOnHelperIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        files.writableACL.insert(helperPath)
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .executableWritable)
        }
    }

    func testWriteACLOnInstallDirectoryIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        files.writableACL.insert(root)
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .unsafeParentDirectory)
        }
    }

    func testRootOwnedCopyRequiresItsLaunchDaemon() throws {
        let (files, signer, reader, _) = try installFixture()
        let policy = HelperInstallPolicy(
            layout: .rootOwnedCopy,
            helperPath: helperPath,
            launchDaemonPlistPath: nil,
            expectedTeamIdentifier: team
        )
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .launchDaemonPlistMissing)
        }
    }

    func testWriteACLOnLaunchDaemonIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        files.writableACL.insert(plistPath)
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .launchDaemonPlistUnsafe)
        }
    }

    func testAdHocSignatureIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        signer.infos[helperPath] = HelperSigningInfo(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: nil,
            isAdHoc: true
        )
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .signatureRejected)
        }
    }

    func testAdHocStaticSignatureIsRejected() {
        let signer = FakeHelperSigner()
        signer.staticFailure = .signatureRejected
        XCTAssertThrowsError(
            try signer.verifyStaticCode(
                atPath: HelperRequirement.helperExecutablePath,
                requirement: HelperRequirement.makeSelf(identifier: HelperRequirement.helperIdentifier)
            )
        ) { XCTAssertEqual($0 as? HelperTrustError, .signatureRejected) }
    }

    func testMissingOrInvalidTeamIdentityFailsClosed() throws {
        let (files, signer, reader, _) = try installFixture()
        for team in ["", "SHORT", "ABCDE-FGHI", "ABCDEFGHI;"] {
            let policy = HelperInstallPolicy(
                layout: .rootOwnedCopy,
                helperPath: helperPath,
                launchDaemonPlistPath: nil,
                expectedTeamIdentifier: team
            )
            XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
                XCTAssertEqual($0 as? HelperTrustError, .invalidSigningPolicy)
            }
        }
    }

    func testHelperOutsideProtectedRootIsRejected() throws {
        let (files, signer, reader, _) = try installFixture()
        let outside = "/Users/example/helper"
        files.identities[outside] = file(owner: 501)
        files.canonical[outside] = outside
        let policy = HelperInstallPolicy(
            layout: .rootOwnedCopy,
            helperPath: outside,
            launchDaemonPlistPath: nil,
            expectedTeamIdentifier: team
        )
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .unsafeInstallRoot)
        }
    }

    func testLaunchDaemonMustNameThisHelper() throws {
        let helper = HelperRequirement.helperExecutablePath
        let valid = try validPlist(helperPath: helper)
        XCTAssertNoThrow(
            try HelperLaunchDaemonPolicy.validate(
                plistData: valid,
                helperPath: helper,
                serviceName: HelperRequirement.helperServiceName
            )
        )
        let other: [String: Any] = [
            "Label": HelperRequirement.helperServiceName,
            "ProgramArguments": ["/tmp/evil"],
            "MachServices": [HelperRequirement.helperServiceName: true],
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: other, format: .xml, options: 0)
        XCTAssertThrowsError(
            try HelperLaunchDaemonPolicy.validate(
                plistData: data,
                helperPath: helper,
                serviceName: HelperRequirement.helperServiceName
            )
        ) { XCTAssertEqual($0 as? HelperTrustError, .launchDaemonPlistMismatch) }
    }

    func testRunningCallerMustSatisfyTheExactTeamRequirement() throws {
        let signer = FakeHelperSigner()
        let policy = try HelperCallerPolicy(teamIdentifier: team)
        let authorizer = HelperCallerAuthorizer(policy: policy, checker: signer)
        let token = try XCTUnwrap(HelperAuditToken(
            bytes: [UInt8](repeating: 7, count: HelperAuditToken.byteCount),
            processIdentifier: 4242,
            sessionIdentifier: 9001
        ))
        let caller = try authorizer.authorize(auditToken: token)
        XCTAssertEqual(caller.processIdentifier, 4242)
        XCTAssertEqual(caller.sessionIdentifier, 9001)
        XCTAssertEqual(signer.lastProcessIdentifier, 4242)
        XCTAssertEqual(signer.lastAuditToken, token.bytes)
        XCTAssertEqual(
            signer.lastRequirement,
            "anchor apple generic and identifier \"dev.hotspotshade.mac\" and certificate leaf[subject.OU] = \"ABCDEFGHIJ\" and \(signingClauses) and !entitlement[\"com.apple.security.get-task-allow\"] and !entitlement[\"com.apple.security.cs.disable-library-validation\"] and !entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"]"
        )

        signer.runningFailure = .callerRejected
        XCTAssertThrowsError(try authorizer.authorize(auditToken: token)) {
            XCTAssertEqual($0 as? HelperTrustError, .callerRejected)
        }
    }

    func testAuthorizerRejectsAnIncompleteAuditToken() throws {
        let signer = FakeHelperSigner()
        let policy = try HelperCallerPolicy(teamIdentifier: team)
        let authorizer = HelperCallerAuthorizer(policy: policy, checker: signer)
        XCTAssertNil(HelperAuditToken(bytes: [0, 1, 2], processIdentifier: 4242))
        XCTAssertNil(HelperAuditToken(
            bytes: [UInt8](repeating: 0, count: HelperAuditToken.byteCount),
            processIdentifier: 0
        ))
        XCTAssertNil(HelperAuditToken(
            bytes: [UInt8](repeating: 0, count: HelperAuditToken.byteCount),
            processIdentifier: -1
        ))
        let withoutSession = try XCTUnwrap(HelperAuditToken(
            bytes: [UInt8](repeating: 0, count: HelperAuditToken.byteCount),
            processIdentifier: 1
        ))
        XCTAssertThrowsError(try authorizer.authorize(auditToken: withoutSession)) {
            XCTAssertEqual($0 as? HelperTrustError, .callerRejected)
        }
        let valid = try XCTUnwrap(HelperAuditToken(
            bytes: [UInt8](repeating: 0, count: HelperAuditToken.byteCount),
            processIdentifier: 1,
            sessionIdentifier: 1
        ))
        XCTAssertNoThrow(try authorizer.authorize(auditToken: valid))
    }

    func testAuditTokenReadsTheSessionWordWithTheDocumentedPositions() throws {
        var words = [UInt32](repeating: 0, count: 8)
        words[HelperAuditToken.processIdentifierWord] = 4242
        words[HelperAuditToken.sessionIdentifierWord] = 9001
        XCTAssertEqual(HelperAuditToken.processIdentifier(fromWords: words), 4242)
        XCTAssertEqual(HelperAuditToken.sessionIdentifier(fromWords: words), 9001)
        words[HelperAuditToken.sessionIdentifierWord] = 0
        XCTAssertNil(HelperAuditToken.sessionIdentifier(fromWords: words))
        XCTAssertNil(HelperAuditToken.sessionIdentifier(fromWords: [1, 2, 3]))
    }

    func testHardenedRuntimeIsRequired() throws {
        let (files, signer, reader, policy) = try installFixture()
        signer.infos[helperPath] = HelperSigningInfo(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: team,
            isAdHoc: false,
            hasHardenedRuntime: false
        )
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .signatureRejected)
        }
    }

    func testDebuggerEntitlementIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        signer.infos[helperPath] = HelperSigningInfo(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: team,
            isAdHoc: false,
            hasHardenedRuntime: true,
            allowsDebugging: true
        )
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .signatureRejected)
        }
    }

    func testRequirementRejectsInjectedValues() {
        XCTAssertThrowsError(try HelperRequirement.make(identifier: "dev.hotspotshade.mac\" or true", teamIdentifier: team))
        XCTAssertThrowsError(try HelperRequirement.make(identifier: "dev.hotspotshade.mac", teamIdentifier: "ABCDEFGH\" or true"))
        XCTAssertThrowsError(try HelperRequirement.make(identifier: "", teamIdentifier: team))
        XCTAssertThrowsError(try HelperCallerPolicy(teamIdentifier: ""))
    }

    private func bundleFixture() -> (FakeHelperFiles, FakeHelperSigner, HelperInstallPolicy) {
        let app = "/Applications/HotspotShade.app"
        let helper = app + "/Contents/MacOS/HotspotShadeHelper"
        let files = FakeHelperFiles()
        for path in ["/", "/Applications", app, app + "/Contents", app + "/Contents/MacOS"] {
            files.identities[path] = file(mode: 0o755, regular: false, directory: true)
            files.canonical[path] = path
        }
        // A normal app bundle can be root:admin. The group cannot write, so it
        // is still a boundary. A 0775 /Applications is rejected separately.
        files.identities[app] = file(group: 20, mode: 0o755, regular: false, directory: true)
        files.identities[helper] = file(group: 20, mode: 0o755)
        files.canonical[helper] = helper
        let signer = FakeHelperSigner()
        signer.infos[app] = HelperSigningInfo(
            identifier: HelperRequirement.appIdentifier,
            teamIdentifier: team,
            isAdHoc: false, hasHardenedRuntime: true
        )
        signer.infos[helper] = HelperSigningInfo(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: team,
            isAdHoc: false, hasHardenedRuntime: true
        )
        let policy = HelperInstallPolicy(
            layout: .signedAppBundle(appBundlePath: app),
            helperPath: helper,
            launchDaemonPlistPath: nil,
            expectedTeamIdentifier: team
        )
        return (files, signer, policy)
    }

    func testSignedAppBundleIsAcceptedWhenEveryParentIsProtected() throws {
        let (files, signer, policy) = bundleFixture()
        let accepted = try HelperInstallVerifier(
            policy: policy,
            files: files,
            signatures: signer,
            reader: FakeHelperReader()
        ).verify()
        XCTAssertEqual(accepted.helperPath, policy.helperPath)
        XCTAssertEqual(accepted.layout, policy.layout)
    }

    func testWritableApplicationsDirectoryRejectsTheBundle() throws {
        let (files, signer, policy) = bundleFixture()
        files.identities["/Applications"] = file(
            group: 20, mode: 0o775, regular: false, directory: true
        )
        XCTAssertThrowsError(
            try HelperInstallVerifier(
                policy: policy,
                files: files,
                signatures: signer,
                reader: FakeHelperReader()
            ).verify()
        ) { XCTAssertEqual($0 as? HelperTrustError, .unsafeParentDirectory) }
    }

    func testUserOwnedAppBundleIsRejected() throws {
        let (files, signer, policy) = bundleFixture()
        files.identities["/Applications/HotspotShade.app"] = file(
            owner: 501, group: 20, mode: 0o755, regular: false, directory: true
        )
        XCTAssertThrowsError(
            try HelperInstallVerifier(
                policy: policy,
                files: files,
                signatures: signer,
                reader: FakeHelperReader()
            ).verify()
        ) { XCTAssertEqual($0 as? HelperTrustError, .bundleNotOwnedByRoot) }
    }

    func testExpectedTeamComesFromTheRunningAppSignature() throws {
        let signer = FakeHelperSigner()
        let app = "/Applications/HotspotShade.app"
        signer.infos[app] = HelperSigningInfo(
            identifier: HelperRequirement.appIdentifier,
            teamIdentifier: team,
            isAdHoc: false, hasHardenedRuntime: true
        )
        XCTAssertEqual(
            try HelperInstallPolicy.developerTeamIdentifier(
                bundlePath: app,
                signatures: signer
            ),
            team
        )
        signer.infos[app] = HelperSigningInfo(
            identifier: HelperRequirement.appIdentifier,
            teamIdentifier: nil,
            isAdHoc: true
        )
        XCTAssertThrowsError(
            try HelperInstallPolicy.developerTeamIdentifier(
                bundlePath: app,
                signatures: signer
            )
        ) { XCTAssertEqual($0 as? HelperTrustError, .missingSigningIdentity) }
    }

    func testRootOwnedEngineVerifierRejectsUserOwnedEngine() throws {
        let files = FakeHelperFiles()
        let engineRoot = "/Library/Application Support/HotspotShade/engine"
        let engine = engineRoot + "/hotspotshade"
        for path in ["/", "/Library", "/Library/Application Support", "/Library/Application Support/HotspotShade", engineRoot] {
            files.identities[path] = file(mode: 0o755, regular: false, directory: true)
            files.canonical[path] = path
        }
        files.identities[engine] = file(owner: 501)
        files.canonical[engine] = engine
        let verifier = RootOwnedExecutableVerifier(files: files, signatures: FakeHelperSigner())
        XCTAssertThrowsError(
            try verifier.verify(
                RootOwnedExecutablePolicy(
                    path: engine,
                    trustedRoot: engineRoot,
                    identifier: HelperRequirement.engineIdentifier,
                    teamIdentifier: team
                )
            )
        ) { XCTAssertEqual($0 as? HelperTrustError, .executableNotOwnedByRoot) }
    }

    func testRootOwnedEngineUnderAnAdminGroupParentIsAccepted() throws {
        let files = FakeHelperFiles()
        let engineRoot = "/Library/Application Support/HotspotShade/engine"
        let engine = engineRoot + "/hotspotshade"
        for path in ["/", "/Library", "/Library/Application Support/HotspotShade", engineRoot] {
            files.identities[path] = file(mode: 0o755, regular: false, directory: true)
            files.canonical[path] = path
        }
        // A stock /Library/Application Support is root:admin 0755. The group
        // cannot write, so it is still a boundary. /Applications is 0775 and
        // is rejected elsewhere.
        files.identities["/Library/Application Support"] = file(
            group: 20, mode: 0o755, regular: false, directory: true
        )
        files.canonical["/Library/Application Support"] = "/Library/Application Support"
        files.identities[engine] = file()
        files.canonical[engine] = engine
        let signer = FakeHelperSigner()
        signer.infos[engine] = HelperSigningInfo(
            identifier: HelperRequirement.engineIdentifier,
            teamIdentifier: team,
            isAdHoc: false, hasHardenedRuntime: true
        )
        let accepted = try RootOwnedExecutableVerifier(files: files, signatures: signer).verify(
            RootOwnedExecutablePolicy(
                path: engine,
                trustedRoot: engineRoot,
                identifier: HelperRequirement.engineIdentifier,
                teamIdentifier: team
            )
        )
        XCTAssertEqual(accepted, engine)
    }

    func testWritableEngineSubdirectoryIsRejected() throws {
        let files = FakeHelperFiles()
        let engineRoot = "/Library/Application Support/HotspotShade/engine"
        let engine = engineRoot + "/hotspotshade"
        for path in ["/", "/Library", "/Library/Application Support", "/Library/Application Support/HotspotShade", engineRoot] {
            files.identities[path] = file(mode: 0o755, regular: false, directory: true)
            files.canonical[path] = path
        }
        files.identities["/Library/Application Support/HotspotShade"] = file(
            mode: 0o775, regular: false, directory: true
        )
        files.identities[engine] = file()
        files.canonical[engine] = engine
        let signer = FakeHelperSigner()
        signer.infos[engine] = HelperSigningInfo(
            identifier: HelperRequirement.engineIdentifier,
            teamIdentifier: team,
            isAdHoc: false, hasHardenedRuntime: true
        )
        XCTAssertThrowsError(
            try RootOwnedExecutableVerifier(files: files, signatures: signer).verify(
                RootOwnedExecutablePolicy(
                    path: engine,
                    trustedRoot: engineRoot,
                    identifier: HelperRequirement.engineIdentifier,
                    teamIdentifier: team
                )
            )
        ) { XCTAssertEqual($0 as? HelperTrustError, .unsafeParentDirectory) }
    }

    func testRootEngineLauncherFailsClosedWithoutRoot() throws {
        if geteuid() == 0 { throw XCTSkip("This check is for an unprivileged test process.") }
        let launcher = RootEngineLauncher(teamIdentifier: team)
        XCTAssertThrowsError(try launcher.launch(holding: nil)) {
            XCTAssertEqual($0 as? HelperTrustError, .requiresRoot)
        }
    }

    func testWriteACLOnRootEngineIsRejected() throws {
        let files = FakeHelperFiles()
        let engineRoot = "/Library/Application Support/HotspotShade/engine"
        let engine = engineRoot + "/hotspotshade"
        for path in ["/", "/Library", "/Library/Application Support", "/Library/Application Support/HotspotShade", engineRoot] {
            files.identities[path] = file(mode: 0o755, regular: false, directory: true)
            files.canonical[path] = path
        }
        files.identities[engine] = file()
        files.canonical[engine] = engine
        files.writableACL.insert(engine)
        let signer = FakeHelperSigner()
        signer.infos[engine] = HelperSigningInfo(
            identifier: HelperRequirement.engineIdentifier,
            teamIdentifier: team,
            isAdHoc: false, hasHardenedRuntime: true
        )
        XCTAssertThrowsError(
            try RootOwnedExecutableVerifier(files: files, signatures: signer).verify(
                RootOwnedExecutablePolicy(
                    path: engine,
                    trustedRoot: engineRoot,
                    identifier: HelperRequirement.engineIdentifier,
                    teamIdentifier: team
                )
            )
        ) { XCTAssertEqual($0 as? HelperTrustError, .executableWritable) }
    }

    func testSessionOwnershipPreventsOneConnectionFromStoppingAnother() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let first = UUID()
        let second = UUID()

        guard case .started(let engine) = controller.start(connection: first) else {
            return XCTFail("The first session must start.")
        }
        XCTAssertEqual(engine.port, 5353)
        XCTAssertEqual(controller.start(connection: second), .busy)
        XCTAssertEqual(controller.stop(connection: second, reason: .user), .stopped)
        XCTAssertEqual(launcher.engine.stopCalls, 0)
        XCTAssertTrue(controller.isRunning)

        XCTAssertEqual(controller.stop(connection: first, reason: .user), .stopped)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertFalse(controller.isRunning)
        XCTAssertEqual(controller.stop(connection: first, reason: .user), .stopped)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
    }

    // A second connection's stop request succeeds at the transport layer but
    // owns nothing. The helper must report that distinction and leave the
    // first connection's engine running.
    func testNonOwningStopReportsNoOwnershipAndLeavesTheEngineRunning() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let first = UUID()
        let second = UUID()
        guard case .started(let session) = controller.start(connection: first) else {
            return XCTFail("The first session must start.")
        }
        let report = controller.stopReportingOwnership(connection: second, reason: .user)
        XCTAssertFalse(report.owned)
        XCTAssertEqual(launcher.engine.stopCalls, 0)
        XCTAssertTrue(controller.isRunning)
        let snapshot = controller.snapshot()
        XCTAssertTrue(snapshot.running)
        XCTAssertFalse(snapshot.stopping)
        XCTAssertEqual(snapshot.currentSession, session.sessionID)
        XCTAssertNil(snapshot.lastSession)
        XCTAssertEqual(snapshot.lastResult, .none)
    }

    func testAnOwnedStopRecordsTheExactSessionResultForAReconnect() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        guard case .started(let session) = controller.start(connection: connection) else {
            return XCTFail("The session must start.")
        }
        let report = controller.stopReportingOwnership(connection: connection, reason: .user)
        XCTAssertTrue(report.owned)
        XCTAssertEqual(report.result, .stopped)
        let snapshot = controller.snapshot()
        XCTAssertFalse(snapshot.running)
        XCTAssertFalse(snapshot.stopping)
        XCTAssertNil(snapshot.currentSession)
        XCTAssertEqual(snapshot.lastSession, session.sessionID)
        XCTAssertEqual(snapshot.lastResult, .stopped)
        // A retry from a new connection can match the same session.
        let retry = controller.stopReportingOwnership(connection: UUID(), reason: .user)
        XCTAssertFalse(retry.owned)
        XCTAssertEqual(controller.snapshot().lastSession, session.sessionID)
        XCTAssertEqual(controller.snapshot().lastResult, .stopped)
    }

    func testSnapshotExposesAnInFlightLaunch() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        var observed = false
        launcher.duringLaunch = {
            let snapshot = controller.snapshot()
            XCTAssertTrue(snapshot.starting)
            XCTAssertFalse(snapshot.running)
            XCTAssertFalse(snapshot.stopping)
            observed = true
        }
        guard case .started = controller.start(connection: UUID()) else {
            return XCTFail("The session must start.")
        }
        XCTAssertTrue(observed)
        XCTAssertFalse(controller.snapshot().starting)
        XCTAssertTrue(controller.snapshot().running)
    }

    func testSnapshotReportsStoppingDuringADelayedStopAndThenACleanResult() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        guard case .started(let session) = controller.start(connection: connection) else {
            return XCTFail("The session must start.")
        }
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let done = DispatchSemaphore(value: 0)
        let report = Box<HelperSessionController.StopReport>()
        launcher.engine.duringStop = {
            entered.signal()
            release.wait()
        }
        DispatchQueue.global().async {
            report.value = controller.stopReportingOwnership(connection: connection, reason: .user)
            done.signal()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
        let during = controller.snapshot()
        XCTAssertFalse(during.running)
        XCTAssertTrue(during.stopping, "A stop in flight is not a completed stop.")
        XCTAssertNil(during.lastSession)
        XCTAssertEqual(during.lastResult, .none)
        release.signal()
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        let after = controller.snapshot()
        XCTAssertFalse(after.stopping)
        XCTAssertEqual(after.lastSession, session.sessionID)
        XCTAssertEqual(after.lastResult, .stopped)
        XCTAssertTrue(report.value?.owned == true)
    }

    func testConnectionLossStopsOnlyItsOwnEngine() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        _ = controller.start(connection: connection)
        controller.connectionClosed(UUID())
        XCTAssertEqual(launcher.engine.stopCalls, 0)
        controller.connectionClosed(connection)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertFalse(controller.isRunning)
    }

    func testConnectionClosedDuringLaunchStopsTheLateEngine() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        launcher.duringLaunch = { controller.connectionClosed(connection) }
        XCTAssertEqual(controller.start(connection: connection), .connectionClosed)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertFalse(controller.isRunning)
        // A late start for a closed connection is refused without a launch.
        XCTAssertEqual(controller.start(connection: connection), .connectionClosed)
        XCTAssertEqual(launcher.launches, 1)
    }

    func testCancelDuringLaunchStopsTheLateEngine() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        launcher.duringLaunch = { controller.stop(connection: connection, reason: .cancelled) }
        XCTAssertEqual(controller.start(connection: connection), .cancelled)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertFalse(controller.isRunning)
        // A cancel is not a permanent refusal for the connection.
        launcher.duringLaunch = nil
        guard case .started = controller.start(connection: connection) else {
            return XCTFail("A later start must be allowed after a cancellation.")
        }
    }

    func testStartIsRefusedWhileAStopIsFinishing() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        let other = UUID()
        _ = controller.start(connection: connection)
        // A stop keeps the session slot occupied until the engine exits. A
        // second connection must not start an overlapping engine in that
        // window.
        launcher.engine.duringStop = {
            XCTAssertEqual(controller.start(connection: other), .busy)
        }
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .stopped)
        XCTAssertEqual(launcher.launches, 1)
        XCTAssertFalse(controller.isRunning)
    }

    func testShutdownDuringLaunchStopsTheLateEngine() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        let shutdownDone = DispatchSemaphore(value: 0)
        // Shutdown runs on another thread, as the helper signal handler does.
        // The launch waits until the controller has closed, so this launch is
        // guaranteed to finish after shutdown began. It must stop its late
        // engine instead of serving a helper that is leaving.
        launcher.duringLaunch = {
            DispatchQueue.global().async {
                _ = controller.shutDown()
                shutdownDone.signal()
            }
            let deadline = Date().addingTimeInterval(5)
            while !controller.isShutDown, Date() < deadline {
                usleep(1_000)
            }
        }
        XCTAssertEqual(controller.start(connection: connection), .connectionClosed)
        XCTAssertEqual(shutdownDone.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertFalse(controller.isRunning)
        // A start after shutdown is refused without another launch.
        XCTAssertEqual(controller.start(connection: UUID()), .cancelled)
        XCTAssertEqual(launcher.launches, 1)
    }

    func testLauncherStopTimeoutBlocksEveryLaterStart() {
        let launcher = FakeEngineLauncher()
        launcher.failure = .engineStopTimedOut
        let controller = makeController(launcher)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertFalse(controller.isRunning)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 1)
    }

    func testTimedOutStopBlocksTheNextStart() {
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .timedOut
        let controller = makeController(launcher)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .cancelled), .timedOut)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 1)
    }

    func testEngineDescriptionRedactsTheLaunchSecret() {
        let engine = HelperEngineDescription(port: 5353, secret: "distinct-test-value")
        XCTAssertFalse(String(describing: engine).contains("distinct-test-value"))
        XCTAssertFalse(String(reflecting: engine).contains("distinct-test-value"))
    }

    func testLaunchFailureDoesNotCreateASession() {
        let launcher = FakeEngineLauncher()
        launcher.failure = .engineStartFailed
        let controller = makeController(launcher)
        XCTAssertEqual(controller.start(connection: UUID()), .launchFailed)
        XCTAssertFalse(controller.isRunning)
        XCTAssertFalse(controller.requiresCleanup)
    }

    func testShutdownStopsTheOwnedEngine() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        _ = controller.start(connection: UUID())
        XCTAssertEqual(controller.shutDown(), .stopped)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertFalse(controller.isRunning)
    }

    func testClientRefusesToConnectWhenInstallTrustFails() throws {
        let (files, signer, reader, _) = try installFixture()
        files.identities[helperPath] = file(owner: 501)
        let policy = HelperInstallPolicy(
            layout: .rootOwnedCopy,
            helperPath: helperPath,
            launchDaemonPlistPath: nil,
            expectedTeamIdentifier: team
        )
        let counter = TransportFactoryCounter()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in
            counter.calls += 1
            return FakeHelperTransport()
        }
        XCTAssertThrowsError(try client.connect()) {
            XCTAssertEqual($0 as? HelperTrustError, .executableNotOwnedByRoot)
        }
        XCTAssertEqual(counter.calls, 0)
        XCTAssertEqual(client.state, .disconnected)
    }

    func testClientStartsAndStopsThroughAnAuthenticatedTransport() throws {
        let (files, signer, reader, policy) = try installFixture()
        let counter = TransportFactoryCounter()
        let transport = FakeHelperTransport()
        transport.reply = HelperStartReply(port: 4444, secret: "distinct-test-value")
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in
            counter.calls += 1
            return transport
        }
        _ = try client.connect()
        XCTAssertEqual(counter.calls, 1)
        XCTAssertEqual(transport.handshakeCalls, 1)
        let reply = try client.start()
        XCTAssertEqual(reply, transport.reply)
        XCTAssertEqual(reply.port, 4444)
        XCTAssertEqual(reply.secret, "distinct-test-value")
        XCTAssertEqual(client.state, .running(reply))
        XCTAssertEqual(transport.lastServerNonce, transport.handshakeReply.serverNonce)
        XCTAssertEqual(transport.events, ["handshake", "start"])
        // One handshake authorizes one start. A second start without a new
        // connect must not reuse the nonce.
        XCTAssertThrowsError(try client.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .handshakeRequired)
        }
        XCTAssertFalse(String(describing: reply).contains("distinct-test-value"))
        XCTAssertFalse(String(reflecting: reply).contains("distinct-test-value"))
        client.stop()
        XCTAssertEqual(transport.stopCalls, 1)
        XCTAssertEqual(client.state, .disconnected)
        client.close()
        XCTAssertEqual(transport.closeCalls, 1)
    }

    func testClientDoesNotReportANonOwningStopAsClean() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let session = UUID()
        transport.stopReply = HelperStopReply(
            owned: false,
            status: HelperStatus(
                running: true,
                cleanupBlocked: false,
                currentSession: session
            )
        )
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        let reply = client.stop()
        XCTAssertEqual(reply?.owned, false)
        XCTAssertEqual(reply?.status.running, true)
        XCTAssertEqual(client.state, .unavailable(.stopNotConfirmed))
    }

    func testClientReportsANonOwningStopWithAnIdleHelperAsUnconfirmed() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.stopReply = HelperStopReply(
            owned: false,
            status: HelperStatus(running: false, cleanupBlocked: false)
        )
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        XCTAssertEqual(client.stop()?.owned, false)
        XCTAssertEqual(client.state, .unavailable(.stopNotConfirmed))
    }

    func testClientTreatsConnectionLossAsUnavailableAndNeverRestarts() throws {        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        transport.invalidate(.connectionLost)
        XCTAssertEqual(client.state, .unavailable(.helperUnavailable))
        XCTAssertThrowsError(try client.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .notConnected)
        }
        XCTAssertEqual(transport.startCalls, 0)
    }

    func testClientReportsBusyWithoutStoppingTheOtherSession() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.failure = .helperBusy
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        XCTAssertThrowsError(try client.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .helperBusy)
        }
        XCTAssertEqual(transport.stopCalls, 0)
        XCTAssertEqual(client.state, .unavailable(.helperBusy))
    }

    func testClientTimeoutCancelsAndClosesAnAmbiguousStart() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.failure = .helperTimeout
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        XCTAssertTrue(client.isConnected)
        XCTAssertThrowsError(try client.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .helperTimeout)
        }
        // The helper may have started an engine whose reply was lost. Cancel
        // and close, so the helper's connection-loss path stops that engine.
        XCTAssertEqual(transport.cancelCalls, 1)
        XCTAssertEqual(transport.closeCalls, 1)
        XCTAssertEqual(client.state, .unavailable(.helperTimeout))
        XCTAssertFalse(client.isConnected)
        XCTAssertThrowsError(try client.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .notConnected)
        }
        XCTAssertEqual(transport.startCalls, 1)
    }

    func testPreflightAcceptsOnlyVerifiedInstalls() throws {
        let (files, signer, reader, policy) = try installFixture()
        let available = ProtectedHelperPreflight(
            verifier: verifier(files, signer, reader, policy)
        ).evaluate()
        XCTAssertTrue(available.isAvailable)

        let invalid = HelperInstallPolicy(
            layout: .rootOwnedCopy,
            helperPath: helperPath,
            launchDaemonPlistPath: nil,
            expectedTeamIdentifier: "SHORT"
        )
        let unavailable = ProtectedHelperPreflight(
            verifier: verifier(files, signer, reader, invalid)
        ).evaluate()
        XCTAssertEqual(unavailable, .unavailable(.invalidSigningPolicy))
    }

    func testProtectedEngineProcessStartsAndStopsThroughTheClient() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.reply = HelperStartReply(port: 4444, secret: "distinct-test-value")
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start(credentials: 12)
        XCTAssertTrue(engine.isRunning)
        XCTAssertEqual(engine.port, 4444)
        XCTAssertEqual(engine.secret, "distinct-test-value")
        XCTAssertEqual(transport.lastCredentials, 12)
        // Starting the engine changes no route, so it never prompts.
        XCTAssertEqual(authorization.calls, 0)
        XCTAssertEqual(transport.authorizeCalls, 0)
        // The tunnel start is a separate administrator authorization.
        try engine.authorizeStart()
        XCTAssertEqual(authorization.calls, 1)
        XCTAssertEqual(transport.authorizeCalls, 1)
        XCTAssertEqual(transport.lastAuthorization, authorization.form)
        // The lease stays held until the reply arrives, then it is released so
        // the grant is destroyed.
        XCTAssertEqual(authorization.lease?.releases, 1)
        engine.stop()
        XCTAssertFalse(engine.isRunning)
        XCTAssertNil(engine.port)
        XCTAssertEqual(engine.secret, "")
        XCTAssertEqual(transport.handshakeCalls, 2)
        XCTAssertEqual(transport.lastServerNonce, transport.handshakeReply.serverNonce)
        XCTAssertEqual(transport.events, ["handshake", "status", "start", "handshake", "authorize"])
        XCTAssertEqual(transport.stopCalls, 1)
        XCTAssertEqual(transport.closeCalls, 1)
    }

    func testProtectedEngineProcessReturnsTheCleanStopResultBeforeClose() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        XCTAssertEqual(engine.stop(), .stopped)
        XCTAssertEqual(transport.stopCalls, 1)
        XCTAssertEqual(transport.closeCalls, 1)
        XCTAssertEqual(client.state, .disconnected)
        XCTAssertFalse(engine.isRunning)
    }

    func testProtectedEngineProcessReportsACleanupBlockBeforeClose() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        transport.stopFailure = .cleanupBlocked
        let outcome = engine.stop()
        XCTAssertEqual(outcome, .uncertain(Strings.helperCleanup))
        XCTAssertTrue(outcome.isUncertain)
        XCTAssertEqual(transport.closeCalls, 1)
        XCTAssertEqual(client.state, .disconnected, "close() clears the client state after the result is captured.")
    }

    func testProtectedEngineProcessReportsAStopTimeoutAsUncertain() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        transport.stopFailure = .helperTimeout
        let outcome = engine.stop()
        XCTAssertEqual(outcome, .uncertain(EngineLaunchText.stopTimedOut))
        XCTAssertFalse(outcome == .stopped)
        XCTAssertEqual(transport.closeCalls, 1)
    }

    func testProtectedEngineProcessKeepsAnEarlierCleanupBlockWhenStopCannotConnect() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        transport.invalidate(.cleanupBlocked)
        XCTAssertEqual(engine.unavailableReason, .cleanupBlocked)
        XCTAssertTrue(engine.isRunning, "The retained session is still unconfirmed.")
        transport.statusReply = HelperStatus(running: false, cleanupBlocked: true)
        let outcome = engine.stop()
        XCTAssertEqual(outcome, .uncertain(Strings.helperCleanup))
        XCTAssertTrue(outcome.isUncertain)
    }

    func testStartRefusesAfterAnUncertainStop() throws {
        let (files, signer, reader, policy) = try installFixture()
        let first = FakeHelperTransport()
        first.stopFailure = .helperTimeout
        let sequence = TransportSequence([first])
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in try sequence.next() }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        XCTAssertTrue(engine.stop().isUncertain)
        XCTAssertThrowsError(try engine.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .stopNotConfirmed)
        }
        XCTAssertEqual(sequence.callCount, 1, "The refused start must not open a new connection.")
        XCTAssertNotNil(engine.sessionID)
    }

    // An idle helper with a clean record for some other session is not proof
    // that this object's engine stopped. No exact identity means uncertainty.
    func testAForcedCleanupConfirmationRejectsAnUnrelatedCleanSessionRecord() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            lastSession: UUID(),
            lastResult: .stopped
        )
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        XCTAssertEqual(engine.confirmCleanup(force: true), .uncertain(EngineLaunchText.stopUnverified))
        XCTAssertEqual(transport.statusCalls, 1)
    }

    func testAForcedCleanupConfirmationRejectsAnEmptyIdleSnapshot() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.statusReply = HelperStatus(running: false, cleanupBlocked: false)
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        XCTAssertEqual(engine.confirmCleanup(force: true), .uncertain(EngineLaunchText.stopUnverified))
    }

    func testAForcedCleanupConfirmationRejectsALiveOrInFlightSession() throws {
        let (files, signer, reader, policy) = try installFixture()
        let session = UUID()
        for status in [
            HelperStatus(running: true, cleanupBlocked: false, currentSession: session),
            HelperStatus(running: false, cleanupBlocked: false, stopping: true, currentSession: session),
            HelperStatus(running: false, cleanupBlocked: false, starting: true),
            HelperStatus(running: false, cleanupBlocked: true, lastSession: session, lastResult: .stopped),
        ] {
            let transport = FakeHelperTransport()
            transport.statusReply = status
            let client = ProtectedHelperClient(
                verifier: verifier(files, signer, reader, policy)
            ) { _ in transport }
            let engine = ProtectedEngineProcess(
                client: client,
                authorization: FakeAuthorizationProvider(),
                startRightChecker: FakeStartRightChecker()
            )
            XCTAssertTrue(engine.confirmCleanup(force: true).isUncertain, "\(status)")
        }
    }

    func testAStopRetryUsesTheRetainedSessionInsteadOfTheNewConnectionsStop() throws {
        let (files, signer, reader, policy) = try installFixture()
        let first = FakeHelperTransport()
        first.stopFailure = .helperTimeout
        let second = FakeHelperTransport()
        let sequence = TransportSequence([first, second])
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in try sequence.next() }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        let firstOutcome = engine.stop()
        XCTAssertEqual(firstOutcome, .uncertain(EngineLaunchText.stopTimedOut))
        XCTAssertEqual(sequence.callCount, 1)
        XCTAssertEqual(first.stopCalls, 1)
        guard let retainedSession = engine.sessionID else {
            return XCTFail("An uncertain stop must retain the helper session id.")
        }
        // The first stop closed its connection. A retry must reconnect and ask
        // about the retained session. The new connection owns nothing, so its
        // own stop acknowledgement is not used.
        second.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            stopping: false,
            currentSession: nil,
            lastSession: retainedSession,
            lastResult: .stopped
        )
        let secondOutcome = engine.stop()
        XCTAssertEqual(secondOutcome, .stopped)
        XCTAssertEqual(sequence.callCount, 2)
        XCTAssertEqual(second.stopCalls, 0)
        XCTAssertEqual(second.statusCalls, 1)
        XCTAssertNil(engine.sessionID)
    }

    // This is the critical case in the review. A new connection asks the helper
    // to stop. The helper answers ok because the request itself succeeded, but
    // it owned nothing and the old engine still runs. That answer must never
    // become a clean stop.
    func testANewConnectionCannotProveACleanStopWhileTheOldEngineRuns() throws {
        let (files, signer, reader, policy) = try installFixture()
        let first = FakeHelperTransport()
        first.stopFailure = .helperTimeout
        let second = FakeHelperTransport()
        let third = FakeHelperTransport()
        let fourth = FakeHelperTransport()
        let sequence = TransportSequence([first, second, third, fourth])
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in try sequence.next() }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        XCTAssertTrue(engine.stop().isUncertain)
        guard let session = engine.sessionID else {
            return XCTFail("The uncertain stop must retain the session id.")
        }
        second.statusReply = HelperStatus(
            running: true,
            cleanupBlocked: false,
            stopping: false,
            currentSession: session,
            lastSession: nil,
            lastResult: .none
        )
        let running = engine.stop()
        XCTAssertEqual(running, .uncertain(EngineLaunchText.stopUnverified))
        XCTAssertEqual(engine.sessionID, session, "A live old engine keeps the session retained.")
        // A stop that is still in flight is not a completed stop either.
        third.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            stopping: true,
            currentSession: session,
            lastSession: nil,
            lastResult: .none
        )
        XCTAssertEqual(engine.stop(), .uncertain(EngineLaunchText.stopUnverified))
        XCTAssertEqual(engine.sessionID, session)
        // Only the helper's completed record for this exact session is proof.
        fourth.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            stopping: false,
            currentSession: nil,
            lastSession: session,
            lastResult: .stopped
        )
        XCTAssertEqual(engine.stop(), .stopped)
        XCTAssertNil(engine.sessionID)
        XCTAssertEqual(second.stopCalls, 0)
        XCTAssertEqual(third.stopCalls, 0)
        XCTAssertEqual(fourth.stopCalls, 0)
    }

    func testANewConnectionWithoutTheRetainedSessionStaysUncertain() throws {
        let (files, signer, reader, policy) = try installFixture()
        let first = FakeHelperTransport()
        first.stopFailure = .helperTimeout
        let second = FakeHelperTransport()
        let sequence = TransportSequence([first, second])
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in try sequence.next() }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        XCTAssertTrue(engine.stop().isUncertain)
        guard let session = engine.sessionID else {
            return XCTFail("The uncertain stop must retain the session id.")
        }
        // A helper restart forgets its session record. An empty idle snapshot
        // is not proof for the session that the old connection started.
        second.statusReply = HelperStatus(running: false, cleanupBlocked: false)
        XCTAssertEqual(engine.stop(), .uncertain(EngineLaunchText.stopUnverified))
        XCTAssertEqual(engine.sessionID, session)
    }

    func testANewConnectionCannotClearAnUnpromptedEngineExit() throws {
        let (files, signer, reader, policy) = try installFixture()
        let first = FakeHelperTransport()
        first.stopFailure = .helperTimeout
        let second = FakeHelperTransport()
        let sequence = TransportSequence([first, second])
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in try sequence.next() }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        XCTAssertTrue(engine.stop().isUncertain)
        guard let session = engine.sessionID else {
            return XCTFail("The uncertain stop must retain the session id.")
        }
        second.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            lastSession: session,
            lastResult: .engineExited
        )
        XCTAssertEqual(engine.stop(), .uncertain(EngineLaunchText.stopUnclean))
    }

    func testAStopRetryThatCannotReconnectStaysUncertain() throws {
        let (files, signer, reader, policy) = try installFixture()
        let first = FakeHelperTransport()
        first.stopFailure = .helperTimeout
        let sequence = TransportSequence([first], failAfter: 1)
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in try sequence.next() }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        XCTAssertTrue(engine.stop().isUncertain)
        let retry = engine.stop()
        XCTAssertEqual(retry, .uncertain(EngineLaunchText.stopTimedOut))
        XCTAssertTrue(retry.isUncertain)
        XCTAssertEqual(sequence.callCount, 2, "The retry tried a new connection, and its failure stayed uncertain.")
    }

    func testProtectedEngineProcessStartsWithoutAuthorizationWhenTheStartWasAlreadyCancelled() throws {
        let (files, signer, reader, policy) = try installFixture()
        let counter = TransportFactoryCounter()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in
            counter.calls += 1
            return FakeHelperTransport()
        }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        let cancellation = EngineLaunchCancellation()
        cancellation.cancel()
        XCTAssertThrowsError(try engine.start(cancellation: cancellation)) {
            XCTAssertEqual($0 as? HelperTrustError, .cancelled)
        }
        XCTAssertEqual(counter.calls, 0, "A cancelled start must not connect to the helper.")
        XCTAssertEqual(authorization.calls, 0, "Starting the engine must not request authorization.")
        XCTAssertFalse(engine.isRunning)
    }

    func testProtectedEngineProcessChecksCancellationAfterStatusBeforeTheStartRequest() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        let cancellation = EngineLaunchCancellation()
        transport.duringStatus = { cancellation.cancel() }
        XCTAssertThrowsError(try engine.start(cancellation: cancellation)) {
            XCTAssertEqual($0 as? HelperTrustError, .cancelled)
        }
        XCTAssertEqual(transport.statusCalls, 1)
        XCTAssertEqual(authorization.calls, 0, "Starting the engine must not request authorization.")
        XCTAssertEqual(transport.startCalls, 0)
        XCTAssertEqual(transport.closeCalls, 1)
        XCTAssertFalse(engine.isRunning)
    }

    func testProtectedEngineProcessReleasesTheGrantWhenTheTunnelAuthorizationFails() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        transport.authorizeFailure = .helperBusy
        XCTAssertThrowsError(try engine.authorizeStart()) {
            XCTAssertEqual($0 as? HelperTrustError, .helperBusy)
        }
        XCTAssertEqual(authorization.lease?.releases, 1)
        XCTAssertEqual(transport.authorizeCalls, 1)
        // A failed tunnel authorization does not stop the engine. The person
        // can try the tunnel start again.
        XCTAssertTrue(engine.isRunning)
        engine.stop()
    }

    func testProtectedEngineProcessDoesNotPromptWhenTheEngineIsNotRunning() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        XCTAssertThrowsError(try engine.authorizeStart()) {
            XCTAssertEqual($0 as? HelperTrustError, .tunnelNotRunning)
        }
        XCTAssertEqual(authorization.calls, 0)
        XCTAssertEqual(transport.authorizeCalls, 0)
    }

    func testProtectedEngineProcessDoesNotReachTheHelperWithoutAuthorization() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        authorization.failure = .notAuthorized
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        XCTAssertThrowsError(try engine.authorizeStart()) {
            XCTAssertEqual($0 as? HelperTrustError, .notAuthorized)
        }
        XCTAssertEqual(transport.authorizeCalls, 0)
        XCTAssertTrue(engine.isRunning)
        engine.stop()
    }

    func testProtectedEngineProcessHandshakesBeforeSendingTheAuthorization() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        transport.handshakeFailure = .responseRejected
        XCTAssertThrowsError(try engine.authorizeStart()) {
            XCTAssertEqual($0 as? HelperTrustError, .responseRejected)
        }
        XCTAssertEqual(transport.handshakeCalls, 2)
        XCTAssertEqual(authorization.calls, 0, "A failed handshake must not open an administrator prompt.")
        XCTAssertEqual(transport.authorizeCalls, 0)
        XCTAssertNil(transport.lastAuthorization)
        XCTAssertTrue(engine.isRunning)
        engine.stop()
    }

    func testProtectedEngineProcessDoesNotPromptWhenTheHelperIsBusy() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.statusReply = HelperStatus(running: true, cleanupBlocked: false)
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        XCTAssertThrowsError(try engine.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .helperBusy)
        }
        XCTAssertEqual(transport.statusCalls, 1)
        XCTAssertEqual(authorization.calls, 0, "A busy helper must not show a prompt.")
        XCTAssertEqual(transport.startCalls, 0)
        XCTAssertFalse(engine.isRunning)
    }

    func testProtectedEngineProcessDoesNotPromptWhenCleanupIsBlocked() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.statusReply = HelperStatus(running: false, cleanupBlocked: true)
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        XCTAssertThrowsError(try engine.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .cleanupBlocked)
        }
        XCTAssertEqual(authorization.calls, 0, "A blocked helper must not show a prompt.")
        XCTAssertEqual(transport.startCalls, 0)
        // The failed start closes the handshake. The helper still owns the
        // durable cleanup block, and the app shows the thrown cleanup error.
        XCTAssertEqual(client.state, .disconnected)
        XCTAssertEqual(transport.closeCalls, 1)
        XCTAssertFalse(engine.isRunning)
    }

    func testProtectedEngineProcessFailsClosedWhenTheHelperStatusIsUnavailable() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.statusFailure = .helperTimeout
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        XCTAssertThrowsError(try engine.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .helperTimeout)
        }
        XCTAssertEqual(authorization.calls, 0, "An unknown helper state must not show a prompt.")
        XCTAssertEqual(transport.startCalls, 0)
        XCTAssertFalse(engine.isRunning)
    }

    func testProtectedEngineProcessRefusesAMissingStartRightBeforePrompting() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let rights = FakeStartRightChecker()
        rights.failure = .startRightNotConfigured
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: rights
        )
        // Starting the engine is not gated by the administrator right.
        try engine.start()
        XCTAssertThrowsError(try engine.authorizeStart()) {
            XCTAssertEqual($0 as? HelperTrustError, .startRightNotConfigured)
        }
        XCTAssertEqual(rights.calls, 1)
        XCTAssertEqual(authorization.calls, 0, "A missing right must not open a prompt.")
        XCTAssertEqual(transport.authorizeCalls, 0)
        XCTAssertTrue(engine.isRunning)
        engine.stop()
    }

    func testProtectedEngineProcessDoesNotConnectWhenInstallTrustFails() throws {
        let (files, signer, reader, _) = try installFixture()
        files.identities[helperPath] = file(owner: 501)
        let policy = HelperInstallPolicy(
            layout: .rootOwnedCopy,
            helperPath: helperPath,
            launchDaemonPlistPath: plistPath,
            expectedTeamIdentifier: team
        )
        let counter = TransportFactoryCounter()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in
            counter.calls += 1
            return FakeHelperTransport()
        }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        XCTAssertThrowsError(try engine.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .executableNotOwnedByRoot)
        }
        XCTAssertFalse(engine.isRunning)
        XCTAssertNil(engine.port)
        XCTAssertEqual(counter.calls, 0)
    }

    // MARK: - Start authorization

    private func helperForm(_ byte: UInt8 = 0x33) -> Data {
        Data(repeating: byte, count: HelperStartAuthorizationPolicy.externalFormByteCount)
    }

    private func authorizationGate(
        checker: FakeAuthorizationFormChecker,
        launcher: FakeEngineLauncher,
        rightChecker: FakeStartRightChecker = FakeStartRightChecker()
    ) -> (HelperStartGate, HelperSessionController) {
        let controller = makeController(launcher)
        let verifier = AuthorizationServicesStartAuthorizationVerifier(checker: checker)
        return (
            HelperStartGate(verifier: verifier, rightChecker: rightChecker, controller: controller),
            controller
        )
    }

    func testEngineStartGateLaunchesWithoutAuthorization() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        let (gate, controller) = authorizationGate(checker: checker, launcher: launcher)
        let connection = UUID()

        guard case .started = gate.startEngine(connection: connection) else {
            return XCTFail("Starting the engine must not need an administrator form.")
        }
        XCTAssertEqual(checker.calls, 0)
        XCTAssertEqual(launcher.launches, 1)
        XCTAssertTrue(controller.isRunning)
    }

    func testEngineStartGateDoesNotPromptWhenTheControllerWouldRefuse() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        let (gate, _) = authorizationGate(checker: checker, launcher: launcher)
        let first = UUID()
        guard case .started = gate.startEngine(connection: first) else {
            return XCTFail("The first start must launch.")
        }
        XCTAssertEqual(gate.startEngine(connection: UUID()), .busy)
        XCTAssertEqual(checker.calls, 0, "The engine start gate never shows an authorization prompt.")
    }

    func testAuthorizationGateRefusesWithoutAuthorizationAndWritesNoGrant() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        checker.failure = .notAuthorized
        let (gate, controller) = authorizationGate(checker: checker, launcher: launcher)
        let connection = UUID()
        _ = gate.startEngine(connection: connection)

        XCTAssertEqual(gate.authorize(connection: connection, form: helperForm()), .notAuthorized)
        XCTAssertEqual(checker.calls, 1)
        XCTAssertEqual(launcher.engine.authorizeCalls, 0)
        XCTAssertTrue(controller.isRunning)
        // The refusal leaves the engine running, so a later authorization
        // works without a helper restart.
        checker.failure = nil
        XCTAssertEqual(gate.authorize(connection: connection, form: helperForm()), .authorized)
        XCTAssertEqual(launcher.engine.authorizeCalls, 1)
    }

    func testAuthorizationGateChecksTheFixedRightAndFormWithoutLaunching() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        let (gate, _) = authorizationGate(checker: checker, launcher: launcher)
        let connection = UUID()
        _ = gate.startEngine(connection: connection)
        let form = helperForm(0x5a)

        XCTAssertEqual(gate.authorize(connection: connection, form: form), .authorized)
        XCTAssertEqual(launcher.launches, 1)
        XCTAssertEqual(checker.rights, [HelperStartAuthorizationPolicy.startRight])
        XCTAssertEqual(checker.forms, [[UInt8](form)])
        XCTAssertEqual(launcher.engine.authorizeCalls, 1)
    }

    func testAuthorizationGateRejectsAMalformedFormBeforeAnyWrite() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        let (gate, controller) = authorizationGate(checker: checker, launcher: launcher)
        let connection = UUID()
        _ = gate.startEngine(connection: connection)
        for form in [Data(), Data(repeating: 0x01, count: 31), Data(repeating: 0x01, count: 33)] {
            XCTAssertEqual(gate.authorize(connection: connection, form: form), .notAuthorized)
        }
        // Empty also covers a missing message field.
        XCTAssertEqual(checker.calls, 0)
        XCTAssertEqual(launcher.engine.authorizeCalls, 0)
        XCTAssertTrue(controller.isRunning)
    }

    func testAuthorizationGateReportsABusyAuthorizationPrompt() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        checker.failure = .authorizationBusy
        let (gate, _) = authorizationGate(checker: checker, launcher: launcher)
        let connection = UUID()
        _ = gate.startEngine(connection: connection)
        // The production checker maps every failure to refusal; a busy prompt
        // is reported by the authorizer seam and never becomes a success.
        XCTAssertEqual(gate.authorize(connection: connection, form: helperForm()), .notAuthorized)
        XCTAssertEqual(launcher.engine.authorizeCalls, 0)
    }

    func testAuthorizationGateRefusesWithoutAnEngineSession() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        let (gate, _) = authorizationGate(checker: checker, launcher: launcher)
        XCTAssertEqual(gate.authorize(connection: UUID(), form: helperForm()), .notRunning)
        XCTAssertEqual(checker.calls, 1)
        XCTAssertEqual(launcher.engine.authorizeCalls, 0)
    }

    func testAuthorizationGateReportsAGrantWriteFailure() {
        let launcher = FakeEngineLauncher()
        launcher.engine.authorizeFailure = HelperTrustError.grantFailed
        let checker = FakeAuthorizationFormChecker()
        let (gate, controller) = authorizationGate(checker: checker, launcher: launcher)
        let connection = UUID()
        _ = gate.startEngine(connection: connection)
        XCTAssertEqual(gate.authorize(connection: connection, form: helperForm()), .grantFailed)
        XCTAssertEqual(launcher.engine.authorizeCalls, 1)
        XCTAssertTrue(controller.isRunning, "A grant failure does not stop the engine.")
    }

    // MARK: - Authorization deadline

    private func deadlineGate(
        checker: FakeAuthorizationFormChecker,
        launcher: FakeEngineLauncher,
        clock: ManualClock,
        intent: TestLaunchIntentStore = TestLaunchIntentStore(),
        exclusion: TestStartExclusion = TestStartExclusion()
    ) -> (HelperStartGate, HelperSessionController) {
        let controller = makeDeadlineController(launcher, clock: clock, intent: intent, exclusion: exclusion)
        let verifier = AuthorizationServicesStartAuthorizationVerifier(checker: checker)
        return (
            HelperStartGate(verifier: verifier, rightChecker: FakeStartRightChecker(), controller: controller),
            controller
        )
    }

    func testAnUnauthorizedSessionStopsAtTheAuthorizationDeadline() {
        XCTAssertEqual(HelperAuthorizationDeadline.unauthorizedSession, 120)
        XCTAssertEqual(HelperAuthorizationDeadline.timeoutReason, "authorization_timeout")
        let clock = ManualClock()
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        let exclusion = TestStartExclusion()
        let (gate, controller) = deadlineGate(
            checker: FakeAuthorizationFormChecker(),
            launcher: launcher,
            clock: clock,
            intent: intent,
            exclusion: exclusion
        )
        let connection = UUID()
        guard case .started(let session) = gate.startEngine(connection: connection) else {
            return XCTFail("The engine must start without a prompt.")
        }

        // Inside the bound the session stays, so the person can still answer.
        clock.advance(HelperAuthorizationDeadline.unauthorizedSession - 1)
        XCTAssertNil(controller.expireUnauthorizedSession())
        XCTAssertTrue(controller.isRunning)
        XCTAssertEqual(launcher.engine.stopCalls, 0)

        clock.advance(1)
        let expired = controller.expireUnauthorizedSession()
        XCTAssertEqual(
            expired,
            HelperSessionController.ExpiredSession(
                connection: connection,
                sessionID: session.sessionID,
                result: .stopped
            )
        )
        // The normal stop path ran once: the engine stop closes the parent
        // descriptor and sends SIGTERM. A clean stop clears the intent and
        // releases the shared lock like a user stop.
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertFalse(controller.isRunning)
        XCTAssertFalse(controller.isStopping)
        XCTAssertFalse(intent.present)
        XCTAssertEqual(exclusion.lease.releaseCalls, 1)
        XCTAssertEqual(exclusion.lease.abandonCalls, 0)
        XCTAssertFalse(controller.requiresCleanup)
        // A reconnecting caller reads the same record as for any other stop.
        let snapshot = controller.snapshot()
        XCTAssertEqual(snapshot.lastSession, session.sessionID)
        XCTAssertEqual(snapshot.lastResult, .stopped)
        // The stop is reported once. A late authorization finds no session and
        // writes no grant.
        XCTAssertNil(controller.expireUnauthorizedSession())
        XCTAssertEqual(gate.authorize(connection: connection, form: helperForm()), .notRunning)
        XCTAssertEqual(launcher.engine.authorizeCalls, 0)
        // There is no restart. A new start is a new request and a new session.
        XCTAssertEqual(launcher.launches, 1)
        launcher.engine = FakeRunningEngine()
        guard case .started(let next) = gate.startEngine(connection: connection) else {
            return XCTFail("A clean deadline stop must not block a later start.")
        }
        XCTAssertNotEqual(next.sessionID, session.sessionID)
    }

    func testAVerifiedAuthorizationEndsTheDeadline() {
        let clock = ManualClock()
        let launcher = FakeEngineLauncher()
        let (gate, controller) = deadlineGate(
            checker: FakeAuthorizationFormChecker(),
            launcher: launcher,
            clock: clock
        )
        let connection = UUID()
        _ = gate.startEngine(connection: connection)
        clock.advance(HelperAuthorizationDeadline.unauthorizedSession - 5)
        XCTAssertEqual(gate.authorize(connection: connection, form: helperForm()), .authorized)
        clock.advance(HelperAuthorizationDeadline.unauthorizedSession * 100)
        XCTAssertNil(controller.expireUnauthorizedSession())
        XCTAssertTrue(controller.isRunning)
        XCTAssertEqual(launcher.engine.stopCalls, 0)
    }

    func testARefusedOrFailedAuthorizationDoesNotExtendTheDeadline() {
        for failure in ["refused", "grant"] {
            let clock = ManualClock()
            let launcher = FakeEngineLauncher()
            let checker = FakeAuthorizationFormChecker()
            if failure == "refused" {
                checker.failure = .notAuthorized
            } else {
                launcher.engine.authorizeFailure = HelperTrustError.grantFailed
            }
            let (gate, controller) = deadlineGate(checker: checker, launcher: launcher, clock: clock)
            let connection = UUID()
            _ = gate.startEngine(connection: connection)
            XCTAssertNotEqual(gate.authorize(connection: connection, form: helperForm()), .authorized)
            clock.advance(HelperAuthorizationDeadline.unauthorizedSession)
            XCTAssertEqual(controller.expireUnauthorizedSession()?.connection, connection, failure)
            XCTAssertFalse(controller.isRunning, failure)
            XCTAssertEqual(launcher.engine.stopCalls, 1, failure)
        }
    }

    func testAnUncleanDeadlineStopBlocksLikeAnyOtherStop() {
        let clock = ManualClock()
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .timedOut
        let exclusion = TestStartExclusion()
        let controller = makeDeadlineController(launcher, clock: clock, exclusion: exclusion)
        let connection = UUID()
        guard case .started(let session) = controller.start(connection: connection) else {
            return XCTFail("The engine must start.")
        }
        clock.advance(HelperAuthorizationDeadline.unauthorizedSession)
        XCTAssertEqual(controller.expireUnauthorizedSession()?.result, .timedOut)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(exclusion.lease.abandonCalls, 1)
        XCTAssertEqual(controller.snapshot().lastSession, session.sessionID)
        XCTAssertEqual(controller.snapshot().lastResult, .timedOut)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
    }

    func testAnExitedEngineIsLeftToTheExitPathAtTheDeadline() {
        let clock = ManualClock()
        let launcher = FakeEngineLauncher()
        let controller = makeDeadlineController(launcher, clock: clock)
        let connection = UUID()
        _ = controller.start(connection: connection)
        launcher.engine.isRunning = false
        clock.advance(HelperAuthorizationDeadline.unauthorizedSession)
        // An engine that exited on its own is not a clean deadline stop. The
        // exit path records the cleanup block instead.
        XCTAssertNil(controller.expireUnauthorizedSession())
        XCTAssertEqual(controller.reapExitedEngine(), connection)
        XCTAssertEqual(controller.snapshot().lastResult, .engineExited)
    }

    func testAuthorizationGateRefusesAMissingRightWithoutCallingSecurity() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        let rights = FakeStartRightChecker()
        rights.failure = .startRightNotConfigured
        let (gate, _) = authorizationGate(checker: checker, launcher: launcher, rightChecker: rights)
        let connection = UUID()
        _ = gate.startEngine(connection: connection)
        XCTAssertEqual(gate.authorize(connection: connection, form: helperForm()), .notConfigured)
        XCTAssertEqual(rights.calls, 1)
        XCTAssertEqual(checker.calls, 0)
        XCTAssertEqual(launcher.engine.authorizeCalls, 0)
    }

    func testAuthorizationPolicyUsesOneFixedRightAndNoFallback() {
        XCTAssertEqual(HelperStartAuthorizationPolicy.startRight, "dev.hotspotshade.tunnel.start")
        XCTAssertEqual(HelperStartAuthorizationPolicy.externalFormByteCount, 32)
        XCTAssertTrue(HelperStartAuthorizationPolicy.requestFlags.contains(.interactionAllowed))
        XCTAssertTrue(HelperStartAuthorizationPolicy.requestFlags.contains(.extendRights))
        XCTAssertFalse(HelperStartAuthorizationPolicy.verifyFlags.contains(.interactionAllowed))
        XCTAssertFalse(HelperStartAuthorizationPolicy.verifyFlags.contains(.extendRights))
        XCTAssertTrue(HelperStartAuthorizationPolicy.prompt.contains("administrator"))
        // A zero timeout is the live failure, so it must stay outside the
        // reviewed window, and the canonical value must stay inside it.
        XCTAssertFalse(HelperStartAuthorizationPolicy.isStartRightTimeout(0))
        XCTAssertTrue(
            HelperStartAuthorizationPolicy.isStartRightTimeout(
                HelperStartAuthorizationPolicy.startRightTimeoutSeconds
            )
        )
    }

    func testAppAuthorizationKeepsCancellationDistinctFromADenial() {
        XCTAssertEqual(
            HelperStartAuthorizationPolicy.trustError(forAuthorizationStatus: errAuthorizationCanceled),
            .cancelled
        )
        XCTAssertEqual(
            HelperStartAuthorizationPolicy.trustError(forAuthorizationStatus: errAuthorizationDenied),
            .notAuthorized
        )
    }

    func testAppAuthorizationRejectsAMalformedCreatorForm() throws {
        let creator = FakeAuthorizationCreator()
        creator.form = Data(repeating: 0x01, count: 31)
        let provider = AuthorizationServicesStartAuthorization(creator: creator)
        XCTAssertThrowsError(try provider.beginStartAuthorization()) {
            XCTAssertEqual($0 as? HelperTrustError, .notAuthorized)
        }
        XCTAssertEqual(creator.calls, 1)
        XCTAssertEqual(creator.lease?.releases, 1)

        creator.form = helperForm()
        let lease = try provider.beginStartAuthorization()
        XCTAssertEqual(lease.externalForm, helperForm())
        XCTAssertEqual(creator.lastRight, HelperStartAuthorizationPolicy.startRight)
        XCTAssertEqual(creator.lastPrompt, HelperStartAuthorizationPolicy.prompt)
    }

    func testAppAuthorizationNeverInventsAFormWithoutTheSystemGrant() {
        let creator = FakeAuthorizationCreator()
        creator.failure = .notAuthorized
        let provider = AuthorizationServicesStartAuthorization(creator: creator)
        XCTAssertThrowsError(try provider.beginStartAuthorization()) {
            XCTAssertEqual($0 as? HelperTrustError, .notAuthorized)
        }
        XCTAssertNil(creator.lease)
    }

    func testHelperAuthorizationRejectsAWrongLengthFormWithoutCallingSecurity() {
        let checker = FakeAuthorizationFormChecker()
        let verifier = AuthorizationServicesStartAuthorizationVerifier(checker: checker)
        XCTAssertThrowsError(try verifier.verify(Data())) {
            XCTAssertEqual($0 as? HelperTrustError, .notAuthorized)
        }
        XCTAssertThrowsError(try verifier.verify(Data(repeating: 0, count: 31))) {
            XCTAssertEqual($0 as? HelperTrustError, .notAuthorized)
        }
        XCTAssertThrowsError(try verifier.verify(Data(repeating: 0, count: 4096))) {
            XCTAssertEqual($0 as? HelperTrustError, .notAuthorized)
        }
        XCTAssertEqual(checker.calls, 0)
    }

    func testHelperAuthorizationPassesTheFixedRightAndFailsClosed() throws {
        let checker = FakeAuthorizationFormChecker()
        let verifier = AuthorizationServicesStartAuthorizationVerifier(checker: checker)
        try verifier.verify(helperForm(0x77))
        XCTAssertEqual(checker.calls, 1)
        XCTAssertEqual(checker.rights, [HelperStartAuthorizationPolicy.startRight])
        XCTAssertEqual(checker.forms, [[UInt8](helperForm(0x77))])

        checker.failure = .notAuthorized
        XCTAssertThrowsError(try verifier.verify(helperForm())) {
            XCTAssertEqual($0 as? HelperTrustError, .notAuthorized)
        }
    }

    // MARK: - Cleanup block, handshake, right configuration, and runtime files

    func testFailedStopSetsADurableBlockAndRefusesLaterStarts() {
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .failed
        let store = TestCleanupBlockStore()
        let controller = makeController(launcher, store: store)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .failed)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(store.records.count, 1)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 1)
    }

    func testDurableBlockSurvivesAControllerRestartAndIsNeverCleared() {
        let store = TestCleanupBlockStore()
        store.blocked = true
        store.records = ["earlier run"]
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher, store: store)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
        // A later successful inspect is still a block. There is no automatic
        // clear, so a second controller also refuses.
        let second = makeController(launcher, store: store)
        XCTAssertTrue(second.requiresCleanup)
        XCTAssertEqual(second.start(connection: UUID()), .cleanupBlocked)
        XCTAssertTrue(store.blocked)
    }

    func testUnreadableDurableBlockFailsClosed() {
        let store = TestCleanupBlockStore()
        store.readFailure = HelperCleanupBlockError.unreadable
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher, store: store)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
    }

    func testUncleanLateEngineBlocksEveryLaterStart() {
        let launcher = FakeEngineLauncher()
        launcher.failure = .engineExitUnclean
        let store = TestCleanupBlockStore()
        let controller = makeController(launcher, store: store)
        // The launcher spawned an engine that exited before it reported a
        // port. That is not proof of cleanup, so the start is refused and the
        // block is durable.
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(store.records.count, 1)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 1)
    }

    func testBlockPersistenceFailureStillRefusesStarts() {
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .failed
        let store = TestCleanupBlockStore()
        store.writeFailure = HelperCleanupBlockError.writeFailed
        let controller = makeController(launcher, store: store)
        let connection = UUID()
        _ = controller.start(connection: connection)
        _ = controller.stop(connection: connection, reason: .user)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertTrue(controller.cleanupPersistenceFailed)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
    }

    // MARK: - Write-ahead launch intent

    func testLaunchIntentIsDurableBeforeSpawnAndBlocksAfterARestart() {
        let launcher = FakeEngineLauncher()
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        var sawIntentDuringLaunch = false
        launcher.duringLaunch = { sawIntentDuringLaunch = intent.present }
        let controller = makeController(launcher, store: store, intent: intent)
        guard case .started = controller.start(connection: UUID()) else {
            return XCTFail("The session must start.")
        }
        XCTAssertTrue(sawIntentDuringLaunch, "The intent must exist before the launcher runs.")
        XCTAssertTrue(intent.present)

        // A helper crash leaves the intent behind. A new controller must refuse
        // every start even though the cleanup marker is absent.
        let restarted = makeController(launcher, store: store, intent: intent)
        XCTAssertTrue(restarted.requiresCleanup)
        XCTAssertEqual(restarted.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 1)
    }

    // A record that another participant owns is re-read. A direct engine that
    // exits cleanly removes its record, so the helper must not keep a refusal
    // that was latched when the record was present.
    func testAnObservedIntentIsRecheckedAfterAConcurrentDirectStartExits() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        intent.present = true
        let controller = makeController(launcher, intent: intent)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertEqual(intent.createCalls, 0)
        XCTAssertTrue(intent.present)

        // The direct engine finished its own cleanup and removed the record.
        intent.present = false
        XCTAssertFalse(controller.requiresCleanup)
        guard case .started = controller.start(connection: UUID()) else {
            return XCTFail("A cleaned external record must not block the next start.")
        }
        XCTAssertEqual(launcher.launches, 1)
        XCTAssertTrue(intent.present, "The helper now owns the launch intent.")
    }

    // The create can fail because a concurrent direct engine created the same
    // record after this controller was built. That record is also re-read.
    func testAnIntentCreatedAfterControllerStartIsRecheckedAfterItExits() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        let controller = makeController(launcher, intent: intent)
        intent.present = true

        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(intent.createCalls, 1)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertTrue(controller.requiresCleanup)

        intent.present = false
        XCTAssertFalse(controller.requiresCleanup)
        guard case .started = controller.start(connection: UUID()) else {
            return XCTFail("A cleaned external record must not block the next start.")
        }
        XCTAssertEqual(launcher.launches, 1)
    }

    // A record that this helper could not clear is its own cleanup
    // uncertainty. An absent re-read must never clear it.
    func testAnUncertainIntentIsNeverClearedByAnAbsentRecheck() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        intent.clearFailure = HelperLaunchIntentError.writeFailed
        let controller = makeController(launcher, intent: intent)
        let connection = UUID()
        guard case .started = controller.start(connection: connection) else {
            return XCTFail("The session must start.")
        }
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .stopped)
        XCTAssertTrue(intent.present)
        XCTAssertTrue(controller.requiresCleanup)

        // Simulate an external or operator removal after the failed clear. The
        // helper still cannot prove that its own engine cleaned up, so the
        // gate stays closed.
        intent.clearFailure = nil
        intent.present = false
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 1)
    }

    // An unreadable re-read is not evidence that the record is gone.
    func testAnUnreadableRecheckKeepsAnObservedIntentBlocked() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        intent.present = true
        let controller = makeController(launcher, intent: intent)
        intent.readFailure = HelperLaunchIntentError.unreadable
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
    }

    func testCleanStopClearsTheLaunchIntentAndAllowsALaterStart() {
        let launcher = FakeEngineLauncher()
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        let controller = makeController(launcher, store: store, intent: intent)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .stopped)
        XCTAssertFalse(intent.present)
        XCTAssertEqual(intent.clearCalls, 1)
        XCTAssertEqual(intent.clearSawPresent, [true])
        XCTAssertFalse(controller.requiresCleanup)

        // A helper restart after a verified clean stop starts normally.
        let restarted = makeController(launcher, store: store, intent: intent)
        guard case .started = restarted.start(connection: UUID()) else {
            return XCTFail("A clean stop must not leave a block.")
        }
    }

    func testUncleanStopKeepsTheLaunchIntentAndBlocksAfterARestart() {
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .failed
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        let controller = makeController(launcher, store: store, intent: intent)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .failed)
        XCTAssertTrue(intent.present)
        XCTAssertEqual(intent.clearCalls, 0)
        XCTAssertTrue(store.blocked)
        XCTAssertTrue(controller.requiresCleanup)

        let restarted = makeController(launcher, store: store, intent: intent)
        XCTAssertEqual(restarted.start(connection: UUID()), .cleanupBlocked)
    }

    func testTimedOutStopKeepsTheLaunchIntent() {
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .timedOut
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        let controller = makeController(launcher, store: store, intent: intent)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .timedOut)
        XCTAssertTrue(intent.present)
        XCTAssertEqual(intent.clearCalls, 0)
        XCTAssertTrue(controller.requiresCleanup)
    }

    func testLaunchThatProvesNoEngineClearsTheIntent() {
        let launcher = FakeEngineLauncher()
        launcher.failure = .engineStartFailed
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        let controller = makeController(launcher, store: store, intent: intent)
        XCTAssertEqual(controller.start(connection: UUID()), .launchFailed)
        XCTAssertFalse(intent.present)
        XCTAssertEqual(intent.clearCalls, 1)
        XCTAssertFalse(controller.requiresCleanup)
        // The next start is allowed because the failed launch proved that no
        // engine survived it.
        launcher.failure = nil
        guard case .started = controller.start(connection: UUID()) else {
            return XCTFail("A proven failed launch must not block the next start.")
        }
    }

    func testUncleanLaunchKeepsTheIntentAndBlocks() {
        let launcher = FakeEngineLauncher()
        launcher.failure = .engineExitUnclean
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        let controller = makeController(launcher, store: store, intent: intent)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertTrue(intent.present)
        XCTAssertEqual(intent.clearCalls, 0)
        XCTAssertTrue(controller.requiresCleanup)
        let restarted = makeController(launcher, store: store, intent: intent)
        XCTAssertEqual(restarted.start(connection: UUID()), .cleanupBlocked)
    }

    func testUnknownLaunchFailureDoesNotAssumeAnEngineIsAbsent() {
        struct AmbiguousLaunchFailure: Error {}
        let launcher = FakeEngineLauncher()
        launcher.anyFailure = AmbiguousLaunchFailure()
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        let controller = makeController(launcher, store: store, intent: intent)
        // An error that is not a known pre-spawn or clean-stop result must not
        // clear the intent or allow a later start.
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertTrue(intent.present)
        XCTAssertEqual(intent.clearCalls, 0)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 1)
    }

    func testIntentWriteFailurePreventsTheLaunch() {
        let launcher = FakeEngineLauncher()
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        intent.createFailure = HelperLaunchIntentError.writeFailed
        let controller = makeController(launcher, store: store, intent: intent)
        XCTAssertEqual(controller.start(connection: UUID()), .launchFailed)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertEqual(intent.createCalls, 1)
        // The store reports that no intent remains, so a later attempt is
        // allowed. A read error or a present intent would block instead.
        XCTAssertFalse(controller.requiresCleanup)
    }

    func testIntentReadFailureBlocksEveryStart() {
        let launcher = FakeEngineLauncher()
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        intent.readFailure = HelperLaunchIntentError.unreadable
        let controller = makeController(launcher, store: store, intent: intent)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
    }

    // A create rollback that kept ambiguous state is the helper's own
    // uncertainty. A later absence read must not clear it, and the controller
    // must not try to delete the record.
    func testIntentRollbackUncertaintyBlocksEvenWhenTheRecordReadsAbsent() {
        let launcher = FakeEngineLauncher()
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        intent.createFailure = HelperLaunchIntentError.rollbackUncertain
        let controller = makeController(launcher, store: store, intent: intent)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertEqual(intent.createCalls, 1)
        XCTAssertEqual(intent.clearCalls, 0)
        XCTAssertTrue(controller.requiresCleanup)

        // The fake store would now allow a retry, but the latched uncertainty
        // is never re-evaluated.
        intent.createFailure = nil
        XCTAssertFalse(intent.present)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertEqual(intent.createCalls, 1)
        XCTAssertEqual(intent.clearCalls, 0)
    }

    // A rollback that kept a safe record from another participant is not this
    // helper's uncertainty. It is re-read after that participant removes it.
    func testIntentRetainedForeignRecordIsRecheckedAfterItIsRemoved() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        intent.present = true
        intent.createFailure = HelperLaunchIntentError.alreadyPresent
        let controller = makeController(launcher, intent: intent)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertTrue(controller.requiresCleanup)

        intent.present = false
        intent.createFailure = nil
        XCTAssertFalse(controller.requiresCleanup)
        guard case .started = controller.start(connection: UUID()) else {
            return XCTFail("A removed foreign record must not block the next start.")
        }
        XCTAssertEqual(launcher.launches, 1)
    }

    func testUnpromptedEngineExitKeepsTheIntentEvenWhenTheStopLooksClean() {
        let launcher = FakeEngineLauncher()
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        let controller = makeController(launcher, store: store, intent: intent)
        let connection = UUID()
        guard case .started = controller.start(connection: connection) else {
            return XCTFail("The session must start.")
        }
        launcher.engine.isRunning = false
        launcher.engine.stopResult = .stopped
        XCTAssertEqual(controller.reapExitedEngine(), connection)
        // An exit that nobody requested is not proof that the engine removed
        // its routes, so the intent stays for a person to inspect.
        XCTAssertTrue(intent.present)
        XCTAssertEqual(intent.clearCalls, 0)
        XCTAssertTrue(controller.requiresCleanup)
        let restarted = makeController(launcher, store: store, intent: intent)
        XCTAssertEqual(restarted.start(connection: UUID()), .cleanupBlocked)
    }

    // MARK: - Start exclusion and install journal

    func testStartExclusionIsPreparedBeforeTheIntentAndLaunch() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        let exclusion = TestStartExclusion()
        var sawPreparedDuringLaunch = false
        var sawIntentDuringLaunch = false
        launcher.duringLaunch = {
            sawPreparedDuringLaunch = exclusion.prepareCalls == 1
            sawIntentDuringLaunch = intent.present
        }
        let controller = makeController(launcher, intent: intent, exclusion: exclusion)
        let connection = UUID()
        guard case .started = controller.start(connection: connection) else {
            return XCTFail("The session must start.")
        }
        XCTAssertTrue(sawPreparedDuringLaunch, "The shared lock must exist before spawn.")
        XCTAssertTrue(sawIntentDuringLaunch, "The launch intent must exist before spawn.")
        XCTAssertEqual(exclusion.prepareSessions, [connection])
        XCTAssertEqual(launcher.lastHandoff, exclusion.lease.handoff)
    }

    func testStartExclusionBusyRefusesBeforeTheIntent() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        let exclusion = TestStartExclusion()
        exclusion.prepareFailure = HelperStartExclusionError.busy
        let controller = makeController(launcher, intent: intent, exclusion: exclusion)
        XCTAssertEqual(controller.start(connection: UUID()), .startExclusionBusy)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertEqual(intent.createCalls, 0)
        XCTAssertFalse(controller.requiresCleanup)
    }

    func testStartExclusionUnavailableRefusesBeforeTheIntent() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        let exclusion = TestStartExclusion()
        exclusion.prepareFailure = HelperStartExclusionError.unavailable
        let controller = makeController(launcher, intent: intent, exclusion: exclusion)
        XCTAssertEqual(controller.start(connection: UUID()), .startExclusionUnavailable)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertEqual(intent.createCalls, 0)
    }

    func testAnExistingInstallJournalBlocksEveryStart() {
        let launcher = FakeEngineLauncher()
        let exclusion = TestStartExclusion()
        exclusion.installJournalPresent = true
        let controller = makeController(launcher, exclusion: exclusion)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.preflightStart(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 0)
    }

    func testInstallJournalPrepareRaceBlocksWithoutLaunch() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        let exclusion = TestStartExclusion()
        exclusion.prepareFailure = HelperStartExclusionError.installJournalPresent
        let controller = makeController(launcher, intent: intent, exclusion: exclusion)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(launcher.launches, 0)
        XCTAssertEqual(intent.createCalls, 0)
    }

    func testPreflightProbeRefusesWhileTheExclusiveLockIsHeld() {
        let launcher = FakeEngineLauncher()
        let exclusion = TestStartExclusion()
        exclusion.probe = .busy
        let controller = makeController(launcher, exclusion: exclusion)
        XCTAssertEqual(
            controller.preflightStart(connection: UUID()),
            .startExclusionBusy
        )
        XCTAssertEqual(launcher.launches, 0)
    }

    func testPreflightProbeReportsAnUnavailableExclusionState() {
        let launcher = FakeEngineLauncher()
        let exclusion = TestStartExclusion()
        exclusion.probe = .unavailable
        let controller = makeController(launcher, exclusion: exclusion)
        XCTAssertEqual(
            controller.preflightStart(connection: UUID()),
            .startExclusionUnavailable
        )
        XCTAssertEqual(launcher.launches, 0)
    }

    func testCleanStopReleasesTheExclusionLease() {
        let launcher = FakeEngineLauncher()
        let exclusion = TestStartExclusion()
        let controller = makeController(launcher, exclusion: exclusion)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .stopped)
        XCTAssertEqual(exclusion.lease.releaseCalls, 1)
        XCTAssertEqual(exclusion.lease.abandonCalls, 0)
    }

    func testFailedStopRetainsTheExclusionLease() {
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .failed
        let exclusion = TestStartExclusion()
        let controller = makeController(launcher, exclusion: exclusion)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .failed)
        XCTAssertEqual(exclusion.lease.releaseCalls, 0)
        XCTAssertEqual(exclusion.lease.abandonCalls, 1)
        XCTAssertTrue(controller.requiresCleanup)
    }

    func testUnpromptedEngineExitRetainsTheExclusionLease() {
        let launcher = FakeEngineLauncher()
        let exclusion = TestStartExclusion()
        let controller = makeController(launcher, exclusion: exclusion)
        let connection = UUID()
        _ = controller.start(connection: connection)
        launcher.engine.isRunning = false
        XCTAssertEqual(controller.reapExitedEngine(), connection)
        XCTAssertEqual(exclusion.lease.releaseCalls, 0)
        XCTAssertEqual(exclusion.lease.abandonCalls, 1)
    }

    func testLaunchFailureReleasesTheExclusionLease() {
        let launcher = FakeEngineLauncher()
        launcher.failure = .engineStartFailed
        let exclusion = TestStartExclusion()
        let controller = makeController(launcher, exclusion: exclusion)
        XCTAssertEqual(controller.start(connection: UUID()), .launchFailed)
        XCTAssertEqual(exclusion.lease.releaseCalls, 1)
        XCTAssertEqual(exclusion.lease.abandonCalls, 0)
    }

    func testFailedIntentClearAfterACleanStopReleasesButBlocks() {
        let launcher = FakeEngineLauncher()
        let intent = TestLaunchIntentStore()
        intent.clearFailure = HelperLaunchIntentError.writeFailed
        let exclusion = TestStartExclusion()
        let controller = makeController(launcher, intent: intent, exclusion: exclusion)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .stopped)
        // The engine stopped cleanly, so the shared lock can be released. The
        // durable intent remains and refuses every later start.
        XCTAssertEqual(exclusion.lease.releaseCalls, 1)
        XCTAssertEqual(exclusion.lease.abandonCalls, 0)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
    }

    func testUncleanLaunchRetainsTheExclusionLease() {
        let launcher = FakeEngineLauncher()
        launcher.failure = .engineExitUnclean
        let exclusion = TestStartExclusion()
        let controller = makeController(launcher, exclusion: exclusion)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(exclusion.lease.abandonCalls, 1)
        XCTAssertTrue(controller.requiresCleanup)
    }

    func testFailedIntentClearAfterACleanStopBlocksEveryLaterStart() {
        let launcher = FakeEngineLauncher()
        let store = TestCleanupBlockStore()
        let intent = TestLaunchIntentStore()
        intent.clearFailure = HelperLaunchIntentError.writeFailed
        let controller = makeController(launcher, store: store, intent: intent)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .stopped)
        XCTAssertTrue(intent.present)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
    }

    func testCancelDuringLaunchStopsTheLateEngineAndBlocksOnAnUncleanStop() {
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .failed
        let store = TestCleanupBlockStore()
        let controller = makeController(launcher, store: store)
        let connection = UUID()
        launcher.duringLaunch = { controller.stop(connection: connection, reason: .cancelled) }
        // The cancel reply reports the request as cancelled. The engine may
        // have spawned before the cancel was observed, so the late engine is
        // stopped and never served. An unclean late stop is a cleanup block.
        XCTAssertEqual(controller.start(connection: connection), .cancelled)
        XCTAssertFalse(controller.isRunning)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(store.records.count, 1)
    }

    func testRootCleanupBlockStorePersistsWithoutAutomaticDeletion() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let store = RootCleanupBlockStore(
            directoryPath: state,
            fileName: "cleanup-blocked",
            expectedOwner: geteuid()
        )
        XCTAssertFalse(try store.isBlocked())
        try store.recordBlock(reason: "hermetic test")
        XCTAssertTrue(try store.isBlocked())
        let second = RootCleanupBlockStore(
            directoryPath: state,
            fileName: "cleanup-blocked",
            expectedOwner: geteuid()
        )
        XCTAssertTrue(try second.isBlocked())
        // No API clears it. Removing the file is a person's explicit action.
        try FileManager.default.removeItem(atPath: store.markerPath)
        XCTAssertFalse(try store.isBlocked())
    }

    func testRootCleanupBlockStoreRejectsASymlinkMarker() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        try FileManager.default.createDirectory(atPath: state, withIntermediateDirectories: false)
        chmod(state, 0o700)
        let target = root + "/other"
        try Data("not a marker".utf8).write(to: URL(fileURLWithPath: target))
        XCTAssertEqual(symlink(target, state + "/cleanup-blocked"), 0)
        let store = RootCleanupBlockStore(
            directoryPath: state,
            fileName: "cleanup-blocked",
            expectedOwner: geteuid()
        )
        XCTAssertThrowsError(try store.isBlocked())
    }

    func testRootCleanupBlockStoreRejectsAWorldWritableDirectory() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        try FileManager.default.createDirectory(atPath: state, withIntermediateDirectories: false)
        chmod(state, 0o777)
        let store = RootCleanupBlockStore(
            directoryPath: state,
            fileName: "cleanup-blocked",
            expectedOwner: geteuid()
        )
        XCTAssertThrowsError(try store.isBlocked()) {
            XCTAssertEqual($0 as? HelperCleanupBlockError, .unsafe)
        }
    }

    func testRootCleanupBlockStoreRejectsAReadableMarkerAndWritableReuse() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let store = RootCleanupBlockStore(
            directoryPath: state,
            fileName: "cleanup-blocked",
            expectedOwner: geteuid()
        )
        try store.recordBlock(reason: "hermetic test")
        // The marker must stay owner-only. Another program that leaves it
        // group or other readable is not evidence that the host is clean.
        XCTAssertEqual(chmod(store.markerPath, 0o644), 0)
        XCTAssertThrowsError(try store.isBlocked()) {
            XCTAssertEqual($0 as? HelperCleanupBlockError, .unsafe)
        }
        // Recording a block must not accept the weaker file either.
        XCTAssertThrowsError(try store.recordBlock(reason: "second")) {
            XCTAssertEqual($0 as? HelperCleanupBlockError, .unsafe)
        }
    }

    func testRootCleanupBlockStoreRejectsAnExtendedACLMarker() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let store = RootCleanupBlockStore(
            directoryPath: state,
            fileName: "cleanup-blocked",
            expectedOwner: geteuid()
        )
        try store.recordBlock(reason: "hermetic test")
        XCTAssertTrue(ProtectedHelperTestSupport.addExtendedACL(to: store.markerPath))
        XCTAssertThrowsError(try store.isBlocked()) {
            XCTAssertEqual($0 as? HelperCleanupBlockError, .unsafe)
        }
        XCTAssertThrowsError(try store.recordBlock(reason: "second")) {
            XCTAssertEqual($0 as? HelperCleanupBlockError, .unsafe)
        }
    }

    func testRootCleanupBlockStoreCreatesTheMarkerWithOwnerOnlyPermissions() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let store = RootCleanupBlockStore(
            directoryPath: state,
            fileName: "cleanup-blocked",
            expectedOwner: geteuid()
        )
        try store.recordBlock(reason: "hermetic test")
        var marker = stat()
        XCTAssertEqual(lstat(store.markerPath, &marker), 0)
        XCTAssertEqual(marker.st_mode & 0o777, 0o600)
        var directory = stat()
        XCTAssertEqual(lstat(state, &directory), 0)
        XCTAssertEqual(directory.st_mode & 0o777, 0o700)
    }

    // MARK: - Root launch intent store

    func testRootLaunchIntentStoreIsDurableAndClearedAfterACleanStop() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid()
        )
        XCTAssertFalse(try store.isPresent())
        try store.create()
        XCTAssertTrue(try store.isPresent())

        var intent = stat()
        XCTAssertEqual(lstat(store.intentPath, &intent), 0)
        XCTAssertEqual(intent.st_mode & 0o777, 0o600)
        var directory = stat()
        XCTAssertEqual(lstat(state, &directory), 0)
        XCTAssertEqual(directory.st_mode & 0o777, 0o700)

        // A restart reads the same durable file. It must not overwrite it.
        let second = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid()
        )
        XCTAssertTrue(try second.isPresent())
        XCTAssertThrowsError(try second.create()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .alreadyPresent)
        }
        // Only a verified clean stop clears it. Clearing an absent file is
        // already clean.
        try second.clearAfterVerifiedCleanStop()
        XCTAssertFalse(try store.isPresent())
        XCTAssertNoThrow(try second.clearAfterVerifiedCleanStop())
    }

    func testRootLaunchIntentStoreRejectsASymlink() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        try FileManager.default.createDirectory(atPath: state, withIntermediateDirectories: false)
        chmod(state, 0o700)
        let target = root + "/other"
        try Data("not an intent".utf8).write(to: URL(fileURLWithPath: target))
        XCTAssertEqual(symlink(target, state + "/engine-session"), 0)
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid()
        )
        XCTAssertThrowsError(try store.isPresent()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
        XCTAssertThrowsError(try store.clearAfterVerifiedCleanStop()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: target))
    }

    func testRootLaunchIntentStoreRejectsAReadableIntentAndUnsafeDirectory() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid()
        )
        try store.create()
        XCTAssertEqual(chmod(store.intentPath, 0o644), 0)
        XCTAssertThrowsError(try store.isPresent()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
        XCTAssertThrowsError(try store.clearAfterVerifiedCleanStop()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: store.intentPath))

        let unsafeRoot = root + "/unsafe"
        try FileManager.default.createDirectory(atPath: unsafeRoot, withIntermediateDirectories: false)
        chmod(unsafeRoot, 0o777)
        let unsafeStore = RootLaunchIntentStore(
            directoryPath: unsafeRoot,
            fileName: "engine-session",
            expectedOwner: geteuid()
        )
        XCTAssertThrowsError(try unsafeStore.isPresent()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
        XCTAssertThrowsError(try unsafeStore.create()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
    }

    func testRootLaunchIntentStoreRefusesANonRegularIntent() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        try FileManager.default.createDirectory(atPath: state, withIntermediateDirectories: false)
        chmod(state, 0o700)
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid()
        )
        try FileManager.default.createDirectory(
            atPath: store.intentPath,
            withIntermediateDirectories: false
        )
        XCTAssertThrowsError(try store.isPresent()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
        XCTAssertThrowsError(try store.clearAfterVerifiedCleanStop()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
    }

    // MARK: - Launch intent create rollback

    // A deterministic create failure with an unchanged record removes only the
    // inode this call created.
    func testRootLaunchIntentStoreRollsBackItsOwnRecordAfterACreateFailure() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        var seam = RootStateDirectorySeam.production
        seam.writeAll = { _, _ in throw RootStateDirectoryError.writeFailed }
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid(),
            seam: seam
        )
        XCTAssertThrowsError(try store.create()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .writeFailed)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.intentPath))
        XCTAssertFalse(try store.isPresent())
    }

    // A replacement from another participant is a different inode. The
    // rollback must compare the held descriptor with the name and keep the
    // replacement instead of unlinking it by name.
    func testRootLaunchIntentStoreKeepsAReplacementRecord() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let intentPath = state + "/engine-session"
        let movedPath = state + "/moved-record"
        var moved = false
        var replacement = false
        var seam = RootStateDirectorySeam.production
        seam.writeAll = { _, _ in throw RootStateDirectoryError.writeFailed }
        seam.beforeRollback = { _ in
            moved = intentPath.withCString { source in
                movedPath.withCString { destination in
                    rename(source, destination) == 0
                }
            }
            replacement = self.writeOwnerOnlyFile(intentPath, contents: "foreign record\n")
        }
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid(),
            seam: seam
        )
        XCTAssertThrowsError(try store.create()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .alreadyPresent)
        }
        XCTAssertTrue(moved)
        XCTAssertTrue(replacement)
        XCTAssertEqual(
            try String(contentsOfFile: intentPath, encoding: .utf8),
            "foreign record\n"
        )
        // The record this call created was moved aside by the other
        // participant. The rollback leaves both objects in place.
        XCTAssertTrue(FileManager.default.fileExists(atPath: movedPath))
        XCTAssertTrue(try store.isPresent())
    }

    // A record that gained a hard link is not provably ours alone. The rollback
    // keeps every name instead of removing one.
    func testRootLaunchIntentStoreKeepsAHardLinkedCreatedRecord() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let intentPath = state + "/engine-session"
        let aliasPath = state + "/linked-record"
        var linked = false
        var seam = RootStateDirectorySeam.production
        seam.writeAll = { _, _ in throw RootStateDirectoryError.writeFailed }
        seam.beforeRollback = { _ in
            linked = intentPath.withCString { source in
                aliasPath.withCString { alias in
                    link(source, alias) == 0
                }
            }
        }
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid(),
            seam: seam
        )
        XCTAssertThrowsError(try store.create()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .rollbackUncertain)
        }
        XCTAssertTrue(linked)
        XCTAssertTrue(FileManager.default.fileExists(atPath: intentPath))
        XCTAssertTrue(FileManager.default.fileExists(atPath: aliasPath))
    }

    // An ACL-bearing record is ambiguous evidence. The rollback keeps it and
    // reports uncertainty instead of deleting the permission-bearing object.
    func testRootLaunchIntentStoreKeepsACreatedRecordWithAnExtendedACL() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let intentPath = state + "/engine-session"
        var aclAdded = false
        var seam = RootStateDirectorySeam.production
        seam.writeAll = { _, _ in throw RootStateDirectoryError.writeFailed }
        seam.beforeRollback = { _ in
            aclAdded = ProtectedHelperTestSupport.addExtendedACL(to: intentPath)
        }
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid(),
            seam: seam
        )
        XCTAssertThrowsError(try store.create()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .rollbackUncertain)
        }
        XCTAssertTrue(aclAdded)
        XCTAssertTrue(FileManager.default.fileExists(atPath: intentPath))
        XCTAssertThrowsError(try store.isPresent()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
    }

    // A removal that reached the live directory but could not be synced is not
    // proof of a durable rollback. The store reports uncertainty even though a
    // later presence read says absent.
    func testRootLaunchIntentStoreReportsUncertaintyWhenTheRollbackIsNotSynced() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        var seam = RootStateDirectorySeam.production
        seam.writeAll = { _, _ in throw RootStateDirectoryError.writeFailed }
        seam.syncDirectory = { _ in -1 }
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid(),
            seam: seam
        )
        XCTAssertThrowsError(try store.create()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .rollbackUncertain)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.intentPath))
        XCTAssertFalse(try store.isPresent())
    }

    // A clean-stop clear refuses a record that gained a hard link, so one name
    // cannot be removed while another still reaches the same inode.
    func testRootLaunchIntentStoreRefusesToRemoveAHardLinkedRecord() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let state = root + "/state"
        let store = RootLaunchIntentStore(
            directoryPath: state,
            fileName: "engine-session",
            expectedOwner: geteuid()
        )
        try store.create()
        let aliasPath = state + "/linked-record"
        XCTAssertEqual(
            store.intentPath.withCString { source in
                aliasPath.withCString { alias in
                    link(source, alias)
                }
            },
            0
        )
        XCTAssertThrowsError(try store.clearAfterVerifiedCleanStop()) {
            XCTAssertEqual($0 as? HelperLaunchIntentError, .unsafe)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: store.intentPath))
        XCTAssertTrue(FileManager.default.fileExists(atPath: aliasPath))
    }

    private func writeOwnerOnlyFile(_ path: String, contents: String) -> Bool {
        let descriptor = path.withCString { pointer in
            Darwin.open(
                pointer,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        let bytes = Array(contents.utf8)
        let written = bytes.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return write(descriptor, base, bytes.count)
        }
        return written == bytes.count
    }

    func testHandshakeGateIssuesOneFreshNoncePerConnection() throws {
        let gate = HelperHandshakeGate()
        let connection = UUID()
        let clientNonce = Data(repeating: 0x11, count: HelperHandshakeGate.nonceByteCount)
        let handshake = try XCTUnwrap(gate.issue(connection: connection, clientNonce: clientNonce))
        XCTAssertEqual(handshake.serverNonce.count, HelperHandshakeGate.nonceByteCount)
        XCTAssertTrue(gate.consume(connection: connection, serverNonce: handshake.serverNonce))
        // One nonce is accepted once. A replay is refused.
        XCTAssertFalse(gate.consume(connection: connection, serverNonce: handshake.serverNonce))
        // A new handshake issues a new value.
        let second = try XCTUnwrap(gate.issue(connection: connection, clientNonce: clientNonce))
        XCTAssertNotEqual(second.serverNonce, handshake.serverNonce)
    }

    func testHandshakeGateRejectsAWrongOrExpiredNonce() throws {
        let clock = Box(Date())
        let fixedNonce = Data(repeating: 0x22, count: HelperHandshakeGate.nonceByteCount)
        let gate = HelperHandshakeGate(now: { clock.value ?? Date() }, makeNonce: { fixedNonce })
        let connection = UUID()
        let handshake = try XCTUnwrap(gate.issue(
            connection: connection,
            clientNonce: Data(repeating: 0x33, count: HelperHandshakeGate.nonceByteCount)
        ))
        XCTAssertFalse(gate.consume(
            connection: connection,
            serverNonce: Data(repeating: 0x44, count: HelperHandshakeGate.nonceByteCount)
        ))
        // The wrong attempt consumed the entry.
        XCTAssertFalse(gate.consume(connection: connection, serverNonce: handshake.serverNonce))

        _ = gate.issue(
            connection: connection,
            clientNonce: Data(repeating: 0x33, count: HelperHandshakeGate.nonceByteCount)
        )
        clock.value = Date().addingTimeInterval(HelperHandshakeGate.lifetime + 1)
        XCTAssertFalse(gate.consume(connection: connection, serverNonce: fixedNonce))
        XCTAssertNil(gate.issue(
            connection: UUID(),
            clientNonce: Data(repeating: 0x33, count: 3)
        ))
    }

    private func safeStartRight(
        overrides: [String: Any] = [:],
        remove: Set<String> = []
    ) -> [String: Any] {
        var definition: [String: Any] = [
            "class": "user",
            "group": "admin",
            "authenticate-user": true,
            "shared": false,
            "allow-root": false,
            "timeout": 10,
            "comment": "Start the HotspotShade tunnel.",
        ]
        for key in remove { definition.removeValue(forKey: key) }
        for (key, value) in overrides { definition[key] = value }
        return definition
    }

    private func startRightFixture(_ name: String) throws -> [String: Any] {
        let data = try Data(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent(name))
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return try XCTUnwrap(plist as? [String: Any])
    }

    func testStartRightValidatorAcceptsTheInstalledSourceDefinition() {
        XCTAssertTrue(HelperStartRightValidator.isSafe(safeStartRight()))
        // The comment is the only optional install-time key. They are
        // unrelated to the authd metadata covered below.
        XCTAssertTrue(HelperStartRightValidator.isSafe(safeStartRight(remove: ["comment"])))
        XCTAssertFalse(HelperStartRightValidator.isSafe([:]))
    }

    func testStartRightValidatorRequiresEveryExplicitSafeKey() {
        // A missing key is not a safe default. In particular an omitted
        // shared or allow-root must not pass as "not true".
        for key in [
            "class", "group", "authenticate-user", "shared", "allow-root", "timeout",
        ] {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(safeStartRight(remove: [key])),
                "A definition without \(key) must be refused."
            )
        }
    }

    func testStartRightValidatorRefusesUnsafeValues() {
        for value in [true, NSNumber(value: true), 1] {
            XCTAssertFalse(HelperStartRightValidator.isSafe(safeStartRight(overrides: ["shared": value])))
            XCTAssertFalse(HelperStartRightValidator.isSafe(safeStartRight(overrides: ["allow-root": value])))
        }
        XCTAssertFalse(HelperStartRightValidator.isSafe(safeStartRight(overrides: ["class": "allow"])))
        XCTAssertFalse(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["class": "authenticate-admin"])
        ))
        XCTAssertFalse(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["class": "authenticate-admin"], remove: ["group", "authenticate-user"])
        ))
        XCTAssertFalse(HelperStartRightValidator.isSafe(safeStartRight(overrides: ["group": "staff"])))
        XCTAssertFalse(HelperStartRightValidator.isSafe(safeStartRight(overrides: ["authenticate-user": false])))
        XCTAssertFalse(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["class": "rule", "rule": "is-admin"])
        ))
    }

    func testStartRightValidatorAcceptsOnlyABoundedPositiveIntegerTimeout() {
        XCTAssertTrue(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["timeout": NSNumber(value: 10)])
        ))
        // Both ends of the reviewed window are accepted.
        XCTAssertTrue(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["timeout": NSNumber(value: 1)])
        ))
        XCTAssertTrue(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["timeout": NSNumber(value: 60)])
        ))
        // Zero is the live failure: Authorization Services stores no
        // credential, so the helper check after the prompt is denied.
        for value: Any in [0, -1, 61, 300, 0.5, true, "10", NSNumber(value: true)] {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: ["timeout": value])),
                "A timeout of \(value) must be refused."
            )
        }
    }

    func testStartRightValidatorAcceptsAuthdReadBackMetadata() throws {
        let readBack = try startRightFixture("start-right-authd-read.plist")
        XCTAssertTrue(HelperStartRightValidator.isSafe(readBack))
        XCTAssertTrue(HelperStartRightValidator.isSafe(safeStartRight(overrides: [
            "created": NSNumber(value: 700_000_000.0),
            "modified": NSNumber(value: 700_000_001.0),
            "session-owner": false,
            "tries": NSNumber(value: 10_000),
            "version": NSNumber(value: 0),
        ])))
        // Each authd-added key is optional. The source plist, before authd
        // writes the read-back, must stay usable.
        for key in ["created", "modified", "session-owner", "tries", "version"] {
            XCTAssertTrue(
                HelperStartRightValidator.isSafe(readBack.filter { $0.key != key }),
                "The authd key \(key) must be optional."
            )
        }
    }

    func testStartRightValidatorAcceptsAuthdIdentityMetadata() throws {
        let identity = try startRightFixture("start-right-authd-identity.plist")
        XCTAssertTrue(HelperStartRightValidator.isSafe(identity))
        XCTAssertTrue(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["identifier": "com.example.fixture"])
        ))
        XCTAssertTrue(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["requirement": "anchor apple generic"])
        ))
        XCTAssertTrue(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["requirement": "line one\nline two\tend"])
        ))
    }

    func testStartRightValidatorConstrainsTimestamps() {
        for key in ["created", "modified"] {
            for value: Any in [NSNumber(value: 0), 0, NSNumber(value: 700_000_000.0), 700_000_000] {
                XCTAssertTrue(
                    HelperStartRightValidator.isSafe(safeStartRight(overrides: [key: value])),
                    "\(key) of \(value) must be accepted."
                )
            }
            for value: Any in [
                "700000000",
                true,
                NSNumber(value: -1),
                NSNumber(value: Double.nan),
                NSNumber(value: Double.infinity),
                Data([0]),
            ] {
                XCTAssertFalse(
                    HelperStartRightValidator.isSafe(safeStartRight(overrides: [key: value])),
                    "\(key) of \(value) must be refused."
                )
            }
        }
    }

    func testStartRightValidatorConstrainsVersion() {
        for value: Any in [NSNumber(value: 0), 0, 12, 1_000_000] {
            XCTAssertTrue(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: ["version": value])),
                "A version of \(value) must be accepted."
            )
        }
        for value: Any in [-1, 1_000_001, NSNumber(value: 1.0), 0.5, true, "0"] {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: ["version": value])),
                "A version of \(value) must be refused."
            )
        }
    }

    func testStartRightValidatorConstrainsSessionOwner() {
        XCTAssertTrue(HelperStartRightValidator.isSafe(safeStartRight(overrides: ["session-owner": false])))
        for value: Any in [true, 0, 1, NSNumber(value: 0), "false"] {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: ["session-owner": value])),
                "A session-owner of \(value) must be refused."
            )
        }
    }

    func testStartRightValidatorConstrainsTries() {
        for value: Any in [NSNumber(value: 1), 1, 10_000, NSNumber(value: 10_000)] {
            XCTAssertTrue(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: ["tries": value])),
                "A tries value of \(value) must be accepted."
            )
        }
        for value: Any in [0, -1, 10_001, NSNumber(value: 1.0), 0.5, true, "10000"] {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: ["tries": value])),
                "A tries value of \(value) must be refused."
            )
        }
    }

    func testStartRightValidatorConstrainsIdentityMetadataText() {
        for value: Any in [1, true, Data([0x41]), "", String(repeating: "a", count: 1025)] {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: ["identifier": value])),
                "An identifier of \(value) must be refused."
            )
        }
        XCTAssertFalse(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["identifier": "com.example\nfixture"])
        ))
        XCTAssertTrue(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["identifier": "com.example.fixture"])
        ))

        for value: Any in [1, true, Data([0x41]), "", String(repeating: "a", count: 4097)] {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: ["requirement": value])),
                "A requirement of \(value) must be refused."
            )
        }
        XCTAssertFalse(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["requirement": "anchor\u{0}"])
        ))
        XCTAssertFalse(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["requirement": "anchor\u{e9}"])
        ))
        XCTAssertTrue(HelperStartRightValidator.isSafe(
            safeStartRight(overrides: ["requirement": "anchor apple generic\nand identifier \"x\""])
        ))
    }

    func testStartRightValidatorRefusesUnsupportedExtraSemantics() {
        let unsupported: [(String, Any)] = [
            ("rule", "allow"),
            ("rule", ["allow"]),
            ("mechanisms", ["builtin:authenticate"]),
            ("k-of-n", 1),
            ("entitlement", "com.example.entitlement"),
            ("entitled", true),
            ("entitled-group", true),
            ("vpn-entitled-group", true),
            ("password-only", true),
            ("default-prompt", ["": "prompt"]),
            ("unknown-field", "value"),
        ]
        for (key, value) in unsupported {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(safeStartRight(overrides: [key: value])),
                "The key \(key) must be refused."
            )
        }
        XCTAssertFalse(HelperStartRightValidator.isSafe(safeStartRight(overrides: ["comment": 1])))
    }

    func testStartRightValidatorRefusesAccessGrantingFixtureKeys() throws {
        for name in ["start-right-malicious-rule.plist", "start-right-malicious-entitled.plist"] {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(try startRightFixture(name)),
                "The \(name) fixture must be refused."
            )
        }
    }

    func testStartRightValidatorDoesNotLetMetadataMaskUnsafeSettings() {
        let metadata: [String: Any] = [
            "created": NSNumber(value: 700_000_000.0),
            "modified": NSNumber(value: 700_000_001.0),
            "session-owner": false,
            "tries": NSNumber(value: 10_000),
            "version": NSNumber(value: 0),
            "identifier": "com.example.fixture",
            "requirement": "anchor apple generic",
        ]
        let unsafeSettings: [(String, Any)] = [
            ("class", "allow"),
            ("class", "rule"),
            ("group", "staff"),
            ("authenticate-user", false),
            ("shared", true),
            ("allow-root", true),
            ("timeout", 0),
            ("timeout", 99),
            ("session-owner", true),
            ("tries", 10_001),
        ]
        for (key, value) in unsafeSettings {
            XCTAssertFalse(
                HelperStartRightValidator.isSafe(
                    safeStartRight(overrides: metadata).merging([key: value]) { _, new in new }
                ),
                "The unsafe \(key) setting must not be masked by metadata."
            )
        }
    }

    func testStartRightValidatorKeepsTheInstalledTemplateShape() throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Helper/dev.hotspotshade.tunnel.start.plist"))
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        let definition = try XCTUnwrap(plist as? [String: Any])
        XCTAssertTrue(HelperStartRightValidator.isSafe(definition))
        XCTAssertEqual(
            definition["timeout"] as? Int,
            HelperStartAuthorizationPolicy.startRightTimeoutSeconds,
            "The canonical template must use the reviewed positive timeout."
        )
    }

    func testStartGateRefusesWhenTheRightIsNotConfigured() {
        let launcher = FakeEngineLauncher()
        let checker = FakeAuthorizationFormChecker()
        let rights = FakeStartRightChecker()
        rights.failure = .startRightNotConfigured
        let (gate, controller) = authorizationGate(
            checker: checker,
            launcher: launcher,
            rightChecker: rights
        )
        let connection = UUID()
        _ = gate.startEngine(connection: connection)
        XCTAssertEqual(gate.authorize(connection: connection, form: helperForm()), .notConfigured)
        XCTAssertEqual(rights.calls, 1)
        XCTAssertEqual(checker.calls, 0)
        XCTAssertEqual(launcher.launches, 1)
        XCTAssertTrue(controller.isRunning)
    }

    func testRootRuntimeDirectoryRejectsAnExtendedACLParent() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let parent = root + "/run"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(parent, 0o700), 0)
        XCTAssertTrue(ProtectedHelperTestSupport.addExtendedACL(to: parent))
        XCTAssertThrowsError(
            try RootEngineRuntimeDirectory(
                parentPath: parent,
                namePrefix: "test-",
                expectedOwner: geteuid()
            )
        ) {
            XCTAssertEqual($0 as? HelperTrustError, .unsafeParentDirectory)
        }
    }

    func testRootRuntimeDirectoryRejectsAnExtendedACLAddedAfterCreation() throws {
        let (runtime, root) = try makeRuntimeDirectory()
        defer {
            runtime.remove()
            try? FileManager.default.removeItem(atPath: root)
        }
        XCTAssertTrue(ProtectedHelperTestSupport.addExtendedACL(to: runtime.path))
        try Data("65535\n".utf8).write(to: URL(fileURLWithPath: runtime.portFilePath))
        XCTAssertThrowsError(try runtime.readPort())
    }

    func testRootRuntimeDirectoryReadsThePortThroughHeldDescriptors() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let parent = root + "/run"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        chmod(parent, 0o700)
        let runtime = try RootEngineRuntimeDirectory(
            parentPath: parent,
            namePrefix: "test-",
            expectedOwner: geteuid()
        )
        defer { runtime.remove() }
        try Data("65535\n".utf8).write(to: URL(fileURLWithPath: runtime.portFilePath))
        XCTAssertEqual(try runtime.readPort(), 65535)

        // A symlink at the port path is rejected even when its target is a
        // regular file with a valid value.
        unlink(runtime.portFilePath)
        XCTAssertEqual(symlink(root + "/other-port", runtime.portFilePath), 0)
        try Data("1234\n".utf8).write(to: URL(fileURLWithPath: root + "/other-port"))
        XCTAssertThrowsError(try runtime.readPort())
    }

    func testRootRuntimeDirectoryIgnoresAPathSubstitution() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let parent = root + "/run"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        chmod(parent, 0o700)
        let runtime = try RootEngineRuntimeDirectory(
            parentPath: parent,
            namePrefix: "test-",
            expectedOwner: geteuid()
        )
        defer {
            runtime.remove()
            try? FileManager.default.removeItem(atPath: root)
        }
        let original = runtime.path
        let moved = original + "-moved"
        XCTAssertEqual(rename(original, moved), 0)
        // A replacement directory at the original path must not be read.
        try FileManager.default.createDirectory(atPath: original, withIntermediateDirectories: false)
        try Data("1\n".utf8).write(to: URL(fileURLWithPath: original + "/port"))
        try Data("65535\n".utf8).write(to: URL(fileURLWithPath: moved + "/port"))
        XCTAssertEqual(try runtime.readPort(), 65535)
    }

    func testRootRuntimeDirectoryRejectsAGroupWritablePortFile() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let parent = root + "/run"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        chmod(parent, 0o700)
        let runtime = try RootEngineRuntimeDirectory(
            parentPath: parent,
            namePrefix: "test-",
            expectedOwner: geteuid()
        )
        defer { runtime.remove() }
        try Data("65535\n".utf8).write(to: URL(fileURLWithPath: runtime.portFilePath))
        // A valid value alone is not enough: another user must not be able to
        // rewrite the port that the helper trusts.
        XCTAssertEqual(chmod(runtime.portFilePath, 0o666), 0)
        XCTAssertThrowsError(try runtime.readPort())
    }

    func testRootRuntimeDirectoryRejectsANonRegularOrOversizedPortFile() throws {
        let root = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let parent = root + "/run"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        chmod(parent, 0o700)
        let runtime = try RootEngineRuntimeDirectory(
            parentPath: parent,
            namePrefix: "test-",
            expectedOwner: geteuid()
        )
        defer { runtime.remove() }
        // A directory at the port path is not a readable port value.
        try FileManager.default.createDirectory(
            atPath: runtime.portFilePath,
            withIntermediateDirectories: false
        )
        XCTAssertThrowsError(try runtime.readPort())
        try FileManager.default.removeItem(atPath: runtime.portFilePath)
        // A file longer than the fixed maximum is rejected before it is read.
        try Data(repeating: 0x31, count: 17)
            .write(to: URL(fileURLWithPath: runtime.portFilePath))
        XCTAssertThrowsError(try runtime.readPort())
        // An empty file is not a port either.
        try Data().write(to: URL(fileURLWithPath: runtime.portFilePath))
        XCTAssertThrowsError(try runtime.readPort())
    }

    func testRootRuntimeDirectoryRemovesAStalePortTempFile() throws {
        let (runtime, root) = try makeRuntimeDirectory()
        defer {
            runtime.remove()
            try? FileManager.default.removeItem(atPath: root)
        }
        let runtimePath = runtime.path
        // The engine publishes the port through port.tmp and a rename. An
        // interrupted publish must not keep the private runtime directory
        // alive after the engine is gone.
        try Data("65535\n".utf8).write(
            to: URL(fileURLWithPath: runtime.portFilePath + ".tmp")
        )
        runtime.remove()
        XCTAssertFalse(FileManager.default.fileExists(atPath: runtimePath))
    }

    func testClientStatusReportsACleanupBlock() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.statusReply = HelperStatus(running: false, cleanupBlocked: true)
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        let status = try client.status()
        XCTAssertFalse(status.running)
        XCTAssertTrue(status.cleanupBlocked)
        XCTAssertEqual(client.state, .unavailable(.cleanupBlocked))
    }

    func testClientRefusesToStartWithoutAHandshake() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        XCTAssertThrowsError(try client.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .notConnected)
        }
        XCTAssertEqual(transport.startCalls, 0)
    }

    private func temporaryDirectory() -> String {
        let path = NSTemporaryDirectory() + "hotspotshade-test-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
        return path
    }

    private func makeRuntimeDirectory() throws -> (RootEngineRuntimeDirectory, String) {
        let root = temporaryDirectory()
        let parent = root + "/run"
        try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: false)
        chmod(parent, 0o700)
        let runtime = try RootEngineRuntimeDirectory(
            parentPath: parent,
            namePrefix: "test-",
            expectedOwner: geteuid()
        )
        return (runtime, root)
    }

    func testRuntimeDirectoryWritesAndRemovesTheTunnelGrant() throws {
        let (runtime, root) = try makeRuntimeDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try runtime.writeTunnelGrant()
        let path = runtime.grantFilePath
        var status = stat()
        XCTAssertEqual(lstat(path, &status), 0)
        XCTAssertEqual(status.st_mode & S_IFMT, S_IFREG)
        XCTAssertEqual(status.st_uid, geteuid())
        XCTAssertEqual(status.st_mode & 0o777, 0o600)
        XCTAssertEqual(status.st_nlink, 1)
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let fields = text.trimmingCharacters(in: .newlines).split(separator: " ")
        XCTAssertEqual(fields.count, 2)
        XCTAssertEqual(fields[0].count, 64)
        XCTAssertTrue(fields[0].allSatisfy { $0.isHexDigit })
        XCTAssertNotNil(Int(fields[1]))
        // A second authorization replaces the first grant, never reuses it.
        try runtime.writeTunnelGrant()
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        runtime.removeTunnelGrant()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        runtime.remove()
        XCTAssertFalse(FileManager.default.fileExists(atPath: runtime.path))
    }

    // posix_spawn keeps the child owned by this test process. Foundation's
    // Process would reap it itself, and RunningRootEngine must read the exit
    // status through waitpid.
    private func spawnShell(_ script: String) throws -> pid_t {
        var argv: [UnsafeMutablePointer<CChar>?] = ["/bin/sh", "-c", script].map { strdup($0) }
        argv.append(nil)
        let environment = ["PATH=/usr/bin:/bin"]
        var envp: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) }
        envp.append(nil)
        defer {
            for pointer in argv { if let pointer { free(pointer) } }
            for pointer in envp { if let pointer { free(pointer) } }
        }
        var pid: pid_t = 0
        let result = posix_spawn(&pid, "/bin/sh", nil, nil, &argv, &envp)
        guard result == 0, pid > 0 else { throw HelperTrustError.engineStartFailed }
        return pid
    }

    // MARK: - Signing policy

    func testLibraryValidationEntitlementIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        signer.infos[helperPath] = HelperSigningInfo(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: team,
            isAdHoc: false,
            hasHardenedRuntime: true,
            disablesLibraryValidation: true
        )
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .signatureRejected)
        }
    }

    func testDyldEnvironmentEntitlementIsRejected() throws {
        let (files, signer, reader, policy) = try installFixture()
        signer.infos[helperPath] = HelperSigningInfo(
            identifier: HelperRequirement.helperIdentifier,
            teamIdentifier: team,
            isAdHoc: false,
            hasHardenedRuntime: true,
            allowsDyldEnvironmentVariables: true
        )
        XCTAssertThrowsError(try verifier(files, signer, reader, policy).verify()) {
            XCTAssertEqual($0 as? HelperTrustError, .signatureRejected)
        }
    }

    func testRequirementNamesEveryDeniedEntitlement() throws {
        XCTAssertEqual(
            HelperRequirement.deniedEntitlementClauses,
            [
                "!entitlement[\"com.apple.security.get-task-allow\"]",
                "!entitlement[\"com.apple.security.cs.disable-library-validation\"]",
                "!entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"]",
            ]
        )
        let requirement = try HelperRequirement.make(identifier: "dev.hotspotshade.mac", teamIdentifier: team)
        for clause in HelperRequirement.deniedEntitlementClauses {
            XCTAssertTrue(requirement.contains(clause), "The requirement must include \(clause).")
        }
        let selfRequirement = try HelperRequirement.makeSelf(identifier: HelperRequirement.helperIdentifier)
        for clause in HelperRequirement.deniedEntitlementClauses {
            XCTAssertTrue(selfRequirement.contains(clause))
        }
        #if HOTSPOTSHADE_LOCAL_PREVIEW
        XCTAssertTrue(HelperRequirement.isLocalPreview)
        XCTAssertTrue(selfRequirement.contains("1.2.840.113635.100.6.2.1"))
        XCTAssertTrue(selfRequirement.contains("1.2.840.113635.100.6.1.12"))
        XCTAssertFalse(selfRequirement.contains("1.2.840.113635.100.6.1.13"))
        #else
        XCTAssertFalse(HelperRequirement.isLocalPreview)
        XCTAssertTrue(selfRequirement.contains("1.2.840.113635.100.6.2.6"))
        XCTAssertTrue(selfRequirement.contains("1.2.840.113635.100.6.1.13"))
        XCTAssertFalse(selfRequirement.contains("1.2.840.113635.100.6.1.12"))
        #endif
    }

    func testSigningRequirementsCompileWithSecurityFramework() throws {
        for text in [
            try HelperRequirement.make(identifier: HelperRequirement.appIdentifier, teamIdentifier: team),
            try HelperRequirement.makeSelf(identifier: HelperRequirement.helperIdentifier),
        ] {
            var requirement: SecRequirement?
            XCTAssertEqual(SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement), errSecSuccess)
            XCTAssertNotNil(requirement)
        }
    }

    // MARK: - Engine liveness and descriptor writes

    func testEngineExitFreesTheSessionAndBlocksEveryLaterStart() {
        let launcher = FakeEngineLauncher()
        let store = TestCleanupBlockStore()
        let controller = makeController(launcher, store: store)
        let connection = UUID()
        guard case .started = controller.start(connection: connection) else {
            return XCTFail("The session must start.")
        }
        XCTAssertNil(controller.reapExitedEngine())
        launcher.engine.isRunning = false
        XCTAssertEqual(controller.reapExitedEngine(), connection)
        XCTAssertFalse(controller.isRunning)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertNil(controller.reapExitedEngine())
        // An exit without a stop request is not proof that the engine removed
        // its routes. The slot is free, but every later start is refused.
        XCTAssertTrue(controller.requiresCleanup)
        XCTAssertEqual(store.records.count, 1)
        XCTAssertTrue(store.blocked)
        launcher.engine = FakeRunningEngine()
        XCTAssertEqual(controller.start(connection: UUID()), .cleanupBlocked)
        XCTAssertEqual(launcher.launches, 1)
    }

    func testRunningRootEngineReportsAZeroExitAsStopped() throws {
        let (runtime, root) = try makeRuntimeDirectory()
        defer {
            runtime.remove()
            try? FileManager.default.removeItem(atPath: root)
        }
        // Wait until the shell has installed the trap. A SIGTERM that arrives
        // before it would kill the shell by signal instead of exercising the
        // zero exit status.
        let marker = root + "/trap-installed"
        let script = "trap 'exit 0' TERM; : > '\(marker)'; while :; do sleep 0.02; done"
        let pid = try spawnShell(script)
        let engine = RunningRootEngine(
            processIdentifier: pid,
            parentWrite: -1,
            port: 1,
            secret: "test",
            runtime: runtime
        )
        XCTAssertTrue(engine.isRunning)
        let deadline = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: marker), Date() < deadline {
            usleep(10_000)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker))
        XCTAssertEqual(engine.stop(), .stopped)
        XCTAssertFalse(engine.isRunning)
    }

    func testRunningRootEngineTreatsSignalAndNonZeroExitAsFailed() throws {
        for script in [
            "trap 'exit 3' TERM; while :; do sleep 0.02; done",
            "exec sleep 30",
        ] {
            let (runtime, root) = try makeRuntimeDirectory()
            defer {
                runtime.remove()
                try? FileManager.default.removeItem(atPath: root)
            }
            let pid = try spawnShell(script)
            let engine = RunningRootEngine(
                processIdentifier: pid,
                parentWrite: -1,
                port: 1,
                secret: "test",
                runtime: runtime
            )
            XCTAssertTrue(engine.isRunning)
            XCTAssertEqual(engine.stop(), .failed, "Only a zero exit is a clean stop.")
            XCTAssertFalse(engine.isRunning)
        }
    }

    func testShutdownWaitsForALateLaunchStopTimeoutAndReportsIt() {
        let launcher = BlockingEngineLauncher()
        launcher.engine.stopResult = .timedOut
        let exclusion = TestStartExclusion()
        let controller = makeController(launcher, exclusion: exclusion)
        let connection = UUID()
        let startResult = Box<HelperSessionStartResult>()
        let stopResult = Box<EngineStopResult>()
        let startDone = DispatchSemaphore(value: 0)
        let shutdownDone = DispatchSemaphore(value: 0)
        let stopEntered = DispatchSemaphore(value: 0)
        let allowStop = DispatchSemaphore(value: 0)
        launcher.engine.duringStop = {
            stopEntered.signal()
            allowStop.wait()
        }

        DispatchQueue.global().async {
            startResult.value = controller.start(connection: connection)
            startDone.signal()
        }
        XCTAssertEqual(launcher.entered.wait(timeout: .now() + 5), .success)

        DispatchQueue.global().async {
            stopResult.value = controller.shutDown()
            shutdownDone.signal()
        }
        XCTAssertEqual(shutdownDone.wait(timeout: .now() + 0.3), .timedOut)

        launcher.release.signal()
        XCTAssertEqual(stopEntered.wait(timeout: .now() + 5), .success)
        // The launch slot has cleared, but the late engine is still stopping.
        // Shutdown must wait for that cleanup instead of returning .stopped.
        XCTAssertEqual(shutdownDone.wait(timeout: .now() + 0.3), .timedOut)
        allowStop.signal()

        XCTAssertEqual(startDone.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(shutdownDone.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(startResult.value, .connectionClosed)
        XCTAssertEqual(stopResult.value, .timedOut)
        XCTAssertTrue(controller.hasRetainedExclusion)
        XCTAssertEqual(exclusion.lease.abandonCalls, 1)
        XCTAssertTrue(controller.requiresCleanup)
    }

    func testShutdownWaitsForAnUncleanLaunchCleanup() {
        let launcher = FakeEngineLauncher()
        launcher.failure = .engineExitUnclean
        let store = TestCleanupBlockStore()
        let exclusion = TestStartExclusion()
        let recordEntered = DispatchSemaphore(value: 0)
        let allowRecord = DispatchSemaphore(value: 0)
        store.duringRecord = {
            recordEntered.signal()
            allowRecord.wait()
        }
        let controller = makeController(launcher, store: store, exclusion: exclusion)
        let startResult = Box<HelperSessionStartResult>()
        let stopResult = Box<EngineStopResult>()
        let startDone = DispatchSemaphore(value: 0)
        let shutdownDone = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            startResult.value = controller.start(connection: UUID())
            startDone.signal()
        }
        XCTAssertEqual(recordEntered.wait(timeout: .now() + 5), .success)

        DispatchQueue.global().async {
            stopResult.value = controller.shutDown()
            shutdownDone.signal()
        }
        // The launch slot cleared, but the durable cleanup block and the
        // retained lease are not written yet. Shutdown must wait for them.
        XCTAssertEqual(shutdownDone.wait(timeout: .now() + 0.3), .timedOut)
        allowRecord.signal()

        XCTAssertEqual(startDone.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(shutdownDone.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(startResult.value, .cleanupBlocked)
        XCTAssertEqual(stopResult.value, .failed)
        XCTAssertTrue(controller.hasRetainedExclusion)
        XCTAssertEqual(exclusion.lease.abandonCalls, 1)
    }

    func testShutdownReportsARetainedLeaseInsteadOfACleanExit() {
        let launcher = FakeEngineLauncher()
        launcher.engine.stopResult = .failed
        let exclusion = TestStartExclusion()
        let controller = makeController(launcher, exclusion: exclusion)
        let connection = UUID()
        _ = controller.start(connection: connection)
        XCTAssertEqual(controller.stop(connection: connection, reason: .user), .failed)
        XCTAssertTrue(controller.hasRetainedExclusion)
        // No engine session remains, but the helper still holds a shared lock
        // for an engine that may own routes. Exiting cleanly would drop it.
        XCTAssertEqual(controller.shutDown(), .failed)
    }

    func testShutdownWaitsForAnInFlightLaunchAndStopsTheLateEngine() {
        let launcher = BlockingEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        let startResult = Box<HelperSessionStartResult>()
        let stopResult = Box<EngineStopResult>()
        let startDone = DispatchSemaphore(value: 0)
        let shutdownDone = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            startResult.value = controller.start(connection: connection)
            startDone.signal()
        }
        XCTAssertEqual(launcher.entered.wait(timeout: .now() + 5), .success)

        DispatchQueue.global().async {
            stopResult.value = controller.shutDown()
            shutdownDone.signal()
        }
        // The shutdown must wait for the launch instead of letting a late
        // engine start under a helper that is leaving.
        XCTAssertEqual(shutdownDone.wait(timeout: .now() + 0.3), .timedOut)

        launcher.release.signal()
        XCTAssertEqual(startDone.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(shutdownDone.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(startResult.value, .connectionClosed)
        XCTAssertEqual(stopResult.value, .stopped)
        XCTAssertEqual(launcher.engine.stopCalls, 1)
        XCTAssertFalse(controller.isRunning)
    }

    func testQueuedCancelDoesNotStopALaterStart() {
        let launcher = FakeEngineLauncher()
        let controller = makeController(launcher)
        let connection = UUID()
        // Nothing is running and nothing is launching, so the cancel is a
        // no-op and leaves no record for the next request.
        XCTAssertEqual(controller.stop(connection: connection, reason: .cancelled), .stopped)
        guard case .started(let session) = controller.start(connection: connection) else {
            return XCTFail("The queued cancel must not block the later start.")
        }
        XCTAssertEqual(session.port, 5353)
        XCTAssertEqual(session.secret, "secret")
        XCTAssertEqual(launcher.engine.stopCalls, 0)
        XCTAssertTrue(controller.isRunning)
    }

    func testSecretWriteDoesNotRaiseSIGPIPEWhenTheReaderIsGone() {
        var descriptors: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&descriptors), 0)
        XCTAssertEqual(close(descriptors[0]), 0)
        // The write must return false, not kill this process with SIGPIPE.
        XCTAssertFalse(HelperPipeWriter.writeAll(descriptor: descriptors[1], bytes: Array("secret\n".utf8)))
        XCTAssertEqual(close(descriptors[1]), 0)
    }

    func testSecretWriteSendsEveryByteWhenTheReaderIsOpen() {
        var descriptors: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&descriptors), 0)
        defer { close(descriptors[0]) }
        let bytes = Array("0123456789abcdef0123456789abcdef\n".utf8)
        XCTAssertTrue(HelperPipeWriter.writeAll(descriptor: descriptors[1], bytes: bytes))
        XCTAssertEqual(close(descriptors[1]), 0)
        var received = [UInt8](repeating: 0, count: bytes.count)
        let count = read(descriptors[0], &received, received.count)
        XCTAssertEqual(count, bytes.count)
        XCTAssertEqual(received, bytes)
    }

    // MARK: - Client failure reporting

    func testClientReportsEngineExitAndNeverRestarts() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        XCTAssertTrue(client.isConnected)
        transport.invalidate(.engineExited)
        XCTAssertEqual(client.state, .unavailable(.engineExited))
        XCTAssertFalse(client.isConnected)
        XCTAssertThrowsError(try client.start()) {
            XCTAssertEqual($0 as? HelperTrustError, .notConnected)
        }
        XCTAssertEqual(transport.startCalls, 0)
    }

    func testEngineExitedNoticeNamesTheAuthorizationTimeout() {
        XCTAssertEqual(
            HelperInvalidation.engineExitedNotice(reason: "authorization_timeout", cleanupBlocked: false),
            .authorizationTimedOut
        )
        XCTAssertEqual(
            HelperInvalidation.engineExitedNotice(reason: nil, cleanupBlocked: false),
            .engineExited
        )
        XCTAssertEqual(
            HelperInvalidation.engineExitedNotice(reason: "something_else", cleanupBlocked: false),
            .engineExited
        )
        // A cleanup block always wins over the reason.
        XCTAssertEqual(
            HelperInvalidation.engineExitedNotice(reason: "authorization_timeout", cleanupBlocked: true),
            .cleanupBlocked
        )
    }

    // The helper stops an engine whose administrator authorization took longer
    // than its deadline. The app says so in plain words, never "lost the
    // helper" or a route warning, and the stop still needs the helper's exact
    // clean record before it counts as a clean stop.
    func testAuthorizationTimeoutNoticeSaysTheAuthorizationWasNotCompletedInTime() throws {
        let (files, signer, reader, policy) = try installFixture()
        let first = FakeHelperTransport()
        let second = FakeHelperTransport()
        let sequence = TransportSequence([first, second])
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in try sequence.next() }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start()
        guard let session = engine.sessionID else {
            return XCTFail("The start must retain the session id.")
        }
        first.invalidate(.authorizationTimedOut)
        XCTAssertEqual(client.state, .unavailable(.authorizationTimedOut))
        XCTAssertFalse(client.isConnected)
        XCTAssertTrue(engine.isRunning, "The stop is not confirmed until the helper record is read.")

        var thrown: Error?
        XCTAssertThrowsError(try engine.authorizeStart()) { thrown = $0 }
        XCTAssertEqual(thrown as? HelperTrustError, .authorizationTimedOut)
        XCTAssertEqual(authorization.calls, 0, "No prompt for an engine the helper already stopped.")
        let failure = EngineLaunchFailure.fromHelper(try XCTUnwrap(thrown))
        XCTAssertEqual(failure.kind, .authorization)
        XCTAssertEqual(failure.diagnosticCode, "authorization_timeout")
        XCTAssertEqual(failure.message, Strings.helperAuthorizationTimedOut)
        XCTAssertTrue(failure.message.contains("not completed in time"))
        XCTAssertNotEqual(failure.message, Strings.helperLost)
        XCTAssertFalse(failure.message.contains("route"))
        XCTAssertEqual(EngineLaunchFailure.fromLost(HelperTrustError.authorizationTimedOut).message, Strings.helperAuthorizationTimedOut)
        XCTAssertEqual(Strings.helperMessage(HelperTrustError.authorizationTimedOut), Strings.helperAuthorizationTimedOut)

        // A stop answer without a reply keeps the uncertainty but names the
        // timeout instead of a route warning.
        XCTAssertEqual(
            TunnelStopResult.fromHelperStop(
                reply: nil,
                previous: .unavailable(.authorizationTimedOut),
                session: session,
                everStarted: true
            ),
            .uncertain(EngineLaunchText.stopAuthorizationTimedOut)
        )

        // The stop reconnects and reads the helper record. The deadline stop
        // is a clean record for this exact session.
        second.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            lastSession: session,
            lastResult: .stopped
        )
        XCTAssertEqual(engine.stop(), .stopped)
        XCTAssertFalse(engine.isRunning)
        XCTAssertEqual(second.stopCalls, 0, "A new connection owns nothing and reads the record instead.")
    }

    func testAuthorizationTimeoutReplyRaceStillNamesTheTimeout() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        _ = try client.start()
        try client.performHandshake()
        // The deadline notice lands while the authorize request is in flight,
        // and the helper answers that no engine is running.
        transport.authorizeFailure = .tunnelNotRunning
        transport.onAuthorize = { transport.invalidate(.authorizationTimedOut) }
        XCTAssertThrowsError(try client.authorizeStart(authorization: Data([1]))) {
            XCTAssertEqual($0 as? HelperTrustError, .authorizationTimedOut)
        }
        // Without the notice the same reply keeps its own meaning.
        let plain = FakeHelperTransport()
        plain.authorizeFailure = .tunnelNotRunning
        let other = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in plain }
        _ = try other.connect()
        _ = try other.start()
        try other.performHandshake()
        XCTAssertThrowsError(try other.authorizeStart(authorization: Data([1]))) {
            XCTAssertEqual($0 as? HelperTrustError, .tunnelNotRunning)
        }
    }

    func testClientStopDeadlineOutlastsTheHelperEngineStopBound() {
        XCTAssertEqual(HelperEngineStopDeadline.engineStop, 60)
        XCTAssertEqual(HelperEngineStopDeadline.clientReplyGrace, 10)
        XCTAssertEqual(HelperEngineStopDeadline.clientStop, 70)
        XCTAssertGreaterThan(
            HelperEngineStopDeadline.clientStop,
            HelperEngineStopDeadline.engineStop
        )
    }

    func testClientReportsAStopFailureInsteadOfClaimingSuccess() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.stopFailure = .cleanupBlocked
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        client.stop()
        XCTAssertEqual(client.state, .unavailable(.cleanupBlocked))
        XCTAssertFalse(client.isConnected)
        XCTAssertEqual(transport.closeCalls, 1)
    }

    func testClientReportsACancelFailureAndCloses() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.cancelFailure = .helperTimeout
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        _ = try client.connect()
        client.cancel()
        XCTAssertEqual(client.state, .unavailable(.helperTimeout))
        XCTAssertFalse(client.isConnected)
        XCTAssertEqual(transport.closeCalls, 1)
    }

    // MARK: - Start and stop fences

    // A start that is delayed inside its status read must not send the helper
    // start request after the quit or the stop cancels its generation.
    func testADelayedStartIsCancelledBeforeTheHelperStartRequest() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        transport.duringStatus = { engine.abortPendingStarts() }
        XCTAssertThrowsError(try engine.start()) { error in
            XCTAssertEqual(error as? HelperTrustError, HelperTrustError.cancelled)
        }
        XCTAssertEqual(transport.statusCalls, 1)
        XCTAssertEqual(transport.startCalls, 0, "The cancelled start must not reach the helper.")
        XCTAssertNil(engine.port)
        XCTAssertFalse(engine.isRunning)
        XCTAssertEqual(transport.closeCalls, 1)
    }

    // A start whose helper reply arrives after the generation was cancelled
    // must stop the engine it just created on the same connection and never
    // publish its port or secret.
    func testACancelledStartStopsTheEngineItAlreadyStarted() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.reply = HelperStartReply(port: 5555, secret: String(repeating: "a", count: 64))
        transport.stopReply = HelperStopReply(
            owned: true,
            status: HelperStatus(running: false, cleanupBlocked: false)
        )
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        transport.duringStart = { engine.abortPendingStarts() }
        XCTAssertThrowsError(try engine.start()) { error in
            XCTAssertEqual(error as? HelperTrustError, HelperTrustError.cancelled)
        }
        XCTAssertEqual(transport.startCalls, 1)
        XCTAssertEqual(transport.stopCalls, 1, "The late engine must be stopped.")
        XCTAssertNil(engine.port)
        XCTAssertNil(engine.sessionID)
        XCTAssertFalse(engine.isRunning)
        XCTAssertEqual(engine.lastStop, .stopped)
    }

    // A stop that begins while a delayed start is in flight must never leave an
    // unpublished root engine. If the stop's fence wins before the start
    // request, no engine exists. If the start already reached the helper, the
    // start stops that engine on the same connection and publishes nothing.
    func testAStopRacingADelayedStartNeverLeavesAnUnpublishedEngine() throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        transport.reply = HelperStartReply(port: 5555, secret: String(repeating: "a", count: 64))
        transport.stopReply = HelperStopReply(
            owned: true,
            status: HelperStatus(running: false, cleanupBlocked: false)
        )
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        transport.duringStatus = {
            entered.signal()
            release.wait()
        }
        let startError = Box<Error>()
        let startDone = expectation(description: "start")
        DispatchQueue.global().async {
            do {
                try engine.start()
            } catch {
                startError.value = error
            }
            startDone.fulfill()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        let stopDone = expectation(description: "stop")
        DispatchQueue.global().async {
            _ = engine.stop()
            stopDone.fulfill()
        }
        release.signal()
        wait(for: [startDone, stopDone], timeout: 5)
        // The stop runs on another queue, so its fence can land before the
        // start request, after it, or after the whole start returned. In
        // every order no engine is left running and nothing stays published.
        XCTAssertNil(engine.port)
        XCTAssertFalse(engine.isRunning)
        if startError.value == nil {
            // The start finished first and published its engine. The stop
            // then stopped that engine through the helper.
            XCTAssertEqual(transport.startCalls, 1)
            XCTAssertEqual(transport.stopCalls, 1, "The published engine must be stopped.")
            XCTAssertEqual(engine.lastStop, .stopped)
        } else {
            XCTAssertEqual(startError.value as? HelperTrustError, HelperTrustError.cancelled)
            if transport.startCalls == 1 {
                XCTAssertEqual(transport.stopCalls, 1, "A late engine must be stopped.")
                XCTAssertEqual(engine.lastStop, .stopped)
            } else {
                XCTAssertEqual(transport.startCalls, 0)
                XCTAssertEqual(transport.stopCalls, 0)
            }
        }
    }
}

// The app wires one tunnel session and one routing backend around the same
// app-owned cleanup state. These tests use that wiring with a real
// ProtectedEngineProcess on the fake helper transport. They run no prompt, no
// handoff, no root engine, and no route change.
extension ProtectedHelperTests {
    private func wiredSession(
        _ transport: FakeHelperTransport
    ) throws -> (ProtectedEngineProcess, RealTunnelSession, TunnelRoutingBackend, FakeBackend, UUID) {
        let (files, signer, reader, policy) = try installFixture()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start(credentials: 12)
        let session = try XCTUnwrap(engine.sessionID)
        let user = FakeBackend()
        user.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let elevated = FakeBackend()
        elevated.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        elevated.stopClearsRunning = true
        let tunnel = RealTunnelSession(
            user: user,
            handoffDescriptor: { 12 },
            isQuitting: { false }
        )
        // The authorizer stores the process and the elevated backend, as the
        // real start does after the helper starts the root engine.
        // Every other closure is the app's own router wiring.
        let router = tunnel.makeRouter(
            user: user,
            authorizeStart: { tunnel.installForTesting(process: engine, backend: elevated) }
        )
        return (engine, tunnel, router, elevated, session)
    }

    // The session and the router share one elevated token. A clean helper stop
    // of the process that this app started is a clean Turn off. It must not be
    // reported as a previous session that is still open.
    func testAWiredRouterAndSessionReportACleanStopForTheirOwnProcess() async throws {
        let transport = FakeHelperTransport()
        let (_, tunnel, router, elevated, _) = try wiredSession(transport)
        try await router.startTunnel(experimentalICMP: false)
        XCTAssertTrue(router.activeBackendIsElevated)
        XCTAssertTrue(tunnel.cleanup.hasElevatedSession)

        try await router.stopTunnel(timeout: 1)

        XCTAssertEqual(elevated.calls.filter { $0 == "stopTunnel" }.count, 1)
        XCTAssertEqual(transport.stopCalls, 1)
        XCTAssertNil(tunnel.cleanup.pending)
        XCTAssertFalse(tunnel.cleanup.hasElevatedSession)
        XCTAssertFalse(tunnel.hasElevatedSession)
        XCTAssertFalse(router.activeBackendIsElevated)
        // A second start is allowed after the clean stop.
        try await router.startTunnel(experimentalICMP: false)
        XCTAssertTrue(router.activeBackendIsElevated)
    }

    // The elevated engine's stop reply was lost and the helper stop timed out.
    // The launch screen's Retry cleanup reaches only the helper. Even when the
    // helper then reports a clean result for the exact session, the engine's
    // route observation is still missing, so the answer is a final route mark,
    // not a clean stop.
    func testAHelperOnlyRetryAfterALostEngineReplyIsNotACleanStop() async throws {
        let transport = FakeHelperTransport()
        let (engine, tunnel, router, elevated, session) = try wiredSession(transport)
        try await router.startTunnel(experimentalICMP: false)
        elevated.failure = BackendError.response("The stop reply was lost.")
        transport.stopFailure = .helperTimeout
        do {
            try await router.stopTunnel(timeout: 1)
            XCTFail("A lost engine reply with a helper timeout is not a clean stop.")
        } catch {}
        XCTAssertEqual(tunnel.cleanup.pending?.kind, .retryable)
        XCTAssertTrue(tunnel.cleanup.hasLostRouteObservation)
        XCTAssertTrue(tunnel.hasElevatedSession)

        // The helper now answers with the clean record for the exact session.
        transport.stopFailure = nil
        transport.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            lastSession: session,
            lastResult: .stopped
        )
        let retry = await tunnel.stopElevated()

        // The helper part of the answer was clean. Only the lost engine
        // observation makes this a final route mark.
        XCTAssertEqual(engine.lastStop, .stopped)
        XCTAssertEqual(retry, .routesUnverified(EngineLaunchText.routeCleanupUnverified))
        XCTAssertEqual(tunnel.cleanup.pending?.kind, .routesUnverified)
        XCTAssertFalse(tunnel.cleanup.hasLostRouteObservation)
        XCTAssertFalse(tunnel.cleanup.hasElevatedSession)
        // A final mark repeats its answer and never becomes clean.
        let again = await tunnel.stopElevated()
        XCTAssertEqual(again, .routesUnverified(EngineLaunchText.routeCleanupUnverified))
        do {
            try await router.startTunnel(experimentalICMP: false)
            XCTFail("A final route mark refuses a new start.")
        } catch {}
    }

    // The same elevated engine answers a later stop. An idle engine refuses a
    // stop while its own cleanup is uncertain, so that answer replaces the
    // observation that the first attempt lost, and the exact helper record can
    // confirm a clean stop.
    func testARouterRetryThatReachesTheSameEngineCanConfirmACleanStop() async throws {
        let transport = FakeHelperTransport()
        let (_, tunnel, router, elevated, session) = try wiredSession(transport)
        try await router.startTunnel(experimentalICMP: false)
        elevated.failure = BackendError.response("The stop reply was lost.")
        transport.stopFailure = .helperTimeout
        do { try await router.stopTunnel(timeout: 1) } catch {}
        XCTAssertTrue(tunnel.cleanup.hasLostRouteObservation)

        elevated.failure = nil
        transport.stopFailure = nil
        transport.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            lastSession: session,
            lastResult: .stopped
        )
        try await router.stopTunnel(timeout: 1)

        XCTAssertNil(tunnel.cleanup.pending)
        XCTAssertFalse(tunnel.cleanup.hasLostRouteObservation)
        XCTAssertFalse(tunnel.cleanup.hasElevatedSession)
        XCTAssertFalse(router.activeBackendIsElevated)
    }

    // The person turns the tunnel on and off through the dashboard. The
    // wired session and router share one elevated token, so a normal Turn off
    // ends in a clean Off with no "still open" error and no cleanup mark.
    @MainActor
    func testAWiredTurnOffThroughTheModelIsACleanOff() async throws {
        let transport = FakeHelperTransport()
        let (_, tunnel, router, elevated, _) = try wiredSession(transport)
        let gate = AppActionGate()
        let model = AppModel(
            backend: router,
            isQuitting: { gate.isQuitting },
            actionGate: gate,
            pingSetting: W6PingSetting(),
            pasteboard: NoPasteboard(),
            forgetIntent: MemoryForgetIntent(),
            notificationSink: NoNotificationSink(),
            settingsOpener: NoSettingsOpener(),
            linkProvider: NoLinkInfoProvider(),
            macOSVersion: "14.5",
            appVersion: "1.0 (1)"
        )
        elevated.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        await model.refresh()
        elevated.currentStatus = Status(running: true, paired: true, phone: Phone(state: "connected"))
        await model.turnOn()
        XCTAssertTrue(router.activeBackendIsElevated)
        XCTAssertEqual(model.screen, .on)

        await model.turnOff()

        XCTAssertEqual(transport.stopCalls, 1)
        XCTAssertNil(tunnel.cleanup.pending)
        XCTAssertFalse(tunnel.cleanup.hasElevatedSession)
        XCTAssertFalse(router.activeBackendIsElevated)
        XCTAssertEqual(model.screen, .ready)
        XCTAssertFalse(model.dashboard.subtitle.contains(EngineLaunchText.elevatedSessionOpen))
    }

    // A Turn off that lands after the authorizer stored the root engine but
    // before the router published it stops that engine through the helper.
    // The start publishes nothing and leaves no mark or session behind.
    func testAWiredStopDuringTheStartStopsThePreparedEngine() async throws {
        let transport = FakeHelperTransport()
        let (files, signer, reader, policy) = try installFixture()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: FakeAuthorizationProvider(),
            startRightChecker: FakeStartRightChecker()
        )
        try engine.start(credentials: 12)
        let user = FakeBackend()
        user.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let elevated = FakeBackend()
        elevated.currentStatus = Status(running: false, paired: true, phone: Phone(state: "ready"))
        let tunnel = RealTunnelSession(user: user, handoffDescriptor: { 12 }, isQuitting: { false })
        let box = Box<TunnelRoutingBackend>()
        let router = tunnel.makeRouter(
            user: user,
            authorizeStart: {
                tunnel.installForTesting(process: engine, backend: elevated)
                try await box.value?.stopTunnel(timeout: 1)
            }
        )
        box.value = router
        do {
            try await router.startTunnel(experimentalICMP: false)
            XCTFail("A stop during the start must cancel it.")
        } catch {
            XCTAssertEqual(error as? TunnelRoutingError, .startCancelledByStop)
        }
        XCTAssertEqual(transport.stopCalls, 1)
        XCTAssertFalse(elevated.calls.contains("startTunnel"))
        XCTAssertNil(tunnel.cleanup.pending)
        XCTAssertFalse(tunnel.cleanup.hasElevatedSession)
        XCTAssertFalse(tunnel.hasElevatedSession)
        XCTAssertFalse(router.activeBackendIsElevated)
    }

    // A reconnect after a lost helper reply must name the exact session. A
    // clean record for an unrelated session is never proof for this one.
    func testAWiredRetryRefusesAnUnrelatedCleanSessionRecord() async throws {
        let transport = FakeHelperTransport()
        let (_, tunnel, router, _, _) = try wiredSession(transport)
        try await router.startTunnel(experimentalICMP: false)
        transport.stopFailure = .helperTimeout
        do { try await router.stopTunnel(timeout: 1) } catch {}
        XCTAssertEqual(tunnel.cleanup.pending?.kind, .retryable)

        transport.stopFailure = nil
        transport.statusReply = HelperStatus(
            running: false,
            cleanupBlocked: false,
            lastSession: UUID(),
            lastResult: .stopped
        )
        let retry = await tunnel.stopElevated()
        XCTAssertEqual(retry.cleanupKind, .routesUnverified)
        XCTAssertNotEqual(retry, .stopped)
        XCTAssertEqual(tunnel.cleanup.pending?.kind, .routesUnverified)
    }
}

// The tunnel session passes its own cancellation into the helper start. These
// tests use a real ProtectedEngineProcess on the fake helper transport. They
// run no prompt, no root engine, and no route change.
extension ProtectedHelperTests {
    // A quit lands after the session's last fence check and before the
    // process reads its own fence. The process fence was moved before start()
    // read it, so only the session's cancellation can stop the helper start.
    // The person then chooses Stay, so isQuitting is false again. The helper
    // must not be asked to start a root engine, and no prompt is shown.
    func testAQuitBetweenTheSessionCheckAndTheHelperStartStillCancelsIt() async throws {
        let (files, signer, reader, policy) = try installFixture()
        let transport = FakeHelperTransport()
        let client = ProtectedHelperClient(
            verifier: verifier(files, signer, reader, policy)
        ) { _ in transport }
        let authorization = FakeAuthorizationProvider()
        let engine = ProtectedEngineProcess(
            client: client,
            authorization: authorization,
            startRightChecker: FakeStartRightChecker()
        )
        let user = FakeBackend()
        let box = Box<RealTunnelSession>()
        let descriptorReads = Box<Int>(0)
        let session = RealTunnelSession(
            user: user,
            handoffDescriptor: {
                // The first read is the session's descriptor check. The second
                // is the argument of the helper start, which is evaluated after
                // the session's last fence check and before start() reads the
                // process fence. The quit and the Stay land exactly there.
                descriptorReads.value = (descriptorReads.value ?? 0) + 1
                if descriptorReads.value == 2 {
                    box.value?.abortPendingStarts()
                }
                return 12
            },
            isQuitting: { false },
            authorization: authorization,
            stopBeforeStart: { .stopped },
            makeProcess: { engine }
        )
        box.value = session

        do {
            try await session.authorizeTunnelStart()
            XCTFail("A start that a quit aborted must not reach the helper.")
        } catch {}

        XCTAssertEqual(descriptorReads.value, 2)
        XCTAssertTrue(user.calls.contains("pairHandoff"))
        XCTAssertEqual(transport.startCalls, 0, "The helper must not start a root engine after the quit.")
        XCTAssertEqual(transport.authorizeCalls, 0)
        XCTAssertEqual(authorization.calls, 0)
        XCTAssertNil(session.existingElevatedBackend())
    }
}
