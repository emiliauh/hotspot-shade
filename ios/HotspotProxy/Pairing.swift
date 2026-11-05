import Foundation
import CryptoKit
import Network

// Pairing protocol v1, phone side. The laptop side is rust/src/pairing.rs.
// The source device state machine is rust/src/source_pairing.rs.
// Both test suites hold the same fixed vectors. Change both sides together.
// This file uses Foundation, CryptoKit, and Network only. It opens no socket.
// The clock, the trust list, and the random source are injected for the tests.

enum PairingStatus: UInt8 {
    case ok = 0
    case denied = 1
    case busy = 2
    case rejected = 3
    case timedOut = 4
    case notActive = 5
    case lockedOut = 6
}

struct PairingError: Error, Equatable {
    let reason: String
}

/// The proxy credentials that the phone sends to a paired laptop.
struct PairingCredentials: Equatable {
    let host: String
    let port: UInt16
    let token: String
}

struct PairingPhoneInfo {
    let proxyRunning: Bool
    let foreground: Bool
    let connections: UInt16
    let port: UInt16
    let host: String
    /// The status sequence number. The app sends 0. The parity vector covers a
    /// nonzero value, so this field stays part of the wire format.
    var sequence: UInt32 = 0
}

/// The session keys from the key schedule.
struct PairingKeys {
    let h: Data
    let kEnc: Data
    let kProof: Data
    let sas: Data
}

enum PairingProtocol {
    static let port: UInt16 = 18090
    static let maxFrame = 512
    static let version: UInt8 = 1
    static let hello: UInt8 = 0x01
    static let challenge: UInt8 = 0x02
    static let reveal: UInt8 = 0x03
    static let result: UInt8 = 0x04
    static let helloLength = 66
    static let challengeLength = 34
    static let revealLength = 65
    static let commitLabel = Data("hotspotshade-commit-v1".utf8)
    static let pairLabel = Data("hotspotshade-pair-v1".utf8)

    static func sha256(_ parts: [Data]) -> Data {
        var hash = SHA256()
        for part in parts { hash.update(data: part) }
        return Data(hash.finalize())
    }

    /// C = SHA256("hotspotshade-commit-v1" || L_e || L_s).
    static func commitment(lE: Data, lS: Data) -> Data {
        sha256([commitLabel, lE, lS])
    }

    /// h = SHA256("hotspotshade-pair-v1" || L_s || L_e || P_e).
    static func transcriptHash(lS: Data, lE: Data, pE: Data) -> Data {
        sha256([pairLabel, lS, lE, pE])
    }

    /// One X25519 agreement. Reject an invalid key and an all-zero result.
    static func agree(_ privateKey: Curve25519.KeyAgreement.PrivateKey, _ publicKey: Data) throws -> Data {
        guard publicKey.count == 32,
              let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey),
              let shared = try? privateKey.sharedSecretFromKeyAgreement(with: peer)
        else { throw PairingError(reason: "key agreement failed") }
        let bytes = shared.withUnsafeBytes { Data($0) }
        guard bytes.count == 32, bytes.contains(where: { $0 != 0 }) else {
            throw PairingError(reason: "low-order key")
        }
        return bytes
    }

    /// prk = HKDF-Extract(h, ee || es). Expand "enc", "proof", and "sas".
    static func deriveKeys(ee: Data, es: Data, h: Data) -> PairingKeys {
        let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: ee + es), salt: h)
        func expand(_ info: String, _ count: Int) -> Data {
            HKDF<SHA256>.expand(pseudoRandomKey: prk, info: Data(info.utf8), outputByteCount: count)
                .withUnsafeBytes { Data($0) }
        }
        return PairingKeys(h: h, kEnc: expand("enc", 32), kProof: expand("proof", 32), sas: expand("sas", 4))
    }

    /// Six decimal digits: u32 big-endian of the SAS bytes, modulo 1000000.
    static func sasCode(_ sas: Data) -> String {
        let value = sas.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let code = String(value % 1_000_000)
        return String(repeating: "0", count: 6 - code.count) + code
    }

    /// Show the code as two groups of three digits, for example "482 193".
    static func formatCode(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }

    /// proof = HMAC-SHA256(k_proof, "laptop" || h).
    static func laptopProof(_ keys: PairingKeys) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data("laptop".utf8) + keys.h, using: SymmetricKey(data: keys.kProof)))
    }

    /// Check a proof in constant time.
    static func verifyProof(_ keys: PairingKeys, _ proof: Data) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: Data("laptop".utf8) + keys.h,
                                               using: SymmetricKey(data: keys.kProof))
    }

    /// RESULT plaintext: [port:u16][token_len:u8][token][host_len:u8][host].
    static func encodeCredentials(_ credentials: PairingCredentials) throws -> Data {
        let token = Data(credentials.token.utf8)
        let host = Data(credentials.host.utf8)
        guard credentials.port != 0, !token.isEmpty, token.count <= 255, !host.isEmpty, host.count <= 255 else {
            throw PairingError(reason: "invalid credentials")
        }
        var out = Data([UInt8(credentials.port >> 8), UInt8(credentials.port & 0xff), UInt8(token.count)])
        out += token
        out.append(UInt8(host.count))
        out += host
        return out
    }

    /// Parse the RESULT plaintext with strict lengths.
    static func decodeCredentials(_ bytes: Data) throws -> PairingCredentials {
        let b = [UInt8](bytes)
        guard b.count >= 3 else { throw PairingError(reason: "short plaintext") }
        let port = UInt16(b[0]) << 8 | UInt16(b[1])
        let tokenLength = Int(b[2])
        guard port != 0, tokenLength > 0, b.count >= 4 + tokenLength else { throw PairingError(reason: "bad plaintext") }
        let hostLength = Int(b[3 + tokenLength])
        guard hostLength > 0, b.count == 4 + tokenLength + hostLength,
              let token = String(bytes: b[3..<(3 + tokenLength)], encoding: .utf8),
              let host = String(bytes: b[(4 + tokenLength)...], encoding: .utf8)
        else { throw PairingError(reason: "bad plaintext") }
        return PairingCredentials(host: host, port: port, token: token)
    }

    /// ChaCha20-Poly1305 with key k_enc and aad h. Return ciphertext || tag.
    static func seal(_ keys: PairingKeys, nonce: Data, credentials: PairingCredentials) throws -> Data {
        let box = try ChaChaPoly.seal(try encodeCredentials(credentials), using: SymmetricKey(data: keys.kEnc),
                                      nonce: try ChaChaPoly.Nonce(data: nonce), authenticating: keys.h)
        return box.ciphertext + box.tag
    }

    static func open(_ keys: PairingKeys, nonce: Data, ciphertext: Data) throws -> PairingCredentials {
        guard ciphertext.count >= 16 else { throw PairingError(reason: "short ciphertext") }
        let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce),
                                           ciphertext: ciphertext.prefix(ciphertext.count - 16),
                                           tag: ciphertext.suffix(16))
        return try decodeCredentials(try ChaChaPoly.open(box, using: SymmetricKey(data: keys.kEnc), authenticating: keys.h))
    }

    static func sealMessage(_ keys: PairingKeys, nonce: Data, plaintext: Data) throws -> Data {
        let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: keys.kEnc),
                                      nonce: try ChaChaPoly.Nonce(data: nonce), authenticating: keys.h)
        return box.ciphertext + box.tag
    }

    static func openMessage(_ keys: PairingKeys, nonce: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw PairingError(reason: "short ciphertext") }
        let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce),
                                           ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
        return try ChaChaPoly.open(box, using: SymmetricKey(data: keys.kEnc), authenticating: keys.h)
    }

    static func encodeStatus(_ info: PairingPhoneInfo, challenge: Data) throws -> Data {
        let host = Data(info.host.utf8)
        guard challenge.count == 16, host.count <= 21 else { throw PairingError(reason: "invalid status") }
        let seq = info.sequence
        var result = challenge + Data([UInt8(truncatingIfNeeded: seq >> 24), UInt8(truncatingIfNeeded: seq >> 16),
                                       UInt8(truncatingIfNeeded: seq >> 8), UInt8(truncatingIfNeeded: seq),
                                       info.proxyRunning ? 1 : 0, info.foreground ? 1 : 0,
                                       UInt8(info.connections >> 8), UInt8(info.connections & 255),
                                       UInt8(info.port >> 8), UInt8(info.port & 255), UInt8(host.count)])
        result += host
        return result
    }

    static func encodeHello(lS: Data, commit: Data) -> Data { Data([hello, version]) + lS + commit }

    /// Parse HELLO. Return (L_s, C).
    static func decodeHello(_ message: Data) throws -> (Data, Data) {
        let b = [UInt8](message)
        guard (b.count == helloLength || (b.count == helloLength + 1 && b[66] & 0xfc == 0)), b[0] == hello, b[1] == version else { throw PairingError(reason: "bad hello") }
        return (Data(b[2..<34]), Data(b[34..<66]))
    }

    static func encodeChallenge(pE: Data, known: Bool) -> Data { Data([challenge]) + pE + Data([known ? 1 : 0]) }

    static func encodeReveal(lE: Data, proof: Data) -> Data { Data([reveal]) + lE + proof }

    /// Parse REVEAL. Return (L_e, proof).
    static func decodeReveal(_ message: Data) throws -> (Data, Data) {
        let b = [UInt8](message)
        guard b.count == revealLength, b[0] == reveal else { throw PairingError(reason: "bad reveal") }
        return (Data(b[1..<33]), Data(b[33..<65]))
    }

    static func encodeResult(_ status: PairingStatus) -> Data { Data([result, status.rawValue]) }

    static func encodeResultOK(nonce: Data, ciphertext: Data) -> Data {
        Data([result, PairingStatus.ok.rawValue]) + nonce + ciphertext
    }

    /// Prefix the payload with its u16 big-endian length.
    static func frame(_ payload: Data) -> Data {
        precondition(!payload.isEmpty && payload.count <= maxFrame)
        return Data([UInt8(payload.count >> 8), UInt8(payload.count & 0xff)]) + payload
    }
}

/// Collect frames from a byte stream. Reject an empty or oversize frame.
struct PairingFrameReader {
    private var buffer = Data()

    mutating func push(_ bytes: Data) { buffer += bytes }

    /// Return the next complete frame, or nil when more bytes are needed.
    mutating func next() throws -> Data? {
        let b = [UInt8](buffer.prefix(2))
        guard b.count == 2 else { return nil }
        let length = Int(b[0]) << 8 | Int(b[1])
        guard length > 0, length <= PairingProtocol.maxFrame else { throw PairingError(reason: "bad frame length") }
        guard buffer.count >= 2 + length else { return nil }
        let start = buffer.startIndex
        let payload = Data(buffer[(start + 2)..<(start + 2 + length)])
        buffer = Data(buffer[(start + 2 + length)...])
        return payload
    }
}

/// The list of laptop static public keys that the phone trusts.
protocol PairingTrustStore: AnyObject {
    func contains(_ key: Data) -> Bool
    func add(_ key: Data)
    func remove(_ key: Data)
    func removeAll()
    var count: Int { get }
}

final class MemoryTrustStore: PairingTrustStore {
    private var keys: Set<Data> = []
    private let lock = NSLock()
    func contains(_ key: Data) -> Bool { lock.lock(); defer { lock.unlock() }; return keys.contains(key) }
    func add(_ key: Data) { lock.lock(); keys.insert(key); lock.unlock() }
    func remove(_ key: Data) { lock.lock(); keys.remove(key); lock.unlock() }
    func removeAll() { lock.lock(); keys.removeAll(); lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return keys.count }
}

/// Store public keys only, base64, in UserDefaults.
final class UserDefaultsTrustStore: PairingTrustStore {
    private let defaults: UserDefaults
    private let key: String
    private let lock = NSLock()

    init(defaults: UserDefaults = .standard, key: String = "pairedLaptops") {
        self.defaults = defaults
        self.key = key
    }

    private func load() -> [String] { defaults.stringArray(forKey: key) ?? [] }

    func contains(_ publicKey: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return load().contains(publicKey.base64EncodedString())
    }

    func add(_ publicKey: Data) {
        lock.lock(); defer { lock.unlock() }
        let value = publicKey.base64EncodedString()
        var list = load()
        guard !list.contains(value) else { return }
        list.append(value)
        defaults.set(list, forKey: key)
    }

    func remove(_ publicKey: Data) {
        lock.lock(); defer { lock.unlock() }
        defaults.set(load().filter { $0 != publicKey.base64EncodedString() }, forKey: key)
    }

    func removeAll() {
        lock.lock(); defer { lock.unlock() }
        defaults.removeObject(forKey: key)
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return load().count }
}

/// One atomic snapshot for the host to display and later approve or deny.
struct PairingPrompt: Equatable {
    let id: UUID
    /// The connection that owns the prompt. The responder sets it. The app
    /// display model leaves it at zero because the server owns the decision.
    let connection: Int
    let code: String

    init(id: UUID, code: String, connection: Int = 0) {
        self.id = id
        self.code = code
        self.connection = connection
    }
}

/// The debug and display text redact the code. A log line must not hold a
/// value that a person reads from the screen.
extension PairingPrompt: CustomStringConvertible, CustomDebugStringConvertible {
    var description: String {
        "PairingPrompt(id: \(id), connection: \(connection), code: \"[redacted]\")"
    }

    var debugDescription: String { description }
}

/// The phone pairing state machine. It takes frames and returns frames.
/// One pairing runs at a time. The caller owns the sockets, runs every call
/// on one queue, and calls `tick` when `nextDeadline` passes.
final class PairingResponder {
    static let decisionSeconds: TimeInterval = 60
    static let inactiveDecisionSeconds: TimeInterval = 120
    static let failureWindow: TimeInterval = 60
    static let failuresForLockout = 3
    static let lockoutSeconds: TimeInterval = 30
    /// The largest peer identifier that the responder accepts. A source
    /// address text is shorter than this limit.
    static let maximumPeerLength = 64
    // Limit untrusted challenges before generating an ephemeral key. A
    // per-address limit alone is not enough when a peer changes addresses.
    static let challengeWindow: TimeInterval = 60
    /// The largest number of unknown challenges from one source address in
    /// `challengeWindow`. One source address cannot use the whole global
    /// budget.
    static let maximumPeerChallenges = 4
    /// The largest number of unknown challenges across all source addresses
    /// in `challengeWindow`.
    static let maximumUnknownChallenges = 8

    struct Output: Equatable {
        var connection: Int
        var frames: [Data] = []
        var close = false
        var status: PairingStatus?
    }
    private enum Stage {
        case awaitingReveal
        case awaitingDecision(PairingKeys, UUID)
        case authenticated(PairingKeys)
    }
    private struct Session {
        let connection: Int
        let lS: Data
        let commit: Data
        let ephemeral: Curve25519.KeyAgreement.PrivateKey
        let known: Bool
        let flags: UInt8
        var shownActive: Bool
        var deadline: TimeInterval
        /// The time of the first inactive notice for a live prompt. The
        /// extension cap starts at this value.
        var firstDeactivate: TimeInterval?
        var stage: Stage
    }
    private struct Budget {
        var failures: [TimeInterval] = []
        var until: TimeInterval = 0
        var level = 0
    }
    private let trust: PairingTrustStore
    private let credentials: () -> PairingCredentials?
    private let ephemeralKey: () -> Curve25519.KeyAgreement.PrivateKey
    private let nonce: () -> Data
    private let statusProvider: () -> PairingPhoneInfo?
    private var sessions: [Int: Session] = [:]
    private var peers: [Int: String] = [:]
    private var budgets: [String: Budget] = [:]
    private var decision: Int?
    private var unknownBudget: [String: [TimeInterval]] = [:]
    /// The times of the unknown challenges for each source address. The sum
    /// of the lists is at most `maximumUnknownChallenges`, so the map stays
    /// small.
    private var unknownChallenges: [String: [TimeInterval]] = [:]
    private var lastNow: TimeInterval = 0
    private var inactive = false
    private var failures: [String: [TimeInterval]] = [:]
    /// Source address to the end of its lockout. The map is capped at 256
    /// entries and pruned, so a hostile hotspot cannot grow it without bound.
    private var lockouts: [String: TimeInterval] = [:]

    init(trust: PairingTrustStore,
         credentials: @escaping () -> PairingCredentials?,
         ephemeralKey: @escaping () -> Curve25519.KeyAgreement.PrivateKey = { Curve25519.KeyAgreement.PrivateKey() },
         nonce: @escaping () -> Data = { Data(ChaChaPoly.Nonce()) },
         status: @escaping () -> PairingPhoneInfo? = { nil }) {
        self.trust = trust
        self.credentials = credentials
        self.ephemeralKey = ephemeralKey
        self.nonce = nonce
        self.statusProvider = status
    }

    /// The current unexpired prompt. The host must return this connection,
    /// this ID, and this code with the person's decision. Nil means that no
    /// prompt waits or that its deadline passed.
    var pendingPrompt: PairingPrompt? {
        guard let id = decision, let session = sessions[id],
              case .awaitingDecision(let keys, let promptID) = session.stage,
              lastNow < session.deadline else { return nil }
        return PairingPrompt(id: promptID,
                             code: PairingProtocol.formatCode(PairingProtocol.sasCode(keys.sas)),
                             connection: id)
    }
    var pendingCode: String? { pendingPrompt?.code }
    var nextDeadline: TimeInterval? { sessions.values.map(\.deadline).min() }
    /// The recorded prompt failures that the expiration rule keeps. The value
    /// holds no address and no key. The tests use it to check that only a
    /// visible prompt timeout counts.
    var promptFailureCount: Int { failures.values.reduce(0) { $0 + $1.count } }

    func receive(_ frame: Data, connection: Int, now: TimeInterval, active: Bool, peer: String) throws -> Output {
        let peer = try Self.canonicalPeer(peer)
        inactive = !active
        lastNow = now
        // A prompt that already passed its deadline was not visible. Do not
        // mark it visible, or the timeout counts as a prompt failure.
        if active, let id = decision, var pending = sessions[id],
           case .awaitingDecision = pending.stage, now < pending.deadline {
            pending.shownActive = true
            sessions[id] = pending
        }
        peers[connection] = peer
        if let session = sessions[connection] {
            if now >= session.deadline { return expire(session, now: now) }
            switch session.stage {
            case .awaitingReveal: return receiveReveal(frame, session: session, now: now, active: active)
            case .awaitingDecision:
                sessions.removeValue(forKey: connection)
                decision = nil
                if frame.first == 0x05 { return reply(connection, .rejected) }
                return bad(connection, now: now)
            case .authenticated(let keys): return receiveStatus(frame, connection: connection, keys: keys, now: now)
            }
        }
        guard let (lS, commit) = try? PairingProtocol.decodeHello(frame) else { return bad(connection, now: now) }
        let known = trust.contains(lS)
        let flags = frame.count == 67 ? frame.last! : 0
        if !known && flags != 0 { return reply(connection, .rejected, log: false) }
        if !known && isLocked(now: now, peer: peer) { return reply(connection, .lockedOut) }
        if !known, let budget = budgets[peer], now < budget.until { return reply(connection, .rejected) }
        if !known {
            // A source device with pairing off answers NotActive. It must not
            // charge the challenge budget, or the peer is locked out later.
            guard credentials() != nil else { return reply(connection, .notActive) }
            pruneChallenges(now: now)
            // Charge both challenge budgets before the ephemeral key exists.
            // An active attacker must not get a fresh handshake for each
            // connection attempt.
            guard !challengeBudgetUsed(peer: peer) else {
                return reply(connection, .busy, log: false)
            }
            unknownChallenges[peer, default: []].append(now)
        }
        let ephemeral = ephemeralKey()
        sessions[connection] = Session(connection: connection, lS: lS, commit: commit, ephemeral: ephemeral,
                                       known: known, flags: flags, shownActive: false, deadline: now + 5,
                                       firstDeactivate: nil, stage: .awaitingReveal)
        let challenge = PairingProtocol.encodeChallenge(pE: ephemeral.publicKey.rawRepresentation, known: known)
        return Output(connection: connection, frames: [PairingProtocol.frame(challenge)])
    }
    /// Handle a frame parser error for a connection. This method removes the
    /// session and the decision before it checks the peer text. A failed check
    /// must not leak a session slot or leave a prompt unanswerable.
    func receiveInvalid(connection: Int, now: TimeInterval, peer: String) throws -> Output {
        let sessionPeer = peers[connection]
        sessions.removeValue(forKey: connection)
        if decision == connection { decision = nil }
        let peer = try Self.canonicalPeer(peer)
        lastNow = now
        peers[connection] = sessionPeer ?? peer
        return bad(connection, now: now)
    }
    /// Apply the person's decision to the pending prompt. The connection, the
    /// prompt ID, and the code must name the prompt that the person saw. A
    /// stale connection, a stale prompt, a different code, or an expired
    /// deadline does not approve a prompt. Nil means that no prompt waits for
    /// this decision. An expired prompt returns a timeout for the host to
    /// send and close.
    func decide(connection: Int, promptID: UUID, code: String, allow: Bool, now: TimeInterval) -> Output? {
        lastNow = now
        guard decision == connection, let current = sessions[connection],
              case .awaitingDecision(let keys, let currentID) = current.stage else { return nil }
        guard currentID == promptID,
              PairingProtocol.formatCode(PairingProtocol.sasCode(keys.sas)) == code else { return nil }
        guard now < current.deadline else { return expire(current, now: now) }
        decision = nil
        sessions.removeValue(forKey: connection)
        guard allow else { return finish(connection, .denied, now: now) }
        return success(current, keys: keys, now: now, addTrust: true)
    }
    func tick(now: TimeInterval) -> Output? {
        lastNow = now
        guard let current = sessions.values.filter({ now >= $0.deadline }).min(by: { $0.deadline < $1.deadline }) else { return nil }
        return expire(current, now: now)
    }
    private func expire(_ current: Session, now: TimeInterval) -> Output {
        sessions.removeValue(forKey: current.connection)
        if decision == current.connection { decision = nil }
        if case .awaitingDecision = current.stage {
            if current.shownActive && !inactive { return finish(current.connection, .timedOut, now: now) }
            return reply(current.connection, .timedOut)
        }
        return reply(current.connection, .timedOut)
    }
    /// Mark the app as active. A pending prompt becomes visible only when its
    /// deadline has not passed. A prompt that was never visible before its
    /// deadline is not a visible timeout.
    func activate() {
        inactive = false
        guard let id = decision, var current = sessions[id],
              case .awaitingDecision = current.stage, lastNow < current.deadline else { return }
        current.shownActive = true
        sessions[id] = current
    }
    /// Mark the app as inactive. A live prompt gets at most 120 seconds after
    /// the first inactive notice. A repeated notice cannot extend the prompt
    /// past that limit. An expired prompt returns a timeout for the host to
    /// send and close. A prompt that is not live is not extended.
    func deactivate(now: TimeInterval) -> Output? {
        lastNow = now
        inactive = true
        guard let id = decision, let current = sessions[id],
              case .awaitingDecision = current.stage else { return nil }
        guard now < current.deadline else { return expire(current, now: now) }
        var extended = current
        let first = extended.firstDeactivate ?? now
        extended.firstDeactivate = first
        let cap = first + Self.inactiveDecisionSeconds
        let target = min(now + Self.inactiveDecisionSeconds, cap)
        if target > extended.deadline { extended.deadline = target }
        sessions[id] = extended
        return nil
    }
    func connectionClosed(_ connection: Int) {
        sessions.removeValue(forKey: connection)
        peers.removeValue(forKey: connection)
        unknownBudget = unknownBudget.mapValues { $0.filter { lastNow - $0 < 600 } }.filter { !$0.value.isEmpty }
        budgets = budgets.filter { lastNow < $0.value.until || $0.value.failures.contains { lastNow - $0 < 60 } }
        failures = failures.mapValues { $0.filter { lastNow - $0 < Self.failureWindow } }.filter { !$0.value.isEmpty }
        lockouts = lockouts.filter { lastNow < $0.value }
        pruneChallenges(now: lastNow)
        if decision == connection { decision = nil }
    }
    /// A source address is locked out for 30 seconds after 3 denied decisions.
    /// The lockout replaces the prompt-attempt budget: when it ends, the
    /// source gets a fresh set of attempts, so a REVEAL is served again and
    /// not only a CHALLENGE. Lockouts are kept per source address.
    func isLocked(now: TimeInterval, peer: String) -> Bool {
        lockouts = lockouts.filter { now < $0.value }
        guard let until = lockouts[peer] else { return false }
        return now < until
    }
    /// True when the source address or the whole responder has no challenge
    /// budget left for the current window. Call `pruneChallenges` first.
    private func challengeBudgetUsed(peer: String) -> Bool {
        let peerCount = unknownChallenges[peer]?.count ?? 0
        let total = unknownChallenges.values.reduce(0) { $0 + $1.count }
        return peerCount >= Self.maximumPeerChallenges || total >= Self.maximumUnknownChallenges
    }
    private func pruneChallenges(now: TimeInterval) {
        unknownChallenges = unknownChallenges.compactMapValues { times in
            // A backwards clock is not evidence that the window has expired.
            let kept = times.filter { now < $0 || now - $0 < Self.challengeWindow }
            return kept.isEmpty ? nil : kept
        }
    }
    /// Reject an empty peer identifier. Also reject a value above
    /// `maximumPeerLength` and a value with a byte outside visible ASCII. The
    /// host passes the source address text.
    private static func validatePeer(_ peer: String) throws {
        guard !peer.isEmpty,
              peer.utf8.count <= maximumPeerLength,
              peer.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw PairingError(reason: "invalid peer")
        }
    }
    /// Return the rate-limit key for one peer identifier. An IP address is
    /// canonicalized, so alternate spellings share one budget. An IPv4-mapped
    /// IPv6 address maps to its IPv4 form. A text with a port or a zone is
    /// rejected, because it would give one address more than one budget.
    private static func canonicalPeer(_ peer: String) throws -> String {
        try validatePeer(peer)
        // A zone identifier would give one address more than one budget. The
        // IPv6 parser accepts a zone text, so reject it first.
        if peer.contains("%") { throw PairingError(reason: "invalid peer") }
        if let address = canonicalAddress(peer) { return address }
        if parsesAsSocketAddress(peer) { throw PairingError(reason: "invalid peer") }
        return peer
    }
    /// The canonical text for one IP address. An IPv4-mapped IPv6 address maps
    /// to its IPv4 form.
    private static func canonicalAddress(_ text: String) -> String? {
        if let address = IPv4Address(text) { return address.debugDescription }
        guard let address = IPv6Address(text) else { return nil }
        let bytes = [UInt8](address.rawValue)
        if bytes.count == 16, bytes.prefix(10).allSatisfy({ $0 == 0 }),
           bytes[10] == 0xff, bytes[11] == 0xff {
            return IPv4Address(Data(bytes[12..<16]))?.debugDescription
        }
        return address.debugDescription
    }
    /// True when the text names an address and a port. Such a text would give
    /// one address more than one budget.
    private static func parsesAsSocketAddress(_ text: String) -> Bool {
        guard let colon = text.lastIndex(of: ":") else { return false }
        let host = String(text[..<colon])
        let port = String(text[text.index(after: colon)...])
        guard !host.isEmpty, !port.isEmpty,
              port.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              let value = UInt32(port), value <= 65535 else { return false }
        if host.hasPrefix("["), host.hasSuffix("]"), host.count > 2 {
            return IPv6Address(String(host.dropFirst().dropLast())) != nil
        }
        return IPv4Address(host) != nil
    }
    private func receiveReveal(_ frame: Data, session current: Session, now: TimeInterval, active: Bool) -> Output {
        let id = current.connection
        sessions.removeValue(forKey: id)
        guard let (lE, proof) = try? PairingProtocol.decodeReveal(frame),
              PairingProtocol.commitment(lE: lE, lS: current.lS) == current.commit,
              let ee = try? PairingProtocol.agree(current.ephemeral, lE),
              let es = try? PairingProtocol.agree(current.ephemeral, current.lS) else { return bad(id, now: now) }
        let pE = current.ephemeral.publicKey.rawRepresentation
        let keys = PairingProtocol.deriveKeys(ee: ee, es: es, h: PairingProtocol.transcriptHash(lS: current.lS, lE: lE, pE: pE))
        guard PairingProtocol.verifyProof(keys, proof) else { return bad(id, now: now) }
        if current.known {
            if current.flags != 0 {
                var authenticated = current
                authenticated.stage = .authenticated(keys)
                authenticated.deadline = now + 5
                sessions[id] = authenticated
                return Output(connection: id)
            }
            return success(current, keys: keys, now: now)
        }
        guard decision == nil else { return reply(id, .busy) }
        // Check the credentials before the attempt budget. A source device
        // with pairing off answers NotActive. It must not charge the budget,
        // or the peer is locked out for the whole attempt window.
        guard credentials() != nil else { return reply(id, .notActive) }
        let peer = peers[id] ?? ""
        unknownBudget = unknownBudget.mapValues { $0.filter { now - $0 < 600 } }.filter { !$0.value.isEmpty }
        if unknownBudget[peer] == nil && unknownBudget.count >= 256 { return reply(id, .lockedOut) }
        var attempts = unknownBudget[peer] ?? []
        guard attempts.count < 3 else { return reply(id, .lockedOut) }
        attempts.append(now)
        unknownBudget[peer] = attempts
        var waiting = current
        waiting.deadline = now + (active ? Self.decisionSeconds : Self.inactiveDecisionSeconds)
        waiting.shownActive = active
        waiting.stage = .awaitingDecision(keys, UUID())
        sessions[id] = waiting
        decision = id
        return Output(connection: id)
    }
    private func success(_ current: Session, keys: PairingKeys, now: TimeInterval, addTrust: Bool = false) -> Output {
        let nonceBytes = nonce()
        guard let credentials = credentials(), let ciphertext = try? PairingProtocol.seal(keys, nonce: nonceBytes, credentials: credentials)
        else { return reply(current.connection, .notActive) }
        // Add the target device to the trust store only after the result is
        // ready. A failed result must not leave a trusted key behind.
        if addTrust { trust.add(current.lS) }
        var authenticated = current
        authenticated.stage = .authenticated(keys)
        authenticated.deadline = now + 5
        sessions[current.connection] = authenticated
        let message = PairingProtocol.encodeResultOK(nonce: nonceBytes, ciphertext: ciphertext)
        return Output(connection: current.connection, frames: [PairingProtocol.frame(message)], close: false, status: .ok)
    }
    private func receiveStatus(_ frame: Data, connection: Int, keys: PairingKeys, now: TimeInterval) -> Output {
        // Read the session once. The trust list can change between HELLO and this frame, so
        // no code below may assume that a session or a trusted key still exists.
        guard let session = sessions[connection] else { return reply(connection, .rejected) }
        if session.flags == 2 {
            sessions.removeValue(forKey: connection)
            if frame.count >= 29, frame.first == 0x07, trust.contains(session.lS),
               let request = try? PairingProtocol.openMessage(keys, nonce: Data(frame.dropFirst().prefix(12)), ciphertext: Data(frame.dropFirst(13))),
               request.isEmpty {
                trust.remove(session.lS)
                return reply(connection, .ok, log: false)
            }
            return reply(connection, .rejected)
        }
        guard trust.contains(session.lS), frame.count >= 29, frame.first == 0x05,
              let request = try? PairingProtocol.openMessage(keys, nonce: Data(frame.dropFirst().prefix(12)), ciphertext: Data(frame.dropFirst(13))),
              request.count == 17, let info = statusProvider(),
              let plaintext = try? PairingProtocol.encodeStatus(info, challenge: Data(request.prefix(16))) else {
            sessions.removeValue(forKey: connection)
            return reply(connection, .rejected)
        }
        let responseNonce = nonce()
        guard let response = try? PairingProtocol.sealMessage(keys, nonce: responseNonce, plaintext: plaintext) else { return reply(connection, .rejected) }
        sessions.removeValue(forKey: connection)
        return Output(connection: connection, frames: [PairingProtocol.frame(Data([0x06]) + responseNonce + response)], close: true)
    }
    private func bad(_ connection: Int, now: TimeInterval) -> Output {
        let peer = peers[connection] ?? ""
        if budgets[peer] == nil && budgets.count >= 256 { return reply(connection, .rejected) }
        var budget = budgets[peer] ?? Budget()
        budget.failures = budget.failures.filter { now - $0 < 60 }
        budget.failures.append(now)
        if budget.failures.count >= 10 {
            budget.until = now + pow(2, Double(min(budget.level, 2)))
            budget.level = min(budget.level + 1, 2)
            budget.failures = []
        }
        budgets[peer] = budget
        return reply(connection, .rejected)
    }
    private func finish(_ connection: Int, _ status: PairingStatus, now: TimeInterval) -> Output {
        let peer = peers[connection] ?? ""
        var recent = (failures[peer] ?? []).filter { now - $0 < Self.failureWindow }
        recent.append(now)
        if recent.count >= Self.failuresForLockout {
            lockouts = lockouts.filter { now < $0.value }
            if lockouts[peer] != nil || lockouts.count < 256 {
                lockouts[peer] = now + Self.lockoutSeconds
            }
            // The lockout replaces the prompt-attempt budget. A REVEAL is
            // served again after it ends.
            unknownBudget[peer] = nil
            recent = []
        }
        if failures[peer] != nil || failures.count < 256 { failures[peer] = recent }
        return reply(connection, status)
    }
    private func reply(_ connection: Int, _ status: PairingStatus, log: Bool = true) -> Output {
        Output(connection: connection, frames: [PairingProtocol.frame(PairingProtocol.encodeResult(status))], close: true, status: log ? status : nil)
    }
}
