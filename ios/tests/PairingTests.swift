import Foundation
import CryptoKit

// Fixed public test vectors. rust/src/pairing.rs holds the same values.
// Change both files together.
enum Vectors {
    static let lSPrivate = Data(repeating: 0x11, count: 32)
    static let lEPrivate = Data(repeating: 0x22, count: 32)
    static let pEPrivate = Data(repeating: 0x33, count: 32)
    static let nonce = Data(repeating: 0x44, count: 12)
    static let token = "test-token-0123456789abcdef"
    static let lS = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
    static let lE = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
    static let pE = "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14"
    static let c = "c7bf4d2e3388ea312b7750dbcfc430402b2c6b1e457fe2ee1ffeae09a4fd3aeb"
    static let ee = "1fdc192faa0212a9aae7bb4f41b580227fd5ad3e5d777faae230dfe973f3e805"
    static let es = "5bf22caf31c0316785b0b9bc60e56d48582ce59435ce5b3c028052be42631e0f"
    static let h = "51e50f017883e3dde1ea99a473a142dfd758835adfdc933f706b3d2e9752b1b7"
    static let kEnc = "d15b719f5c092e967be6a0a355bb972014e6245ff4d7ea9a53434878b8358b78"
    static let kProof = "09089c6978faac4cc8f0ae44767a3fd8789346826ef99366d2f8c13e09ece263"
    static let sas = "e961ca48"
    static let code = "500104"
    static let proof = "7554e349e225b68c5c2310ce69bf08c44f6aac2c73ac5a11e75a8142c1f7f97a"
    static let ciphertext = "132a89d1add706e92d7844032a37f2486c9f386e21255687facf153edc23e7dced55371101721d50afaa326d1fb62e2c270f1501bb51d043e9c8"
}

func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

func key(_ raw: Data) -> Curve25519.KeyAgreement.PrivateKey {
    try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
}

func check(_ condition: Bool, _ message: String, line: Int = #line) {
    if !condition {
        print("FAIL line \(line): \(message)")
        exit(1)
    }
}

/// A test laptop. It runs the laptop side of the protocol with fixed keys.
struct TestLaptop {
    var staticKey = key(Vectors.lSPrivate)
    var ephemeralKey = key(Vectors.lEPrivate)
    var lS: Data { staticKey.publicKey.rawRepresentation }
    var lE: Data { ephemeralKey.publicKey.rawRepresentation }

    func hello(commitTo other: Data? = nil) -> Data {
        PairingProtocol.encodeHello(lS: lS, commit: PairingProtocol.commitment(lE: other ?? lE, lS: lS))
    }

    func keys(pE: Data) -> PairingKeys {
        let ee = try! PairingProtocol.agree(ephemeralKey, pE)
        let es = try! PairingProtocol.agree(staticKey, pE)
        return PairingProtocol.deriveKeys(ee: ee, es: es, h: PairingProtocol.transcriptHash(lS: lS, lE: lE, pE: pE))
    }

    /// Parse CHALLENGE and build REVEAL. Return the keys too.
    func reveal(challengeFrame: Data, breakProof: Bool = false) -> (Data, PairingKeys, Bool) {
        let challenge = [UInt8](unframe(challengeFrame))
        check(challenge.count == 34 && challenge[0] == 0x02, "challenge shape")
        let pE = Data(challenge[1..<33])
        let keys = keys(pE: pE)
        var proof = PairingProtocol.laptopProof(keys)
        if breakProof { proof[proof.startIndex] ^= 1 }
        return (PairingProtocol.encodeReveal(lE: lE, proof: proof), keys, challenge[33] == 1)
    }
}

/// The responder takes frame payloads. The socket code strips the length prefix.
func message(_ payload: Data) -> Data { payload }

func unframe(_ framed: Data) -> Data {
    var reader = PairingFrameReader()
    try! reader.push(framed)
    return try! reader.next()!
}

func status(_ output: PairingResponder.Output?) -> PairingStatus? {
    guard let output = output, let last = output.frames.last else { return nil }
    let message = [UInt8](unframe(last))
    guard message.first == 0x04, message.count >= 2 else { return nil }
    return PairingStatus(rawValue: message[1])
}

/// The tests that do not name a source address use one fixed address. The
/// peer-budget tests name the address and call the throwing method.
extension PairingResponder {
    func receive(_ frame: Data, connection: Int, now: TimeInterval, active: Bool) -> Output {
        try! receive(frame, connection: connection, now: now, active: active, peer: "peer")
    }

    func receiveInvalid(connection: Int, now: TimeInterval) -> Output {
        try! receiveInvalid(connection: connection, now: now, peer: "peer")
    }
}

/// Apply a decision to the prompt that the host shows now.
func decidePending(_ phone: PairingResponder, allow: Bool, now: TimeInterval) -> PairingResponder.Output? {
    guard let prompt = phone.pendingPrompt else { return nil }
    return phone.decide(connection: prompt.connection, promptID: prompt.id, code: prompt.code,
                        allow: allow, now: now)
}

@main
struct PairingTests {
    static let credentials = PairingCredentials(host: "172.20.10.1", port: 1080, token: Vectors.token)!

    static func responder(trust: PairingTrustStore = MemoryTrustStore(),
                          credentials: PairingCredentials? = PairingTests.credentials) -> PairingResponder {
        PairingResponder(trust: trust, credentials: { credentials },
                         ephemeralKey: { key(Vectors.pEPrivate) }, nonce: { Vectors.nonce })
    }

    static func main() {
        parityVectors()
        framing()
        unknownAllowThenKnown()
        deny()
        badCommitmentProofAndLength()
        timeoutBusyAndInactive()
        lockout()
        statusChannel()
        knownStatusOnly()
        sourceBudget()
        statusOnlyAndForget()
        independentSources()
        perPeerLockout()
        unknownChallengeBudget()
        peerChallengeBudget()
        knownChallengeBudget()
        knownRefundUsesTheProvenSession()
        knownForgottenBeforeReveal()
        unsupportedFlags()
        sessionCap()
        emptyPeerIsRejected()
        receiveInvalidReleasesTheSession()
        pairingOffChargesNoBudget()
        peerCanonicalization()
        promptVisibility()
        deactivateCap()
        promptDebugRedaction()
        credentialDebugRedaction()
        expiredDecisionsCannotBeApproved()
        staleDecisionCannotApproveAnotherPrompt()
        tamperedCiphertext()
        credentialConstructorRules()
        credentialParsingIsStrict()
        statusRequiresLiveCredentials()
        encodeStatusValidation()
        sessionNonceReuse()
        frameReaderBound()
        frameErrorsAreTyped()
        trustStore()
        print("Pairing tests passed")
    }

    static func unknownChallengeBudget() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        var generated = 0
        let phone = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { generated += 1; return key(Vectors.pEPrivate) },
                                     nonce: { Vectors.nonce })
        for id in 0..<PairingResponder.maximumUnknownChallenges {
            let result = try! phone.receive(laptop.hello(), connection: id, now: 0, active: true, peer: "peer-\(id)")
            check(!result.close, "unknown challenge \(id) is allowed")
            phone.connectionClosed(id)
        }
        let blocked = try! phone.receive(laptop.hello(), connection: 99, now: 1, active: true, peer: "another-peer")
        check(status(blocked) == .busy && generated == PairingResponder.maximumUnknownChallenges,
              "the global budget refuses a challenge before key generation")
        trust.add(laptop.lS)
        let known = try! phone.receive(laptop.hello(), connection: 100, now: 2, active: true, peer: "known")
        check(!known.close, "known targets can still use the status channel")
        phone.connectionClosed(100)
        trust.remove(laptop.lS)
        let later = try! phone.receive(laptop.hello(), connection: 101, now: 60, active: true, peer: "another-peer")
        check(!later.close, "the challenge window eventually expires")
    }

    static func peerChallengeBudget() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        var generated = 0
        let phone = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { generated += 1; return key(Vectors.pEPrivate) },
                                     nonce: { Vectors.nonce })

        // One source address gets four challenges.
        for id in 0..<PairingResponder.maximumPeerChallenges {
            let output = try! phone.receive(laptop.hello(), connection: id, now: 0, active: true, peer: "peer-a")
            check(!output.close && output.frames.count == 1, "peer-a challenge \(id)")
            phone.connectionClosed(id)
        }
        let refused = try! phone.receive(laptop.hello(), connection: 10, now: 0, active: true, peer: "peer-a")
        check(status(refused) == .busy, "the per-address budget is spent")
        // A refused challenge must not create an ephemeral key or a session.
        check(generated == PairingResponder.maximumPeerChallenges, "a refused challenge creates no key")
        check(phone.nextDeadline == nil, "a refused challenge creates no session")

        // Another source address has its own budget until the global limit.
        let other = try! phone.receive(laptop.hello(), connection: 11, now: 0, active: true, peer: "peer-b")
        check(!other.close && other.frames.count == 1, "peer-b has its own budget")
        phone.connectionClosed(11)

        // peer-a holds four and peer-b holds one. Three more addresses fill
        // the global budget of eight.
        for index in 0..<(PairingResponder.maximumUnknownChallenges - PairingResponder.maximumPeerChallenges - 1) {
            let id = 20 + index
            let output = try! phone.receive(laptop.hello(), connection: id, now: 0, active: true, peer: "peer-c\(index)")
            check(!output.close && output.frames.count == 1, "peer-c\(index) challenge")
            phone.connectionClosed(id)
        }
        let global = try! phone.receive(laptop.hello(), connection: 30, now: 0, active: true, peer: "peer-d")
        check(status(global) == .busy, "the global budget is spent")
        check(generated == PairingResponder.maximumUnknownChallenges, "a globally refused challenge creates no key")

        // The window clears both budgets.
        let later = try! phone.receive(laptop.hello(), connection: 31, now: 60, active: true, peer: "peer-a")
        check(!later.close && later.frames.count == 1, "the challenge window clears both budgets")
    }

    static func knownChallengeBudget() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        trust.add(laptop.lS)
        var generated = 0
        let phone = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { generated += 1; return key(Vectors.pEPrivate) },
                                     nonce: { Vectors.nonce })

        // The trusted public key is public. A claim of it that never sends a
        // proof spends the known budget, so it cannot generate keys without
        // bound.
        for id in 0..<PairingResponder.maximumKnownPeerChallenges {
            let output = try! phone.receive(laptop.hello(), connection: id, now: 0, active: true, peer: "peer-a")
            check(!output.close && output.frames.count == 1, "known challenge \(id)")
            phone.connectionClosed(id)
        }
        check(generated == PairingResponder.maximumKnownPeerChallenges,
              "one key for each known challenge")
        let refused = try! phone.receive(laptop.hello(), connection: 20, now: 0, active: true, peer: "peer-a")
        check(status(refused) == .busy, "the per-address known budget is spent")
        check(generated == PairingResponder.maximumKnownPeerChallenges,
              "a refused known challenge creates no key")
        check(phone.nextDeadline == nil, "a refused known challenge creates no session")

        // Another source address has its own budget until the global limit.
        let other = try! phone.receive(laptop.hello(), connection: 21, now: 0, active: true, peer: "peer-b")
        check(!other.close && other.frames.count == 1, "another address has its own known budget")
        phone.connectionClosed(21)
        var index = 0
        while generated < PairingResponder.maximumKnownChallenges,
              index < PairingResponder.maximumKnownChallenges {
            let id = 30 + index
            let output = try! phone.receive(laptop.hello(), connection: id, now: 0, active: true,
                                            peer: "peer-c\(index)")
            check(!output.close, "global known challenge \(index)")
            phone.connectionClosed(id)
            index += 1
        }
        let global = try! phone.receive(laptop.hello(), connection: 60, now: 0, active: true, peer: "peer-d")
        check(status(global) == .busy, "the global known budget is spent")
        check(generated == PairingResponder.maximumKnownChallenges,
              "a globally refused challenge creates no key")

        // The unknown budget is separate. An unpaired target device can still
        // start while the known budget is spent.
        let stranger = TestLaptop(staticKey: key(Data(repeating: 0x77, count: 32)))
        let unknown = try! phone.receive(stranger.hello(), connection: 61, now: 0, active: true, peer: "peer-e")
        check(!unknown.close && unknown.frames.count == 1,
              "the known budget does not block an unknown target")
        check(generated == PairingResponder.maximumKnownChallenges + 1,
              "an unknown challenge uses its own budget")
        phone.connectionClosed(61)

        // The presence probe runs every few seconds. A verified proof refunds
        // its charge, so the target's own status checks are not limited.
        var probeGenerated = 0
        let probe = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { probeGenerated += 1; return key(Vectors.pEPrivate) },
                                     nonce: { Vectors.nonce })
        for round in 0..<30 {
            let now = Double(round) * 0.5
            let challenge = try! probe.receive(laptop.hello() + Data([1]), connection: round, now: now,
                                               active: true, peer: "172.20.10.2")
            check(!challenge.close && challenge.frames.count == 1, "status probe \(round) gets a challenge")
            let (reveal, _, known) = laptop.reveal(challengeFrame: challenge.frames[0])
            check(known, "the probe sees a known challenge")
            let proof = try! probe.receive(reveal, connection: round, now: now + 0.1,
                                           active: true, peer: "172.20.10.2")
            check(proof.frames.isEmpty && !proof.close, "the probe authenticates")
            probe.connectionClosed(round)
        }
        check(probeGenerated == 30, "every legitimate probe gets its own key")

        // A bad proof does not refund. Eight claims spend the budget and the
        // ninth answers Busy.
        var brokenGenerated = 0
        let broken = PairingResponder(trust: trust, credentials: { credentials },
                                      ephemeralKey: { brokenGenerated += 1; return key(Vectors.pEPrivate) },
                                      nonce: { Vectors.nonce })
        for round in 0..<PairingResponder.maximumKnownPeerChallenges {
            let challenge = try! broken.receive(laptop.hello(), connection: round, now: 0,
                                                active: true, peer: "peer-x")
            let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0], breakProof: true)
            check(status(try! broken.receive(reveal, connection: round, now: 0.1,
                                             active: true, peer: "peer-x")) == .rejected,
                  "a bad proof is rejected")
            broken.connectionClosed(round)
        }
        check(brokenGenerated == PairingResponder.maximumKnownPeerChallenges,
              "a bad proof creates one key per claim")
        let blocked = try! broken.receive(laptop.hello(), connection: 40, now: 0.2,
                                          active: true, peer: "peer-x")
        check(status(blocked) == .busy, "a bad proof does not refund its charge")
        check(brokenGenerated == PairingResponder.maximumKnownPeerChallenges,
              "the refused claim creates no key")

        // A legitimate known pairing still gets the token under the budget.
        let pairing = PairingResponder(trust: trust, credentials: { credentials },
                                       ephemeralKey: { key(Vectors.pEPrivate) }, nonce: { Vectors.nonce })
        let challenge = try! pairing.receive(laptop.hello(), connection: 1, now: 0,
                                             active: true, peer: "172.20.10.2")
        let (reveal, keys, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        let success = try! pairing.receive(reveal, connection: 1, now: 1, active: true,
                                           peer: "172.20.10.2")
        check(success.status == .ok, "a known target still receives the token")
        let message = [UInt8](unframe(success.frames[0]))
        check(try! PairingProtocol.open(keys, nonce: Data(message[2..<14]),
                                        ciphertext: Data(message[14...])) == credentials,
              "the known result holds the credentials")
    }

    static func knownRefundUsesTheProvenSession() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        trust.add(laptop.lS)
        var generated = 0
        let phone = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { generated += 1; return key(Vectors.pEPrivate) },
                                     nonce: { Vectors.nonce })

        // At t=0 the first known claim is charged.
        let older = try! phone.receive(laptop.hello() + Data([1]), connection: 1, now: 0,
                                       active: true, peer: "172.20.10.2")
        let (olderReveal, _, olderKnown) = laptop.reveal(challengeFrame: older.frames[0])
        check(olderKnown, "the first claim is known")

        // At t=4 a second session from the same address is charged. Both
        // sessions are live and each paid its own challenge.
        let newer = try! phone.receive(laptop.hello() + Data([1]), connection: 2, now: 4,
                                       active: true, peer: "172.20.10.2")
        check(!newer.close, "the second claim gets a challenge")
        phone.connectionClosed(2)

        // Only the older session proves, before its 5 second deadline. Its
        // refund must remove the t=0 charge, not the latest t=4 charge.
        let proof = try! phone.receive(olderReveal, connection: 1, now: 4, active: true,
                                       peer: "172.20.10.2")
        check(proof.frames.isEmpty && !proof.close, "the older session authenticates")
        phone.connectionClosed(1)

        // At t=61 the t=0 charge would have expired. The unproven t=4 charge
        // keeps its own window, so seven new claims fit and the eighth is
        // refused. Removing the latest charge would have allowed eight.
        for round in 0..<7 {
            let output = try! phone.receive(laptop.hello() + Data([1]), connection: 10 + round,
                                            now: 61, active: true, peer: "172.20.10.2")
            check(!output.close, "claim \(round) after the refund")
            phone.connectionClosed(10 + round)
        }
        let busy = try! phone.receive(laptop.hello() + Data([1]), connection: 30, now: 61,
                                      active: true, peer: "172.20.10.2")
        check(status(busy) == .busy, "the unproven charge still counts")
        check(generated == 9, "one key for each allowed claim")
    }

    static func knownForgottenBeforeReveal() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        trust.add(laptop.lS)
        let phone = responder(trust: trust)
        // The target is trusted at HELLO. The person taps Forget before REVEAL.
        let challenge = phone.receive(laptop.hello(), connection: 1, now: 0, active: true)
        let (reveal, _, known) = laptop.reveal(challengeFrame: challenge.frames[0])
        check(known, "the challenge marks the target as known")
        trust.remove(laptop.lS)
        let result = phone.receive(reveal, connection: 1, now: 1, active: true)
        check(status(result) == .rejected && result.close, "a forgotten target gets no token")
        check(result.frames.count == 1, "the refusal is one RESULT frame")
        check(!trust.contains(laptop.lS), "the refusal does not restore trust")
        check(phone.pendingPrompt == nil, "a forgotten target gets no prompt")
        // The session is gone, so a later status frame on the same connection
        // is refused too.
        let later = phone.receive(Data([5]) + Data(repeating: 0x44, count: 12) + Data(count: 32),
                                  connection: 1, now: 2, active: true)
        check(status(later) == .rejected, "no authenticated session remains")

        // The other order is fail-closed too. A target that was unknown at
        // HELLO and becomes trusted before REVEAL still needs the prompt.
        let lateTrust = MemoryTrustStore()
        let late = responder(trust: lateTrust)
        let second = late.receive(laptop.hello(), connection: 2, now: 0, active: true)
        let (secondReveal, _, knownAtHello) = laptop.reveal(challengeFrame: second.frames[0])
        check(!knownAtHello, "the target was unknown at HELLO")
        lateTrust.add(laptop.lS)
        let waiting = late.receive(secondReveal, connection: 2, now: 1, active: true)
        check(waiting.frames.isEmpty && !waiting.close, "a key added after HELLO still needs the prompt")
        let prompt = late.pendingPrompt
        check(prompt != nil, "the prompt is shown")
        check(decidePending(late, allow: true, now: 2)?.status == .ok, "the prompt can still approve")
        check(lateTrust.count == 1 && lateTrust.contains(laptop.lS), "the approval trusts the key once")
    }

    static func unsupportedFlags() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        var generated = 0
        let phone = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { generated += 1; return key(Vectors.pEPrivate) },
                                     nonce: { Vectors.nonce })
        // Flags 3 would mean status-only and forget at the same time.
        let unknown = try! phone.receive(laptop.hello() + Data([3]), connection: 1, now: 0,
                                         active: true, peer: "a")
        check(status(unknown) == .rejected && unknown.close, "unknown flags 3 is rejected")
        check(unknown.status == nil, "the flags 3 refusal is not logged as a status")
        check(generated == 0 && phone.nextDeadline == nil, "flags 3 creates no key and no session")
        // A trusted key does not make flags 3 valid.
        trust.add(laptop.lS)
        let known = try! phone.receive(laptop.hello() + Data([3]), connection: 2, now: 1,
                                       active: true, peer: "a")
        check(status(known) == .rejected, "known flags 3 is rejected")
        check(generated == 0, "known flags 3 creates no key")
        // An undefined high bit fails the HELLO shape check.
        let high = try! phone.receive(laptop.hello() + Data([4]), connection: 3, now: 2,
                                      active: true, peer: "a")
        check(status(high) == .rejected, "an undefined HELLO flag is rejected")
        check(generated == 0, "an undefined flag creates no key")

        // A status request must end with a zero flag byte.
        let info = PairingPhoneInfo(proxyRunning: true, foreground: true, connections: 1,
                                    port: 31000, host: "172.20.10.1")
        let statusTrust = MemoryTrustStore()
        statusTrust.add(laptop.lS)
        let statusPhone = PairingResponder(trust: statusTrust, credentials: { credentials },
                                           ephemeralKey: { key(Vectors.pEPrivate) },
                                           nonce: { Vectors.nonce }, status: { info })
        let challenge = try! statusPhone.receive(laptop.hello() + Data([1]), connection: 1, now: 0,
                                                 active: true, peer: "a")
        let (reveal, keys, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        let authenticated = try! statusPhone.receive(reveal, connection: 1, now: 1, active: true, peer: "a")
        check(!authenticated.close, "the status handshake authenticates")
        let nonce = Data(repeating: 0x44, count: 12)
        let challengeBytes = Data(repeating: 0x55, count: 16)
        let refusedCiphertext = try! PairingProtocol.sealMessage(keys, nonce: nonce,
                                                                 plaintext: challengeBytes + Data([1]))
        let refused = try! statusPhone.receive(Data([5]) + nonce + refusedCiphertext, connection: 1,
                                               now: 2, active: true, peer: "a")
        check(status(refused) == .rejected, "a nonzero status flag is rejected")
        check(statusTrust.contains(laptop.lS), "the refusal keeps trust")
        let again = try! statusPhone.receive(Data([5]) + nonce + refusedCiphertext, connection: 1,
                                             now: 3, active: true, peer: "a")
        check(status(again) == .rejected, "the refused session is gone")

        // A replayed status request finds no session after the first answer.
        let replayChallenge = try! statusPhone.receive(laptop.hello() + Data([1]), connection: 2, now: 4,
                                                       active: true, peer: "a")
        let (replayReveal, replayKeys, _) = laptop.reveal(challengeFrame: replayChallenge.frames[0])
        _ = try! statusPhone.receive(replayReveal, connection: 2, now: 5, active: true, peer: "a")
        let requestNonce = Data(repeating: 0x43, count: 12)
        let request = try! PairingProtocol.sealMessage(replayKeys, nonce: requestNonce,
                                                       plaintext: challengeBytes + Data([0]))
        let answered = try! statusPhone.receive(Data([5]) + requestNonce + request, connection: 2,
                                                now: 6, active: true, peer: "a")
        check(answered.frames.count == 1 && answered.close, "a valid status request is answered")
        let replayed = try! statusPhone.receive(Data([5]) + requestNonce + request, connection: 2,
                                                now: 7, active: true, peer: "a")
        check(status(replayed) == .rejected, "a replayed status request is refused")
    }

    static func sessionCap() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        trust.add(laptop.lS)
        var generated = 0
        let phone = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { generated += 1; return key(Vectors.pEPrivate) },
                                     nonce: { Vectors.nonce })
        var challenges: [Data] = []
        for id in 0..<PairingResponder.maximumSessions {
            let output = try! phone.receive(laptop.hello(), connection: id, now: 0,
                                            active: true, peer: "peer-\(id)")
            check(!output.close && output.frames.count == 1, "session \(id) is allowed")
            challenges.append(output.frames[0])
        }
        let over = try! phone.receive(laptop.hello(), connection: 10, now: 0, active: true, peer: "peer-10")
        check(status(over) == .busy && over.close, "a HELLO over the session cap is refused")
        check(generated == PairingResponder.maximumSessions, "the session cap creates no extra key")
        // A live session can still finish, and closing it frees the slot.
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenges[0])
        check(try! phone.receive(reveal, connection: 0, now: 1, active: true,
                                 peer: "peer-0").status == .ok,
              "an existing session still completes")
        phone.connectionClosed(0)
        let fresh = try! phone.receive(laptop.hello(), connection: 11, now: 2, active: true, peer: "peer-11")
        check(!fresh.close && fresh.frames.count == 1, "closing a session frees the slot")
    }

    static func emptyPeerIsRejected() {
        let laptop = TestLaptop()
        var generated = 0
        let phone = PairingResponder(trust: MemoryTrustStore(), credentials: { credentials },
                                     ephemeralKey: { generated += 1; return key(Vectors.pEPrivate) },
                                     nonce: { Vectors.nonce })
        check((try? phone.receive(laptop.hello(), connection: 1, now: 0, active: true, peer: "")) == nil,
              "an empty peer is rejected")
        check((try? phone.receive(laptop.hello(), connection: 1, now: 0, active: true, peer: " ")) == nil,
              "a space peer is rejected")
        check((try? phone.receive(laptop.hello(), connection: 1, now: 0, active: true, peer: "peer\n")) == nil,
              "a control byte in the peer is rejected")
        let long = String(repeating: "a", count: PairingResponder.maximumPeerLength + 1)
        check((try? phone.receive(laptop.hello(), connection: 1, now: 0, active: true, peer: long)) == nil,
              "a long peer is rejected")
        check((try? phone.receiveInvalid(connection: 1, now: 0, peer: "")) == nil,
              "receiveInvalid rejects an empty peer")
        check(generated == 0, "an unusable peer creates no key")
        check(phone.nextDeadline == nil, "an unusable peer creates no session")
        check(phone.pendingPrompt == nil, "an unusable peer creates no prompt")
    }

    static func receiveInvalidReleasesTheSession() {
        let laptop = TestLaptop()
        let phone = responder()
        let challenge = phone.receive(laptop.hello(), connection: 1, now: 0, active: true)
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        _ = phone.receive(reveal, connection: 1, now: 1, active: true)
        let prompt = phone.pendingPrompt!
        check(phone.nextDeadline != nil, "the prompt waits for a decision")

        // The peer text is unusable. The session and the decision must be
        // removed before the error returns.
        check((try? phone.receiveInvalid(connection: 1, now: 2, peer: "")) == nil,
              "receiveInvalid rejects an empty peer")
        check(phone.pendingPrompt == nil, "the failed check removes the prompt")
        check(phone.nextDeadline == nil, "the failed check removes the session")
        check(phone.decide(connection: prompt.connection, promptID: prompt.id, code: prompt.code,
                           allow: true, now: 2) == nil, "the removed prompt cannot be approved")

        // The released decision lets a new target get a prompt.
        let second = TestLaptop(ephemeralKey: key(Data(repeating: 0x23, count: 32)))
        let nextChallenge = phone.receive(second.hello(), connection: 2, now: 3, active: true)
        let (nextReveal, _, _) = second.reveal(challengeFrame: nextChallenge.frames[0])
        _ = phone.receive(nextReveal, connection: 2, now: 4, active: true)
        check(phone.pendingPrompt != nil, "a new target gets a prompt")
    }

    static func pairingOffChargesNoBudget() {
        let laptop = TestLaptop()
        var available = false
        var generated = 0
        let challenges = PairingResponder(trust: MemoryTrustStore(),
                                          credentials: { available ? credentials : nil },
                                          ephemeralKey: { generated += 1; return key(Vectors.pEPrivate) },
                                          nonce: { Vectors.nonce })
        // Pairing is off. More tries than the challenge and attempt limits must
        // still answer NotActive, not Busy or LockedOut.
        for id in 0..<(3 + PairingResponder.maximumPeerChallenges + 1) {
            let output = try! challenges.receive(laptop.hello(), connection: id, now: 0,
                                                 active: true, peer: "peer")
            check(status(output) == .notActive, "pairing off answers NotActive")
            check(challenges.pendingPrompt == nil, "pairing off creates no prompt")
        }
        check(generated == 0, "pairing off creates no key")
        check(challenges.nextDeadline == nil, "pairing off creates no session")

        // The off period charged no challenge budget. Four challenges remain.
        available = true
        for id in 0..<PairingResponder.maximumPeerChallenges {
            let output = try! challenges.receive(laptop.hello(), connection: id, now: 1,
                                                 active: true, peer: "peer")
            check(!output.close && output.frames.count == 1, "the off period charged no challenge")
            challenges.connectionClosed(id)
        }
        check(generated == PairingResponder.maximumPeerChallenges,
              "pairing on creates one key for each challenge")

        // Pairing stops after the challenge. Three REVEAL frames answer
        // NotActive and must not use a prompt attempt. The fourth REVEAL
        // answers LockedOut when an attempt was charged.
        available = true
        let attempts = PairingResponder(trust: MemoryTrustStore(),
                                        credentials: { available ? credentials : nil },
                                        ephemeralKey: { key(Vectors.pEPrivate) },
                                        nonce: { Vectors.nonce })
        for round in 0..<3 {
            let now = Double(round) * 2
            available = true
            let challenge = try! attempts.receive(laptop.hello(), connection: round, now: now,
                                                  active: true, peer: "peer")
            let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
            available = false
            let answer = try! attempts.receive(reveal, connection: round, now: now + 1,
                                               active: true, peer: "peer")
            check(status(answer) == .notActive, "a stopped pairing answers NotActive")
            check(attempts.pendingPrompt == nil, "a stopped pairing creates no prompt")
        }
        available = true
        let challenge = try! attempts.receive(laptop.hello(), connection: 9, now: 6,
                                              active: true, peer: "peer")
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        let served = try! attempts.receive(reveal, connection: 9, now: 7, active: true, peer: "peer")
        check(served.frames.isEmpty && !served.close, "NotActive does not charge a reveal attempt")
        check(attempts.pendingPrompt != nil, "pairing works again after a stopped pairing")
    }

    static func peerCanonicalization() {
        let laptop = TestLaptop()
        // Alternate spellings of one IPv6 address share one challenge budget.
        let v6 = PairingResponder(trust: MemoryTrustStore(), credentials: { credentials },
                                  ephemeralKey: { key(Vectors.pEPrivate) }, nonce: { Vectors.nonce })
        for id in 0..<PairingResponder.maximumPeerChallenges {
            let output = try! v6.receive(laptop.hello(), connection: id, now: 0,
                                         active: true, peer: "2001:db8::1")
            check(!output.close && output.frames.count == 1, "IPv6 challenge \(id)")
            v6.connectionClosed(id)
        }
        let full = try! v6.receive(laptop.hello(), connection: 10, now: 0, active: true,
                                   peer: "2001:0db8:0000:0000:0000:0000:0000:0001")
        check(status(full) == .busy, "alternate IPv6 spellings share one budget")

        // An IPv4-mapped IPv6 address shares the IPv4 budget.
        let mapped = PairingResponder(trust: MemoryTrustStore(), credentials: { credentials },
                                      ephemeralKey: { key(Vectors.pEPrivate) },
                                      nonce: { Vectors.nonce })
        for id in 0..<PairingResponder.maximumPeerChallenges {
            let output = try! mapped.receive(laptop.hello(), connection: id, now: 0,
                                             active: true, peer: "192.0.2.1")
            check(!output.close && output.frames.count == 1, "IPv4 challenge \(id)")
            mapped.connectionClosed(id)
        }
        for (index, peer) in ["::ffff:192.0.2.1", "::ffff:c000:201"].enumerated() {
            let output = try! mapped.receive(laptop.hello(), connection: 20 + index, now: 0,
                                             active: true, peer: peer)
            check(status(output) == .busy, "an IPv4-mapped address shares the IPv4 budget")
        }

        // A port or a zone would give one address more than one budget.
        let phone = responder()
        check((try? phone.receive(laptop.hello(), connection: 1, now: 0,
                                  active: true, peer: "192.0.2.1:443")) == nil,
              "a peer text with a port is rejected")
        check((try? phone.receive(laptop.hello(), connection: 1, now: 0,
                                  active: true, peer: "fe80::1%en0")) == nil,
              "a peer text with a zone is rejected")
        check((try? phone.receiveInvalid(connection: 1, now: 0, peer: "192.0.2.1:443")) == nil,
              "receiveInvalid rejects a peer text with a port")
    }

    static func promptVisibility() {
        let laptop = TestLaptop()

        // An unknown target gets an inactive prompt at t=0. Its deadline is 120.
        func inactivePrompt(_ phone: PairingResponder) {
            let challenge = phone.receive(laptop.hello(), connection: 1, now: 0, active: false)
            let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
            _ = phone.receive(reveal, connection: 1, now: 0, active: false)
            check(phone.pendingPrompt != nil, "the inactive prompt waits")
            check(phone.nextDeadline == 120, "the inactive deadline is 120 seconds")
        }

        // A frame at the deadline must not mark the expired prompt visible.
        let expired = responder()
        inactivePrompt(expired)
        _ = expired.receive(laptop.hello(), connection: 2, now: 120, active: true)
        check(status(expired.tick(now: 120)) == .timedOut, "the expired prompt times out")
        check(expired.promptFailureCount == 0, "an expired prompt that was never visible does not count")

        // A frame before the deadline marks the prompt visible.
        let visible = responder()
        inactivePrompt(visible)
        _ = visible.receive(laptop.hello(), connection: 2, now: 119.9, active: true)
        check(status(visible.tick(now: 120)) == .timedOut, "the visible prompt times out")
        check(visible.promptFailureCount == 1, "a visible prompt timeout counts")

        // activate applies the same deadline check. A stale decision advances
        // the last observed time and leaves the prompt in place.
        let lateActivate = responder()
        inactivePrompt(lateActivate)
        _ = lateActivate.decide(connection: -1, promptID: UUID(), code: "", allow: true, now: 120)
        lateActivate.activate()
        check(status(lateActivate.tick(now: 120)) == .timedOut, "the late prompt times out")
        check(lateActivate.promptFailureCount == 0, "activate does not mark an expired prompt visible")

        let earlyActivate = responder()
        inactivePrompt(earlyActivate)
        _ = earlyActivate.decide(connection: -1, promptID: UUID(), code: "", allow: true, now: 119.9)
        earlyActivate.activate()
        check(status(earlyActivate.tick(now: 120)) == .timedOut, "the live prompt times out")
        check(earlyActivate.promptFailureCount == 1, "activate marks a live prompt visible")
    }

    static func deactivateCap() {
        let laptop = TestLaptop()
        let phone = responder()
        let challenge = phone.receive(laptop.hello(), connection: 1, now: 0, active: true)
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        _ = phone.receive(reveal, connection: 1, now: 0, active: true)
        check(phone.nextDeadline == 60, "the live prompt has 60 seconds")
        check(phone.deactivate(now: 30) == nil, "the first inactive notice extends the prompt")
        check(phone.nextDeadline == 150, "deactivate extends by 120 seconds")
        check(phone.deactivate(now: 31) == nil, "a repeated notice is accepted")
        check(phone.nextDeadline == 150, "a repeated notice cannot extend the prompt")
        check(phone.deactivate(now: 91) == nil, "a later notice is accepted")
        check(phone.nextDeadline == 150, "the cap is 120 seconds after the first notice")
        check(phone.tick(now: 149) == nil, "no early timeout")
        check(status(phone.tick(now: 150)) == .timedOut, "the capped prompt times out")
    }

    static func promptDebugRedaction() {
        let laptop = TestLaptop()
        let phone = responder()
        let challenge = phone.receive(laptop.hello(), connection: 1, now: 0, active: true)
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        _ = phone.receive(reveal, connection: 1, now: 1, active: true)
        let prompt = phone.pendingPrompt!
        let debug = String(reflecting: prompt)
        check(!debug.contains(prompt.code), "the debug text hides the code")
        check(debug.contains("[redacted]"), "the debug text marks the redaction")
        check(debug.contains("id") && debug.contains("connection"), "the debug text keeps the identifiers")
        check(!String(describing: prompt).contains(prompt.code), "the display text hides the code")
    }

    static func credentialDebugRedaction() {
        let credentialsText = String(reflecting: credentials)
        check(!credentialsText.contains(Vectors.token), "the credentials debug text hides the token")
        check(credentialsText.contains("[redacted]"), "the credentials debug text marks the redaction")
        check(credentialsText.contains("172.20.10.1") && credentialsText.contains("1080"),
              "the credentials debug text keeps host and port")
        check(!String(describing: credentials).contains(Vectors.token),
              "the credentials display text hides the token")

        let laptop = TestLaptop()
        let keys = laptop.keys(pE: key(Vectors.pEPrivate).publicKey.rawRepresentation)
        let keysText = String(reflecting: keys)
        check(!keysText.contains(hex(keys.kEnc)), "the key debug text hides k_enc")
        check(!keysText.contains(hex(keys.kProof)), "the key debug text hides k_proof")
        check(!keysText.contains(hex(keys.sas)), "the key debug text hides the SAS bytes")
        check(keysText.contains("[redacted]"), "the key debug text marks the redaction")

        // An Output frame can hold the sealed credentials. Its text shows a
        // frame count, not the bytes.
        let phone = responder()
        let challenge = phone.receive(laptop.hello(), connection: 1, now: 0, active: true)
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        _ = phone.receive(reveal, connection: 1, now: 1, active: true)
        let allowed = decidePending(phone, allow: true, now: 2)!
        let outputText = String(reflecting: allowed)
        check(!outputText.contains(hex(allowed.frames[0])), "the output debug text hides the frame bytes")
        check(outputText.contains("frame_count: 1"), "the output debug text shows the frame count")
        check(!outputText.contains(Vectors.token), "the output debug text hides the token")
    }

    static func expiredDecisionsCannotBeApproved() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        let phone = responder(trust: trust)
        let challenge = phone.receive(laptop.hello(), connection: 1, now: 0, active: true)
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        _ = phone.receive(reveal, connection: 1, now: 1, active: true)
        let prompt = phone.pendingPrompt!
        check(status(phone.decide(connection: prompt.connection, promptID: prompt.id, code: prompt.code,
                                  allow: true, now: 61)) == .timedOut, "late approval expires")
        check(phone.pendingPrompt == nil, "an expired prompt is not shown")
        check(!trust.contains(laptop.lS), "late approval does not trust the target")

        let second = responder()
        let next = second.receive(laptop.hello(), connection: 2, now: 0, active: true)
        let (nextReveal, _, _) = laptop.reveal(challengeFrame: next.frames[0])
        _ = second.receive(nextReveal, connection: 2, now: 1, active: true)
        check(second.pendingPrompt != nil, "the prompt is live before the deadline")
        check(status(second.deactivate(now: 61)) == .timedOut, "an expired prompt is not extended")
        check(second.pendingCode == nil, "an expired prompt is removed")
        check(second.nextDeadline == nil, "an expired prompt leaves no deadline")

        // The accessor reads no prompt after the deadline, even before the
        // tick removes the session.
        let accessor = responder()
        let live = accessor.receive(laptop.hello(), connection: 3, now: 0, active: true)
        let (liveReveal, _, _) = laptop.reveal(challengeFrame: live.frames[0])
        _ = accessor.receive(liveReveal, connection: 3, now: 1, active: true)
        check(accessor.pendingPrompt != nil, "the prompt is live at first")
        _ = accessor.receive(laptop.hello(), connection: 4, now: 61, active: true)
        check(accessor.pendingPrompt == nil, "the accessor returns nil after the deadline")
        check(accessor.nextDeadline == 61, "the prompt session still waits for the tick")
    }

    static func staleDecisionCannotApproveAnotherPrompt() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        let phone = responder(trust: trust)
        let first = phone.receive(laptop.hello(), connection: 1, now: 0, active: true)
        let (firstReveal, _, _) = laptop.reveal(challengeFrame: first.frames[0])
        _ = phone.receive(firstReveal, connection: 1, now: 1, active: true)
        let old = phone.pendingPrompt!
        phone.connectionClosed(1)

        let second = phone.receive(laptop.hello(), connection: 1, now: 2, active: true)
        let (secondReveal, _, _) = laptop.reveal(challengeFrame: second.frames[0])
        _ = phone.receive(secondReveal, connection: 1, now: 3, active: true)
        let current = phone.pendingPrompt!
        check(current.code == old.code && current.id != old.id, "equal codes have distinct prompt IDs")
        check(current.connection == old.connection, "the connection ID is reused")
        check(phone.decide(connection: old.connection, promptID: old.id, code: old.code,
                           allow: true, now: 4) == nil, "a stale prompt ID is ignored")
        check(!trust.contains(laptop.lS), "a stale Allow cannot add trust")
        check(phone.pendingPrompt == current, "a stale Allow does not clear the current prompt")
        check(phone.decide(connection: current.connection + 1, promptID: current.id, code: current.code,
                           allow: false, now: 4) == nil, "a wrong connection is ignored")
        check(phone.decide(connection: current.connection, promptID: current.id, code: "000 000",
                           allow: true, now: 4) == nil, "a wrong code is ignored")
        check(!trust.contains(laptop.lS), "a wrong connection or code cannot add trust")
        check(phone.pendingPrompt == current, "a wrong connection or code does not clear the prompt")
        check(phone.decide(connection: current.connection, promptID: current.id, code: current.code,
                           allow: true, now: 5)?.status == .ok, "the current Allow succeeds")
        check(trust.contains(laptop.lS), "the current Allow trusts the displayed prompt")
    }

    static func parityVectors() {
        let lS = key(Vectors.lSPrivate), lE = key(Vectors.lEPrivate), pE = key(Vectors.pEPrivate)
        let lSPub = lS.publicKey.rawRepresentation, lEPub = lE.publicKey.rawRepresentation
        let pEPub = pE.publicKey.rawRepresentation
        check(hex(lSPub) == Vectors.lS, "L_s")
        check(hex(lEPub) == Vectors.lE, "L_e")
        check(hex(pEPub) == Vectors.pE, "P_e")
        check(hex(PairingProtocol.commitment(lE: lEPub, lS: lSPub)) == Vectors.c, "C")
        // The phone computes ee and es from its ephemeral key.
        let ee = try! PairingProtocol.agree(pE, lEPub)
        let es = try! PairingProtocol.agree(pE, lSPub)
        check(hex(ee) == Vectors.ee, "ee")
        check(hex(es) == Vectors.es, "es")
        check(try! PairingProtocol.agree(lE, pEPub) == ee, "laptop ee")
        check(try! PairingProtocol.agree(lS, pEPub) == es, "laptop es")
        let h = PairingProtocol.transcriptHash(lS: lSPub, lE: lEPub, pE: pEPub)
        check(hex(h) == Vectors.h, "h")
        let keys = PairingProtocol.deriveKeys(ee: ee, es: es, h: h)
        check(hex(keys.kEnc) == Vectors.kEnc, "k_enc")
        check(hex(keys.kProof) == Vectors.kProof, "k_proof")
        check(hex(keys.sas) == Vectors.sas, "sas bytes")
        check(PairingProtocol.sasCode(keys.sas) == Vectors.code, "code")
        check(PairingProtocol.formatCode(Vectors.code) == "500 104", "formatted code")
        let proof = PairingProtocol.laptopProof(keys)
        check(hex(proof) == Vectors.proof, "proof")
        check(PairingProtocol.verifyProof(keys, proof), "proof verifies")
        let ciphertext = try! PairingProtocol.seal(keys, nonce: Vectors.nonce, credentials: credentials)
        check(hex(ciphertext) == Vectors.ciphertext, "ciphertext \(hex(ciphertext))")
        let hello = PairingProtocol.encodeHello(lS: lSPub, commit: PairingProtocol.commitment(lE: lEPub, lS: lSPub)) + Data([1])
        check(hex(hello) == "0101" + Vectors.lS + Vectors.c + "01", "status hello vector")
        let forget = Data([7]) + Vectors.nonce + (try! PairingProtocol.sealMessage(keys, nonce: Vectors.nonce, plaintext: Data()))
        check(hex(forget) == "07444444444444444444444444db466ed9c760a7484fa50848950711f7", "forget vector")
        let req = Data(repeating: 0x55, count: 16) + Data([0])
        let response = try! PairingProtocol.encodeStatus(PairingPhoneInfo(proxyRunning: true, foreground: true, connections: 2, port: 1080, host: "172.20.10.1", sequence: 1), challenge: Data(repeating: 0x55, count: 16))
        check(hex(try! PairingProtocol.sealMessage(keys, nonce: Data(repeating: 0x44, count: 12), plaintext: req)) == "4247c7f09df127910c427a33114f972c5e2ad0449eded52ee1f8b60f3162ba126f", "status request vector")
        check(hex(try! PairingProtocol.sealMessage(keys, nonce: Data(repeating: 0x66, count: 12), plaintext: response)) == "85c1d284f91bc6a6749ad370bf6c6abe5f8d0a580845185b4292fe2e89545d589039f667f42eadf73ae2df6c3949ce678dffda5da446", "status response vector")

        check(try! PairingProtocol.open(keys, nonce: Vectors.nonce, ciphertext: ciphertext) == credentials, "open")
        check(PairingProtocol.sasCode(Data([0, 0, 0, 7])) == "000007", "zero padding")
        check(PairingProtocol.sasCode(Data([0xff, 0xff, 0xff, 0xff])) == "967295", "wrap")
        // A low-order point gives an all-zero result. Reject it.
        check((try? PairingProtocol.agree(pE, Data(count: 32))) == nil, "all-zero public key")
        var one = Data(count: 32); one[0] = 1
        check((try? PairingProtocol.agree(pE, one)) == nil, "low-order public key")
    }

    static func statusOnlyAndForget() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        let phone = responder(trust: trust)
        let unknown = try! phone.receive(laptop.hello() + Data([1]), connection: 1, now: 0, active: true, peer: "a")
        check(status(unknown) == .rejected && phone.pendingCode == nil && unknown.status == nil, "unknown status has no prompt or log")
        trust.add(laptop.lS)
        let challenge = try! phone.receive(laptop.hello() + Data([2]), connection: 2, now: 1, active: true, peer: "a")
        let (reveal, keys, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        let proof = try! phone.receive(reveal, connection: 2, now: 2, active: true, peer: "a")
        check(proof.frames.isEmpty && proof.status == nil, "forget proof has no result")
        let ciphertext = try! PairingProtocol.sealMessage(keys, nonce: Vectors.nonce, plaintext: Data())
        let result = try! phone.receive(Data([7]) + Vectors.nonce + ciphertext, connection: 2, now: 3, active: true, peer: "a")
        check(status(result) == .ok && !trust.contains(laptop.lS), "forget revokes trust")
        // The trust list can change between the handshake and the forget frame (the user taps
        // Forget). A peer must not be able to crash the app with that timing.
        trust.add(laptop.lS)
        let late = try! phone.receive(laptop.hello() + Data([2]), connection: 3, now: 4, active: true, peer: "b")
        let (lateReveal, lateKeys, _) = laptop.reveal(challengeFrame: late.frames[0])
        _ = try! phone.receive(lateReveal, connection: 3, now: 5, active: true, peer: "b")
        trust.remove(laptop.lS)
        let lateCiphertext = try! PairingProtocol.sealMessage(lateKeys, nonce: Vectors.nonce, plaintext: Data())
        let lateResult = try! phone.receive(Data([7]) + Vectors.nonce + lateCiphertext, connection: 3, now: 6, active: true, peer: "b")
        check(status(lateResult) == .rejected, "forget after trust removal is rejected and does not crash")
        // A frame for a connection without a session is rejected too.
        let orphan = try! phone.receive(Data([5]) + Data(count: 40), connection: 99, now: 7, active: true, peer: "b")
        check(status(orphan) == .rejected || orphan.frames.isEmpty, "a frame without a session does not crash")
    }

    static func independentSources() {
        let laptop = TestLaptop()
        let trusted = TestLaptop(staticKey: key(Data(repeating: 0x77, count: 32)))
        let trust = MemoryTrustStore()
        trust.add(trusted.lS)
        let phone = responder(trust: trust)
        for i in 0..<3 {
            let now = Double(i * 2)
            let challenge = try! phone.receive(laptop.hello(), connection: i, now: now, active: true, peer: "one")
            let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
            _ = try! phone.receive(reveal, connection: i, now: now + 0.5, active: true, peer: "one")
            check(status(decidePending(phone, allow: false, now: now + 1)) == .denied, "denial counts")
            phone.connectionClosed(i)
        }
        check(status(try! phone.receive(laptop.hello(), connection: 4, now: 7, active: true, peer: "one")) == .lockedOut, "source locked")
        let other = try! phone.receive(laptop.hello(), connection: 5, now: 7, active: true, peer: "two")
        check(other.frames.count == 1 && !other.close, "other source is not locked")
        let known = try! phone.receive(trusted.hello(), connection: 6, now: 7, active: true, peer: "one")
        check(known.frames.count == 1 && !known.close, "known peer is not locked")
    }

    static func framing() {
        var reader = PairingFrameReader()
        let framed = try! PairingProtocol.frame(Data([1, 2, 3]))
        try! reader.push(framed.prefix(3))
        check((try? reader.next()) == .some(nil), "partial frame waits")
        try! reader.push(framed.suffix(from: 3))
        check((try? reader.next()) == .some(Data([1, 2, 3])), "complete frame")
        var big = PairingFrameReader()
        try! big.push(Data([0x02, 0x01]))
        check((try? big.next()) == nil, "oversize frame throws")
        var empty = PairingFrameReader()
        try! empty.push(Data([0, 0]))
        check((try? empty.next()) == nil, "empty frame throws")
        let plain = try! PairingProtocol.encodeCredentials(credentials)
        check(try! PairingProtocol.decodeCredentials(plain) == credentials, "plaintext round trip")
        check((try? PairingProtocol.decodeCredentials(plain + Data([1]))) == nil, "long plaintext")
        check((try? PairingProtocol.decodeCredentials(plain.dropLast())) == nil, "short plaintext")
    }

    static func unknownAllowThenKnown() {
        let trust = MemoryTrustStore()
        let phone = responder(trust: trust)
        let laptop = TestLaptop()
        let challenge = phone.receive(message(laptop.hello()), connection: 1, now: 0, active: true)
        check(challenge.frames.count == 1 && !challenge.close, "challenge sent")
        let (reveal, keys, known) = laptop.reveal(challengeFrame: challenge.frames[0])
        check(!known, "unknown laptop")
        let waiting = phone.receive(message(reveal), connection: 1, now: 1, active: true)
        check(waiting.frames.isEmpty && !waiting.close, "waits for the user")
        check(phone.pendingCode == "500 104", "prompt shows the vector code: \(phone.pendingCode ?? "nil")")
        let prompt = phone.pendingPrompt!
        let allowed = phone.decide(connection: prompt.connection, promptID: prompt.id, code: prompt.code,
                                   allow: true, now: 2)
        check(allowed?.status == .ok && allowed?.close == false, "allow sends ok")
        check(phone.pendingCode == nil, "prompt cleared")
        check(trust.count == 1 && trust.contains(laptop.lS), "laptop trusted")
        let result = [UInt8](unframe(allowed!.frames[0]))
        check(result[0] == 0x04 && result[1] == 0, "result ok")
        let nonce = Data(result[2..<14]), ciphertext = Data(result[14...])
        check(hex(ciphertext) == Vectors.ciphertext, "same ciphertext as the Rust vector")
        check(try! PairingProtocol.open(keys, nonce: nonce, ciphertext: ciphertext) == credentials, "laptop opens result")
        check(phone.decide(connection: prompt.connection, promptID: prompt.id, code: prompt.code,
                           allow: true, now: 3) == nil, "no second decision")

        // A known laptop gets the result with no prompt.
        let again = phone.receive(message(laptop.hello()), connection: 2, now: 10, active: true)
        let (reveal2, _, known2) = laptop.reveal(challengeFrame: again.frames[0])
        check(known2, "known flag set")
        let direct = phone.receive(message(reveal2), connection: 2, now: 11, active: true)
        check(direct.status == .ok && !direct.close, "known laptop gets ok at once")
        check(phone.pendingCode == nil, "no prompt for a known laptop")
    }

    static func deny() {
        let trust = MemoryTrustStore()
        let phone = responder(trust: trust)
        let laptop = TestLaptop()
        let challenge = phone.receive(message(laptop.hello()), connection: 1, now: 0, active: true)
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        _ = phone.receive(message(reveal), connection: 1, now: 1, active: true)
        let denied = decidePending(phone, allow: false, now: 2)
        check(status(denied) == .denied && denied?.close == true, "deny sends 1")
        check(trust.count == 0, "denied laptop not trusted")
    }

    static func badCommitmentProofAndLength() {
        let laptop = TestLaptop()
        // Bad commitment.
        var phone = responder()
        var challenge = phone.receive(message(laptop.hello(commitTo: Data(repeating: 9, count: 32))),
                                      connection: 1, now: 0, active: true)
        var (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        check(status(phone.receive(message(reveal), connection: 1, now: 1, active: true)) == .rejected,
              "bad commitment rejected")
        check(phone.pendingCode == nil, "no prompt after bad commitment")
        // Bad proof.
        phone = responder()
        challenge = phone.receive(message(laptop.hello()), connection: 1, now: 0, active: true)
        (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0], breakProof: true)
        check(status(phone.receive(message(reveal), connection: 1, now: 1, active: true)) == .rejected,
              "bad proof rejected")
        // Wrong-length HELLO and REVEAL.
        phone = responder()
        check(status(phone.receive(message(laptop.hello().dropLast()), connection: 1, now: 0, active: true)) == .rejected,
              "short hello rejected")
        challenge = phone.receive(message(laptop.hello()), connection: 2, now: 0, active: true)
        (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        check(status(phone.receive(message(reveal + Data([0])), connection: 2, now: 1, active: true)) == .rejected,
              "long reveal rejected")
        // Oversize frame.
        phone = responder()
        check(phone.receiveInvalid(connection: 3, now: 0).status == .rejected, "oversize frame rejected")
        // A frame while the user decides is a protocol error.
        phone = responder()
        challenge = phone.receive(message(laptop.hello()), connection: 4, now: 0, active: true)
        (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        _ = phone.receive(message(reveal), connection: 4, now: 1, active: true)
        check(status(phone.receive(message(reveal), connection: 4, now: 2, active: true)) == .rejected,
              "extra frame rejected")
        check(phone.pendingCode == nil, "prompt cleared after a protocol error")
    }

    static func timeoutBusyAndInactive() {
        let laptop = TestLaptop()
        let phone = responder()
        let c = phone.receive(message(laptop.hello()), connection: 1, now: 100, active: true)
        let (r, _, _) = laptop.reveal(challengeFrame: c.frames[0])
        _ = phone.receive(message(r), connection: 1, now: 101, active: true)
        let c2 = phone.receive(message(laptop.hello()), connection: 2, now: 102, active: true)
        let (r2, _, _) = laptop.reveal(challengeFrame: c2.frames[0])
        check(status(phone.receive(message(r2), connection: 2, now: 103, active: true)) == .busy, "verified second decision is busy")
        check(phone.nextDeadline == 161, "decision deadline")
        check(phone.tick(now: 160.9) == nil, "no early timeout")
        check(status(phone.tick(now: 161)) == .timedOut, "decision times out")
        let inactive = responder()
        let ci = inactive.receive(message(laptop.hello()), connection: 3, now: 200, active: false)
        let (ri, _, _) = laptop.reveal(challengeFrame: ci.frames[0])
        _ = inactive.receive(message(ri), connection: 3, now: 201, active: false)
        check(inactive.pendingCode != nil, "inactive decision remains pending")
        check(inactive.nextDeadline == 321, "inactive deadline is 120 seconds")
        check(decidePending(inactive, allow: true, now: 202)?.status == .ok, "allow while inactive")
        let trust = MemoryTrustStore(); trust.add(laptop.lS)
        let known = responder(trust: trust)
        let ck = known.receive(message(laptop.hello()), connection: 4, now: 0, active: false)
        let (rk, _, _) = laptop.reveal(challengeFrame: ck.frames[0])
        check(known.receive(message(rk), connection: 4, now: 1, active: false).status == .ok, "known laptop while inactive")
        let leaving = responder()
        let cl = leaving.receive(message(laptop.hello()), connection: 5, now: 0, active: true)
        let (rl, _, _) = laptop.reveal(challengeFrame: cl.frames[0])
        _ = leaving.receive(message(rl), connection: 5, now: 1, active: true)
        check(leaving.deactivate(now: 2) == nil && leaving.pendingCode != nil, "deactivate keeps pending decision")
        check(leaving.nextDeadline == 122, "deactivate extends deadline")
        let pre = responder()
        _ = pre.receive(message(laptop.hello()), connection: 6, now: 0, active: true)
        let fresh = pre.receive(message(laptop.hello()), connection: 7, now: 1, active: true)
        check(!fresh.close, "unverified session does not block another")
        check(pre.tick(now: 5)?.connection == 6, "pre-proof deadline")
        pre.connectionClosed(7)
        check(pre.tick(now: 6) == nil, "closed connection forgotten")
    }

    static func lockout() {
        let laptop = TestLaptop()
        let phone = responder()
        for i in 0..<3 {
            let now = Double(i)
            let c = phone.receive(message(laptop.hello()), connection: i, now: now, active: true)
            let (r, _, _) = laptop.reveal(challengeFrame: c.frames[0])
            _ = phone.receive(message(r), connection: i, now: now, active: true)
            check(status(decidePending(phone, allow: false, now: now)) == .denied, "denial \(i)")
        }
        check(status(phone.receive(message(laptop.hello()), connection: 9, now: 3, active: true)) == .lockedOut,
              "locked after 3 denials")
        check(status(phone.receive(message(laptop.hello()), connection: 10, now: 31.9, active: true)) == .lockedOut,
              "still locked before 30 s")
        let after = phone.receive(message(laptop.hello()), connection: 11, now: 32, active: true)
        check(!after.close && after.frames.count == 1, "lockout ends after 30 s")
        // The lockout replaces the prompt-attempt budget. A REVEAL is served
        // after the lockout, not only a CHALLENGE.
        let (afterReveal, _, _) = laptop.reveal(challengeFrame: after.frames[0])
        let served = phone.receive(afterReveal, connection: 11, now: 32.5, active: true)
        check(served.frames.isEmpty && !served.close, "REVEAL is served after the lockout")
        check(phone.pendingCode != nil, "a new prompt after the lockout")
        let garbage = responder()
        for i in 0..<3 {
            _ = garbage.receive(message(laptop.hello().dropLast()), connection: i, now: Double(i), active: true)
        }
        let legitimate = garbage.receive(message(laptop.hello()), connection: 12, now: 3, active: true)
        check(!legitimate.close && legitimate.frames.count == 1, "garbage does not lock out pairing")
        // Failures older than 60 seconds do not count.
        let spread = responder()
        for (i, now) in [0.0, 61, 122].enumerated() {
            _ = spread.receive(message(laptop.hello().dropLast()), connection: i, now: now, active: true)
        }
        check(!spread.isLocked(now: 123, peer: "peer"), "spread failures do not lock")
    }

    static func perPeerLockout() {
        let laptop = TestLaptop()
        let phone = responder()
        // Source "one" is locked from t=2 to t=32. Source "two" is locked
        // from t=12 to t=42. Each lockout ends at its own time.
        for i in 0..<3 {
            let now = Double(i)
            let c = try! phone.receive(message(laptop.hello()), connection: i, now: now, active: true, peer: "one")
            let (r, _, _) = laptop.reveal(challengeFrame: c.frames[0])
            _ = try! phone.receive(message(r), connection: i, now: now, active: true, peer: "one")
            check(status(decidePending(phone, allow: false, now: now)) == .denied, "one denial \(i)")
        }
        let other = try! phone.receive(message(laptop.hello()), connection: 9, now: 3, active: true, peer: "two")
        check(!other.close && other.frames.count == 1, "another source is not locked by the first")
        for i in 0..<3 {
            let now = 10.0 + Double(i)
            let c = try! phone.receive(message(laptop.hello()), connection: 10 + i, now: now, active: true, peer: "two")
            let (r, _, _) = laptop.reveal(challengeFrame: c.frames[0])
            _ = try! phone.receive(message(r), connection: 10 + i, now: now, active: true, peer: "two")
            check(status(decidePending(phone, allow: false, now: now)) == .denied, "two denial \(i)")
        }
        // The second lockout must not overwrite the first. At 20 both sources
        // are still locked.
        let oneLockedAt20 = try! phone.receive(message(laptop.hello()), connection: 23, now: 20, active: true, peer: "one")
        check(status(oneLockedAt20) == .lockedOut, "one is still locked at 20")
        let twoLockedAt20 = try! phone.receive(message(laptop.hello()), connection: 24, now: 20, active: true, peer: "two")
        check(status(twoLockedAt20) == .lockedOut, "two is locked at 20")
        let oneAfter = try! phone.receive(message(laptop.hello()), connection: 20, now: 33, active: true, peer: "one")
        check(!oneAfter.close && oneAfter.frames.count == 1, "one is unlocked at 33")
        let (oneReveal, _, _) = laptop.reveal(challengeFrame: oneAfter.frames[0])
        let oneServed = try! phone.receive(oneReveal, connection: 20, now: 33.5, active: true, peer: "one")
        check(oneServed.frames.isEmpty && !oneServed.close, "one REVEAL is served at 33.5")
        let twoStill = try! phone.receive(message(laptop.hello()), connection: 21, now: 33, active: true, peer: "two")
        check(status(twoStill) == .lockedOut, "two is still locked at 33")
        let twoAfter = try! phone.receive(message(laptop.hello()), connection: 22, now: 43, active: true, peer: "two")
        check(!phone.isLocked(now: 43, peer: "two"), "two is unlocked at 43")
        check(status(twoAfter) == .busy, "the per-address challenge limit still applies")
        let afterWindow = try! phone.receive(message(laptop.hello()), connection: 25, now: 72, active: true, peer: "two")
        check(!afterWindow.close && afterWindow.frames.count == 1, "two can start after both challenge windows")
    }

    static func knownStatusOnly() {
        let trust = MemoryTrustStore()
        let laptop = TestLaptop()
        trust.add(laptop.lS)
        let info = PairingPhoneInfo(proxyRunning: true, foreground: true, connections: 1, port: 31000, host: "172.20.10.1")
        let phone = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { key(Vectors.pEPrivate) }, nonce: { Data(repeating: 0x66, count: 12) },
                                     status: { info })
        let challenge = try! phone.receive(laptop.hello() + Data([1]), connection: 1, now: 0, active: true, peer: "a")
        let (reveal, keys, known) = laptop.reveal(challengeFrame: challenge.frames[0])
        check(known, "known peer")
        let proof = try! phone.receive(reveal, connection: 1, now: 1, active: true, peer: "a")
        check(proof.frames.isEmpty && proof.status == nil && !proof.close, "status-only handshake sends no token")
        let challengeBytes = Data(repeating: 0x55, count: 16)
        let requestNonce = Data(repeating: 0x44, count: 12)
        let ciphertext = try! PairingProtocol.sealMessage(keys, nonce: requestNonce, plaintext: challengeBytes + Data([0]))
        let answer = try! phone.receive(Data([5]) + requestNonce + ciphertext, connection: 1, now: 2, active: true, peer: "a")
        check(answer.frames.count == 1 && answer.close, "status answer")
        let response = unframe(answer.frames[0])
        check(response.first == 6, "status response type")
        let plain = try! PairingProtocol.openMessage(keys, nonce: Data(response.dropFirst().prefix(12)),
                                                     ciphertext: Data(response.dropFirst(13)))
        check(plain == (try! PairingProtocol.encodeStatus(info, challenge: challengeBytes)), "status answer is the status")
    }

    static func statusChannel() {
        let trust = MemoryTrustStore()
        let laptop = TestLaptop(); trust.add(laptop.lS)
        let info = PairingPhoneInfo(proxyRunning: true, foreground: false, connections: 2, port: 1080, host: "172.20.10.1", sequence: 1)
        // The result and the status answer share one session, so the nonces differ.
        var nonceByte: UInt8 = 0x65
        let phone = PairingResponder(trust: trust, credentials: { credentials },
                                     ephemeralKey: { key(Vectors.pEPrivate) }, nonce: { nonceByte += 1; return Data(repeating: nonceByte, count: 12) },
                                     status: { info })
        let c = phone.receive(laptop.hello(), connection: 1, now: 0, active: false)
        let (reveal, keys, _) = laptop.reveal(challengeFrame: c.frames[0])
        check(phone.receive(reveal, connection: 1, now: 1, active: false).status == .ok, "known proof accepted")
        let challenge = Data(repeating: 0x55, count: 16)
        let requestNonce = Data(repeating: 0x44, count: 12)
        let ciphertext = try! PairingProtocol.sealMessage(keys, nonce: requestNonce, plaintext: challenge + Data([0]))
        let output = phone.receive(Data([5]) + requestNonce + ciphertext, connection: 1, now: 2, active: false)
        let response = unframe(output.frames[0])
        check(response.first == 6 && output.close, "status response")
        let plain = try! PairingProtocol.openMessage(keys, nonce: Data(response.dropFirst().prefix(12)), ciphertext: Data(response.dropFirst(13)))
        check(plain == (try! PairingProtocol.encodeStatus(info, challenge: challenge)), "status echoes challenge")
        let unknown = responder()
        let cu = unknown.receive(laptop.hello(), connection: 2, now: 0, active: true)
        let (ru, ku, _) = laptop.reveal(challengeFrame: cu.frames[0])
        _ = unknown.receive(ru, connection: 2, now: 1, active: true)
        let ct = try! PairingProtocol.sealMessage(ku, nonce: requestNonce, plaintext: challenge + Data([0]))
        check(status(unknown.receive(Data([5]) + requestNonce + ct, connection: 2, now: 2, active: true)) == .rejected, "unknown key rejected")
    }

    static func sourceBudget() {
        let phone = responder(), laptop = TestLaptop()
        for i in 0..<10 { _ = try! phone.receive(Data([0]), connection: i, now: 0, active: true, peer: "bad") }
        check(status(try! phone.receive(laptop.hello(), connection: 11, now: 0.5, active: true, peer: "bad")) == .rejected, "bad source backs off")
        let other = try! phone.receive(laptop.hello(), connection: 12, now: 0.5, active: true, peer: "good")
        check(!other.close, "other source can pair")
        let after = try! phone.receive(laptop.hello(), connection: 13, now: 1, active: true, peer: "bad")
        check(!after.close, "backoff ends")
    }

    static func tamperedCiphertext() {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        trust.add(laptop.lS)
        let phone = responder(trust: trust)
        let c = phone.receive(message(laptop.hello()), connection: 1, now: 0, active: true)
        let (r, keys, _) = laptop.reveal(challengeFrame: c.frames[0])
        let out = phone.receive(message(r), connection: 1, now: 1, active: true)
        var message = [UInt8](unframe(out.frames[0]))
        message[20] ^= 1
        let nonce = Data(message[2..<14]), ciphertext = Data(message[14...])
        check((try? PairingProtocol.open(keys, nonce: nonce, ciphertext: ciphertext)) == nil, "tampered ciphertext fails")
    }

    // MARK: Parity with rust/src/source_pairing.rs and the Kotlin responder

    /// Run a known, status-only handshake and return the phone, the keys, and a
    /// sealed status request for the connection.
    static func statusSession(credentials liveCredentials: @escaping () -> PairingCredentials?,
                              status info: PairingPhoneInfo?,
                              nonce: @escaping () -> Data = { Data(repeating: 0x66, count: 12) })
        -> (PairingResponder, Data) {
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        trust.add(laptop.lS)
        let phone = PairingResponder(trust: trust, credentials: liveCredentials,
                                     ephemeralKey: { key(Vectors.pEPrivate) }, nonce: nonce,
                                     status: { info })
        let challenge = try! phone.receive(laptop.hello() + Data([1]), connection: 1, now: 0, active: true, peer: "a")
        let (reveal, keys, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        let proof = try! phone.receive(reveal, connection: 1, now: 1, active: true, peer: "a")
        check(proof.frames.isEmpty && !proof.close, "the status-only handshake authenticates")
        let request = try! PairingProtocol.sealMessage(keys, nonce: Data(repeating: 0x44, count: 12),
                                                       plaintext: Data(repeating: 0x55, count: 16) + Data([0]))
        return (phone, Data([5]) + Data(repeating: 0x44, count: 12) + request)
    }

    /// Item 1: the credential constructor follows the Rust and Kotlin rule.
    static func credentialConstructorRules() {
        let token = Vectors.token
        check(PairingCredentials(host: "172.20.10.1", port: 1024, token: token) != nil, "port 1024 is allowed")
        check(PairingCredentials(host: "172.20.10.1", port: 65535, token: token) != nil, "port 65535 is allowed")
        check(PairingCredentials(host: "255.255.255.255", port: 1080, token: token) != nil, "broadcast is not refused, as in Rust")
        for port: UInt16 in [0, 1, 80, 1023, 18090] {
            check(PairingCredentials(host: "172.20.10.1", port: port, token: token) == nil, "port \(port) is refused")
        }
        for host in ["", "0.0.0.0", "224.0.0.1", "239.255.255.255", "172.20.10.01", "172.20.10", "172.20.10.1.5",
                     "256.1.1.1", "::1", "localhost", "172.20.10.1%en0", " 172.20.10.1", "172.20.10.1 ",
                     "172.20.10.-1", "+1.2.3.4", "\u{0661}.\u{0662}.\u{0663}.\u{0664}", "1.2.3.4\n"] {
            check(PairingCredentials(host: host, port: 1080, token: token) == nil, "host \(host.debugDescription) is refused")
        }
        check(PairingCredentials(host: "172.20.10.1", port: 1080, token: "") == nil, "an empty token is refused")
        check(PairingCredentials(host: "172.20.10.1", port: 1080, token: String(repeating: "a", count: 255)) != nil, "a 255 byte token is allowed")
        check(PairingCredentials(host: "172.20.10.1", port: 1080, token: String(repeating: "a", count: 256)) == nil, "a 256 byte token is refused")
        for bad in ["caf\u{e9}", "a b", "tab\t", "del\u{7f}", "nul\u{0}", "line\n", "\u{1F600}"] {
            check(PairingCredentials(host: "172.20.10.1", port: 1080, token: bad) == nil, "token \(bad.debugDescription) is refused")
        }
        check(PairingCredentials(host: "172.20.10.1", port: 1080, token: "!~") != nil, "the printable ASCII ends are allowed")
    }

    /// Item 2: the RESULT plaintext parser is strict, as in rust/src/pairing.rs.
    static func credentialParsingIsStrict() {
        func plain(port: UInt16 = 1080, token: [UInt8], host: [UInt8]) -> Data {
            Data([UInt8(port >> 8), UInt8(port & 0xff), UInt8(token.count)] + token + [UInt8(host.count)] + host)
        }
        let token = [UInt8](Vectors.token.utf8)
        let host = [UInt8]("172.20.10.1".utf8)
        check((try? PairingProtocol.decodeCredentials(plain(token: token, host: host))) == credentials, "the valid plaintext parses")
        // The wire format keeps what Rust keeps: only port 0 is refused.
        let lowPort = try? PairingProtocol.decodeCredentials(plain(port: 80, token: token, host: host))
        check(lowPort?.port == 80, "a low wire port parses, as in Rust")
        check((try? PairingProtocol.decodeCredentials(plain(port: 0, token: token, host: host))) == nil, "port 0 is refused")
        for bad: [UInt8] in [[0xc3, 0xa9], [0x20, 0x61], [0x61, 0x7f], [0x61, 0x09], [0xff, 0xfe]] {
            check((try? PairingProtocol.decodeCredentials(plain(token: bad, host: host))) == nil, "token bytes \(bad) are refused")
        }
        for badHost in ["example.com", "172.20.10.01", "256.1.1.1", "1.2.3", "::1", "172.20.10.1%en0", "1.2.3.4 ", "\u{0661}.2.3.4"] {
            check((try? PairingProtocol.decodeCredentials(plain(token: token, host: [UInt8](badHost.utf8)))) == nil,
                  "host \(badHost.debugDescription) is refused")
        }
        check((try? PairingProtocol.decodeCredentials(plain(token: token, host: [0xff, 0xfe, 0xfd, 0xfc]))) == nil, "a non-UTF-8 host is refused")
        // The Rust parser does not apply the usable-host rule. Neither does this one.
        check((try? PairingProtocol.decodeCredentials(plain(token: token, host: [UInt8]("0.0.0.0".utf8)))) != nil, "the wire parser keeps the Rust host rule")
    }

    /// Items 3, 4 and 5 at the responder: the status answer needs live
    /// credentials that match the status host. A refusal sends status 3.
    static func statusRequiresLiveCredentials() {
        let info = PairingPhoneInfo(proxyRunning: true, foreground: true, connections: 1, port: 31000, host: "172.20.10.1")
        var live: PairingCredentials? = credentials
        let (phone, request) = statusSession(credentials: { live }, status: info)
        live = nil
        let missing = try! phone.receive(request, connection: 1, now: 2, active: true, peer: "a")
        check(status(missing) == .rejected && missing.close, "a status request without live credentials is Rejected")
        check(phone.nextDeadline == nil, "the refused status request leaves no session")

        // A different host in the status than in the credentials.
        let otherHost = PairingPhoneInfo(proxyRunning: true, foreground: true, connections: 1, port: 31000, host: "172.20.10.2")
        let (mismatchPhone, mismatchRequest) = statusSession(credentials: { credentials }, status: otherHost)
        let mismatch = try! mismatchPhone.receive(mismatchRequest, connection: 1, now: 2, active: true, peer: "a")
        check(status(mismatch) == .rejected && mismatch.close, "a status host that differs from the credentials is Rejected")

        // A new proxy port is allowed: the target device learns it here.
        let (okPhone, okRequest) = statusSession(credentials: { credentials }, status: info)
        let answered = try! okPhone.receive(okRequest, connection: 1, now: 2, active: true, peer: "a")
        check(answered.frames.count == 1 && answered.close && answered.status == nil, "a matching status is answered")
        check(info.port != credentials.port, "the answered status carries a different port than the credentials")

        // No status provider.
        let (nilPhone, nilRequest) = statusSession(credentials: { credentials }, status: nil)
        check(status(try! nilPhone.receive(nilRequest, connection: 1, now: 2, active: true, peer: "a")) == .rejected,
              "no status provider is Rejected")
    }

    /// Item 4: encodeStatus checks the port and the host, and counts UTF-8 bytes.
    static func encodeStatusValidation() {
        let challenge = Data(repeating: 0x55, count: 16)
        func info(port: UInt16 = 1080, host: String = "172.20.10.1") -> PairingPhoneInfo {
            PairingPhoneInfo(proxyRunning: true, foreground: true, connections: 1, port: port, host: host)
        }
        check((try? PairingProtocol.encodeStatus(info(), challenge: challenge)) != nil, "a valid status encodes")
        for port: UInt16 in [0, 80, 1023, 18090] {
            check((try? PairingProtocol.encodeStatus(info(port: port), challenge: challenge)) == nil, "status port \(port) is refused")
        }
        for host in ["", "0.0.0.0", "224.0.0.1", "172.20.10.01", "example.com", "172.20.10.1%en0",
                     String(repeating: "\u{e9}", count: 11), "172.20.10.1" + String(repeating: "\u{e9}", count: 5)] {
            check((try? PairingProtocol.encodeStatus(info(host: host), challenge: challenge)) == nil,
                  "status host \(host.debugDescription) is refused")
        }
        // 11 characters, 22 UTF-8 bytes. A Character count would let it pass.
        let wide = String(repeating: "\u{e9}", count: 11)
        check(wide.count <= 21 && wide.utf8.count > 21, "the wide host is short in characters and long in bytes")
        check((try? PairingProtocol.encodeStatus(info(), challenge: Data(count: 15))) == nil, "a short challenge is refused")

        // At the responder an unusable status port ends the session with no
        // reply, as the Rust responder returns an error there.
        let (phone, request) = statusSession(credentials: { credentials }, status: info(port: 80))
        let output = try! phone.receive(request, connection: 1, now: 2, active: true, peer: "a")
        check(output.frames.isEmpty && output.close && output.status == nil, "an unusable status ends the session with no reply")
        check(phone.nextDeadline == nil, "the failed status leaves no session")
    }

    /// Item 5: a repeated nonce, a short nonce, or a fifth nonce is refused.
    static func sessionNonceReuse() {
        let used = (0..<4).map { Data(repeating: UInt8($0), count: 12) }
        check(PairingResponder.isFreshNonce(Data(repeating: 9, count: 12), used: []), "a first nonce is fresh")
        check(PairingResponder.isFreshNonce(Data(repeating: 9, count: 12), used: Array(used.prefix(3))), "a fourth nonce is fresh")
        check(!PairingResponder.isFreshNonce(Data(repeating: 9, count: 12), used: used), "a fifth nonce is refused")
        check(!PairingResponder.isFreshNonce(used[1], used: Array(used.prefix(2))), "a repeated nonce is refused")
        check(!PairingResponder.isFreshNonce(Data(repeating: 9, count: 11), used: []), "an 11 byte nonce is refused")
        check(!PairingResponder.isFreshNonce(Data(repeating: 9, count: 13), used: []), "a 13 byte nonce is refused")

        // Known target, status allowed: the result and the status answer share
        // one session. A constant nonce repeats, so the status answer is refused.
        let laptop = TestLaptop()
        let trust = MemoryTrustStore()
        trust.add(laptop.lS)
        let info = PairingPhoneInfo(proxyRunning: true, foreground: true, connections: 1, port: 1080, host: "172.20.10.1")
        func run(nonce: @escaping () -> Data) -> (PairingResponder.Output, PairingResponder.Output) {
            let phone = PairingResponder(trust: trust, credentials: { credentials },
                                         ephemeralKey: { key(Vectors.pEPrivate) }, nonce: nonce, status: { info })
            let challenge = try! phone.receive(laptop.hello(), connection: 1, now: 0, active: true, peer: "a")
            let (reveal, keys, _) = laptop.reveal(challengeFrame: challenge.frames[0])
            let result = try! phone.receive(reveal, connection: 1, now: 1, active: true, peer: "a")
            let requestNonce = Data(repeating: 0x44, count: 12)
            let sealed = try! PairingProtocol.sealMessage(keys, nonce: requestNonce, plaintext: Data(repeating: 0x55, count: 16) + Data([0]))
            let answer = try! phone.receive(Data([5]) + requestNonce + sealed, connection: 1, now: 2, active: true, peer: "a")
            return (result, answer)
        }
        let (firstResult, reused) = run(nonce: { Vectors.nonce })
        check(firstResult.status == .ok && firstResult.frames.count == 1, "the first nonce seals the result")
        check(reused.frames.isEmpty && reused.close && reused.status == nil, "a reused nonce ends the session with no reply")
        var counter: UInt8 = 0x70
        let (secondResult, answered) = run(nonce: { counter += 1; return Data(repeating: counter, count: 12) })
        check(secondResult.status == .ok, "distinct nonces seal the result")
        check(answered.frames.count == 1 && answered.close, "a distinct nonce seals the status answer")

        // A short nonce from the source ends an unknown pairing with no reply
        // and adds no trust.
        let freshTrust = MemoryTrustStore()
        let short = PairingResponder(trust: freshTrust, credentials: { credentials },
                                     ephemeralKey: { key(Vectors.pEPrivate) }, nonce: { Data(repeating: 1, count: 11) })
        let challenge = try! short.receive(laptop.hello(), connection: 1, now: 0, active: true, peer: "a")
        let (reveal, _, _) = laptop.reveal(challengeFrame: challenge.frames[0])
        _ = try! short.receive(reveal, connection: 1, now: 1, active: true, peer: "a")
        let denied = decidePending(short, allow: true, now: 2)
        check(denied != nil && denied!.frames.isEmpty && denied!.close && denied!.status == nil,
              "an unusable nonce ends the approved pairing with no reply")
        check(freshTrust.count == 0, "an unusable nonce adds no trust")
        check(short.nextDeadline == nil, "the failed pairing leaves no session")
    }

    /// Item 6: the frame reader holds at most 4 * (2 + 512) bytes.
    static func frameReaderBound() {
        check(PairingProtocol.maxBuffered == 2056, "the buffer cap is 2056 bytes")
        var reader = PairingFrameReader()
        // A prefix that names a complete 512 byte frame, then filler. The reader
        // does not parse until next(), so the cap is the only limit here.
        try! reader.push(Data(count: 2056))
        check(reader.bufferedCount == 2056, "the reader holds the full cap")
        check((try? reader.push(Data([0]))) == nil, "one byte past the cap throws")
        check(reader.bufferedCount == 2056, "a refused push keeps the buffer")
        var once = PairingFrameReader()
        check((try? once.push(Data(count: 2057))) == nil, "one push past the cap throws")
        check(once.bufferedCount == 0, "a refused push adds nothing")
        var split = PairingFrameReader()
        try! split.push(Data(count: 2000))
        check((try? split.push(Data(count: 57))) == nil, "a push that would pass the cap throws")
        try! split.push(Data(count: 56))
        check(split.bufferedCount == 2056, "a push to the cap is allowed")
        // Draining frames frees space.
        var drain = PairingFrameReader()
        let framed = try! PairingProtocol.frame(Data(repeating: 7, count: 512))
        for _ in 0..<3 { try! drain.push(framed) }
        for _ in 0..<3 { check((try! drain.next())?.count == 512, "a full frame drains") }
        check(drain.bufferedCount == 0, "the drained reader is empty")
        try! drain.push(Data(count: 2056))
    }

    /// Item 7: an outgoing frame error is a typed error, not a crash.
    static func frameErrorsAreTyped() {
        check((try? PairingProtocol.frame(Data())) == nil, "an empty payload throws")
        check((try? PairingProtocol.frame(Data(count: 513))) == nil, "an oversize payload throws")
        do {
            _ = try PairingProtocol.frame(Data())
            check(false, "the empty frame did not throw")
        } catch let error as PairingError {
            check(!error.reason.isEmpty, "the frame error is a PairingError with a reason")
        } catch {
            check(false, "the frame error is a PairingError")
        }
        check((try? PairingProtocol.frame(Data(count: 512)))?.count == 514, "a 512 byte payload frames")
        check((try? PairingProtocol.frame(Data([1]))) == Data([0, 1, 1]), "a one byte payload frames")
    }

    static func trustStore() {
        let suite = "hotspotproxy.tests.\(getpid())"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = UserDefaultsTrustStore(defaults: defaults)
        let laptop = TestLaptop()
        check(store.count == 0, "empty store")
        store.add(laptop.lS)
        store.add(laptop.lS)
        check(store.count == 1 && store.contains(laptop.lS), "one key stored")
        check(defaults.stringArray(forKey: "pairedLaptops") == [laptop.lS.base64EncodedString()], "public key in base64")
        store.removeAll()
        check(store.count == 0, "forget all")
    }
}
