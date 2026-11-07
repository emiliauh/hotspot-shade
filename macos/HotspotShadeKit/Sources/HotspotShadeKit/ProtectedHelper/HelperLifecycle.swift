import Foundation
import Darwin

// The helper owns one engine session at a time. A session belongs to the
// authenticated connection that started it. A second connection never stops a
// tunnel that is in use. When its connection closes, the helper stops only its
// own engine and closes the parent descriptor. There is no restart.
public struct HelperEngineDescription: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let port: UInt16
    public let secret: String
    public init(port: UInt16, secret: String) {
        self.port = port
        self.secret = secret
    }
    // The per-launch secret is a credential. A log or a debugger must not
    // print it as part of a value description.
    public var description: String { "HelperEngineDescription(port: \(port), secret: <redacted>)" }
    public var debugDescription: String { description }
}

public enum EngineStopReason: Equatable, Sendable {
    case user
    case cancelled
    case connectionClosed
    case helperShutdown
    case engineExited
    // The helper stopped an engine that received no verified administrator
    // authorization within `HelperAuthorizationDeadline.unauthorizedSession`.
    case authorizationTimeout
}

public enum EngineStopResult: Equatable, Sendable {
    case stopped
    case timedOut
    // The engine exited, but not with a clean zero status. It may have left
    // routes behind, so the caller treats it like a timeout.
    case failed
}

// The last completed stop result for one helper session. The app keeps the
// session id from the start reply and may reconnect after a lost stop reply.
// A new connection can then ask what happened to that exact session instead of
// treating its own unrelated stop acknowledgement as proof.
public enum HelperSessionStopResult: String, Equatable, Sendable {
    case none
    case stopped
    case timedOut
    case failed
    // The engine exited without a stop request. Even a zero exit is not proof
    // that its routes were removed.
    case engineExited
    // The engine exited before the helper ever wrote a tunnel grant for this
    // session. The engine changes a route only after it consumes a grant, so
    // this is a failed start that changed no route, not a cleanup problem.
    case failedStart = "failed_start"
}

// What the helper knows about its one engine session. `currentSession` is the
// live session while one exists. `lastSession` and `lastResult` describe the
// most recent completed session. A reconnecting caller can match its retained
// session id against these values. The values live in helper memory only, so a
// helper restart makes them unavailable, which keeps the caller uncertain.
public struct HelperStatus: Equatable, Sendable {
    public let running: Bool
    public let stopping: Bool
    // A launch is in progress but has not produced a session yet. A reconnecting
    // caller must not treat that window as idle.
    public let starting: Bool
    public let cleanupBlocked: Bool
    public let currentSession: UUID?
    public let lastSession: UUID?
    public let lastResult: HelperSessionStopResult
    // The fixed reason of the last failed start, when the last result is
    // `failedStart`.
    public let lastFailureReason: EngineStartFailureReason?

    public init(
        running: Bool,
        cleanupBlocked: Bool,
        stopping: Bool = false,
        starting: Bool = false,
        currentSession: UUID? = nil,
        lastSession: UUID? = nil,
        lastResult: HelperSessionStopResult = .none,
        lastFailureReason: EngineStartFailureReason? = nil
    ) {
        self.lastFailureReason = lastFailureReason
        self.running = running
        self.stopping = stopping
        self.starting = starting
        self.cleanupBlocked = cleanupBlocked
        self.currentSession = currentSession
        self.lastSession = lastSession
        self.lastResult = lastResult
    }
}

// The full answer to one stop request. `owned` is true only when this
// connection owned the session or the in-flight launch that the request
// affected. A false value means the helper stopped nothing, so its `ok` reply
// must never be read as proof that another connection's engine stopped.
public struct HelperStopReply: Equatable, Sendable {
    public let owned: Bool
    public let status: HelperStatus

    public init(owned: Bool, status: HelperStatus) {
        self.owned = owned
        self.status = status
    }
}

// The one engine session that this helper started. The controller assigns the
// id before the engine is announced to the app. The app returns it on a later
// stop or status request so the helper can describe that exact session.
public struct HelperEngineSession: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let sessionID: UUID
    public let engine: HelperEngineDescription

    public init(sessionID: UUID, engine: HelperEngineDescription) {
        self.sessionID = sessionID
        self.engine = engine
    }

    public var port: UInt16 { engine.port }
    public var secret: String { engine.secret }
    public var description: String { "HelperEngineSession(session: \(sessionID.uuidString), port: \(port), secret: <redacted>)" }
    public var debugDescription: String { description }
}

// The helper bounds one engine stop. The app's XPC stop call must wait longer
// than that bound, or it reports a timeout while the helper is still stopping
// the engine and the reply is still on its way.
public enum HelperEngineStopDeadline {
    public static let engineStop: TimeInterval = 60
    public static let clientReplyGrace: TimeInterval = 10
    public static let clientStop: TimeInterval = engineStop + clientReplyGrace
}

// The helper starts the root engine before the person answers the
// administrator prompt. That engine can hold the imported pairing token, so it
// must not wait for an answer forever. A session that receives no verified
// authorization within this bound is stopped on the normal stop path: the
// parent descriptor closes, then SIGTERM, never SIGKILL. The owner gets the
// fixed reason `authorization_timeout`.
public enum HelperAuthorizationDeadline {
    public static let unauthorizedSession: TimeInterval = 120
    public static let timeoutReason = "authorization_timeout"
}

public protocol RunningHelperEngine: AnyObject {
    var description: HelperEngineDescription { get }
    var isRunning: Bool { get }
    // Write the one-time grant that the engine consumes before it changes a
    // route. The helper calls this only after it verifies an administrator
    // authorization. A grant write failure is a failed authorization, not a
    // failed engine stop.
    func authorizeStart() throws
    // Close the parent liveness descriptor first, then send SIGTERM. Never use
    // SIGKILL. Return timedOut when the engine did not exit in the bound.
    func stop() -> EngineStopResult
    // True only when the helper reaped this engine and so knows that it
    // exited. An unreadable wait status is not a known exit.
    var exitObserved: Bool { get }
    // The fixed reason from the engine's startup failure line, if any.
    var startFailureReason: EngineStartFailureReason? { get }
}

public extension RunningHelperEngine {
    // An engine that cannot report its exit is never a known exit, so the
    // helper keeps the cleanup path for it.
    var exitObserved: Bool { false }
    var startFailureReason: EngineStartFailureReason? { nil }
}

// The result of one administrator authorization for a tunnel start. The
// engine already runs; only the route-changing operation is gated.
public enum HelperTunnelAuthorizationResult: Equatable, Sendable {
    case authorized
    // No engine session belongs to this connection.
    case notRunning
    // The fixed right is missing or weaker than the reviewed definition.
    case notConfigured
    // The form is missing, malformed, expired, or does not carry the right.
    case notAuthorized
    // The authorization passed, but the helper could not write the one-time
    // grant. The engine still runs and refuses a start.
    case grantFailed
}

public protocol HelperEngineLaunching: AnyObject {
    // The controller writes the durable launch intent and holds its own shared
    // start lock before this call. The handoff carries the locked descriptor
    // that the child inherits. The engine also opens its own shared lock before
    // it changes a route or opens a TUN device, then validates the handoff. A
    // launcher that spawned an engine and could not prove a clean stop throws
    // `engineStopTimedOut` or `engineExitUnclean`, which leaves that intent in
    // place. A launcher that failed before spawn, failed to spawn, or stopped a
    // spawned child with a clean zero exit throws one of the errors the
    // controller treats as proof that no engine survives. Any other error
    // leaves the intent in place and blocks later starts.
    func launch(holding exclusion: HelperStartExclusionHandoff?) throws -> RunningHelperEngine
    // The same launch with the one private pairing handoff descriptor. The
    // descriptor is inherited by the root engine. The helper never reads it.
    func launch(
        holding exclusion: HelperStartExclusionHandoff?,
        credentials: Int32?
    ) throws -> RunningHelperEngine
}

public extension HelperEngineLaunching {
    // Existing launchers and tests keep the no-credential launch.
    func launch(
        holding exclusion: HelperStartExclusionHandoff?,
        credentials: Int32?
    ) throws -> RunningHelperEngine {
        _ = credentials
        return try launch(holding: exclusion)
    }
}

public enum HelperSessionStartResult: Equatable, Sendable {
    case started(HelperEngineSession)
    case busy
    case cleanupBlocked
    case launchFailed
    // The engine exited before it was ready and before any grant. No route
    // changed, the launch intent is cleared, and no cleanup block is set.
    case engineDidNotStart(EngineStartFailureReason)
    // Another process holds the exclusive start lock, for example an install or
    // upgrade coordinator. No engine was started.
    case startExclusionBusy
    // The lock or journal cannot be established safely. No engine was started.
    case startExclusionUnavailable
    case connectionClosed
    case cancelled
    case notAuthorized
    case authorizationBusy
    case notConfigured
}

public final class HelperSessionController: @unchecked Sendable {
    private let launcher: HelperEngineLaunching
    private let cleanupStore: HelperCleanupBlockStoring
    private let intentStore: HelperLaunchIntentStoring
    private let exclusion: HelperStartExclusionPreparing
    private let condition = NSCondition()
    private var session: Session?
    private var starting: UUID?
    // A stop can take up to 60 seconds. Keep the session slot occupied for the
    // whole stop so a second connection cannot start an overlapping engine.
    private var stoppingCount = 0
    // A connection can close or cancel while its launch is still in flight.
    // Remember it so the late engine is stopped instead of serving nobody.
    private var closedConnections: Set<UUID> = []
    private var stopPending: Set<UUID> = []
    // Set by shutDown. A launch that finishes after shutdown must stop its
    // late engine instead of serving a helper that is exiting.
    private var closed = false
    // An unclean stop must keep the shared exclusion lock for the life of this
    // helper. The engine may still own routes, and the installer coordinator
    // must not be able to take the exclusive lock. The leases are released only
    // when this process exits.
    private var retainedExclusions: [HelperStartExclusionLease] = []
    // A late launch can stop its own engine after shutDown has already woken.
    // Its result is recorded here so shutDown does not report a clean exit for
    // a stop that timed out or failed.
    private var lateLaunchStopResult: EngineStopResult?

    private struct Session {
        let id: UUID
        let connection: UUID
        let engine: RunningHelperEngine
        let exclusion: HelperStartExclusionLease
        // The monotonic time when the session became active.
        let startedAt: TimeInterval
        // True after one verified administrator authorization wrote a grant.
        // An unauthorized session is stopped at the authorization deadline.
        var authorized = false
        // True from the moment the helper begins a grant write, even if the
        // write then fails. Only a session that never reached a grant write
        // can prove that its engine changed no route.
        var grantAttempted = false
    }

    // A monotonic clock in seconds. Tests inject a manual clock.
    private let clock: @Sendable () -> TimeInterval
    private let authorizationDeadline: TimeInterval

    // The answer to one authorization-deadline stop. The helper uses the
    // connection to tell only the owner.
    public struct ExpiredSession: Equatable, Sendable {
        public let connection: UUID
        public let sessionID: UUID
        public let result: EngineStopResult
    }

    public static func monotonicSeconds() -> TimeInterval {
        TimeInterval(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
    }

    // The in-memory history that a reconnecting caller can check. It is
    // deliberately lost on a helper restart: an absent record is not proof
    // that an older engine stopped.
    private var lastStoppedSession: (id: UUID, result: HelperSessionStopResult, reason: EngineStartFailureReason?)?
    private let failureRecord: HelperStartFailureRecording

    // The answer to one stop request. `owned` is false for a connection that
    // did not own the stopped session, even though the request itself
    // succeeded. The app must not read that acknowledgement as a stop.
    public struct StopReport: Equatable, Sendable {
        public let owned: Bool
        public let result: EngineStopResult

        public init(owned: Bool, result: EngineStopResult) {
            self.owned = owned
            self.result = result
        }
    }

    // Both stores are required. An in-memory default here would silently forget
    // a block or a launch intent when the helper restarts. The production
    // helper passes the root stores; tests pass in-memory stores explicitly.
    public init(
        launcher: HelperEngineLaunching,
        cleanupStore: HelperCleanupBlockStoring,
        intentStore: HelperLaunchIntentStoring,
        exclusion: HelperStartExclusionPreparing,
        authorizationDeadline: TimeInterval = HelperAuthorizationDeadline.unauthorizedSession,
        failureRecord: HelperStartFailureRecording = NoStartFailureRecord(),
        clock: @escaping @Sendable () -> TimeInterval = { HelperSessionController.monotonicSeconds() }
    ) {
        self.failureRecord = failureRecord
        self.launcher = launcher
        self.cleanupStore = cleanupStore
        self.intentStore = intentStore
        self.exclusion = exclusion
        self.authorizationDeadline = authorizationDeadline
        self.clock = clock
        // Start blocked when the durable state cannot be read. An unsafe or
        // unreadable marker is not evidence that the host is clean. An intent
        // left by an earlier helper means an engine may still be alive. An
        // install journal means a file transaction did not finish, so a start
        // and the coordinator recovery must not overlap. All three block until
        // a person completes the documented recovery.
        self.cleanupBlocked = (try? cleanupStore.isBlocked()) ?? true
        do {
            // A present record belongs to another participant (a concurrent
            // direct engine or an earlier helper). It is re-read before a
            // refusal, so a clean external exit does not block this helper
            // forever. An unreadable store is not evidence that no engine
            // exists, so it keeps the gate closed without re-evaluation.
            self.staleIntent = try intentStore.isPresent()
            self.intentUncertain = false
        } catch {
            self.staleIntent = true
            self.intentUncertain = true
        }
        // Unlike the launch intent, the install journal is not re-read by the
        // observed-intent path. A helper that saw a journal keeps its refusal
        // for its lifetime; a restart re-reads the state directory. The start
        // path also checks the journal again in prepare, under the shared lock.
        self.staleInstallJournal = (try? exclusion.isInstallJournalPresent()) ?? true
    }

    public var isRunning: Bool {
        condition.lock(); defer { condition.unlock() }
        return session != nil
    }

    // True while a stop or a late-launch cleanup owns the session slot. A
    // status reader must not accept "running false" as a completed stop during
    // this window.
    public var isStopping: Bool {
        condition.lock(); defer { condition.unlock() }
        return stoppingCount > 0
    }

    // The helper's current and most recent session identity. The caller can
    // match a retained id and stop result after reconnecting. These values are
    // memory-only and never survive a helper restart.
    public struct SessionSnapshot: Equatable, Sendable {
        public let running: Bool
        public let stopping: Bool
        public let starting: Bool
        public let currentSession: UUID?
        public let lastSession: UUID?
        public let lastResult: HelperSessionStopResult
        public let lastFailureReason: EngineStartFailureReason?

        public init(
            running: Bool,
            stopping: Bool,
            starting: Bool,
            currentSession: UUID?,
            lastSession: UUID?,
            lastResult: HelperSessionStopResult,
            lastFailureReason: EngineStartFailureReason? = nil
        ) {
            self.lastFailureReason = lastFailureReason
            self.running = running
            self.stopping = stopping
            self.starting = starting
            self.currentSession = currentSession
            self.lastSession = lastSession
            self.lastResult = lastResult
        }
    }

    public func snapshot() -> SessionSnapshot {
        condition.lock(); defer { condition.unlock() }
        return SessionSnapshot(
            running: session != nil,
            stopping: stoppingCount > 0,
            starting: starting != nil,
            currentSession: session?.id,
            lastSession: lastStoppedSession?.id,
            lastResult: lastStoppedSession?.result ?? .none,
            lastFailureReason: lastStoppedSession?.reason
        )
    }

    // True when this helper abandoned a shared exclusion lease because an
    // engine may still own routes. shutdown reports a non-clean result in that
    // state so the process stays alive and keeps the lock held.
    public var hasRetainedExclusion: Bool {
        condition.lock(); defer { condition.unlock() }
        return !retainedExclusions.isEmpty
    }

    // A stop that timed out or an engine that exited abnormally leaves an
    // engine that may still own routes. The controller refuses a new start
    // until a person inspects the host. The block is also written to a
    // root-owned marker so a helper restart cannot forget it.
    //
    // A launch intent that is present when no session is active belongs to an
    // earlier helper or to another participant, for example a concurrent direct
    // engine. It means an engine may still exist, so it blocks every start just
    // like the cleanup marker. A record that this helper did not create is
    // re-read before a refusal; see refreshObservedIntent.
    public var requiresCleanup: Bool {
        refreshCleanupBlock()
        refreshObservedIntent()
        condition.lock(); defer { condition.unlock() }
        return cleanupBlocked || staleIntent || staleInstallJournal
    }

    private var cleanupBlocked = false
    private var cleanupPersistFailed = false
    private var staleIntent = false
    // True when this helper cannot prove that its own launch intent is gone:
    // a create rollback left a changed, hard-linked, ACL-bearing, or unsynced
    // record; an unclean launch; an unclean stop; an unprompted engine exit; or
    // a failed clear. This state is sticky for the life of the process. It is
    // never re-evaluated or cleared automatically, because a later absence read
    // cannot prove that the earlier object is gone or that its removal is
    // durable. Only a new helper process re-reads the disk.
    private var intentUncertain = false
    // Latched when the install or service journal is present or unreadable at
    // construction, when a live prepare refuses because one is present, or when
    // the exclusion state cannot be checked safely. This latch is deliberately
    // one-way for the life of this helper. A journal that later disappears does
    // not prove that the coordinator finished its file transaction, and the two
    // journal recovery procedures are not integrated. `requiresCleanup` and
    // `preflightStart` use the latch; the start path also re-reads the journal
    // under the shared lock in prepare. Only a process restart re-reads the
    // state directory from disk.
    private var staleInstallJournal = false

    // A request that would be refused must not prompt for authorization. This
    // check is advisory: start() repeats the checks under the same lock and
    // acquires the real shared lock. The lock probe is only to avoid a prompt
    // while an install or upgrade already holds the exclusive lock.
    public func preflightStart(connection: UUID) -> HelperSessionStartResult? {
        refreshCleanupBlock()
        refreshObservedIntent()
        condition.lock()
        if closed { condition.unlock(); return .cancelled }
        if cleanupBlocked || staleIntent || staleInstallJournal {
            condition.unlock()
            return .cleanupBlocked
        }
        if closedConnections.contains(connection) { condition.unlock(); return .connectionClosed }
        if session != nil || starting != nil || stoppingCount > 0 {
            condition.unlock()
            return .busy
        }
        condition.unlock()
        switch exclusion.probeSharedAvailability() {
        case .available: return nil
        case .busy: return .startExclusionBusy
        case .unavailable: return .startExclusionUnavailable
        }
    }

    public var isShutDown: Bool {
        condition.lock(); defer { condition.unlock() }
        return closed
    }

    // True when the durable store could not be written after a block was
    // recorded in memory. The helper then keeps running and refuses starts, but
    // it cannot promise the block survives a restart. This is reported only for
    // the helper log; it never allows a start.
    public var cleanupPersistenceFailed: Bool {
        condition.lock(); defer { condition.unlock() }
        return cleanupPersistFailed
    }

    public func start(connection: UUID) -> HelperSessionStartResult {
        start(connection: connection, credentials: nil)
    }

    public func start(connection: UUID, credentials: Int32?) -> HelperSessionStartResult {
        refreshCleanupBlock()
        refreshObservedIntent()
        condition.lock()
        if closed {
            condition.unlock()
            return .cancelled
        }
        if cleanupBlocked || staleIntent || staleInstallJournal {
            condition.unlock()
            return .cleanupBlocked
        }
        if closedConnections.contains(connection) {
            condition.unlock()
            return .connectionClosed
        }
        if session != nil || starting != nil || stoppingCount > 0 {
            condition.unlock()
            return .busy
        }
        // A cancel or close request that arrived before this launch belongs to
        // an earlier request on the same connection. Clear it here so a stale
        // cancel cannot stop this newer launch.
        stopPending.remove(connection)
        let sessionID = UUID()
        starting = connection
        condition.unlock()

        // Take the helper's own shared lock before the launch intent or spawn.
        // A busy lock means an install or upgrade owns the exclusive lock. A
        // lock or install journal that cannot be checked is a refusal.
        let lease: HelperStartExclusionLease
        do {
            lease = try exclusion.prepare(session: connection)
        } catch let error as HelperStartExclusionError {
            condition.lock()
            if starting == connection { starting = nil }
            stopPending.remove(connection)
            let result: HelperSessionStartResult
            switch error {
            case .busy:
                result = .startExclusionBusy
            case .installJournalPresent:
                staleInstallJournal = true
                result = .cleanupBlocked
            case .unavailable, .unsafe, .writeFailed:
                result = .startExclusionUnavailable
            }
            condition.broadcast()
            condition.unlock()
            return result
        } catch {
            // An unknown exclusion failure does not prove that state is clean.
            // Refuse and keep the helper on the blocked path.
            condition.lock()
            if starting == connection { starting = nil }
            stopPending.remove(connection)
            staleInstallJournal = true
            condition.broadcast()
            condition.unlock()
            return .cleanupBlocked
        }

        // Write the durable launch intent, the helper start record, before the
        // launcher can spawn an engine. The store fsyncs the file and the
        // containing directory. If this fails, no engine has started and the
        // request is refused.
        do {
            try intentStore.create()
        } catch {
            // A partial or present intent is not proof that no engine exists.
            // Latch a block only when the store cannot prove that the name is
            // absent. A clean write failure before spawn may retry. A record
            // that another participant owns can be re-read after it exits; a
            // read failure cannot, so it stays uncertain. A rollback that kept
            // a changed, linked, ACL-bearing, or unsynced record is this
            // helper's own uncertainty and is never re-evaluated.
            let uncertain = Self.intentCreateLeftUncertainty(error)
            let present: Bool
            var readable = true
            do {
                present = try intentStore.isPresent()
            } catch {
                present = true
                readable = false
            }
            lease.releaseAfterCleanStop()
            condition.lock()
            if starting == connection { starting = nil }
            stopPending.remove(connection)
            if present || uncertain {
                staleIntent = true
                intentUncertain = uncertain || !readable
            }
            condition.broadcast()
            condition.unlock()
            return present || uncertain ? .cleanupBlocked : .launchFailed
        }
        condition.lock()
        staleIntent = false
        intentUncertain = false
        condition.unlock()

        let engine: RunningHelperEngine
        do {
            engine = try launcher.launch(holding: lease.handoff, credentials: credentials)
        } catch let error as HelperTrustError where error == .engineStopTimedOut
            || error == .engineExitUnclean {
            // The launcher spawned an engine but could not prove a clean stop.
            // The engine may still own a route, so refuse every later start and
            // record a durable block. The launch intent stays, and the shared
            // lock stays held for the life of this helper. Hold the stop slot
            // until the durable block and retained lease are in place so a
            // concurrent shutdown cannot exit in between.
            condition.lock()
            staleIntent = true
            intentUncertain = true
            if starting == connection { starting = nil }
            stopPending.remove(connection)
            stoppingCount += 1
            condition.broadcast()
            condition.unlock()
            markCleanupBlocked(reason: "launch stop was not clean")
            retainExclusion(lease)
            condition.lock()
            stoppingCount -= 1
            condition.broadcast()
            condition.unlock()
            return .cleanupBlocked
        } catch let error as HelperEngineExitedBeforeGrant {
            // The launcher reaped an engine that exited before it published
            // its port. No session existed, so the helper never wrote a grant
            // and the engine cannot have changed a route. This is a failed
            // start with a fixed reason: clear the write-ahead intent, release
            // the shared lock, and set no cleanup block. A failed intent clear
            // keeps the record on disk, so that case still refuses later starts.
            let cleared = clearIntentAfterVerifiedCleanStop()
            lease.releaseAfterCleanStop()
            failureRecord.record(error.reason)
            condition.lock()
            if starting == connection { starting = nil }
            stopPending.remove(connection)
            condition.broadcast()
            condition.unlock()
            return cleared ? .engineDidNotStart(error.reason) : .cleanupBlocked
        } catch let error where Self.launchFailureProvesNoEngine(error) {
            // These errors prove that no engine survives: the launcher either
            // refused before spawn, failed to spawn, or spawned a child that
            // exited cleanly. Clear the write-ahead intent only now. A failed
            // clear leaves the record in place for a person to inspect.
            var cleared = true
            do {
                try intentStore.clearAfterVerifiedCleanStop()
            } catch {
                cleared = false
            }
            lease.releaseAfterCleanStop()
            condition.lock()
            if starting == connection { starting = nil }
            stopPending.remove(connection)
            if !cleared {
                staleIntent = true
                intentUncertain = true
            }
            condition.broadcast()
            condition.unlock()
            return cleared ? .launchFailed : .cleanupBlocked
        } catch {
            // An unknown launcher failure does not prove that no engine exists.
            // Keep the intent and the shared lock, and block every later start
            // instead of guessing. Hold the stop slot until the durable block
            // and retained lease are in place.
            condition.lock()
            staleIntent = true
            intentUncertain = true
            if starting == connection { starting = nil }
            stopPending.remove(connection)
            stoppingCount += 1
            condition.broadcast()
            condition.unlock()
            markCleanupBlocked(reason: "launch failure did not prove an engine stop")
            retainExclusion(lease)
            condition.lock()
            stoppingCount -= 1
            condition.broadcast()
            condition.unlock()
            return .cleanupBlocked
        }

        condition.lock()
        if starting == connection { starting = nil }
        // shutDown() waits for an in-flight launch to clear. Wake it here on
        // every completion path, including a late launch that will be stopped
        // because the helper is closing.
        condition.broadcast()
        let cancelled = stopPending.remove(connection) != nil
        // Another connection can win the race while the engine starts. Its
        // session stays; this late engine is stopped before it is used. The
        // same rule applies when the requesting connection closed or cancelled
        // during the launch, or when the helper began to shut down.
        var lateReason: EngineStopReason?
        var lateResult: HelperSessionStartResult = .connectionClosed
        if closed || closedConnections.contains(connection) {
            lateReason = .connectionClosed
            lateResult = .connectionClosed
        } else if cancelled {
            lateReason = .cancelled
            lateResult = .cancelled
        } else if cleanupBlocked || staleIntent || staleInstallJournal || session != nil || stoppingCount > 0 {
            let blocked = cleanupBlocked || staleIntent || staleInstallJournal
            lateReason = .cancelled
            lateResult = blocked ? .cleanupBlocked : .busy
        }
        if let lateReason {
            // Keep the stop slot until the late engine's cleanup finishes. A
            // shutdown that wakes on the cleared launch slot must not exit
            // while this engine is still being stopped.
            stoppingCount += 1
            condition.unlock()
            let stopResult = finishAndRecord(
                engine,
                sessionID: sessionID,
                reason: lateReason,
                exclusion: lease,
                // A late engine never had a session, so no grant was written.
                grantAttempted: false
            )
            condition.lock()
            stoppingCount -= 1
            if stopResult != .stopped {
                lateLaunchStopResult = Self.combineStopResult(
                    lateLaunchStopResult,
                    stopResult
                )
            }
            condition.broadcast()
            condition.unlock()
            return lateResult
        }
        session = Session(
            id: sessionID,
            connection: connection,
            engine: engine,
            exclusion: lease,
            startedAt: clock()
        )
        condition.broadcast()
        condition.unlock()
        return .started(HelperEngineSession(sessionID: sessionID, engine: engine.description))
    }

    // Write the one-time tunnel grant for the session that this connection
    // owns. The engine already runs; this call changes no route and stops
    // nothing. The condition lock stays held for the bounded file write so a
    // concurrent stop cannot remove the runtime directory underneath it.
    public func authorizeStart(connection: UUID) -> HelperTunnelAuthorizationResult {
        condition.lock()
        guard let active = session, active.connection == connection else {
            condition.unlock()
            return .notRunning
        }
        // Do not write a grant for an engine that has already exited. The
        // liveness watch records the cleanup block for that exit.
        guard active.engine.isRunning else {
            condition.unlock()
            return .notRunning
        }
        do {
            // Mark the attempt before the write. A partial write that fails
            // still counts, so a later exit keeps the cleanup path.
            session?.grantAttempted = true
            try active.engine.authorizeStart()
            // The person answered the prompt, so the authorization deadline
            // no longer applies to this session.
            session?.authorized = true
            condition.unlock()
            return .authorized
        } catch {
            condition.unlock()
            return .grantFailed
        }
    }

    // Stop the session that this connection owns. A caller that did not own
    // the session gets a successful transport acknowledgement with
    // `owned == false`; the helper never stops or claims another connection's
    // engine. The caller must keep its uncertainty in that case.
    public func stopReportingOwnership(connection: UUID, reason: EngineStopReason) -> StopReport {
        condition.lock()
        guard let active = session, active.connection == connection else {
            // A cancel can arrive while the engine is still launching. Record
            // it so the late engine is stopped before it is used. A cancel
            // cannot interrupt posix_spawn or an authorization check. It only
            // guarantees that the caller will not receive the late engine and
            // that the helper will stop it. The reply can therefore arrive
            // before the child has spawned.
            if starting == connection {
                stopPending.insert(connection)
                condition.unlock()
                return StopReport(owned: true, result: .stopped)
            }
            condition.unlock()
            return StopReport(owned: false, result: .stopped)
        }
        session = nil
        stoppingCount += 1
        condition.unlock()
        let result = finishAndRecord(
            active.engine,
            sessionID: active.id,
            reason: reason,
            exclusion: active.exclusion,
            grantAttempted: active.grantAttempted
        )
        condition.lock()
        stoppingCount -= 1
        condition.broadcast()
        condition.unlock()
        return StopReport(owned: true, result: result)
    }

    @discardableResult
    public func stop(connection: UUID, reason: EngineStopReason) -> EngineStopResult {
        stopReportingOwnership(connection: connection, reason: reason).result
    }

    // The helper runtime calls this when the XPC connection is invalidated or
    // interrupted. It is the parent-loss path.
    public func connectionClosed(_ connection: UUID) {
        condition.lock()
        closedConnections.insert(connection)
        // Keep the late-close record bounded. A connection id is never reused,
        // so dropping the oldest record cannot affect a live connection.
        if closedConnections.count > 128, let first = closedConnections.first {
            closedConnections.remove(first)
        }
        condition.unlock()
        stop(connection: connection, reason: .connectionClosed)
    }

    // SIGTERM and process termination must clean up every owned engine. Wait
    // for a stop that another thread already began, and for a launch and its
    // late cleanup, instead of exiting while an engine may still start or stop.
    // A retained lease or a late stop that timed out or failed is not a clean
    // exit: the caller must keep this process alive and the lock held.
    @discardableResult
    public func shutDown() -> EngineStopResult {
        condition.lock()
        closed = true
        while stoppingCount > 0 || starting != nil {
            condition.wait()
        }
        let active = session
        session = nil
        if active != nil { stoppingCount += 1 }
        var result = lateLaunchStopResult ?? .stopped
        condition.unlock()

        if let active {
            result = Self.combineStopResult(
                result,
                finishAndRecord(
                    active.engine,
                    sessionID: active.id,
                    reason: .helperShutdown,
                    exclusion: active.exclusion,
                    grantAttempted: active.grantAttempted
                )
            )
        }

        condition.lock()
        if active != nil { stoppingCount -= 1 }
        if !retainedExclusions.isEmpty, result == .stopped {
            result = .failed
        }
        condition.broadcast()
        condition.unlock()
        return result
    }

    private static func combineStopResult(
        _ first: EngineStopResult?,
        _ second: EngineStopResult
    ) -> EngineStopResult {
        switch (first, second) {
        case (.some(.failed), _), (_, .failed):
            return .failed
        case (.some(.timedOut), _), (_, .timedOut):
            return .timedOut
        default:
            return .stopped
        }
    }

    // The helper polls this while a session exists. When the engine has exited
    // on its own, the slot must be freed so the owning connection can be told,
    // but the exit is not proof of cleanup. The engine may have failed after it
    // installed routes, so this path records the same durable cleanup block as
    // an unclean stop. The one exception is an engine that the helper reaped
    // before any grant write for its session: it cannot have changed a route,
    // so it is a failed start. It returns the connection that owned the engine
    // exactly once.
    public func reapExitedEngine() -> UUID? {
        reapExitedEngineReport()?.connection
    }

    // One reaped engine. `failedStart` is true when the helper reaped an
    // engine that exited before any grant write for its session: that engine
    // cannot have changed a route, so the exit is a failed start with a fixed
    // reason and sets no cleanup block.
    public struct ReapedEngine: Equatable, Sendable {
        public let connection: UUID
        public let sessionID: UUID
        public let failedStart: Bool
        public let reason: EngineStartFailureReason?
    }

    public func reapExitedEngineReport() -> ReapedEngine? {
        condition.lock()
        guard let active = session, !active.engine.isRunning else {
            condition.unlock()
            return nil
        }
        session = nil
        stoppingCount += 1
        condition.unlock()

        // `isRunning` reaped the child when it knows the exit. An engine whose
        // exit the helper cannot read, or one that reached a grant write, keeps
        // the cleanup path below.
        if !active.grantAttempted && active.engine.exitObserved {
            _ = finishAndRecord(
                active.engine,
                sessionID: active.id,
                reason: .engineExited,
                exclusion: active.exclusion,
                grantAttempted: false
            )
            condition.lock()
            stoppingCount -= 1
            let failure = lastStoppedSession?.id == active.id ? lastStoppedSession : nil
            condition.broadcast()
            condition.unlock()
            if let failure, failure.result == .failedStart {
                return ReapedEngine(
                    connection: active.connection,
                    sessionID: active.id,
                    failedStart: true,
                    reason: failure.reason
                )
            }
            return ReapedEngine(connection: active.connection, sessionID: active.id, failedStart: false, reason: nil)
        }

        markCleanupBlocked(reason: "engine exited without a stop request")

        // Reap the dead child and remove its runtime directory. stop() returns
        // .stopped only when the child exited with a clean status. A non-clean
        // exit has already recorded the block above. Even a clean exit was not
        // requested, so the intent and shared lock stay held.
        _ = finishAndRecord(
            active.engine,
            sessionID: active.id,
            reason: .engineExited,
            exclusion: active.exclusion,
            grantAttempted: active.grantAttempted
        )

        condition.lock()
        stoppingCount -= 1
        condition.broadcast()
        condition.unlock()
        return ReapedEngine(connection: active.connection, sessionID: active.id, failedStart: false, reason: nil)
    }

    // The helper polls this while a session exists. A live session that has
    // received no verified authorization within the deadline is stopped on the
    // normal stop path and recorded like any other stop, so a reconnecting
    // caller reads the same session result. A grant write that already
    // succeeded, an engine that already exited (see reapExitedEngine), or a
    // session that is still inside the bound is left alone. It returns the
    // stopped session exactly once.
    public func expireUnauthorizedSession() -> ExpiredSession? {
        condition.lock()
        guard let active = session,
              !active.authorized,
              active.engine.isRunning,
              clock() - active.startedAt >= authorizationDeadline
        else {
            condition.unlock()
            return nil
        }
        session = nil
        stoppingCount += 1
        condition.unlock()
        let result = finishAndRecord(
            active.engine,
            sessionID: active.id,
            reason: .authorizationTimeout,
            exclusion: active.exclusion,
            grantAttempted: active.grantAttempted
        )
        condition.lock()
        stoppingCount -= 1
        condition.broadcast()
        condition.unlock()
        return ExpiredSession(connection: active.connection, sessionID: active.id, result: result)
    }

    // A rollback that could not prove its own record gone is a sticky
    // uncertainty. An absence read afterwards is not evidence, because the
    // record may have been kept, its removal may not be durable, or it may have
    // been replaced. Only a new helper process may re-read the disk.
    private static func intentCreateLeftUncertainty(_ error: Error) -> Bool {
        guard let error = error as? HelperLaunchIntentError else { return false }
        return error == .rollbackUncertain
    }

    // Every error in this set is raised before a child exists, by a failed
    // spawn that created no child, or after the launcher already stopped a
    // spawned child with a clean zero exit. An error outside this set is not
    // proof that no engine survives.
    private static func launchFailureProvesNoEngine(_ error: Error) -> Bool {
        guard let error = error as? HelperTrustError else { return false }
        switch error {
        case .engineStartFailed,
             .requiresRoot,
             .missingSigningIdentity,
             .invalidSigningPolicy,
             .signatureUnavailable,
             .signatureRejected,
             .notInstalledPath,
             .pathIsNotCanonical,
             .executableNotRegularFile,
             .executableNotOwnedByRoot,
             .executableWritable,
             .unsafeParentDirectory,
             .unsafeInstallRoot:
            return true
        default:
            return false
        }
    }

    // Record the exact session result before another connection can ask. The
    // record is written after the child stop completes, so a status read that
    // races the stop sees `stopping` and cannot claim a clean result early.
    private func finishAndRecord(
        _ engine: RunningHelperEngine,
        sessionID: UUID,
        reason: EngineStopReason,
        exclusion lease: HelperStartExclusionLease,
        grantAttempted: Bool
    ) -> EngineStopResult {
        let (result, failedStart) = finish(
            engine,
            reason: reason,
            exclusion: lease,
            grantAttempted: grantAttempted
        )
        let recorded: HelperSessionStopResult
        switch (reason, result) {
        case _ where failedStart != nil:
            recorded = .failedStart
        case (.engineExited, _):
            recorded = .engineExited
        case (_, .stopped):
            recorded = .stopped
        case (_, .timedOut):
            recorded = .timedOut
        case (_, .failed):
            recorded = .failed
        }
        condition.lock()
        lastStoppedSession = (id: sessionID, result: recorded, reason: failedStart)
        condition.broadcast()
        condition.unlock()
        return result
    }

    // Stop one engine and settle the durable state. The second value is the
    // fixed reason when this was a failed start: the helper reaped an engine
    // that never reached a grant write, so it cannot have changed a route.
    private func finish(
        _ engine: RunningHelperEngine,
        reason: EngineStopReason,
        exclusion lease: HelperStartExclusionLease,
        grantAttempted: Bool
    ) -> (EngineStopResult, EngineStartFailureReason?) {
        let result = engine.stop()
        if result == .timedOut {
            markCleanupBlocked(reason: "engine stop timed out")
            markIntentStale()
            retainExclusion(lease)
        } else if !grantAttempted && engine.exitObserved
            && (result == .failed || reason == .engineExited) {
            // The engine changes a route only after it consumes a grant, and
            // this session never reached a grant write. The helper reaped the
            // child, so it is gone. Clear the intent and release the lock like
            // a clean stop, and record the fixed reason. A failed clear keeps
            // the record on disk and blocks later starts.
            _ = clearIntentAfterVerifiedCleanStop()
            lease.releaseAfterCleanStop()
            guard reason == .engineExited else {
                // A requested stop (a person, a cancel, a lost connection, or
                // the authorization deadline) of an engine that never reached
                // a grant. Its exit status is not route evidence, so this is a
                // clean stop with the reason the caller gave, not a failed
                // start and not a block.
                return (.stopped, nil)
            }
            let failure = engine.startFailureReason ?? .exitedWithoutReason
            failureRecord.record(failure)
            return (result, failure)
        } else if result == .failed {
            markCleanupBlocked(reason: "engine exit status was not clean")
            markIntentStale()
            retainExclusion(lease)
        } else if reason == .engineExited {
            // An engine that exits without a stop request is not proof that it
            // removed its routes. Keep the intent and shared lock even though
            // the child exited with a zero status.
            markIntentStale()
            retainExclusion(lease)
        } else {
            // The engine stopped cleanly. Try to clear the intent, then release
            // the helper's own shared lock. A failed intent clear leaves a
            // durable record that makes the installer refuse; it does not mean
            // the engine is still alive, so the lock can be released.
            _ = clearIntentAfterVerifiedCleanStop()
            lease.releaseAfterCleanStop()
        }
        return (result, nil)
    }

    // The stop, launch-failure, or connection-loss path returned a clean child
    // exit. Only now may the write-ahead intent leave the disk. A failed clear
    // keeps the intent for a later helper and blocks this one. True means the
    // intent is provably gone.
    @discardableResult
    private func clearIntentAfterVerifiedCleanStop() -> Bool {
        do {
            try intentStore.clearAfterVerifiedCleanStop()
            condition.lock()
            staleIntent = false
            intentUncertain = false
            condition.unlock()
            return true
        } catch {
            condition.lock()
            staleIntent = true
            intentUncertain = true
            condition.unlock()
            return false
        }
    }

    private func markIntentStale() {
        condition.lock()
        staleIntent = true
        intentUncertain = true
        condition.unlock()
    }

    // Keep an unclean session's lease alive for the rest of this helper
    // process. The shared lock must not be released while the engine may still
    // own routes. The retained array is bounded by the block itself: no start
    // can create another session after this point.
    private func retainExclusion(_ lease: HelperStartExclusionLease) {
        lease.abandon()
        condition.lock()
        retainedExclusions.append(lease)
        condition.broadcast()
        condition.unlock()
    }

    // Record the block in memory first. A failure to persist it never unblocks
    // the running helper, but the helper log records that a restart could lose
    // the block. The store itself is append-only from this process: there is no
    // automatic clear.
    private func markCleanupBlocked(reason: String) {
        condition.lock()
        cleanupBlocked = true
        condition.broadcast()
        condition.unlock()
        do {
            try cleanupStore.recordBlock(reason: reason)
            condition.lock()
            cleanupPersistFailed = false
            condition.unlock()
        } catch {
            condition.lock()
            cleanupPersistFailed = true
            condition.unlock()
        }
    }

    // Pick up a marker that another helper process wrote after this one
    // started. A read error means the state is unknown, so it is treated as
    // blocked. The check never clears a block: a person must remove the marker.
    private func refreshCleanupBlock() {
        let persisted: Bool
        do {
            persisted = try cleanupStore.isBlocked()
        } catch {
            persisted = true
        }
        guard persisted else { return }
        condition.lock()
        if !cleanupBlocked {
            cleanupBlocked = true
            condition.broadcast()
        }
        condition.unlock()
    }

    // Re-read a launch intent that another participant owns.
    //
    // A concurrent direct engine or another helper creates the same
    // `engine-session` record that this helper refuses. That participant
    // removes the record only after its own cleanup. A refusal must therefore
    // not latch the record forever: one presence read is made before a
    // refusal, with no retry loop. A present record, an unreadable store, a
    // live session, an in-flight launch or stop, a retained exclusion lease,
    // or this helper's own uncertain intent keeps the gate closed. A read that
    // races with a new participant is safe because the create that follows is
    // still `O_EXCL`.
    //
    // Absence alone does not prove that an engine from an earlier process
    // stopped cleaning up. This helper treats absence the same way a fresh
    // helper start does: the durable record is gone, so the remaining evidence
    // is the recovery action that removed it. It never clears its own
    // `intentUncertain` state. A record left by a crashed helper is removed
    // only by the reviewed recovery procedure; this check only observes that
    // removal. A presence read that races with an unapproved removal cannot be
    // detected, because the record carries no owner identity.
    //
    // A create rollback that kept a safe record from another participant sets
    // `staleIntent` without `intentUncertain`, so this check can clear it after
    // that participant removes it. A rollback that kept a changed, hard-linked,
    // ACL-bearing, or unsynced record sets `intentUncertain`, and this check
    // never clears it.
    private func refreshObservedIntent() {
        condition.lock()
        let shouldRecheck = staleIntent
            && !intentUncertain
            && retainedExclusions.isEmpty
            && session == nil
            && starting == nil
            && stoppingCount == 0
        condition.unlock()
        guard shouldRecheck else { return }
        let present: Bool
        do {
            present = try intentStore.isPresent()
        } catch {
            // An unreadable store is not evidence that the record is gone.
            return
        }
        guard !present else { return }
        condition.lock()
        // The launch state can change while the presence read runs. Recheck
        // every guard under the lock and never clear an owned uncertainty.
        if staleIntent
            && !intentUncertain
            && retainedExclusions.isEmpty
            && session == nil
            && starting == nil
            && stoppingCount == 0
        {
            staleIntent = false
            condition.broadcast()
        }
        condition.unlock()
    }
}

// A helper that cannot prove its install path or signing identity must exit
// before it opens a listener. This value is the only result the app shows.
public enum ProtectedHelperAvailability: Equatable, Sendable {
    case available(VerifiedHelperInstall)
    case unavailable(HelperTrustError)

    public var isAvailable: Bool {
        if case .available = self { return true }
        return false
    }
}

public final class ProtectedHelperPreflight: Sendable {
    private let verifier: HelperInstallVerifier
    public init(verifier: HelperInstallVerifier) { self.verifier = verifier }

    public func evaluate() -> ProtectedHelperAvailability {
        do {
            return .available(try verifier.verify())
        } catch let error as HelperTrustError {
            return .unavailable(error)
        } catch {
            return .unavailable(.signatureUnavailable)
        }
    }
}
