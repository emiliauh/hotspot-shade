import XCTest
@testable import HotspotShadeKit

final class EngineLaunchTests: XCTestCase {
    // MARK: - Launch policy

    func testUserEngineStartsWithoutAnAdministratorPrompt() {
        XCTAssertTrue(EngineLaunchPolicy.startsAutomatically())
    }

    func testTunnelAuthorizationFailuresUsePlainSentences() {
        let notRunning = EngineLaunchFailure.fromHelper(HelperTrustError.tunnelNotRunning)
        XCTAssertEqual(notRunning.kind, .engine)
        XCTAssertEqual(notRunning.message, Strings.helperTunnelNotRunning)
        XCTAssertEqual(notRunning.diagnosticCode, "tunnel_not_running")

        let grant = EngineLaunchFailure.fromHelper(HelperTrustError.grantFailed)
        XCTAssertEqual(grant.kind, .authorization)
        XCTAssertEqual(grant.message, Strings.helperGrantFailed)
        XCTAssertEqual(grant.diagnosticCode, "authorization_failed")
    }

    // MARK: - Failure mapping

    func testCleanupBlockKeepsRecoveryAndDoesNotClaimACleanStop() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.cleanupBlocked)
        XCTAssertEqual(failure.kind, .cleanup)
        XCTAssertEqual(failure.message, Strings.helperCleanup)
        XCTAssertTrue(failure.recovery.contains("Restarting the target device does not clear it"))
        XCTAssertEqual(failure.diagnosticCode, "cleanup_blocked")
    }

    func testDeniedAuthorizationHasAPlainRecovery() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.notAuthorized)
        XCTAssertEqual(failure.kind, .authorization)
        XCTAssertEqual(failure.message, Strings.helperNotAuthorized)
        XCTAssertTrue(failure.recovery.contains("administrator account"))
    }

    func testCancelledAuthorizationIsNotAnEngineFailure() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.cancelled)
        XCTAssertEqual(failure.kind, .authorization)
        XCTAssertTrue(failure.message.contains("cancelled"))
        XCTAssertEqual(failure.diagnosticCode, "authorization_cancelled")
    }

    func testUnsignedHelperSaysUseADeveloperIDBuild() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.signatureRejected)
        XCTAssertEqual(failure.message, Strings.helperNotSigned)
        XCTAssertEqual(failure.kind, .helper)
    }

    func testMissingHelperSaysInstallThePackage() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.notInstalledPath)
        XCTAssertEqual(failure.message, Strings.helperNotInstalled)
        if HelperRequirement.isLocalPreview {
            XCTAssertTrue(failure.recovery.contains("local preview setup"))
        } else {
            XCTAssertTrue(failure.recovery.contains("Install the signed helper package"))
        }
    }

    func testStartExclusionFailuresUseFixedSentencesWithoutSystemDetails() {
        let busy = EngineLaunchFailure.fromHelper(HelperTrustError.startExclusionBusy)
        XCTAssertEqual(busy.kind, .helper)
        XCTAssertEqual(busy.message, Strings.helperStartExclusionBusy)
        XCTAssertEqual(busy.diagnosticCode, "start_exclusion_busy")
        XCTAssertFalse(busy.message.localizedCaseInsensitiveContains("lock"))

        let unavailable = EngineLaunchFailure.fromHelper(HelperTrustError.startExclusionUnavailable)
        XCTAssertEqual(unavailable.kind, .helper)
        XCTAssertEqual(unavailable.message, Strings.helperStartExclusionUnavailable)
        XCTAssertEqual(unavailable.diagnosticCode, "start_exclusion_unavailable")
        XCTAssertFalse(unavailable.message.localizedCaseInsensitiveContains("journal"))
        XCTAssertNotEqual(unavailable.message, Strings.helperFailed)
    }

    func testRealStartTimeoutIsAnEngineFailureNotAHelperFailure() {
        let failure = EngineLaunchFailure.fromHelper(BackendError.timeout)
        XCTAssertEqual(failure.kind, .engine)
        XCTAssertEqual(failure.diagnosticCode, "engine_timeout")
        XCTAssertEqual(failure.message, "The engine did not answer in time.")
    }

    func testUserEngineFailureNeverMentionsTheHelper() {
        let failure = EngineLaunchFailure.fromUserEngine(BackendError.missingEngine)
        XCTAssertEqual(failure.message, Strings.engineMissing)
        XCTAssertEqual(failure.kind, .engine)
        XCTAssertFalse(failure.message.lowercased().contains("helper"))
        XCTAssertEqual(failure.diagnosticCode, "engine_missing")
    }

    func testLostConnectionIsAStopNotAStartingState() {
        let failure = EngineLaunchFailure.fromLost(HelperTrustError.helperUnavailable)
        XCTAssertEqual(failure.message, Strings.helperLost)
        XCTAssertEqual(failure.diagnosticCode, "helper_lost")
        XCTAssertNotEqual(failure.message, Strings.helperStopped)
    }

    func testLostConnectionAfterCleanupBlockKeepsTheCleanupMessage() {
        let failure = EngineLaunchFailure.fromLost(HelperTrustError.cleanupBlocked)
        XCTAssertEqual(failure.kind, .cleanup)
        XCTAssertEqual(failure.message, Strings.helperCleanup)
    }

    func testLostEngineExitKeepsTheCleanupGuidance() {
        for error in [HelperTrustError.engineExited, .engineStopTimedOut, .engineExitUnclean] {
            let failure = EngineLaunchFailure.fromLost(error)
            XCTAssertEqual(failure.kind, .cleanup, "\(error)")
            XCTAssertEqual(failure.message, Strings.helperCleanup, "\(error)")
            XCTAssertEqual(failure.recovery, EngineLaunchText.cleanupRecovery, "\(error)")
        }
    }

    func testAUserEngineLossCarriesAnUncertainStopIntoTheLostState() {
        let uncertain = EngineLaunchFailure.fromUserEngineLoss(cleanup: "The helper did not confirm the stop.", kind: .retryable)
        XCTAssertEqual(uncertain.kind, .cleanup)
        XCTAssertEqual(uncertain.message, "The helper did not confirm the stop.")
        // A retryable mark names the retry. It is not a durable cleanup block,
        // so it must not say that the block has no approved clear path.
        XCTAssertEqual(uncertain.recovery, EngineLaunchText.quitRecovery)
        XCTAssertFalse(uncertain.cleanupIsFinal)
        XCTAssertEqual(EngineLaunchState.lost(uncertain).presentation().action, .retryCleanup)
        XCTAssertEqual(uncertain.diagnosticCode, "engine_lost_cleanup")
        let plain = EngineLaunchFailure.fromUserEngineLoss(cleanup: nil, kind: nil)
        XCTAssertEqual(plain.kind, .engine)
        XCTAssertEqual(plain.diagnosticCode, "engine_exited")
    }

    // Each final mark keeps its own recovery text on the lost screen. A
    // durable block is not forgotten by a relaunch, so it must never get the
    // route text that says a relaunch forgets the warning.
    func testAUserEngineLossKeepsTheRecoveryTextOfTheMarkKind() {
        let durable = EngineLaunchFailure.fromUserEngineLoss(cleanup: Strings.helperCleanup, kind: .durableBlock)
        XCTAssertEqual(durable.recovery, EngineLaunchText.cleanupRecovery)
        XCTAssertTrue(durable.cleanupIsFinal)
        XCTAssertFalse(durable.recovery.contains("Restarting the app"))
        XCTAssertNil(EngineLaunchState.lost(durable).presentation().action)
        let routes = EngineLaunchFailure.fromUserEngineLoss(cleanup: EngineLaunchText.routeCleanupUnverified, kind: .routesUnverified)
        XCTAssertEqual(routes.recovery, EngineLaunchText.routeCleanupRecovery)
        XCTAssertTrue(routes.cleanupIsFinal)
        XCTAssertNil(EngineLaunchState.lost(routes).presentation().action)
        // A failed Retry cleanup uses the same mapping.
        let retryBlocked = EngineLaunchFailure.fromCleanupRetry(message: Strings.helperCleanup, kind: .durableBlock)
        XCTAssertEqual(retryBlocked.recovery, EngineLaunchText.cleanupRecovery)
        XCTAssertTrue(retryBlocked.cleanupIsFinal)
        let retryAgain = EngineLaunchFailure.fromCleanupRetry(message: "The helper did not answer.", kind: .retryable)
        XCTAssertEqual(retryAgain.recovery, EngineLaunchText.quitRecovery)
        XCTAssertEqual(EngineLaunchState.lost(retryAgain).presentation().action, .retryCleanup)
        // No retryable text mentions a cleanup block that the helper never set.
        XCTAssertFalse(EngineLaunchText.quitRecovery.lowercased().contains("cleanup block"))
    }

    func testCleanupRecoveryDoesNotContradictTheDurableBlock() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.cleanupBlocked)
        XCTAssertFalse(failure.recovery.contains("Restart the target device, then try again"))
        XCTAssertTrue(failure.recovery.contains("Restarting the target device does not clear it"))
        XCTAssertTrue(failure.recovery.contains("administrator"))
        XCTAssertTrue(failure.recovery.contains("preview-clear-cleanup-block"))
        XCTAssertTrue(failure.recovery.contains("no 2000::/3 route"))
        XCTAssertLessThan(
            failure.recovery.range(of: "netstat -rn")!.lowerBound,
            failure.recovery.range(of: "preview-clear-cleanup-block")!.lowerBound
        )
    }

    func testCleanupTimeoutAndUncleanExitUseDistinctDiagnosticCodes() {
        XCTAssertEqual(EngineLaunchFailure.fromHelper(HelperTrustError.engineStopTimedOut).diagnosticCode, "cleanup_timeout")
        XCTAssertEqual(EngineLaunchFailure.fromHelper(HelperTrustError.engineExitUnclean).diagnosticCode, "cleanup_unclean")
        XCTAssertEqual(EngineLaunchFailure.fromHelper(HelperTrustError.engineExited).diagnosticCode, "cleanup_engine_exited")
    }

    // MARK: - Presentation

    func testWaitingStateOffersOnlyAnExplicitStart() {
        let presentation = EngineLaunchState.waiting.presentation()
        XCTAssertEqual(presentation.actionTitle, "Start HotspotShade")
        XCTAssertFalse(presentation.showsProgress)
        XCTAssertFalse(presentation.isAttention)
        XCTAssertTrue(presentation.showsCopyDiagnostics)
        XCTAssertTrue(presentation.message.contains("as your account"))
        XCTAssertTrue(presentation.message.contains("turn on the tunnel"))
    }

    func testStartingStateDoesNotClaimAnAdministratorPrompt() {
        let real = EngineLaunchState.starting.presentation()
        XCTAssertTrue(real.message.contains("No administrator authorization is needed"))
        XCTAssertNil(real.actionTitle)
        XCTAssertTrue(real.showsProgress)
    }

    func testFailedStateKeepsTheRecoveryAndDiagnostics() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.cleanupBlocked)
        let presentation = EngineLaunchState.failed(failure).presentation()
        XCTAssertEqual(presentation.title, "HotspotShade did not start")
        XCTAssertEqual(presentation.message, Strings.helperCleanup)
        XCTAssertEqual(presentation.recovery, failure.recovery)
        XCTAssertEqual(presentation.actionTitle, Strings.tryAgain)
        XCTAssertTrue(presentation.isAttention)
        XCTAssertTrue(presentation.showsCopyDiagnostics)
    }

    func testLostStateDoesNotClaimAStopOrStarting() {
        let failure = EngineLaunchFailure.fromLost(HelperTrustError.helperUnavailable)
        let presentation = EngineLaunchState.lost(failure).presentation()
        XCTAssertEqual(presentation.title, "HotspotShade needs attention")
        XCTAssertFalse(presentation.title.lowercased().contains("starting"))
        XCTAssertFalse(presentation.title.lowercased().contains("stopped"))
        XCTAssertEqual(presentation.actionTitle, Strings.tryAgain)
        XCTAssertTrue(presentation.isAttention)
    }

    // Finding 2: an unconfirmed cleanup has a reachable retry. The per-launch
    // secret never appears in the text.
    func testLostCleanupOffersRetryCleanup() {
        let failure = EngineLaunchFailure(
            kind: .cleanup,
            message: "The helper did not confirm the stop.",
            recovery: EngineLaunchText.quitRecovery,
            diagnosticCode: "cleanup_retry"
        )
        let presentation = EngineLaunchState.lost(failure).presentation()
        XCTAssertEqual(presentation.actionTitle, EngineLaunchText.retryCleanupAction)
        XCTAssertTrue(presentation.message.contains("did not confirm"))
        XCTAssertFalse(presentation.message.lowercased().contains("secret"))
    }

    // MARK: - Menu

    func testFailedMenuDoesNotSayStarting() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.cleanupBlocked)
        let content = EngineLaunchMenu.content(state: .failed(failure), quitting: false)
        XCTAssertEqual(content.header.title, "HotspotShade did not start")
        XCTAssertNotEqual(content.header.title, UIStrings.menuStarting)
        XCTAssertEqual(content.stateWord, "Needs attention")
        XCTAssertEqual(content.detail.title, failure.message)
        XCTAssertEqual(content.iconSymbol, "exclamationmark.triangle")
        XCTAssertEqual(content.notices.first?.title, failure.recovery)
        XCTAssertTrue(content.copyDiagnostics.isEnabled)
        XCTAssertEqual(content.quit.title, Strings.quit)
        XCTAssertTrue(content.quit.isEnabled)
    }

    func testLostMenuShowsAttentionAndKeepsDiagnostics() {
        let failure = EngineLaunchFailure.fromLost(HelperTrustError.cleanupBlocked)
        let content = EngineLaunchMenu.content(state: .lost(failure), quitting: false)
        XCTAssertEqual(content.header.title, "HotspotShade needs attention")
        XCTAssertEqual(content.stateWord, "Needs attention")
        XCTAssertEqual(content.detail.title, failure.message)
        XCTAssertEqual(content.notices.first?.title, failure.recovery)
        XCTAssertTrue(content.copyDiagnostics.isEnabled)
    }

    func testQuittingMenuSaysTurningOffAndDisablesQuit() {
        let content = EngineLaunchMenu.content(state: .stopping, quitting: true)
        XCTAssertEqual(content.quit.title, UIStrings.turningOff)
        XCTAssertFalse(content.quit.isEnabled)
        XCTAssertFalse(content.copyDiagnostics.isEnabled)
    }

    func testWaitingMenuOffersNoTunnelAction() {
        let content = EngineLaunchMenu.content(state: .waiting, quitting: false)
        XCTAssertTrue(content.actions.isEmpty)
        XCTAssertEqual(content.header.title, "HotspotShade is ready")
        XCTAssertEqual(content.stateWord, "Ready")
        XCTAssertEqual(content.detail.title, "Open HotspotShade to start its engine.")
        XCTAssertTrue(content.copyDiagnostics.isEnabled)
    }

    // MARK: - Diagnostics

    func testLaunchDiagnosticsHoldTheFailureWithoutSecrets() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.cleanupBlocked)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let text = EngineLaunchDiagnostics.text(
            state: .lost(failure),
            appVersion: "1.2.3 (4)",
            macOSVersion: "Version 14.0",
            now: now
        )
        XCTAssertTrue(text.hasPrefix("HotspotShade start diagnostics"))
        XCTAssertTrue(text.contains("Time: 2027-"))
        XCTAssertTrue(text.contains("macOS: Version 14.0"))
        XCTAssertTrue(text.contains("App: 1.2.3 (4)"))
        XCTAssertTrue(text.contains("Engine owner: your account"))
        XCTAssertTrue(text.contains("Engine: unavailable"))
        XCTAssertTrue(text.contains("Reason: cleanup_blocked"))
        XCTAssertTrue(text.contains("Recovery: \(failure.recovery)"))
        XCTAssertFalse(text.contains("did not restart"), "A cleanup loss is not a lost helper connection.")
        XCTAssertFalse(text.lowercased().contains("token"))
        XCTAssertFalse(text.lowercased().contains("secret"))
    }

    func testWaitingDiagnosticsSayNoPromptWasRequested() {
        let text = EngineLaunchDiagnostics.text(state: .waiting, appVersion: "1.0", macOSVersion: "14.0")
        XCTAssertTrue(text.contains("Engine: not started"))
        XCTAssertTrue(text.contains("No administrator authorization was requested"))
    }

    func testLostHelperDiagnosticsKeepTheConnectionNote() {
        let failure = EngineLaunchFailure.fromLost(HelperTrustError.helperUnavailable)
        let text = EngineLaunchDiagnostics.text(
            state: .lost(failure),
            appVersion: "1.0",
            macOSVersion: "14.0"
        )
        XCTAssertTrue(text.contains("did not restart"))
    }

    // MARK: - Quit outcome

    func testConfirmedTunnelStopWinsOverAnUnobservedProcessStop() {
        XCTAssertEqual(EngineStopOutcome.combine(tunnel: .stopped, engine: .stopRequested), .stopped)
    }

    // Finding 3: the user engine never owns routes. A dead user engine must not
    // turn a confirmed helper stop into an unproven cleanup.
    func testConfirmedTunnelStopWinsOverAnUncertainUserEngineStop() {
        XCTAssertEqual(
            EngineStopOutcome.combine(
                tunnel: .stopped,
                engine: .uncertain("The user engine did not stop.")
            ),
            .stopped
        )
    }

    func testUncertainTunnelStopAlwaysWins() {
        let uncertain = EngineStopOutcome.uncertain("The engine did not answer.")
        XCTAssertEqual(EngineStopOutcome.combine(tunnel: uncertain, engine: .stopped), uncertain)
        XCTAssertTrue(uncertain.isUncertain)
        XCTAssertEqual(uncertain.message, "The engine did not answer.")
    }

    func testNoTunnelAndARequestedStopIsNotCalledStopped() {
        XCTAssertEqual(EngineStopOutcome.combine(tunnel: .notRunning, engine: .stopRequested), .stopRequested)
    }

    func testPendingLaunchIsNotCalledStopped() {
        XCTAssertEqual(EngineStopOutcome.combine(tunnel: .notRunning, engine: .startPending), .startPending)
        XCTAssertFalse(EngineStopOutcome.startPending.isUncertain)
    }

    // MARK: - Protected stop result

    func testAnOwnedHelperStopIsCleanOnlyWhenTheSessionIsIdle() {
        let session = UUID()
        let ownedClean = HelperStopReply(
            owned: true,
            status: HelperStatus(running: false, cleanupBlocked: false)
        )
        XCTAssertEqual(
            EngineStopOutcome.fromHelperStop(
                reply: ownedClean,
                previous: .disconnected,
                session: session,
                everStarted: true
            ),
            .stopped
        )
        let ownedRunning = HelperStopReply(
            owned: true,
            status: HelperStatus(running: true, cleanupBlocked: false, currentSession: session)
        )
        XCTAssertEqual(
            EngineStopOutcome.fromHelperStop(
                reply: ownedRunning,
                previous: .disconnected,
                session: session,
                everStarted: true
            ),
            .uncertain(EngineLaunchText.stopUnverified)
        )
    }

    // Finding 5: a non-owning connection's successful stop reply is not proof.
    // Only the exact retained session's completed clean record is.
    func testANonOwningHelperStopNeedsTheExactSessionRecord() {
        let session = UUID()
        let other = UUID()
        let live = HelperStopReply(
            owned: false,
            status: HelperStatus(
                running: true,
                cleanupBlocked: false,
                currentSession: other
            )
        )
        XCTAssertEqual(
            EngineStopOutcome.fromHelperStop(
                reply: live,
                previous: .disconnected,
                session: session,
                everStarted: true
            ),
            .uncertain(EngineLaunchText.stopUnverified)
        )
        let stopping = HelperStopReply(
            owned: false,
            status: HelperStatus(running: false, cleanupBlocked: false, stopping: true, currentSession: session)
        )
        XCTAssertEqual(
            EngineStopOutcome.fromHelperStop(
                reply: stopping,
                previous: .disconnected,
                session: session,
                everStarted: true
            ),
            .uncertain(EngineLaunchText.stopUnverified)
        )
        let matched = HelperStopReply(
            owned: false,
            status: HelperStatus(
                running: false,
                cleanupBlocked: false,
                lastSession: session,
                lastResult: .stopped
            )
        )
        XCTAssertEqual(
            EngineStopOutcome.fromHelperStop(
                reply: matched,
                previous: .disconnected,
                session: session,
                everStarted: true
            ),
            .stopped
        )
        let wrongRecord = HelperStopReply(
            owned: false,
            status: HelperStatus(
                running: false,
                cleanupBlocked: false,
                lastSession: other,
                lastResult: .stopped
            )
        )
        XCTAssertEqual(
            EngineStopOutcome.fromHelperStop(
                reply: wrongRecord,
                previous: .disconnected,
                session: session,
                everStarted: true
            ),
            .uncertain(EngineLaunchText.stopUnverified)
        )
    }

    func testAHelperStopWithACleanupBlockOrTimeoutIsUncertain() {
        let session = UUID()
        let blocked = HelperStopReply(
            owned: true,
            status: HelperStatus(running: false, cleanupBlocked: true)
        )
        XCTAssertEqual(
            EngineStopOutcome.fromHelperStop(
                reply: blocked,
                previous: .disconnected,
                session: session,
                everStarted: true
            ),
            .uncertain(Strings.helperCleanup)
        )
        let timedOut = HelperStopReply(
            owned: false,
            status: HelperStatus(
                running: false,
                cleanupBlocked: false,
                lastSession: session,
                lastResult: .timedOut
            )
        )
        XCTAssertEqual(
            EngineStopOutcome.fromHelperStop(
                reply: timedOut,
                previous: .disconnected,
                session: session,
                everStarted: true
            ),
            .uncertain(EngineLaunchText.stopTimedOut)
        )
    }

    // MARK: - Stay recovery

    func testStayKeepsThePreviousCleanupGuidance() {
        let failure = EngineLaunchFailure.fromHelper(HelperTrustError.cleanupBlocked)
        let previous = EngineLaunchState.lost(failure)
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: previous,
            outcome: .uncertain("A generic quit failure.")
        )
        XCTAssertEqual(restored, previous)
        XCTAssertEqual(restored.failure?.diagnosticCode, "cleanup_blocked")
    }

    func testStayKeepsAnEarlierLostHelperMessage() {
        let failure = EngineLaunchFailure.fromLost(HelperTrustError.helperUnavailable)
        let previous = EngineLaunchState.lost(failure)
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: previous,
            outcome: .uncertain(Strings.helperLost)
        )
        XCTAssertEqual(restored, previous)
        XCTAssertEqual(restored.failure?.message, Strings.helperLost)
        XCTAssertEqual(restored.failure?.diagnosticCode, "helper_lost")
    }

    func testStayShowsACleanupBlockFromTheQuitStop() {
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: .running,
            outcome: .uncertain(Strings.helperCleanup)
        )
        XCTAssertEqual(restored.failure?.kind, .cleanup)
        XCTAssertEqual(restored.failure?.message, Strings.helperCleanup)
        XCTAssertEqual(restored.failure?.recovery, EngineLaunchText.cleanupRecovery)
        XCTAssertEqual(restored.failure?.diagnosticCode, "quit_unverified")
    }

    func testStayOnATimeoutKeepsTheTimeoutTextAndDoesNotPromiseAReversibleBlock() {
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: .running,
            outcome: .uncertain(EngineLaunchText.stopTimedOut)
        )
        XCTAssertEqual(restored.failure?.message, EngineLaunchText.stopTimedOut)
        XCTAssertEqual(restored.failure?.recovery, EngineLaunchText.quitRecovery)
        XCTAssertFalse(restored.failure?.recovery.contains("Restart the target device, then try again") ?? true)
    }

    // A quit that cancels a user-engine launch must not leave the launch screen
    // stuck on "Starting" after Stay.
    func testStayAfterACancelledLaunchShowsTheStartScreen() {
        let restored = EngineLaunchState.afterCancelledQuit(
            previous: .starting,
            outcome: .startPending
        )
        XCTAssertEqual(restored, .waiting)
    }

    // MARK: - Lifetime fence

    func testLifetimeFenceRejectsAnOldMonitorAfterQuitOrStay() {
        var fence = EngineLifetimeFence()
        let startToken = fence.beginStart()
        XCTAssertTrue(fence.permits(startToken, stopping: false))
        XCTAssertFalse(fence.permits(startToken, stopping: true))

        fence.beginQuit()
        XCTAssertFalse(fence.permits(startToken, stopping: false))
        XCTAssertEqual(fence.quitGeneration, 1)

        let quitToken = fence.current
        XCTAssertTrue(fence.permits(quitToken, stopping: false))
        XCTAssertFalse(fence.permits(quitToken, stopping: true))
        fence.cancelQuit()
        XCTAssertFalse(fence.permits(quitToken, stopping: false))

        let nextStart = fence.beginStart()
        XCTAssertTrue(fence.permits(nextStart, stopping: false))
        XCTAssertFalse(fence.permits(nextStart, stopping: true))
    }

    // MARK: - Stop/restart serialization

    private final class GateOrder: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [String] = []
        func append(_ value: String) {
            lock.lock(); values.append(value); lock.unlock()
        }
        var events: [String] {
            lock.lock(); defer { lock.unlock() }
            return values
        }
    }

    func testSerialGateMakesAStopWaitForARestart() async {
        let gate = SerialOperationGate()
        let order = GateOrder()
        await gate.acquire()
        let stop = Task {
            await gate.acquire()
            order.append("stop")
            await gate.release()
        }
        try? await Task.sleep(nanoseconds: 30_000_000)
        XCTAssertEqual(order.events, [], "The stop must not run while the restart holds the gate.")
        await gate.release()
        await stop.value
        XCTAssertEqual(order.events, ["stop"])
    }

    // MARK: - Coordinator direction

    func testCoordinatorDirectionGateDoesNotInvertATurnOffOrTurnOn() {
        let on = PreviewData.model(.on)
        XCTAssertTrue(on.permits(.turnOff))
        XCTAssertFalse(on.permits(.turnOn))

        let ready = PreviewData.model(.ready)
        XCTAssertTrue(ready.permits(.turnOn))
        XCTAssertFalse(ready.permits(.turnOff))

        let starting = PreviewData.model(.starting)
        XCTAssertFalse(starting.permits(.turnOn))
        XCTAssertFalse(starting.permits(.turnOff))

        let stopping = PreviewData.model(.turningOff)
        XCTAssertFalse(stopping.permits(.turnOn))
        XCTAssertFalse(stopping.permits(.turnOff))
    }
}
