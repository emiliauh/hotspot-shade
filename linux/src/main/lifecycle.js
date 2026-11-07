'use strict';

/* The quit path for the Linux app.
 *
 * The window close leads to app.quit(). In engine mode the app must stop the
 * engine before it exits. The privileged dispose path closes the helper
 * request pipe and waits; the direct path sends SIGTERM and closes the
 * parent-liveness pipe. Neither sends a
 * forced kill. The app quits after the engine stops, or after the dispose path
 * reports that it cannot stop. The app never restarts the engine.
 *
 * The dispose path returns a structured result:
 *
 *   { stopped: true, timedOut: false }
 *   { stopped: false, timedOut: true, failed: true, reason: '...' }
 *
 * Additional fields describe uncertain cleanup or a known running engine.
 * `neverStarted` is metadata, not a substitute for `stopped: true`.
 *
 * A rejection is a failed stop too. The quit path must not drop either shape,
 * because a failed stop means the engine or the root helper may still hold the
 * tunnel and the helper lock. This module turns the result into one fixed
 * notice for the person. The notice never holds a token, an address, an error
 * message, or an exit code. It never claims that the routes were removed or
 * that the helper lock was released.
 *
 * The person is told before the app quits. The notice is shown through the
 * native dialog in main.js, because this module is pure and the Node tests
 * inject a fake report function. The stop wait itself is bounded inside the
 * backend, so the quit path does not add a second clock or retry loop.
 *
 * This module is pure so the Node tests can call it with a fake app and a fake
 * backend.
 */

const STOP_FAILED_NOTICE = Object.freeze({
  kind: 'stop_failed',
  title: 'HotspotShade',
  message: 'HotspotShade could not confirm that the engine stopped.',
  detail: 'HotspotShade quit anyway. The engine or the privileged helper may still be running and may still hold the tunnel. Check the engine and the routes before you start HotspotShade again.'
});

const STOP_TIMEOUT_NOTICE = Object.freeze({
  kind: 'stop_timeout',
  title: 'HotspotShade',
  message: 'The stop did not finish in time.',
  detail: 'HotspotShade quit anyway. The privileged helper may still be running and may still hold the tunnel. Check the engine and the routes before you start HotspotShade again.'
});

/* The engine exited on a signal or a non-zero code before the app could
 * confirm a clean stop. The process may be gone, but its route cleanup may not
 * have run. */
const CLEANUP_UNCONFIRMED_NOTICE = Object.freeze({
  kind: 'cleanup_unconfirmed',
  title: 'HotspotShade',
  message: 'HotspotShade could not confirm that the engine cleaned up.',
  detail: 'The engine exited before the app could confirm a clean stop. Routes or rules may remain. Check the routes before you start HotspotShade again.'
});

/* The development engine survived the graceful signal and the parent pipe
 * close. The app quit without a forced kill, so the engine may still run. This
 * notice names no privileged helper, because the development path starts the
 * engine directly as the signed-in account. */
const ENGINE_RUNNING_NOTICE = Object.freeze({
  kind: 'engine_running',
  title: 'HotspotShade',
  message: 'The engine is still running.',
  detail: 'The engine did not exit after the graceful stop request. HotspotShade quit without forcing it. End the engine process yourself and check the routes before you start HotspotShade again.'
});

/* The app quit before it saw the helper report that authorization finished.
 * The helper should see the closed request pipe and start no engine, but the
 * app cannot prove that the readiness line was not already on its way. The
 * notice must not claim that no engine or tunnel exists. */
const AUTHORIZATION_UNCONFIRMED_NOTICE = Object.freeze({
  kind: 'authorization_unconfirmed',
  title: 'HotspotShade',
  message: 'HotspotShade quit before it could confirm whether the helper started an engine.',
  detail: 'The privileged helper may still be running and may still hold the tunnel. Dismiss any authorization prompt that is still open, then check the engine and the routes before you start HotspotShade again.'
});

/* Reasons that mean the stop was cut short by a time budget rather than a
 * reported engine or helper error. The reason is used only to pick a fixed
 * notice. It is never shown to the person. */
const TIMEOUT_REASONS = Object.freeze([
  'engine_stop_timeout',
  'helper_exit_timeout'
]);

/* Read one dispose result. Return a notice kind, or an empty string when the
 * result reports a stop that the app can trust.
 *
 * Engine mode needs an explicit clean stop. Demo mode can use an unstructured
 * result because it has no engine or route-owning helper. */
function stopFailureKind(result, requireConfirmation) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    return requireConfirmation ? 'stop_failed' : '';
  }
  const failed = result.failed === true || result.timedOut === true || result.stopped === false;
  const reason = typeof result.reason === 'string' ? result.reason : '';
  if (result.stillRunning === true) return 'engine_running';
  if (result.cleanupUnconfirmed === true || reason === 'engine_cleanup_failed') return 'cleanup_unconfirmed';
  if (!failed) return requireConfirmation && result.stopped !== true ? 'stop_failed' : '';
  if (reason === 'authorization_unconfirmed') return 'authorization_unconfirmed';
  return TIMEOUT_REASONS.indexOf(reason) === -1 ? 'stop_failed' : 'stop_timeout';
}

function noticeFor(kind) {
  if (kind === 'stop_timeout') return STOP_TIMEOUT_NOTICE;
  if (kind === 'cleanup_unconfirmed') return CLEANUP_UNCONFIRMED_NOTICE;
  if (kind === 'engine_running') return ENGINE_RUNNING_NOTICE;
  if (kind === 'authorization_unconfirmed') return AUTHORIZATION_UNCONFIRMED_NOTICE;
  return STOP_FAILED_NOTICE;
}

/* A monitor failure must not prevent the route-owning backend from stopping. */
function disposeBackend(monitor, backend, onMonitorError) {
  try {
    if (monitor) monitor.stop();
  } catch (_) {
    try {
      if (onMonitorError) onMonitorError();
    } catch (_) { /* Reporting must not prevent the backend stop. */ }
  }
  return backend ? backend.dispose() : undefined;
}

function wireLifecycle(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const app = settings.app;
  const backend = settings.backend;
  const engineMode = settings.engineMode;
  const unregister = typeof settings.unregister === 'function' ? settings.unregister : function () {};
  const onError = typeof settings.onError === 'function' ? settings.onError : function () {};
  const report = typeof settings.report === 'function' ? settings.report : null;

  if (!app || typeof app.on !== 'function' || typeof app.quit !== 'function') {
    throw new TypeError('An app with on and quit is required.');
  }

  function engineModeActive() {
    return typeof engineMode === 'function' ? engineMode() === true : engineMode === true;
  }

  let quitStarted = false;
  let quitReady = false;
  let disposeCalls = 0;
  let unregistered = false;
  let reported = false;
  let stopPromise = null;

  /* Show one fixed notice. A report failure must never block the quit, so the
   * call is wrapped and the flag is set before the call. A second failed
   * dispose result, a rejection, or a duplicate will-quit does not show a
   * second notice. */
  function reportStopFailure(kind) {
    if (reported) return;
    reported = true;
    if (!report) return;
    try {
      report(noticeFor(kind));
    } catch (error) {
      /* The quit proceeds even when the notice cannot be shown. */
    }
  }

  function reportInternalError(error) {
    try {
      onError(error);
    } catch (ignored) {
      /* A logging failure must not hide the stop warning or block quit. */
    }
  }

  function runUnregister() {
    if (unregistered) return;
    unregistered = true;
    try {
      unregister();
    } catch (error) {
      /* Quitting must not depend on the unregister hook. */
    }
  }

  /* Call the backend dispose path once. Every later caller gets the same
   * promise, so a duplicate will-quit cannot stop the engine twice or report
   * twice. A synchronous result, an asynchronous result, and a rejection all
   * end in a resolved promise, so the quit always continues.
   *
   * A synchronous failed result is reported here, before will-quit returns,
   * because an Electron will-quit handler cannot wait for a microtask. */
  function dispose() {
    if (stopPromise) return stopPromise;
    disposeCalls += 1;
    let result;
    try {
      result = backend && typeof backend.dispose === 'function' ? backend.dispose() : undefined;
    } catch (error) {
      reportInternalError(error);
      reportStopFailure('stop_failed');
      stopPromise = Promise.resolve();
      return stopPromise;
    }
    if (result && typeof result.then === 'function') {
      stopPromise = Promise.resolve(result).then(function (value) {
        const kind = stopFailureKind(value, engineModeActive());
        if (kind) reportStopFailure(kind);
        return value;
      }, function (error) {
        reportInternalError(error);
        reportStopFailure('stop_failed');
        return undefined;
      });
      return stopPromise;
    }
    const kind = stopFailureKind(result, engineModeActive());
    if (kind) reportStopFailure(kind);
    stopPromise = Promise.resolve(result);
    return stopPromise;
  }

  app.on('before-quit', function (event) {
    if (!engineModeActive() || quitReady) return;
    if (event && typeof event.preventDefault === 'function') event.preventDefault();
    if (quitStarted) return;
    quitStarted = true;
    dispose().then(function () {
      quitReady = true;
      app.quit();
    }, function () {
      /* The dispose promise does not reject. Keep the quit path safe if a
       * future backend change breaks that promise. */
      quitReady = true;
      app.quit();
    });
  });

  app.on('will-quit', function () {
    runUnregister();
    /* In engine mode the stop already ran and reported in before-quit. The
     * memoized promise makes this call free. In demo mode this is the only
     * dispose call. A synchronous failure is reported here while the app is
     * still in the quit event. */
    dispose();
  });

  return Object.freeze({
    disposeCalls: function () { return disposeCalls; },
    quitReady: function () { return quitReady; },
    quitStarted: function () { return quitStarted; },
    reported: function () { return reported; }
  });
}

module.exports = {
  AUTHORIZATION_UNCONFIRMED_NOTICE: AUTHORIZATION_UNCONFIRMED_NOTICE,
  CLEANUP_UNCONFIRMED_NOTICE: CLEANUP_UNCONFIRMED_NOTICE,
  ENGINE_RUNNING_NOTICE: ENGINE_RUNNING_NOTICE,
  STOP_FAILED_NOTICE: STOP_FAILED_NOTICE,
  STOP_TIMEOUT_NOTICE: STOP_TIMEOUT_NOTICE,
  disposeBackend: disposeBackend,
  stopFailureKind: stopFailureKind,
  wireLifecycle: wireLifecycle
};
