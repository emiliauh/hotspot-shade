'use strict';

/* The packaged Linux backend: one user engine and, while a tunnel needs it,
 * one root engine.
 *
 * At app open the main process runs the bundled engine as the signed-in user.
 * The Dashboard, pairing, forget, status, Activity, diagnostics, and Recent
 * failures use that user engine, so opening the app asks for no administrator
 * authorization.
 *
 * Turn on is the only step that asks. For source device proxy mode the user
 * engine first writes its pairing identity and source device credentials into
 * its private handoff socket. The app then calls pkexec with the helper. The
 * helper passes the socket to the root engine and never reads it. The root
 * engine imports the pairing and starts the tunnel. Direct mode passes no
 * handoff.
 *
 * While a root engine exists it is the status source. A confirmed stop
 * returns the app to the user engine, which still holds the pairing. A stop
 * that is not confirmed keeps the root engine as the status source and marks
 * the status as uncertain, so the page never shows Off for it. A running false
 * answer does not clear that mark; only a helper exit that proves the state
 * does, and every status read looks for that exit. A later Turn off asks the
 * helper client to close its request pipe again and re-read the outcome.
 * Pairing and forget are refused while a
 * root tunnel runs or a stop is unconfirmed. A root engine whose tunnel
 * stopped by itself is stopped through the helper before a new start, a
 * pairing, or a forget.
 *
 * This module holds no credential. The handoff socket passes through as an
 * opaque stream object.
 */

const { BackendError } = require('./errors');

const CLEANUP_MESSAGE = 'The tunnel stop could not be confirmed. The privileged engine may still hold the routes. Inspect the routes, then turn the tunnel off again, or quit and start HotspotShade again.';
const STATUS_READ_ATTEMPTS = 3;
const TIMEOUT_REASONS = Object.freeze(['helper_exit_timeout', 'engine_stop_timeout']);

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/* A stop result from engine-client.js that proves a clean stop, or a launch
 * that proved no engine started. */
function confirmedStop(result) {
  return isPlainObject(result)
    && result.stopped === true
    && result.failed !== true
    && result.timedOut !== true
    && result.cleanupUnconfirmed !== true
    && result.stillRunning !== true;
}

/* What a confirmed root stop returns. It is not read from the user engine. */
const STOP_CONFIRMED = Object.freeze({ source: 'user', running: false, stopped: true });

function cleanupError() {
  return new BackendError('engine_stop_incomplete', CLEANUP_MESSAGE);
}

function cancelledError() {
  return new BackendError('start_cancelled', 'The start was cancelled. Check the current status before trying again.');
}

function handoffError(error) {
  const code = error && typeof error.code === 'string' ? error.code : '';
  const message = error && typeof error.message === 'string' ? error.message : '';
  if (code === 'not_paired' || message === 'not_paired') {
    return new BackendError('not_paired', 'Pair with the source device first.');
  }
  if (code === 'tunnel_running' || message === 'tunnel_running') {
    return new BackendError('tunnel_running', 'Turn off the tunnel first.');
  }
  if (error instanceof BackendError && !/^[a-z_]+$/.test(message)) return error;
  return new BackendError('handoff_failed', 'The app could not pass the pairing to the tunnel engine. Start the app again.');
}

function createSessionBackend(options) {
  const settings = isPlainObject(options) ? options : {};
  const userClient = settings.userClient;
  const createRootClient = settings.createRootClient;
  if (!userClient || typeof userClient.call !== 'function' || typeof userClient.stop !== 'function') {
    throw new TypeError('A user engine client is required.');
  }
  if (typeof createRootClient !== 'function') {
    throw new TypeError('A root engine client factory is required.');
  }

  /* { client, ready, stopping, stopSettled, outcome } for the one root engine
   * session. */
  let root = null;
  /* Set when a root stop was not confirmed. It lives outside the root client,
   * so no later status answer can clear it. Only a confirmed result can. */
  let cleanupPending = false;
  let startFlight = null;
  let stopFlight = null;
  let generation = 0;
  let disposed = false;

  function viaRoot() {
    return !!root && root.ready === true;
  }

  function sourceClient() {
    return viaRoot() ? root.client : userClient;
  }

  function markUncertain(value) {
    return Object.assign({}, isPlainObject(value) ? value : {}, {
      state: 'unknown',
      cleanup_blocked: true,
      error: CLEANUP_MESSAGE
    });
  }

  /* Stop one root session through its engine and its helper. The flight is
   * kept on the session, so a stop, a failed start, and a quit share one
   * result. */
  function stopRoot(entry, options) {
    /* A retry re-attempts a stop whose previous attempt ended without a
     * confirmation. It never replaces an attempt that is still running. */
    const retry = !!options && options.retry === true
      && entry.stopping && entry.stopSettled === true && root === entry && cleanupPending;
    if (entry.stopping && !retry) return entry.stopping;
    entry.stopSettled = false;
    const flight = (async function () {
      if (entry.ready && !retry) {
        try {
          await entry.client.call('stop');
        } catch (error) {
          /* The helper stop below decides whether the stop is confirmed. */
        }
      }
      let result;
      try {
        /* The client caches its first stop result. A retry asks it to close
         * the helper request pipe again and classify the helper's state now. */
        result = retry && typeof entry.client.retryStop === 'function'
          ? await entry.client.retryStop()
          : await entry.client.stop();
      } catch (error) {
        result = { stopped: false, timedOut: false, failed: true, reason: 'helper_stop_failed' };
      }
      const confirmed = confirmedStop(result);
      const outcome = { confirmed: confirmed, result: result };
      entry.outcome = outcome;
      entry.stopSettled = true;
      if (root === entry) {
        if (confirmed) {
          root = null;
          cleanupPending = false;
        } else {
          cleanupPending = true;
        }
      }
      return outcome;
    })();
    entry.stopping = flight;
    return flight;
  }

  /* A stop result is kept, but the helper can exit after it. Classify that
   * later exit once:
   * - exit 0 after a stop timeout: the helper stopped its engine cleanly;
   * - exit 126, 127, or 7 after a stop during the authorization prompt, with
   *   no engine port ever announced and stdout ended normally: pkexec refused
   *   or the helper abandoned the start, so no engine ran.
   * Anything else keeps the mark. */
  async function lateConfirmation() {
    const entry = root;
    if (!entry || !cleanupPending || !entry.stopping) return false;
    await entry.stopping;
    return evaluateLateConfirmation();
  }

  /* The same check with no wait: it reads the helper exit that the client has
   * already recorded. A stop attempt that is still running decides for itself,
   * so the check leaves it alone. Every status read calls this, so a mark from
   * a stop whose helper exited later clears without a user action. */
  function evaluateLateConfirmation() {
    const entry = root;
    if (!entry || !cleanupPending || !entry.stopping) return false;
    if (entry.stopSettled !== true) return false;
    const outcome = entry.outcome;
    if (root !== entry || !cleanupPending) return !cleanupPending;
    const client = entry.client;
    const exit = typeof client.exitInfo === 'function' ? client.exitInfo() : null;
    const reason = outcome && outcome.result ? outcome.result.reason : '';
    if (!exit || exit.signal || exit.error || !Number.isInteger(exit.code)) return false;
    const cleanAfterTimeout = exit.code === 0 && TIMEOUT_REASONS.indexOf(reason) !== -1;
    const neverStarted = reason === 'authorization_unconfirmed'
      && [126, 127, 7].indexOf(exit.code) !== -1
      && client.engineSeen === false
      && client.outputSettled === true;
    if (!cleanAfterTimeout && !neverStarted) return false;
    root = null;
    cleanupPending = false;
    return true;
  }

  /* Pairing and forget run on the user engine. A root engine whose tunnel
   * stopped by itself is stopped first; a live root tunnel refuses them. */
  async function userOnly(blockedCode) {
    if (disposed) throw new BackendError('engine_stopped', 'The engine is stopping.');
    if (startFlight || stopFlight) {
      throw new BackendError(blockedCode, 'Wait for the tunnel to finish starting or stopping.', 409);
    }
    if (cleanupPending && !(await lateConfirmation())) throw cleanupError();
    const entry = root;
    if (!entry) return;
    if (entry.ready) {
      const read = await readRootStatus(entry);
      const status = read.status;
      if (root !== entry) {
        /* A concurrent stop settled this session while the status read ran. */
        if (cleanupPending) throw cleanupError();
        if (!root) return;
        throw new BackendError(blockedCode, 'Wait for the tunnel to finish starting or stopping.', 409);
      }
      if (status && status.running === true) {
        throw new BackendError(blockedCode, 'Turn off the tunnel first.', 409);
      }
      /* A read that failed for another reason than a lost engine does not
       * prove the tunnel is off. Never stop a tunnel that may still run. */
      if (!status && !read.lost) {
        throw new BackendError(blockedCode, 'The tunnel status could not be read. Try again in a moment.', 409);
      }
    }
    const outcome = await stopRoot(entry);
    if (!outcome.confirmed) throw cleanupError();
  }

  /* Read the root engine's status. `lost` is true when the client reports
   * that its engine stopped or is stopping, which is the one failure that
   * proves the root tunnel is not running. Any other failure, such as a
   * timeout, proves nothing. */
  async function readRootStatus(entry) {
    try {
      return { status: await entry.client.call('status'), lost: false };
    } catch (error) {
      return { status: null, lost: !!error && error.code === 'engine_stopped' };
    }
  }

  /* One pairing or forget request in flight. A start waits for none of them;
   * it is refused, so a handoff never carries a pairing that is changing. */
  let userOperations = 0;
  async function withUserOperation(blockedCode, operation) {
    userOperations += 1;
    try {
      await userOnly(blockedCode);
      return await userClient.call(operation);
    } finally {
      userOperations -= 1;
    }
  }

  /* A read that began before the session changed hands answers for the old
   * source: a user engine that says running false after the root tunnel is
   * live, or a root engine that a stop already closed. Stamp each read with
   * the generation and the source, drop a stale answer, and read again. */
  async function status() {
    for (let attempt = 0; attempt < STATUS_READ_ATTEMPTS; attempt += 1) {
      if (cleanupPending) evaluateLateConfirmation();
      const stampGeneration = generation;
      const stampRoot = root;
      const client = sourceClient();
      let value = null;
      let failure = null;
      try {
        value = await client.call('status');
      } catch (error) {
        failure = error;
      }
      if (stampGeneration !== generation || stampRoot !== root || client !== sourceClient()) {
        /* The session changed hands during the read. Drop the answer or the
         * failure, and read again from the current source. */
        continue;
      }
      if (failure) {
        /* A stopped or lost root engine cannot answer, but the mark is still
         * pending. Answer with the uncertain status itself, so the page keeps
         * the "Try to turn off" action instead of showing an engine loss. */
        if (cleanupPending) return markUncertain(null);
        throw failure;
      }
      return cleanupPending ? markUncertain(value) : value;
    }
    throw new BackendError('status_changed', 'The tunnel changed while its status was read. Check again.');
  }

  function start(startOptions) {
    if (disposed) return Promise.reject(new BackendError('engine_stopped', 'The engine is stopping.'));
    if (stopFlight) return Promise.reject(new BackendError('engine_stopping', 'The tunnel is stopping. Try again when it is off.'));
    if (startFlight) return startFlight;
    if (userOperations > 0) {
      return Promise.reject(new BackendError('pairing_busy', 'Wait for pairing or forget to finish, then turn the tunnel on.', 409));
    }
    const mode = isPlainObject(startOptions) && startOptions.mode === 'direct' ? 'direct' : 'phone';
    const params = { mode: mode, ping: mode === 'phone' && isPlainObject(startOptions) && startOptions.ping === true };
    const myGeneration = ++generation;
    const flight = (async function () {
      if (cleanupPending && !(await lateConfirmation())) throw cleanupError();
      const existing = root;
      if (existing) {
        if (existing.ready) {
          const read = await readRootStatus(existing);
          const current = read.status;
          /* A live root tunnel answers its own start, which reports that it
           * already runs. */
          if (current && current.running === true && root === existing && !existing.stopping) {
            return existing.client.call('start', params);
          }
          /* An unreadable status is not proof that the tunnel is off. */
          if (!current && !read.lost && root === existing && !existing.stopping) {
            throw new BackendError('status_unavailable', 'The tunnel status could not be read. Try again in a moment.');
          }
        }
        /* An auto-stopped or lost root engine is stopped through the helper
         * before a new start. */
        const outcome = await stopRoot(existing);
        if (!outcome.confirmed) throw cleanupError();
      }
      if (myGeneration !== generation || disposed) throw cancelledError();
      let handoffStream = null;
      if (mode === 'phone') {
        /* A pairing that is still running would change the credentials after
         * the handoff. Ask the person to wait for it. */
        let pair = null;
        try {
          pair = await userClient.call('pairState');
        } catch (error) {
          pair = null;
        }
        if (pair && ['connecting', 'confirm', 'starting'].indexOf(pair.state) !== -1) {
          throw new BackendError('pairing_busy', 'Wait for pairing or forget to finish, then turn the tunnel on.', 409);
        }
        if (userOperations > 0) {
          throw new BackendError('pairing_busy', 'Wait for pairing or forget to finish, then turn the tunnel on.', 409);
        }
        if (myGeneration !== generation || disposed) throw cancelledError();
        try {
          await userClient.call('handoff');
        } catch (error) {
          throw handoffError(error);
        }
        handoffStream = userClient.handoffStream || null;
        if (!handoffStream) throw handoffError(null);
      }
      if (myGeneration !== generation || disposed) throw cancelledError();
      /* No await between the check above and this assignment, so a stop or a
       * quit always sees the session it must stop. */
      const entry = { client: createRootClient(handoffStream), ready: false, stopping: null };
      root = entry;
      try {
        await entry.client.start();
      } catch (error) {
        await stopRoot(entry);
        throw error;
      }
      if (myGeneration !== generation || disposed || entry.stopping) {
        await stopRoot(entry);
        throw cancelledError();
      }
      entry.ready = true;
      let started;
      try {
        started = await entry.client.call('start', params);
      } catch (error) {
        /* The root engine refused or failed the start. Return to the user
         * engine through a confirmed helper stop. */
        await stopRoot(entry);
        throw error;
      }
      if (myGeneration !== generation || entry.stopping) throw cancelledError();
      return started;
    })();
    startFlight = flight;
    flight.then(clearStart, clearStart);
    function clearStart() {
      if (startFlight === flight) startFlight = null;
    }
    return flight;
  }

  function stop() {
    if (stopFlight) return stopFlight;
    /* A stop cancels every start that began before it. */
    generation += 1;
    const flight = (async function () {
      const entry = root;
      if (entry) {
        if (cleanupPending && await lateConfirmation()) {
          return Object.assign({}, STOP_CONFIRMED);
        }
        /* A later Turn off after an unconfirmed attempt tries again. */
        const outcome = await stopRoot(entry, { retry: cleanupPending });
        if (!outcome.confirmed) throw cleanupError();
        /* The user engine may have died while the root engine ran. A fixed
         * confirmation keeps a confirmed stop from reading as a failed one;
         * the next status poll reports an engine loss on its own. */
        return Object.assign({}, STOP_CONFIRMED);
      }
      return userClient.call('stop');
    })();
    stopFlight = flight;
    flight.then(clearStop, clearStop);
    function clearStop() {
      if (stopFlight === flight) stopFlight = null;
    }
    return flight;
  }

  async function dispose() {
    disposed = true;
    generation += 1;
    let rootOutcome = null;
    if (root && cleanupPending) await lateConfirmation();
    if (root) rootOutcome = await stopRoot(root);
    const userResult = await userClient.stop();
    if (rootOutcome && !rootOutcome.confirmed) return rootOutcome.result;
    return userResult;
  }

  function describeEngine() {
    const user = typeof userClient.describe === 'function' ? userClient.describe() : {};
    const elevated = viaRoot() && typeof root.client.describe === 'function' ? root.client.describe() : null;
    return {
      connected: elevated ? elevated.connected === true : user.connected === true,
      transport: elevated ? elevated.transport : (user.transport || 'not_connected'),
      tunnel: 'engine_service',
      privileged: !!elevated,
      operations: Array.isArray(user.operations) ? user.operations : []
    };
  }

  return Object.freeze({
    mode: 'engine',
    status: status,
    pairState: function () { return sourceClient().call('pairState'); },
    beginPairing: function () { return withUserOperation('tunnel_running', 'pair'); },
    /* Cancel is harmless and always reaches the engine that runs pairing. */
    cancelPairing: function () { return userClient.call('pairCancel'); },
    forget: function () { return withUserOperation('forget_blocked', 'forget'); },
    start: start,
    stop: stop,
    probe: function () { return sourceClient().call('probe'); },
    activity: function (query) {
      const since = isPlainObject(query) && Number.isInteger(query.since) ? query.since : 0;
      return sourceClient().call('activity', { since: since });
    },
    failures: function () { return sourceClient().call('failures'); },
    diagnostics: function () { return sourceClient().call('diagnostics'); },
    applyScenario: function () {
      throw new BackendError('demo_only', 'The demo scenario is not available.');
    },
    describeEngine: describeEngine,
    describe: describeEngine,
    dispose: dispose,
    /* Main-process test and lifecycle view. It holds no credential. */
    session: function () {
      return { elevated: !!root, ready: viaRoot(), cleanupPending: cleanupPending, starting: !!startFlight, stopping: !!stopFlight };
    }
  });
}

module.exports = {
  CLEANUP_MESSAGE: CLEANUP_MESSAGE,
  confirmedStop: confirmedStop,
  createSessionBackend: createSessionBackend
};
