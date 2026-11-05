'use strict';

/* The protected engine boundary for the Linux target app.
 *
 * The transport is `engine-client.js`. It starts the binary named by an
 * explicit setting or by HOTSPOTSHADE_ENGINE, passes a per-launch bearer secret
 * on descriptor 3, and keeps the parent-liveness descriptor 4 open. It calls
 * only the fixed operation list in that module. The app uses the in-memory
 * demo backend when no engine is configured.
 *
 * The boundary keeps these properties:
 *
 * 1. The parent passes a per-launch bearer secret on a descriptor. The secret
 *    never appears on a command line, in the environment, in a log, or in the
 *    renderer.
 * 2. The parent keeps a liveness descriptor open. The engine shuts down when
 *    the descriptor closes.
 * 3. The parent may call only the fixed operation list in engine-client.js. It
 *    sends no generic path, URL, shell command, or arbitrary request.
 * 4. The secret stays in the main process. The preload and the page receive
 *    status values only.
 * 5. Stop is idempotent. The engine removes every route, address, and device
 *    that it created on every exit path.
 * 6. The app never starts an untrusted binary, a privileged helper, or an
 *    auto-restart loop.
 *
 * This module holds the disconnected boundary that the demo backend reports in
 * the bootstrap answer. `engine-client.js` holds the connected transport.
 */

const BOUNDARY_OPERATIONS = Object.freeze([
  'status',
  'pair.state',
  'pair.begin',
  'pair.cancel',
  'pair.forget',
  'tunnel.start',
  'tunnel.stop',
  'phone.probe',
  'activity',
  'failures',
  'diagnostics'
]);

class EngineUnavailableError extends Error {
  constructor(message) {
    super(message || 'The protected engine is not connected for this backend.');
    this.name = 'EngineUnavailableError';
    this.code = 'engine_unavailable';
  }
}

function createEngineBoundary() {
  let disposed = false;

  return Object.freeze({
    connected: false,
    describe: function () {
      return {
        connected: false,
        transport: 'not_connected',
        tunnel: 'not_implemented',
        operations: BOUNDARY_OPERATIONS.slice()
      };
    },
    call: async function (operation) {
      if (!BOUNDARY_OPERATIONS.includes(operation)) {
        throw new EngineUnavailableError('The engine operation is not known.');
      }
      if (disposed) {
        throw new EngineUnavailableError('The protected engine boundary is closed.');
      }
      // There is no transport here. The connected transport is separate and
      // has its own tests.
      throw new EngineUnavailableError();
    },
    dispose: function () {
      disposed = true;
    }
  });
}

/* The same backend shape as the demo backend, backed by a boundary. This
 * adapter stays for the disconnected boundary tests. The connected transport
 * uses `createEngineBackend` in engine-backend.js. */
function createEngineBoundaryBackend(boundary) {
  if (!boundary || typeof boundary.call !== 'function') {
    throw new TypeError('A boundary is required.');
  }
  function call(operation, params) {
    return boundary.call(operation, params);
  }
  return Object.freeze({
    mode: 'engine',
    status: function () { return call('status'); },
    pairState: function () { return call('pair.state'); },
    beginPairing: function () { return call('pair.begin'); },
    cancelPairing: function () { return call('pair.cancel'); },
    forget: function () { return call('pair.forget'); },
    start: function (options) { return call('tunnel.start', { ping: options && options.ping === true }); },
    stop: function () { return call('tunnel.stop'); },
    probe: function () { return call('phone.probe'); },
    activity: function (query) { return call('activity', { since: query && query.since }); },
    failures: function () { return call('failures'); },
    diagnostics: function () { return call('diagnostics'); },
    applyScenario: function () { throw new EngineUnavailableError('The demo scenario is not available.'); },
    dispose: function () { boundary.dispose(); }
  });
}

module.exports = {
  BOUNDARY_OPERATIONS: BOUNDARY_OPERATIONS,
  EngineUnavailableError: EngineUnavailableError,
  createEngineBoundary: createEngineBoundary,
  createEngineBoundaryBackend: createEngineBoundaryBackend
};
