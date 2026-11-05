'use strict';

/* The engine backend for the Linux target app.
 *
 * This is the same backend shape as the in-memory demo backend. Each method
 * maps to one fixed operation in engine-client.js. The page cannot name a
 * path, URL, host, command, or request body.
 *
 * The engine holds the pairing token and the tunnel state. This module holds
 * no credential. It returns status values only.
 */

const { BackendError } = require('./errors');

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function createEngineBackend(options) {
  const settings = isPlainObject(options) ? options : {};
  const client = settings.client;
  if (!client || typeof client.call !== 'function') {
    throw new TypeError('An engine client is required.');
  }

  function call(operation, params) {
    return client.call(operation, params);
  }

  return Object.freeze({
    mode: 'engine',
    status: function () { return call('status'); },
    pairState: function () { return call('pairState'); },
    beginPairing: function () { return call('pair'); },
    cancelPairing: function () { return call('pairCancel'); },
    forget: function () { return call('forget'); },
    start: function (options) {
      return call('start', { ping: isPlainObject(options) && options.ping === true });
    },
    stop: function () { return call('stop'); },
    probe: function () { return call('probe'); },
    activity: function (query) {
      const since = isPlainObject(query) && Number.isInteger(query.since) ? query.since : 0;
      return call('activity', { since: since });
    },
    failures: function () { return call('failures'); },
    diagnostics: function () { return call('diagnostics'); },
    applyScenario: function () {
      throw new BackendError('demo_only', 'The demo scenario is not available.');
    },
    describeEngine: function () {
      return typeof client.describe === 'function'
        ? client.describe()
        : { connected: false, transport: 'not_connected', tunnel: 'engine_service', operations: [] };
    },
    dispose: function () {
      return typeof client.stop === 'function' ? client.stop() : undefined;
    }
  });
}

/* A configured engine that cannot start. Every call reports the same plain
 * error. The app opens normally, so the person can read the error and fix the
 * setting. */
function createUnavailableEngineBackend(message) {
  const text = typeof message === 'string' && message ? message : 'The engine is not available.';
  function fail() {
    return Promise.reject(new BackendError('engine_config', text));
  }
  return Object.freeze({
    mode: 'engine',
    status: fail,
    pairState: fail,
    beginPairing: fail,
    cancelPairing: fail,
    forget: fail,
    start: fail,
    stop: fail,
    probe: fail,
    activity: fail,
    failures: fail,
    diagnostics: fail,
    applyScenario: function () {
      throw new BackendError('demo_only', 'The demo scenario is not available.');
    },
    describeEngine: function () {
      return { connected: false, transport: 'not_connected', tunnel: 'engine_service', operations: [] };
    },
    dispose: function () {}
  });
}

module.exports = {
  createEngineBackend: createEngineBackend,
  createUnavailableEngineBackend: createUnavailableEngineBackend
};
