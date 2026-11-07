'use strict';

/* The main-process status monitor.
 *
 * It polls the selected backend and keeps the last status for the tray item.
 * It also feeds the pure notification policy. The page keeps its own poll for
 * the visible values. The monitor stops with the app.
 *
 * The monitor never starts or stops the tunnel by itself.
 */

const { createNotificationPolicy, createRateLimiter, sanitize } = require('./notifications');

const DEFAULT_INTERVAL_MS = 2000;
const ENGINE_GONE_AFTER = 3;

function notificationsAllowedForConfig(config) {
  return !!config && config.mode === 'engine' && config.demo !== true;
}

function createStatusMonitor(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const backend = settings.backend;
  const sink = settings.sink;
  const settingsStore = settings.settingsStore;
  const policy = settings.policy && typeof settings.policy.evaluate === 'function'
    ? settings.policy
    : createNotificationPolicy();
  const isFocused = typeof settings.isFocused === 'function' ? settings.isFocused : function () { return false; };
  const onState = typeof settings.onState === 'function' ? settings.onState : null;
  const allowNotifications = settings.allowNotifications === true;
  const intervalMs = Number.isInteger(settings.intervalMs) && settings.intervalMs >= 500
    ? settings.intervalMs
    : DEFAULT_INTERVAL_MS;
  const onError = typeof settings.onError === 'function' ? settings.onError : null;
  const engineGoneLimiter = createRateLimiter({ now: settings.now });

  if (!backend || typeof backend.status !== 'function') throw new TypeError('A backend is required.');
  if (!settingsStore || typeof settingsStore.snapshot !== 'function') throw new TypeError('A settings store is required.');

  let timer = null;
  let activePoll = null;
  let queuedRefresh = null;
  let refreshGeneration = 0;
  let stopped = false;
  let failures = 0;
  let engineGoneNotified = false;
  let state = { status: null, pair: null };

  function reportError(error) {
    if (!onError) return;
    try { onError(error); } catch (_) { /* Reporting must not reject a poll. */ }
  }

  function publish() {
    if (!onState) return;
    try {
      onState(Object.assign({}, state));
    } catch (error) {
      reportError(error);
    }
  }

  function notifyEngineGone() {
    if (!allowNotifications) return;
    const current = settingsStore.snapshot();
    if (current.notifications !== true || !sink || sink.supported !== true ||
        typeof sink.post !== 'function') return;
    if (engineGoneNotified) return;
    engineGoneNotified = true;
    if (engineGoneLimiter.take('engine-gone')) {
      sink.post({
        kind: 'engine-gone',
        title: 'HotspotShade',
        body: 'The engine did not answer. Open HotspotShade to check its status.'
      });
    }
  }

  function evaluateNotifications(status, pair) {
    if (!allowNotifications) return;
    const current = settingsStore.snapshot();
    const output = policy.evaluate({
      enabled: current.notifications === true,
      supported: sink && sink.supported === true,
      isFocused: isFocused() === true,
      status: status,
      pair: pair
    });
    if (!sink || typeof sink.post !== 'function') return;
    for (const message of output.messages) {
      sink.post({
        kind: message.kind,
        title: message.title,
        body: message.body
      });
    }
  }

  async function runPoll(generation) {
    if (stopped) return;
    try {
      let nextStatus = null;
      let nextPair = null;
      try {
        nextStatus = await backend.status();
      } catch (error) {
        /* A stop can happen while the status request is pending. A late
         * rejection must not publish an empty state or send an engine-gone
         * message after the monitor has stopped. */
        if (stopped || generation !== refreshGeneration) return;
        failures += 1;
        if (failures >= ENGINE_GONE_AFTER) {
          state = { status: null, pair: null, unavailable: true };
          publish();
          notifyEngineGone();
        }
        return;
      }
      if (stopped || generation !== refreshGeneration) return;
      try {
        nextPair = await backend.pairState();
      } catch (error) {
        nextPair = state.pair;
      }
      if (stopped || generation !== refreshGeneration) return;
      failures = 0;
      engineGoneNotified = false;
      state = {
        status: nextStatus && typeof nextStatus === 'object' ? nextStatus : {},
        pair: nextPair && typeof nextPair === 'object' ? nextPair : {}
      };
      evaluateNotifications(state.status, state.pair);
      publish();
    } catch (error) {
      reportError(error);
    }
  }

  function poll() {
    if (stopped) return Promise.resolve();
    if (activePoll) return activePoll;
    const current = runPoll(refreshGeneration);
    activePoll = current;
    current.then(function () {
      if (activePoll === current) activePoll = null;
    });
    return current;
  }

  function start() {
    if (timer || stopped) return;
    poll();
    timer = setInterval(function () {
      poll();
    }, intervalMs);
    if (timer && typeof timer.unref === 'function') timer.unref();
  }

  function stop() {
    stopped = true;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  function refreshNow() {
    if (stopped) return Promise.resolve();
    if (!activePoll) return poll();
    // Do not publish a poll started before this refresh request. A request
    // made during the queued poll needs its own subsequent poll as well.
    refreshGeneration += 1;
    if (!queuedRefresh || queuedRefresh.after !== activePoll) {
      const after = activePoll;
      const queued = { after: after, promise: null };
      queued.promise = after.then(function () {
        return poll();
      }).finally(function () {
        if (queuedRefresh === queued) queuedRefresh = null;
      });
      queuedRefresh = queued;
    }
    return queuedRefresh.promise;
  }

  return Object.freeze({
    start: start,
    stop: stop,
    refreshNow: refreshNow,
    getState: function () { return state; }
  });
}

module.exports = {
  DEFAULT_INTERVAL_MS: DEFAULT_INTERVAL_MS,
  ENGINE_GONE_AFTER: ENGINE_GONE_AFTER,
  notificationsAllowedForConfig: notificationsAllowedForConfig,
  createStatusMonitor: createStatusMonitor,
  sanitize: sanitize
};
