'use strict';

/* The main-process status monitor.
 *
 * It polls the selected backend and keeps the last status for the tray item.
 * It also feeds the pure notification policy. The page keeps its own poll for
 * the visible values. The monitor stops with the app.
 *
 * The monitor never starts or stops the tunnel by itself.
 */

const { createNotificationPolicy, sanitize } = require('./notifications');

const DEFAULT_INTERVAL_MS = 2000;
const ENGINE_GONE_AFTER = 3;

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

  if (!backend || typeof backend.status !== 'function') throw new TypeError('A backend is required.');
  if (!settingsStore || typeof settingsStore.snapshot !== 'function') throw new TypeError('A settings store is required.');

  let timer = null;
  let inFlight = false;
  let stopped = false;
  let failures = 0;
  let engineGoneNotified = false;
  let state = { status: null, pair: null };

  function publish() {
    if (!onState) return;
    try {
      onState({ status: state.status, pair: state.pair });
    } catch (error) {
      if (onError) onError(error);
    }
  }

  function notifyEngineGone() {
    if (!allowNotifications) return;
    const current = settingsStore.snapshot();
    if (current.notifications !== true || (sink && sink.supported !== true)) return;
    if (engineGoneNotified) return;
    engineGoneNotified = true;
    if (sink && typeof sink.post === 'function') {
      sink.post({
        kind: 'engine-gone',
        title: 'HotspotShade',
        body: 'The engine stopped. Open HotspotShade to start it again.'
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

  async function poll() {
    if (stopped || inFlight) return;
    inFlight = true;
    try {
      let nextStatus = null;
      let nextPair = null;
      try {
        nextStatus = await backend.status();
      } catch (error) {
        failures += 1;
        if (failures >= ENGINE_GONE_AFTER) {
          state = { status: null, pair: null };
          publish();
          notifyEngineGone();
        }
        return;
      }
      failures = 0;
      engineGoneNotified = false;
      try {
        nextPair = await backend.pairState();
      } catch (error) {
        nextPair = state.pair;
      }
      if (stopped) return;
      state = {
        status: nextStatus && typeof nextStatus === 'object' ? nextStatus : {},
        pair: nextPair && typeof nextPair === 'object' ? nextPair : {}
      };
      evaluateNotifications(state.status, state.pair);
      publish();
    } catch (error) {
      if (onError) onError(error);
    } finally {
      inFlight = false;
    }
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
    return poll();
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
  createStatusMonitor: createStatusMonitor,
  sanitize: sanitize
};
