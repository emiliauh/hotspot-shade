'use strict';

/* Tray Start and Stop actions for the Linux target app.
 *
 * One action runs at a time. A second request is ignored while the first one
 * is pending, so a tray click cannot start a duplicate start or stop. Both a
 * synchronous throw and an asynchronous rejection reset the busy flag exactly
 * once and reach one failure reporter. The module never retries an action.
 *
 * The runner is pure so the Node tests can inject a fake backend, a fake
 * refresh, and fake reporting callbacks.
 */

function createTrayActionRunner(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const backend = typeof settings.backend === 'function'
    ? settings.backend
    : function () { return settings.backend; };
  const startPayload = typeof settings.startPayload === 'function'
    ? settings.startPayload
    : function () { return {}; };
  const refresh = typeof settings.refresh === 'function' ? settings.refresh : null;
  const onFailure = typeof settings.onFailure === 'function' ? settings.onFailure : null;
  const onError = typeof settings.onError === 'function' ? settings.onError : null;

  let busy = false;

  function reportError(error) {
    if (!onError) return;
    try {
      onError(error);
    } catch (ignored) {
      /* Reporting must not escape the runner. */
    }
  }

  function reportFailure(kind, error) {
    if (!onFailure) return;
    try {
      onFailure(kind, error);
    } catch (failureError) {
      reportError(failureError);
    }
  }

  /* The status refresh follows a successful action. A refresh failure is not
   * an action failure, because the tunnel operation itself succeeded. */
  function refreshAfterAction() {
    if (!refresh) return undefined;
    try {
      const result = refresh();
      if (result && typeof result.then === 'function') {
        return Promise.resolve(result).then(undefined, reportError);
      }
      return undefined;
    } catch (error) {
      reportError(error);
      return undefined;
    }
  }

  function settle(kind, action) {
    let settled = false;

    function complete(error) {
      if (settled) return;
      settled = true;
      busy = false;
      if (error !== undefined) reportFailure(kind, error);
    }

    Promise.resolve(action).then(function () {
      return refreshAfterAction();
    }).then(function () {
      complete();
    }, function (error) {
      complete(error);
    }).then(undefined, function (error) {
      /* A late unexpected throw still clears busy exactly once and never
       * becomes an unhandled rejection. */
      complete(error);
      reportError(error);
    });
  }

  /* Return true when the action was attempted, false when it was ignored or
   * failed before it could run. A synchronous backend throw is reported here
   * and never reaches Electron's event loop. */
  function run(kind) {
    if (busy) return false;
    let service;
    try {
      service = backend();
    } catch (error) {
      reportError(error);
      return false;
    }
    if (!service) return false;
    busy = true;
    let action;
    try {
      action = kind === 'stop'
        ? service.stop()
        : service.start(startPayload());
    } catch (error) {
      busy = false;
      reportFailure(kind, error);
      return false;
    }
    settle(kind, action);
    return true;
  }

  return Object.freeze({
    run: run,
    isBusy: function () { return busy; }
  });
}

module.exports = {
  createTrayActionRunner: createTrayActionRunner
};
