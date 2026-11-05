'use strict';

/* The quit path for the Linux app.
 *
 * The window close leads to app.quit(). In engine mode the app must stop the
 * engine before it exits. It calls the backend dispose path, which sends
 * SIGTERM first and waits. The app quits after the engine stops, or after the
 * dispose path reports that it cannot stop. The app never restarts the engine.
 *
 * This module is pure so the Node tests can call it with a fake app and a fake
 * backend.
 */

function wireLifecycle(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const app = settings.app;
  const backend = settings.backend;
  const engineMode = settings.engineMode;
  const unregister = typeof settings.unregister === 'function' ? settings.unregister : function () {};
  const onError = typeof settings.onError === 'function' ? settings.onError : function () {};

  if (!app || typeof app.on !== 'function' || typeof app.quit !== 'function') {
    throw new TypeError('An app with on and quit is required.');
  }

  function engineModeActive() {
    return typeof engineMode === 'function' ? engineMode() === true : engineMode === true;
  }

  let quitStarted = false;
  let quitReady = false;
  let disposeCalls = 0;

  function dispose() {
    disposeCalls += 1;
    try {
      const result = backend && typeof backend.dispose === 'function' ? backend.dispose() : undefined;
      if (result && typeof result.then === 'function') {
        return Promise.resolve(result).catch(function (error) {
          onError(error);
        });
      }
      return Promise.resolve();
    } catch (error) {
      onError(error);
      return Promise.resolve();
    }
  }

  app.on('before-quit', function (event) {
    if (!engineModeActive() || quitReady) return;
    if (event && typeof event.preventDefault === 'function') event.preventDefault();
    if (quitStarted) return;
    quitStarted = true;
    dispose().then(function () {
      quitReady = true;
      app.quit();
    });
  });

  app.on('will-quit', function () {
    unregister();
    dispose();
  });

  return Object.freeze({
    disposeCalls: function () { return disposeCalls; },
    quitReady: function () { return quitReady; },
    quitStarted: function () { return quitStarted; }
  });
}

module.exports = {
  wireLifecycle: wireLifecycle
};
