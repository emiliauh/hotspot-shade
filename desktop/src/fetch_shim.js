// Route the desktop page's same-origin /api/ requests to the narrow Tauri demo
// command. The page and its assets load from the embedded origin. No network
// request is made for an API call.
(function () {
  'use strict';

  var API_PREFIX = '/api/';
  var MAX_BODY = 1024 * 1024;
  var MAX_QUERY = 4096;

  function reply(status, body) {
    return new Response(JSON.stringify(body), {
      status: status,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store'
      }
    });
  }

  function abortError() {
    var message = 'The request was aborted.';
    if (typeof DOMException === 'function') {
      return new DOMException(message, 'AbortError');
    }
    var error = new Error(message);
    error.name = 'AbortError';
    return error;
  }

  function abortReason(signal) {
    if (signal && signal.reason !== undefined) {
      return signal.reason;
    }
    return abortError();
  }

  function sameAppOrigin(url) {
    var location = window.location;
    return url.protocol === location.protocol &&
      url.hostname === location.hostname &&
      url.port === location.port &&
      url.username === '' &&
      url.password === '';
  }

  function isRequest(input) {
    return typeof Request === 'function' && input instanceof Request;
  }

  function inputUrl(input) {
    if (typeof input === 'string') {
      return input;
    }
    if (typeof URL === 'function' && input instanceof URL) {
      return input.href;
    }
    return null;
  }

  function install() {
    var internals = window.__TAURI_INTERNALS__;
    if (!internals || typeof internals.invoke !== 'function') {
      return false;
    }
    if (window.__hotspotshadeBridgeInstalled) {
      return true;
    }
    window.__hotspotshadeBridgeInstalled = true;

    var originalFetch = window.fetch;
    window.fetch = function (input, init) {
      init = init || {};
      if (isRequest(input)) {
        // The shim does not read a Request body, method, or signal. Reject the
        // object before it can reach the original fetch function.
        return Promise.resolve(reply(400, {
          ok: false,
          error: 'Request objects are not supported. Pass a URL string and an init object.'
        }));
      }
      var raw = inputUrl(input);
      if (raw === null) {
        return Promise.resolve(reply(400, {
          ok: false,
          error: 'The fetch input must be a URL string or a URL object.'
        }));
      }
      var url;
      try {
        url = new URL(raw, window.location.href);
      } catch (error) {
        return originalFetch.apply(window, arguments);
      }
      if (!sameAppOrigin(url) || url.pathname.indexOf(API_PREFIX) !== 0) {
        return originalFetch.apply(window, arguments);
      }

      var query = url.search ? url.search.slice(1) : '';
      if (query.length > MAX_QUERY) {
        return Promise.resolve(reply(414, {
          ok: false,
          error: 'The request query is too large.'
        }));
      }

      var signal = init.signal;
      if (signal && signal.aborted) {
        return Promise.reject(abortReason(signal));
      }

      var method = String(init.method || 'GET').toUpperCase();
      var body = null;
      if (init.body !== undefined && init.body !== null) {
        if (typeof init.body !== 'string') {
          return Promise.resolve(reply(400, {
            ok: false,
            error: 'The request body must be JSON text.'
          }));
        }
        if (init.body.length > MAX_BODY) {
          return Promise.resolve(reply(413, {
            ok: false,
            error: 'The request body is too large.'
          }));
        }
        try {
          body = JSON.parse(init.body);
        } catch (error) {
          return Promise.resolve(reply(400, {
            ok: false,
            error: 'The request body must be valid JSON.'
          }));
        }
      }

      return new Promise(function (resolve, reject) {
        var settled = false;
        function finish(callback, value) {
          if (settled) {
            return;
          }
          settled = true;
          if (signal && typeof signal.removeEventListener === 'function') {
            signal.removeEventListener('abort', onAbort);
          }
          callback(value);
        }
        function onAbort() {
          finish(reject, abortReason(signal));
        }
        if (signal && typeof signal.addEventListener === 'function') {
          signal.addEventListener('abort', onAbort, { once: true });
          if (signal.aborted) {
            onAbort();
            return;
          }
        }
        try {
          internals.invoke('demo_api', {
            method: method,
            path: url.pathname,
            query: query,
            body: body
          }).then(function (result) {
            finish(resolve, reply(result.status, result.body));
          }, function () {
            finish(resolve, reply(503, {
              ok: false,
              error: 'The local demo service is unavailable.'
            }));
          });
        } catch (error) {
          finish(resolve, reply(503, {
            ok: false,
            error: 'The local demo service is unavailable.'
          }));
        }
      });
    };
    return true;
  }

  if (!install()) {
    // Tauri normally injects the IPC before page scripts. If it is late,
    // install before the page handles DOMContentLoaded.
    window.addEventListener('DOMContentLoaded', install, { once: true });
  }
})();
