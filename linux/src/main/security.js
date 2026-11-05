'use strict';

/* Security policy for the Electron shell.
 *
 * The renderer is local, sandboxed, and isolated. It has no Node.js access, no
 * network access, no navigation, no new window, no download, and no permission.
 * The page talks to the main process through the fixed preload allowlist only.
 * These values are shared by the app and the hermetic policy tests.
 */

const path = require('node:path');

const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "child-src 'none'",
  "worker-src 'none'",
  "base-uri 'none'",
  "form-action 'none'"
].join('; ');

const SAFE_WEB_PREFERENCES = Object.freeze({
  contextIsolation: true,
  sandbox: true,
  nodeIntegration: false,
  nodeIntegrationInWorker: false,
  nodeIntegrationInSubFrames: false,
  webSecurity: true,
  allowRunningInsecureContent: false,
  experimentalFeatures: false,
  plugins: false,
  webviewTag: false,
  spellcheck: false,
  enableWebSQL: false,
  navigateOnDragDrop: false,
  safeDialogs: true,
  devTools: false,
  backgroundThrottling: true
});

const ALLOWED_EXTENSIONS = Object.freeze(['.html', '.css', '.js', '.svg', '.png', '.webmanifest']);

const guardedSessions = new WeakSet();

function isPathInside(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (relative.length > 0 && !relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}

function isAllowedAppUrl(rawUrl, rendererRoot) {
  try {
    if (typeof rawUrl !== 'string' || !rawUrl) return false;
    const url = new URL(rawUrl);
    if (url.protocol !== 'file:') return false;
    if (url.host && url.host !== 'localhost') return false;
    if (url.search) return false;

    let pathname = url.pathname;
    if (process.platform === 'win32' && /^\/[A-Za-z]:/.test(pathname)) pathname = pathname.slice(1);
    const decoded = decodeURIComponent(pathname);
    if (!decoded) return false;
    const target = path.resolve(decoded);
    if (!isPathInside(rendererRoot, target)) return false;
    const extension = path.extname(target).toLowerCase();
    return ALLOWED_EXTENSIONS.includes(extension);
  } catch (error) {
    return false;
  }
}

function samePageUrl(candidate, expected) {
  try {
    const left = new URL(candidate);
    const right = new URL(expected);
    if (left.protocol !== 'file:' || right.protocol !== 'file:') return false;
    left.hash = '';
    right.hash = '';
    return left.href === right.href;
  } catch (error) {
    return false;
  }
}

function applySessionPolicy(session, options) {
  const settings = options && typeof options === 'object' ? options : {};
  const rendererRoot = settings.rendererRoot;
  const onDeniedRequest = typeof settings.onDeniedRequest === 'function' ? settings.onDeniedRequest : null;
  const onInternalError = typeof settings.onInternalError === 'function' ? settings.onInternalError : null;

  if (!session || typeof session !== 'object') throw new TypeError('A session is required.');
  if (typeof rendererRoot !== 'string' || !rendererRoot) throw new TypeError('A renderer root is required.');
  if (guardedSessions.has(session)) return;
  guardedSessions.add(session);

  function denyRequest(url) {
    if (onDeniedRequest) onDeniedRequest(url);
  }

  if (session.webRequest && typeof session.webRequest.onBeforeRequest === 'function') {
    session.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, function (details, callback) {
      if (isAllowedAppUrl(details.url, rendererRoot)) {
        callback({});
        return;
      }
      denyRequest(details.url);
      callback({ cancel: true });
    });
  }

  if (session.webRequest && typeof session.webRequest.onHeadersReceived === 'function') {
    session.webRequest.onHeadersReceived({ urls: ['<all_urls>'] }, function (details, callback) {
      const headers = Object.assign({}, details.responseHeaders || {});
      // File responses can have no MIME header. nosniff then rejects CSS and
      // scripts. Give each permitted local asset its fixed media type.
      const types = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'text/javascript; charset=utf-8',
        '.svg': 'image/svg+xml',
        '.png': 'image/png',
        '.webmanifest': 'application/manifest+json'
      };
      if (isAllowedAppUrl(details.url, rendererRoot)) {
        const extension = path.extname(decodeURIComponent(new URL(details.url).pathname)).toLowerCase();
        for (const key of Object.keys(headers)) {
          if (key.toLowerCase() === 'content-type') delete headers[key];
        }
        headers['Content-Type'] = [types[extension]];
      }
      headers['Content-Security-Policy'] = [CONTENT_SECURITY_POLICY];
      headers['X-Content-Type-Options'] = ['nosniff'];
      headers['Referrer-Policy'] = ['no-referrer'];
      callback({
        responseHeaders: headers
      });
    });
  }

  if (typeof session.setPermissionRequestHandler === 'function') {
    session.setPermissionRequestHandler(function (_webContents, _permission, callback) {
      callback(false);
    });
  }

  if (typeof session.setPermissionCheckHandler === 'function') {
    session.setPermissionCheckHandler(function () {
      return false;
    });
  }

  if (typeof session.setDevicePermissionHandler === 'function') {
    session.setDevicePermissionHandler(function () {
      return false;
    });
  }

  if (typeof session.setDisplayMediaRequestHandler === 'function') {
    session.setDisplayMediaRequestHandler(function (_request, callback) {
      callback({});
    });
  }

  if (typeof session.setSpellCheckerEnabled === 'function') {
    session.setSpellCheckerEnabled(false);
  }

  session.on('will-download', function (event, item) {
    if (event && typeof event.preventDefault === 'function') event.preventDefault();
    if (item && typeof item.cancel === 'function') item.cancel();
  });

  if (onInternalError) {
    session.on('unhandled-rejection', function (error) {
      onInternalError(error);
    });
  }
}

function hardenWebContents(contents, options) {
  const settings = options && typeof options === 'object' ? options : {};
  const indexUrl = settings.indexUrl;
  const onBlockedNavigation = typeof settings.onBlockedNavigation === 'function' ? settings.onBlockedNavigation : null;

  if (!contents || typeof contents !== 'object') throw new TypeError('Web contents are required.');
  if (typeof indexUrl !== 'string' || !indexUrl) throw new TypeError('The index URL is required.');

  contents.setWindowOpenHandler(function () {
    return { action: 'deny' };
  });

  contents.on('will-navigate', function (event, url) {
    if (!samePageUrl(url, indexUrl)) {
      if (onBlockedNavigation) onBlockedNavigation();
      event.preventDefault();
    }
  });

  contents.on('will-redirect', function (event) {
    if (onBlockedNavigation) onBlockedNavigation();
    event.preventDefault();
  });

  contents.on('will-attach-webview', function (event) {
    if (onBlockedNavigation) onBlockedNavigation();
    event.preventDefault();
  });
}

module.exports = {
  ALLOWED_EXTENSIONS: ALLOWED_EXTENSIONS,
  CONTENT_SECURITY_POLICY: CONTENT_SECURITY_POLICY,
  SAFE_WEB_PREFERENCES: SAFE_WEB_PREFERENCES,
  applySessionPolicy: applySessionPolicy,
  hardenWebContents: hardenWebContents,
  isAllowedAppUrl: isAllowedAppUrl,
  isPathInside: isPathInside,
  samePageUrl: samePageUrl
};
