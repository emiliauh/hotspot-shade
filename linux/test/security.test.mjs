import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const security = require('../src/main/security.js');

const root = path.join(os.tmpdir(), 'hotspotshade-linux-renderer');
const indexUrl = pathToFileURL(path.join(root, 'index.html')).href;

function fakeSession() {
  const handlers = {};
  return {
    handlers,
    webRequest: {
      onBeforeRequest(filter, listener) { handlers.request = { filter, listener }; },
      onHeadersReceived(filter, listener) { handlers.headers = { filter, listener }; }
    },
    setPermissionRequestHandler(handler) { handlers.permissionRequest = handler; },
    setPermissionCheckHandler(handler) { handlers.permissionCheck = handler; },
    setDevicePermissionHandler(handler) { handlers.devicePermission = handler; },
    setDisplayMediaRequestHandler(handler) { handlers.displayMedia = handler; },
    setSpellCheckerEnabled(value) { handlers.spellcheck = value; },
    on(event, handler) { handlers[event] = handler; }
  };
}

test('the renderer preferences keep isolation, sandbox, and no Node.js', () => {
  const prefs = security.SAFE_WEB_PREFERENCES;
  assert.equal(prefs.contextIsolation, true);
  assert.equal(prefs.sandbox, true);
  assert.equal(prefs.nodeIntegration, false);
  assert.equal(prefs.nodeIntegrationInWorker, false);
  assert.equal(prefs.nodeIntegrationInSubFrames, false);
  assert.equal(prefs.webSecurity, true);
  assert.equal(prefs.allowRunningInsecureContent, false);
  assert.equal(prefs.webviewTag, false);
  assert.equal(prefs.devTools, false);
  assert.equal(prefs.navigateOnDragDrop, false);
  assert.equal(prefs.spellcheck, false);
  assert.equal(Object.isFrozen(prefs), true);
});

test('the content security policy is local and strict', () => {
  const policy = security.CONTENT_SECURITY_POLICY;
  assert.match(policy, /default-src 'none'/);
  assert.match(policy, /script-src 'self'/);
  assert.match(policy, /style-src 'self'/);
  assert.match(policy, /connect-src 'none'/);
  assert.match(policy, /object-src 'none'/);
  assert.match(policy, /frame-src 'none'/);
  assert.match(policy, /base-uri 'none'/);
  assert.match(policy, /form-action 'none'/);
  assert.doesNotMatch(policy, /unsafe-inline/);
  assert.doesNotMatch(policy, /unsafe-eval/);
  assert.doesNotMatch(policy, /https?:/);
});

test('only renderer files inside the app root are allowed', () => {
  assert.equal(security.isAllowedAppUrl(indexUrl, root), true);
  assert.equal(security.isAllowedAppUrl(pathToFileURL(path.join(root, 'styles.css')).href, root), true);
  assert.equal(security.isAllowedAppUrl(pathToFileURL(path.join(root, 'model.js')).href, root), true);
  assert.equal(security.isAllowedAppUrl(pathToFileURL(path.join(root, 'favicon.svg')).href, root), true);

  assert.equal(security.isAllowedAppUrl('https://example.com/', root), false);
  assert.equal(security.isAllowedAppUrl('http://127.0.0.1:8787/', root), false);
  assert.equal(security.isAllowedAppUrl('ws://example.com/', root), false);
  assert.equal(security.isAllowedAppUrl('data:text/html,hi', root), false);
  assert.equal(security.isAllowedAppUrl('file://evil-host/index.html', root), false);
  assert.equal(security.isAllowedAppUrl(pathToFileURL(path.join(root, 'notes.txt')).href, root), false);
  assert.equal(security.isAllowedAppUrl(pathToFileURL(path.join(root, 'index.html')).href + '?x=1', root), false);
  assert.equal(security.isAllowedAppUrl(pathToFileURL(path.join(root, '..', 'secret.html')).href, root), false);
  assert.equal(security.isAllowedAppUrl(pathToFileURL(path.join(root, '..', '..', 'etc', 'passwd')).href, root), false);
  assert.equal(security.isAllowedAppUrl('', root), false);
  assert.equal(security.isAllowedAppUrl('not a url', root), false);
});

test('the session denies requests, permissions, and downloads', () => {
  const session = fakeSession();
  let denied = 0;
  security.applySessionPolicy(session, {
    rendererRoot: root,
    onDeniedRequest() { denied += 1; }
  });

  assert.equal(session.handlers.spellcheck, false);
  assert.ok(session.handlers.request);
  assert.deepEqual(session.handlers.request.filter, { urls: ['<all_urls>'] });

  let response = null;
  session.handlers.request.listener({ url: indexUrl }, (value) => { response = value; });
  assert.deepEqual(response, {});
  assert.equal(denied, 0);

  response = null;
  session.handlers.request.listener({ url: 'https://example.com/' }, (value) => { response = value; });
  assert.deepEqual(response, { cancel: true });
  assert.equal(denied, 1);

  response = null;
  session.handlers.request.listener({ url: 'file:///etc/passwd' }, (value) => { response = value; });
  assert.deepEqual(response, { cancel: true });
  assert.equal(denied, 2);

  let headers = null;
  session.handlers.headers.listener({ url: indexUrl, responseHeaders: {} }, (value) => { headers = value; });
  assert.match(headers.responseHeaders['Content-Security-Policy'][0], /default-src 'none'/);
  assert.deepEqual(headers.responseHeaders['X-Content-Type-Options'], ['nosniff']);
  assert.deepEqual(headers.responseHeaders['Referrer-Policy'], ['no-referrer']);

  const stylesheetUrl = pathToFileURL(path.join(root, 'styles.css')).href;
  session.handlers.headers.listener({
    url: stylesheetUrl,
    responseHeaders: { 'content-type': ['application/octet-stream'], 'X-Existing': ['kept'] }
  }, (value) => { headers = value; });
  assert.deepEqual(headers.responseHeaders['Content-Type'], ['text/css; charset=utf-8']);
  assert.equal(headers.responseHeaders['content-type'], undefined);
  assert.deepEqual(headers.responseHeaders['X-Existing'], ['kept']);
  assert.deepEqual(headers.responseHeaders['X-Content-Type-Options'], ['nosniff']);

  let permission = null;
  session.handlers.permissionRequest(null, 'camera', (value) => { permission = value; });
  assert.equal(permission, false);
  assert.equal(session.handlers.permissionCheck(), false);
  assert.equal(session.handlers.devicePermission(), false);

  let display = null;
  session.handlers.displayMedia(null, (value) => { display = value; });
  assert.deepEqual(display, {});

  let prevented = false;
  let cancelled = false;
  session.handlers['will-download']({ preventDefault() { prevented = true; } }, { cancel() { cancelled = true; } });
  assert.equal(prevented, true);
  assert.equal(cancelled, true);
});

test('the session policy installs one handler set per session', () => {
  const session = fakeSession();
  security.applySessionPolicy(session, { rendererRoot: root });
  const first = session.handlers.request;
  security.applySessionPolicy(session, { rendererRoot: root });
  assert.equal(session.handlers.request, first);
});

test('web contents deny windows, redirects, webviews, and external navigation', () => {
  const listeners = {};
  let windowHandler = null;
  const contents = {
    setWindowOpenHandler(handler) { windowHandler = handler; },
    on(event, handler) { listeners[event] = handler; }
  };
  security.hardenWebContents(contents, { indexUrl });

  assert.deepEqual(windowHandler(), { action: 'deny' });

  let prevented = false;
  listeners['will-navigate']({ preventDefault() { prevented = true; } }, 'https://example.com/');
  assert.equal(prevented, true);

  prevented = false;
  listeners['will-navigate']({ preventDefault() { prevented = true; } }, indexUrl + '#activity');
  assert.equal(prevented, false);

  prevented = false;
  listeners['will-navigate']({ preventDefault() { prevented = true; } }, indexUrl + '?x=1');
  assert.equal(prevented, true);

  prevented = false;
  listeners['will-redirect']({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);

  prevented = false;
  listeners['will-attach-webview']({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
});

test('same-page checks use the exact file, not only the scheme', () => {
  assert.equal(security.samePageUrl(indexUrl + '#settings', indexUrl), true);
  assert.equal(security.samePageUrl(indexUrl, indexUrl), true);
  assert.equal(security.samePageUrl(indexUrl.replace('index.html', 'other.html'), indexUrl), false);
  assert.equal(security.samePageUrl('https://example.com/', indexUrl), false);
  assert.equal(security.samePageUrl('nope', indexUrl), false);
});
