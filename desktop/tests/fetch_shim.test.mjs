import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const shim = fs.readFileSync(path.join(here, '..', 'src', 'fetch_shim.js'), 'utf8');

function makeWindow(overrides = {}) {
  const calls = [];
  const originalCalls = [];
  const window = {
    location: {
      href: 'tauri://localhost/index.html',
      protocol: 'tauri:',
      hostname: 'localhost',
      port: '',
      origin: 'null'
    },
    __TAURI_INTERNALS__: {
      invoke: async (command, args) => {
        calls.push({ command, args });
        return { status: 200, body: { ok: true, value: 1 } };
      }
    },
    addEventListener() {},
    fetch: async (...args) => {
      originalCalls.push(args);
      return new Response('original', { status: 200 });
    }
  };
  return { window: Object.assign(window, overrides), calls, originalCalls };
}

function run(window) {
  const context = vm.createContext({
    window,
    Response,
    Request,
    URL,
    DOMException,
    JSON,
    String,
    Promise,
    Error,
    console
  });
  vm.runInContext(shim, context, { filename: 'fetch_shim.js' });
  return window;
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

test('routes same-origin API calls through the demo command', async () => {
  const { window, calls } = makeWindow();
  run(window);
  const response = await window.fetch('/api/status', { method: 'GET' });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true, value: 1 });
  assert.deepEqual(plain(calls), [{
    command: 'demo_api',
    args: { method: 'GET', path: '/api/status', query: '', body: null }
  }]);
});

test('passes the query and a parsed JSON body', async () => {
  const { window, calls } = makeWindow();
  run(window);
  await window.fetch('/api/logs?since=12');
  assert.equal(calls[0].args.query, 'since=12');
  await window.fetch('/api/start', {
    method: 'POST',
    body: JSON.stringify({ mode: 'tun' })
  });
  assert.equal(calls[1].args.method, 'POST');
  assert.deepEqual(plain(calls[1].args.body), { mode: 'tun' });
});

test('does not route a request to another origin', async () => {
  const { window, calls } = makeWindow();
  run(window);
  const response = await window.fetch('https://evil.example/api/status');
  assert.equal(await response.text(), 'original');
  assert.equal(calls.length, 0);
});

test('does not route a same-origin request outside the API prefix', async () => {
  const { window, calls } = makeWindow();
  run(window);
  const response = await window.fetch('/styles.css');
  assert.equal(await response.text(), 'original');
  assert.equal(calls.length, 0);
});

test('rejects an invalid JSON body before the command', async () => {
  const { window, calls } = makeWindow();
  run(window);
  const response = await window.fetch('/api/start', { method: 'POST', body: 'not json' });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).ok, false);
  assert.equal(calls.length, 0);
});

test('rejects an oversized body before the command', async () => {
  const { window, calls } = makeWindow();
  run(window);
  const response = await window.fetch('/api/start', {
    method: 'POST',
    body: 'x'.repeat(1024 * 1024 + 1)
  });
  assert.equal(response.status, 413);
  assert.equal(calls.length, 0);
});

test('returns a fixed error when the demo command fails', async () => {
  const { window } = makeWindow({
    __TAURI_INTERNALS__: {
      invoke: async () => {
        throw new Error('unavailable');
      }
    }
  });
  run(window);
  const response = await window.fetch('/api/status');
  assert.equal(response.status, 503);
  assert.equal((await response.json()).ok, false);
});

test('installs only one fetch wrapper', async () => {
  const { window, calls } = makeWindow();
  run(window);
  const first = window.fetch;
  run(window);
  assert.equal(window.fetch, first);
  await window.fetch('/api/status');
  assert.equal(calls.length, 1);
});

test('rejects a Request object before the command or the original fetch', async () => {
  const { window, calls, originalCalls } = makeWindow();
  run(window);
  const response = await window.fetch(new Request('https://evil.example/api/status'));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).ok, false);
  assert.equal(calls.length, 0);
  assert.equal(originalCalls.length, 0);
});

test('rejects an unsupported input type', async () => {
  const { window, calls, originalCalls } = makeWindow();
  run(window);
  const response = await window.fetch(42);
  assert.equal(response.status, 400);
  assert.equal((await response.json()).ok, false);
  assert.equal(calls.length, 0);
  assert.equal(originalCalls.length, 0);
});

test('accepts a URL object for an API path', async () => {
  const { window, calls } = makeWindow();
  run(window);
  const response = await window.fetch(new URL('/api/status', 'tauri://localhost/index.html'));
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].args.path, '/api/status');
});

test('rejects an oversized query before the command', async () => {
  const { window, calls, originalCalls } = makeWindow();
  run(window);
  const atLimit = 'a'.repeat(4096);
  const accepted = await window.fetch('/api/logs?' + atLimit);
  assert.equal(accepted.status, 200);
  assert.equal(calls[0].args.query.length, 4096);

  const overLimit = 'a'.repeat(4097);
  const rejected = await window.fetch('/api/logs?' + overLimit);
  assert.equal(rejected.status, 414);
  assert.equal((await rejected.json()).ok, false);
  assert.equal(calls.length, 1);
  assert.equal(originalCalls.length, 0);
});

test('rejects an already aborted signal before the command', async () => {
  const { window, calls, originalCalls } = makeWindow();
  run(window);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    window.fetch('/api/status', { signal: controller.signal }),
    (error) => error.name === 'AbortError'
  );
  assert.equal(calls.length, 0);
  assert.equal(originalCalls.length, 0);
});

test('rejects when the signal aborts during the command', async () => {
  const { window, calls } = makeWindow();
  let resolveInvoke;
  window.__TAURI_INTERNALS__ = {
    invoke: (command, args) => {
      calls.push({ command, args });
      return new Promise((resolve) => {
        resolveInvoke = resolve;
      });
    }
  };
  run(window);
  const controller = new AbortController();
  const pending = window.fetch('/api/status', { signal: controller.signal });
  assert.equal(calls.length, 1);
  controller.abort();
  await assert.rejects(pending, (error) => error.name === 'AbortError');
  resolveInvoke({ status: 200, body: { ok: true } });
});
