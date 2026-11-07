import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createEngineHttpClient } = require('../src/backend/engine-client.js');
const secret = 'ab'.repeat(32); // Public test value; never an actual credential.
const binary = process.env.HS_REAL_ENGINE_BIN || '';
const confined = process.env.HS_TEST_NETWORK_CONFINED === '1';
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test('the Linux client reads a real unprivileged engine and parent loss stops it', {
  skip: !confined || !binary ? 'Requires an isolated network and HS_REAL_ENGINE_BIN.' : false,
  timeout: 25000
}, async () => {
  assert.equal(process.platform, 'linux');
  assert.equal(path.isAbsolute(binary), true);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-real-engine-'));
  fs.chmodSync(directory, 0o700);
  const portFile = path.join(directory, 'port');
  const child = spawn(binary, [
    'gui', '--no-open', '--port', '0', '--port-file', portFile,
    '--token-fd', '3', '--parent-fd', '4'
  ], {
    cwd: directory,
    env: { HOME: directory, TMPDIR: directory, PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' },
    stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe']
  });
  const exited = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }));
    child.once('error', (error) => resolve({ error }));
  });
  try {
    // A failed launch can close the private input before the key is written.
    // The startup assertion below reports that failure without an unhandled EPIPE.
    child.stdio[3].on('error', () => {});
    child.stdio[4].on('error', () => {});
    child.stdio[3].end(secret + '\n');
    let port = 0;
    const deadline = Date.now() + 10000;
    while (!port && Date.now() < deadline && child.exitCode === null) {
      try { port = Number(fs.readFileSync(portFile, 'utf8').trim()); } catch { /* not ready */ }
      if (!port) await delay(50);
    }
    assert.ok(Number.isInteger(port) && port > 0 && port <= 65535, 'engine did not become ready');
    const client = createEngineHttpClient({ port, secret });
    const status = await client.call('status');
    assert.equal(status.demo, false);
    assert.equal(status.running, false);
    assert.equal(status.api, 1);

    // Node uses a duplex socket for this inherited descriptor. Destroy the
    // parent end completely; a write-side FIN alone is not parent loss.
    child.stdio[4].destroy();
    const result = await Promise.race([exited, delay(6000).then(() => null)]);
    assert.ok(result, 'engine did not exit after parent channel closed');
    assert.equal(result.code, 0);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.stdio[4].destroy();
      child.kill('SIGTERM');
      await Promise.race([exited, delay(6000)]);
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
