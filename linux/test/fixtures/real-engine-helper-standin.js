'use strict';

/* TEST STAND-IN for the privileged helper. It is NOT the real helper.
 *
 * The real helper is the Rust program in linux/helper. It runs as root, keeps
 * state files under /run and /var/lib, and starts the packaged engine. This
 * script exists so the app's pkexec client path (secret on stdin, HS_READY,
 * HS_PORT, stop by closing stdin, exit codes) can run against the REAL engine
 * binary without root, polkit, a TUN device, or a route change.
 *
 * Differences from the real helper, on purpose:
 *   - It refuses to run as root, so it can never become a privileged path.
 *   - It runs the engine as the current user with a temporary HOME that the
 *     test names in HS_STANDIN_HOME. The engine path is HS_STANDIN_ENGINE.
 *   - It writes no PENDING or ENGINE record and takes no lock.
 *   - It has no prctl parent-death signal. Parent loss is detected only through
 *     end of file on stdin, which is also how the real helper learns of it.
 *
 * It keeps the same engine arguments, the same descriptor layout (secret on 3,
 * liveness on 4, and for HS2 the handoff socket from descriptor 2 on 5), the
 * same HS1 and HS2 request lines, and the same exit code meaning
 * for a clean stop (0), a signaled engine (4), and a failed engine (5).
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const EXIT_SIGNALED = 4;
const EXIT_FAILED = 5;
const EOF_GRACE_MS = 8000;
const TERM_GRACE_MS = 10000;

if (typeof process.geteuid === 'function' && process.geteuid() === 0) {
  console.error('stand-in helper: refusing to run as root.');
  process.exit(1);
}

const engine = process.env.HS_STANDIN_ENGINE || '';
const home = process.env.HS_STANDIN_HOME || '';
const pidFile = process.env.HS_STANDIN_PID_FILE || '';
if (!path.isAbsolute(engine) || !path.isAbsolute(home)) {
  console.error('stand-in helper: HS_STANDIN_ENGINE and HS_STANDIN_HOME must be absolute paths.');
  process.exit(1);
}

let buffer = Buffer.alloc(0);
let stdinEnded = false;
const readers = [];

function flush() {
  while (readers.length) {
    const index = buffer.indexOf(10);
    if (index === -1) {
      if (stdinEnded) readers.shift()('');
      else return;
    } else {
      const line = buffer.subarray(0, index).toString('utf8');
      buffer = buffer.subarray(index + 1);
      readers.shift()(line);
    }
  }
}

function readLine() {
  return new Promise((resolve) => {
    readers.push(resolve);
    flush();
  });
}

const stdinClosed = new Promise((resolve) => {
  process.stdin.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    flush();
  });
  process.stdin.on('end', () => { stdinEnded = true; flush(); resolve(); });
  process.stdin.on('error', () => { stdinEnded = true; flush(); resolve(); });
  process.stdin.resume();
});

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  /* HS2 means descriptor 2 is the user engine handoff socket. Like the real
   * helper, pass it to the engine as descriptor 5 and never read it. This
   * stand-in writes nothing on stderr. */
  const version = await readLine();
  if (version !== 'HS1' && version !== 'HS2') process.exit(2);
  const handoff = version === 'HS2';
  const secret = await readLine();
  if (!/^[0-9a-f]{64}$/.test(secret)) process.exit(3);
  if (process.argv.join(' ').includes(secret) || JSON.stringify(process.env).includes(secret)) {
    console.error('stand-in helper: the secret reached argv or the environment.');
    process.exit(4);
  }

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hs-standin-'));
  fs.chmodSync(directory, 0o700);
  const portPath = path.join(directory, 'port');
  process.stdout.write('HS_READY\n');

  const child = spawn(engine, [
    'gui', '--no-open', '--port', '0', '--port-file', portPath,
    '--token-fd', '3', '--parent-fd', '4'
  ].concat(handoff ? ['--credentials-fd', '5'] : []), {
    cwd: directory,
    env: { HOME: home, PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8', TMPDIR: directory },
    stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'].concat(handoff ? [2] : [])
  });
  let exit = null;
  const exited = new Promise((resolve) => {
    child.once('exit', (code, signal) => { exit = { code, signal }; resolve(); });
    child.once('error', () => { exit = { code: null, signal: null, error: true }; resolve(); });
  });
  child.stdio[3].on('error', () => {});
  child.stdio[4].on('error', () => {});
  child.stdio[3].end(secret + '\n');
  if (pidFile && child.pid) fs.writeFileSync(pidFile, String(child.pid), { mode: 0o600 });

  let port = 0;
  const deadline = Date.now() + 10000;
  while (!port && !exit && Date.now() < deadline && !stdinEnded) {
    try { port = Number(fs.readFileSync(portPath, 'utf8').trim()); } catch (error) { /* not ready */ }
    if (!port) await delay(50);
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    child.stdio[4].destroy();
    if (!exit) child.kill('SIGTERM');
    await Promise.race([exited, delay(TERM_GRACE_MS)]);
    fs.rmSync(directory, { recursive: true, force: true });
    process.exit(exit && exit.code === 0 ? 7 : EXIT_FAILED);
  }
  fs.rmSync(directory, { recursive: true, force: true });
  process.stdout.write('HS_PORT ' + port + '\n');

  // Stop path: request pipe EOF, or the engine ending by itself.
  await Promise.race([stdinClosed, exited]);
  if (!exit) {
    child.stdio[4].destroy();
    await Promise.race([exited, delay(EOF_GRACE_MS)]);
    if (!exit) {
      child.kill('SIGTERM');
      await Promise.race([exited, delay(TERM_GRACE_MS)]);
    }
  }
  if (!exit) process.exit(3);
  if (exit.signal) process.exit(EXIT_SIGNALED);
  process.exit(exit.code === 0 ? 0 : EXIT_FAILED);
}

main().catch(() => process.exit(6));
