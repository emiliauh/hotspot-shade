'use strict';

/* The protected Linux engine transport.
 *
 * The main process launches the HotspotShade binary with the same `gui` mode
 * arguments that the macOS app uses:
 *
 *   gui --no-open --port 0 --port-file <private-file> --token-fd 3 --parent-fd 4
 *
 * The per-launch bearer secret travels on descriptor 3. It never appears on a
 * command line, in the environment, in a log, or in the renderer. Descriptor 4
 * is the parent-liveness channel: the engine stops when Electron closes it.
 *
 * The engine listens on a loopback port only. This module may call only the
 * fixed operation list below. It never accepts a path, URL, host, command, or
 * generic request body from a caller.
 *
 * The engine binary is named by an explicit setting or by the
 * HOTSPOTSHADE_ENGINE environment variable. A relative name is refused. This
 * module never searches PATH for the engine.
 *
 * A packaged app uses the fixed pkexec helper. The app calls pkexec with the
 * helper path and no other argument. The helper starts the packaged engine and
 * holds the secret on descriptor 3 and the liveness channel on descriptor 4.
 * A development build starts the engine directly and needs root outside the
 * app for a real tunnel. The engine demo mode needs no root.
 */

const { randomBytes } = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { BackendError } = require('./errors');

const ENGINE_ENV = 'HOTSPOTSHADE_ENGINE';
const ENGINE_DEMO_ENV = 'HOTSPOTSHADE_ENGINE_DEMO';
const PRIVILEGED_ENV = 'HOTSPOTSHADE_PRIVILEGED';
const HELPER_ENV = 'HOTSPOTSHADE_HELPER';
const PKEXEC_ENV = 'HOTSPOTSHADE_PKEXEC';
const PRIVILEGED_ENGINE_ENV = 'HOTSPOTSHADE_PRIVILEGED_ENGINE';
const DEFAULT_HELPER_PATH = '/usr/lib/hotspotshade/hotspotshade-helper';
const DEFAULT_PKEXEC_PATH = '/usr/bin/pkexec';
const DEFAULT_ENGINE_PATH = '/opt/hotspotshade/resources/engine/hotspotshade';
const LOOPBACK = '127.0.0.1';
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_PORT_LINE = 64;
const START_TIMEOUT_MS = 10000;
const STOP_GRACE_MS = 5000;
const PRIVILEGED_STOP_GRACE_MS = 15000;
const PARENT_CLOSE_MS = 2000;
const KILL_WAIT_MS = 1000;
const PORT_POLL_MS = 50;

/* The complete operation allowlist. The first three fields are fixed. The
 * caller can set only `ping` for start and `since` for activity. */
const OPERATIONS = Object.freeze({
  status: Object.freeze({ method: 'GET', path: '/api/status', timeoutMs: 3000 }),
  pairState: Object.freeze({ method: 'GET', path: '/api/phone/pair', timeoutMs: 3000 }),
  pair: Object.freeze({ method: 'POST', path: '/api/phone/pair', timeoutMs: 5000 }),
  pairCancel: Object.freeze({ method: 'POST', path: '/api/phone/pair/cancel', timeoutMs: 5000 }),
  forget: Object.freeze({ method: 'POST', path: '/api/phone/forget', timeoutMs: 5000 }),
  start: Object.freeze({ method: 'POST', path: '/api/start', timeoutMs: 90000 }),
  stop: Object.freeze({ method: 'POST', path: '/api/stop', timeoutMs: 70000 }),
  probe: Object.freeze({ method: 'POST', path: '/api/phone/probe', timeoutMs: 5000 }),
  activity: Object.freeze({ method: 'GET', path: '/api/logs', timeoutMs: 5000 }),
  failures: Object.freeze({ method: 'GET', path: '/api/failures', timeoutMs: 3000 }),
  diagnostics: Object.freeze({ method: 'GET', path: '/api/diagnostics', timeoutMs: 3000 })
});

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function delay(milliseconds) {
  return new Promise(function (resolve) {
    setTimeout(resolve, milliseconds);
  });
}

function cleanMessage(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim()
    .slice(0, 300);
}

function cleanCode(value) {
  return typeof value === 'string' && /^[a-z0-9_]{1,40}$/.test(value) ? value : '';
}

/* Read one --engine value. It accepts `--engine /path` and `--engine=/path`. */
function readEngineArgument(argv) {
  if (!Array.isArray(argv)) return { present: false, value: '', problem: '' };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (typeof item !== 'string') continue;
    if (item === '--engine') {
      const value = argv[index + 1];
      if (typeof value !== 'string' || !value || value.startsWith('--')) {
        return { present: true, value: '', problem: 'The --engine setting needs an absolute path.' };
      }
      return { present: true, value: value, problem: '' };
    }
    if (item.startsWith('--engine=')) {
      return { present: true, value: item.slice('--engine='.length), problem: '' };
    }
  }
  return { present: false, value: '', problem: '' };
}

/* Pick the backend mode for this launch.
 *
 * `--demo` selects the in-memory demo backend and wins over an engine setting.
 * With no engine setting the demo backend is the default.
 *
 * A packaged app uses the fixed privileged helper. The app calls `pkexec` with
 * the helper path and no other argument. The helper starts the packaged engine.
 * The app never runs the window or the engine client as root.
 *
 * A development `--engine` path or HOTSPOTSHADE_ENGINE keeps the unprivileged
 * direct start. That path is not used with root.
 *
 * A bad engine or helper setting selects the engine mode with a plain error,
 * so the app can show it. */
function resolveEngineConfig(options) {
  const settings = isPlainObject(options) ? options : {};
  const argv = Array.isArray(settings.argv) ? settings.argv : [];
  const env = isPlainObject(settings.env) ? settings.env : {};
  const isPackaged = settings.isPackaged === true;
  const forceDemo = argv.includes('--demo');
  const argument = readEngineArgument(argv);
  const envValue = typeof env[ENGINE_ENV] === 'string' ? env[ENGINE_ENV].trim() : '';
  const engineDemo = argv.includes('--engine-demo')
    || String(env[ENGINE_DEMO_ENV] || '').trim().toLowerCase() === '1'
    || String(env[ENGINE_DEMO_ENV] || '').trim().toLowerCase() === 'true';
  const privilegedRequested = isPackaged
    || argv.includes('--privileged')
    || String(env[PRIVILEGED_ENV] || '').trim().toLowerCase() === '1'
    || String(env[PRIVILEGED_ENV] || '').trim().toLowerCase() === 'true';

  if (forceDemo) {
    return { mode: 'demo', executable: '', demo: false, privileged: false, error: null };
  }
  if (argument.problem) {
    return { mode: 'error', executable: '', demo: engineDemo, privileged: false, error: argument.problem };
  }
  if (argument.present && !argument.value.trim()) {
    return { mode: 'error', executable: '', demo: engineDemo, privileged: false, error: 'The --engine setting needs an absolute path.' };
  }
  const value = argument.present ? argument.value.trim() : envValue;
  if (!value) {
    if (!privilegedRequested) {
      return { mode: 'demo', executable: '', demo: false, privileged: false, error: null };
    }
    return resolvePrivilegedConfig({
      env: env,
      engineDemo: engineDemo,
      fileSystem: settings.fileSystem
    });
  }
  if (value.indexOf('\u0000') !== -1) {
    return { mode: 'error', executable: '', demo: engineDemo, privileged: false, error: 'The engine setting is not valid.' };
  }
  if (!path.isAbsolute(value)) {
    return {
      mode: 'error',
      executable: '',
      demo: engineDemo,
      privileged: false,
      error: 'The engine setting must be an absolute file path. The app does not search PATH.'
    };
  }
  const fileSystem = settings.fileSystem && typeof settings.fileSystem === 'object'
    ? settings.fileSystem
    : fs;
  let stat = null;
  try {
    stat = fileSystem.statSync(value);
  } catch (error) {
    return { mode: 'error', executable: '', demo: engineDemo, privileged: false, error: 'The engine file is missing.' };
  }
  if (!stat.isFile()) {
    return { mode: 'error', executable: '', demo: engineDemo, privileged: false, error: 'The engine path is not a file.' };
  }
  try {
    fileSystem.accessSync(value, fs.constants.X_OK);
  } catch (error) {
    return { mode: 'error', executable: '', demo: engineDemo, privileged: false, error: 'The engine file is not executable.' };
  }
  return { mode: 'engine', executable: value, demo: engineDemo, privileged: false, error: null };
}

function privilegedPath(env, name, fallback) {
  const value = typeof env[name] === 'string' ? env[name].trim() : '';
  return value && path.isAbsolute(value) ? value : fallback;
}

function executableProblem(fileSystem, filePath, noun) {
  let stat = null;
  try {
    stat = fileSystem.statSync(filePath);
  } catch (error) {
    return 'The ' + noun + ' is missing.';
  }
  if (!stat.isFile()) return 'The ' + noun + ' path is not a file.';
  try {
    fileSystem.accessSync(filePath, fs.constants.X_OK);
  } catch (error) {
    return 'The ' + noun + ' is not executable.';
  }
  return '';
}

function resolvePrivilegedConfig(options) {
  const settings = isPlainObject(options) ? options : {};
  const env = isPlainObject(settings.env) ? settings.env : {};
  const fileSystem = settings.fileSystem && typeof settings.fileSystem === 'object'
    ? settings.fileSystem
    : fs;
  const engineDemo = settings.engineDemo === true;
  const enginePath = privilegedPath(env, PRIVILEGED_ENGINE_ENV, DEFAULT_ENGINE_PATH);
  const engineProblem = executableProblem(fileSystem, enginePath, 'packaged engine');
  if (engineProblem) {
    return { mode: 'error', executable: '', demo: engineDemo, privileged: false, error: engineProblem };
  }
  if (engineDemo) {
    /* The engine demo needs no privilege. The helper is not involved. */
    return { mode: 'engine', executable: enginePath, demo: true, privileged: false, error: null };
  }
  const helperPath = privilegedPath(env, HELPER_ENV, DEFAULT_HELPER_PATH);
  const pkexecPath = privilegedPath(env, PKEXEC_ENV, DEFAULT_PKEXEC_PATH);
  const helperProblem = executableProblem(fileSystem, helperPath, 'privileged helper');
  if (helperProblem) {
    return { mode: 'error', executable: '', demo: false, privileged: false, error: helperProblem };
  }
  const pkexecProblem = executableProblem(fileSystem, pkexecPath, 'pkexec program');
  if (pkexecProblem) {
    return { mode: 'error', executable: '', demo: false, privileged: false, error: pkexecProblem };
  }
  return {
    mode: 'engine',
    executable: '',
    demo: false,
    privileged: true,
    helperPath: helperPath,
    pkexecPath: pkexecPath,
    enginePath: enginePath,
    error: null
  };
}

function readErrorBody(body) {
  if (typeof body !== 'string' || !body) return { code: '', message: '' };
  let value;
  try {
    value = JSON.parse(body);
  } catch (error) {
    return { code: '', message: '' };
  }
  if (!isPlainObject(value)) return { code: '', message: '' };
  const nested = isPlainObject(value.error) ? value.error : {};
  const raw = typeof value.error === 'string' ? value.error : nested.message;
  const code = cleanCode(value.code) || cleanCode(nested.code) || (typeof value.error === 'string' ? cleanCode(value.error) : '');
  return { code: code, message: cleanMessage(raw) };
}

function responseError(operation, statusCode, body) {
  const parsed = readErrorBody(body);
  const message = parsed.message || 'The engine request failed.';
  if (operation === 'forget' && statusCode === 409) {
    return new BackendError('forget_blocked', 'Turn off the tunnel first.', 409);
  }
  if (statusCode === 401 || statusCode === 403) {
    return new BackendError('engine_unauthorized', 'The engine rejected the request.', statusCode);
  }
  if (statusCode === 404) {
    return new BackendError('not_supported', 'This engine does not support the request.', 404);
  }
  if (parsed.code === 'phone_token_rejected') {
    return new BackendError('phone_token_rejected', message, statusCode);
  }
  if (operation === 'forget' && statusCode === 400) {
    return new BackendError('forget_failed', message, 400);
  }
  return new BackendError(parsed.code || 'engine_error', message, Number.isInteger(statusCode) ? statusCode : 400);
}

/* One request to the loopback engine. The path and the method come from the
 * fixed operation list. The secret stays in the Authorization header. */
function defaultRequest(request) {
  return new Promise(function (resolve, reject) {
    let settled = false;
    let timer = null;
    function finish(error, value) {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    }
    const headers = {
      Host: LOOPBACK + ':' + request.port,
      Authorization: 'Bearer ' + request.secret,
      Accept: 'application/json',
      Connection: 'close'
    };
    if (request.body) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(request.body);
    }
    let req;
    try {
      req = http.request({
        host: LOOPBACK,
        port: request.port,
        method: request.method,
        path: request.path,
        agent: false,
        headers: headers
      }, function (response) {
        const chunks = [];
        let size = 0;
        response.on('data', function (chunk) {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            response.destroy();
            finish(new BackendError('engine_response_too_large', 'The engine sent a response that is too large.'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', function () {
          finish(null, {
            statusCode: Number(response.statusCode) || 0,
            body: Buffer.concat(chunks).toString('utf8')
          });
        });
        response.on('error', function () {
          finish(new BackendError('engine_unavailable', 'The engine did not answer.'));
        });
      });
    } catch (error) {
      finish(new BackendError('engine_unavailable', 'The engine did not answer.'));
      return;
    }
    req.setTimeout(request.timeoutMs, function () {
      req.destroy();
      finish(new BackendError('engine_timeout', 'The engine did not answer in time.'));
    });
    req.on('error', function () {
      finish(new BackendError('engine_unavailable', 'The engine did not answer.'));
    });
    if (request.body) req.write(request.body);
    req.end();
  });
}

function buildRequest(operation, params) {
  const spec = OPERATIONS[operation];
  if (!spec) throw new BackendError('invalid_request', 'The engine operation is not known.');
  let target = spec.path;
  let body = spec.method === 'POST' ? '{}' : '';
  if (operation === 'activity') {
    let since = 0;
    if (isPlainObject(params) && params.since !== undefined) {
      if (!Number.isInteger(params.since)) {
        throw new BackendError('invalid_request', 'The activity request is not valid.');
      }
      since = params.since;
    }
    if (since < 0 || since > 1000000000) {
      throw new BackendError('invalid_request', 'The activity request is not valid.');
    }
    target = spec.path + '?since=' + since;
  }
  if (operation === 'start') {
    const ping = isPlainObject(params) && params.ping === true;
    body = JSON.stringify({ mode: 'phone', options: { experimental_icmp: ping } });
  }
  return { method: spec.method, path: target, body: body, timeoutMs: spec.timeoutMs };
}

function decodeBody(operation, value) {
  if (!isPlainObject(value)) {
    throw new BackendError('engine_bad_response', 'The engine sent a response that this app cannot read.');
  }
  if (value.ok === false) {
    throw responseError(operation, 400, JSON.stringify(value));
  }
  if (operation === 'start' || operation === 'stop') {
    return isPlainObject(value.status) ? value.status : {};
  }
  if (operation === 'activity') {
    return {
      logs: Array.isArray(value.logs) ? value.logs : [],
      next: Number.isInteger(value.next) && value.next >= 0 ? value.next : 0
    };
  }
  return value;
}

/* The HTTP half of the boundary. Tests inject a fake port and secret. */
function createEngineHttpClient(options) {
  const settings = isPlainObject(options) ? options : {};
  const port = Number(settings.port);
  const secret = settings.secret;
  const request = typeof settings.request === 'function' ? settings.request : defaultRequest;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new TypeError('A loopback port is required.');
  if (typeof secret !== 'string' || secret.length < 32) throw new TypeError('An engine secret is required.');

  async function call(operation, params) {
    const requestSpec = buildRequest(operation, params);
    let response;
    try {
      response = await request({
        port: port,
        secret: secret,
        method: requestSpec.method,
        path: requestSpec.path,
        body: requestSpec.body,
        timeoutMs: requestSpec.timeoutMs
      });
    } catch (error) {
      if (error instanceof BackendError) throw error;
      throw new BackendError('engine_unavailable', 'The engine did not answer.');
    }
    if (!response || !Number.isInteger(response.statusCode)) {
      throw new BackendError('engine_bad_response', 'The engine sent a response that this app cannot read.');
    }
    if (response.statusCode < 200 || response.statusCode > 299) {
      throw responseError(operation, response.statusCode, response.body);
    }
    let value;
    try {
      value = response.body ? JSON.parse(response.body) : {};
    } catch (error) {
      throw new BackendError('engine_bad_response', 'The engine sent a response that this app cannot read.');
    }
    return decodeBody(operation, value);
  }

  return Object.freeze({
    connected: true,
    call: call,
    operations: Object.freeze(Object.keys(OPERATIONS)),
    port: port
  });
}

function childEnvironment() {
  const source = process.env;
  const env = {
    PATH: '/usr/local/bin:/usr/bin:/bin',
    HOME: source.HOME || os.homedir(),
    LANG: source.LANG || 'C.UTF-8'
  };
  if (source.LC_ALL) env.LC_ALL = source.LC_ALL;
  if (source.TMPDIR) env.TMPDIR = source.TMPDIR;
  return env;
}

function crashMessage(privileged, exit) {
  if (privileged && exit && (exit.code === 126 || exit.code === 127)) {
    return 'The privileged helper did not get authorization. Start the app again and approve the request.';
  }
  return 'The engine stopped unexpectedly. Start the app again.';
}

function crashDetail(exit) {
  if (!exit) return 'The engine stopped.';
  if (exit.error) return 'The engine could not be started.';
  if (exit.signal) return 'The engine exited on signal ' + String(exit.signal) + '.';
  if (Number.isInteger(exit.code)) return 'The engine exited with code ' + exit.code + '.';
  return 'The engine exited.';
}

function startupMessage(privileged, exit) {
  if (privileged && exit && (exit.code === 126 || exit.code === 127)) {
    return 'The privileged helper did not get authorization. Approve the request and start the app again.';
  }
  return 'The engine stopped during startup. Check the engine setting.';
}

/* The process half of the boundary. It starts one engine, learns the loopback
 * port, and stops the engine on request.
 *
 * The direct path starts the configured engine with the secret on descriptor 3
 * and the parent-liveness descriptor 4.
 *
 * The privileged path calls `pkexec` with the fixed helper path and no other
 * argument. The secret travels on stdin. The helper starts the packaged engine
 * as root with the secret on descriptor 3 and holds the parent-liveness
 * descriptor until its stdin closes. The app never runs as root. */
function createEngineClient(options) {
  const settings = isPlainObject(options) ? options : {};
  const privileged = settings.privileged === true;
  const executable = typeof settings.executable === 'string' ? settings.executable : '';
  const helperPath = typeof settings.helperPath === 'string' ? settings.helperPath : '';
  const pkexecPath = typeof settings.pkexecPath === 'string' ? settings.pkexecPath : '';
  const enginePath = typeof settings.enginePath === 'string' ? settings.enginePath : '';
  const demo = settings.demo === true;
  const argvPrefix = Array.isArray(settings.argvPrefix)
    ? settings.argvPrefix.filter(function (value) { return typeof value === 'string'; })
    : [];
  const startTimeoutMs = Number.isInteger(settings.startTimeoutMs) ? settings.startTimeoutMs : START_TIMEOUT_MS;
  const stopGraceMs = Number.isInteger(settings.stopGraceMs)
    ? settings.stopGraceMs
    : (privileged ? PRIVILEGED_STOP_GRACE_MS : STOP_GRACE_MS);
  const parentCloseMs = Number.isInteger(settings.parentCloseMs) ? settings.parentCloseMs : PARENT_CLOSE_MS;
  const killWaitMs = Number.isInteger(settings.killWaitMs) ? settings.killWaitMs : KILL_WAIT_MS;
  const spawnProcess = typeof settings.spawn === 'function' ? settings.spawn : spawn;
  const fileSystem = isPlainObject(settings.fs) ? settings.fs : fs;

  let child = null;
  let secret = '';
  let port = null;
  let tempDirectory = null;
  let portFile = null;
  let exit = null;
  let exitedResolve = null;
  const exited = new Promise(function (resolve) { exitedResolve = resolve; });
  let startPromise = null;
  let launchFailed = false;
  let stopPromise = null;
  let stopping = false;
  let crashed = null;
  let httpClient = null;

  function closeTokenPipe() {
    if (!child || !child.stdio) return;
    const stream = child.stdio[3];
    if (stream && typeof stream.destroy === 'function' && !stream.destroyed) {
      try {
        stream.destroy();
      } catch (error) {
        /* The pipe is already closed. */
      }
    }
  }

  function closeParentPipe() {
    if (!child || !child.stdio) return;
    const stream = child.stdio[4];
    if (stream && typeof stream.destroy === 'function' && !stream.destroyed) {
      try {
        stream.destroy();
      } catch (error) {
        /* The pipe is already closed. */
      }
    }
  }

  /* The privileged helper reads the request from stdin and stops the engine
   * when stdin closes. This is also the parent-loss path. */
  function closeStdin() {
    if (!child || !child.stdin) return;
    const stream = child.stdin;
    try {
      if (typeof stream.end === 'function') stream.end();
      else if (typeof stream.destroy === 'function') stream.destroy();
    } catch (error) {
      /* The helper is already gone. */
    }
  }

  function removeTempDirectory() {
    if (!tempDirectory) return;
    try {
      fileSystem.rmSync(tempDirectory, { recursive: true, force: true });
    } catch (error) {
      /* Report the cleanup failure in the main process log. */
      console.warn('The engine temporary directory could not be removed.');
    }
    tempDirectory = null;
    portFile = null;
  }

  function recordExit(info) {
    if (exit) return;
    exit = info;
    if (exitedResolve) exitedResolve();
    if (!stopping && httpClient) {
      crashed = info;
      console.error('The engine stopped. ' + crashDetail(info));
    }
  }

  function attachProcessHandlers() {
    child.on('error', function () {
      recordExit({ code: null, signal: null, error: true });
    });
    child.on('exit', function (code, signal) {
      recordExit({ code: Number.isInteger(code) ? code : null, signal: signal || null, error: false });
    });
  }

  async function waitForExit(milliseconds) {
    if (exit) return true;
    const timeout = delay(milliseconds).then(function () { return false; });
    return Promise.race([exited.then(function () { return true; }), timeout]);
  }

  function readPort() {
    if (!portFile) return null;
    let text;
    try {
      text = fileSystem.readFileSync(portFile, 'utf8').trim();
    } catch (error) {
      return null;
    }
    if (!/^[0-9]{1,5}$/.test(text)) return null;
    const value = Number(text);
    return value > 0 && value <= 65535 ? value : null;
  }

  function validPort(value) {
    const portValue = Number(value);
    return Number.isInteger(portValue) && portValue > 0 && portValue <= 65535 ? portValue : null;
  }

  async function launchDirect() {
    if (!executable || !path.isAbsolute(executable)) {
      throw new BackendError('engine_config', 'The engine setting must be an absolute file path.');
    }
    try {
      fileSystem.accessSync(executable, fs.constants.X_OK);
    } catch (error) {
      throw new BackendError('engine_config', 'The engine file is missing or not executable.');
    }
    try {
      tempDirectory = fileSystem.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-engine-'));
      fileSystem.chmodSync(tempDirectory, 0o700);
    } catch (error) {
      tempDirectory = null;
      throw new BackendError('engine_config', 'The engine temporary directory could not be created.');
    }
    portFile = path.join(tempDirectory, 'port');
    secret = randomBytes(32).toString('hex');
    const args = argvPrefix.concat([
      'gui',
      '--no-open',
      '--port',
      '0',
      '--port-file',
      portFile,
      '--token-fd',
      '3',
      '--parent-fd',
      '4'
    ]);
    if (demo) args.push('--demo');
    try {
      child = spawnProcess(executable, args, {
        cwd: tempDirectory,
        env: childEnvironment(),
        stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'],
        detached: false,
        windowsHide: true
      });
    } catch (error) {
      removeTempDirectory();
      throw new BackendError('engine_start_failed', 'The engine did not start.');
    }
    attachProcessHandlers();
    if (child.stdout && typeof child.stdout.resume === 'function') child.stdout.resume();
    if (child.stderr && typeof child.stderr.resume === 'function') child.stderr.resume();
    const tokenStream = child.stdio ? child.stdio[3] : null;
    if (!tokenStream || typeof tokenStream.end !== 'function') {
      launchFailed = true;
      await stop();
      throw new BackendError('engine_start_failed', 'The engine did not start.');
    }
    tokenStream.on('error', function () {
      /* A closed token pipe is reported by the startup wait. */
    });
    tokenStream.end(secret + '\n', function () {
      if (typeof tokenStream.destroy === 'function' && !tokenStream.destroyed) tokenStream.destroy();
    });
    const deadline = Date.now() + startTimeoutMs;
    while (Date.now() < deadline) {
      if (exit) {
        launchFailed = true;
        await stop();
        throw new BackendError('engine_start_failed', startupMessage(false, exit));
      }
      const value = readPort();
      if (value) {
        port = value;
        httpClient = createEngineHttpClient({ port: value, secret: secret });
        return httpClient;
      }
      await delay(PORT_POLL_MS);
    }
    launchFailed = true;
    await stop();
    throw new BackendError('engine_start_timeout', 'The engine did not start in time.');
  }

  async function launchPrivileged() {
    if (!path.isAbsolute(pkexecPath) || !path.isAbsolute(helperPath) || !path.isAbsolute(enginePath)) {
      throw new BackendError('engine_config', 'The privileged helper setting must be an absolute file path.');
    }
    try {
      fileSystem.accessSync(pkexecPath, fs.constants.X_OK);
      fileSystem.accessSync(helperPath, fs.constants.X_OK);
      fileSystem.accessSync(enginePath, fs.constants.X_OK);
    } catch (error) {
      throw new BackendError('engine_config', 'The privileged helper or the packaged engine is missing.');
    }
    secret = randomBytes(32).toString('hex');
    try {
      child = spawnProcess(pkexecPath, [helperPath], {
        cwd: os.tmpdir(),
        env: childEnvironment(),
        stdio: ['pipe', 'pipe', 'pipe'],
        detached: false,
        windowsHide: true
      });
    } catch (error) {
      throw new BackendError('engine_start_failed', 'The privileged helper did not start.');
    }
    attachProcessHandlers();
    if (!child.stdin || !child.stdout) {
      launchFailed = true;
      await stop();
      throw new BackendError('engine_start_failed', 'The privileged helper did not start.');
    }
    child.stdin.on('error', function () {
      /* A closed request pipe is reported by the startup wait. */
    });
    if (child.stderr && typeof child.stderr.resume === 'function') child.stderr.resume();

    let announced = null;
    let output = '';
    if (typeof child.stdout.setEncoding === 'function') child.stdout.setEncoding('utf8');
    child.stdout.on('data', function (chunk) {
      output += String(chunk);
      if (output.length > MAX_PORT_LINE * 4) output = output.slice(-MAX_PORT_LINE * 4);
      const match = output.match(/(?:^|\n)HS_PORT ([0-9]{1,5})(?:\r?\n|$)/);
      if (!match) return;
      const value = validPort(match[1]);
      if (value) announced = value;
    });

    try {
      child.stdin.write('HS1\n' + secret + '\n');
    } catch (error) {
      launchFailed = true;
      await stop();
      throw new BackendError('engine_start_failed', 'The privileged helper did not start.');
    }

    const deadline = Date.now() + startTimeoutMs;
    while (Date.now() < deadline) {
      if (exit) {
        launchFailed = true;
        await stop();
        throw new BackendError('engine_start_failed', startupMessage(true, exit));
      }
      if (announced) {
        port = announced;
        httpClient = createEngineHttpClient({ port: announced, secret: secret });
        return httpClient;
      }
      await delay(PORT_POLL_MS);
    }
    launchFailed = true;
    await stop();
    throw new BackendError('engine_start_timeout', 'The engine did not start in time.');
  }

  async function launch() {
    if (stopping) throw new BackendError('engine_stopped', 'The engine is stopping.');
    if (privileged) return launchPrivileged();
    return launchDirect();
  }

  async function ensureStarted() {
    if (crashed) throw new BackendError('engine_stopped', crashMessage(privileged, crashed));
    if (httpClient) return httpClient;
    if (startPromise) return startPromise;
    if (stopping) throw new BackendError('engine_stopped', 'The engine is stopping.');
    startPromise = launch().then(function (client) {
      return client;
    }, function (error) {
      launchFailed = true;
      throw error;
    });
    return startPromise;
  }

  async function call(operation, params) {
    const client = await ensureStarted();
    if (crashed) throw new BackendError('engine_stopped', crashMessage(privileged, crashed));
    try {
      return await client.call(operation, params);
    } catch (error) {
      if (crashed) throw new BackendError('engine_stopped', crashMessage(privileged, crashed));
      throw error;
    }
  }

  async function stop() {
    if (stopPromise) return stopPromise;
    stopping = true;
    stopPromise = (async function () {
      const processHandle = child;
      if (processHandle && !exit) {
        if (privileged) {
          /* Closing the request pipe is the stop path and the parent-loss
           * path. The app cannot signal a root helper. */
          closeStdin();
          const stopped = await waitForExit(stopGraceMs);
          if (!stopped) {
            try {
              processHandle.kill('SIGTERM');
            } catch (error) {
              /* The helper runs as root. The app cannot signal it. */
            }
            const closed = await waitForExit(parentCloseMs);
            if (!closed) {
              try {
                processHandle.kill('SIGKILL');
              } catch (error) {
                /* The helper runs as root. The app cannot signal it. */
              }
              await waitForExit(killWaitMs);
            }
          }
        } else {
          try {
            processHandle.kill('SIGTERM');
          } catch (error) {
            /* The engine is already gone. */
          }
          const stopped = await waitForExit(stopGraceMs);
          if (!stopped) {
            /* The engine can also stop when its parent-liveness pipe closes. */
            closeParentPipe();
            const closed = await waitForExit(parentCloseMs);
            if (!closed) {
              try {
                processHandle.kill('SIGKILL');
              } catch (error) {
                /* The engine is already gone. */
              }
              await waitForExit(killWaitMs);
            }
          }
        }
      }
      closeStdin();
      closeTokenPipe();
      closeParentPipe();
      removeTempDirectory();
      secret = '';
      port = null;
      httpClient = null;
      if (!launchFailed) startPromise = null;
    })();
    return stopPromise;
  }

  function describe() {
    return {
      connected: !!httpClient && !stopping && !crashed,
      transport: httpClient ? (privileged ? 'privileged_pkexec' : 'loopback_http') : 'not_connected',
      tunnel: demo ? 'engine_demo' : 'engine_service',
      privileged: privileged,
      operations: Object.keys(OPERATIONS)
    };
  }

  return Object.freeze({
    mode: 'engine',
    call: call,
    start: function () { return ensureStarted(); },
    stop: stop,
    dispose: stop,
    describe: describe,
    isRunning: function () { return !!child && !exit && !stopping; },
    /* The following values are for the main process only. The renderer must
     * never receive them. */
    get pid() { return child && !exit ? child.pid || null : null; },
    get tempDirectory() { return tempDirectory; },
    exitInfo: function () { return exit ? Object.assign({}, exit) : null; }
  });
}

module.exports = {
  DEFAULT_ENGINE_PATH: DEFAULT_ENGINE_PATH,
  DEFAULT_HELPER_PATH: DEFAULT_HELPER_PATH,
  DEFAULT_PKEXEC_PATH: DEFAULT_PKEXEC_PATH,
  ENGINE_DEMO_ENV: ENGINE_DEMO_ENV,
  ENGINE_ENV: ENGINE_ENV,
  HELPER_ENV: HELPER_ENV,
  OPERATIONS: OPERATIONS,
  PKEXEC_ENV: PKEXEC_ENV,
  PRIVILEGED_ENGINE_ENV: PRIVILEGED_ENGINE_ENV,
  PRIVILEGED_ENV: PRIVILEGED_ENV,
  createEngineClient: createEngineClient,
  createEngineHttpClient: createEngineHttpClient,
  resolveEngineConfig: resolveEngineConfig
};
