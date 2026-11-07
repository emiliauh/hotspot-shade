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
 * A development engine binary is named by an explicit setting or by the
 * HOTSPOTSHADE_ENGINE environment variable. A relative name is refused. This
 * module never searches PATH for the engine. A packaged app ignores environment
 * path overrides and normally uses the fixed packaged paths. An explicit
 * --engine argument selects an unprivileged development engine.
 *
 * A packaged app normally uses the fixed pkexec helper. The app calls pkexec
 * with the helper path and no other argument. The helper starts the packaged
 * engine and holds the secret on descriptor 3 and the liveness channel on
 * descriptor 4. An explicit --engine argument does not use the helper.
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
/* This budget starts when the helper prints HS_READY, after pkexec has
 * authorized the launch. Password prompt time is not part of it. */
const START_TIMEOUT_MS = 10000;
/* A person may take a long time at the polkit prompt. The authorization wait
 * is separate from the engine startup wait. If it expires, the app closes the
 * request pipe; a late helper start then sees the closed pipe and starts no
 * engine. */
const AUTHORIZATION_TIMEOUT_MS = 120000;
const STOP_GRACE_MS = 5000;
/* The root helper stops the engine 8 seconds after stdin closes and then
 * gives the engine up to 45 seconds to remove its routes and rules. The app
 * cannot signal a root helper, so it waits for the real helper exit for the
 * whole helper budget. A shorter wait would let a second privileged engine
 * start while the old root helper still owns the routing table. */
const PRIVILEGED_STOP_GRACE_MS = 65000;
/* When the prompt is still open, no engine has started. Closing the request
 * pipe is enough. The app waits a short time for pkexec to notice. A late
 * authorization is refused by the helper's closed-pipe check. If HS_READY
 * arrives during this wait, the stop moves to the helper exit budget below. */
const AUTHORIZATION_STOP_MS = 3000;
const PARENT_CLOSE_MS = 2000;
const PORT_POLL_MS = 50;
/* The child `exit` event can arrive before its stdout stream has delivered
 * every buffered line. A readiness-dependent classification waits this long
 * for the stream to close. If it does not close, the result reports
 * uncertainty instead of claiming that no engine started. */
const STDOUT_DRAIN_MS = 500;

/* Stable helper exit codes. Every non-zero code is a failed stop, not a clean
 * one, except 126, 127, and 7 before an engine exists (see stop()). The
 * current helper reports a stop timeout with the HS_STOP_TIMEOUT line and
 * stays alive; exit code 3 is reserved for that case in a later helper. Code 9
 * is a cleanup failure: the engine status may be clean, but a state file or a
 * private directory could not be removed. */
const HELPER_ENGINE_SIGNALED = 4;
const HELPER_ENGINE_FAILED = 5;
const HELPER_ALREADY_RUNNING = 6;
const HELPER_ABANDONED = 7;
const HELPER_STATE_UNCERTAIN = 8;
const HELPER_CLEANUP_FAILED = 9;

/* Exit 1 covers several preparation failures. The helper writes one fixed line
 * on stderr, `HS_REASON <slug>`, before its human text. The app keeps a
 * bounded tail of helper stderr, takes the last such line, and maps only a
 * slug listed here. An unknown or malformed slug is ignored, so helper stderr
 * can never put text of its own into a message. The messages name only the
 * fixed install paths. */
const MAX_HELPER_STDERR = 4096;
const HELPER_REASON_MESSAGES = Object.freeze({
  bad_arguments: 'The privileged helper was started with an argument it refuses. Reinstall the HotspotShade package.',
  not_root: 'The privileged helper did not run as root. Check that polkit (pkexec) is installed, then try again.',
  not_pkexec: 'The privileged helper was not started through pkexec. Start HotspotShade from its desktop entry and try again.',
  engine_unsafe_permissions: 'The HotspotShade install directory (/opt/hotspotshade) has unsafe permissions: the engine and every directory above it must be owned by root and not writable by other users. Reinstall the HotspotShade package.',
  engine_missing: 'The packaged engine (/opt/hotspotshade/resources/engine/hotspotshade) is missing or not executable. Reinstall the HotspotShade package.',
  request_invalid: 'The privileged helper did not accept the start request. Update HotspotShade so the app and the helper match, then try again.',
  home_unavailable: 'The privileged helper could not use its state directory (/var/lib/hotspotshade). Check the disk and try again.',
  home_unsafe: 'The helper state directory (/var/lib/hotspotshade) is not owned by root or is not private, so the helper refused to use it. An administrator must inspect it.',
  lock_unavailable: 'The privileged helper could not open its lock file in /var/lib/hotspotshade. An administrator must inspect that directory.',
  identity_unavailable: 'The privileged helper could not read the boot and process-namespace identity from /proc. Check that /proc is mounted, then try again.',
  pipes_failed: 'The privileged helper could not set up its private pipes. Close other programs and try again.',
  temp_directory_failed: 'The privileged helper could not create its private directory under /tmp. Check the disk and the /tmp permissions, then try again.',
  state_write_failed: 'The privileged helper could not write its start record in /var/lib/hotspotshade, so it started no engine. Check the disk, then try again.'
});

/* Return the plain-English message for the last known reason line in a helper
 * stderr tail, or an empty string. */
function helperReasonMessage(stderrText) {
  if (typeof stderrText !== 'string' || !stderrText) return '';
  let slug = '';
  for (const match of stderrText.matchAll(/(?:^|\n)HS_REASON ([a-z_]{1,32})\r?(?=\n|$)/g)) {
    slug = match[1];
  }
  return Object.prototype.hasOwnProperty.call(HELPER_REASON_MESSAGES, slug)
    ? HELPER_REASON_MESSAGES[slug]
    : '';
}

/* The complete operation allowlist. The first three fields are fixed. The
 * caller can set only the fixed mode and ping flag for start and `since` for
 * activity. */
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
  diagnostics: Object.freeze({ method: 'GET', path: '/api/diagnostics', timeoutMs: 3000 }),
  /* The user engine writes the pairing to its private handoff socket. The
   * answer holds no token, key, host, or port. */
  handoff: Object.freeze({ method: 'POST', path: '/api/pairing/handoff', timeoutMs: 5000 })
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

/* A start that races a stop must settle as a stop, not as a live client and
 * not as a secret-validation error. */
function engineStoppingError() {
  return new BackendError('engine_stopped', 'The engine is stopping.');
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
 * A packaged app normally uses the fixed privileged helper. The app calls
 * `pkexec` with the helper path and no other argument. An explicit --engine
 * argument instead selects an unprivileged development engine. The app never
 * runs the window or the engine client as root.
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
  /* A packaged app has no demo mode. `--demo`, `--engine-demo`, and
   * HOTSPOTSHADE_ENGINE_DEMO are development and test seams for unpackaged
   * runs only, so the app a person installs always shows real state. */
  const forceDemo = !isPackaged && argv.includes('--demo');
  const argument = readEngineArgument(argv);
  /* A packaged build uses the fixed helper and the fixed packaged paths. It
   * ignores the development environment overrides, so a stray variable cannot
   * replace the program that runs with privilege. A development build keeps
   * the overrides for tests and local work. */
  const envValue = !isPackaged && typeof env[ENGINE_ENV] === 'string' ? env[ENGINE_ENV].trim() : '';
  const engineDemo = !isPackaged && (argv.includes('--engine-demo')
    || String(env[ENGINE_DEMO_ENV] || '').trim().toLowerCase() === '1'
    || String(env[ENGINE_DEMO_ENV] || '').trim().toLowerCase() === 'true');
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
      fileSystem: settings.fileSystem,
      isPackaged: isPackaged
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

/* The HOME for the user engine: `${XDG_DATA_HOME:-$HOME/.local/share}/
 * hotspotshade/engine`. The engine keeps its pairing identity key below it.
 * A relative XDG_DATA_HOME is ignored, as the XDG base directory rules say. */
function userEngineHome(env, homeDirectory) {
  const values = isPlainObject(env) ? env : {};
  const xdg = typeof values.XDG_DATA_HOME === 'string' ? values.XDG_DATA_HOME.trim() : '';
  const base = xdg && path.isAbsolute(xdg)
    ? xdg
    : path.join(typeof homeDirectory === 'string' && homeDirectory ? homeDirectory : os.homedir(), '.local', 'share');
  return path.join(base, 'hotspotshade', 'engine');
}

function privilegedPath(env, name, fallback, allowOverride) {
  if (!allowOverride) return fallback;
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
  /* A packaged launch never trusts a path from the environment. The fixed
   * paths are the packaging contract. A development launch may override them
   * for local tests. */
  const allowOverride = settings.isPackaged !== true;
  const enginePath = privilegedPath(env, PRIVILEGED_ENGINE_ENV, DEFAULT_ENGINE_PATH, allowOverride);
  const engineProblem = executableProblem(fileSystem, enginePath, 'packaged engine');
  if (engineProblem) {
    return { mode: 'error', executable: '', demo: engineDemo, privileged: false, error: engineProblem };
  }
  if (engineDemo) {
    /* The engine demo needs no privilege. The helper is not involved. */
    return { mode: 'engine', executable: enginePath, demo: true, privileged: false, error: null };
  }
  const helperPath = privilegedPath(env, HELPER_ENV, DEFAULT_HELPER_PATH, allowOverride);
  const pkexecPath = privilegedPath(env, PKEXEC_ENV, DEFAULT_PKEXEC_PATH, allowOverride);
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

function startMessageCode(message) {
  switch (message) {
    case 'The tunnel could not configure its routes.':
      return 'route_setup';
    case 'The tunnel could not create its virtual interface.':
      return 'tunnel_setup';
    case 'The tunnel could not start.':
      return 'service_start';
    case 'The start was cancelled.':
      return 'start_cancelled';
    case 'Start HotspotShade as Administrator to use the tunnel.':
      return 'admin_required';
    case 'This Windows build runs source device proxy mode only.':
      return 'unsupported_mode';
    case 'The protected helper is not available. Install the signed HotspotShade helper package, then try again.':
      return 'protected_helper_required';
    default:
      return '';
  }
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
  if (operation === 'start' && !parsed.code) {
    const fixed = startMessageCode(message);
    if (fixed) return new BackendError(fixed, message, statusCode);
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
    /* Socket inactivity is not an end-to-end deadline: a peer can keep the
     * socket active by trickling bytes. Bound the whole request as well. */
    timer = setTimeout(function () {
      req.destroy();
      finish(new BackendError('engine_timeout', 'The engine did not answer in time.'));
    }, request.timeoutMs);
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
    const requested = isPlainObject(params) && params.mode !== undefined ? params.mode : 'phone';
    if (requested !== 'phone' && requested !== 'direct') {
      throw new BackendError('invalid_request', 'The tunnel mode is not known.');
    }
    if (requested === 'direct') {
      /* Direct mode has no source device app. The engine chooses the physical
       * hotspot interface and pins every outer socket to it. IPv6 stays
       * blocked by default; the app names no interface, DNS server, host, or
       * token. */
      body = JSON.stringify({ mode: 'tun', options: { ipv6: 'block' } });
    } else {
      const ping = isPlainObject(params) && params.ping === true;
      body = JSON.stringify({ mode: 'phone', options: { experimental_icmp: ping } });
    }
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

/* A transport or decoding failure does not prove whether a mutation ran. */
function operationResponseError(operation, error) {
  if ((operation !== 'start' && operation !== 'stop') ||
      !['engine_timeout', 'engine_unavailable', 'engine_response_too_large', 'engine_bad_response'].includes(error.code)) {
    return error;
  }
  const action = operation === 'start' ? 'starting' : 'stopping';
  const first = error.code === 'engine_timeout'
    ? 'The engine did not answer in time.'
    : 'The engine did not return a usable response.';
  return new BackendError(error.code, `${first} It may still be ${action}. Check the current status.`);
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
      const failure = error instanceof BackendError
        ? error : new BackendError('engine_unavailable', 'The engine did not answer.');
      throw operationResponseError(operation, failure);
    }
    if (!response || !Number.isInteger(response.statusCode)) {
      throw operationResponseError(operation, new BackendError('engine_bad_response', 'The engine sent a response that this app cannot read.'));
    }
    if (response.statusCode < 200 || response.statusCode > 299) {
      throw responseError(operation, response.statusCode, response.body);
    }
    let value;
    try {
      value = response.body ? JSON.parse(response.body) : {};
    } catch (error) {
      throw operationResponseError(operation, new BackendError('engine_bad_response', 'The engine sent a response that this app cannot read.'));
    }
    try {
      return decodeBody(operation, value);
    } catch (error) {
      if (error instanceof BackendError) throw operationResponseError(operation, error);
      throw error;
    }
  }

  return Object.freeze({
    connected: true,
    call: call,
    operations: Object.freeze(Object.keys(OPERATIONS)),
    port: port
  });
}

function childEnvironment(home) {
  const source = process.env;
  const env = {
    PATH: '/usr/local/bin:/usr/bin:/bin',
    HOME: home || source.HOME || os.homedir(),
    LANG: source.LANG || 'C.UTF-8'
  };
  if (source.LC_ALL) env.LC_ALL = source.LC_ALL;
  if (source.TMPDIR) env.TMPDIR = source.TMPDIR;
  return env;
}

function crashMessage(privileged, exit, engineKnown, reasonMessage) {
  if (privileged && exit) {
    if (exit.code === HELPER_STATE_UNCERTAIN) {
      return 'The previous engine state could not be verified. An administrator must check for a running engine and inspect the routes before recovery.';
    }
    if (exit.code === 1) {
      return reasonMessage
        || 'The privileged helper could not prepare the engine start. Check the package and try again.';
    }
    if (exit.code === HELPER_ENGINE_SIGNALED || exit.code === HELPER_ENGINE_FAILED) {
      return 'The packaged engine stopped unexpectedly. Inspect the routes and start the app again.';
    }
    if (exit.code === HELPER_CLEANUP_FAILED) {
      return 'The privileged helper could not confirm cleanup after the engine stopped. Inspect the routes and start the app again.';
    }
    if (exit.code === HELPER_ALREADY_RUNNING) {
      return 'A previous privileged engine is still running. Inspect the routes and start the app again.';
    }
    if (exit.code === HELPER_ABANDONED) {
      return engineKnown
        ? 'The privileged helper exited after the engine start. Inspect the routes and start the app again.'
        : 'The privileged helper exited before it started an engine. Start the app again.';
    }
    if (exit.code === 126 || exit.code === 127) {
      return engineKnown
        ? 'The privileged helper exited after the engine start. Inspect the routes and start the app again.'
        : 'The privileged helper did not get authorization. Start the app again and approve the request.';
    }
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

function startupMessage(privileged, exit, engineKnown, reasonMessage) {
  if (privileged && exit) {
    if (exit.code === HELPER_STATE_UNCERTAIN) {
      return 'The previous engine state could not be verified. An administrator must check for a running engine and inspect the routes before recovery.';
    }
    if (exit.code === HELPER_ALREADY_RUNNING) {
      return 'A previous privileged engine is still running. Inspect the routes, stop it, and start the app again.';
    }
    if (exit.code === 1) {
      return reasonMessage
        || 'The privileged helper could not prepare the engine start. Check the package and try again.';
    }
    if (exit.code === HELPER_ABANDONED) {
      return engineKnown
        ? 'The privileged helper exited after the engine start. Inspect the routes and start the app again.'
        : 'Authorization finished after the app stopped waiting. The helper started no engine.';
    }
    if (exit.code === HELPER_ENGINE_SIGNALED) {
      return 'The packaged engine exited on a signal. Inspect the routes and start the app again.';
    }
    if (exit.code === HELPER_ENGINE_FAILED) {
      return 'The packaged engine failed to start. Inspect the routes and check the package.';
    }
    if (exit.code === HELPER_CLEANUP_FAILED) {
      return 'The privileged helper could not confirm cleanup. Inspect the routes before starting again.';
    }
    if (exit.code === 126 || exit.code === 127) {
      return engineKnown
        ? 'The privileged helper exited after the engine start. Inspect the routes and start the app again.'
        : 'The privileged helper did not get authorization. Approve the request and start the app again.';
    }
  }
  return 'The engine stopped during startup. Check the engine setting.';
}

function helperReason(code, signal) {
  if (signal) return 'helper_signaled';
  if (code === 3) return 'engine_stop_timeout';
  if (code === HELPER_ENGINE_SIGNALED) return 'engine_signaled';
  if (code === HELPER_ENGINE_FAILED) return 'engine_failed';
  if (code === HELPER_ALREADY_RUNNING) return 'engine_already_running';
  if (code === HELPER_ABANDONED) return 'engine_authorization_canceled';
  if (code === HELPER_STATE_UNCERTAIN) return 'engine_state_uncertain';
  if (code === HELPER_CLEANUP_FAILED) return 'engine_cleanup_failed';
  if (Number.isInteger(code) && code !== 0) return 'helper_failed';
  return '';
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
  /* The user engine exports its pairing on its standard input socket. Node
   * never reads a child's stdin stream, so the frame stays in the kernel until
   * a root engine reads it. Only the unprivileged direct path exports. */
  const exportsHandoff = !privileged && settings.handoff === true;
  /* An absolute HOME for the user engine. Its identity key lives below it. */
  const engineHome = !privileged && typeof settings.home === 'string' && path.isAbsolute(settings.home)
    ? settings.home
    : '';
  /* The privileged path passes this socket to pkexec as descriptor 2 and sends
   * an HS2 request. pkexec keeps only descriptors 0, 1, and 2. */
  const handoffStream = privileged && settings.handoffStream && typeof settings.handoffStream === 'object'
    ? settings.handoffStream
    : null;
  const argvPrefix = Array.isArray(settings.argvPrefix)
    ? settings.argvPrefix.filter(function (value) { return typeof value === 'string'; })
    : [];
  const startTimeoutMs = Number.isInteger(settings.startTimeoutMs) ? settings.startTimeoutMs : START_TIMEOUT_MS;
  const authorizationTimeoutMs = Number.isInteger(settings.authorizationTimeoutMs)
    ? settings.authorizationTimeoutMs
    : AUTHORIZATION_TIMEOUT_MS;
  const stopGraceMs = Number.isInteger(settings.stopGraceMs)
    ? settings.stopGraceMs
    : STOP_GRACE_MS;
  /* The privileged path waits for the real root helper exit. The default
   * covers the helper's 8 second EOF grace and its 45 second engine grace. */
  const helperExitMs = Number.isInteger(settings.helperExitMs)
    ? settings.helperExitMs
    : PRIVILEGED_STOP_GRACE_MS;
  const authorizationStopMs = Number.isInteger(settings.authorizationStopMs)
    ? settings.authorizationStopMs
    : AUTHORIZATION_STOP_MS;
  const parentCloseMs = Number.isInteger(settings.parentCloseMs) ? settings.parentCloseMs : PARENT_CLOSE_MS;
  const stdoutDrainMs = Number.isInteger(settings.stdoutDrainMs) ? settings.stdoutDrainMs : STDOUT_DRAIN_MS;
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
  /* A child `error` is not always a spawn failure. After the process exists it
   * can report that a signal could not be delivered, and the process may still
   * be alive. `spawned` separates that case from a failed spawn. */
  let spawned = false;
  let processError = null;
  let startPromise = null;
  let startSettled = false;
  let startFailure = null;
  let launchFailed = false;
  let stopPromise = null;
  let stopping = false;
  let stopTimedOut = false;
  let stopIncomplete = false;
  let helperReady = false;
  let readinessResolve = null;
  const readinessNotice = new Promise(function (resolve) {
    readinessResolve = resolve;
  });
  let enginePortSeen = false;
  let stdoutEnded = false;
  let stdoutBroken = false;
  let stdoutClosedResolve = null;
  const stdoutClosedNotice = new Promise(function (resolve) {
    stdoutClosedResolve = resolve;
  });
  let helperStderr = '';
  let stderrEnded = false;
  let stderrClosedResolve = null;
  const stderrClosedNotice = new Promise(function (resolve) {
    stderrClosedResolve = resolve;
  });
  let helperStopTimeout = false;
  let stopTimeoutResolve = null;
  const stopTimeoutNotice = new Promise(function (resolve) {
    stopTimeoutResolve = resolve;
  });
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
    /* Node emits `spawn` once the process exists and leaves `pid` undefined
     * when it does not. A fake child in a test can set `pid` directly. */
    if (typeof child.on === 'function') {
      child.on('spawn', function () {
        spawned = true;
      });
    }
    if (Number.isInteger(child.pid) && child.pid > 0) spawned = true;
    child.on('error', function (error) {
      if (spawned) {
        /* The process exists, so this reports a failed signal or a similar
         * child error. The process may still be alive: do not record an exit,
         * lose the pid, or classify the readiness as absent. */
        processError = error instanceof Error
          ? error
          : new Error('The engine process reported an error.');
        return;
      }
      /* Before a successful spawn the error proves that no process exists. */
      recordExit({ code: null, signal: null, error: true, spawn: true });
    });
    child.on('exit', function (code, signal) {
      recordExit({ code: Number.isInteger(code) ? code : null, signal: signal || null, error: false });
    });
  }

  async function waitForExit(milliseconds) {
    if (exit) return true;
    let timer = null;
    const timeout = new Promise(function (resolve) {
      timer = setTimeout(function () { resolve(false); }, milliseconds);
    });
    try {
      return await Promise.race([exited.then(function () { return true; }), timeout]);
    } finally {
      /* A pending timer keeps the Node process alive after a fast exit. */
      if (timer) clearTimeout(timer);
    }
  }

  function noteStdoutEnded() {
    if (stdoutEnded) return;
    stdoutEnded = true;
    if (stdoutClosedResolve) {
      stdoutClosedResolve();
      stdoutClosedResolve = null;
    }
  }

  function noteStdoutBroken() {
    stdoutBroken = true;
    noteStdoutEnded();
  }

  function noteStderrEnded() {
    if (stderrEnded) return;
    stderrEnded = true;
    if (stderrClosedResolve) {
      stderrClosedResolve();
      stderrClosedResolve = null;
    }
  }

  /* Keep only a bounded tail of helper stderr. The reason line is read from it
   * and nothing else is retained or shown. */
  function attachHelperStderr() {
    const stream = child && child.stderr;
    if (!stream || typeof stream.on !== 'function') {
      noteStderrEnded();
      return;
    }
    if (typeof stream.setEncoding === 'function') stream.setEncoding('utf8');
    stream.on('data', function (chunk) {
      helperStderr += String(chunk);
      if (helperStderr.length > MAX_HELPER_STDERR) {
        helperStderr = helperStderr.slice(-MAX_HELPER_STDERR);
      }
    });
    stream.on('end', noteStderrEnded);
    stream.on('close', noteStderrEnded);
    stream.on('error', noteStderrEnded);
    if (stream.readableEnded === true) noteStderrEnded();
  }

  /* The child `exit` event can arrive before the last stderr bytes. Wait for
   * the stream to end, up to a bound, before reading the reason line. */
  async function waitForStderr(milliseconds) {
    if (stderrEnded) return true;
    let timer = null;
    const timeout = new Promise(function (resolve) {
      timer = setTimeout(function () { resolve(false); }, milliseconds);
    });
    try {
      return await Promise.race([
        stderrClosedNotice.then(function () { return true; }),
        timeout
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  function currentReasonMessage() {
    return helperReasonMessage(helperStderr);
  }

  /* Readiness is one-way. A line that arrives while a stop is waiting must
   * be visible to that wait, even if the start promise has already given up. */
  function noteHelperReady() {
    if (helperReady) return;
    helperReady = true;
    if (readinessResolve) {
      readinessResolve();
      readinessResolve = null;
    }
  }

  /* The child `exit` event does not guarantee that every buffered stdout line
   * has arrived. A readiness claim waits for the readable side to end, up to a
   * bound. A stream that only closes, or that reports an error, leaves the
   * readiness unknown, not absent. */
  async function waitForStdout(milliseconds) {
    if (stdoutBroken) return false;
    if (stdoutEnded) return true;
    let timer = null;
    const timeout = new Promise(function (resolve) {
      timer = setTimeout(function () { resolve(false); }, milliseconds);
    });
    try {
      const ended = await Promise.race([
        stdoutClosedNotice.then(function () { return true; }),
        timeout
      ]);
      return ended && !stdoutBroken;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /* One bounded wait for a privileged stop. It returns when the helper exits,
   * reports an engine stop timeout, or an absolute deadline is reached. The
   * readiness promise is watched only while the caller still needs it, so a
   * readiness that already arrived cannot spin the loop. */
  async function waitForStopEvent(deadline, watchReadiness) {
    if (exit) return 'exit';
    if (helperStopTimeout) return 'timeout';
    const remaining = deadline - Date.now();
    if (remaining <= 0) return 'deadline';
    let timer = null;
    const timeout = new Promise(function (resolve) {
      timer = setTimeout(function () { resolve('deadline'); }, remaining);
    });
    const events = [
      exited.then(function () { return 'exit'; }),
      stopTimeoutNotice.then(function () { return 'timeout'; }),
      timeout
    ];
    if (watchReadiness) {
      events.push(readinessNotice.then(function () { return 'readiness'; }));
    }
    try {
      return await Promise.race(events);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /* The app gives an open authorization prompt a short stop wait. HS_READY
   * means authorization finished and an engine may start. If it arrives, the
   * wait must move to the remaining supervised-helper budget. Both bounds are
   * absolute times from the stop request, so the whole stop stays bounded. */
  async function waitForPrivilegedStop() {
    const startedAt = Date.now();
    const authorizationDeadline = startedAt + authorizationStopMs;
    const helperDeadline = startedAt + helperExitMs;
    for (;;) {
      if (exit) return 'exit';
      if (helperStopTimeout) return 'timeout';
      const supervised = helperReady || enginePortSeen || !!httpClient;
      const deadline = supervised
        ? helperDeadline
        : Math.min(authorizationDeadline, helperDeadline);
      if (Date.now() >= deadline) {
        if (supervised) return 'deadline';
        // Allow pending stream events one poll turn before deciding that the
        // short authorization wait expired. The helper deadline stays fixed.
        await new Promise(function (resolve) { setImmediate(resolve); });
        if (exit) return 'exit';
        if (helperStopTimeout) return 'timeout';
        if (helperReady || enginePortSeen || httpClient) continue;
        return 'authorization_deadline';
      }
      const event = await waitForStopEvent(deadline, !supervised);
      if (event === 'exit' || event === 'timeout') return event;
      /* Recheck readiness after either event. */
    }
  }

  function noteHelperStopTimeout() {
    if (helperStopTimeout) return;
    helperStopTimeout = true;
    if (stopTimeoutResolve) {
      stopTimeoutResolve();
      stopTimeoutResolve = null;
    }
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
    if (exportsHandoff) args.push('--handoff-fd', '0');
    if (engineHome) {
      try {
        fileSystem.mkdirSync(engineHome, { recursive: true, mode: 0o700 });
        fileSystem.chmodSync(engineHome, 0o700);
      } catch (error) {
        removeTempDirectory();
        throw new BackendError('engine_config', 'The engine data directory could not be created.');
      }
    }
    try {
      child = spawnProcess(executable, args, {
        cwd: tempDirectory,
        env: childEnvironment(engineHome),
        /* Descriptor 0 is the private pairing handoff socket when this engine
         * exports one. Node creates it and never reads a child's stdin. */
        stdio: [exportsHandoff ? 'pipe' : 'ignore', 'pipe', 'pipe', 'pipe', 'pipe'],
        detached: false,
        windowsHide: true
      });
    } catch (error) {
      removeTempDirectory();
      throw new BackendError('engine_start_failed', 'The engine did not start.');
    }
    attachProcessHandlers();
    if (exportsHandoff && child.stdin && typeof child.stdin.on === 'function') {
      child.stdin.on('error', function () {
        /* A lost handoff socket is reported by the handoff request. */
      });
    }
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
      /* Once a stop has started, this start must never return a live client.
       * The stop path may clear the secret while this loop is still awake. */
      if (stopping) throw engineStoppingError();
      const value = readPort();
      if (value) {
        if (stopping || !secret) throw engineStoppingError();
        port = value;
        httpClient = createEngineHttpClient({ port: value, secret: secret });
        return httpClient;
      }
      await delay(PORT_POLL_MS);
    }
    if (stopping) throw engineStoppingError();
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
        /* With a pairing handoff, descriptor 2 is the user engine's handoff
         * socket. The helper moves it to the engine and sends its own reason
         * lines on stdout instead. */
        stdio: ['pipe', 'pipe', handoffStream || 'pipe'],
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
    attachHelperStderr();

    let announced = null;
    let output = '';
    if (typeof child.stdout.setEncoding === 'function') child.stdout.setEncoding('utf8');
    child.stdout.on('data', function (chunk) {
      output += String(chunk);
      if (handoffStream) {
        /* The helper reason lines arrive on stdout in this mode. Keep the
         * same bounded tail that stderr uses. */
        helperStderr += String(chunk);
        if (helperStderr.length > MAX_HELPER_STDERR) helperStderr = helperStderr.slice(-MAX_HELPER_STDERR);
      }
      if (output.length > MAX_PORT_LINE * 8) output = output.slice(-MAX_PORT_LINE * 8);
      if (!helperReady && /(?:^|\n)HS_READY\r?\n/.test(output)) {
        noteHelperReady();
      }
      if (/(?:^|\n)HS_STOP_TIMEOUT\r?\n/.test(output)) {
        noteHelperStopTimeout();
      }
      const match = output.match(/(?:^|\n)HS_PORT ([0-9]{1,5})\r?\n/);
      if (!match) return;
      const value = validPort(match[1]);
      if (value) {
        announced = value;
        enginePortSeen = true;
        /* The helper started an engine, so the stop path must treat it as one
         * that may need cleanup. */
        noteHelperReady();
      }
    });
    child.stdout.on('end', noteStdoutEnded);
    child.stdout.on('error', noteStdoutBroken);
    /* An already-ended stream cannot give us a readiness line that the app
     * never saw. Treat that as unknown, not absent. */
    if (child.stdout.readableEnded === true) noteStdoutBroken();

    /* A helper exit code that depends on readiness is classified only after
     * the buffered stdout has drained. If the stream does not close, the
     * message reports uncertainty instead of claiming that no engine
     * started. */
    async function startupFailureMessage() {
      const settled = await waitForStdout(stdoutDrainMs);
      if (!settled && exit && !exit.signal
        && (exit.code === HELPER_ABANDONED || exit.code === 126 || exit.code === 127)) {
        return 'The privileged helper exited before the app could confirm whether it started an engine. Inspect the routes and start the app again.';
      }
      if (exit && !exit.signal && exit.code === 1) await waitForStderr(stdoutDrainMs);
      return startupMessage(true, exit, enginePortSeen || !!httpClient, currentReasonMessage());
    }

    try {
      child.stdin.write((handoffStream ? 'HS2\n' : 'HS1\n') + secret + '\n');
    } catch (error) {
      launchFailed = true;
      await stop();
      throw new BackendError('engine_start_failed', 'The privileged helper did not start.');
    }

    /* Phase 1: wait for the helper to report that authorization completed.
     * The polkit password prompt happens before HS_READY, so prompt time does
     * not consume the engine startup budget. */
    const authorizationDeadline = Date.now() + authorizationTimeoutMs;
    while (!helperReady && !announced && Date.now() < authorizationDeadline) {
      if (exit) {
        launchFailed = true;
        await stop();
        throw new BackendError('engine_start_failed', await startupFailureMessage());
      }
      if (stopping) throw engineStoppingError();
      await delay(PORT_POLL_MS);
    }
    if (!helperReady && !announced) {
      if (stopping) throw engineStoppingError();
      launchFailed = true;
      await stop();
      throw new BackendError(
        'engine_authorization_timeout',
        'The app stopped waiting for authorization. Dismiss any remaining prompt and check that the helper has stopped before starting the app again.'
      );
    }

    /* Phase 2: the engine has a full startup budget after authorization. */
    const deadline = Date.now() + startTimeoutMs;
    while (Date.now() < deadline) {
      if (exit) {
        launchFailed = true;
        await stop();
        throw new BackendError('engine_start_failed', await startupFailureMessage());
      }
      /* A stop can begin after readiness and before the port line. The stop
       * path clears the secret, so this start must settle as a stop. */
      if (stopping) throw engineStoppingError();
      if (announced) {
        if (!secret) throw engineStoppingError();
        port = announced;
        httpClient = createEngineHttpClient({ port: announced, secret: secret });
        return httpClient;
      }
      await delay(PORT_POLL_MS);
    }
    if (stopping) throw engineStoppingError();
    launchFailed = true;
    await stop();
    throw new BackendError('engine_start_timeout', 'The engine did not start in time after authorization.');
  }

  async function launch() {
    if (stopping) throw new BackendError('engine_stopped', 'The engine is stopping.');
    if (privileged) return launchPrivileged();
    return launchDirect();
  }

  async function ensureStarted() {
    if (crashed) {
      throw new BackendError(
        'engine_stopped',
        crashMessage(privileged, crashed, enginePortSeen || !!httpClient, currentReasonMessage())
      );
    }
    if (stopIncomplete) {
      throw new BackendError(
        'engine_stop_incomplete',
        'The previous privileged engine did not stop cleanly. Inspect the routes and start the app again.'
      );
    }
    if (stopTimedOut && child && !exit) {
      throw new BackendError(
        'engine_stop_timeout',
        'The previous privileged helper is still running. Wait for it to exit before starting the engine again.'
      );
    }
    /* Check the stop state before handing back a cached client. Once a stop
     * has started, no start may return a live client or read the cleared
     * secret. A launch failure that already settled is safe to repeat, because
     * it proves that no client exists. */
    if (stopping) {
      if (startSettled && startFailure) throw startFailure;
      throw engineStoppingError();
    }
    if (httpClient) return httpClient;
    if (startPromise) return startPromise;
    startPromise = launch().then(function (client) {
      startSettled = true;
      return client;
    }, function (error) {
      startSettled = true;
      startFailure = error;
      launchFailed = true;
      throw error;
    });
    return startPromise;
  }

  async function call(operation, params) {
    const client = await ensureStarted();
    if (stopping) throw engineStoppingError();
    const engineKnown = function () { return enginePortSeen || !!httpClient; };
    if (crashed) {
      throw new BackendError('engine_stopped', crashMessage(privileged, crashed, engineKnown(), currentReasonMessage()));
    }
    try {
      return await client.call(operation, params);
    } catch (error) {
      if (crashed) {
        throw new BackendError('engine_stopped', crashMessage(privileged, crashed, engineKnown(), currentReasonMessage()));
      }
      throw error;
    }
  }

  async function stop() {
    if (stopPromise) return stopPromise;
    stopping = true;
    stopPromise = (async function () {
      const processHandle = child;
      let timedOut = false;
      let failed = false;
      let reason = '';
      let stillRunning = false;
      let neverStarted = false;
      let cleanupUnconfirmed = false;
      if (processHandle && !exit) {
        if (privileged) {
          /* Closing the request pipe is the stop path and the parent-loss
           * path. The app cannot signal a root helper, so it sends no signal
           * and waits for the helper to stop the engine and exit. The app
           * never sends a forced kill, because that would skip the engine
           * route and rule cleanup. */
          closeStdin();
          const outcome = await waitForPrivilegedStop();
          if (outcome !== 'exit') {
            timedOut = true;
            stopTimedOut = true;
            failed = true;
            const supervised = helperReady || enginePortSeen || !!httpClient;
            reason = outcome === 'timeout'
              ? 'engine_stop_timeout'
              : (supervised ? 'helper_exit_timeout' : 'authorization_unconfirmed');
            console.error(
              'The privileged helper did not exit within the stop budget. The app will not start another engine until it is resolved. Inspect the routes before starting again.'
            );
          }
        } else {
          /* The development engine runs as the signed-in account. Send the
           * graceful signal and close the parent-liveness pipe, and never send
           * SIGKILL. A forced kill would skip the engine's route cleanup. */
          let signalAccepted = false;
          try {
            signalAccepted = processHandle.kill('SIGTERM') !== false;
          } catch (error) {
            processError = processError || (error instanceof Error
              ? error
              : new Error('The engine signal failed.'));
          }
          const stopped = await waitForExit(stopGraceMs);
          if (!stopped) {
            /* The engine can also stop when its parent-liveness pipe closes. */
            closeParentPipe();
            const closed = await waitForExit(parentCloseMs);
            if (!closed) {
              stillRunning = true;
              failed = true;
              cleanupUnconfirmed = true;
              reason = 'engine_still_running';
              console.error(
                !signalAccepted || processError
                  ? 'The development engine could not be signaled and did not exit after the parent pipe close. The app leaves it running.'
                  : 'The development engine did not exit after the graceful stop request and the parent pipe close. The app leaves it running.'
              );
            }
          }
        }
      }
      /* A direct engine that exited on a signal or a non-zero code may have
       * skipped its route cleanup. Report that as unconfirmed, not clean. */
      if (!privileged && exit && !stillRunning) {
        if (exit.error) {
          if (exit.spawn === true && !httpClient && !enginePortSeen) {
            /* A failed spawn is the one error that proves no process exists. */
            neverStarted = true;
            reason = 'engine_start_failed';
          } else {
            failed = true;
            reason = 'engine_start_failed';
            cleanupUnconfirmed = true;
          }
        } else if (exit.signal) {
          failed = true;
          reason = 'engine_signaled';
          cleanupUnconfirmed = true;
        } else if (Number.isInteger(exit.code) && exit.code !== 0) {
          failed = true;
          reason = 'engine_failed';
          cleanupUnconfirmed = true;
        }
      }
      /* A helper that exits non-zero did not prove a clean stop. A signal exit
       * can also mean the helper died before it stopped the engine. The child
       * `exit` event can arrive before buffered stdout, so a readiness claim
       * waits for the stream to close. A stream that does not close leaves the
       * readiness unknown, never absent. */
      if (privileged && exit) {
        const stdoutSettled = await waitForStdout(stdoutDrainMs);
        const engineObserved = !!httpClient || enginePortSeen;
        const everReady = helperReady || engineObserved;
        const abandoned = !exit.signal && exit.code === HELPER_ABANDONED;
        const notAuthorized = !exit.signal && (exit.code === 126 || exit.code === 127);
        if (abandoned && stdoutSettled && !engineObserved) {
          /* Exit 7 before any port announcement proves that the helper
           * started no engine. */
          neverStarted = true;
          reason = 'engine_authorization_canceled';
        } else if (abandoned && !stdoutSettled) {
          failed = true;
          reason = 'helper_readiness_unconfirmed';
          stopIncomplete = true;
        } else if (abandoned && engineObserved) {
          failed = true;
          reason = 'helper_abandoned_after_start';
          stopIncomplete = true;
        } else if (exit.error && exit.spawn === true && !everReady && !engineObserved) {
          neverStarted = true;
          reason = 'helper_start_failed';
        } else if (exit.error) {
          failed = true;
          reason = 'helper_start_failed';
        } else if (exit.signal) {
          failed = true;
          reason = 'helper_signaled';
          stopIncomplete = true;
          stopTimedOut = true;
        } else if (notAuthorized && !everReady) {
          if (stdoutSettled) {
            neverStarted = true;
            reason = 'helper_failed';
          } else {
            failed = true;
            reason = 'helper_readiness_unconfirmed';
            stopIncomplete = true;
          }
        } else if (Number.isInteger(exit.code) && exit.code !== 0) {
          failed = true;
          reason = reason || helperReason(exit.code, exit.signal);
          if (exit.code === 3) {
            stopTimedOut = true;
          }
          if (exit.code === 3 || exit.code === HELPER_ENGINE_SIGNALED
            || exit.code === HELPER_ENGINE_FAILED || exit.code === HELPER_CLEANUP_FAILED) {
            stopIncomplete = true;
          }
        } else if (Number.isInteger(exit.code) && exit.code === 0
          && helperReady && !engineObserved) {
          /* The helper reported readiness but never named a port. An engine
           * may have started and exited before the port line. Do not call that
           * a clean stop. */
          failed = true;
          reason = 'helper_exit_before_port';
          stopIncomplete = true;
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
      const result = { stopped: !timedOut && !failed, timedOut: timedOut };
      if (neverStarted) {
        /* No engine existed, so there is nothing to clean up. */
        result.neverStarted = true;
        if (reason) result.reason = reason;
        if (privileged && exit && Number.isInteger(exit.code)) result.helperCode = exit.code;
      }
      if (stillRunning) result.stillRunning = true;
      if (cleanupUnconfirmed) result.cleanupUnconfirmed = true;
      if (failed) {
        result.failed = true;
        if (reason) result.reason = reason;
        if (privileged && exit && Number.isInteger(exit.code)) result.helperCode = exit.code;
        if (privileged && exit && exit.signal) result.helperSignal = exit.signal;
      }
      return result;
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
    /* The app end of the user engine's pairing handoff socket, for the next
     * privileged launch only. The main process passes it on and never reads
     * it. It is null when this client exports no handoff or has no engine. */
    /* True once the helper announced an engine port. A late exit after an
     * unconfirmed authorization stop proves no engine only when this stayed
     * false and stdout ended normally. */
    get engineSeen() { return enginePortSeen; },
    get outputSettled() { return stdoutEnded && !stdoutBroken; },
    get handoffStream() {
      return exportsHandoff && child && !exit && child.stdin && !child.stdin.destroyed ? child.stdin : null;
    },
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
  HELPER_REASON_MESSAGES: HELPER_REASON_MESSAGES,
  OPERATIONS: OPERATIONS,
  PKEXEC_ENV: PKEXEC_ENV,
  PRIVILEGED_ENGINE_ENV: PRIVILEGED_ENGINE_ENV,
  PRIVILEGED_ENV: PRIVILEGED_ENV,
  createEngineClient: createEngineClient,
  createEngineHttpClient: createEngineHttpClient,
  helperReasonMessage: helperReasonMessage,
  resolveEngineConfig: resolveEngineConfig,
  userEngineHome: userEngineHome
};
