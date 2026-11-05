'use strict';

/* The XDG autostart entry for the Linux target app.
 *
 * The app writes one `.desktop` file in the user autostart directory. It writes
 * with a temporary file and a rename, so a reader sees the old file or the new
 * file, never a partial file. The removal is one unlink.
 *
 * The entry starts the packaged app as the desktop user. It never starts a
 * privileged helper and never holds a secret.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const AUTOSTART_DIR_ENV = 'HS_AUTOSTART_DIR';
const FILE_NAME = 'hotspotshade.desktop';

function resolveAutostartDirectory(env) {
  const values = env && typeof env === 'object' ? env : {};
  const override = typeof values[AUTOSTART_DIR_ENV] === 'string' ? values[AUTOSTART_DIR_ENV].trim() : '';
  if (override) return path.isAbsolute(override) ? override : '';
  const configHome = typeof values.XDG_CONFIG_HOME === 'string' ? values.XDG_CONFIG_HOME.trim() : '';
  if (configHome && path.isAbsolute(configHome)) {
    return path.join(configHome, 'autostart');
  }
  const home = typeof values.HOME === 'string' ? values.HOME.trim() : '';
  if (home && path.isAbsolute(home)) {
    return path.join(home, '.config', 'autostart');
  }
  return '';
}

/* Quote one Exec value. The desktop entry specification reserves the
 * backslash, the double quote, the backtick, and the dollar sign. */
function desktopQuote(value) {
  const text = typeof value === 'string' ? value : '';
  return '"' + text
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/`/g, '\\`')
    .replace(/\$/g, '\\$')
    .replace(/%/g, '%%') + '"';
}

function desktopEntryText(execPath) {
  return [
    '[Desktop Entry]',
    'Type=Application',
    'Version=1.0',
    'Name=HotspotShade',
    'Comment=Start HotspotShade when you log in.',
    'Exec=' + desktopQuote(execPath),
    'Terminal=false',
    'X-GNOME-Autostart-enabled=true',
    'Categories=Network;',
    ''
  ].join('\n');
}

function atomicWrite(fileSystem, target, text, mode) {
  const directory = path.dirname(target);
  fileSystem.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const suffix = crypto.randomBytes(6).toString('hex');
  const temporary = target + '.tmp-' + String(process.pid) + '-' + suffix;
  let descriptor = null;
  try {
    descriptor = fileSystem.openSync(temporary, 'wx', mode);
    fileSystem.writeFileSync(descriptor, text);
    try {
      fileSystem.fsyncSync(descriptor);
    } catch (error) {
      /* Some file systems cannot sync a file. The rename is still atomic. */
    }
    fileSystem.closeSync(descriptor);
    descriptor = null;
    fileSystem.renameSync(temporary, target);
  } catch (error) {
    if (descriptor !== null) {
      try {
        fileSystem.closeSync(descriptor);
      } catch (closeError) {
        /* Best effort. */
      }
    }
    try {
      fileSystem.unlinkSync(temporary);
    } catch (unlinkError) {
      /* Best effort. */
    }
    throw error;
  }
}

function createAutostart(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const fileSystem = settings.fs && typeof settings.fs === 'object' ? settings.fs : fs;
  const env = settings.env && typeof settings.env === 'object' ? settings.env : process.env;
  const execPath = typeof settings.execPath === 'string' ? settings.execPath : '';
  const fileName = typeof settings.fileName === 'string' && settings.fileName
    ? settings.fileName
    : FILE_NAME;

  function directory() {
    return resolveAutostartDirectory(env);
  }

  function filePath() {
    const root = directory();
    return root ? path.join(root, fileName) : '';
  }

  function available() {
    return !!(directory() && execPath && path.isAbsolute(execPath));
  }

  function enabled() {
    const target = filePath();
    if (!target) return false;
    try {
      return fileSystem.existsSync(target);
    } catch (error) {
      return false;
    }
  }

  function enable() {
    const target = filePath();
    if (!available() || !target) {
      throw new Error('The autostart directory is not available.');
    }
    atomicWrite(fileSystem, target, desktopEntryText(execPath), 0o644);
  }

  function disable() {
    const target = filePath();
    if (!target) {
      throw new Error('The autostart directory is not available.');
    }
    try {
      fileSystem.unlinkSync(target);
    } catch (error) {
      if (error && error.code === 'ENOENT') return;
      throw error;
    }
  }

  function status() {
    return {
      available: available(),
      enabled: enabled()
    };
  }

  return Object.freeze({
    available: available,
    disable: disable,
    enable: enable,
    enabled: enabled,
    filePath: filePath,
    status: status,
    text: function () { return desktopEntryText(execPath); }
  });
}

module.exports = {
  AUTOSTART_DIR_ENV: AUTOSTART_DIR_ENV,
  FILE_NAME: FILE_NAME,
  createAutostart: createAutostart,
  desktopEntryText: desktopEntryText,
  desktopQuote: desktopQuote,
  resolveAutostartDirectory: resolveAutostartDirectory
};
