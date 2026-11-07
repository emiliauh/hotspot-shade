import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { DEFAULT_ENGINE_PATH, DEFAULT_HELPER_PATH } = require('../src/backend/engine-client.js');

function read(relative) {
  return fs.readFileSync(path.join(root, relative), 'utf8');
}

test('the polkit action points at the fixed helper path', () => {
  const policy = read('packaging/local.hotspotshade.tunnel.policy');
  assert.match(policy, /id="local\.hotspotshade\.tunnel"/);
  assert.match(policy, new RegExp('<annotate key="org\\.freedesktop\\.policykit\\.exec\\.path">' + DEFAULT_HELPER_PATH.replace(/\./g, '\\.') + '</annotate>'));
  assert.match(policy, /<allow_any>auth_admin<\/allow_any>/);
  assert.match(policy, /<allow_inactive>auth_admin<\/allow_inactive>/);
  assert.match(policy, /<allow_active>auth_admin<\/allow_active>/);
  assert.doesNotMatch(policy, /auth_admin_keep/);
  assert.doesNotMatch(policy, /allow_any>yes|allow_active>yes/);
});

test('the desktop entry starts only the packaged app', () => {
  const desktop = read('packaging/hotspotshade.desktop');
  assert.match(desktop, /^Name=HotspotShade$/m);
  assert.match(desktop, /^Exec=\/opt\/hotspotshade\/HotspotShade %U$/m);
  assert.match(desktop, /^Icon=hotspotshade$/m);
  assert.match(desktop, /^Terminal=false$/m);
  assert.doesNotMatch(desktop, /pkexec|hotspotshade-helper|token/i);
});

test('the package script builds the engine, the helper, and one .deb', () => {
  const script = read('scripts/package-deb.sh');
  assert.match(script, /^umask 022$/m);
  assert.match(script, /cargo build --release --locked --manifest-path "\$repo\/rust\/Cargo\.toml"/);
  assert.match(script, /cargo build --release --locked --manifest-path "\$root\/helper\/Cargo\.toml"/);
  assert.match(script, /electron-packager/);
  assert.match(script, /dpkg-deb --build --root-owner-group/);
  assert.match(script, /uname -m/);
  assert.match(script, /Build the \$arch package on a \$arch host/);
  assert.match(script, /resources\/engine\/hotspotshade/);
  assert.match(script, /usr\/lib\/hotspotshade\/hotspotshade-helper/);
  assert.match(script, /local\.hotspotshade\.tunnel\.policy/);
  assert.doesNotMatch(script, /\bsudo\b/);
  assert.doesNotMatch(script, /curl|wget|\|\s*sh/);
});

test('the helper accepts no arguments and keeps the secret off the command line', () => {
  const source = read('helper/src/main.rs');
  const script = read('scripts/package-deb.sh');
  assert.match(source, /env::args_os\(\)\.len\(\) != 1/);
  assert.match(source, /"HS1"/);
  assert.match(source, /--token-fd/);
  assert.match(source, /--parent-fd/);
  assert.match(source, /DEFAULT_ENGINE/);
  assert.match(source, /PKEXEC_UID/);
  assert.match(source, /ENGINE_HOME/);
  assert.match(script, /\/var\/lib\/hotspotshade/);
  assert.doesNotMatch(source, /println!\([^)]*secret/i);
  assert.doesNotMatch(source, /eprintln!\([^)]*secret/i);
  assert.doesNotMatch(source, /Command::new\([^)]*arg\(/);
  assert.match(source, /command\.spawn/);
});

test('the helper and the transport use the same fixed paths', () => {
  const helper = read('helper/src/main.rs');
  const transport = read('src/backend/engine-client.js');
  assert.ok(helper.includes(DEFAULT_ENGINE_PATH));
  assert.ok(transport.includes(DEFAULT_HELPER_PATH));
  assert.ok(transport.includes(DEFAULT_ENGINE_PATH));
});

test('the package script sets umask 022 before it creates any packaged path', () => {
  const script = read('scripts/package-deb.sh');
  const umaskAt = script.search(/^umask 022$/m);
  const firstMkdir = script.search(/^mkdir -p "\$build\/deb/m);
  assert.ok(umaskAt >= 0, 'the script must set umask 022');
  assert.ok(firstMkdir > umaskAt, 'the umask must come before the package tree');
  assert.doesNotMatch(
    script.slice(0, umaskAt),
    /^(mkdir|cp|install|chmod|electron-packager)\b/m,
    'nothing may create a packaged path before the umask is set',
  );
});

/* The root helper refuses a packaged engine whose file or any ancestor
 * directory is writable by another user (helper/src/main.rs,
 * check_engine_owner). A group-writable package directory from the invoking
 * shell's umask is exactly that failure, so stage the tree under umask 002 and
 * read the modes back from the built .deb. The fixture mirrors the mkdir, cp,
 * chmod, and dpkg-deb steps of scripts/package-deb.sh. It needs dpkg-deb and is
 * skipped where it is absent. */
const dpkgDeb = (() => {
  try {
    const help = execFileSync('dpkg-deb', ['--help'], { encoding: 'utf8' });
    return help.includes('--root-owner-group') ? 'available' : false;
  } catch {
    return false;
  }
})();

function buildFixtureStage(umask) {
  return `set -eu
umask ${umask}
deb="$1"
mkdir -p "$deb/DEBIAN"
mkdir -p "$deb/opt/hotspotshade"
mkdir -p "$deb/opt/hotspotshade/resources/engine"
mkdir -p "$deb/usr/bin"
mkdir -p "$deb/usr/lib/hotspotshade"
mkdir -p "$deb/usr/share/applications"
mkdir -p "$deb/usr/share/pixmaps"
mkdir -p "$deb/usr/share/polkit-1/actions"
printf '#!/bin/sh\\nexit 0\\n' > "$deb/opt/hotspotshade/HotspotShade"
mkdir -p "$deb/opt/hotspotshade/resources/app"
printf '{}\\n' > "$deb/opt/hotspotshade/resources/app/package.json"
printf 'engine\\n' > "$deb/opt/hotspotshade/resources/engine/hotspotshade"
printf 'helper\\n' > "$deb/usr/lib/hotspotshade/hotspotshade-helper"
printf '[Desktop Entry]\\n' > "$deb/usr/share/applications/hotspotshade.desktop"
printf 'png\\n' > "$deb/usr/share/pixmaps/hotspotshade.png"
printf '<policyconfig/>\\n' > "$deb/usr/share/polkit-1/actions/local.hotspotshade.tunnel.policy"
printf '#!/bin/sh\\nexec /opt/hotspotshade/HotspotShade "$@"\\n' > "$deb/usr/bin/hotspotshade"
chmod 0755 "$deb/usr/bin/hotspotshade"
chmod 0755 "$deb/opt/hotspotshade/HotspotShade"
chmod 0755 "$deb/opt/hotspotshade/resources/engine/hotspotshade"
chmod 0755 "$deb/usr/lib/hotspotshade/hotspotshade-helper"
chmod 0644 "$deb/usr/share/applications/hotspotshade.desktop"
chmod 0644 "$deb/usr/share/pixmaps/hotspotshade.png"
chmod 0644 "$deb/usr/share/polkit-1/actions/local.hotspotshade.tunnel.policy"
printf 'Package: hotspotshade\\nVersion: 0.0.0\\nArchitecture: all\\nMaintainer: x\\nDescription: x\\n' > "$deb/DEBIAN/control"
dpkg-deb --build --root-owner-group "$deb" "$2" >/dev/null
`;
}

function listDeb(deb) {
  const output = execFileSync('dpkg-deb', ['-c', deb], { encoding: 'utf8' });
  return output
    .trim()
    .split('\n')
    .map((line) => {
      const [mode, owner] = line.trim().split(/\s+/);
      const name = line.slice(line.indexOf('./'));
      return { mode, owner, name };
    });
}

test('the staged package keeps helper-safe modes under an invoking umask 002', { skip: !dpkgDeb && 'dpkg-deb is not available' }, () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-packaging-'));
  try {
    const cases = [
      { name: 'fixed', umask: '022' },
      { name: 'nofix', umask: '002' },
    ];
    const modes = {};
    for (const item of cases) {
      const deb = path.join(work, `${item.name}.deb`);
      execFileSync('sh', ['-c', buildFixtureStage(item.umask), 'stage', path.join(work, item.name), deb]);
      modes[item.name] = listDeb(deb);
    }

    const fixed = modes.fixed.filter((entry) => entry.name.startsWith('./opt/hotspotshade'));
    assert.ok(fixed.length >= 5, 'the fixture must contain the engine path chain');
    for (const entry of fixed) {
      assert.equal(entry.owner, 'root/root', `${entry.name} must be root-owned`);
      assert.doesNotMatch(entry.mode.slice(4, 7), /w/, `${entry.name} must not be group-writable`);
      assert.doesNotMatch(entry.mode.slice(7, 10), /w/, `${entry.name} must not be world-writable`);
    }
    const engine = modes.fixed.find((entry) => entry.name === './opt/hotspotshade/resources/engine/hotspotshade');
    assert.ok(engine, 'the engine file must be packaged');
    assert.match(engine.mode, /^-rwxr-xr-x$/, 'the engine must be executable and not writable by others');

    /* Negative control: without the script's umask the same staging steps
     * record group-writable directories, which the helper refuses. */
    const unfixed = modes.nofix.filter((entry) => entry.name.startsWith('./opt/hotspotshade') && entry.mode.startsWith('d'));
    assert.ok(
      unfixed.some((entry) => entry.mode[5] === 'w'),
      'the fixture must reproduce the group-writable directory the fix prevents',
    );
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

/* ---------------------------------------------------------------------------
 * Maintainer scripts and the build-host checks.
 *
 * The scripts under packaging/debian run as root in a real install. These
 * tests run them as the current user against a temporary state directory. The
 * script paths are plain assignments at the top of each file with no
 * environment override, so the test rewrites exactly those lines in a copy.
 * `flock` is replaced by a shim that returns a chosen status, because the
 * shim's answers are what the scripts branch on; one test uses the real flock
 * where the host has it.
 * ------------------------------------------------------------------------- */

/* Debian's /bin/sh is dash. Run the maintainer scripts under dash when the host
 * has it, because it rejects bashisms that macOS's bash-as-sh accepts. */
const POSIX_SHELL = fs.existsSync('/bin/dash') ? '/bin/dash' : '/bin/sh';

const BOOT_NOW = '11111111-2222-3333-4444-555555555555';
const BOOT_OLD = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

function realFlockPath() {
  for (const directory of ['/usr/bin', '/bin', '/usr/local/bin', '/opt/homebrew/bin']) {
    const candidate = path.join(directory, 'flock');
    if (fs.existsSync(candidate)) return candidate;
  }
  return '';
}

function rewriteAssignments(text, values) {
  let result = text;
  for (const [name, value] of Object.entries(values)) {
    const pattern = new RegExp('^' + name + '=.*$', 'gm');
    const matches = result.match(pattern) || [];
    assert.equal(matches.length, 1, name + ' must be assigned exactly once');
    result = result.replace(pattern, () => name + '=' + value);
  }
  return result;
}

function maintainerFixture(options = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-maint-'));
  const stateDir = path.join(work, 'state');
  const bootFile = path.join(work, 'boot_id');
  const binDir = path.join(work, 'bin');
  fs.mkdirSync(binDir);
  fs.writeFileSync(bootFile, BOOT_NOW + '\n');
  const shim = path.join(binDir, 'flock');
  fs.writeFileSync(shim, '#!/bin/sh\nexit "${FAKE_FLOCK_STATUS:-0}"\n', { mode: 0o755 });
  const scripts = {};
  for (const name of ['prerm', 'postrm']) {
    const text = rewriteAssignments(read(path.join('packaging/debian', name)), {
      STATE_DIR: stateDir,
      BOOT_ID_FILE: bootFile,
    });
    scripts[name] = path.join(work, name);
    fs.writeFileSync(scripts[name], text, { mode: 0o755 });
  }
  if (options.state !== false) {
    fs.mkdirSync(stateDir, { mode: 0o700 });
  }
  return {
    work,
    stateDir,
    scripts,
    lock: path.join(stateDir, 'helper.lock'),
    record: path.join(stateDir, 'engine.state'),
    run(name, args, env = {}) {
      const result = spawnSync(POSIX_SHELL, [scripts[name], ...args], {
        encoding: 'utf8',
        env: Object.assign({ PATH: binDir + ':/usr/bin:/bin', HOME: path.join(work, 'home') }, env),
      });
      return { status: result.status, stdout: result.stdout, stderr: result.stderr };
    },
    remove() {
      fs.rmSync(work, { recursive: true, force: true });
    },
  };
}

function stateRecordText(kind, boot) {
  return `HS_ENGINE 2\nBOOT ${boot}\nNS 4 4026531836\n${kind} 4242 987654\n`;
}

function listTree(directory) {
  const names = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      names.push(path.relative(directory, full) + (entry.isDirectory() ? '/' : ''));
      if (entry.isDirectory()) walk(full);
    }
  };
  walk(directory);
  return names.sort();
}

test('the maintainer scripts are POSIX sh, never signal a process, and keep their paths fixed', () => {
  for (const name of ['postinst', 'prerm', 'postrm']) {
    const text = read(path.join('packaging/debian', name));
    const code = text
      .split('\n')
      .filter((line) => !/^\s*#/.test(line))
      .join('\n');
    assert.match(text, /^#!\/bin\/sh\n/, name + ' must be a POSIX sh script');
    assert.match(text, /^set -e$/m);
    assert.doesNotMatch(code, /(^|[\s;|&(])(kill|pkill|killall)\s/, name + ' must not signal any process');
    assert.doesNotMatch(code, /systemctl|service |pkexec|\bsudo\b\s+(?!rm )/, name + ' must not start or stop anything');
    assert.doesNotMatch(code, /\$HOME|\/home\/|\.config|autostart/, name + ' must not touch user settings or autostart');
    assert.doesNotMatch(text, /\$\{(STATE_DIR|BOOT_ID_FILE|ENGINE_PATH)[:-]/, name + ' must not take a path from the environment');
  }
  for (const name of ['prerm', 'postrm']) {
    const text = read(path.join('packaging/debian', name));
    assert.match(text, /^STATE_DIR=\/var\/lib\/hotspotshade$/m);
    assert.match(text, /^BOOT_ID_FILE=\/proc\/sys\/kernel\/random\/boot_id$/m);
  }
  const prerm = read('packaging/debian/prerm');
  assert.match(prerm, /remove \| upgrade \| deconfigure \| failed-upgrade/);
  assert.match(prerm, /flock -n -s -E 99/);
});

test('the package script installs all three maintainer scripts and states its platform limits', () => {
  const script = read('scripts/package-deb.sh');
  for (const name of ['postinst', 'prerm', 'postrm']) {
    assert.match(
      script,
      new RegExp('install -m 0755 "\\$root/packaging/debian/' + name + '" "\\$build/deb/DEBIAN/' + name + '"'),
    );
  }
  assert.match(script, /package-deb-lib\.sh/);
  assert.match(script, /hs_check_build_host \/etc\/os-release/);
  assert.match(script, /dpkg-shlibdeps -O/);
  assert.match(script, /hs_merge_depends/);
  assert.match(script, /^Depends: \$depends$/m);
  assert.match(script, /^Recommends: \$HS_RECOMMENDS$/m);
  assert.match(script, /Debian and Ubuntu only/);
  assert.match(script, /polkit authentication agent/);
  assert.match(script, /Ubuntu 24\.04/);
  assert.match(script, /glibc 2\.39/);
  assert.match(script, /HOTSPOTSHADE_ALLOW_NEWER_GLIBC/);
  const lib = read('scripts/package-deb-lib.sh');
  assert.match(lib, /HS_RECOMMENDS="policykit-1-gnome/);
  assert.match(lib, /libasound2t64 \| libasound2/);
  assert.match(lib, /libgtk-3-0t64 \| libgtk-3-0/);
  assert.match(lib, /libcups2t64 \| libcups2/);
  assert.match(lib, /libatk-bridge2\.0-0t64 \| libatk-bridge2\.0-0/);
});

test('every runtime library in the test image is covered by the package Depends', () => {
  const dockerfile = read('scripts/Dockerfile.test');
  const lib = read('scripts/package-deb-lib.sh');
  const known = lib.match(/^HS_KNOWN_DEPENDS_NAMES="([^"]+)"$/m)[1].split(' ');
  const installed = dockerfile
    .split('\n')
    .map((line) => line.trim().replace(/\s*\\$/, ''))
    .filter((line) => /^lib[a-z0-9.+-]+$/.test(line));
  assert.ok(installed.length >= 10, 'the Dockerfile library list must be readable');
  for (const library of installed) {
    const covered = known.some((name) => name === library || name === library + 't64');
    assert.ok(covered, library + ' is installed for the app but missing from the package Depends');
  }
});

function libraryCall(body, ...args) {
  const result = spawnSync('sh', ['-c', '. "$1"; shift; ' + body, 'sh', path.join(root, 'scripts/package-deb-lib.sh'), ...args], {
    encoding: 'utf8',
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function hostCheck(osRelease, glibc, allow = '0') {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-osrelease-'));
  try {
    const file = path.join(work, 'os-release');
    if (osRelease !== null) fs.writeFileSync(file, osRelease);
    const result = spawnSync(
      'sh',
      ['-c', '. "$1"; hs_check_build_host "$2" "$3" "$4"', 'sh', path.join(root, 'scripts/package-deb-lib.sh'), file, glibc, allow],
      { encoding: 'utf8' },
    );
    return { status: result.status, stderr: result.stderr };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

const UBUNTU_2404 = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\nID_LIKE=debian\n';

test('the build host check accepts the Ubuntu 24.04 baseline silently', () => {
  const result = hostCheck(UBUNTU_2404, 'glibc 2.39');
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
});

test('the build host check refuses a newer glibc and names the override', () => {
  for (const glibc of ['glibc 2.40', 'glibc 2.43', 'glibc 3.0']) {
    const result = hostCheck(UBUNTU_2404, glibc);
    assert.equal(result.status, 2, glibc);
    assert.match(result.stderr, /newer than the Ubuntu 24\.04 baseline/);
    assert.match(result.stderr, /Build on Ubuntu 24\.04/);
    assert.match(result.stderr, /HOTSPOTSHADE_ALLOW_NEWER_GLIBC=1/);
  }
});

test('the newer glibc override continues with a loud warning', () => {
  const result = hostCheck('ID=ubuntu\nVERSION_ID="26.04"\n', 'glibc 2.43', '1');
  assert.equal(result.status, 0);
  assert.match(result.stderr, /WARNING: this build host has glibc 2\.43/);
  assert.match(result.stderr, /will not run on Ubuntu 24\.04/);
});

test('the build host check refuses a host that is not Debian or Ubuntu', () => {
  for (const text of ['ID=fedora\nVERSION_ID=41\n', 'ID=arch\n', 'ID=alpine\nVERSION_ID=3.20\n', '']) {
    const result = hostCheck(text, 'glibc 2.39');
    assert.equal(result.status, 2, JSON.stringify(text));
    assert.match(result.stderr, /Debian and Ubuntu only/);
  }
  const missing = hostCheck(null, 'glibc 2.39');
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /Debian and Ubuntu only/);
});

test('the build host check accepts Debian-family hosts that are not 24.04 with a note', () => {
  const mint = hostCheck('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22"\n', 'glibc 2.35');
  assert.equal(mint.status, 0);
  assert.match(mint.stderr, /tested build baseline is Ubuntu 24\.04/);
  const debian = hostCheck('ID=debian\nVERSION_ID="12"\n', 'glibc 2.36');
  assert.equal(debian.status, 0);
  assert.match(debian.stderr, /untested from this host/);
  const newerDebian = hostCheck('ID=debian\nVERSION_ID="13"\n', 'glibc 2.41');
  assert.equal(newerDebian.status, 2);
});

test('the build host check refuses a host whose glibc cannot be read', () => {
  for (const glibc of ['', 'musl 1.2', 'glibc']) {
    const result = hostCheck(UBUNTU_2404, glibc);
    assert.equal(result.status, 2, JSON.stringify(glibc));
    assert.match(result.stderr, /Cannot read a glibc version/);
  }
});

test('the derived Depends merge keeps version constraints and adds the other libraries', () => {
  const derived = 'libasound2t64 (>= 1.0.16), libc6 (>= 2.34), libgtk-3-0t64 (>= 3.24.0), libglib2.0-0t64 (>= 2.80.0), libxdamage1 (>= 1:1.1)';
  const result = libraryCall('hs_merge_depends "$1"', derived);
  assert.equal(result.status, 0, result.stderr);
  const depends = result.stdout.trim();
  assert.match(depends, /^libc6 \(>= 2\.34\), libglib2\.0-0t64 \(>= 2\.80\.0\), libxdamage1 \(>= 1:1\.1\), libasound2t64 \(>= 1\.0\.16\) \| libasound2,/);
  assert.equal(depends.match(/libasound2t64/g).length, 1, 'no duplicate alternative');
  assert.equal(depends.match(/libgtk-3-0t64/g).length, 1);
  assert.match(depends, /libgtk-3-0t64 \(>= 3\.24\.0\) \| libgtk-3-0,/, 'the derived constraint replaces the bare name');
  assert.match(depends, /libcups2t64 \| libcups2/);
  assert.match(depends, /libatk-bridge2\.0-0t64 \| libatk-bridge2\.0-0/);
  assert.match(depends, /libnss3/);
  assert.match(depends, /libgbm1/);
  assert.match(depends, /libxss1/);
  assert.match(depends, /xdg-utils/);
  assert.match(depends, /pkexec$/);
  assert.doesNotMatch(depends, /,\s*,|^\s*,|,\s*$/);
});

test('an empty derived list still gives the known libraries without a stray comma', () => {
  const result = libraryCall('hs_merge_depends ""');
  assert.equal(result.status, 0, result.stderr);
  const depends = result.stdout.trim();
  assert.match(depends, /^libasound2t64 \| libasound2, /);
  assert.doesNotMatch(depends, /^,|,\s*,|,\s*$/);
});

test('prerm lets a remove or upgrade go on when no helper and no record exist', () => {
  const fixture = maintainerFixture();
  try {
    fs.writeFileSync(fixture.lock, '');
    for (const action of ['remove', 'upgrade', 'deconfigure', 'failed-upgrade']) {
      const result = fixture.run('prerm', [action, '0.2.0'], { FAKE_FLOCK_STATUS: '0' });
      assert.equal(result.status, 0, action + ': ' + result.stderr);
      assert.equal(result.stderr, '');
    }
    const absent = maintainerFixture({ state: false });
    try {
      assert.equal(absent.run('prerm', ['remove']).status, 0);
    } finally {
      absent.remove();
    }
  } finally {
    fixture.remove();
  }
});

test('prerm ignores actions that are not a remove or an upgrade', () => {
  const fixture = maintainerFixture();
  try {
    fs.writeFileSync(fixture.lock, '');
    fs.writeFileSync(fixture.record, stateRecordText('ENGINE', BOOT_NOW));
    for (const action of ['abort-install', 'abort-upgrade', 'configure', '']) {
      const result = fixture.run('prerm', action ? [action] : [], { FAKE_FLOCK_STATUS: '99' });
      assert.equal(result.status, 0, JSON.stringify(action));
    }
  } finally {
    fixture.remove();
  }
});

test('prerm refuses while the helper lock is held and prints exact recovery text', () => {
  const fixture = maintainerFixture();
  try {
    fs.writeFileSync(fixture.lock, '');
    const before = listTree(fixture.work);
    const removal = fixture.run('prerm', ['remove'], { FAKE_FLOCK_STATUS: '99' });
    assert.equal(removal.status, 1);
    assert.equal(removal.stdout, '');
    assert.match(removal.stderr, /refusing to remove the package: the privileged helper is running/);
    assert.ok(removal.stderr.includes('(it holds ' + fixture.lock + ')'));
    assert.match(removal.stderr, /never\s+stops a root tunnel/);
    assert.match(removal.stderr, /1\. Quit HotspotShade/);
    assert.match(removal.stderr, /pgrep -af \/opt\/hotspotshade\/resources\/engine\/hotspotshade/);
    assert.match(removal.stderr, /ip rule show; ip route show table all; ip -6 route show table all/);
    assert.ok(removal.stderr.includes('sudo rm ' + fixture.record));
    assert.match(removal.stderr, /SIGTERM/);
    assert.match(removal.stderr, /Do not use\s+SIGKILL/);
    assert.deepEqual(listTree(fixture.work), before, 'the script changes nothing');

    for (const [action, verb] of [['upgrade', 'upgrade'], ['failed-upgrade', 'upgrade'], ['deconfigure', 'remove']]) {
      const result = fixture.run('prerm', [action, '0.2.0'], { FAKE_FLOCK_STATUS: '99' });
      assert.equal(result.status, 1, action);
      assert.match(result.stderr, new RegExp('refusing to ' + verb + ' the package'), action);
    }
  } finally {
    fixture.remove();
  }
});

test('prerm refuses a same-boot state record even when no helper holds the lock', () => {
  for (const kind of ['ENGINE', 'PENDING']) {
    const fixture = maintainerFixture();
    try {
      fs.writeFileSync(fixture.lock, '');
      fs.writeFileSync(fixture.record, stateRecordText(kind, BOOT_NOW));
      const before = fs.readFileSync(fixture.record, 'utf8');
      const result = fixture.run('prerm', ['remove'], { FAKE_FLOCK_STATUS: '0' });
      assert.equal(result.status, 1, kind);
      assert.match(result.stderr, /an engine state record is present/);
      assert.ok(result.stderr.includes('sudo rm ' + fixture.record));
      assert.equal(fs.readFileSync(fixture.record, 'utf8'), before, 'the record is kept for the person to inspect');
    } finally {
      fixture.remove();
    }
  }
});

test('prerm refuses a record it cannot read as version 2, and a record that is not a plain file', () => {
  const bodies = [
    'HS_ENGINE 1\nBOOT ' + BOOT_NOW + '\n',
    'HS_ENGINE 3\nBOOT ' + BOOT_OLD + '\nNS 4 4\nENGINE 1 2\n',
    'garbage\n',
    'HS_ENGINE 2\nBOOT not-a-uuid\nNS 4 4\nENGINE 1 2\n',
    '',
  ];
  for (const body of bodies) {
    const fixture = maintainerFixture();
    try {
      fs.writeFileSync(fixture.record, body);
      const result = fixture.run('prerm', ['remove'], { FAKE_FLOCK_STATUS: '0' });
      assert.equal(result.status, 1, JSON.stringify(body));
      assert.match(result.stderr, /cannot be shown to be from an earlier boot/);
    } finally {
      fixture.remove();
    }
  }
  const asDirectory = maintainerFixture();
  try {
    fs.mkdirSync(asDirectory.record);
    assert.equal(asDirectory.run('prerm', ['remove']).status, 1);
    fs.rmSync(asDirectory.record, { recursive: true });
    fs.symlinkSync(path.join(asDirectory.work, 'elsewhere'), asDirectory.record);
    const linked = asDirectory.run('prerm', ['remove']);
    assert.equal(linked.status, 1);
    assert.match(linked.stderr, /symbolic link/);
  } finally {
    asDirectory.remove();
  }
});

test('prerm does not block on a record from an earlier boot', () => {
  const fixture = maintainerFixture();
  try {
    fs.writeFileSync(fixture.lock, '');
    fs.writeFileSync(fixture.record, stateRecordText('ENGINE', BOOT_OLD));
    const result = fixture.run('prerm', ['remove'], { FAKE_FLOCK_STATUS: '0' });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(fs.existsSync(fixture.record), 'prerm never deletes the record');
  } finally {
    fixture.remove();
  }
});

test('prerm fails closed when the lock cannot be checked', () => {
  const fixture = maintainerFixture();
  try {
    fs.writeFileSync(fixture.lock, '');
    const failed = fixture.run('prerm', ['remove'], { FAKE_FLOCK_STATUS: '1' });
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /helper lock could not be checked \(flock exit 1\)/);

    const noFlock = path.join(fixture.work, 'noflock');
    fs.mkdirSync(noFlock);
    for (const tool of ['sed', 'head', 'tr']) {
      for (const directory of ['/usr/bin', '/bin']) {
        if (fs.existsSync(path.join(directory, tool))) {
          fs.symlinkSync(path.join(directory, tool), path.join(noFlock, tool));
          break;
        }
      }
    }
    const result = spawnSync(POSIX_SHELL, [fixture.scripts.prerm, 'remove'], {
      encoding: 'utf8',
      env: { PATH: noFlock },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /flock command is missing/);

    fs.rmSync(fixture.lock);
    fs.symlinkSync(path.join(fixture.work, 'elsewhere'), fixture.lock);
    const linked = fixture.run('prerm', ['remove']);
    assert.equal(linked.status, 1);
    assert.match(linked.stderr, /symbolic link/);
  } finally {
    fixture.remove();
  }
});

test('prerm refuses when its own check dies half way instead of reading silence as safe', () => {
  const fixture = maintainerFixture();
  try {
    fs.writeFileSync(fixture.lock, '');
    /* A record from an earlier boot would let the change through. A sed that
     * fails while parsing it must turn into a refusal, not into an empty
     * answer that reads as safe. */
    fs.writeFileSync(fixture.record, stateRecordText('ENGINE', BOOT_OLD));
    const broken = path.join(fixture.work, 'brokenbin');
    fs.mkdirSync(broken);
    fs.writeFileSync(path.join(broken, 'sed'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const result = spawnSync(POSIX_SHELL, [fixture.scripts.prerm, 'remove'], {
      encoding: 'utf8',
      env: { PATH: broken + ':' + path.join(fixture.work, 'bin') + ':/usr/bin:/bin', FAKE_FLOCK_STATUS: '0' },
    });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /refusing to remove the package/);
    assert.match(result.stderr, /safety check itself failed/);
  } finally {
    fixture.remove();
  }
});

test('a lock path that is not a regular file is refused without opening it', () => {
  const fixture = maintainerFixture();
  try {
    execFileSync('mkfifo', [fixture.lock]);
    const prerm = fixture.run('prerm', ['remove'], { FAKE_FLOCK_STATUS: '0' });
    assert.equal(prerm.status, 1);
    assert.match(prerm.stderr, /not a regular file/);
    const postrm = fixture.run('postrm', ['purge'], { FAKE_FLOCK_STATUS: '0' });
    assert.equal(postrm.status, 0);
    assert.match(postrm.stderr, /not a regular file/);
    assert.ok(fs.existsSync(fixture.stateDir), 'the directory is kept');
  } finally {
    fixture.remove();
  }
});

test('a postrm purge that cannot remove the directory warns and still exits 0', () => {
  const fixture = maintainerFixture();
  try {
    populateState(fixture);
    const broken = path.join(fixture.work, 'brokenbin');
    fs.mkdirSync(broken);
    fs.writeFileSync(path.join(broken, 'rm'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const result = spawnSync(POSIX_SHELL, [fixture.scripts.postrm, 'purge'], {
      encoding: 'utf8',
      env: { PATH: broken + ':' + path.join(fixture.work, 'bin') + ':/usr/bin:/bin', FAKE_FLOCK_STATUS: '0' },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stderr, /could not be fully removed/);
  } finally {
    fixture.remove();
  }
});

const realFlock = realFlockPath();
const onLinux = process.platform === 'linux';

test(
  'prerm sees a lock that a real flock process holds',
  { skip: (!realFlock || !onLinux) && 'needs util-linux flock on Linux' },
  async () => {
    const fixture = maintainerFixture();
    fs.writeFileSync(fixture.lock, '');
    const holder = spawn(realFlock, ['-x', '-n', fixture.lock, 'sleep', '30'], { stdio: 'ignore' });
    try {
      await new Promise((resolve) => setTimeout(resolve, 300));
      const real = { PATH: '/usr/bin:/bin', HOME: fixture.work };
      const held = spawnSync(POSIX_SHELL, [fixture.scripts.prerm, 'remove'], { encoding: 'utf8', env: real });
      assert.equal(held.status, 1, held.stderr);
      assert.match(held.stderr, /the privileged helper is running/);
      holder.kill('SIGTERM');
      await new Promise((resolve) => holder.once('exit', resolve));
      const free = spawnSync(POSIX_SHELL, [fixture.scripts.prerm, 'remove'], { encoding: 'utf8', env: real });
      assert.equal(free.status, 0, free.stderr);
    } finally {
      if (holder.exitCode === null) holder.kill('SIGKILL');
      fixture.remove();
    }
  },
);

function populateState(fixture) {
  fs.writeFileSync(path.join(fixture.stateDir, 'identity.key'), 'root identity key\n');
  fs.writeFileSync(path.join(fixture.stateDir, 'trust.json'), '{}\n');
  fs.writeFileSync(fixture.lock, '');
}

test('postrm removes the state directory on purge only', () => {
  for (const action of ['remove', 'upgrade', 'failed-upgrade', 'abort-install', 'abort-upgrade', 'disappear']) {
    const fixture = maintainerFixture();
    try {
      populateState(fixture);
      fs.writeFileSync(fixture.record, stateRecordText('PENDING', BOOT_OLD));
      const before = listTree(fixture.work);
      const result = fixture.run('postrm', [action], { FAKE_FLOCK_STATUS: '0' });
      assert.equal(result.status, 0, action);
      assert.deepEqual(listTree(fixture.work), before, action + ' must keep every state file');
    } finally {
      fixture.remove();
    }
  }
  const fixture = maintainerFixture();
  try {
    populateState(fixture);
    fs.writeFileSync(fixture.record, stateRecordText('PENDING', BOOT_OLD));
    const result = fixture.run('postrm', ['purge'], { FAKE_FLOCK_STATUS: '0' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    assert.ok(!fs.existsSync(fixture.stateDir), 'purge removes the key, the trust list, and the stale record');
  } finally {
    fixture.remove();
  }
});

test('postrm purge with the state directory already gone succeeds', () => {
  const fixture = maintainerFixture({ state: false });
  try {
    const result = fixture.run('postrm', ['purge']);
    assert.equal(result.status, 0, result.stderr);
  } finally {
    fixture.remove();
  }
});

test('postrm purge keeps the directory while a helper runs or a same-boot record remains', () => {
  const cases = [
    { name: 'locked', flock: '99', record: null, message: /privileged helper is still running/ },
    { name: 'lock check failed', flock: '1', record: null, message: /could not be checked/ },
    { name: 'engine record', flock: '0', record: stateRecordText('ENGINE', BOOT_NOW), message: /record from this boot remains/ },
    { name: 'pending record', flock: '0', record: stateRecordText('PENDING', BOOT_NOW), message: /record from this boot remains/ },
    { name: 'unreadable record', flock: '0', record: 'HS_ENGINE 1\n', message: /record from this boot remains/ },
  ];
  for (const item of cases) {
    const fixture = maintainerFixture();
    try {
      populateState(fixture);
      if (item.record) fs.writeFileSync(fixture.record, item.record);
      const before = listTree(fixture.work);
      const result = fixture.run('postrm', ['purge'], { FAKE_FLOCK_STATUS: item.flock });
      assert.equal(result.status, 0, item.name + ': a failing postrm would leave the package half-purged');
      assert.match(result.stderr, item.message, item.name);
      assert.ok(result.stderr.includes('sudo rm -rf ' + fixture.stateDir), item.name);
      assert.deepEqual(listTree(fixture.work), before, item.name + ' must delete nothing');
    } finally {
      fixture.remove();
    }
  }
});

test('postrm purge never follows a symbolic link and never touches user files', () => {
  const fixture = maintainerFixture({ state: false });
  try {
    const target = path.join(fixture.work, 'precious');
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, 'data'), 'keep\n');
    fs.symlinkSync(target, fixture.stateDir);
    const home = path.join(fixture.work, 'home');
    fs.mkdirSync(path.join(home, '.config/autostart'), { recursive: true });
    fs.mkdirSync(path.join(home, '.config/HotspotShade'), { recursive: true });
    fs.writeFileSync(path.join(home, '.config/autostart/hotspotshade.desktop'), '[Desktop Entry]\n');
    fs.writeFileSync(path.join(home, '.config/HotspotShade/settings.json'), '{}\n');
    const result = fixture.run('postrm', ['purge'], { FAKE_FLOCK_STATUS: '0', HOME: home });
    assert.equal(result.status, 0);
    assert.match(result.stderr, /symbolic link; it was not removed/);
    assert.ok(fs.existsSync(path.join(target, 'data')));
    assert.ok(fs.existsSync(path.join(home, '.config/autostart/hotspotshade.desktop')));
    assert.ok(fs.existsSync(path.join(home, '.config/HotspotShade/settings.json')));
    fs.unlinkSync(fixture.stateDir);

    fs.mkdirSync(fixture.stateDir);
    fs.writeFileSync(path.join(fixture.stateDir, 'identity.key'), 'k\n');
    const purged = fixture.run('postrm', ['purge'], { FAKE_FLOCK_STATUS: '0', HOME: home });
    assert.equal(purged.status, 0);
    assert.ok(!fs.existsSync(fixture.stateDir));
    assert.ok(fs.existsSync(path.join(home, '.config/autostart/hotspotshade.desktop')), 'the autostart entry stays');
    assert.ok(fs.existsSync(path.join(home, '.config/HotspotShade/settings.json')), 'user settings stay');
  } finally {
    fixture.remove();
  }
});

test('a built package carries executable postinst, prerm, and postrm scripts', { skip: !dpkgDeb && 'dpkg-deb is not available' }, () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'hotspotshade-maint-deb-'));
  try {
    const stage = path.join(work, 'stage');
    fs.mkdirSync(path.join(stage, 'DEBIAN'), { recursive: true });
    for (const name of ['postinst', 'prerm', 'postrm']) {
      fs.copyFileSync(path.join(root, 'packaging/debian', name), path.join(stage, 'DEBIAN', name));
      fs.chmodSync(path.join(stage, 'DEBIAN', name), 0o755);
    }
    fs.writeFileSync(
      path.join(stage, 'DEBIAN/control'),
      'Package: hotspotshade\nVersion: 0.0.0\nArchitecture: all\nMaintainer: x\nDescription: x\n',
    );
    const deb = path.join(work, 'x.deb');
    execFileSync('dpkg-deb', ['--build', '--root-owner-group', stage, deb], { stdio: 'ignore' });
    const out = path.join(work, 'control');
    execFileSync('dpkg-deb', ['-e', deb, out]);
    for (const name of ['postinst', 'prerm', 'postrm']) {
      const mode = fs.statSync(path.join(out, name)).mode & 0o777;
      assert.equal(mode, 0o755, name);
    }
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

test('the helper never uses println for protocol lines and reports a reason line on exit 1', () => {
  const source = read('helper/src/main.rs');
  const production = source.slice(0, source.indexOf('#[cfg(test)]\nmod tests'));
  assert.doesNotMatch(production, /(^|[^a-z_])println!\(/m, 'println! panics on EPIPE');
  const eprints = production.match(/(^|[^a-z_])eprintln!\(/gm) || [];
  assert.equal(eprints.length, 0, 'eprintln! panics when stderr is a closed pipe');
  assert.match(production, /announce\("HS_READY"\)/);
  assert.match(production, /announce\(&format!\("HS_PORT \{port\}"\)\)/);
  assert.match(production, /fn fail_reason\(/);
  assert.match(production, /HS_REASON \{reason\}/);
  assert.doesNotMatch(production, /fail\("/, 'every exit 1 path carries a reason line');
});

test('the README describes the package truthfully', () => {
  const readme = read('README.md');
  assert.doesNotMatch(readme, /The helper is the only root process/);
  assert.match(readme, /HS_AUTOSTART_DIR/);
  assert.match(readme, /prerm/);
  assert.match(readme, /purge/);
  assert.match(readme, /Debian and Ubuntu only/);
  assert.match(readme, /polkit authentication agent/);
});
