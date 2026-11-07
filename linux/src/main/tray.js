'use strict';

/* The Linux tray item.
 *
 * Electron uses StatusNotifierItem on a desktop with a status notifier host.
 * On a desktop without one, the Tray constructor fails and the app continues
 * without a tray item. The window close then quits the app, as before.
 *
 * The menu holds Start, Stop, Open, and Quit only. The state comes from the
 * real backend status. The icon is the local app icon.
 */

const TRAY_SIZE = 22;

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function trayState(status, pair, unavailable, tunnelMode) {
  const data = isPlainObject(status) ? status : null;
  const pairing = isPlainObject(pair) ? pair : null;
  const running = !!data && data.running === true;
  const runningKnown = !!data && typeof data.running === 'boolean';
  const pairingKnown = !!data && typeof data.paired === 'boolean';
  const paired = !!data && data.paired === true;
  const phone = data && isPlainObject(data.phone) ? data.phone : {};
  const demo = !!data && data.demo === true;
  const unknown = !!data && data.state === 'unknown';
  const direct = tunnelMode === 'direct';
  const blocked = unavailable === true || unknown || (!!data && !runningKnown) ||
    (!!data && data.cleanup_blocked === true);
  let label = 'Starting';
  if (blocked) {
    /* A configured engine that cannot run has no status to report. "Starting"
     * would be wrong forever, so the tray says that it is not available. */
    label = 'Not available';
  } else if (data) {
    if (running) label = 'Tunnel on';
    else if (direct) label = 'Ready';
    else if (!pairingKnown) label = 'Not available';
    else if (paired && phone.state === 'not_trusted') label = 'Not trusted';
    else if (paired) label = 'Ready';
    else label = 'Not paired';
  }
  if (demo) label += ' (demo)';
  return {
    label: label,
    demo: demo,
    tooltip: 'HotspotShade. ' + label + '.',
    startEnabled: !blocked && !!data && (direct || paired) && !running && !!pairing && pairing.state !== 'connecting' && pairing.state !== 'confirm' && pairing.state !== 'starting',
    stopEnabled: running && unavailable !== true,
    stopIsAttempt: blocked && running && unavailable !== true
  };
}

function createTrayMenuTemplate(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const state = trayState(settings.status, settings.pair, settings.unavailable, settings.tunnelMode);
  const onStart = typeof settings.onStart === 'function' ? settings.onStart : function () {};
  const onStop = typeof settings.onStop === 'function' ? settings.onStop : function () {};
  const onOpen = typeof settings.onOpen === 'function' ? settings.onOpen : function () {};
  const onQuit = typeof settings.onQuit === 'function' ? settings.onQuit : function () {};
  return [
    {
      label: 'HotspotShade. ' + state.label,
      enabled: false
    },
    { type: 'separator' },
    {
      label: state.demo ? 'Start simulated tunnel' : 'Start tunnel',
      enabled: state.startEnabled,
      click: onStart
    },
    {
      label: state.stopIsAttempt ? 'Try to turn off' : (state.demo ? 'Stop simulated tunnel' : 'Stop tunnel'),
      enabled: state.stopEnabled,
      click: onStop
    },
    { type: 'separator' },
    {
      label: 'Open HotspotShade',
      click: onOpen
    },
    {
      label: 'Quit HotspotShade',
      click: onQuit
    }
  ];
}

function createTrayIcon(nativeImage, iconPath) {
  if (!nativeImage || typeof nativeImage.createFromPath !== 'function') return null;
  if (typeof iconPath !== 'string' || !iconPath) return null;
  let image;
  try {
    image = nativeImage.createFromPath(iconPath);
  } catch (error) {
    return null;
  }
  if (!image || typeof image.isEmpty !== 'function' || image.isEmpty()) return null;
  try {
    return image.resize({ width: TRAY_SIZE, height: TRAY_SIZE });
  } catch (error) {
    return image;
  }
}

function createTray(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const Tray = settings.Tray;
  const Menu = settings.Menu;
  const nativeImage = settings.nativeImage;
  const iconPath = settings.iconPath;
  const onStart = settings.onStart;
  const onStop = settings.onStop;
  const onOpen = settings.onOpen;
  const onQuit = settings.onQuit;
  const onError = typeof settings.onError === 'function' ? settings.onError : function () {};
  const getTunnelMode = typeof settings.getTunnelMode === 'function' ? settings.getTunnelMode : function () { return 'phone'; };

  if (typeof Tray !== 'function' || !Menu || typeof Menu.buildFromTemplate !== 'function') {
    return unavailable();
  }

  const icon = createTrayIcon(nativeImage, iconPath);
  if (!icon) return unavailable();

  let tray = null;
  try {
    tray = new Tray(icon);
  } catch (error) {
    onError(error);
    return unavailable();
  }

  let current = trayState(null, null);
  let lastState = { status: null, pair: null };

  function selectedMode() {
    try { return getTunnelMode() === 'direct' ? 'direct' : 'phone'; }
    catch (error) { onError(error); return 'phone'; }
  }

  function apply(state) {
    lastState = state || { status: null, pair: null };
    const mode = selectedMode();
    current = trayState(lastState.status, lastState.pair, lastState.unavailable, mode);
    try {
      tray.setToolTip(current.tooltip);
    } catch (error) {
      onError(error);
    }
    const menu = Menu.buildFromTemplate(createTrayMenuTemplate({
      status: state && state.status,
      pair: state && state.pair,
      unavailable: state && state.unavailable,
      tunnelMode: mode,
      onStart: function () {
        // A setting can change between menu construction and the click.
        if (trayState(lastState.status, lastState.pair, lastState.unavailable, selectedMode()).startEnabled && typeof onStart === 'function') onStart();
      },
      onStop: onStop,
      onOpen: onOpen,
      onQuit: onQuit
    }));
    try {
      tray.setContextMenu(menu);
    } catch (error) {
      onError(error);
    }
  }

  try {
    tray.on('click', function () {
      if (typeof onOpen === 'function') onOpen();
    });
  } catch (error) {
    /* A desktop can ignore the click event. The Open row still works. */
  }

  apply({ status: null, pair: null });

  return Object.freeze({
    available: true,
    update: function (state) { apply(state); },
    destroy: function () {
      try {
        tray.destroy();
      } catch (error) {
        /* Best effort. */
      }
    },
    state: function () { return current; }
  });

  function unavailable() {
    return Object.freeze({
      available: false,
      update: function () {},
      destroy: function () {},
      state: function () { return currentOrStarting(); }
    });
  }

  function currentOrStarting() {
    return trayState(null, null);
  }
}

module.exports = {
  TRAY_SIZE: TRAY_SIZE,
  createTray: createTray,
  createTrayIcon: createTrayIcon,
  createTrayMenuTemplate: createTrayMenuTemplate,
  trayState: trayState
};
