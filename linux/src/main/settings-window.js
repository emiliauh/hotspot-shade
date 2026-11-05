'use strict';

/* The separate Settings window.
 *
 * It loads the same local page as the main window. The preload reports the
 * window kind, and the page hides the sidebar and shows the Settings sections.
 * The window uses the same sandbox, isolation, and session policy as the main
 * window. It is not a modal dialog, so the person can read the status while a
 * settings change finishes.
 */

const path = require('node:path');
const { SAFE_WEB_PREFERENCES } = require('./security');

const WINDOW_KIND_ARGUMENT = '--hs-window-kind=settings';

function createSettingsWindow(options) {
  const settings = options && typeof options === 'object' ? options : {};
  const BrowserWindow = settings.BrowserWindow;
  const appRoot = settings.appRoot;
  const preloadPath = settings.preloadPath;
  const iconPath = settings.iconPath;
  const parent = settings.parent;

  if (!BrowserWindow) throw new TypeError('BrowserWindow is required.');
  if (typeof appRoot !== 'string' || !appRoot) throw new TypeError('The app root is required.');
  if (typeof preloadPath !== 'string' || !preloadPath) throw new TypeError('The preload path is required.');

  const window = new BrowserWindow({
    width: 640,
    height: 680,
    minWidth: 520,
    minHeight: 480,
    useContentSize: true,
    show: false,
    center: true,
    title: 'HotspotShade Settings',
    frame: true,
    titleBarStyle: 'default',
    autoHideMenuBar: true,
    parent: parent || undefined,
    icon: iconPath,
    backgroundColor: '#f6f6f8',
    webPreferences: Object.assign({}, SAFE_WEB_PREFERENCES, {
      preload: preloadPath,
      additionalArguments: [WINDOW_KIND_ARGUMENT]
    })
  });

  window.setMenuBarVisibility(false);
  window.once('ready-to-show', function () {
    window.show();
    window.focus();
  });

  window.loadFile(path.join(appRoot, 'index.html'));
  return window;
}

module.exports = {
  WINDOW_KIND_ARGUMENT: WINDOW_KIND_ARGUMENT,
  createSettingsWindow: createSettingsWindow
};
