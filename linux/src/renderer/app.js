/* HotspotShade for Linux page.
 *
 * The page talks only to the narrow preload bridge. The main process selects
 * the in-memory demo backend or the local engine service. This file opens no
 * listener, starts no process, and makes no network request. It never holds
 * an engine secret or a pairing token.
 */
(function () {
  'use strict';

  var api = window.hotspotshade;
  var model = window.HotspotShadeModel;
  var THEME_KEY = 'hs-linux-theme';
  var PING_KEY = 'hs-linux-ping';
  var POLL_VISIBLE_MS = 1000;
  var POLL_HIDDEN_MS = 5000;
  var PAIR_POLL_MS = 450;
  var ACTION_WAIT_MS = 5000;
  var VIEWS = ['dashboard', 'activity', 'settings'];
  var SETTINGS_TABS = ['general', 'pairing', 'advanced'];
  var SCENARIOS = ['ready', 'source-stopped', 'not-trusted', 'reset'];
  var TITLES = { dashboard: 'Dashboard', activity: 'Activity', settings: 'Settings' };
  var settingsWindowMode = !!(api && api.windowKind === 'settings');

  var dom = {};
  var state = {
    view: 'dashboard',
    settingsTab: 'general',
    bridgeState: 'starting',
    bridgeError: null,
    bootstrap: null,
    status: null,
    hasStatus: false,
    pair: null,
    busy: null,
    error: null,
    retryAction: null,
    forgetBlocked: false,
    failureSince: null,
    freshness: 'fresh',
    ping: storedPing(),
    settings: {
      notifications: true,
      notificationsSupported: true,
      launchAtLogin: false,
      launchAtLoginAvailable: false,
      ping: true
    },
    themePreference: storedTheme(),
    logs: [],
    lastSeq: 0,
    activityDetails: false,
    activityLoading: false,
    activityLoaded: false,
    activityError: null,
    failures: null,
    failuresLoaded: false,
    failuresLoading: false,
    failureReport: '',
    statusInFlight: false,
    statusQueued: false,
    statusPromise: null,
    engineConnected: false,
    pollTimer: null,
    pairTimer: null,
    copyTimer: null,
    manualRefreshing: false
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function text(value) {
    return typeof value === 'string' ? value : '';
  }

  function object(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }

  function storedTheme() {
    try {
      var saved = localStorage.getItem(THEME_KEY);
      if (saved === 'system' || saved === 'light' || saved === 'dark') return saved;
    } catch (error) {
      return 'system';
    }
    return 'system';
  }

  function storedPing() {
    try {
      var saved = localStorage.getItem(PING_KEY);
      if (saved === 'true') return true;
      if (saved === 'false') return false;
    } catch (error) {
      return true;
    }
    return true;
  }

  function systemDark() {
    try {
      return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    } catch (error) {
      return false;
    }
  }

  function systemHighContrast() {
    try {
      if (!window.matchMedia) return false;
      return window.matchMedia('(prefers-contrast: more)').matches
        || window.matchMedia('(forced-colors: active)').matches;
    } catch (error) {
      return false;
    }
  }

  function applyContrast() {
    var high = systemHighContrast();
    document.documentElement.setAttribute('data-contrast', high ? 'high' : 'normal');
    return high;
  }

  function adoptSettings(value) {
    var settings = object(value);
    state.settings = {
      notifications: settings.notifications === true,
      notificationsSupported: settings.notificationsSupported === true,
      launchAtLogin: settings.launchAtLogin === true,
      launchAtLoginAvailable: settings.launchAtLoginAvailable === true,
      ping: settings.ping === true
    };
    state.ping = state.settings.ping;
  }

  function effectiveTheme(preference) {
    if (preference === 'light' || preference === 'dark') return preference;
    return systemDark() ? 'dark' : 'light';
  }

  function errorMessage(error) {
    if (error && typeof error.message === 'string' && error.message) return model.sanitized(error.message);
    return 'The request failed.';
  }

  function errorCode(error) {
    return error && typeof error.code === 'string' ? error.code : '';
  }

  function engineMode() {
    return !!(state.bootstrap && state.bootstrap.mode === 'engine');
  }

  function simulatedData() {
    if (!state.bootstrap) return false;
    if (state.bootstrap.mode === 'demo') return true;
    return object(state.status).demo === true;
  }

  /* Use live text for the engine backend and demo text for the demo backend. */
  function wording(live, demo) {
    return simulatedData() ? demo : live;
  }

  function bridgeReady() {
    return state.bridgeState === 'ready';
  }

  function setText(element, value) {
    if (element && element.textContent !== value) element.textContent = value;
  }

  function renderList(element, lines) {
    if (!element) return;
    element.textContent = '';
    lines.forEach(function (line) {
      var item = document.createElement('li');
      item.textContent = line;
      element.appendChild(item);
    });
  }

  function nowSeconds() {
    return Date.now() / 1000;
  }

  function currentFreshness() {
    return model.statusFreshness(state.failureSince, Date.now(), state.hasStatus);
  }

  function pairingIsActive(pair) {
    var value = text(object(pair).state);
    return value === 'connecting' || value === 'confirm' || value === 'starting';
  }

  function call(method) {
    var args = Array.prototype.slice.call(arguments, 1);
    return api[method].apply(api, args).then(function (result) {
      if (result && result.ok === true) return result.data;
      var error = new Error(
        result && result.error && typeof result.error.message === 'string'
          ? result.error.message
          : 'The request failed.'
      );
      error.code = result && result.error && typeof result.error.code === 'string'
        ? result.error.code
        : 'internal';
      throw error;
    });
  }

  function updateSetting(name, value) {
    if (!api || typeof api.updateSetting !== 'function') return Promise.reject(new Error('The setting is not available.'));
    return call('updateSetting', name, value).then(function (data) {
      adoptSettings(data);
      render();
      return data;
    });
  }

  function init() {
    [
      'demoPill', 'demoBanner', 'demoBannerText', 'demoLine', 'demoDetails', 'platformBadge', 'platformText',
      'themeToggle', 'refreshButton', 'mainContent', 'versionLabel', 'navStatusDot', 'contextLabel',
      'view-dashboard', 'view-activity', 'view-settings',
      'dashboardContent', 'statusDot', 'dashboardTitle', 'dashboardSubtitle',
      'dashboardChecked', 'primaryAction', 'secondaryAction', 'pairHint',
      'sourceValue', 'sourceDetails', 'connectionValue', 'connectionDetails',
      'attentionCard', 'attentionList',
      'pairingPanel', 'pairingPanelTitle', 'pairingMessage',
      'pairCodeBlock', 'pairCode', 'waitingForCode', 'copyCode', 'cancelPairing',
      'pairingSimulatedNote', 'pairingSimulatedCard', 'pairingSimulatedBody',
      'activityTitle', 'activitySubtitle', 'activityDetailsToggle', 'activityRefresh',
      'activityState', 'activityStateIcon', 'activitySpinner', 'activityStateTitle',
      'activityStateText', 'activityRetry', 'activityList', 'activityNote',
      'settingsTabGeneral', 'settingsTabPairing', 'settingsTabAdvanced', 'settingsSubtitle',
      'settingsGeneralPanel', 'settingsPairingPanel', 'settingsAdvancedPanel',
      'pingToggle', 'pingHelp', 'loginToggle', 'loginHelp', 'notificationsToggle',
      'notificationsHelp', 'notificationsStatus', 'appearanceHelp',
      'settingsPairingState', 'settingsPairingMessage',
      'settingsPair', 'settingsCancel', 'settingsForget', 'settingsTurnOffForget',
      'settingsPairReason', 'settingsForgetMessage',
      'failuresRefresh', 'copyFailures', 'failuresSummary', 'failuresSubtitle', 'failuresTable',
      'failuresBody', 'failuresEmpty', 'wifiAdvice',
      'modeCard', 'modeCardTitle', 'modeCardBody', 'demoScenario', 'applyScenario', 'appVersion', 'appPlatform', 'appMode',
      'appStatus', 'appBoundary', 'appTunnel', 'copyDiagnostics', 'copyState',
      'demoLimits', 'demoLimitsNote', 'engineLimits', 'demoScenariosCard', 'toastRegion'
    ].forEach(function (id) { dom[id] = byId(id); });

    wireEvents();
    applyContrast();
    applyTheme(state.themePreference, false);
    if (settingsWindowMode) {
      document.documentElement.setAttribute('data-window', 'settings');
      setView('settings', false);
    } else {
      document.documentElement.setAttribute('data-window', 'main');
      setView(viewFromHash(), false);
    }

    if (!api || typeof api.status !== 'function' || typeof api.bootstrap !== 'function') {
      state.bridgeState = 'failed';
      state.bridgeError = 'The app bridge is unavailable. Start the app with Electron.';
      render();
      return;
    }

    loadBootstrap().then(function () {
      if (!bridgeReady()) return;
      return Promise.all([refreshStatus(), refreshPair()]).then(function () {
        schedulePoll();
        window.setInterval(function () {
          var freshness = currentFreshness();
          if (freshness !== state.freshness) {
            state.freshness = freshness;
            render();
          }
        }, 1000);
      });
    });
  }

  /* ------------------------------- bootstrap ------------------------------ */

  function loadBootstrap() {
    state.bridgeState = 'starting';
    state.bridgeError = null;
    render();
    return call('bootstrap').then(function (info) {
      if (!info || (info.mode !== 'demo' && info.mode !== 'engine')) {
        state.bridgeState = 'failed';
        state.bridgeError = 'This app does not know the selected backend mode.';
        render();
        return;
      }
      state.bootstrap = object(info);
      adoptSettings(info.settings);
      state.bridgeState = 'ready';
      state.bridgeError = null;
      render();
    }).catch(function (error) {
      state.bridgeState = 'failed';
      state.bridgeError = errorMessage(error);
      render();
    });
  }

  /* -------------------------------- status -------------------------------- */

  function adoptPairState() {
    var status = object(state.status);
    var pair = object(state.pair);
    var phase = text(pair.state);
    if (status.paired === true && !phase) {
      state.pair = { state: 'paired' };
    } else if (status.paired === false && phase === 'paired' && !state.busy) {
      state.pair = { state: 'idle' };
    }
  }

  function refreshStatus() {
    if (!bridgeReady()) return Promise.resolve();
    if (state.statusInFlight) {
      state.statusQueued = true;
      return state.statusPromise || Promise.resolve();
    }
    state.statusInFlight = true;
    state.statusPromise = call('status').then(function (data) {
      state.status = object(data);
      state.hasStatus = true;
      state.failureSince = null;
      state.freshness = 'fresh';
      if (engineMode()) state.engineConnected = true;
      if (data.running !== true && state.busy !== 'forget') state.forgetBlocked = false;
      adoptPairState();
      if (state.error && state.retryAction === 'checkNow') {
        state.error = null;
        state.retryAction = null;
      }
      if (typeof data.error === 'string' && data.error && !state.error) {
        state.error = model.sanitized(data.error);
        state.retryAction = 'checkNow';
      }
      render();
    }).catch(function (error) {
      if (!state.failureSince) state.failureSince = Date.now();
      state.freshness = currentFreshness();
      if (engineMode()) state.engineConnected = false;
      if (engineMode() && errorCode(error) === 'engine_stopped') {
        state.error = errorMessage(error);
        state.retryAction = 'checkNow';
      }
      if (!state.hasStatus) {
        state.error = errorMessage(error);
        state.retryAction = 'checkNow';
      }
      render();
    }).then(function () {
      state.statusInFlight = false;
      state.statusPromise = null;
      if (state.statusQueued) {
        state.statusQueued = false;
        return refreshStatus();
      }
      return undefined;
    });
    return state.statusPromise;
  }

  function refreshPair() {
    if (!bridgeReady()) return Promise.resolve();
    return call('pairState').then(function (data) {
      state.pair = object(data);
      adoptPairState();
      render();
    }).catch(function () {
      /* The status poll still reports the saved pairing. */
    });
  }

  function refreshAll() {
    if (state.manualRefreshing || !bridgeReady()) return Promise.resolve();
    state.manualRefreshing = true;
    renderRefreshButton();
    return Promise.all([refreshStatus(), refreshPair()]).then(function () {
      if (state.view === 'activity') return loadLogs(true);
      if (state.view === 'settings' && state.settingsTab === 'advanced') return loadFailures();
      return undefined;
    }).then(function () {
      state.manualRefreshing = false;
      renderRefreshButton();
    }, function () {
      state.manualRefreshing = false;
      renderRefreshButton();
    });
  }

  function schedulePoll() {
    if (state.pollTimer) window.clearTimeout(state.pollTimer);
    var delay = document.visibilityState === 'visible' ? POLL_VISIBLE_MS : POLL_HIDDEN_MS;
    state.pollTimer = window.setTimeout(function () {
      refreshStatus().then(schedulePoll, schedulePoll);
    }, delay);
  }

  function waitForStatus(predicate, timeoutMilliseconds) {
    var started = Date.now();
    return new Promise(function (resolve) {
      function check() {
        refreshStatus().then(function () {
          var status = object(state.status);
          if (predicate(status)) {
            resolve(true);
            return;
          }
          if (Date.now() - started >= timeoutMilliseconds) {
            resolve(false);
            return;
          }
          window.setTimeout(check, 250);
        });
      }
      check();
    });
  }

  /* -------------------------------- actions ------------------------------- */

  function toast(title, message) {
    if (!dom.toastRegion) return;
    while (dom.toastRegion.children.length >= 4) {
      dom.toastRegion.removeChild(dom.toastRegion.firstChild);
    }
    var node = document.createElement('div');
    node.className = 'toast';

    var content = document.createElement('div');
    content.className = 'toast-content';
    var heading = document.createElement('span');
    heading.className = 'toast-title';
    heading.textContent = title;
    content.appendChild(heading);
    if (message) {
      var copy = document.createElement('span');
      copy.className = 'toast-message';
      copy.textContent = message;
      content.appendChild(copy);
    }

    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'toast-close';
    close.setAttribute('aria-label', 'Close message');
    var icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.setAttribute('fill', 'none');
    icon.setAttribute('stroke', 'currentColor');
    icon.setAttribute('stroke-width', '2');
    icon.setAttribute('aria-hidden', 'true');
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'm6 6 12 12M18 6 6 18');
    icon.appendChild(path);
    close.appendChild(icon);

    node.appendChild(content);
    node.appendChild(close);
    dom.toastRegion.appendChild(node);

    var timer = window.setTimeout(function () {
      dismissToast(node);
    }, 5000);

    close.addEventListener('click', function () {
      window.clearTimeout(timer);
      dismissToast(node);
    });
  }

  function dismissToast(node) {
    if (!node || !node.parentNode) return;
    node.classList.add('is-leaving');
    window.setTimeout(function () {
      if (node.parentNode) node.parentNode.removeChild(node);
    }, 150);
  }

  function beginAction(kind) {
    state.busy = kind;
    state.error = null;
    state.retryAction = null;
    render();
  }

  function failAction(kind, error, title) {
    state.busy = null;
    state.error = errorMessage(error);
    state.retryAction = kind;
    render();
    toast(title || 'The action did not finish', state.error);
  }

  function startTunnel(quiet) {
    if (state.busy || !bridgeReady()) return Promise.resolve(false);
    beginAction('start');
    return call('start', { ping: state.ping }).then(function () {
      return waitForStatus(function (status) { return status.running === true; }, ACTION_WAIT_MS);
    }).then(function (finished) {
      state.busy = null;
      if (!finished) {
        state.error = wording('The start did not finish. Check the status.', 'The simulated start did not finish. Check the status.');
        state.retryAction = 'start';
        render();
        return false;
      }
      return refreshStatus().then(function () {
        if (!quiet) toast(
          wording('Tunnel started', 'Simulated tunnel started'),
          wording('The engine reports the tunnel is on.', 'The demo session is simulated. No route, TUN device, or outer socket was created.')
        );
        return true;
      });
    }).catch(function (error) {
      failAction('start', error, wording('The start did not finish', 'The simulated start did not finish'));
      return false;
    });
  }

  function stopTunnel(quiet) {
    if (state.busy || !bridgeReady()) return Promise.resolve(false);
    beginAction('stop');
    return call('stop').then(function () {
      return waitForStatus(function (status) { return status.running === false; }, ACTION_WAIT_MS);
    }).then(function (finished) {
      state.busy = null;
      if (!finished) {
        state.error = wording('The stop did not finish. Check the status.', 'The simulated stop did not finish. Check the status.');
        state.retryAction = 'stop';
        render();
        return false;
      }
      return refreshStatus().then(function () {
        if (!quiet) toast(
          wording('Tunnel stopped', 'Simulated tunnel stopped'),
          wording('The engine reports the tunnel is off.', 'No route or device changed.')
        );
        return true;
      });
    }).catch(function (error) {
      failAction('stop', error, wording('The stop did not finish', 'The simulated stop did not finish'));
      return false;
    });
  }

  function clearPairPoll() {
    if (state.pairTimer) {
      window.clearTimeout(state.pairTimer);
      state.pairTimer = null;
    }
  }

  function pollPair() {
    clearPairPoll();
    state.pairTimer = window.setTimeout(function () {
      call('pairState').then(function (data) {
        state.pair = object(data);
        var active = pairingIsActive(state.pair);
        render();
        if (active) {
          pollPair();
          return;
        }
        state.busy = null;
        if (state.pair.state === 'paired') {
          refreshStatus().then(function () {
            toast(
              wording('Pairing is ready', 'Pairing is ready'),
              wording('The source device is paired.', 'The pairing is simulated. No connection was made.')
            );
          });
        } else if (state.pair.state === 'failed') {
          state.error = model.sanitized(state.pair.error) || model.TEXT.pairingFailed;
          state.retryAction = 'pair';
          render();
        }
      }).catch(function (error) {
        state.busy = null;
        state.error = errorMessage(error);
        state.retryAction = 'pair';
        render();
      });
    }, PAIR_POLL_MS);
  }

  function startPairing() {
    if (state.busy || !bridgeReady()) return Promise.resolve(false);
    if (pairingIsActive(state.pair)) return Promise.resolve(false);
    clearPairPoll();
    state.pair = { state: 'connecting' };
    beginAction('pair');
    return call('pair').then(function (data) {
      state.pair = object(data);
      state.busy = null;
      render();
      pollPair();
      return true;
    }).catch(function (error) {
      state.pair = null;
      failAction('pair', error, wording('The pairing did not start', 'The simulated pairing did not start'));
      return false;
    });
  }

  function cancelPairing() {
    if (state.busy === 'pair' || !bridgeReady()) return Promise.resolve(false);
    clearPairPoll();
    state.busy = 'pair';
    render();
    return call('pairCancel').then(function (data) {
      state.pair = object(data);
      state.busy = null;
      state.error = null;
      state.retryAction = null;
      render();
      toast(
        'Pairing cancelled',
        wording('The pairing request stopped.', 'The simulated pairing stopped.')
      );
      return true;
    }).catch(function (error) {
      failAction('pair', error, wording('The pairing did not stop', 'The simulated pairing did not stop'));
      return false;
    });
  }

  function forgetSourceDevice() {
    if (state.busy || !bridgeReady()) return Promise.resolve(false);
    beginAction('forget');
    return call('forget').then(function () {
      return waitForStatus(function (status) {
        var forget = object(status.forget);
        return forget.state === 'confirmed' || forget.state === 'not_delivered';
      }, ACTION_WAIT_MS);
    }).then(function (finished) {
      state.busy = null;
      state.forgetBlocked = false;
      state.pair = { state: 'idle' };
      if (!finished) {
        state.error = wording(
          'The Forget request is still running. Check the status again.',
          'The simulated Forget did not finish. Check the status.'
        );
        state.retryAction = 'forget';
        render();
        return false;
      }
      return refreshStatus().then(function () {
        toast(
          'Source device forgotten',
          wording('The pairing is removed from this target device.', 'The simulated pairing is removed from this target device.')
        );
        return true;
      });
    }).catch(function (error) {
      if (errorCode(error) === 'forget_blocked') {
        state.busy = null;
        state.forgetBlocked = true;
        state.error = null;
        state.retryAction = null;
        render();
        toast('Turn off the tunnel first', errorMessage(error));
        return false;
      }
      failAction('forget', error, wording('The Forget did not finish', 'The simulated Forget did not finish'));
      return false;
    });
  }

  function stopAndForget() {
    if (state.busy || !bridgeReady()) return Promise.resolve(false);
    return stopTunnel(true).then(function (stopped) {
      if (!stopped) return false;
      return forgetSourceDevice();
    });
  }

  function checkNow() {
    if (state.busy || !bridgeReady()) return Promise.resolve(false);
    beginAction('check');
    return call('probe').then(function () {
      state.busy = null;
      return refreshStatus().then(function () {
        toast(
          'Check finished',
          wording('The source device status is updated.', 'The simulated source device answer is updated.')
        );
        return true;
      });
    }).catch(function (error) {
      if (errorCode(error) === 'rate_limited') {
        state.busy = null;
        render();
        toast('The check is too fast', errorMessage(error));
        return false;
      }
      failAction('checkNow', error, wording('The check did not finish', 'The simulated check did not finish'));
      return false;
    });
  }

  function applyScenario() {
    if (state.busy || !bridgeReady()) return Promise.resolve(false);
    var name = dom.demoScenario ? dom.demoScenario.value : '';
    if (SCENARIOS.indexOf(name) === -1) return Promise.resolve(false);
    beginAction('scenario');
    return call('demoScenario', name).then(function () {
      state.busy = null;
      state.error = null;
      state.retryAction = null;
      state.forgetBlocked = false;
      state.pair = null;
      if (name === 'reset') {
        state.logs = [];
        state.lastSeq = 0;
        state.activityLoaded = false;
        state.activityError = null;
        state.failures = null;
        state.failuresLoaded = false;
        state.failureReport = '';
      }
      return Promise.all([refreshStatus(), refreshPair()]).then(function () {
        if (state.view === 'activity') return loadLogs(name === 'reset');
        return undefined;
      }).then(function () {
        render();
        if (state.view === 'settings' && state.settingsTab === 'advanced') renderFailures();
        toast('Demo scenario applied', name === 'reset' ? 'The simulated state is reset. No route or device changed.' : 'The simulated status changed.');
        return true;
      });
    }).catch(function (error) {
      failAction('scenario', error, 'The demo scenario did not apply');
      return false;
    });
  }

  function retryLastAction() {
    if (!bridgeReady()) {
      if (api && typeof api.bootstrap === 'function') return loadBootstrap();
      toast('The app bridge is unavailable', 'Start the app with Electron.');
      return Promise.resolve(false);
    }
    var target = state.retryAction || 'checkNow';
    if (target === 'start') return startTunnel(false);
    if (target === 'stop') return stopTunnel(false);
    if (target === 'pair') return startPairing();
    if (target === 'forget') return forgetSourceDevice();
    if (target === 'scenario') return applyScenario();
    return checkNow();
  }

  function performAction(id) {
    if (id === 'retry') return retryLastAction();
    if (id === 'pair' || id === 'pairAgain') return startPairing();
    if (id === 'turnOn') return startTunnel(false);
    if (id === 'turnOff') return stopTunnel(false);
    if (id === 'checkNow') return checkNow();
    if (id === 'forget') return forgetSourceDevice();
    if (id === 'turnOffAndForget') return stopAndForget();
    return Promise.resolve(false);
  }

  /* -------------------------------- activity ------------------------------ */

  function mergeLogs(entries) {
    if (!Array.isArray(entries)) return;
    var known = {};
    state.logs.forEach(function (entry) {
      if (entry && entry.seq !== undefined) known[String(entry.seq)] = true;
    });
    entries.forEach(function (entry) {
      if (!entry || entry.seq === undefined) return;
      var key = String(entry.seq);
      if (known[key]) return;
      known[key] = true;
      state.logs.push(entry);
      var sequence = parseInt(entry.seq, 10);
      if (isFinite(sequence) && sequence > state.lastSeq) state.lastSeq = sequence;
    });
    state.logs.sort(function (left, right) {
      return (parseInt(left.seq, 10) || 0) - (parseInt(right.seq, 10) || 0);
    });
    if (state.logs.length > 800) state.logs = state.logs.slice(state.logs.length - 800);
  }

  function loadLogs(reset) {
    if (!bridgeReady() || state.activityLoading) return Promise.resolve();
    state.activityLoading = true;
    state.activityError = null;
    if (reset) {
      state.logs = [];
      state.lastSeq = 0;
    }
    renderActivity();
    return call('activity', state.lastSeq).then(function (data) {
      var value = object(data);
      mergeLogs(value.logs);
      var next = Number(value.next);
      if (isFinite(next) && next > state.lastSeq) state.lastSeq = next;
      state.activityLoaded = true;
      state.activityLoading = false;
      renderActivity();
    }).catch(function (error) {
      state.activityLoading = false;
      state.activityLoaded = true;
      state.activityError = errorMessage(error);
      renderActivity();
    });
  }

  /* -------------------------------- failures ------------------------------ */

  function loadFailures() {
    if (!bridgeReady() || state.failuresLoading) return Promise.resolve();
    state.failuresLoading = true;
    renderFailures();
    return call('failures').then(function (data) {
      state.failures = object(data);
      state.failuresLoaded = true;
      state.failuresLoading = false;
      renderFailures();
    }).catch(function () {
      state.failures = null;
      state.failuresLoaded = true;
      state.failuresLoading = false;
      renderFailures();
    });
  }

  function copyText(value) {
    return call('copyText', value);
  }

  function copyPairCode() {
    var pairing = model.pairingView(state.pair, state.busy);
    if (!pairing.code) return;
    copyText(pairing.code).then(function () {
      toast('Pairing code copied', wording('The code is on the clipboard.', 'The code is simulated.'));
    }).catch(function (error) {
      toast('Could not copy the code', errorMessage(error));
    });
  }

  function copyFailureReport() {
    if (!state.failureReport) return;
    copyText(state.failureReport).then(function () {
      toast('Failure report copied', wording('One line for each failure group.', 'One line for each simulated group.'));
    }).catch(function (error) {
      toast('Could not copy the report', errorMessage(error));
    });
  }

  function setCopyState(message) {
    setText(dom.copyState, message);
    if (state.copyTimer) window.clearTimeout(state.copyTimer);
    if (message) {
      state.copyTimer = window.setTimeout(function () {
        if (dom.copyState.textContent === message) setText(dom.copyState, '');
      }, 4000);
    }
  }

  function copyDiagnosticsReport() {
    if (!bridgeReady()) return Promise.resolve();
    return call('diagnostics').then(function (data) {
      return copyText(model.diagnosticsReport(data, simulatedData()));
    }).then(function () {
      setCopyState('The diagnostics report is copied.');
      toast('Diagnostics copied', wording('A plain-text summary is on the clipboard.', 'A plain-text demo summary is on the clipboard.'));
    }).catch(function (error) {
      setCopyState('');
      toast('Could not copy diagnostics', errorMessage(error));
    });
  }

  /* ---------------------------------- theme ------------------------------- */

  function updateThemeControls() {
    var choices = document.querySelectorAll('[data-theme-pref]');
    Array.prototype.forEach.call(choices, function (choice) {
      var value = choice.getAttribute('data-theme-pref');
      choice.setAttribute('aria-pressed', String(value === state.themePreference));
    });
    var actual = effectiveTheme(state.themePreference);
    var label = actual === 'dark' ? 'Switch to light appearance' : 'Switch to dark appearance';
    dom.themeToggle.setAttribute('aria-label', label);
    dom.themeToggle.title = label;
  }

  function applyTheme(preference, persist) {
    if (preference !== 'system' && preference !== 'light' && preference !== 'dark') preference = 'system';
    state.themePreference = preference;
    var actual = effectiveTheme(preference);
    document.documentElement.setAttribute('data-theme', actual);
    document.documentElement.setAttribute('data-theme-preference', preference);
    if (persist) {
      try {
        localStorage.setItem(THEME_KEY, preference);
      } catch (error) {
        /* Private mode. */
      }
    }
    updateThemeControls();
  }

  function toggleTheme() {
    applyTheme(effectiveTheme(state.themePreference) === 'dark' ? 'light' : 'dark', true);
  }

  /* --------------------------------- render ------------------------------- */

  /* Keep the demo labels for the demo backend. Replace them with engine text
   * only when the engine backend is active. */
  function applyModeLabels() {
    var engine = engineMode();
    var simulated = simulatedData();
    var live = engine && !simulated;
    var known = !!state.bootstrap;

    if (dom.demoPill) {
      dom.demoPill.hidden = !known || live;
      dom.demoPill.textContent = simulated && engine ? 'Engine demo' : 'Demo';
      dom.demoPill.title = live
        ? ''
        : simulated && engine
          ? 'The local engine service runs in demo mode. Data is simulated.'
          : 'Simulated data. No sockets open. No traffic leaves this machine.';
    }
    if (dom.demoBanner) dom.demoBanner.hidden = !known || live;
    if (dom.demoBannerText) {
      dom.demoBannerText.textContent = simulated && engine
        ? 'The local engine service runs in demo mode. Data is simulated. No tunnel, routes, or network traffic.'
        : 'All data is simulated. No tunnel, routes, or network traffic.';
    }
    if (dom.demoLine) {
      dom.demoLine.hidden = !known || live;
      dom.demoLine.textContent = simulated && engine
        ? 'Engine demo mode. Data is simulated.'
        : 'Demo mode. Data is simulated.';
    }
    if (dom.modeCardTitle) {
      dom.modeCardTitle.textContent = !engine
        ? 'Demo mode'
        : simulated
          ? 'Engine demo mode'
          : 'Engine mode';
    }
    if (dom.modeCardBody) {
      dom.modeCardBody.textContent = !engine
        ? 'This app uses the in-memory demo backend. It has no tunnel, no route change, no TUN device, no listener, and no external request. Demo data only.'
        : simulated
          ? 'This app uses the local engine service in demo mode. The engine holds the tunnel state. No tunnel, route, or TUN device is created.'
          : 'This app uses the local engine service. The engine holds the tunnel state and the pairing credentials. This page receives status values only.';
    }
    if (dom.demoScenariosCard) dom.demoScenariosCard.hidden = engine;
    if (dom.demoLimits) dom.demoLimits.hidden = engine;
    if (dom.engineLimits) dom.engineLimits.hidden = !engine;
    if (dom.pairingSimulatedNote) {
      dom.pairingSimulatedNote.hidden = live;
      dom.pairingSimulatedNote.textContent = simulated && engine
        ? 'The local engine service runs in demo mode. No real source device is contacted.'
        : 'This pairing is simulated. No connection is made.';
    }
    if (dom.pairingSimulatedCard) dom.pairingSimulatedCard.hidden = engine;
    if (dom.activitySubtitle) {
      dom.activitySubtitle.textContent = engine
        ? 'Events from the local engine service. The record stays on this target device.'
        : 'Events from the in-memory demo backend. The record stays on this target device.';
    }
    if (dom.activityNote) {
      dom.activityNote.textContent = simulated
        ? 'The activity record is simulated. It is never written to disk.'
        : 'The activity record stays in target device memory. It is never written to disk.';
    }
    if (dom.settingsSubtitle) {
      dom.settingsSubtitle.textContent = engine
        ? 'Settings for this target device. Data comes from the local engine service.'
        : 'Settings for this target device. All data is simulated.';
    }
    if (dom.failuresSubtitle) {
      dom.failuresSubtitle.textContent = engine
        ? 'Failed connection setups on this target device. The record stays in memory.'
        : 'Failed connection setups on this target device. The demo record stays in memory.';
    }
    if (dom.pingHelp) {
      dom.pingHelp.textContent = engine
        ? 'Uses the echo relay. Applies the next time you turn the tunnel on.'
        : 'Uses the simulated echo relay. Applies the next time you turn the tunnel on.';
    }
  }

  function render() {
    var derived = model.deriveDashboard({
      status: state.status,
      hasStatus: state.hasStatus,
      pair: state.pair,
      freshness: currentFreshness(),
      busy: state.busy,
      error: state.error || (state.bridgeState === 'failed' ? state.bridgeError : null),
      forgetBlocked: state.forgetBlocked,
      notificationsUnavailable: state.bridgeState === 'ready' && state.settings.notificationsSupported !== true,
      nowSeconds: nowSeconds()
    });
    renderDashboard(derived);
    renderSettings(derived);
    renderPlatform(derived);
    applyModeLabels();
    updateThemeControls();
    renderRefreshButton();

    document.title = settingsWindowMode
      ? 'HotspotShade Settings' + (simulatedData() ? ' (Demo)' : '')
      : 'HotspotShade' + (simulatedData() ? ' (Demo)' : '') + ' · ' + TITLES[state.view];
    setText(dom.contextLabel, settingsWindowMode ? 'Settings' : TITLES[state.view]);
    var dashboardNav = document.querySelector('.nav-item[data-view="dashboard"]');
    if (dashboardNav) dashboardNav.setAttribute('aria-label', 'Dashboard. ' + derived.title);
  }

  function renderDashboard(derived) {
    var pairing = model.pairingView(state.pair, state.busy);
    var pairingVisible = pairing.active || state.busy === 'pair';
    dom.dashboardContent.hidden = pairingVisible;
    dom.pairingPanel.hidden = !pairingVisible;

    dom.navStatusDot.className = 'nav-status-dot is-' + derived.kind;
    dom.statusDot.className = 'status-dot is-' + derived.kind;
    setText(dom.dashboardTitle, derived.title);
    setText(dom.dashboardSubtitle, derived.subtitle);
    setText(dom.dashboardChecked, derived.checked || '');
    dom.dashboardChecked.hidden = !derived.checked;

    if (derived.primary) {
      dom.primaryAction.hidden = false;
      dom.primaryAction.dataset.action = derived.primary.id;
      setText(dom.primaryAction, derived.primary.label);
      dom.primaryAction.disabled = !!state.busy || (!bridgeReady() && derived.primary.id !== 'retry');
    } else {
      dom.primaryAction.hidden = true;
      dom.primaryAction.dataset.action = '';
      dom.primaryAction.disabled = true;
    }

    if (derived.secondary) {
      dom.secondaryAction.hidden = false;
      dom.secondaryAction.dataset.action = derived.secondary.id;
      setText(dom.secondaryAction, derived.secondary.label);
      dom.secondaryAction.disabled = !!state.busy || !bridgeReady();
      dom.secondaryAction.classList.toggle('button-danger', derived.secondary.id === 'forget' || derived.secondary.id === 'turnOffAndForget');
    } else {
      dom.secondaryAction.hidden = true;
      dom.secondaryAction.dataset.action = '';
      dom.secondaryAction.disabled = true;
      dom.secondaryAction.classList.remove('button-danger');
    }

    var hint = derived.title === model.TEXT.notPaired && derived.primary && derived.primary.id === 'pair' && derived.attention.length === 0;
    dom.pairHint.hidden = !hint;
    if (hint) setText(dom.pairHint, model.TEXT.pairWhenReady);

    setText(dom.sourceValue, derived.source.value);
    renderList(dom.sourceDetails, derived.source.details);
    setText(dom.connectionValue, derived.connection.value);
    renderList(dom.connectionDetails, derived.connection.details);

    dom.attentionCard.hidden = derived.attention.length === 0;
    renderList(dom.attentionList, derived.attention);

    setText(dom.pairingMessage, pairing.message);
    dom.pairCodeBlock.hidden = !pairing.code;
    dom.waitingForCode.hidden = !!pairing.code;
    setText(dom.pairCode, pairing.code || '');
    dom.pairCode.setAttribute('aria-label', pairing.code ? 'Pairing code. ' + pairing.code : 'Pairing code');
    dom.copyCode.disabled = !pairing.code;
    dom.cancelPairing.disabled = state.busy === 'pair';
  }

  function renderSettings(derived) {
    var status = object(state.status);
    var phone = object(status.phone);
    var paired = status.paired === true;
    var running = status.running === true;
    var pairing = model.pairingView(state.pair, state.busy);
    var unavailable = derived.unavailable || !bridgeReady();
    var phoneState = text(phone.state);
    var stateText = 'Not paired';
    if (unavailable) stateText = model.TEXT.statusUnavailableLine;
    else if (phoneState === 'not_trusted' && paired) stateText = model.TEXT.notTrusted;
    else if (pairing.active) stateText = model.TEXT.pairing;
    else if (paired) stateText = model.TEXT.paired;
    setText(dom.settingsPairingState, stateText);

    var message = '';
    if (unavailable) message = model.TEXT.statusUnavailableLine;
    else if (pairing.active) message = pairing.message;
    else message = text(phone.message) || derived.subtitle;
    setText(dom.settingsPairingMessage, message);

    dom.settingsPair.hidden = pairing.active;
    dom.settingsPair.disabled = unavailable || running || !!state.busy || pairing.active;
    dom.settingsCancel.hidden = !pairing.active;
    dom.settingsCancel.disabled = false;
    dom.settingsForget.hidden = !paired || running || pairing.active || unavailable;
    dom.settingsForget.disabled = !!state.busy;
    dom.settingsTurnOffForget.hidden = !running || unavailable;
    dom.settingsTurnOffForget.disabled = !!state.busy;

    var reason = '';
    if (pairing.active) reason = '';
    else if (unavailable) reason = model.TEXT.statusUnavailableLine;
    else if (running) reason = 'Turn off the tunnel first.';
    else if (state.busy) reason = 'Wait for the current action to finish.';
    else if (state.bridgeState !== 'ready') reason = 'The app backend did not answer.';
    setText(dom.settingsPairReason, reason);
    dom.settingsPairReason.hidden = !reason;

    var forgetText = model.forgetMessage(status.forget);
    if (state.forgetBlocked) forgetText = model.TEXT.forgetBlocked;
    setText(dom.settingsForgetMessage, forgetText || '');
    dom.settingsForgetMessage.hidden = !forgetText;

    dom.pingToggle.checked = state.ping;
    dom.pingToggle.disabled = false;

    var login = state.settings;
    dom.loginToggle.checked = login.launchAtLogin === true;
    dom.loginToggle.disabled = !bridgeReady() || login.launchAtLoginAvailable !== true || !!state.busy;
    if (dom.loginHelp) {
      dom.loginHelp.textContent = login.launchAtLoginAvailable !== true
        ? 'Launch at login is available in the packaged app, when the user has an autostart directory.'
        : 'Starts HotspotShade when you log in to this desktop. The app writes one autostart entry.';
    }

    dom.notificationsToggle.checked = login.notifications === true;
    dom.notificationsToggle.disabled = !bridgeReady() || login.notificationsSupported !== true || !!state.busy;
    if (dom.notificationsStatus) {
      setText(dom.notificationsStatus, !login.notificationsSupported
        ? 'This desktop does not support notifications.'
        : login.notifications
          ? 'Notifications are on.'
          : 'Notifications are off.');
    }

    dom.demoScenario.disabled = !bridgeReady() || !!state.busy || engineMode();
    dom.applyScenario.disabled = !bridgeReady() || !!state.busy || engineMode();
  }

  function renderActivity() {
    var entries = model.activityEntries(state.logs);
    var empty = entries.length === 0;
    dom.activityDetailsToggle.setAttribute('aria-pressed', String(state.activityDetails));
    dom.activityRefresh.disabled = state.activityLoading || !bridgeReady();
    dom.activityState.hidden = !empty;
    dom.activityList.hidden = empty;

    if (empty) {
      dom.activitySpinner.hidden = !state.activityLoading;
      dom.activityStateIcon.hidden = state.activityLoading;
      dom.activityRetry.hidden = true;
      if (state.activityLoading) {
        setText(dom.activityStateTitle, 'Loading activity');
        setText(dom.activityStateText, wording('Waiting for the engine.', 'Waiting for the demo backend.'));
      } else if (state.activityError) {
        setText(dom.activityStateTitle, 'The app cannot read activity now.');
        setText(dom.activityStateText, state.activityError);
        dom.activityRetry.hidden = false;
        setText(dom.activityRetry, 'Try again');
      } else {
        setText(dom.activityStateTitle, 'No activity yet.');
        setText(dom.activityStateText, 'Start the tunnel to create entries.');
        dom.activityRetry.hidden = false;
        setText(dom.activityRetry, 'Refresh');
      }
      dom.activityList.textContent = '';
      return;
    }

    var list = dom.activityList;
    var nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
    list.textContent = '';
    entries.forEach(function (entry) {
      var row = document.createElement('li');
      row.className = 'activity-row level-' + entry.level;
      var details = [entry.level, entry.seq ? 'seq ' + entry.seq : ''].filter(Boolean).join(', ');
      row.setAttribute('aria-label', [entry.time, entry.message, state.activityDetails ? details : ''].filter(Boolean).join('. '));

      var time = document.createElement('span');
      time.className = 'activity-time';
      time.textContent = entry.time;
      var body = document.createElement('div');
      body.className = 'activity-body';
      if (state.activityDetails) {
        var detailLine = document.createElement('p');
        detailLine.className = 'activity-details';
        detailLine.textContent = details;
        body.appendChild(detailLine);
      }
      var message = document.createElement('p');
      message.className = 'activity-message';
      message.textContent = entry.message;
      body.appendChild(message);
      row.appendChild(time);
      row.appendChild(body);
      list.appendChild(row);
    });
    if (nearBottom) list.scrollTop = list.scrollHeight;
  }

  function renderFailures() {
    dom.failuresRefresh.disabled = state.failuresLoading || !bridgeReady();
    dom.copyFailures.disabled = true;
    dom.failuresTable.hidden = true;
    dom.failuresEmpty.hidden = true;
    state.failureReport = '';

    if (!state.failuresLoaded) {
      setText(dom.failuresSummary, state.failuresLoading ? 'Loading recent failures.' : 'Press Refresh to read failures.');
      return;
    }

    var view = model.failureView(state.failures);
    if (view.state === 'unavailable') {
      setText(dom.failuresSummary, view.summary);
      return;
    }
    if (view.state === 'empty') {
      setText(dom.failuresSummary, view.summary);
      dom.failuresEmpty.hidden = false;
      setText(dom.failuresEmpty, 'No failed connections yet. ' + (simulatedData() ? 'The demo record stays in memory.' : 'The record stays in target device memory.'));
      return;
    }

    setText(dom.failuresSummary, view.summary);
    dom.failuresTable.hidden = false;
    dom.copyFailures.disabled = !view.copyable;
    state.failureReport = view.report;
    dom.failuresBody.textContent = '';
    view.rows.forEach(function (row) {
      var tableRow = document.createElement('tr');
      var count = document.createElement('td');
      count.textContent = row.count + 'x';
      var kind = document.createElement('td');
      kind.textContent = row.kind;
      var target = document.createElement('td');
      target.textContent = row.target;
      if (row.detail) target.title = row.detail;
      var phase = document.createElement('td');
      phase.textContent = row.phase;
      var reason = document.createElement('td');
      reason.textContent = row.reason;
      tableRow.appendChild(count);
      tableRow.appendChild(kind);
      tableRow.appendChild(target);
      tableRow.appendChild(phase);
      tableRow.appendChild(reason);
      dom.failuresBody.appendChild(tableRow);
    });
  }

  function renderPlatform(derived) {
    var info = object(state.bootstrap && state.bootstrap.app);
    var status = object(state.status);
    var platform = object(status.platform);
    var os = model.displayOs(platform.os || info.platform);
    if (os === 'Unknown OS') os = 'Linux';
    var arch = text(platform.arch || info.arch);
    var label = [os, arch].filter(Boolean).join(' ');
    if (!label) label = 'Linux';
    var engine = engineMode();
    var simulated = simulatedData();
    var known = !!state.bootstrap;
    var suffix = !known ? '' : !engine ? ' · demo' : simulated ? ' · engine demo' : ' · engine';
    setText(dom.platformText, label + suffix);
    dom.platformBadge.title = !known
      ? 'Reading the backend.'
      : simulated
        ? 'Simulated data. No tunnel, routes, or network traffic.'
        : 'Local engine service. Data comes from this target device.';
    setText(dom.appPlatform, label);
    setText(dom.appVersion, text(info.version) || '0.1.0');
    setText(dom.appMode, !known
      ? 'Reading the backend.'
      : !engine
        ? 'Demo. Data is simulated.'
        : simulated
          ? 'Engine demo. Data is simulated.'
          : 'Engine. Data from the local service.');
    setText(dom.appStatus, derived.title);
    var boundary = object(state.bootstrap && state.bootstrap.engine);
    setText(dom.appBoundary, !known
      ? 'Reading the backend'
      : engine
        ? state.engineConnected ? 'Connected' : 'Connecting'
        : boundary.connected === true ? 'Connected' : 'Not connected');
    setText(dom.appTunnel, !known
      ? 'Reading the backend'
      : !engine
        ? boundary.tunnel === 'not_implemented' ? 'Not implemented' : 'Unknown'
        : simulated
          ? 'Engine demo. No tunnel.'
          : 'Engine service');
    setText(dom.versionLabel, (text(info.version) || '0.1.0') + (!known ? '' : simulated ? ' · demo only' : ' · engine'));
  }

  function renderRefreshButton() {
    dom.refreshButton.classList.toggle('is-busy', state.manualRefreshing);
    if (state.manualRefreshing) dom.refreshButton.setAttribute('aria-busy', 'true');
    else dom.refreshButton.removeAttribute('aria-busy');
    dom.refreshButton.disabled = !bridgeReady();
  }

  /* --------------------------------- views -------------------------------- */

  function setView(view, focus) {
    if (settingsWindowMode) view = 'settings';
    if (VIEWS.indexOf(view) === -1) view = 'dashboard';
    state.view = view;
    dom['view-dashboard'].hidden = view !== 'dashboard';
    dom['view-activity'].hidden = view !== 'activity';
    dom['view-settings'].hidden = view !== 'settings';
    Array.prototype.forEach.call(document.querySelectorAll('.nav-item[data-view]'), function (item) {
      if (item.getAttribute('data-view') === view) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
    if (focus) {
      try {
        dom.mainContent.focus({ preventScroll: true });
      } catch (error) {
        dom.mainContent.focus();
      }
    }
    if (window.location.hash !== '#' + view) {
      try {
        history.replaceState(null, '', '#' + view);
      } catch (error) {
        /* The asset URL can be read only. */
      }
    }
    render();
    if (view === 'activity') {
      if (!state.activityLoaded) loadLogs(true);
      else renderActivity();
    }
    if (view === 'settings' && state.settingsTab === 'advanced') {
      renderFailures();
      if (!state.failuresLoaded) loadFailures();
    }
  }

  function selectSettingsTab(tab, focus) {
    if (SETTINGS_TABS.indexOf(tab) === -1) tab = 'general';
    state.settingsTab = tab;
    Array.prototype.forEach.call(document.querySelectorAll('[data-settings-tab]'), function (button) {
      var current = button.getAttribute('data-settings-tab') === tab;
      button.setAttribute('aria-selected', String(current));
      button.tabIndex = current ? 0 : -1;
      if (current && focus) button.focus();
    });
    dom.settingsGeneralPanel.hidden = tab !== 'general';
    dom.settingsPairingPanel.hidden = tab !== 'pairing';
    dom.settingsAdvancedPanel.hidden = tab !== 'advanced';
    render();
    if (tab === 'advanced') {
      renderFailures();
      if (!state.failuresLoaded) loadFailures();
    }
  }

  function viewFromHash() {
    var name = String(window.location.hash || '').replace('#', '');
    return VIEWS.indexOf(name) === -1 ? 'dashboard' : name;
  }

  function focusTarget(element) {
    if (!element) return;
    element.setAttribute('tabindex', '-1');
    element.focus();
    if (typeof element.scrollIntoView === 'function') element.scrollIntoView({ block: 'nearest' });
  }

  function handleMenuCommand(command) {
    if (!model.menuCommandAllowed(command)) return;
    if (command === 'dashboard' || command === 'activity') {
      if (!settingsWindowMode) setView(command, true);
    } else if (command === 'settings') {
      openSettingsWindow();
    } else if (command === 'settings-inline') {
      setView('settings', true);
      selectSettingsTab('general', false);
    } else if (command === 'advanced' || command === 'demo-limitations') {
      setView('settings', true);
      selectSettingsTab('advanced', false);
      focusTarget(engineMode() ? dom.engineLimits : dom.demoLimits);
    } else if (command === 'demo-scenarios') {
      setView('settings', true);
      selectSettingsTab('advanced', false);
      focusTarget(engineMode() ? dom.engineLimits : dom.demoScenario);
    } else if (command === 'refresh') {
      refreshAll();
    } else if (command === 'check-now') {
      checkNow();
    } else if (command === 'theme') {
      toggleTheme();
    }
  }

  function openSettingsWindow() {
    if (settingsWindowMode) {
      selectSettingsTab('general', false);
      return Promise.resolve(false);
    }
    if (!bridgeReady() || !api || typeof api.openSettings !== 'function') {
      setView('settings', true);
      selectSettingsTab('general', false);
      return Promise.resolve(false);
    }
    return call('openSettings').then(function () {
      return true;
    }).catch(function () {
      /* The separate window is not available. Use the page section. */
      setView('settings', true);
      selectSettingsTab('general', false);
      return false;
    });
  }

  /* -------------------------------- wiring -------------------------------- */

  function wireEvents() {
    dom.primaryAction.addEventListener('click', function () {
      performAction(dom.primaryAction.dataset.action);
    });
    dom.secondaryAction.addEventListener('click', function () {
      performAction(dom.secondaryAction.dataset.action);
    });
    dom.cancelPairing.addEventListener('click', function () {
      cancelPairing();
    });
    dom.copyCode.addEventListener('click', copyPairCode);

    dom.settingsPair.addEventListener('click', function () {
      startPairing();
    });
    dom.settingsCancel.addEventListener('click', function () {
      cancelPairing();
    });
    dom.settingsForget.addEventListener('click', function () {
      forgetSourceDevice();
    });
    dom.settingsTurnOffForget.addEventListener('click', function () {
      stopAndForget();
    });

    dom.themeToggle.addEventListener('click', toggleTheme);
    dom.refreshButton.addEventListener('click', refreshAll);
    dom.demoDetails.addEventListener('click', function () {
      handleMenuCommand('demo-limitations');
    });

    dom.activityDetailsToggle.addEventListener('click', function () {
      state.activityDetails = !state.activityDetails;
      dom.activityDetailsToggle.setAttribute('aria-pressed', String(state.activityDetails));
      renderActivity();
    });
    dom.activityRefresh.addEventListener('click', function () {
      loadLogs(true);
    });
    dom.activityRetry.addEventListener('click', function () {
      loadLogs(true);
    });

    dom.failuresRefresh.addEventListener('click', loadFailures);
    dom.copyFailures.addEventListener('click', copyFailureReport);
    dom.copyDiagnostics.addEventListener('click', copyDiagnosticsReport);
    dom.applyScenario.addEventListener('click', applyScenario);

    dom.pingToggle.addEventListener('change', function () {
      var value = !!dom.pingToggle.checked;
      state.ping = value;
      try {
        localStorage.setItem(PING_KEY, value ? 'true' : 'false');
      } catch (error) {
        /* Private mode. */
      }
      updateSetting('ping', value).then(function () {
        toast(value ? 'Ping is on for the next start' : 'Ping is off for the next start', wording('The setting applies to the next start.', 'The setting applies to the simulated session.'));
      }).catch(function (error) {
        state.ping = !value;
        dom.pingToggle.checked = state.ping;
        toast('The setting did not change', errorMessage(error));
      });
    });

    dom.loginToggle.addEventListener('change', function () {
      var value = !!dom.loginToggle.checked;
      dom.loginToggle.disabled = true;
      updateSetting('launchAtLogin', value).then(function () {
        toast(value ? 'Launch at login is on' : 'Launch at login is off', value ? 'HotspotShade starts when you log in.' : 'The autostart entry is removed.');
      }).catch(function (error) {
        dom.loginToggle.checked = !value;
        toast('Launch at login did not change', errorMessage(error));
        render();
      });
    });

    dom.notificationsToggle.addEventListener('change', function () {
      var value = !!dom.notificationsToggle.checked;
      dom.notificationsToggle.disabled = true;
      updateSetting('notifications', value).then(function () {
        toast(value ? 'Notifications are on' : 'Notifications are off', value ? 'The app sends a message when the tunnel stops by itself or pairing finishes.' : 'The app sends no desktop message.');
      }).catch(function (error) {
        dom.notificationsToggle.checked = !value;
        toast('Notifications did not change', errorMessage(error));
        render();
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll('[data-theme-pref]'), function (choice) {
      choice.addEventListener('click', function () {
        applyTheme(choice.getAttribute('data-theme-pref'), true);
      });
    });

    var navItems = Array.prototype.slice.call(document.querySelectorAll('.nav-item[data-view]'));
    navItems.forEach(function (item) {
      item.addEventListener('click', function () {
        var name = item.getAttribute('data-view');
        if (name === 'settings' && !settingsWindowMode) {
          openSettingsWindow();
          return;
        }
        setView(name, true);
      });
      item.addEventListener('keydown', function (event) {
        if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp' && event.key !== 'Home' && event.key !== 'End') return;
        event.preventDefault();
        var index = navItems.indexOf(item);
        var next = index;
        if (event.key === 'ArrowDown') next = (index + 1) % navItems.length;
        if (event.key === 'ArrowUp') next = (index - 1 + navItems.length) % navItems.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = navItems.length - 1;
        navItems[next].focus();
      });
    });

    var settingsTabs = Array.prototype.slice.call(document.querySelectorAll('[data-settings-tab]'));
    settingsTabs.forEach(function (button) {
      button.addEventListener('click', function () {
        selectSettingsTab(button.getAttribute('data-settings-tab'), false);
      });
      button.addEventListener('keydown', function (event) {
        if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft' && event.key !== 'Home' && event.key !== 'End') return;
        event.preventDefault();
        var index = settingsTabs.indexOf(button);
        var next = index;
        if (event.key === 'ArrowRight') next = (index + 1) % settingsTabs.length;
        if (event.key === 'ArrowLeft') next = (index - 1 + settingsTabs.length) % settingsTabs.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = settingsTabs.length - 1;
        selectSettingsTab(settingsTabs[next].getAttribute('data-settings-tab'), true);
      });
    });

    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') return;
      if (pairingIsActive(state.pair)) {
        event.preventDefault();
        cancelPairing();
      }
    });

    document.addEventListener('dragover', function (event) {
      event.preventDefault();
    });
    document.addEventListener('drop', function (event) {
      event.preventDefault();
    });

    document.addEventListener('visibilitychange', schedulePoll);

    var darkQuery = null;
    try {
      darkQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
    } catch (error) {
      darkQuery = null;
    }
    if (darkQuery) {
      var onSchemeChange = function () {
        if (state.themePreference === 'system') applyTheme('system', false);
      };
      if (typeof darkQuery.addEventListener === 'function') darkQuery.addEventListener('change', onSchemeChange);
      else if (typeof darkQuery.addListener === 'function') darkQuery.addListener(onSchemeChange);
    }

    try {
      var contrastQuery = window.matchMedia ? window.matchMedia('(prefers-contrast: more)') : null;
      var forcedQuery = window.matchMedia ? window.matchMedia('(forced-colors: active)') : null;
      var onContrastChange = function () {
        applyContrast();
      };
      [contrastQuery, forcedQuery].forEach(function (query) {
        if (!query) return;
        if (typeof query.addEventListener === 'function') query.addEventListener('change', onContrastChange);
        else if (typeof query.addListener === 'function') query.addListener(onContrastChange);
      });
    } catch (error) {
      /* The desktop reports no contrast preference. */
    }

    window.addEventListener('storage', function (event) {
      if (!event) return;
      if (event.key === THEME_KEY) {
        applyTheme(storedTheme(), false);
      } else if (event.key === PING_KEY) {
        state.ping = storedPing();
        render();
      }
    });

    if (api && typeof api.onMenuCommand === 'function') {
      api.onMenuCommand(handleMenuCommand);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
