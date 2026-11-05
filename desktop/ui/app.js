/* HotspotShade desktop demo page.
 *
 * The page talks only to the narrow demo_api command through the fetch shim.
 * All values are simulated by the in-memory DemoBackend. This file does not
 * open a listener, start a tunnel, or change a route.
 */
(function () {
  'use strict';

  var model = window.HotspotShadeModel;
  var THEME_KEY = 'hs-theme';
  var PING_KEY = 'hs-ping';
  var POLL_VISIBLE_MS = 1000;
  var POLL_HIDDEN_MS = 5000;
  var PAIR_POLL_MS = 450;
  var API_TIMEOUT_MS = 8000;

  var VIEWS = ['dashboard', 'activity', 'settings'];
  var SETTINGS_TABS = ['general', 'pairing', 'advanced'];

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
      var value = localStorage.getItem(THEME_KEY);
      if (value === 'system' || value === 'light' || value === 'dark') return value;
    } catch (error) {
      return 'system';
    }
    return 'system';
  }

  function storedPing() {
    try {
      var value = localStorage.getItem(PING_KEY);
      if (value === 'true') return true;
      if (value === 'false') return false;
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

  function effectiveTheme(preference) {
    if (preference === 'light' || preference === 'dark') return preference;
    return systemDark() ? 'dark' : 'light';
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

  function displayOs(value) {
    var raw = String(value || '').toLowerCase();
    if (raw.indexOf('mac') === 0 || raw === 'darwin') return 'macOS';
    if (raw.indexOf('win') === 0) return 'Windows';
    if (raw.indexOf('linux') === 0) return 'Linux';
    return value ? String(value) : 'Unknown OS';
  }

  function nowSeconds() {
    return Date.now() / 1000;
  }

  function init() {
    var dom = {};
    [
      'demoPill', 'demoBanner', 'demoDetails', 'platformBadge', 'platformText',
      'themeToggle', 'refreshButton', 'mainContent', 'versionLabel', 'navStatusDot',
      'view-dashboard', 'view-activity', 'view-settings',
      'dashboardContent', 'statusDot', 'dashboardTitle', 'dashboardSubtitle',
      'dashboardChecked', 'primaryAction', 'secondaryAction', 'dashboardError',
      'sourceValue', 'sourceDetails', 'connectionValue', 'connectionDetails',
      'attentionCard', 'attentionList',
      'pairingPanel', 'pairingTitle', 'pairingMessage', 'pairingSpinner',
      'pairCodeBlock', 'pairCode', 'copyCode', 'cancelPairing',
      'activityDetailsToggle', 'activityRefresh', 'activityEmpty',
      'activityEmptyTitle', 'activityEmptyText', 'activityList', 'activityNote',
      'settingsTabGeneral', 'settingsTabPairing', 'settingsTabAdvanced',
      'settingsGeneralPanel', 'settingsPairingPanel', 'settingsAdvancedPanel',
      'pingToggle', 'settingsPairingState', 'settingsPairingMessage',
      'settingsPair', 'settingsCancel', 'settingsForget', 'settingsTurnOffForget',
      'settingsForgetMessage', 'failuresRefresh', 'copyFailures', 'failuresSummary',
      'failuresTable', 'failuresBody', 'failuresEmpty', 'copyDiagnostics', 'copyState',
      'appVersion', 'appPlatform', 'appIface', 'appMode', 'appStatus', 'appDemo',
      'demoLimits', 'toastRegion'
    ].forEach(function (id) { dom[id] = byId(id); });

    var state = {
      view: 'dashboard',
      settingsTab: 'general',
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
      themePreference: storedTheme(),
      logs: [],
      lastSeq: 0,
      activityDetails: false,
      activityLoading: false,
      activityError: null,
      failures: null,
      failuresLoaded: false,
      failuresLoading: false,
      statusInFlight: false,
      statusQueued: false,
      statusPromise: null,
      pairTimer: null,
      pollTimer: null,
      toastTimers: {}
    };

    var sections = {
      dashboard: dom['view-dashboard'],
      activity: dom['view-activity'],
      settings: dom['view-settings']
    };

    var navItems = Array.prototype.slice.call(document.querySelectorAll('.nav-item[data-view]'));
    var settingsTabs = Array.prototype.slice.call(document.querySelectorAll('[data-settings-tab]'));
    var themeChoices = Array.prototype.slice.call(document.querySelectorAll('[data-theme-pref]'));

    /* ------------------------------- API -------------------------------- */

    function api(path, options) {
      options = options || {};
      var initRequest = {
        cache: 'no-store',
        headers: { Accept: 'application/json' }
      };
      if (options.method) initRequest.method = options.method;
      if (options.body !== undefined) {
        initRequest.headers['Content-Type'] = 'application/json';
        initRequest.body = JSON.stringify(options.body);
      }

      var controller = null;
      var timer = null;
      if (typeof window.AbortController === 'function') {
        controller = new window.AbortController();
        initRequest.signal = controller.signal;
        timer = window.setTimeout(function () { controller.abort(); }, API_TIMEOUT_MS);
      }

      function clearTimer() {
        if (timer) {
          window.clearTimeout(timer);
          timer = null;
        }
      }

      return fetch(path, initRequest).then(function (response) {
        return response.text().then(function (bodyText) {
          var data = {};
          if (bodyText) {
            try {
              data = JSON.parse(bodyText);
            } catch (error) {
              data = {};
            }
          }
          if (!response.ok || data.ok === false) {
            var message = text(data.error) || text(data.message) || ('The demo request failed. HTTP ' + response.status + '.');
            var failure = new Error(message);
            failure.status = response.status;
            failure.data = data;
            throw failure;
          }
          return data;
        });
      }).catch(function (error) {
        if (error && error.name === 'AbortError') {
          throw new Error('The demo backend did not answer in time.');
        }
        if (error instanceof TypeError) {
          throw new Error('Cannot reach the demo backend.');
        }
        throw error;
      }).then(function (value) {
        clearTimer();
        return value;
      }, function (error) {
        clearTimer();
        throw error;
      });
    }

    /* ------------------------------ status ------------------------------ */

    function currentFreshness() {
      return model.statusFreshness(state.failureSince, Date.now(), state.hasStatus);
    }

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
        var seq = parseInt(entry.seq, 10);
        if (isFinite(seq) && seq > state.lastSeq) state.lastSeq = seq;
      });
      state.logs.sort(function (a, b) {
        return (parseInt(a.seq, 10) || 0) - (parseInt(b.seq, 10) || 0);
      });
      if (state.logs.length > 800) state.logs = state.logs.slice(state.logs.length - 800);
    }

    function adoptPairState() {
      var status = object(state.status);
      var pair = object(state.pair);
      var pairState = text(pair.state);
      if (status.paired === true && !pairState) {
        state.pair = { state: 'paired' };
      } else if (status.paired === false && pairState === 'paired' && !state.busy) {
        state.pair = { state: 'idle' };
      }
    }

    function refreshStatus() {
      if (state.statusInFlight) {
        state.statusQueued = true;
        return state.statusPromise || Promise.resolve();
      }
      state.statusInFlight = true;
      state.statusPromise = api('/api/status').then(function (data) {
        state.status = object(data);
        state.hasStatus = true;
        state.failureSince = null;
        state.freshness = 'fresh';
        if (data.running !== true && state.busy !== 'forget') state.forgetBlocked = false;
        mergeLogs(data.logs);
        adoptPairState();
        if (state.error && state.retryAction === 'checkNow') {
          state.error = null;
          state.retryAction = null;
        }
        if (typeof data.error === 'string' && data.error && !state.error) {
          state.error = data.error;
          state.retryAction = 'checkNow';
        }
        render();
      }).catch(function (error) {
        if (!state.failureSince) state.failureSince = Date.now();
        state.freshness = currentFreshness();
        if (!state.hasStatus) {
          state.error = text(error && error.message);
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
      return api('/api/phone/pair').then(function (data) {
        state.pair = object(data);
        adoptPairState();
        render();
      }).catch(function () {
        /* The status poll still reports the pairing. */
      });
    }

    function refreshAll() {
      dom.refreshButton.classList.add('is-busy');
      dom.refreshButton.setAttribute('aria-busy', 'true');
      return Promise.all([refreshStatus(), refreshPair()]).then(function () {
        dom.refreshButton.classList.remove('is-busy');
        dom.refreshButton.removeAttribute('aria-busy');
      }, function () {
        dom.refreshButton.classList.remove('is-busy');
        dom.refreshButton.removeAttribute('aria-busy');
      });
    }

    function schedulePoll() {
      if (state.pollTimer) window.clearTimeout(state.pollTimer);
      var delay = document.visibilityState === 'visible' ? POLL_VISIBLE_MS : POLL_HIDDEN_MS;
      state.pollTimer = window.setTimeout(function () {
        refreshStatus().then(schedulePoll, schedulePoll);
      }, delay);
    }

    /* ------------------------------ actions ----------------------------- */

    function toast(title, message) {
      if (!dom.toastRegion) return;
      var node = document.createElement('div');
      node.className = 'toast';

      var content = document.createElement('div');
      content.className = 'toast-content';
      var heading = document.createElement('span');
      heading.className = 'toast-title';
      heading.textContent = title;
      var copy = document.createElement('span');
      copy.className = 'toast-message';
      copy.textContent = message || '';
      content.appendChild(heading);
      if (message) content.appendChild(copy);

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
        if (node.parentNode) node.parentNode.removeChild(node);
        delete state.toastTimers[title];
      }, 5000);
      state.toastTimers[title] = timer;
      close.addEventListener('click', function () {
        window.clearTimeout(timer);
        if (node.parentNode) node.parentNode.removeChild(node);
        delete state.toastTimers[title];
      });
    }

    function beginAction(kind) {
      state.busy = kind;
      state.error = null;
      state.retryAction = null;
      render();
    }

    function failAction(kind, error) {
      state.busy = null;
      state.error = text(error && error.message) || 'The demo request failed.';
      state.retryAction = kind;
      render();
      toast('The action did not finish', state.error);
    }

    function startTunnel(quiet) {
      if (state.busy) return Promise.resolve(false);
      beginAction('start');
      return api('/api/start', {
        method: 'POST',
        body: {
          mode: 'phone',
          options: { experimental_icmp: state.ping }
        }
      }).then(function () {
        state.busy = null;
        return refreshStatus().then(function () {
          if (!quiet) toast('Demo tunnel started', 'The session and its counters are simulated.');
          return true;
        });
      }).catch(function (error) {
        failAction('start', error);
        return false;
      });
    }

    function stopTunnel(quiet) {
      if (state.busy) return Promise.resolve(false);
      beginAction('stop');
      return api('/api/stop', { method: 'POST', body: {} }).then(function () {
        state.busy = null;
        state.forgetBlocked = false;
        return refreshStatus().then(function () {
          if (!quiet) toast('Demo tunnel stopped', 'No route or device changed.');
          return true;
        });
      }).catch(function (error) {
        failAction('stop', error);
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
        api('/api/phone/pair').then(function (data) {
          state.pair = object(data);
          var phase = text(state.pair.state);
          render();
          if (phase === 'connecting' || phase === 'confirm' || phase === 'starting') {
            pollPair();
          } else {
            state.busy = null;
            if (phase === 'paired') {
              toast('Pairing is ready', 'The pairing is simulated. No connection was made.');
              refreshStatus();
            } else if (phase === 'failed') {
              state.error = text(state.pair.error) || 'The pairing failed. Try again.';
              state.retryAction = 'pair';
              render();
            }
          }
        }).catch(function (error) {
          state.busy = null;
          state.error = text(error && error.message) || 'The pairing status is unavailable.';
          state.retryAction = 'pair';
          render();
        });
      }, PAIR_POLL_MS);
    }

    function startPairing() {
      if (state.busy) return Promise.resolve(false);
      clearPairPoll();
      state.pair = { state: 'connecting' };
      beginAction('pair');
      return api('/api/phone/pair', { method: 'POST', body: {} }).then(function (data) {
        state.pair = object(data);
        state.busy = null;
        adoptPairState();
        render();
        pollPair();
        return true;
      }).catch(function (error) {
        state.pair = null;
        failAction('pair', error);
        return false;
      });
    }

    function cancelPairing() {
      clearPairPoll();
      state.busy = 'pair';
      render();
      return api('/api/phone/pair/cancel', { method: 'POST', body: {} }).then(function (data) {
        state.pair = object(data);
        state.busy = null;
        state.error = null;
        state.retryAction = null;
        render();
        return true;
      }).catch(function (error) {
        failAction('pair', error);
        return false;
      });
    }

    function forgetSourceDevice() {
      if (state.busy) return Promise.resolve(false);
      beginAction('forget');
      return api('/api/phone/forget', { method: 'POST', body: {} }).then(function () {
        state.busy = null;
        state.error = null;
        state.retryAction = null;
        state.forgetBlocked = false;
        state.pair = { state: 'idle' };
        clearPairPoll();
        return refreshStatus().then(function () {
          toast('Source device forgotten', 'The simulated pairing is removed from this target device.');
          return true;
        });
      }).catch(function (error) {
        if (error && error.status === 409) {
          state.busy = null;
          state.forgetBlocked = true;
          state.error = null;
          state.retryAction = null;
          render();
          toast('Turn off the tunnel first', 'The demo keeps the pairing while the tunnel runs.');
          return false;
        }
        failAction('forget', error);
        return false;
      });
    }

    function stopAndForget() {
      if (state.busy) return Promise.resolve(false);
      return stopTunnel(true).then(function (stopped) {
        if (!stopped) return false;
        return forgetSourceDevice();
      });
    }

    function checkNow() {
      if (state.busy) return Promise.resolve(false);
      beginAction('check');
      return api('/api/phone/probe', { method: 'POST', body: {} }).then(function (data) {
        state.busy = null;
        if (data && data.phone) {
          var status = object(state.status);
          status.phone = data.phone;
          state.status = status;
        }
        return refreshStatus().then(function () {
          toast('Check finished', 'The source device answer is simulated.');
          return true;
        });
      }).catch(function (error) {
        failAction('checkNow', error);
        return false;
      });
    }

    function retryLastAction() {
      var target = state.retryAction || 'checkNow';
      if (target === 'start') return startTunnel(false);
      if (target === 'stop') return stopTunnel(false);
      if (target === 'pair') return startPairing();
      if (target === 'forget') return forgetSourceDevice();
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

    /* ------------------------------- render ----------------------------- */

    function derivedState() {
      return model.deriveDashboard({
        status: state.status,
        hasStatus: state.hasStatus,
        pair: state.pair,
        freshness: currentFreshness(),
        busy: state.busy,
        error: state.error,
        forgetBlocked: state.forgetBlocked,
        nowSeconds: nowSeconds()
      });
    }

    function render() {
      var derived = derivedState();
      var pairing = model.pairingView(state.pair, state.busy);
      var pairingVisible = pairing.active || state.busy === 'pair';

      sections.dashboard.hidden = state.view !== 'dashboard';
      sections.activity.hidden = state.view !== 'activity';
      sections.settings.hidden = state.view !== 'settings';

      navItems.forEach(function (item) {
        if (item.getAttribute('data-view') === state.view) item.setAttribute('aria-current', 'page');
        else item.removeAttribute('aria-current');
      });

      var titles = {
        dashboard: 'Dashboard',
        activity: 'Activity',
        settings: 'Settings'
      };
      document.title = 'HotspotShade Desktop (Demo) · ' + titles[state.view];

      var dashboardNav = document.querySelector('.nav-item[data-view="dashboard"]');
      if (dashboardNav) dashboardNav.setAttribute('aria-label', 'Dashboard. ' + derived.title);

      dom.navStatusDot.className = 'nav-status-dot is-' + derived.kind;
      dom.statusDot.className = 'status-dot is-' + derived.kind;
      setText(dom.dashboardTitle, derived.title);
      setText(dom.dashboardSubtitle, derived.subtitle);
      setText(dom.dashboardChecked, derived.checked || '');
      dom.dashboardChecked.hidden = !derived.checked;
      dom.dashboardContent.hidden = pairingVisible;
      dom.pairingPanel.hidden = !pairingVisible;

      setText(dom.pairingMessage, pairing.message);
      dom.pairingSpinner.hidden = !(pairing.state === 'connecting' || pairing.state === 'starting');
      dom.pairCodeBlock.hidden = !pairing.code;
      setText(dom.pairCode, pairing.code || '');
      dom.copyCode.disabled = !pairing.code;
      dom.cancelPairing.disabled = state.busy === 'pair';

      if (derived.primary) {
        dom.primaryAction.hidden = false;
        dom.primaryAction.dataset.action = derived.primary.id;
        setText(dom.primaryAction, derived.primary.label);
        dom.primaryAction.disabled = !!state.busy;
      } else {
        dom.primaryAction.hidden = true;
        dom.primaryAction.dataset.action = '';
        dom.primaryAction.disabled = true;
      }

      if (derived.secondary) {
        dom.secondaryAction.hidden = false;
        dom.secondaryAction.dataset.action = derived.secondary.id;
        setText(dom.secondaryAction, derived.secondary.label);
        dom.secondaryAction.disabled = !!state.busy;
      } else {
        dom.secondaryAction.hidden = true;
        dom.secondaryAction.dataset.action = '';
        dom.secondaryAction.disabled = true;
      }

      dom.dashboardError.hidden = true;
      setText(dom.dashboardError, '');

      setText(dom.sourceValue, derived.source.value);
      renderList(dom.sourceDetails, derived.source.details);
      setText(dom.connectionValue, derived.connection.value);
      renderList(dom.connectionDetails, derived.connection.details);

      dom.attentionCard.hidden = derived.attention.length === 0;
      renderList(dom.attentionList, derived.attention);

      var status = object(state.status);
      var platform = object(status.platform);
      var os = displayOs(platform.os);
      var arch = text(platform.arch);
      var iface = text(status.iface) || text(platform.default_iface);
      var platformText = [os, arch].filter(Boolean).join(' · ');
      setText(dom.platformText, platformText || 'Local host');
      dom.platformBadge.classList.toggle('is-detected', !!platform.os);
      dom.platformBadge.title = [
        os,
        arch,
        platform.admin === true ? 'elevated' : 'standard user',
        iface ? 'interface ' + iface : 'no default interface'
      ].filter(Boolean).join(' · ');

      setText(dom.appPlatform, [os, arch].filter(Boolean).join(' · ') || 'Unknown');
      setText(dom.appIface, iface || 'Unknown');
      setText(dom.appStatus, derived.title);
      setText(dom.appMode, status.demo === true ? 'Demo. Data is simulated.' : 'Demo bridge');
      setText(dom.appDemo, status.demo === true ? 'Simulated by DemoBackend' : 'Not reported');

      dom.pingToggle.checked = state.ping;
      themeChoices.forEach(function (choice) {
        var value = choice.getAttribute('data-theme-pref');
        choice.setAttribute('aria-pressed', String(value === state.themePreference));
      });
      var actual = effectiveTheme(state.themePreference);
      dom.themeToggle.setAttribute('aria-label', actual === 'dark' ? 'Switch to light appearance' : 'Switch to dark appearance');
      dom.themeToggle.title = actual === 'dark' ? 'Switch to light appearance' : 'Switch to dark appearance';

      renderSettings(derived);
      if (state.view === 'activity') renderActivity();
    }

    function renderSettings(derived) {
      var status = object(state.status);
      var phone = object(status.phone);
      var paired = status.paired === true;
      var running = status.running === true;
      var pairing = model.pairingView(state.pair, state.busy);
      var phoneState = text(phone.state);

      var pairingState = paired ? 'Paired' : 'Not paired';
      if (phoneState === 'not_trusted') pairingState = 'Not trusted';
      if (pairing.active) pairingState = 'Pairing';
      setText(dom.settingsPairingState, pairingState);

      var pairingMessage = text(phone.message);
      if (pairing.active) pairingMessage = pairing.message;
      else if (!pairingMessage) pairingMessage = derived.subtitle;
      setText(dom.settingsPairingMessage, pairingMessage);

      var pairHidden = running || pairing.active || state.busy === 'pair';
      dom.settingsPair.hidden = pairHidden;
      dom.settingsPair.disabled = !!state.busy;
      dom.settingsCancel.hidden = !pairing.active;
      dom.settingsCancel.disabled = !!state.busy;
      dom.settingsForget.hidden = !paired || running || pairing.active;
      dom.settingsForget.disabled = !!state.busy;
      dom.settingsTurnOffForget.hidden = !running;
      dom.settingsTurnOffForget.disabled = !!state.busy;

      var forgetText = model.forgetMessage(status.forget);
      if (state.forgetBlocked) forgetText = model.FORGET_BLOCKED;
      setText(dom.settingsForgetMessage, forgetText || '');
      dom.settingsForgetMessage.hidden = !forgetText;

      dom.failuresRefresh.disabled = state.failuresLoading;
      dom.copyDiagnostics.textContent = 'Copy diagnostics';
      renderFailures();
    }

    function renderFailures() {
      var data = state.failures;
      var groups = data && Array.isArray(data.groups) ? data.groups : [];
      var demo = !!(data && data.demo);
      dom.failuresRefresh.disabled = state.failuresLoading;
      if (!state.failuresLoaded) {
        setText(dom.failuresSummary, state.failuresLoading ? 'Loading recent failures.' : 'Press Refresh to read the simulated failures.');
        dom.failuresTable.hidden = true;
        dom.failuresEmpty.hidden = true;
        dom.copyFailures.disabled = true;
        return;
      }
      if (!data) {
        setText(dom.failuresSummary, 'The simulated failures are unavailable.');
        dom.failuresTable.hidden = true;
        dom.failuresEmpty.hidden = true;
        dom.copyFailures.disabled = true;
        return;
      }
      if (!groups.length) {
        setText(dom.failuresSummary, demo ? 'Simulated data. No failed connections yet.' : 'No failed connections yet.');
        dom.failuresTable.hidden = true;
        dom.failuresEmpty.hidden = false;
        dom.copyFailures.disabled = true;
        return;
      }

      var total = Number(data.total) || 0;
      setText(dom.failuresSummary, (demo ? 'Simulated data. ' : '') + model.formatInt(total) + ' failed ' + (total === 1 ? 'attempt' : 'attempts') + ' this session.');
      dom.failuresTable.hidden = false;
      dom.failuresEmpty.hidden = true;
      dom.copyFailures.disabled = false;

      dom.failuresBody.textContent = '';
      model.failureRows(data).forEach(function (row) {
        var tableRow = document.createElement('tr');
        var count = document.createElement('td');
        count.textContent = model.formatInt(row.count) + 'x';
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

    function activityEntry(entry) {
      var level = text(entry && entry.level).toLowerCase();
      if (level !== 'warn' && level !== 'error' && level !== 'debug') level = 'info';
      return {
        level: level,
        time: model.formatClock(entry && entry.ts),
        message: text(entry && entry.msg),
        seq: entry && entry.seq !== undefined ? String(entry.seq) : ''
      };
    }

    function renderActivity() {
      var entries = state.logs.map(activityEntry).filter(function (entry) { return entry.message; });
      var empty = entries.length === 0;
      dom.activityEmpty.hidden = !empty;
      dom.activityList.hidden = empty;
      dom.activityDetailsToggle.setAttribute('aria-pressed', String(state.activityDetails));
      dom.activityRefresh.disabled = state.activityLoading;

      if (empty) {
        if (state.activityLoading) {
          setText(dom.activityEmptyTitle, 'Loading activity');
          setText(dom.activityEmptyText, 'Waiting for the demo backend.');
        } else if (state.activityError) {
          setText(dom.activityEmptyTitle, 'Activity unavailable');
          setText(dom.activityEmptyText, state.activityError);
        } else {
          setText(dom.activityEmptyTitle, 'No activity yet');
          setText(dom.activityEmptyText, 'Start the simulated tunnel to create entries.');
        }
        dom.activityList.textContent = '';
        return;
      }

      dom.activityList.textContent = '';
      entries.forEach(function (entry) {
        var row = document.createElement('li');
        row.className = 'activity-row level-' + entry.level;
        var time = document.createElement('span');
        time.className = 'activity-time';
        time.textContent = entry.time;
        var body = document.createElement('div');
        body.className = 'activity-body';
        if (state.activityDetails) {
          var details = document.createElement('p');
          details.className = 'activity-details';
          details.textContent = [entry.level, entry.seq ? 'seq ' + entry.seq : ''].filter(Boolean).join(', ');
          body.appendChild(details);
        }
        var message = document.createElement('p');
        message.className = 'activity-message';
        message.textContent = entry.message;
        body.appendChild(message);
        row.appendChild(time);
        row.appendChild(body);
        dom.activityList.appendChild(row);
      });
      dom.activityList.scrollTop = dom.activityList.scrollHeight;
      dom.activityDetailsToggle.setAttribute('aria-pressed', String(state.activityDetails));
    }

    /* ------------------------------- logs ------------------------------- */

    function loadLogs(reset) {
      if (state.activityLoading) return Promise.resolve();
      state.activityLoading = true;
      state.activityError = null;
      var since = reset ? 0 : state.lastSeq;
      renderActivity();
      return api('/api/logs?since=' + encodeURIComponent(String(since))).then(function (data) {
        if (reset) {
          state.logs = [];
          state.lastSeq = 0;
        }
        mergeLogs(data.logs);
        var next = Number(data.next);
        if (isFinite(next) && next > state.lastSeq) state.lastSeq = next;
        state.activityLoading = false;
        renderActivity();
      }).catch(function (error) {
        state.activityLoading = false;
        state.activityError = text(error && error.message) || 'Activity is unavailable.';
        renderActivity();
      });
    }

    /* ------------------------------ failures ---------------------------- */

    function loadFailures() {
      if (state.failuresLoading) return Promise.resolve();
      state.failuresLoading = true;
      renderFailures();
      return api('/api/failures').then(function (data) {
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

    function failureReport() {
      return model.failureReport(state.failures);
    }

    function diagnosticsReport(data) {
      data = object(data);
      var engine = object(data.engine);
      var setup = object(data.setup);
      var dns = object(data.dns);
      var queues = object(data.queues);
      var udp = object(data.udp);
      var tcp = object(data.tcp);
      var failures = object(data.failures);
      var input = Array.isArray(queues.input) ? queues.input : [];

      function metric(value) {
        value = object(value);
        return 'count ' + model.formatInt(value.count) +
          ', p50 ' + model.formatInt(value.p50) + ' ms' +
          ', p95 ' + model.formatInt(value.p95) + ' ms' +
          ', max ' + model.formatInt(value.max) + ' ms';
      }

      function queue(label, value) {
        value = object(value);
        return label + ': peak ' + model.formatInt(value.peak) +
          ', max age ' + model.formatInt(value.max_age_us) + ' us';
      }

      var lines = [
        'HotspotShade diagnostics (demo data)',
        'Demo: ' + (data.demo === true ? 'yes' : 'unknown'),
        'Version: ' + (text(engine.version) || 'unknown'),
        'Running: ' + (data.running === true ? 'yes' : 'no'),
        'Uptime: ' + model.formatInt(engine.uptime_s) + ' s',
        'Workers: ' + model.formatInt(engine.workers),
        'Connect: ' + metric(setup.connect_ms),
        'Greeting: ' + metric(setup.greeting_ms),
        'Auth: ' + metric(setup.auth_ms),
        'Request: ' + metric(setup.request_ms),
        'DNS lookups: ' + model.formatInt(dns.lookups) +
          ' (ok ' + model.formatInt(dns.ok) + ', failed ' + model.formatInt(dns.failed) + ')',
        'DNS time: ' + metric(dns.ms)
      ];
      if (input.length) {
        input.forEach(function (value, index) { lines.push(queue('Input queue ' + (index + 1), value)); });
      } else {
        lines.push('Input queue: none');
      }
      lines.push(queue('Output queue', queues.output));
      lines.push('UDP flows: ' + model.formatInt(udp.flows) + ', age drops: ' + model.formatInt(udp.age_drops));
      lines.push('TCP flows peak: ' + model.formatInt(tcp.flows_peak) +
        ', retransmits: ' + model.formatInt(tcp.retransmits) +
        ', zero window: ' + model.formatInt(tcp.zero_window_ms) + ' ms');
      lines.push('Failures: total ' + model.formatInt(failures.total) + ', dropped ' + model.formatInt(failures.dropped));
      return lines.join('\n');
    }

    function copyText(value) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(value);
      }
      return new Promise(function (resolve, reject) {
        var area = document.createElement('textarea');
        area.value = value;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.top = '-1000px';
        document.body.appendChild(area);
        area.select();
        var copied = false;
        try {
          copied = document.execCommand('copy');
        } catch (error) {
          copied = false;
        }
        document.body.removeChild(area);
        if (copied) resolve();
        else reject(new Error('The copy failed.'));
      });
    }

    function setCopyState(message) {
      setText(dom.copyState, message);
      if (message) {
        window.setTimeout(function () {
          if (dom.copyState.textContent === message) setText(dom.copyState, '');
        }, 4000);
      }
    }

    function copyDiagnosticsReport() {
      api('/api/diagnostics').then(function (data) {
        return copyText(diagnosticsReport(data)).then(function () {
          setCopyState('Copied.');
          toast('Diagnostics copied', 'A plain-text demo summary is on the clipboard.');
        });
      }).catch(function (error) {
        setCopyState('');
        toast('Could not copy diagnostics', text(error && error.message) || 'The diagnostics are unavailable.');
      });
    }

    function copyFailureReport() {
      var report = failureReport();
      if (!report) return;
      copyText(report).then(function () {
        toast('Failure report copied', 'One line for each simulated group.');
      }).catch(function () {
        toast('Could not copy the report', 'Select the rows and copy them by hand.');
      });
    }

    /* ------------------------------- theme ------------------------------ */

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
          /* private mode */
        }
      }
      render();
    }

    function toggleTheme() {
      applyTheme(effectiveTheme(state.themePreference) === 'dark' ? 'light' : 'dark', true);
    }

    /* ------------------------------- views ------------------------------ */

    function setView(view, focus) {
      if (view !== 'dashboard' && view !== 'activity' && view !== 'settings') view = 'dashboard';
      state.view = view;
      if (focus !== false) {
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
      if (view === 'activity') loadLogs(state.logs.length === 0);
    }

    function selectSettingsTab(tab, focus) {
      if (SETTINGS_TABS.indexOf(tab) === -1) tab = 'general';
      state.settingsTab = tab;
      settingsTabs.forEach(function (button) {
        var current = button.getAttribute('data-settings-tab') === tab;
        button.setAttribute('aria-selected', String(current));
        button.tabIndex = current ? 0 : -1;
        if (current && focus) button.focus();
      });
      dom.settingsGeneralPanel.hidden = tab !== 'general';
      dom.settingsPairingPanel.hidden = tab !== 'pairing';
      dom.settingsAdvancedPanel.hidden = tab !== 'advanced';
      if (tab === 'advanced' && !state.failuresLoaded) loadFailures();
      render();
    }

    function viewFromHash() {
      var name = String(window.location.hash || '').replace('#', '');
      if (VIEWS.indexOf(name) !== -1) return name;
      return 'dashboard';
    }

    /* ------------------------------- wiring ----------------------------- */

    dom.primaryAction.addEventListener('click', function () {
      performAction(dom.primaryAction.dataset.action);
    });

    dom.secondaryAction.addEventListener('click', function () {
      performAction(dom.secondaryAction.dataset.action);
    });

    dom.cancelPairing.addEventListener('click', function () {
      cancelPairing();
    });

    dom.copyCode.addEventListener('click', function () {
      if (!model.pairingView(state.pair, state.busy).code) return;
      copyText(model.pairingView(state.pair, state.busy).code).then(function () {
        toast('Pairing code copied', 'The code is simulated.');
      }).catch(function () {
        toast('Could not copy the code', 'Read the code on this screen.');
      });
    });

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
      setView('settings', true);
      selectSettingsTab('advanced', false);
      dom.demoLimits.setAttribute('tabindex', '-1');
      dom.demoLimits.focus();
      dom.demoLimits.scrollIntoView({ block: 'nearest' });
    });

    dom.activityDetailsToggle.addEventListener('click', function () {
      state.activityDetails = !state.activityDetails;
      dom.activityDetailsToggle.setAttribute('aria-pressed', String(state.activityDetails));
      renderActivity();
    });

    dom.activityRefresh.addEventListener('click', function () {
      loadLogs(true);
    });

    dom.failuresRefresh.addEventListener('click', function () {
      loadFailures();
    });

    dom.copyFailures.addEventListener('click', copyFailureReport);
    dom.copyDiagnostics.addEventListener('click', copyDiagnosticsReport);

    dom.pingToggle.addEventListener('change', function () {
      state.ping = !!dom.pingToggle.checked;
      try {
        localStorage.setItem(PING_KEY, state.ping ? 'true' : 'false');
      } catch (error) {
        /* private mode */
      }
      toast(state.ping ? 'Ping is on for the next start' : 'Ping is off for the next start',
        'The setting applies to the simulated session only.');
    });

    themeChoices.forEach(function (choice) {
      choice.addEventListener('click', function () {
        applyTheme(choice.getAttribute('data-theme-pref'), true);
      });
    });

    navItems.forEach(function (item) {
      item.addEventListener('click', function () {
        setView(item.getAttribute('data-view'), true);
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

    document.addEventListener('visibilitychange', schedulePoll);

    window.__hotspotshadeMenu = function (action) {
      if (action === 'dashboard' || action === 'activity') {
        setView(action, true);
      } else if (action === 'settings') {
        setView('settings', true);
        selectSettingsTab('general', false);
      } else if (action === 'advanced') {
        setView('settings', true);
        selectSettingsTab('advanced', false);
        dom.demoLimits.setAttribute('tabindex', '-1');
        dom.demoLimits.focus();
      } else if (action === 'refresh') {
        refreshAll();
      } else if (action === 'check-now') {
        checkNow();
      } else if (action === 'theme') {
        toggleTheme();
      }
    };

    applyTheme(state.themePreference, false);
    setView(viewFromHash(), false);
    refreshStatus().then(function () {
      refreshPair();
      schedulePoll();
    }, function () {
      schedulePoll();
    });

    window.setInterval(function () {
      var freshness = currentFreshness();
      if (freshness !== state.freshness) {
        state.freshness = freshness;
        render();
      }
    }, 1000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
