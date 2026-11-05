/* HotspotShade local GUI, application logic (no external dependencies) */
(function () {
  'use strict';

  /* ---------------------------- theme bootstrap ---------------------------- */
  var THEME_KEY = 'hs-theme';
  var CONFIG_KEY = 'hs-config';
  var PING_KEY = 'hs-ping';

  function queryValue(name) {
    var match = location.search.match(new RegExp('[?&]' + name + '=([^&]*)'));
    if (!match) return null;
    try { return decodeURIComponent(match[1]); } catch (e) { return null; }
  }

  function storedTheme() {
    try { return localStorage.getItem(THEME_KEY); } catch (e) { return null; }
  }
  function systemTheme() {
    try {
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    } catch (e) { return 'light'; }
  }
  function validTheme(value) {
    return value === 'light' || value === 'dark';
  }

  // Ping is on by default. The stored value applies to the next start.
  function storedPing() {
    try {
      var value = localStorage.getItem(PING_KEY);
      if (value === 'true') return true;
      if (value === 'false') return false;
    } catch (e) { /* private mode */ }
    return true;
  }

  var bootTheme = queryValue('theme');
  if (!validTheme(bootTheme)) bootTheme = storedTheme();
  if (!validTheme(bootTheme)) bootTheme = systemTheme();
  document.documentElement.setAttribute('data-theme', bootTheme);

  /* ------------------------------- constants ------------------------------- */

  var TITLES = {
    dashboard: { title: 'Dashboard', sub: 'Start a mode and watch counters.' },
    configure: { title: 'Configure', sub: 'Set the mode and connection options.' },
    logs: { title: 'Logs', sub: 'Service events from the local backend.' },
    about: { title: 'About', sub: 'How the TTL normalizer works.' }
  };

  var ICONS = {
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 4.5 4.5L19 7"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg>',
    warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4 3.8 18.4A1 1 0 0 0 4.7 20h14.6a1 1 0 0 0 .9-1.6L12 4Z"/><path d="M12 9.5v4M12 17h.01"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7.8h.01"/></svg>',
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m8 12 2.7 2.7L16.5 9"/></svg>',
    error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/></svg>',
    close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg>',
    play: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5.5v13a1 1 0 0 0 1.5.86l10.2-6.5a1 1 0 0 0 0-1.72L9.5 4.64A1 1 0 0 0 8 5.5Z"/></svg>',
    pause: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="7" y="5" width="3.5" height="14" rx="1"/><rect x="13.5" y="5" width="3.5" height="14" rx="1"/></svg>'
  };

  /* ---------------------------------- init --------------------------------- */
  function init() {
    var dom = {};
    [
      'pageTitle', 'pageSubtitle', 'platformBadge', 'platformText', 'demoPill', 'themeToggle', 'toastRegion',
      'sideStatus', 'sideDot', 'sideStatusText',
      'statusPill', 'statusText', 'heroUptime', 'heroTitle', 'heroDesc', 'dashMode',
      'startBtn', 'startBtnSpinner', 'startBtnIcon', 'startBtnLabel', 'stopBtn', 'heroHint', 'heroPing', 'heroError', 'heroErrorText',
      'lastStopNote', 'lastStopAlert', 'lastStopText',
      'livePill', 'liveText',
      'metricTcp', 'metricTcpSub', 'metricPackets', 'metricPacketsSub', 'metricBytes', 'metricBytesSub',
      'metricTtl', 'metricTtlSub', 'metricTcpLabel',
      'statsSummary', 'statDnsFlows', 'statDnsOk', 'statDnsFailed', 'copyDiagnostics',
      'failuresSummary', 'failureList', 'copyFailures',
      'healthSummary', 'healthList', 'recentLogs', 'viewLogsBtn',
      'configForm', 'modeSelect', 'modeHelp', 'hostInput', 'hostError', 'portInput', 'portError',
      'dnsInput', 'dnsError', 'ifaceInput', 'ifaceBadge', 'ifaceField', 'pinToggle', 'pinRow', 'socksCard', 'tunCard',
      'phoneCard', 'phonePresence', 'pairPill', 'pairPillText', 'pairStatus', 'pairCodeBlock', 'pairCode', 'pingToggle', 'pingHelp', 'pairStart', 'pairCancel', 'pairForget', 'phoneProbe', 'manualDetails', 'phoneHost', 'phoneHostError', 'phonePort', 'phonePortError', 'phoneToken', 'phoneTokenError', 'phoneDiscover', 'phoneCheck', 'phoneResult',
      'tunDnsInput', 'tunDnsError', 'ipv6Toggle', 'advancedDetails', 'unitInput', 'unitError',
      'addrInput', 'addrError', 'configNote', 'configStopBtn', 'configStartBtn',
      'configStartBtnSpinner', 'configStartBtnLabel',
      'logCount', 'pauseBtn', 'pauseLabel', 'pauseIcon', 'clearLogsBtn', 'autoScrollToggle',
      'logsPanel', 'logsEmpty', 'logsEmptyTitle', 'logsEmptyText', 'logList'
    ].forEach(function (id) { dom[id] = document.getElementById(id); });

    dom.sections = {};
    ['dashboard', 'configure', 'logs', 'about'].forEach(function (view) {
      dom.sections[view] = document.getElementById('view-' + view);
    });
    dom.navItems = Array.prototype.slice.call(document.querySelectorAll('.nav-item'));
    dom.modeButtons = Array.prototype.slice.call(document.querySelectorAll('#dashMode .seg-btn'));

    var state = {
      theme: bootTheme,
      view: 'dashboard',
      status: null,
      probe: null,
      running: false,
      busy: null,
      actionError: null,
      actionErrorTimer: null,
      config: loadConfig(),
      ping: storedPing(),
      logs: [],
      lastSeq: 0,
      renderedThrough: 0,
      paused: false,
      autoScroll: true,
      healthKey: '',
      serverDown: false,
      failures: null,
      mutationEpoch: 0,
      statusInFlight: null,
      toasts: {},
      probeLoaded: false,
      pair: null,
      phone: null,
      forget: null,
      pairTimer: null,
      pairThenStart: false
    };

    /* ------------------------------- utilities ------------------------------ */

    function defaultConfig() {
      return {
        mode: 'socks5', host: '127.0.0.1', port: 1080, dns: '', iface: '',
        pin: true, tunDns: '', ipv6: true, unit: 0, addr: '198.18.0.1'
      };
    }

    function loadConfig() {
      var cfg = defaultConfig();
      var raw;
      try { raw = JSON.parse(localStorage.getItem(CONFIG_KEY) || 'null'); } catch (e) { raw = null; }
      if (!raw || typeof raw !== 'object') return cfg;
      if (raw.mode === 'socks5' || raw.mode === 'tun' || raw.mode === 'auto' || raw.mode === 'phone') cfg.mode = raw.mode;
      if (typeof raw.host === 'string' && raw.host.trim()) cfg.host = raw.host.trim();
      if (raw.port !== undefined && raw.port !== null && raw.port !== '') cfg.port = raw.port;
      if (typeof raw.dns === 'string') cfg.dns = raw.dns;
      if (typeof raw.iface === 'string') cfg.iface = raw.iface;
      if (typeof raw.pin === 'boolean') cfg.pin = raw.pin;
      if (typeof raw.tunDns === 'string') cfg.tunDns = raw.tunDns;
      if (typeof raw.ipv6 === 'boolean') cfg.ipv6 = raw.ipv6;
      if (raw.unit !== undefined && raw.unit !== null && raw.unit !== '') cfg.unit = raw.unit;
      if (typeof raw.addr === 'string' && raw.addr.trim()) cfg.addr = raw.addr.trim();
      return cfg;
    }

    function saveConfig() {
      try { localStorage.setItem(CONFIG_KEY, JSON.stringify(state.config)); } catch (e) { /* private mode */ }
    }

    function num(value) {
      var n = typeof value === 'number' ? value : parseFloat(value);
      return isFinite(n) ? n : 0;
    }

    function pickNumber(obj) {
      for (var i = 1; i < arguments.length; i++) {
        var key = arguments[i];
        if (obj && obj[key] !== undefined && obj[key] !== null) {
          var n = num(obj[key]);
          if (isFinite(n)) return n;
        }
      }
      return 0;
    }

    function formatInt(value) {
      var n = Math.round(num(value));
      if (Math.abs(n) < 1000) return String(n);
      if (Math.abs(n) < 1000000) {
        var k = n / 1000;
        return (k >= 100 ? Math.round(k) : k.toFixed(1).replace(/\.0$/, '')) + 'k';
      }
      var m = n / 1000000;
      return (m >= 100 ? Math.round(m) : m.toFixed(1).replace(/\.0$/, '')) + 'M';
    }

    function formatBytes(value) {
      var n = num(value);
      if (n < 1024) return Math.round(n) + ' B';
      var units = ['KB', 'MB', 'GB', 'TB'];
      var i = -1;
      do { n = n / 1024; i++; } while (n >= 1024 && i < units.length - 1);
      return (n >= 100 ? Math.round(n) : n.toFixed(1).replace(/\.0$/, '')) + ' ' + units[i];
    }

    function formatDuration(totalSeconds) {
      var s = Math.max(0, Math.floor(totalSeconds));
      if (s < 60) return s + 's';
      var m = Math.floor(s / 60);
      if (m < 60) return m + 'm ' + (s % 60) + 's';
      var h = Math.floor(m / 60);
      if (h < 24) return h + 'h ' + (m % 60) + 'm';
      return Math.floor(h / 24) + 'd ' + (h % 24) + 'h';
    }

    function parseTimeMs(value) {
      if (value === null || value === undefined || value === '') return null;
      if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
      var text = String(value).trim();
      if (/^\d+(\.\d+)?$/.test(text)) {
        var epoch = parseFloat(text);
        return epoch < 1e12 ? epoch * 1000 : epoch;
      }
      var ms = Date.parse(text);
      return isNaN(ms) ? null : ms;
    }

    function formatClock(value) {
      var ms = parseTimeMs(value);
      if (ms === null) return 'n/a';
      var d = new Date(ms);
      function two(n) { return n < 10 ? '0' + n : String(n); }
      return two(d.getHours()) + ':' + two(d.getMinutes()) + ':' + two(d.getSeconds());
    }

    function escapeHtml(text) {
      return String(text === null || text === undefined ? '' : text)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // Update a live region only when the text changes. A repeated write can
    // make a screen reader announce the same message again on every poll.
    function setText(element, text) {
      if (element.textContent !== text) element.textContent = text;
    }

    function modeLabel(mode) {
      if (mode === 'tun') return 'Transparent tunnel';
      if (mode === 'phone') return 'Source device proxy';
      if (mode === 'socks5') return 'SOCKS5 proxy';
      if (mode === 'auto') return 'Automatic';
      return 'Session';
    }

    function platformInfo() {
      var st = state.status || {};
      return st.platform || (state.probe && state.probe.platform) || {};
    }

    function displayOs(value) {
      var s = String(value || '').toLowerCase();
      if (s.indexOf('mac') === 0 || s === 'darwin') return 'macOS';
      if (s.indexOf('win') === 0) return 'Windows';
      if (s.indexOf('linux') === 0) return 'Linux';
      return value ? String(value) : 'Unknown OS';
    }

    function capabilities() {
      var p = platformInfo();
      var probe = state.probe || {};
      return (probe.capabilities) || (probe.platform && probe.platform.capabilities) || p.capabilities || {};
    }

    function resolveMode(mode) {
      if (mode !== 'auto') return mode;
      var p = platformInfo();
      return p.admin ? 'tun' : 'socks5';
    }

    function detectedIface() {
      var p = platformInfo();
      return p.default_iface || (state.probe && state.probe.default_iface) || '';
    }

    /* --------------------------------- API ---------------------------------- */

    function api(path, options) {
      options = options || {};
      var init = { cache: 'no-store', headers: { 'Accept': 'application/json' } };
      if (options.method) init.method = options.method;
      if (options.body !== undefined) {
        init.headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(options.body);
      }

      var controller = null;
      var timer = null;
      if (typeof window.AbortController === 'function') {
        controller = new window.AbortController();
        init.signal = controller.signal;
        timer = setTimeout(function () { controller.abort(); }, 8000);
      }

      function clearTimer() {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
      }

      return fetch(path, init).then(function (res) {
        return res.text().then(function (text) {
          var data = {};
          if (text) {
            try { data = JSON.parse(text); } catch (e) { data = {}; }
          }
          if (!res.ok || data.ok === false) {
            var message = (data && (data.error || data.message)) ? (data.error || data.message) : ('Request failed. HTTP ' + res.status + '.');
            var err = new Error(message);
            err.status = res.status;
            err.data = data;
            throw err;
          }
          return data;
        });
      }).catch(function (err) {
        if (err && err.name === 'AbortError') {
          throw new Error('The local server did not answer in time.');
        }
        if (err instanceof TypeError) {
          throw new Error('Cannot reach the local server.');
        }
        throw err;
      }).then(function (value) {
        clearTimer();
        return value;
      }, function (err) {
        clearTimer();
        throw err;
      });
    }

    /* ------------------------------- rendering ------------------------------ */

    function setActionError(message) {
      if (state.actionErrorTimer) {
        clearTimeout(state.actionErrorTimer);
        state.actionErrorTimer = null;
      }
      state.actionError = message || null;
      dom.heroError.hidden = !state.actionError;
      dom.heroErrorText.textContent = state.actionError || '';
      if (state.actionError) {
        state.actionErrorTimer = setTimeout(function () {
          state.actionError = null;
          state.actionErrorTimer = null;
          if (state.status) renderStatus(state.status);
        }, 12000);
      }
    }

    function setStopStyle(button, running) {
      if (!button) return;
      button.classList.toggle('btn-primary', !!running);
      button.classList.toggle('btn-secondary', !running);
    }

    function renderStatus(status) {
      if (!status || typeof status !== 'object') status = {};
      state.status = status;
      state.serverDown = false;
      var presence = status.phone && typeof status.phone === 'object' ? status.phone : null;
      state.phone = presence;
      state.forget = status.forget && typeof status.forget === 'object' ? status.forget : null;
      // One status line at a time. The pairing line is the live region and
      // shows the engine message. The presence line shows only the connection
      // count, so the two lines never repeat the same sentence.
      renderLastStop(status);
      renderPhoneSummary();
      updatePairUI();

      var running = !!status.running;
      var mode = status.mode || null;
      var error = state.actionError || (status.error ? String(status.error) : '');
      var platform = status.platform || {};
      var iface = platform.default_iface || detectedIface() || '';
      var selected = running && mode ? mode : resolveMode(state.config.mode);

      state.running = running;

      dom.demoPill.hidden = !status.demo;
      if (status.demo) {
        dom.demoPill.title = 'Simulated data. No sockets open. No traffic leaves this machine.';
      }

      var platformText = [displayOs(platform.os), platform.arch || ''].filter(Boolean).join(' · ');
      dom.platformText.textContent = platformText || 'Local host';
      dom.platformBadge.classList.toggle('is-detected', !!platform.os);
      dom.platformBadge.title = [
        displayOs(platform.os),
        platform.arch || '',
        platform.admin ? 'elevated' : 'standard user',
        iface ? 'interface ' + iface : 'no default interface'
      ].filter(Boolean).join(' · ');

      dom.statusPill.classList.remove('status-idle', 'status-running', 'status-error');
      if (error) {
        dom.statusPill.classList.add('status-error');
        dom.statusText.textContent = 'Error';
      } else if (running) {
        dom.statusPill.classList.add('status-running');
        dom.statusText.textContent = 'Running';
      } else {
        dom.statusPill.classList.add('status-idle');
        dom.statusText.textContent = 'Idle';
      }

      dom.sideStatus.classList.remove('is-running', 'is-error');
      if (error) {
        dom.sideStatus.classList.add('is-error');
        dom.sideStatusText.textContent = 'Error';
      } else if (running) {
        dom.sideStatus.classList.add('is-running');
        dom.sideStatusText.textContent = 'Running';
      } else {
        dom.sideStatusText.textContent = 'Idle';
      }

      if (error) {
        dom.heroTitle.textContent = 'Session error';
        dom.heroDesc.textContent = 'The backend reported an error. Read the message below.';
      } else if (running) {
        dom.heroTitle.textContent = modeLabel(mode) + ' is running';
        if (mode === 'tun') {
          dom.heroDesc.textContent = 'Capture is active on ' + (iface || 'the default interface') +
            '. Outbound flows use TTL 65.' + (state.config.ipv6 ? ' Global IPv6 is blocked.' : ' IPv6 is inherited.');
        } else if (mode === 'phone') {
          dom.heroDesc.textContent = 'Source device proxy mode is active. Routes can bypass it and DNS can leak.';
        } else {
          dom.heroDesc.textContent = 'Point apps at 127.0.0.1:' + state.config.port +
            '. Outbound sockets use TTL 65.';
        }
      } else {
        dom.heroTitle.textContent = 'Not running';
        if (selected === 'tun') {
          dom.heroDesc.textContent = 'Start transparent capture. The process needs admin rights.';
        } else if (selected === 'phone') {
          dom.heroDesc.textContent = 'Start source device proxy mode. The target device pairs with the source device first if needed.';
        } else {
          dom.heroDesc.textContent = 'Start a SOCKS5 proxy on 127.0.0.1:' + state.config.port +
            '. No admin rights needed.';
        }
      }

      dom.heroError.hidden = !error;
      dom.heroErrorText.textContent = error || '';

      dom.livePill.classList.toggle('is-live', running && !error);
      dom.liveText.textContent = error ? 'Attention' : (running ? 'Live' : 'Idle');

      dom.startBtnLabel.textContent = state.busy === 'start'
        ? 'Starting…'
        : (running ? 'Running' : (selected === 'tun' ? 'Start tunnel' : 'Start proxy'));
      dom.configStartBtnLabel.textContent = state.busy === 'start'
        ? 'Starting…'
        : (running ? 'Session running' : 'Start session');

      if (running && mode === 'socks5') {
        dom.heroHint.textContent = '127.0.0.1:' + state.config.port;
      } else if (running && mode === 'tun') {
        dom.heroHint.textContent = iface ? 'Interface ' + iface : 'Default interface';
      } else if (selected === 'phone') {
        dom.heroHint.textContent = 'Routes can bypass the proxy.';
      } else if (selected === 'tun') {
        dom.heroHint.textContent = 'Needs admin rights.';
      } else {
        dom.heroHint.textContent = 'No admin rights needed.';
      }

      var pingShown = running && mode === 'phone';
      dom.heroPing.hidden = !pingShown;
      setText(dom.heroPing, pingShown
        ? (status.icmp_enabled === true ? 'Ping is on.' : 'Ping is off.')
        : '');

      dom.modeButtons.forEach(function (btn) {
        btn.setAttribute('aria-pressed', String(btn.getAttribute('data-mode') === selected));
      });

      dom.ifaceBadge.textContent = iface || 'auto';
      dom.ifaceBadge.title = iface ? 'Detected interface: ' + iface : 'No default interface detected';
      dom.ifaceInput.placeholder = iface || 'auto';

      var noteSpan = dom.configNote.querySelector('span');
      if (noteSpan) {
        noteSpan.textContent = running
          ? 'A session is running. New settings apply on the next start.'
          : (selected === 'phone' ? 'HotspotShade listens on the hotspot.' : 'Binds to 127.0.0.1 only. Nothing is exposed to the hotspot network.');
      }

      if (state.config.mode === 'auto') updateModeUI();

      setStopStyle(dom.stopBtn, running);
      setStopStyle(dom.configStopBtn, running);

      renderMetrics(status);
      renderUptime();
      renderHealth();
      renderRecent();
      syncBusy();
    }

    function renderMetrics(status) {
      var stats = status.stats && typeof status.stats === 'object' ? status.stats : {};
      var running = !!status.running;
      var mode = status.mode || resolveMode(state.config.mode);

      function hasStat(keys) {
        return keys.some(function (key) {
          return stats[key] !== undefined && stats[key] !== null && stats[key] !== '';
        });
      }

      var tcp = pickNumber(stats, 'tcp_flows', 'tcp', 'flows', 'active_flows', 'tcp_active', 'outer_sockets');
      var udp = pickNumber(stats, 'udp_flows', 'udp', 'udp_active');
      var pktsIn = pickNumber(stats, 'packets_in', 'pkt_in', 'pkts_in', 'in_packets', 'rx_packets');
      var pktsOut = pickNumber(stats, 'packets_out', 'pkt_out', 'pkts_out', 'out_packets', 'tx_packets');
      var bytesIn = pickNumber(stats, 'bytes_in', 'rx_bytes', 'in_bytes');
      var bytesOut = pickNumber(stats, 'bytes_out', 'tx_bytes', 'out_bytes');
      var ttlBad = pickNumber(stats, 'ttl_violations', 'ttl_bad', 'ttl_violation', 'bad_ttl', 'ttl_drops');
      var packetsKnown = hasStat([
        'packets_in', 'pkt_in', 'pkts_in', 'in_packets', 'rx_packets',
        'packets_out', 'pkt_out', 'pkts_out', 'out_packets', 'tx_packets'
      ]);
      var bytesKnown = hasStat([
        'bytes_in', 'rx_bytes', 'in_bytes', 'bytes_out', 'tx_bytes', 'out_bytes'
      ]);

      if (running) {
        dom.metricTcpLabel.textContent = mode === 'socks5' ? 'Open sockets' : 'TCP flows';
        dom.metricTcp.textContent = hasStat(['tcp_flows', 'tcp', 'flows', 'active_flows', 'tcp_active', 'outer_sockets']) ? formatInt(tcp) : 'n/a';
        dom.metricTcpSub.textContent = mode === 'socks5'
          ? 'SOCKS5 egress sockets'
          : (hasStat(['udp_flows', 'udp', 'udp_active']) ? formatInt(udp) + ' UDP flow' + (Math.round(udp) === 1 ? '' : 's') : 'UDP flow count unavailable.');

        if (packetsKnown) {
          dom.metricPackets.textContent = formatInt(pktsIn + pktsOut);
          dom.metricPacketsSub.textContent = formatInt(pktsIn) + ' in · ' + formatInt(pktsOut) + ' out';
        } else {
          dom.metricPackets.textContent = 'n/a';
          dom.metricPacketsSub.textContent = 'Not available.';
        }

        if (bytesKnown) {
          dom.metricBytes.textContent = formatBytes(bytesIn + bytesOut);
          dom.metricBytesSub.textContent = formatBytes(bytesIn) + ' in · ' + formatBytes(bytesOut) + ' out';
        } else {
          dom.metricBytes.textContent = 'n/a';
          dom.metricBytesSub.textContent = 'Not available.';
        }

        var ttlKnown = hasStat(['ttl_violations', 'ttl_bad', 'ttl_violation', 'bad_ttl', 'ttl_drops']);
        dom.metricTtl.textContent = ttlKnown ? formatInt(ttlBad) : 'n/a';
        dom.metricTtlSub.textContent = !ttlKnown ? 'Audit data unavailable.' : (ttlBad > 0 ? 'Dropped and counted.' : 'None detected.');
      } else {
        dom.metricTcpLabel.textContent = 'TCP flows';
        dom.metricTcp.textContent = '0';
        dom.metricTcpSub.textContent = 'No activity';
        dom.metricPackets.textContent = '0';
        dom.metricPacketsSub.textContent = '0 in · 0 out';
        dom.metricBytes.textContent = '0 B';
        dom.metricBytesSub.textContent = '0 B in · 0 B out';
        dom.metricTtl.textContent = '0';
        dom.metricTtlSub.textContent = 'None detected';
      }

      function statCell(el, key) {
        if (!running || !hasStat([key])) {
          el.textContent = running ? 'n/a' : 'No data';
          el.classList.add('is-empty');
        } else {
          el.textContent = formatInt(pickNumber(stats, key));
          el.classList.remove('is-empty');
        }
      }
      statCell(dom.statDnsFlows, 'dns_flows');
      statCell(dom.statDnsOk, 'dns_setup_ok');
      statCell(dom.statDnsFailed, 'dns_setup_failed');
      dom.statsSummary.textContent = running ? 'Live' : 'Idle';
      dom.statsSummary.className = 'pill ' + (running ? 'pill-success' : 'pill-muted');
    }

    function renderUptime() {
      var status = state.status || {};
      if (!status.running) {
        dom.heroUptime.hidden = true;
        dom.heroUptime.textContent = '';
        return;
      }
      dom.heroUptime.hidden = false;
      var started = parseTimeMs(status.started_at);
      if (started === null) {
        dom.heroUptime.textContent = 'Running now';
        return;
      }
      var seconds = (Date.now() - started) / 1000;
      dom.heroUptime.textContent = 'Up ' + formatDuration(Math.max(0, seconds));
    }

    function capTrue(value) {
      return value === true || value === 'true' || value === 'ok' || value === 'OK' ||
        (typeof value === 'number' && value > 0);
    }

    /* --------------------------- recent failures --------------------------- */

    function failureKind(group) {
      var proto = group && group.proto;
      var port = pickNumber(group, 'port');
      if (proto === 'dns') return 'dns';
      if (proto === 'udp') return 'udp';
      if (proto === 'tcp') return port === 80 || port === 443 ? 'web' : 'tcp';
      return 'other';
    }

    function failureKindLabel(kind) {
      if (kind === 'web') return 'Web';
      if (kind === 'dns') return 'DNS';
      if (kind === 'udp') return 'UDP';
      if (kind === 'tcp') return 'TCP';
      return 'Other';
    }

    function failureReason(value) {
      switch (value) {
        case 'unreachable': return 'Could not be reached';
        case 'refused': return 'Connection refused';
        case 'timed_out': return 'No answer in time';
        case 'denied': return 'Denied by the source device';
        default: return 'Stopped with an error';
      }
    }

    // The setup stage of a source device connection. An older engine sends no
    // phase. A newer engine can send a word that this page does not know.
    function failurePhaseToken(value) {
      if (typeof value !== 'string') return null;
      var token = value.trim().toLowerCase();
      if (!token) return null;
      if (token === 'connect' || token === 'greeting' || token === 'auth' || token === 'request') return token;
      return 'unknown';
    }

    function failurePhaseLabel(value) {
      switch (failurePhaseToken(value)) {
        case 'connect': return 'Source connection';
        case 'greeting': return 'Greeting';
        case 'auth': return 'Sign-in';
        case 'request': return 'Destination request';
        case 'unknown': return 'Unknown stage';
        default: return '';
      }
    }

    function failureSummary(text) {
      if (dom.failuresSummary.textContent !== text) dom.failuresSummary.textContent = text;
    }

    function renderFailures(data) {
      state.failures = data && typeof data === 'object' ? data : null;
      var groups = data && Array.isArray(data.groups) ? data.groups : [];
      var demo = !!(data && data.demo);
      dom.failureList.textContent = '';
      if (!data) {
        failureSummary('Failures are unavailable. The local server is not responding.');
        dom.copyFailures.disabled = true;
        return;
      }
      if (!groups.length) {
        failureSummary(demo
          ? 'Simulated failures. No failed connections yet.'
          : 'No failed connections yet.');
        dom.copyFailures.disabled = true;
        return;
      }
      dom.copyFailures.disabled = false;
      var total = pickNumber(data, 'total');
      var summary = formatInt(total) + ' failed ' + (total === 1 ? 'attempt' : 'attempts') + ' this session.';
      failureSummary((demo ? 'Simulated data. ' : '') + summary);

      groups.forEach(function (group) {
        var kind = failureKind(group);
        var name = group && typeof group.name === 'string' && group.name ? group.name : null;
        var ip = group && typeof group.example_ip === 'string' ? group.example_ip : '';
        var family = group && group.family === 'ipv6' ? 'IPv6' : 'IPv4';
        var row = document.createElement('li');
        row.className = 'failure-row';
        var count = document.createElement('span');
        count.className = 'failure-count';
        count.textContent = formatInt(group && group.count) + 'x';
        var body = document.createElement('div');
        body.className = 'failure-body';
        var primary = document.createElement('span');
        primary.className = 'failure-name';
        primary.textContent = name || ip || 'Unknown destination';
        var meta = document.createElement('span');
        meta.className = 'failure-meta';
        var parts = [failureKindLabel(kind), family, 'port ' + pickNumber(group, 'port')];
        var phase = failurePhaseLabel(group && group.phase);
        if (phase) parts.push(phase);
        if (name && ip) parts.push(ip);
        meta.textContent = parts.join(' · ');
        var reason = document.createElement('span');
        reason.className = 'failure-reason';
        reason.textContent = failureReason(group && group.reason);
        body.appendChild(primary);
        body.appendChild(meta);
        row.appendChild(count);
        row.appendChild(body);
        row.appendChild(reason);
        dom.failureList.appendChild(row);
      });
    }

    // A plain-text rendering of the groups. The fields come from the local
    // engine only. A missing phase shows as a dash.
    function failureReportText(data) {
      var groups = data && Array.isArray(data.groups) ? data.groups : [];
      return groups.map(function (group) {
        var parts = [
          String(Math.round(num(group && group.count))) + 'x',
          failureKind(group),
          group && group.family === 'ipv6' ? 'ipv6' : 'ipv4',
          String(pickNumber(group, 'port')),
          (group && group.reason) || 'other',
          failurePhaseToken(group && group.phase) || '-'
        ];
        if (group && typeof group.name === 'string' && group.name) parts.push(group.name);
        if (group && typeof group.example_ip === 'string' && group.example_ip) parts.push(group.example_ip);
        return parts.join(' ');
      }).join('\n');
    }

    function failureReport() {
      return failureReportText(state.failures);
    }

    function copyText(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }
      return new Promise(function (resolve, reject) {
        var area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.top = '-1000px';
        document.body.appendChild(area);
        area.select();
        var copied = false;
        try { copied = document.execCommand('copy'); } catch (e) { copied = false; }
        document.body.removeChild(area);
        if (copied) resolve(); else reject(new Error('copy failed'));
      });
    }

    function copyFailureReport() {
      var text = failureReport();
      if (!text) return;
      copyText(text).then(function () {
        showToast('Failure report copied', 'One line for each group.', 'success');
      }).catch(function () {
        showToast('Could not copy the report', 'Select the rows and copy them by hand.', 'error');
      });
    }

    /* ------------------------------ diagnostics ----------------------------- */

    function plainInt(value) {
      return String(Math.round(num(value)));
    }

    function metricText(m) {
      m = m && typeof m === 'object' ? m : {};
      return 'count ' + plainInt(pickNumber(m, 'count')) +
        ', p50 ' + plainInt(pickNumber(m, 'p50')) + ' ms' +
        ', p95 ' + plainInt(pickNumber(m, 'p95')) + ' ms' +
        ', max ' + plainInt(pickNumber(m, 'max')) + ' ms';
    }

    function queueText(label, q) {
      q = q && typeof q === 'object' ? q : {};
      return label + ': peak ' + plainInt(pickNumber(q, 'peak')) +
        ', max age ' + plainInt(pickNumber(q, 'max_age_us')) + ' us';
    }

    // A plain-text rendering of GET /api/diagnostics. It holds counters only.
    function diagnosticsReport(data) {
      data = data && typeof data === 'object' ? data : {};
      var engine = data.engine && typeof data.engine === 'object' ? data.engine : {};
      var setup = data.setup && typeof data.setup === 'object' ? data.setup : {};
      var dns = data.dns && typeof data.dns === 'object' ? data.dns : {};
      var queues = data.queues && typeof data.queues === 'object' ? data.queues : {};
      var udp = data.udp && typeof data.udp === 'object' ? data.udp : {};
      var tcp = data.tcp && typeof data.tcp === 'object' ? data.tcp : {};
      var established = data.established && typeof data.established === 'object' ? data.established : {};
      var failures = data.failures && typeof data.failures === 'object' ? data.failures : {};
      var input = Array.isArray(queues.input) ? queues.input : [];
      var estBuckets = Array.isArray(established.buckets) ? established.buckets : [];
      var lines = [
        'HotspotShade diagnostics',
        'Version: ' + (engine.version || 'unknown'),
        'Running: ' + (data.running ? 'yes' : 'no'),
        'Uptime: ' + plainInt(pickNumber(engine, 'uptime_s')) + ' s',
        'Workers: ' + plainInt(pickNumber(engine, 'workers')),
        'Connect: ' + metricText(setup.connect_ms),
        'Greeting: ' + metricText(setup.greeting_ms),
        'Auth: ' + metricText(setup.auth_ms),
        'Request: ' + metricText(setup.request_ms),
        'DNS lookups: ' + plainInt(pickNumber(dns, 'lookups')) +
          ' (ok ' + plainInt(pickNumber(dns, 'ok')) +
          ', failed ' + plainInt(pickNumber(dns, 'failed')) + ')',
        'DNS time: ' + metricText(dns.ms)
      ];
      if (input.length) {
        input.forEach(function (q, index) { lines.push(queueText('Input queue ' + (index + 1), q)); });
      } else {
        lines.push('Input queue: none');
      }
      lines.push(queueText('Output queue', queues.output));
      lines.push('UDP flows: ' + plainInt(pickNumber(udp, 'flows')) +
        ', age drops: ' + plainInt(pickNumber(udp, 'age_drops')));
      lines.push('TCP flows peak: ' + plainInt(pickNumber(tcp, 'flows_peak')) +
        ', retransmits: ' + plainInt(pickNumber(tcp, 'retransmits')) +
        ', zero window: ' + plainInt(pickNumber(tcp, 'zero_window_ms')) + ' ms');
      var observed = estBuckets.filter(function (bucket) { return bucket && bucket.observed; }).length;
      if (!estBuckets.length) {
        lines.push('Established: no observation.');
      } else {
        lines.push('Established: ' + plainInt(observed) + ' of ' + plainInt(estBuckets.length) +
          ' s with an established flow.');
      }
      var estEvents = estBuckets.filter(function (bucket) {
        return bucket && (pickNumber(bucket, 'tcp_retransmits') > 0 ||
          pickNumber(bucket, 'window_limited_ms') > 0 ||
          pickNumber(bucket, 'tcp_teardowns') > 0 ||
          pickNumber(bucket, 'udp_teardowns') > 0 ||
          pickNumber(bucket, 'udp_drops') > 0 ||
          pickNumber(bucket, 'relay_drops') > 0 ||
          pickNumber(bucket, 'outer_errors') > 0);
      });
      if (estBuckets.length && !estEvents.length) {
        lines.push('Established events: none in this run.');
      } else if (estEvents.length) {
        estEvents.slice(-8).reverse().forEach(function (bucket) {
          lines.push('Established ' + plainInt(pickNumber(bucket, 'age_s')) + ' s ago: ' +
            'retransmits ' + plainInt(pickNumber(bucket, 'tcp_retransmits')) +
            ', window ' + plainInt(pickNumber(bucket, 'window_limited_ms')) + ' ms' +
            ', TCP ends ' + plainInt(pickNumber(bucket, 'tcp_teardowns')) +
            ', UDP ends ' + plainInt(pickNumber(bucket, 'udp_teardowns')) +
            ', UDP drops ' + plainInt(pickNumber(bucket, 'udp_drops')) +
            ', relay drops ' + plainInt(pickNumber(bucket, 'relay_drops')) +
            ', outer errors ' + plainInt(pickNumber(bucket, 'outer_errors')) +
            ', observed ' + (bucket.observed ? 'yes' : 'no') + '.');
        });
      }
      lines.push('Failures: total ' + plainInt(pickNumber(failures, 'total')) +
        ', dropped ' + plainInt(pickNumber(failures, 'dropped')));
      return lines.join('\n');
    }

    function copyDiagnosticsReport() {
      api('/api/diagnostics').then(function (data) {
        return copyText(diagnosticsReport(data)).then(function () {
          showToast('Diagnostics copied', 'A plain-text summary is on the clipboard.', 'success');
        });
      }).catch(function (err) {
        showToast('Could not copy diagnostics', err.message || 'The diagnostics are unavailable.', 'error');
      });
    }

    function renderHealth(force) {
      if (!state.probeLoaded && !state.probe) {
        state.healthKey = 'pending';
        dom.healthSummary.className = 'pill pill-muted';
        dom.healthSummary.textContent = 'Checking';
        dom.healthList.innerHTML = '<li class="health-row"><span class="health-name">Checking capabilities…</span></li>';
        return;
      }
      var probe = state.probe || {};
      var platform = platformInfo();
      var cap = capabilities();
      var osName = platform.os || probe.os || '';
      var isWindows = /win/i.test(osName);
      var admin = platform.admin === true || probe.admin === true;
      var iface = platform.default_iface || probe.default_iface || '';
      var probeFailed = state.probeLoaded && probe.available === false;
      var key = JSON.stringify([probe.error || '', probe.available, cap, admin, iface, osName, platform.arch || '']);
      if (!force && key === state.healthKey) return;
      state.healthKey = key;

      var tcpOk = capTrue(cap.ip_ttl_tcp) || capTrue(cap.ip_ttl);
      var udpOk = capTrue(cap.ip_ttl_udp) || capTrue(cap.ip_ttl);
      var ttlOk = tcpOk && udpOk;
      var tunFlag = capTrue(cap.utun) || capTrue(cap.tun) || capTrue(cap.wintun) ||
        cap.utun_needs_root === true;
      var rows = [];

      if (ttlOk) {
        rows.push({ name: 'TTL normalization', detail: 'TCP and UDP sockets use TTL 65.', state: 'ok', badge: 'Verified' });
      } else {
        rows.push({
          name: 'TTL normalization',
          detail: probeFailed ? 'The backend is unavailable.' : 'The host probe did not verify it.',
          state: 'fail',
          badge: 'Unavailable'
        });
      }

      if (tunFlag && admin) {
        rows.push({ name: isWindows ? 'wintun capture' : 'utun capture', detail: 'The process can create the adapter.', state: 'ok', badge: 'Ready' });
      } else if (tunFlag || cap.utun_needs_root === true) {
        rows.push({
          name: isWindows ? 'wintun capture' : 'utun capture',
          detail: 'Needs admin rights. SOCKS5 mode works without them.',
          state: 'warn',
          badge: 'Needs admin'
        });
      } else {
        rows.push({
          name: isWindows ? 'wintun capture' : 'utun capture',
          detail: probeFailed ? 'The backend is unavailable.' : 'The host reported no tunnel capability.',
          state: 'fail',
          badge: 'Missing'
        });
      }

      rows.push(admin
        ? { name: 'Admin privileges', detail: 'The process is elevated.', state: 'ok', badge: 'Elevated' }
        : { name: 'Admin privileges', detail: 'Not elevated. SOCKS5 mode works.', state: 'warn', badge: 'Standard' });

      rows.push(iface
        ? { name: 'Default interface', detail: iface, state: 'ok', badge: 'Detected' }
        : { name: 'Default interface', detail: 'No default IPv4 interface.', state: 'fail', badge: 'Missing' });

      var failures = rows.filter(function (r) { return r.state === 'fail'; }).length;
      var warnings = rows.filter(function (r) { return r.state === 'warn'; }).length;
      dom.healthSummary.className = 'pill ' + (failures ? 'pill-danger' : (warnings ? 'pill-warn' : 'pill-success'));
      dom.healthSummary.textContent = failures
        ? failures + ' issue' + (failures === 1 ? '' : 's')
        : (warnings ? warnings + ' note' + (warnings === 1 ? '' : 's') : 'Healthy');

      dom.healthList.innerHTML = rows.map(function (row) {
        var icon = row.state === 'ok' ? ICONS.check : (row.state === 'warn' ? ICONS.warn : ICONS.x);
        var cls = row.state === 'ok' ? 'badge-ok' : (row.state === 'warn' ? 'badge-warn' : 'badge-fail');
        return '<li class="health-row">' +
          '<span class="health-name-wrap"><span class="health-name">' + escapeHtml(row.name) + '</span>' +
          '<span class="health-detail">' + escapeHtml(row.detail) + '</span></span>' +
          '<span class="badge ' + cls + '">' + icon + escapeHtml(row.badge) + '</span></li>';
      }).join('');
    }

    function renderRecent() {
      var latest = state.logs.slice(-5).reverse();
      if (!latest.length) {
        dom.recentLogs.innerHTML = '<li class="log-preview-empty">No activity yet.</li>';
        return;
      }
      dom.recentLogs.innerHTML = latest.map(function (entry) {
        var level = normalizeLevel(entry.level);
        return '<li title="' + escapeHtml(entry.msg) + '">' +
          '<span class="log-preview-time">' + escapeHtml(formatClock(entry.ts)) + '</span>' +
          '<span class="log-preview-level level-' + level + '" aria-hidden="true"></span>' +
          '<span class="log-preview-msg">' + escapeHtml(entry.msg) + '</span></li>';
      }).join('');
    }

    function syncBusy() {
      var busy = !!state.busy;
      var running = state.running;
      dom.startBtn.disabled = busy || running;
      dom.stopBtn.disabled = busy || !running;
      dom.configStartBtn.disabled = busy || running;
      dom.configStopBtn.disabled = busy || !running;
      dom.modeButtons.forEach(function (btn) { btn.disabled = busy || running; });
      dom.phoneProbe.disabled = busy;
      dom.pairForget.disabled = busy || !!(state.pair && PAIR_ACTIVE[state.pair.state]);

      dom.startBtn.setAttribute('aria-busy', state.busy === 'start' ? 'true' : 'false');
      dom.configStartBtn.setAttribute('aria-busy', state.busy === 'start' ? 'true' : 'false');

      dom.startBtnSpinner.hidden = state.busy !== 'start';
      if (state.busy === 'start' || running) {
        dom.startBtnIcon.setAttribute('hidden', '');
      } else {
        dom.startBtnIcon.removeAttribute('hidden');
      }
      dom.configStartBtnSpinner.hidden = state.busy !== 'start';
    }

    function setLogsEmpty(title, detail) {
      dom.logsEmptyTitle.textContent = title;
      dom.logsEmptyText.textContent = detail;
      dom.logsEmpty.hidden = false;
    }

    function renderServerDown(err) {
      state.serverDown = true;
      state.running = false;
      dom.statusPill.classList.remove('status-idle', 'status-running');
      dom.statusPill.classList.add('status-error');
      dom.statusText.textContent = 'Offline';
      dom.sideStatus.classList.remove('is-running');
      dom.sideStatus.classList.add('is-error');
      dom.sideStatusText.textContent = 'Offline';
      dom.heroTitle.textContent = 'Cannot reach the local server';
      dom.heroDesc.textContent = 'The GUI server is not responding. Reload the page or restart the app.';
      dom.heroError.hidden = false;
      dom.heroErrorText.textContent = err && err.message ? err.message : 'The local server did not answer.';
      dom.livePill.classList.remove('is-live');
      dom.liveText.textContent = 'Offline';
      dom.heroUptime.textContent = 'Not running';
      dom.heroPing.hidden = true;
      dom.heroPing.textContent = '';
      setStopStyle(dom.stopBtn, false);
      setStopStyle(dom.configStopBtn, false);
      dom.startBtn.disabled = true;
      dom.stopBtn.disabled = true;
      dom.configStartBtn.disabled = true;
      dom.configStopBtn.disabled = true;
      dom.startBtnLabel.textContent = 'Start proxy';
      dom.configStartBtnLabel.textContent = 'Start session';
      if (!state.logs.length) setLogsEmpty('Activity unavailable.', 'The local server is not responding.');
    }

    /* -------------------------------- routing ------------------------------- */

    function setView(view, updateHash) {
      if (!TITLES[view]) view = 'dashboard';
      state.view = view;
      Object.keys(dom.sections).forEach(function (key) {
        dom.sections[key].hidden = key !== view;
      });
      dom.navItems.forEach(function (item) {
        if (item.getAttribute('data-view') === view) item.setAttribute('aria-current', 'page');
        else item.removeAttribute('aria-current');
      });
      var meta = TITLES[view];
      dom.pageTitle.textContent = meta.title;
      dom.pageSubtitle.textContent = meta.sub;
      document.title = 'hotspotshade · ' + meta.title;
      if (updateHash && location.hash !== '#' + view) {
        try { history.replaceState(null, '', '#' + view); } catch (e) { /* file: URLs */ }
      }
      if (view === 'logs') {
        loadLogs();
        if (state.autoScroll) dom.logsPanel.scrollTop = dom.logsPanel.scrollHeight;
      }
    }

    /* --------------------------------- theme -------------------------------- */

    function setTheme(theme, persist) {
      theme = theme === 'dark' ? 'dark' : 'light';
      state.theme = theme;
      document.documentElement.setAttribute('data-theme', theme);
      if (persist) {
        try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* private mode */ }
      }
      dom.themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
      dom.themeToggle.title = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
    }

    /* ----------------------------- configuration ---------------------------- */

    function updateModeUI() {
      var mode = state.config.mode;
      var resolved = resolveMode(mode);
      dom.modeSelect.value = mode;
      dom.socksCard.hidden = resolved !== 'socks5';
      dom.tunCard.hidden = resolved !== 'tun';
      dom.phoneCard.hidden = resolved !== 'phone';
      dom.ifaceField.hidden = resolved === 'phone';
      dom.pinRow.hidden = resolved === 'phone';
      dom.ifaceInput.disabled = !state.config.pin;
      dom.pinToggle.setAttribute('aria-checked', String(state.config.pin));
      dom.ipv6Toggle.setAttribute('aria-checked', String(state.config.ipv6));
      if (mode === 'phone') {
        dom.modeHelp.textContent = 'Forward captured traffic through the source device proxy app.';
      } else if (mode === 'tun') {
        dom.modeHelp.textContent = 'Captures routed IPv4 traffic through a utun. Some routes can bypass it. Needs admin rights.';
      } else if (mode === 'auto') {
        dom.modeHelp.textContent = 'Uses transparent tun when the process is elevated. Otherwise uses SOCKS5.';
      } else {
        dom.modeHelp.textContent = 'Apps use the proxy at 127.0.0.1:' + (state.config.port || 1080) + '. No admin rights needed.';
      }
    }

    function applyConfigToForm() {
      var c = state.config;
      dom.modeSelect.value = c.mode;
      dom.hostInput.value = c.host;
      dom.portInput.value = c.port;
      dom.dnsInput.value = c.dns;
      dom.ifaceInput.value = c.iface;
      dom.tunDnsInput.value = c.tunDns;
      dom.unitInput.value = c.unit;
      dom.addrInput.value = c.addr;
      dom.pingToggle.checked = state.ping;
      updateModeUI();
    }

    function setFieldError(input, errorEl, message) {
      if (!input || !errorEl) return;
      input.classList.toggle('is-invalid', !!message);
      input.setAttribute('aria-invalid', message ? 'true' : 'false');
      errorEl.textContent = message || '';
      errorEl.hidden = !message;
    }

    function hostError() {
      var value = String(state.config.host || '').trim();
      if (!value) return 'Enter a hostname or IP address.';
      if (/\s/.test(value)) return 'The host cannot contain spaces.';
      if (value.length > 255) return 'The host name is too long.';
      return '';
    }

    function portError() {
      var value = String(state.config.port === null || state.config.port === undefined ? '' : state.config.port).trim();
      if (!/^\d+$/.test(value)) return 'Enter a whole number.';
      var n = parseInt(value, 10);
      if (n < 1 || n > 65535) return 'Enter a port from 1 to 65535.';
      return '';
    }

    function validDnsToken(token) {
      var m = token.match(/^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::(\d{1,5}))?$/);
      if (!m) return false;
      if (m[2] && (parseInt(m[2], 10) < 1 || parseInt(m[2], 10) > 65535)) return false;
      return true;
    }

    function dnsError() {
      var value = String(state.config.dns || '').trim();
      if (!value) return '';
      var parts = value.split(',').map(function (p) { return p.trim(); }).filter(Boolean);
      if (!parts.length || parts.some(function (p) { return !validDnsToken(p); })) {
        return 'Use comma-separated ip[:port] values.';
      }
      return '';
    }

    function tunDnsError() {
      var value = String(state.config.tunDns || '').trim();
      if (!value) return '';
      return validDnsToken(value) ? '' : 'Use a host or ip[:port] value.';
    }

    function unitError() {
      var value = String(state.config.unit === null || state.config.unit === undefined ? '' : state.config.unit).trim();
      if (!/^\d+$/.test(value)) return 'Enter a whole number.';
      var n = parseInt(value, 10);
      if (n < 0 || n > 255) return 'Enter a unit from 0 to 255.';
      return '';
    }

    function addrError() {
      var value = String(state.config.addr || '').trim();
      var parts = value.split('.');
      if (parts.length !== 4) return 'Enter a valid IPv4 address.';
      for (var i = 0; i < parts.length; i++) {
        if (!/^\d{1,3}$/.test(parts[i])) return 'Enter a valid IPv4 address.';
        var n = parseInt(parts[i], 10);
        if (n < 0 || n > 255) return 'Enter a valid IPv4 address.';
      }
      return '';
    }

    function ifaceError() {
      var value = String(state.config.iface || '').trim();
      if (!value) return '';
      if (/\s/.test(value)) return 'The interface name cannot contain spaces.';
      if (value.length > 64) return 'The interface name is too long.';
      return '';
    }

    function phoneHostError() {
      var value = dom.phoneHost.value.trim();
      if (!value || /\s/.test(value) || value.length > 255) return 'Enter a valid source device host.';
      return '';
    }

    function phonePortError() {
      var value = dom.phonePort.value.trim();
      if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) return 'Enter a port from 1 to 65535.';
      return '';
    }

    function phoneTokenError() {
      return dom.phoneToken.value ? '' : 'Enter the source device token.';
    }

    function phoneRequest(kind) {
      if (kind === 'check') {
        var fields = manualPhoneFields();
        fields.forEach(function (field) { setFieldError(field[0], field[1], field[2]); });
        if (fields.some(function (field) { return !!field[2]; })) return;
      }
      dom.phoneDiscover.disabled = true;
      dom.phoneCheck.disabled = true;
      dom.phoneResult.textContent = kind === 'discover' ? 'Discovering source device...' : 'Checking connection...';
      var request = kind === 'discover' ? api('/api/phone/discover') :
        api('/api/phone/check', { method: 'POST', body: buildOptions('phone') });
      request.then(function (data) {
        if (kind === 'discover') {
          if (data.host) dom.phoneHost.value = data.host;
          if (data.port) dom.phonePort.value = data.port;
          dom.phoneResult.textContent = data.message || (data.reachable ? 'Source device is reachable.' : 'Source device is not reachable.');
        } else {
          dom.phoneResult.textContent = data.message || 'Connection check passed.';
        }
      }).catch(function (err) {
        dom.phoneResult.textContent = err.message;
      }).then(function () {
        dom.phoneDiscover.disabled = false;
        dom.phoneCheck.disabled = false;
      });
    }

    function fieldPairs(mode) {
      if (mode === 'phone') {
        if (!manualToken()) return [];
        return manualPhoneFields();
      }
      if (mode === 'socks5') {
        return [
          [dom.hostInput, dom.hostError, hostError()],
          [dom.portInput, dom.portError, portError()],
          [dom.dnsInput, dom.dnsError, dnsError()]
        ];
      }
      return [
        [dom.tunDnsInput, dom.tunDnsError, tunDnsError()],
        [dom.unitInput, dom.unitError, unitError()],
        [dom.addrInput, dom.addrError, addrError()]
      ];
    }

    function manualPhoneFields() {
      return [
        [dom.phoneHost, dom.phoneHostError, phoneHostError()],
        [dom.phonePort, dom.phonePortError, phonePortError()],
        [dom.phoneToken, dom.phoneTokenError, phoneTokenError()]
      ];
    }

    function resolveValidation() {
      var mode = resolveMode(state.config.mode);
      var fields = fieldPairs(mode);
      var errors = [];
      fields.forEach(function (field) {
        if (field[2]) errors.push({ input: field[0], errorEl: field[1], message: field[2] });
      });
      if (mode !== 'phone' && state.config.pin) {
        var ifaceMsg = ifaceError();
        if (ifaceMsg) errors.push({ input: dom.ifaceInput, errorEl: null, message: ifaceMsg });
      }
      return { ok: errors.length === 0, mode: mode, errors: errors, options: buildOptions(mode) };
    }

    function validateConfig(show) {
      var result = resolveValidation();
      fieldPairs(result.mode).forEach(function (field) {
        var message = field[2];
        if (show || (field[0] && field[0].classList.contains('is-invalid'))) {
          setFieldError(field[0], field[1], message);
        } else if (!message) {
          setFieldError(field[0], field[1], '');
        }
      });
      var ifaceMsg = result.mode !== 'phone' && state.config.pin ? ifaceError() : '';
      dom.ifaceInput.classList.toggle('is-invalid', !!ifaceMsg);
      dom.ifaceInput.setAttribute('aria-invalid', ifaceMsg ? 'true' : 'false');
      return result;
    }

    function buildOptions(mode) {
      if (mode === 'phone') {
        var phoneOptions = { experimental_icmp: state.ping };
        // Without a manual token, the service uses the paired credentials.
        if (!manualToken()) return phoneOptions;
        phoneOptions.host = dom.phoneHost.value.trim();
        phoneOptions.port = parseInt(dom.phonePort.value, 10);
        phoneOptions.token = dom.phoneToken.value;
        return phoneOptions;
      }
      var iface = state.config.pin
        ? (String(state.config.iface || '').trim() || detectedIface() || null)
        : null;
      if (mode === 'tun') {
        return {
          unit: parseInt(String(state.config.unit), 10) || 0,
          addr: String(state.config.addr || '').trim() || '198.18.0.1',
          iface: iface,
          dns_upstream: String(state.config.tunDns || '').trim() || null,
          ipv6: state.config.ipv6 ? 'block' : 'inherit',
          no_routes: false
        };
      }
      return {
        host: String(state.config.host || '').trim() || '127.0.0.1',
        port: parseInt(String(state.config.port), 10) || 1080,
        iface: iface,
        dns_servers: String(state.config.dns || '').trim()
          ? String(state.config.dns).split(',').map(function (s) { return s.trim(); }).filter(Boolean)
          : null
      };
    }

    /* -------------------------------- pairing ------------------------------- */

    // The browser never sees the phone token. The service holds it in memory.
    var PAIR_ACTIVE = { connecting: true, confirm: true };

    function manualToken() {
      return !!dom.phoneToken.value;
    }

    function isPaired() {
      return !!((state.pair && state.pair.state === 'paired') || (state.status && state.status.paired));
    }

    // The engine message is the one status line of the source device card.
    // Pairing progress and errors replace it while a pairing is active.
    function updatePairUI() {
      var view = state.pair || { state: 'idle' };
      var phone = state.phone || {};
      var status = state.status || {};
      var forget = state.forget || { state: 'none' };
      var paired = !!status.paired;
      var active = !!PAIR_ACTIVE[view.state];
      var forgetText = forget.state === 'pending'
        ? 'Forgetting...'
        : forget.state === 'confirmed'
          ? 'Forgotten. The source device removed this target device.'
          : forget.state === 'not_delivered'
            ? 'The source device did not answer. This target device forgot the pairing, but the source device may still trust it.'
            : '';
      var pill;
      if (view.state === 'connecting') pill = ['Connecting', 'pill-muted'];
      else if (view.state === 'confirm') pill = ['Waiting for the source device', 'pill-warn'];
      else if (forget.state === 'pending') pill = ['Forgetting', 'pill-warn'];
      else if (forget.state === 'confirmed') pill = ['Forgotten', 'pill-muted'];
      else if (forget.state === 'not_delivered') pill = ['Forget not confirmed', 'pill-warn'];
      else if (view.state === 'failed' && !paired) pill = ['Not paired', 'pill-danger'];
      else if (phone.state === 'not_trusted' || phone.state === 'unpaired') pill = ['Not paired', 'pill-warn'];
      else if (paired) pill = ['Paired', 'pill-success'];
      else pill = ['Not paired', 'pill-muted'];
      dom.pairPill.className = 'pill ' + pill[1];
      dom.pairPillText.textContent = pill[0];

      var text;
      if (view.state === 'connecting') text = 'Connecting to the source device...';
      else if (view.state === 'confirm') text = 'Check that the source device shows the same code, then tap Allow on the source device.';
      else if (view.state === 'failed') text = view.error || 'The pairing failed.';
      else if (forgetText) text = forgetText;
      else if (typeof phone.message === 'string' && phone.message) text = phone.message;
      else text = 'Loading the pairing state...';
      setText(dom.pairStatus, text);

      dom.pairCodeBlock.hidden = view.state !== 'confirm' || !view.code;
      setText(dom.pairCode, view.state === 'confirm' && view.code ? view.code : '');
      dom.pairStart.disabled = active;
      dom.pairStart.textContent = phone.state === 'unpaired' ? 'Pair'
        : phone.state === 'not_trusted' ? 'Pair again'
          : paired ? 'Pair again' : 'Pair with source device';
      var primary = !paired || phone.state === 'not_trusted' || phone.state === 'unpaired';
      dom.pairStart.className = 'btn ' + (primary ? 'btn-primary' : 'btn-secondary');
      dom.pairCancel.hidden = !active;
      dom.pairForget.disabled = active || state.busy === 'forget';
      dom.phoneProbe.disabled = !!state.busy;

      if (active) {
        // Keep a pending poll. A status refresh must not postpone it.
        if (!state.pairTimer) state.pairTimer = setTimeout(loadPair, 700);
      } else {
        if (state.pairTimer) {
          clearTimeout(state.pairTimer);
          state.pairTimer = null;
        }
        if (state.pairThenStart) {
          state.pairThenStart = false;
          if (view.state === 'paired') startSession();
        }
      }
    }

    // Show the automatic stop message and a short one-line note. The message
    // comes from the engine and holds no address.
    function renderLastStop(status) {
      var reason = status.last_stop && status.last_stop.reason;
      var message = typeof status.last_stop_message === 'string' ? status.last_stop_message : '';
      dom.lastStopAlert.hidden = !message;
      setText(dom.lastStopText, message);
      var note = '';
      if (message) {
        note = reason === 'source_device_gone'
          ? 'Stopped automatically: the source device stopped answering.'
          : 'Stopped automatically: the hotspot turned off.';
      }
      dom.lastStopNote.hidden = !note;
      setText(dom.lastStopNote, note);
    }

    function renderPhoneSummary() {
      var phone = state.phone;
      var count = phone && typeof phone.connections === 'number' ? phone.connections : null;
      if (count === null) {
        dom.phonePresence.hidden = true;
        setText(dom.phonePresence, '');
      } else {
        dom.phonePresence.hidden = false;
        setText(dom.phonePresence, 'The source device reports ' + formatInt(count) +
          ' proxy connection' + (count === 1 ? '' : 's') + '.');
      }
    }

    function renderPair(view) {
      state.pair = view && typeof view === 'object' && view.state ? view : { state: 'idle' };
      updatePairUI();
    }

    function pairUnavailable() {
      // The status endpoint can still answer. Show its state instead of a
      // second error line.
      state.pair = null;
      state.pairThenStart = false;
      updatePairUI();
    }

    function loadPair() {
      state.pairTimer = null;
      return api('/api/phone/pair').then(renderPair).catch(pairUnavailable);
    }

    function startPairing(thenStart) {
      state.pairThenStart = !!thenStart;
      state.pair = { state: 'connecting' };
      state.forget = { state: 'none' };
      updatePairUI();
      dom.pairStart.disabled = true;
      setText(dom.pairStatus, 'Connecting to the source device...');
      api('/api/phone/pair', { method: 'POST', body: {} }).then(renderPair).catch(function (err) {
        state.pairThenStart = false;
        showToast('Could not pair', err.message, 'error');
        loadPair();
      });
    }

    function cancelPairing() {
      state.pairThenStart = false;
      api('/api/phone/pair/cancel', { method: 'POST', body: {} }).then(renderPair).catch(function () {
        pairUnavailable();
      });
    }

    // Ask the engine for one immediate probe. The engine rate-limits to one
    // probe per 500 ms and returns the cached phone object.
    function checkSourceDevice() {
      if (state.busy) return;
      state.busy = 'probe';
      syncBusy();
      dom.phoneProbe.textContent = 'Checking...';
      api('/api/phone/probe', { method: 'POST', body: {} }).then(function (data) {
        var phone = data && data.phone;
        if (phone && state.status) {
          renderStatus(Object.assign({}, state.status, { phone: phone }));
        } else if (phone) {
          state.phone = phone;
          renderPhoneSummary();
          updatePairUI();
        }
        showToast('Source device checked', 'The latest result is shown.', 'success');
        loadPair();
      }).catch(function (err) {
        showToast('Could not check the source device', err.message, 'error');
      }).then(function () {
        state.busy = null;
        dom.phoneProbe.textContent = 'Check now';
        syncBusy();
        loadStatus();
      });
    }

    // Forget the pairing. The engine sends a best-effort FORGET, clears the
    // local credentials, and probes the source device at once.
    function forgetPairing() {
      if (state.busy) return;
      state.busy = 'forget';
      state.forget = { state: 'pending', attempts: 0 };
      updatePairUI();
      syncBusy();
      api('/api/phone/forget', { method: 'POST', body: {} }).then(function () {
        showToast('Pairing forgotten', 'The target device cleared the pairing.', 'success');
        loadPair();
        loadStatus();
      }).catch(function (err) {
        showToast('Could not forget the pairing', err.message, 'error');
        loadStatus();
      }).then(function () {
        state.busy = null;
        syncBusy();
      });
    }

    /* ------------------------------ start / stop ---------------------------- */

    function startSession() {
      if (state.busy) return;
      var result = validateConfig(true);
      if (!result.ok) {
        var first = result.errors[0];
        showToast('Check the configuration', first.message, 'error');
        if (state.view === 'dashboard') setView('configure', true);
        if (first.input && dom.manualDetails.contains(first.input)) dom.manualDetails.open = true;
        if (first.input) first.input.focus();
        return;
      }
      if (result.mode === 'phone' && !manualToken() && !isPaired()) {
        if (!state.pair || !PAIR_ACTIVE[state.pair.state]) startPairing(true);
        else state.pairThenStart = true;
        if (state.view === 'dashboard') setView('configure', true);
        return;
      }

      state.busy = 'start';
      state.mutationEpoch += 1;
      setActionError(null);
      syncBusy();

      api('/api/start', { method: 'POST', body: { mode: result.mode, options: result.options } })
        .then(function (data) {
          if (data && data.status) renderStatus(data.status);
          var message = result.mode === 'phone' ? 'Source device proxy mode started.' : result.mode === 'tun'
            ? 'Capture is active on ' + (detectedIface() || 'the default interface') + '.'
            : 'Listening on 127.0.0.1:' + state.config.port + '.';
          showToast(modeLabel(result.mode) + ' started', message, 'success');
        })
        .catch(function (err) {
          showToast('Could not start', err.message, 'error');
          setActionError(err.message);
          renderStatus(state.status || {});
        })
        .then(function () {
          state.busy = null;
          syncBusy();
          if (state.status) renderStatus(state.status);
          loadStatus();
          loadLogs();
          loadFailures();
        });
    }

    function stopSession() {
      if (state.busy) return;
      state.busy = 'stop';
      state.mutationEpoch += 1;
      setActionError(null);
      syncBusy();

      api('/api/stop', { method: 'POST' })
        .then(function (data) {
          if (data && data.status) renderStatus(data.status);
          showToast('Session stopped', 'The session stopped.', 'success');
        })
        .catch(function (err) {
          showToast('Could not stop', err.message, 'error');
          setActionError(err.message);
          renderStatus(state.status || {});
        })
        .then(function () {
          state.busy = null;
          syncBusy();
          if (state.status) renderStatus(state.status);
          loadStatus();
          loadLogs();
          loadFailures();
        });
    }

    /* --------------------------------- logs --------------------------------- */

    var logsInFlight = false;
    var failuresInFlight = false;

    function normalizeLevel(level) {
      var s = String(level || 'info').toLowerCase();
      if (s === 'warning' || s === 'warn') return 'warn';
      if (s === 'err' || s === 'error' || s === 'fatal' || s === 'critical') return 'error';
      if (s === 'debug' || s === 'trace') return 'debug';
      return 'info';
    }

    function normalizeLogEntry(entry, index) {
      var e = (entry && typeof entry === 'object') ? entry : { msg: String(entry === null || entry === undefined ? '' : entry) };
      var seq = parseInt(e.seq, 10);
      if (!isFinite(seq)) seq = state.lastSeq + index + 1;
      var msg = e.msg !== undefined ? e.msg : (e.message !== undefined ? e.message : e.text);
      return {
        seq: seq,
        ts: e.ts || e.time || '',
        level: normalizeLevel(e.level),
        msg: String(msg === null || msg === undefined ? '' : msg)
      };
    }

    function createLogRow(entry) {
      var row = document.createElement('div');
      row.className = 'log-row level-' + entry.level;
      var time = document.createElement('span');
      time.className = 'log-time';
      time.textContent = formatClock(entry.ts);
      if (entry.ts) time.title = String(entry.ts);
      var level = document.createElement('span');
      level.className = 'log-level';
      level.textContent = entry.level;
      var msg = document.createElement('span');
      msg.className = 'log-msg';
      msg.textContent = entry.msg;
      row.appendChild(time);
      row.appendChild(level);
      row.appendChild(msg);
      return row;
    }

    function appendLogEntries(entries) {
      if (!entries || !entries.length) return;
      var fragment = document.createDocumentFragment();
      var appended = 0;
      entries.forEach(function (entry) {
        if (entry.seq <= state.renderedThrough) return;
        fragment.appendChild(createLogRow(entry));
        state.renderedThrough = Math.max(state.renderedThrough, entry.seq);
        appended++;
      });
      if (!appended) return;
      dom.logList.appendChild(fragment);
      while (dom.logList.childElementCount > 2200) {
        dom.logList.removeChild(dom.logList.firstElementChild);
      }
      dom.logsEmpty.hidden = true;
      if (state.autoScroll) dom.logsPanel.scrollTop = dom.logsPanel.scrollHeight;
    }

    function renderAllLogs() {
      dom.logList.innerHTML = '';
      state.renderedThrough = 0;
      var entries = state.logs.slice(-1500);
      if (entries.length) {
        state.renderedThrough = entries[0].seq - 1;
        appendLogEntries(entries);
      } else if (state.serverDown) {
        setLogsEmpty('Activity unavailable.', 'The local server is not responding.');
      } else {
        setLogsEmpty('No activity yet.', 'Start a mode to see log entries.');
      }
      updateLogCount();
    }

    function updateLogCount() {
      var n = state.logs.length;
      dom.logCount.textContent = n + ' event' + (n === 1 ? '' : 's') + (state.paused ? ' · paused' : '');
    }

    function updateAutoScroll() {
      dom.autoScrollToggle.setAttribute('aria-checked', String(state.autoScroll));
    }

    function loadFailures() {
      if (failuresInFlight) return failuresInFlight;
      failuresInFlight = true;
      return api('/api/failures').then(function (data) {
        renderFailures(data && typeof data === 'object' ? data : null);
      }).catch(function () {
        renderFailures(null);
      }).then(function () {
        failuresInFlight = false;
      });
    }

    function loadLogs() {
      if (logsInFlight) return;      logsInFlight = true;
      api('/api/logs?since=' + encodeURIComponent(state.lastSeq))
        .then(function (data) {
          var list = Array.isArray(data.logs) ? data.logs : [];
          var next = Number(data.next);
          if (!isFinite(next)) next = state.lastSeq;

          if (next < state.lastSeq) {
            state.logs = [];
            state.lastSeq = 0;
            state.renderedThrough = 0;
            dom.logList.innerHTML = '';
            setLogsEmpty('Loading activity…', 'Waiting for the local backend.');
            updateLogCount();
            renderRecent();
            setTimeout(loadLogs, 100);
            return;
          }

          if (!list.length) {
            state.lastSeq = Math.max(state.lastSeq, next);
            if (!state.logs.length) setLogsEmpty('No activity yet.', 'Start a mode to see log entries.');
            return;
          }

          var entries = [];
          list.forEach(function (entry, index) {
            var normalized = normalizeLogEntry(entry, index);
            if (normalized.seq > state.lastSeq) entries.push(normalized);
          });
          if (!entries.length) {
            state.lastSeq = Math.max(state.lastSeq, next);
            return;
          }

          state.logs = state.logs.concat(entries);
          if (state.logs.length > 4000) state.logs = state.logs.slice(-4000);
          state.lastSeq = Math.max(state.lastSeq, next);
          entries.forEach(function (entry) { state.lastSeq = Math.max(state.lastSeq, entry.seq); });

          if (!state.paused) appendLogEntries(entries);
          updateLogCount();
          renderRecent();
        })
        .catch(function () {
          if (!state.logs.length) setLogsEmpty('Activity unavailable.', 'The local server is not responding.');
        })
        .then(function () { logsInFlight = false; });
    }

    function setPaused(paused) {
      state.paused = !!paused;
      dom.pauseBtn.setAttribute('aria-pressed', String(state.paused));
      dom.pauseLabel.textContent = state.paused ? 'Resume' : 'Pause';
      dom.pauseIcon.innerHTML = state.paused ? ICONS.play : ICONS.pause;
      if (!state.paused) renderAllLogs();
      updateLogCount();
    }

    function clearLogView() {
      state.logs = [];
      state.renderedThrough = state.lastSeq;
      dom.logList.innerHTML = '';
      setLogsEmpty('No activity yet.', 'New entries appear here.');
      updateLogCount();
      renderRecent();
      showToast('Log view cleared', 'New entries still arrive.', 'info');
    }

    /* -------------------------------- toasts -------------------------------- */

    function showToast(title, message, type) {
      type = type === 'success' || type === 'error' || type === 'warn' ? type : 'info';
      var dedupe = type + '|' + title + '|' + message;
      var now = Date.now();
      if (state.toasts[dedupe] && now - state.toasts[dedupe] < 1500) return;
      state.toasts[dedupe] = now;

      var toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.setAttribute('role', type === 'error' ? 'alert' : 'status');

      var icon = document.createElement('span');
      icon.className = 'toast-icon';
      icon.innerHTML = type === 'success' ? ICONS.success
        : type === 'error' ? ICONS.error
          : type === 'warn' ? ICONS.warn : ICONS.info;

      var content = document.createElement('div');
      content.className = 'toast-content';
      var titleEl = document.createElement('div');
      titleEl.className = 'toast-title';
      titleEl.textContent = title;
      var msgEl = document.createElement('div');
      msgEl.className = 'toast-msg';
      msgEl.textContent = message;
      content.appendChild(titleEl);
      content.appendChild(msgEl);

      var close = document.createElement('button');
      close.type = 'button';
      close.className = 'toast-close';
      close.setAttribute('aria-label', 'Dismiss notification');
      close.innerHTML = ICONS.close;

      toast.appendChild(icon);
      toast.appendChild(content);
      toast.appendChild(close);

      function remove() {
        if (!toast.parentNode) return;
        toast.classList.add('is-leaving');
        setTimeout(function () {
          if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 160);
      }
      close.addEventListener('click', remove);
      setTimeout(remove, type === 'error' ? 6500 : 4500);

      while (dom.toastRegion.childElementCount >= 4) {
        dom.toastRegion.removeChild(dom.toastRegion.firstElementChild);
      }
      dom.toastRegion.appendChild(toast);
    }

    /* ------------------------------- data loaders --------------------------- */

    function loadStatus() {
      if (state.statusInFlight) return state.statusInFlight;
      var epoch = state.mutationEpoch;
      state.statusInFlight = api('/api/status').then(function (data) {
        if (epoch !== state.mutationEpoch) return;
        state.serverDown = false;
        renderStatus(data && typeof data === 'object' ? data : {});
      }).catch(function (err) {
        if (epoch !== state.mutationEpoch) return;
        var first = !state.serverDown;
        renderServerDown(err);
        if (first) showToast('Local server offline', 'The GUI server is not responding.', 'error');
      }).then(function () {
        state.statusInFlight = null;
      });
      return state.statusInFlight;
    }

    function loadProbe() {
      return api('/api/probe').then(function (data) {
        state.probe = data && typeof data === 'object' ? data : {};
        state.probeLoaded = true;
        renderHealth(true);
      }).catch(function (err) {
        state.probe = { available: false, error: err.message };
        state.probeLoaded = true;
        renderHealth(true);
      });
    }

    /* ------------------------------ event wiring ---------------------------- */

    function bindInput(input, key, validator, errorEl) {
      input.addEventListener('input', function () {
        state.config[key] = input.value;
        saveConfig();
        if (key === 'port') updateModeUI();
        var message = validator();
        if (errorEl) {
          if (message || input.classList.contains('is-invalid')) setFieldError(input, errorEl, message);
        } else {
          input.classList.toggle('is-invalid', !!message);
          input.setAttribute('aria-invalid', message ? 'true' : 'false');
        }
        if (!message && key === 'iface' && state.status) renderStatus(state.status);
      });
      input.addEventListener('blur', function () {
        var message = validator();
        if (errorEl && (message || input.value !== '')) setFieldError(input, errorEl, message);
        if (!errorEl && message) {
          input.classList.add('is-invalid');
          input.setAttribute('aria-invalid', 'true');
        }
      });
    }

    function bindEvents() {
      dom.navItems.forEach(function (item) {
        item.addEventListener('click', function () {
          setView(item.getAttribute('data-view'), true);
        });
      });
      dom.viewLogsBtn.addEventListener('click', function () { setView('logs', true); });

      dom.themeToggle.addEventListener('click', function () {
        setTheme(state.theme === 'dark' ? 'light' : 'dark', true);
      });
      try {
        var media = window.matchMedia('(prefers-color-scheme: dark)');
        if (media.addEventListener) {
          media.addEventListener('change', function (event) {
            if (!storedTheme()) setTheme(event.matches ? 'dark' : 'light', false);
          });
        }
      } catch (e) { /* older browsers */ }

      window.addEventListener('storage', function (event) {
        if (event.key === THEME_KEY && validTheme(event.newValue)) {
          setTheme(event.newValue, false);
        }
      });

      dom.modeSelect.addEventListener('change', function () {
        state.config.mode = dom.modeSelect.value;
        saveConfig();
        updateModeUI();
        if (state.config.mode === 'phone' && !dom.phoneHost.value.trim()) phoneRequest('discover');
        validateConfig(false);
        if (state.status) renderStatus(state.status);
      });

      dom.modeButtons.forEach(function (btn) {
        btn.addEventListener('click', function () {
          if (btn.disabled) return;
          state.config.mode = btn.getAttribute('data-mode');
          saveConfig();
          updateModeUI();
          if (state.config.mode === 'phone' && !dom.phoneHost.value.trim()) phoneRequest('discover');
          validateConfig(false);
          if (state.status) renderStatus(state.status);
        });
      });

      dom.pinToggle.addEventListener('click', function () {
        state.config.pin = !state.config.pin;
        saveConfig();
        updateModeUI();
        if (!state.config.pin) {
          dom.ifaceInput.classList.remove('is-invalid');
          dom.ifaceInput.setAttribute('aria-invalid', 'false');
        }
        if (state.status) renderStatus(state.status);
      });

      dom.ipv6Toggle.addEventListener('click', function () {
        state.config.ipv6 = !state.config.ipv6;
        saveConfig();
        updateModeUI();
        if (state.status) renderStatus(state.status);
      });

      dom.pingToggle.addEventListener('change', function () {
        state.ping = !!dom.pingToggle.checked;
        // Keep this setting under its own key. It applies to the next start.
        try { localStorage.setItem(PING_KEY, state.ping ? 'true' : 'false'); } catch (e) { /* private mode */ }
      });

      dom.pairStart.addEventListener('click', function () { startPairing(false); });
      dom.pairCancel.addEventListener('click', cancelPairing);
      dom.phoneProbe.addEventListener('click', checkSourceDevice);
      dom.pairForget.addEventListener('click', forgetPairing);
      dom.copyDiagnostics.addEventListener('click', copyDiagnosticsReport);
      dom.phoneDiscover.addEventListener('click', function () { phoneRequest('discover'); });
      dom.phoneCheck.addEventListener('click', function () { phoneRequest('check'); });
      [dom.phoneHost, dom.phonePort, dom.phoneToken].forEach(function (input) {
        input.addEventListener('input', function () {
          dom.phoneResult.textContent = 'Check the connection before starting.';
          if (!manualToken()) {
            manualPhoneFields().forEach(function (field) { setFieldError(field[0], field[1], ''); });
            return;
          }
          if (input.classList.contains('is-invalid')) validateConfig(false);
        });
      });

      bindInput(dom.hostInput, 'host', hostError, dom.hostError);
      bindInput(dom.portInput, 'port', portError, dom.portError);
      bindInput(dom.dnsInput, 'dns', dnsError, dom.dnsError);
      bindInput(dom.tunDnsInput, 'tunDns', tunDnsError, dom.tunDnsError);
      bindInput(dom.unitInput, 'unit', unitError, dom.unitError);
      bindInput(dom.addrInput, 'addr', addrError, dom.addrError);
      bindInput(dom.ifaceInput, 'iface', ifaceError, null);

      dom.configForm.addEventListener('submit', function (event) {
        event.preventDefault();
        startSession();
      });

      dom.startBtn.addEventListener('click', function () { startSession(); });
      dom.configStartBtn.addEventListener('click', function () { startSession(); });
      dom.stopBtn.addEventListener('click', function () { stopSession(); });
      dom.configStopBtn.addEventListener('click', function () { stopSession(); });

      dom.pauseBtn.addEventListener('click', function () { setPaused(!state.paused); });
      dom.clearLogsBtn.addEventListener('click', clearLogView);
      dom.copyFailures.addEventListener('click', copyFailureReport);
      dom.autoScrollToggle.addEventListener('click', function () {
        state.autoScroll = !state.autoScroll;
        updateAutoScroll();
        if (state.autoScroll) dom.logsPanel.scrollTop = dom.logsPanel.scrollHeight;
      });
      dom.logsPanel.addEventListener('scroll', function () {
        var distance = dom.logsPanel.scrollHeight - dom.logsPanel.scrollTop - dom.logsPanel.clientHeight;
        if (distance > 48 && state.autoScroll) {
          state.autoScroll = false;
          updateAutoScroll();
        }
      });

      window.addEventListener('hashchange', function () {
        setView(location.hash.replace(/^#/, ''), false);
      });

      document.addEventListener('visibilitychange', function () {
        if (!document.hidden) {
          loadStatus();
          loadLogs();
          loadFailures();
          renderUptime();
        }
      });
    }

    /* -------------------------------- bootstrap ----------------------------- */

    setTheme(bootTheme, false);
    applyConfigToForm();
    bindEvents();
    if (state.config.mode === 'phone' && !dom.phoneHost.value.trim()) phoneRequest('discover');
    updateAutoScroll();
    var initial = location.hash ? location.hash.replace(/^#/, '') : 'dashboard';
    setView(initial, false);

    loadStatus();
    loadProbe();
    loadLogs();
    loadFailures();
    loadPair();

    setInterval(function () { if (!document.hidden) loadStatus(); }, 1500);
    setInterval(function () { if (!document.hidden) loadLogs(); }, 1200);
    setInterval(function () { if (!document.hidden) loadFailures(); }, 5000);
    setInterval(function () { if (!document.hidden) loadProbe(); }, 30000);
    setInterval(renderUptime, 1000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
