/* Pure presentation helpers for the HotspotShade Linux target app.
 *
 * This file has no DOM access, no Electron access, and no network access. The
 * page and the hermetic Node tests use the same functions. The values come from
 * the selected backend. The functions never claim that a tunnel is on when the
 * backend does not report it.
 */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.HotspotShadeModel = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var ACTION_LABELS = {
    pair: 'Pair with source device',
    pairAgain: 'Pair again',
    turnOn: 'Turn on',
    turnOff: 'Turn off',
    retry: 'Try again',
    checkNow: 'Check now',
    forget: 'Forget this source device',
    turnOffAndForget: 'Turn off and forget'
  };

  var T = {
    startingApp: 'Starting HotspotShade',
    startingAppDetail: 'The app is reading the local backend status.',
    statusUnavailable: 'Status unavailable',
    statusUnavailableDetail: 'The engine did not answer.',
    needsAttention: 'Needs attention',
    startingTunnel: 'Starting the tunnel',
    stopping: 'Turning off',
    takesAMinute: 'This can take a minute.',
    pairing: 'Pairing',
    pairingDetail: 'Connecting to your source device.',
    forgetting: 'Forgetting this source device',
    forgettingDetail: 'The request is in progress.',
    checking: 'Checking the source device',
    checkingDetail: 'The result updates when the check finishes.',
    on: 'On',
    onDetail: 'The tunnel is on.',
    ready: 'Ready',
    readyDetail: 'The source device is ready.',
    waiting: 'Waiting for your source device',
    notPaired: 'Not paired',
    notPairedDetail: 'Pair with your source device to use it.',
    notTrusted: 'Not trusted',
    notTrustedDetail: 'The source device does not know this target device.',
    proxyOff: 'Paired',
    proxyOffDetail: 'Start the proxy on your source device.',
    noHotspot: 'Connect this target device to the source device hotspot.',
    notRunning: 'Open HotspotShade on your source device.',
    notResponding: 'Open HotspotShade on your source device and keep it open.',
    unknownDetail: 'The engine sent a status that this app does not know.',
    staleStatus: 'The engine did not answer. This status may be out of date.',
    sourceStopped: 'The source device stopped answering. New connections fail.',
    notTrustedRunning: 'The source device forgot this target device. The tunnel keeps running until you turn it off.',
    forgetBlocked: 'Turn off the tunnel to forget this source device.',
    forgetPending: 'Forgetting this source device.',
    forgetConfirmed: 'Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it.',
    forgetNotDelivered: 'Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it.',
    trustedBySource: 'The source device still knows this target device. Press Pair to continue.',
    portChanged: 'The source device changed its port. Turn the tunnel off and on.',
    notificationsDenied: 'Notifications are off. You will not see a message when the tunnel turns off.',
    notificationsUnavailable: 'This desktop does not support notifications.',
    pingOn: 'Ping is on.',
    pingOff: 'Ping is off.',
    directNotUsed: 'Not used',
    directReady: 'Direct mode',
    directDetail: 'No source device app is used. The tunnel uses this target device hotspot link.',
    directOnDetail: 'Direct mode. No source device app is used.',
    directSourceDetail: 'Direct mode does not use a source device app.',
    directIpv6: 'IPv6 is blocked in direct mode.',
    directLink: 'The tunnel uses this target device hotspot link.',
    directUnverified: 'The engine reports direct mode. Live route behavior is not verified by this app.',
    paired: 'Paired',
    notPairedCard: 'Not paired',
    tunnelOn: 'Tunnel on',
    tunnelOff: 'Tunnel off',
    starting: 'Starting',
    statusUnavailableLine: 'The status is unavailable.',
    checkStatusAgain: 'Check the status again.',
    noConnectionYet: 'No connection yet.',
    tunnelReady: 'The tunnel is ready.',
    pairToRestoreTrust: 'Pair again to restore trust.',
    pairWhenReady: 'Pair when you are ready.',
    pressPairToContinue: 'Press Pair to continue.',
    pairingSaved: 'The pairing is saved.',
    lookingForSourceDevice: 'The app is looking for the source device.',
    checksEverySecond: 'The app checks for the source device every second.',
    tunnelUsesSourceDevice: 'The tunnel uses this source device.',
    readTheMessageAbove: 'Read the message above.',
    loading: 'Loading',
    loadingDetail: 'Reading the app backend.',
    simulated: 'Demo mode. Data is simulated.',
    pairingTitle: 'Pair your source device',
    pairingCheck: 'Check both screens.',
    pairingConnecting: 'Connecting to your source device.',
    pairingCompare: 'Check that both screens show the same code.',
    pairingSavedLine: 'The pairing is saved.',
    pairingFailed: 'The pairing failed. Try again.',
    pairingIdle: 'Pair when you are ready.',
    waitingForCode: 'Waiting for the code.'
  };

  /* The two tunnel modes. The page offers one choice before a start. Direct
   * mode has no source device app, blocks IPv6 by default, and uses the engine
   * default physical hotspot interface. Source device proxy mode keeps the
   * existing pairing and forwarding behavior. */
  var START_MODE_ROWS = [
    {
      id: 'phone',
      label: 'Source device proxy',
      detail: 'Uses the HotspotShade app on the source device. IPv6 is forwarded through the source device.'
    },
    {
      id: 'direct',
      label: 'Direct',
      detail: 'No app on the source device. The engine uses this target device hotspot link. IPv6 is blocked by default.'
    }
  ];

  function normalizeStartMode(value) {
    return value === 'direct' ? 'direct' : 'phone';
  }

  function modeChoice(input) {
    var value = object(input);
    var runningMode = value.runningMode === 'phone' || value.runningMode === 'direct' ? value.runningMode : '';
    var selected = runningMode || normalizeStartMode(value.selected);
    var locked = value.locked === true || runningMode !== '';
    return {
      selected: selected,
      running: runningMode !== '',
      locked: locked,
      rows: START_MODE_ROWS.map(function (row) {
        return {
          id: row.id,
          label: row.label,
          detail: row.detail,
          pressed: row.id === selected,
          disabled: locked
        };
      })
    };
  }

  /* Fixed text for known start refusal codes. The code comes from the engine
   * or from the local request validation. An unknown code keeps the plain
   * message that the backend sent. */
  function startFailureText(code, message) {
    var fallback = sanitized(message) || 'The tunnel did not start.';
    switch (text(code)) {
      case 'admin_required':
        return 'Direct mode needs the root engine. Start the packaged app, or run the development engine as root.';
      case 'route_setup':
        return 'The tunnel could not configure its routes. Cleanup may need attention. Check the current status before trying again.';
      case 'tunnel_setup':
        return 'The tunnel could not set up its virtual interface. Check the current status and any cleanup warning before trying again.';
      case 'service_start':
        return 'The engine could not start the tunnel. Check the hotspot link and try again.';
      case 'start_cancelled':
        return 'The start was cancelled. Check the current status and any cleanup warning before trying again.';
      case 'unsupported_mode':
        return 'This engine does not support the selected tunnel mode.';
      case 'protected_helper_required':
        return 'The protected engine helper is not available. Install the signed package, then try again.';
      default:
        return fallback;
    }
  }

  function object(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }

  function text(value) {
    return typeof value === 'string' ? value : '';
  }

  function finite(value) {
    var number = typeof value === 'number' ? value : parseFloat(value);
    return isFinite(number) ? number : null;
  }

  function action(id) {
    return id && ACTION_LABELS[id] ? { id: id, label: ACTION_LABELS[id] } : null;
  }

  function unique(items) {
    var seen = {};
    return items.filter(function (item) {
      if (!item || seen[item]) return false;
      seen[item] = true;
      return true;
    });
  }

  function sanitized(value, limit) {
    var maximum = limit || 600;
    var message = text(value);
    if (!message) return '';
    message = message.replace(/hotspot proxy/gi, 'HotspotShade');
    message = message.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ');
    message = message.replace(/[ \t]+/g, ' ');
    message = message.replace(/\s*\n\s*/g, '\n').trim();
    if (message.length > maximum) message = message.slice(0, maximum);
    return message;
  }

  function formatInt(value) {
    var number = Math.round(finite(value) || 0);
    if (Math.abs(number) < 1000) return String(number);
    if (Math.abs(number) < 1000000) {
      var thousands = number / 1000;
      return (Math.abs(thousands) >= 100 ? Math.round(thousands) : thousands.toFixed(1).replace(/\.0$/, '')) + 'k';
    }
    var millions = number / 1000000;
    return (Math.abs(millions) >= 100 ? Math.round(millions) : millions.toFixed(1).replace(/\.0$/, '')) + 'M';
  }

  function parseTimeMs(value) {
    if (value === null || value === undefined || value === '') return null;
    if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
    var raw = String(value).trim();
    if (/^\d+(\.\d+)?$/.test(raw)) {
      var epoch = parseFloat(raw);
      return epoch < 1e12 ? epoch * 1000 : epoch;
    }
    var parsed = Date.parse(raw);
    return isNaN(parsed) ? null : parsed;
  }

  function formatClock(value) {
    var milliseconds = parseTimeMs(value);
    if (milliseconds === null) return 'n/a';
    var date = new Date(milliseconds);
    function two(number) {
      return number < 10 ? '0' + number : String(number);
    }
    return two(date.getHours()) + ':' + two(date.getMinutes()) + ':' + two(date.getSeconds());
  }

  function checkedText(checkedAt, nowSeconds) {
    var checked = finite(checkedAt);
    var now = finite(nowSeconds);
    if (checked === null || now === null) return null;
    var age = Math.max(0, Math.floor(now - checked));
    if (!Number.isSafeInteger(age)) return null;
    if (age < 10) return 'Checked just now';
    if (age < 60) return 'Checked ' + age + (age === 1 ? ' second ago' : ' seconds ago');
    var minutes = Math.floor(age / 60);
    return 'Checked ' + minutes + (minutes === 1 ? ' minute ago' : ' minutes ago');
  }

  function groupPairingCode(value) {
    var digits = text(value).replace(/\D/g, '');
    if (!digits) return '';
    var groups = [];
    for (var index = 0; index < digits.length; index += 3) {
      groups.push(digits.slice(index, index + 3));
    }
    return groups.join(' ');
  }

  function forgetMessage(forget) {
    var state = text(object(forget).state);
    if (state === 'pending') return T.forgetPending;
    if (state === 'confirmed') return T.forgetConfirmed;
    if (state === 'not_delivered') return T.forgetNotDelivered;
    return null;
  }

  function pingLine(status) {
    var data = object(status);
    if (data.running !== true || data.mode !== 'phone') return null;
    if (data.icmp_enabled === true) return T.pingOn;
    if (data.icmp_enabled === false) return T.pingOff;
    return null;
  }

  function connectionsLine(status) {
    var data = object(status);
    if (data.running !== true) return null;
    var count = finite(object(data.phone).connections);
    if (count === null) return null;
    var value = Math.max(0, Math.round(count));
    return 'The source device reports ' + value + ' active connection' + (value === 1 ? '' : 's') + '.';
  }

  function lastStopLine(status) {
    var data = object(status);
    if (data.running === true) return null;
    var message = sanitized(data.last_stop_message);
    return message ? 'Last stop: ' + message : null;
  }

  /* Destination privacy capabilities for this target build.
   *
   * These rows are fixed facts about the Linux target app and the engine build
   * it ships with. The card reports what the build can do, not a live mode,
   * because the page does not read the tunnel state. Off is the built-in
   * behavior that applies only while a tunnel runs, so it is reported as the
   * default and never as "in force" or "on". Every other mode is unavailable
   * or deferred, and the page offers no switch. When the engine gains a mode,
   * change a row only with a working engine path and a real control. Never
   * mark a mode available on its own.
   */
  var PRIVACY_MODES = [
    {
      id: 'off',
      title: 'Off',
      state: 'default',
      stateText: 'Default',
      detail: 'This is the built-in behavior when a tunnel runs. It normalizes the TTL and sends each inner flow through a normal outer socket, and it changes no payload byte. It adds no concealment of its own. This card does not report whether a tunnel is running now.'
    },
    {
      id: 'shape',
      title: 'Shape the TLS handshake',
      state: 'unavailable',
      stateText: 'Unavailable',
      detail: 'Proposed, not built in this engine. It would re-cut the first TLS records on the relay socket and change no handshake byte. It would not hide the server name, the destination address, the TLS fingerprint, or the flow size, and it cannot pad the handshake.'
    },
    {
      id: 'hide',
      title: 'Hide the destination name',
      state: 'unavailable',
      stateText: 'Unavailable',
      detail: 'Unavailable under the current design. The engine relays bytes and does not terminate another application TLS connection, so it cannot add ECH or change the server name in that handshake. Adding ECH or DoH to the engine would not by itself hide relayed application TLS. This build offers no switch for it.'
    },
    {
      id: 'cover',
      title: 'Cover with an endpoint you own',
      state: 'deferred',
      stateText: 'Deferred',
      detail: 'No endpoint is configured. It would need one TLS endpoint that you own. The project keeps no external relay or VPS, so this build does not offer it, and naming a site that belongs to another service stays out of scope.'
    }
  ];

  var PRIVACY_FACTS = [
    {
      id: 'ech',
      title: 'ECH in the engine',
      value: 'Not in this build',
      detail: 'This build has no TLS client that uses ECH, so it adds no encrypted server name. An application can use its own ECH; that is outside this app, and this card does not turn it on or verify it. A server name may still be visible when a flow does not use ECH.'
    },
    {
      id: 'server_name',
      title: 'Server name override',
      value: 'Not in this build',
      detail: 'The engine relays bytes and opens no TLS session for a destination. A relay cannot change the server name in a handshake it does not terminate.'
    },
    {
      id: 'doh',
      title: 'DNS over HTTPS',
      value: 'Not in this build',
      detail: 'Relayed DNS is forwarded through the tunnel without DoH. A resolver or application can use encrypted DNS on its own; that is outside this app, and this card does not turn it on or verify it. A DNS name may still be visible when the lookup is not encrypted.'
    },
    {
      id: 'one_socket',
      title: 'One socket per flow',
      value: 'Yes',
      detail: 'Each inner flow keeps its own outer socket. The relay adds no nested TLS session.'
    }
  ];

  var PRIVACY_LIMITS = [
    'Off adds no concealment. For a flow that the application does not conceal itself, a network may see the TLS server name, the destination address and network, DNS names, the TLS fingerprint, and the flow size and timing. Some networks do not inspect these values, and some applications or resolvers use their own encryption. This card does not rely on either.',
    'An application or resolver can use its own ECH or encrypted DNS. That work happens outside this app, and this card neither provides it nor verifies it. Metadata such as the destination address, the flow size, and the timing can stay visible even then.',
    'When both endpoints negotiate TLS 1.3, the destination certificate is encrypted. The relay does not control the negotiated version, so this is not a property of this app.',
    'Tethering detection also uses the TCP and operating-system fingerprint and volume patterns. No mode on this page changes those.',
    'The relay is not a TLS tunnel. Each inner flow keeps its own outer socket, so there is no nested TLS handshake to detect. That is a property of the existing relay, not a privacy mode.',
    'Hide, if it is ever built, would cover only flows carried by a product-owned TLS client, and only destinations that publish an ECH config. Most destinations do not. Adding ECH and DoH to the engine would not by itself hide relayed application TLS.'
  ];

  var PRIVACY_STORAGE_NOTE = 'This card has no switch and saves no setting. The app stores no destination-privacy mode, and nothing here changes the engine or a running tunnel.';

  function copyRow(row) {
    return {
      id: row.id,
      title: row.title,
      state: row.state,
      stateText: row.stateText,
      detail: row.detail
    };
  }

  function copyFact(fact) {
    return {
      id: fact.id,
      title: fact.title,
      value: fact.value,
      detail: fact.detail
    };
  }

  function privacyView(input) {
    input = object(input);
    var demo = input.demo === true;
    var engine = input.engine === true;
    var intro;
    if (demo) {
      intro = 'Demo mode. This card describes the app build. The simulated backend runs no tunnel. The card does not report a live mode.';
    } else if (engine) {
      intro = 'This build has no destination-privacy mode. This card reports what the build can do. It does not report whether a tunnel is running. When a tunnel runs it normalizes the TTL and forwards each flow as it is, and it adds no concealment of its own.';
    } else {
      intro = 'This build has no destination-privacy mode. This card reports what the build can do. It does not report whether a tunnel is running. When a tunnel runs it normalizes the TTL and forwards each flow as it is, and it adds no concealment of its own.';
    }
    return {
      mode: 'off',
      modeText: 'Off',
      modeState: 'default',
      modeStateText: 'Default',
      modePillText: 'Off (default)',
      modeTitle: 'Off is the default behavior of this build. This card does not report whether a tunnel is running.',
      appliesLiveMode: false,
      subtitle: 'What this build can and cannot hide. This card is read-only and does not report a live mode.',
      intro: intro,
      demo: demo,
      engine: engine,
      modes: PRIVACY_MODES.map(copyRow),
      facts: PRIVACY_FACTS.map(copyFact),
      limits: PRIVACY_LIMITS.slice(),
      storageNote: PRIVACY_STORAGE_NOTE,
      switchAvailable: false
    };
  }

  function statusFreshness(failureSince, nowMilliseconds, hasStatus) {
    if (!hasStatus) return 'fresh';
    var since = finite(failureSince);
    var now = finite(nowMilliseconds);
    if (since === null || now === null) return 'fresh';
    var age = Math.max(0, now - since);
    if (age >= 10000) return 'unavailable';
    if (age >= 3000) return 'stale';
    return 'fresh';
  }

  function deriveDashboard(input) {
    input = object(input);
    var status = object(input.status);
    var pair = object(input.pair);
    var hasStatus = input.hasStatus !== false && Object.keys(status).length > 0;
    var freshness = input.freshness === 'stale' || input.freshness === 'unavailable' ? input.freshness : 'fresh';
    var busy = text(input.busy);
    var error = sanitized(input.error);
    var pairingState = text(pair.state);
    var pairingActive = pairingState === 'connecting' || pairingState === 'confirm' || pairingState === 'starting';
    var operation = busy === 'start' || busy === 'stop' ? busy : null;
    var running = hasStatus && status.running === true;
    var pairingKnown = hasStatus && typeof status.paired === 'boolean';
    var paired = hasStatus && status.paired === true;
    var selectedMode = normalizeStartMode(input.startMode);
    var runningMode = running
      ? (status.mode === 'tun' ? 'direct' : status.mode === 'phone' ? 'phone' : '')
      : '';
    var directRunning = runningMode === 'direct';
    var directIdle = !running && selectedMode === 'direct';
    var phone = object(status.phone);
    var phoneState = text(phone.state) || (pairingKnown && !paired ? 'unpaired' : 'unknown');
    var phoneMessage = sanitized(phone.message);
    var tokenRejected = sanitized(input.tokenRejected);
    var linkAdvice = Array.isArray(input.linkAdvice) ? input.linkAdvice.map(function (line) { return sanitized(line); }).filter(Boolean) : [];
    var demo = hasStatus && status.demo === true;
    var checked = hasStatus ? checkedText(phone.checked_at, input.nowSeconds) : null;
    var unknown = hasStatus && (status.state === 'unknown' || typeof status.running !== 'boolean');
    var cleanupBlocked = hasStatus && status.cleanup_blocked === true;
    var recoveryBlocked = unknown || cleanupBlocked;
    var unavailable = freshness === 'unavailable' || recoveryBlocked;
    var forgetBlocked = input.forgetBlocked === true;
    var attention = [];
    var title;
    var subtitle;
    var kind;
    var primary = null;
    var secondary = null;

    if (!hasStatus) {
      if (error) {
        title = T.needsAttention;
        subtitle = error;
        kind = 'attention';
        primary = action('retry');
      } else {
        title = T.startingApp;
        subtitle = T.startingAppDetail;
        kind = 'busy';
      }
      return result();
    }

    if (operation === 'start') {
      title = T.startingTunnel;
      subtitle = T.takesAMinute;
      kind = 'busy';
    } else if (operation === 'stop') {
      title = T.stopping;
      subtitle = T.takesAMinute;
      kind = 'busy';
    } else if (recoveryBlocked) {
      title = T.statusUnavailable;
      subtitle = sanitized(status.error) || (cleanupBlocked
        ? 'Tunnel cleanup did not finish. Inspect routes and devices before restarting.'
        : T.unknownDetail);
      kind = 'attention';
      primary = action('checkNow');
    } else if (tokenRejected) {
      title = 'Pair again';
      subtitle = tokenRejected;
      kind = 'attention';
      primary = action('pairAgain');
    } else if (unavailable) {
      title = T.statusUnavailable;
      subtitle = T.statusUnavailableDetail;
      kind = 'attention';
      primary = action('checkNow');
    } else if (error) {
      title = T.needsAttention;
      subtitle = error;
      kind = 'attention';
      primary = action(running ? 'turnOff' : 'retry');
    } else if (running) {
      title = T.on;
      subtitle = directRunning ? T.directOnDetail : (phoneMessage || T.onDetail);
      kind = 'on';
      primary = action('turnOff');
    } else if (pairingActive) {
      title = T.pairing;
      subtitle = T.pairingDetail;
      kind = 'pairing';
    } else if (busy === 'forget') {
      title = T.forgetting;
      subtitle = T.forgettingDetail;
      kind = 'busy';
    } else if (busy === 'check') {
      title = T.checking;
      subtitle = T.checkingDetail;
      kind = 'busy';
    } else if (directIdle) {
      title = T.directReady;
      subtitle = T.directDetail;
      kind = 'off';
      primary = action('turnOn');
    } else if (!pairingKnown) {
      title = T.statusUnavailable;
      subtitle = T.unknownDetail;
      kind = 'attention';
      primary = action('checkNow');
    } else {
      var calm = unpairedState();
      switch (phoneState) {
        case 'not_trusted':
          if (paired) {
            title = T.notTrusted;
            subtitle = phoneMessage || T.notTrustedDetail;
            kind = 'attention';
            primary = action('pairAgain');
          } else {
            title = calm.title; subtitle = calm.subtitle; kind = calm.kind; primary = calm.primary;
          }
          break;
        case 'proxy_off':
          if (paired) {
            title = T.proxyOff;
            subtitle = phoneMessage || T.proxyOffDetail;
            kind = 'off';
          } else {
            title = calm.title; subtitle = calm.subtitle; kind = calm.kind; primary = calm.primary;
          }
          break;
        case 'ready':
        case 'connected':
          if (paired) {
            title = T.ready;
            subtitle = phoneMessage || T.readyDetail;
            kind = 'off';
            primary = action('turnOn');
          } else {
            title = calm.title; subtitle = calm.subtitle; kind = calm.kind; primary = calm.primary;
          }
          break;
        case 'no_hotspot':
          title = T.waiting;
          subtitle = phoneMessage || T.noHotspot;
          kind = 'off';
          break;
        case 'not_running':
          title = T.waiting;
          subtitle = phoneMessage || T.notRunning;
          kind = 'off';
          break;
        case 'not_responding':
          title = T.waiting;
          subtitle = phoneMessage || T.notResponding;
          kind = 'off';
          break;
        case 'unknown':
          title = T.statusUnavailable;
          subtitle = phoneMessage || T.unknownDetail;
          kind = 'attention';
          primary = action('checkNow');
          break;
        case 'unpaired':
        default:
          title = calm.title; subtitle = calm.subtitle; kind = calm.kind; primary = calm.primary;
          break;
      }
    }

    if (recoveryBlocked) {
      secondary = running && freshness === 'fresh'
        ? { id: 'turnOff', label: 'Try to turn off' }
        : null;
    } else if (forgetBlocked) {
      secondary = action('turnOffAndForget');
    } else if (freshness === 'stale') {
      secondary = action('checkNow');
    } else if (paired && !running && !operation && !pairingActive) {
      secondary = action('forget');
    }

    if (!recoveryBlocked && running && !directRunning && phoneState === 'not_responding') attention.push(T.sourceStopped);
    if (!recoveryBlocked && running && !directRunning && phoneState === 'not_trusted') attention.push(T.notTrustedRunning);
    if (recoveryBlocked && input.retryAction === 'stop' && error) attention.push(error);
    if (!recoveryBlocked) attention.push.apply(attention, linkAdvice);
    if (freshness !== 'fresh') attention.push(T.staleStatus);
    if (input.notificationsUnavailable === true) attention.push(T.notificationsUnavailable);
    else if (input.notificationsDenied === true) attention.push(T.notificationsDenied);
    if (forgetBlocked && !recoveryBlocked) attention.unshift(T.forgetBlocked);
    if (!recoveryBlocked && phone.port_changed === true) attention.push(T.portChanged);
    attention = unique(attention);

    if (kind !== 'attention' && title === T.notTrusted) kind = 'attention';

    return result();

    function unpairedState() {
      var message = forgetMessage(status.forget);
      if (message) return { title: T.notPaired, subtitle: message, kind: 'off', primary: action('pair') };
      if (phone.trusted_by_source === true) {
        return { title: T.notPaired, subtitle: T.trustedBySource, kind: 'off', primary: action('pair') };
      }
      return { title: T.notPaired, subtitle: T.notPairedDetail, kind: 'off', primary: action('pair') };
    }

    function result() {
      var cards;
      if (!hasStatus) {
        cards = {
          source: { value: T.loading, details: [T.loadingDetail] },
          connection: { value: T.loading, details: [T.loadingDetail] }
        };
      } else if (unavailable) {
        cards = {
          source: { value: T.statusUnavailableLine, details: [T.checkStatusAgain] },
          connection: { value: T.statusUnavailableLine, details: [T.checkStatusAgain] }
        };
      } else {
        cards = { source: sourceCard(), connection: connectionCard() };
      }
      return {
        kind: kind,
        title: title,
        subtitle: subtitle,
        primary: primary,
        secondary: secondary,
        attention: attention,
        source: cards.source,
        connection: cards.connection,
        checked: checked,
        demo: demo,
        stale: freshness === 'stale',
        unavailable: unavailable,
        hasStatus: hasStatus,
        running: running,
        paired: paired,
        pairingKnown: pairingKnown,
        phoneState: phoneState,
        selectedMode: selectedMode,
        runningMode: runningMode,
        activeMode: runningMode || selectedMode,
        direct: directRunning || directIdle,
        modeLocked: recoveryBlocked || running || !!operation || pairingActive
      };
    }

    function sourceCard() {
      var value;
      var details = [];
      if (directRunning || directIdle) {
        value = T.directNotUsed;
        details.push(T.directSourceDetail);
        if (directRunning) details.push(T.directLink);
      } else if (!pairingKnown) {
        value = T.statusUnavailableLine;
        details.push(T.checkStatusAgain);
      } else if (phoneState === 'not_trusted' && paired) {
        value = T.notTrusted;
        details.push(T.pairToRestoreTrust);
      } else if (paired) {
        value = T.paired;
        if (title === T.pairing) details.push(T.lookingForSourceDevice);
        else if (title === T.waiting) details.push(T.checksEverySecond);
        else if (title === T.on) details.push(T.tunnelUsesSourceDevice);
        else if (title === T.needsAttention) details.push(T.readTheMessageAbove);
        else if (title === T.statusUnavailable) details.push(T.checkStatusAgain);
        else details.push(T.pairingSaved);
      } else {
        value = T.notPairedCard;
        if (subtitle === T.trustedBySource) details.push(T.pressPairToContinue);
        else details.push(T.pairWhenReady);
      }
      if (phone.port_changed === true && details.indexOf(T.portChanged) === -1) details.push(T.portChanged);
      return { value: value, details: unique(details) };
    }

    function connectionCard() {
      var value;
      if (operation === 'start') value = T.starting;
      else if (operation === 'stop') value = T.stopping;
      else if (running) value = T.tunnelOn;
      else value = T.tunnelOff;

      var details = [];
      var stop = lastStopLine(status);
      if (directRunning || directIdle) {
        details.push(T.directDetail);
        details.push(T.directIpv6);
        if (directRunning) details.push(T.directUnverified);
        if (stop) details.push(stop);
        return { value: value, details: unique(details) };
      }
      var ping = pingLine(status);
      var connections = connectionsLine(status);
      if (ping) details.push(ping);
      if (connections) details.push(connections);
      if (stop) details.push(stop);
      for (var index = 0; index < linkAdvice.length; index += 1) {
        if (details.indexOf(linkAdvice[index]) === -1) details.push(linkAdvice[index]);
      }
      if (!details.length) details.push(running ? T.tunnelReady : T.noConnectionYet);
      return { value: value, details: details };
    }
  }

  function pairingView(pair, busy) {
    var data = object(pair);
    var state = text(data.state);
    var active = state === 'connecting' || state === 'confirm' || state === 'starting';
    var rawCode = text(data.code).replace(/\D/g, '');
    var message;
    if (state === 'connecting' || state === 'starting') message = T.pairingConnecting;
    else if (state === 'confirm') message = T.pairingCompare;
    else if (state === 'paired') message = T.pairingSavedLine;
    else if (state === 'failed') message = sanitized(data.error) || T.pairingFailed;
    else message = T.pairingIdle;
    return {
      active: active,
      state: state || 'idle',
      code: groupPairingCode(rawCode) || null,
      rawCode: rawCode || null,
      message: message,
      busy: busy === 'pair'
    };
  }

  function failureProto(group) {
    var value = text(group.proto).toLowerCase();
    return value === 'tcp' || value === 'udp' || value === 'dns' ? value : 'other';
  }

  function failureFamily(group) {
    var value = text(group.family).toLowerCase();
    return value === 'ipv4' || value === 'ipv6' ? value : 'other';
  }

  function failureReason(value) {
    var raw = text(value).trim().toLowerCase();
    if (raw === 'unreachable') return { raw: raw, phrase: 'could not be reached', table: 'Could not be reached' };
    if (raw === 'refused') return { raw: raw, phrase: 'was refused', table: 'Refused' };
    if (raw === 'timed_out') return { raw: raw, phrase: 'got no answer in time', table: 'No answer in time' };
    if (raw === 'denied') return { raw: raw, phrase: 'was blocked', table: 'Blocked' };
    return { raw: 'other', phrase: 'failed', table: 'Failed' };
  }

  // The setup stage of a source device connection. An older engine sends no
  // phase. A newer engine can send a word that this page does not know.
  function failurePhase(value) {
    var token = text(value).trim().toLowerCase();
    if (!token) return null;
    if (token === 'connect' || token === 'greeting' || token === 'auth' || token === 'request') return token;
    return 'unknown';
  }

  function failurePhaseRank(value) {
    var token = failurePhase(value);
    if (token === null) return 0;
    if (token === 'connect') return 1;
    if (token === 'greeting') return 2;
    if (token === 'auth') return 3;
    if (token === 'request') return 4;
    return 5;
  }

  function failurePhaseLabel(value) {
    switch (failurePhase(value)) {
      case 'connect': return 'Source connection';
      case 'greeting': return 'Greeting';
      case 'auth': return 'Sign-in';
      case 'request': return 'Destination request';
      case 'unknown': return 'Unknown stage';
      default: return 'Not reported';
    }
  }

  function failurePhaseWord(value) {
    var token = failurePhase(value);
    return token === null ? '-' : token;
  }

  function failurePhaseClause(value) {
    switch (failurePhase(value)) {
      case 'connect': return 'while the target device connected to the source device';
      case 'greeting': return 'while the target device greeted the source device';
      case 'auth': return 'while the target device signed in to the source device';
      case 'request': return 'while the source device checked the destination';
      case 'unknown': return 'at an unknown stage';
      default: return '';
    }
  }

  function failureKind(group) {
    var proto = failureProto(group);
    var port = finite(group.port);
    if (proto === 'tcp' && (port === 80 || port === 443)) return { id: 'web', word: 'web connection', table: 'Web' };
    if (proto === 'tcp') return { id: 'tcp', word: 'tcp connection', table: 'TCP' };
    if (proto === 'udp') return { id: 'udp', word: 'UDP connection', table: 'UDP' };
    if (proto === 'dns') return { id: 'dns', word: 'DNS lookup', table: 'DNS' };
    return { id: 'other', word: 'connection', table: 'Other' };
  }

  function trimmed(value) {
    var message = text(value).trim();
    return message || null;
  }

  function failureTarget(group) {
    return trimmed(group.name) || trimmed(group.example_ip) || 'an unknown address';
  }

  function orderedGroups(groups) {
    return groups.slice().sort(function (left, right) {
      var leftCount = Math.max(finite(left.count) || 1, 1);
      var rightCount = Math.max(finite(right.count) || 1, 1);
      if (leftCount !== rightCount) return rightCount - leftCount;
      if (failureProto(left) !== failureProto(right)) return failureProto(left) < failureProto(right) ? -1 : 1;
      if (failureFamily(left) !== failureFamily(right)) return failureFamily(left) < failureFamily(right) ? -1 : 1;
      var leftReason = failureReason(left.reason).raw;
      var rightReason = failureReason(right.reason).raw;
      if (leftReason !== rightReason) return leftReason < rightReason ? -1 : 1;
      if (failurePhaseRank(left.phase) !== failurePhaseRank(right.phase)) return failurePhaseRank(left.phase) - failurePhaseRank(right.phase);
      var leftPort = finite(left.port);
      var rightPort = finite(right.port);
      if ((leftPort === null ? Number.MAX_SAFE_INTEGER : leftPort) !== (rightPort === null ? Number.MAX_SAFE_INTEGER : rightPort)) {
        return (leftPort === null ? Number.MAX_SAFE_INTEGER : leftPort) - (rightPort === null ? Number.MAX_SAFE_INTEGER : rightPort);
      }
      var leftName = failureTarget(left);
      var rightName = failureTarget(right);
      if (leftName !== rightName) return leftName < rightName ? -1 : 1;
      var leftIp = trimmed(left.example_ip) || '';
      var rightIp = trimmed(right.example_ip) || '';
      return leftIp < rightIp ? -1 : leftIp > rightIp ? 1 : 0;
    });
  }

  function failureRows(failures) {
    var groups = Array.isArray(object(failures).groups) ? object(failures).groups : [];
    return orderedGroups(groups).map(function (group, index) {
      var count = Math.max(Math.round(finite(group.count) || 1), 1);
      var port = finite(group.port);
      var reason = failureReason(group.reason);
      var kind = failureKind(group);
      var family = failureFamily(group);
      var target = failureTarget(group);
      var detailParts = [];
      if (family === 'ipv4') detailParts.push('IPv4');
      if (family === 'ipv6') detailParts.push('IPv6');
      if (trimmed(group.name) && trimmed(group.example_ip)) detailParts.push(trimmed(group.example_ip));
      if (finite(group.code) !== null) detailParts.push('code ' + Math.round(finite(group.code)));
      var phaseToken = failurePhase(group.phase);
      var summary = count + ' ' + (count === 1 ? 'time' : 'times') + ': ' + (kind.id === 'dns' ? 'DNS lookup for ' : kind.word + ' to ') + target + (port === null ? '' : ' port ' + Math.round(port)) + ' ' + reason.phrase;
      var clause = failurePhaseClause(group.phase);
      if (clause) summary += ' ' + clause;
      return {
        id: index + '-' + [failureProto(group), family, port === null ? '' : port, reason.raw, phaseToken || '', group.name || '', group.example_ip || ''].join('|'),
        count: count,
        kind: kind.table,
        target: target,
        phase: failurePhaseLabel(group.phase),
        phaseToken: phaseToken,
        phaseWord: failurePhaseWord(group.phase),
        reason: reason.table,
        summary: summary,
        detail: detailParts.join(', ')
      };
    });
  }

  function failureReport(failures) {
    var data = object(failures);
    var groups = orderedGroups(Array.isArray(data.groups) ? data.groups : []);
    var total = Math.max(Math.round(finite(data.total) || 0), 0);
    var dropped = Math.max(Math.round(finite(data.dropped) || 0), 0);
    var lines = [
      (data.demo === true ? 'HotspotShade simulated failure report' : 'HotspotShade failure report'),
      'Data: ' + (data.demo === true ? 'simulated by the demo backend' : 'target device memory'),
      'Total: ' + total + ' failed connection' + (total === 1 ? '' : 's') + ', ' + dropped + ' dropped.'
    ];
    groups.forEach(function (group) {
      var kind = failureKind(group);
      var reason = failureReason(group.reason);
      var parts = [
        Math.max(Math.round(finite(group.count) || 1), 1) + 'x',
        kind.table.toLowerCase(),
        failureFamily(group),
        finite(group.port) === null ? '-' : String(Math.round(finite(group.port))),
        reason.raw,
        failurePhaseWord(group.phase),
        trimmed(group.name) || '-',
        trimmed(group.example_ip) || '-'
      ];
      if (finite(group.code) !== null) parts.push('code ' + Math.round(finite(group.code)));
      lines.push(parts.join(' '));
    });
    return lines.join('\n');
  }

  function failureView(failures) {
    if (!failures || typeof failures !== 'object') {
      return {
        state: 'unavailable',
        summary: 'The failure record is unavailable.',
        rows: [],
        report: '',
        copyable: false
      };
    }
    var data = object(failures);
    var rows = failureRows(data);
    var total = Math.max(Math.round(finite(data.total) || 0), 0);
    var demo = data.demo === true;
    if (!rows.length) {
      return {
        state: 'empty',
        summary: (demo ? 'Simulated data. ' : '') + 'No failed connections yet.',
        rows: [],
        report: demo ? failureReport(data) : '',
        copyable: false
      };
    }
    return {
      state: 'ready',
      summary: (demo ? 'Simulated data. ' : '') + formatInt(total) + ' failed ' + (total === 1 ? 'attempt' : 'attempts') + ' this session.',
      rows: rows,
      report: failureReport(data),
      copyable: true,
      demo: demo
    };
  }

  function metric(value) {
    var data = object(value);
    return 'count ' + formatInt(data.count) + ', p50 ' + formatInt(data.p50) + ' ms, p95 ' + formatInt(data.p95) + ' ms, max ' + formatInt(data.max) + ' ms';
  }

  function queueLine(label, value) {
    var data = object(value);
    return label + ': peak ' + formatInt(data.peak) + ', max age ' + formatInt(data.max_age_us) + ' us';
  }

  function diagnosticsReport(value, simulated) {
    var data = object(value);
    var engine = object(data.engine);
    var setup = object(data.setup);
    var dns = object(data.dns);
    var queues = object(data.queues);
    var udp = object(data.udp);
    var tcp = object(data.tcp);
    var failures = object(data.failures);
    var inputs = Array.isArray(queues.input) ? queues.input : [];
    var simulatedData = data.demo === true || simulated === true;
    var heading = 'HotspotShade diagnostics';
    if (data.demo === true) heading += ' (simulated demo)';
    else if (simulated === true) heading += ' (simulated engine demo)';
    var lines = [
      heading,
      'Data: ' + (simulatedData ? 'simulated' : 'local engine service'),
      'Version: ' + (text(engine.version) || 'unknown'),
      'Engine boundary: ' + (text(engine.boundary) || 'engine service'),
      'Tunnel: ' + (text(engine.tunnel) || 'engine service'),
      'Running: ' + (data.running === true ? 'yes' : 'no'),
      'Uptime: ' + formatInt(engine.uptime_s) + ' s',
      'Workers: ' + formatInt(engine.workers),
      'Connect: ' + metric(setup.connect_ms),
      'Greeting: ' + metric(setup.greeting_ms),
      'Auth: ' + metric(setup.auth_ms),
      'Request: ' + metric(setup.request_ms),
      'DNS lookups: ' + formatInt(dns.lookups) + ' (ok ' + formatInt(dns.ok) + ', failed ' + formatInt(dns.failed) + ')',
      'DNS time: ' + metric(dns.ms)
    ];
    if (inputs.length) {
      inputs.forEach(function (item, index) {
        lines.push(queueLine('Input queue ' + (index + 1), item));
      });
    } else {
      lines.push('Input queue: none');
    }
    lines.push(queueLine('Output queue', queues.output));
    lines.push('UDP flows: ' + formatInt(udp.flows) + ', age drops: ' + formatInt(udp.age_drops));
    lines.push('TCP flows peak: ' + formatInt(tcp.flows_peak) + ', retransmits: ' + formatInt(tcp.retransmits) + ', zero window: ' + formatInt(tcp.zero_window_ms) + ' ms');
    lines.push('Failures: total ' + formatInt(failures.total) + ', dropped ' + formatInt(failures.dropped));
    return lines.join('\n');
  }

  function activityEntries(lines) {
    if (!Array.isArray(lines)) return [];
    return lines.map(function (entry) {
      var level = text(entry.level).toLowerCase();
      if (level !== 'warn' && level !== 'error' && level !== 'debug') level = 'info';
      return {
        seq: entry.seq === undefined || entry.seq === null ? '' : String(entry.seq),
        time: formatClock(entry.ts),
        level: level,
        message: sanitized(entry.msg, 1000)
      };
    }).filter(function (entry) {
      return entry.message;
    });
  }

  function displayOs(value) {
    var raw = text(value).toLowerCase();
    if (raw.indexOf('linux') === 0) return 'Linux';
    if (raw.indexOf('mac') === 0 || raw === 'darwin') return 'macOS';
    if (raw.indexOf('win') === 0) return 'Windows';
    return text(value) || 'Unknown OS';
  }

  function menuCommandAllowed(value) {
    return ['dashboard', 'activity', 'settings', 'settings-inline', 'advanced', 'refresh', 'check-now', 'theme', 'demo-limitations', 'demo-scenarios'].indexOf(value) !== -1;
  }

  function tunnelStateConfirmed(status, running) {
    var value = object(status);
    return typeof running === 'boolean' && value.running === running &&
      value.state !== 'unknown' && value.cleanup_blocked !== true;
  }

  return {
    ACTION_LABELS: ACTION_LABELS,
    START_MODE_ROWS: START_MODE_ROWS,
    TEXT: T,
    deriveDashboard: deriveDashboard,
    tunnelStateConfirmed: tunnelStateConfirmed,
    modeChoice: modeChoice,
    normalizeStartMode: normalizeStartMode,
    startFailureText: startFailureText,
    pairingView: pairingView,
    groupPairingCode: groupPairingCode,
    checkedText: checkedText,
    forgetMessage: forgetMessage,
    pingLine: pingLine,
    connectionsLine: connectionsLine,
    lastStopLine: lastStopLine,
    privacyView: privacyView,
    statusFreshness: statusFreshness,
    formatInt: formatInt,
    formatClock: formatClock,
    failureView: failureView,
    failureReport: failureReport,
    failureRows: failureRows,
    failureReason: failureReason,
    failurePhase: failurePhase,
    failurePhaseLabel: failurePhaseLabel,
    failurePhaseWord: failurePhaseWord,
    failurePhaseClause: failurePhaseClause,
    diagnosticsReport: diagnosticsReport,
    activityEntries: activityEntries,
    displayOs: displayOs,
    menuCommandAllowed: menuCommandAllowed,
    sanitized: sanitized
  };
});
