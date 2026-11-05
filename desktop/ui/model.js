/* Pure state and text helpers for the HotspotShade desktop demo.
 *
 * This file has no DOM access. The desktop page and the hermetic tests use the
 * same functions. The demo bridge supplies the values. Nothing here contacts
 * the real engine.
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

  var DEMO_TITLE = 'Simulated data. No sockets open. No traffic leaves this machine.';
  var DEMO_BANNER = 'All data is simulated. No tunnel, routes, or network traffic.';
  var STALE_TEXT = 'The engine did not answer. This status may be out of date.';
  var UNAVAILABLE_TEXT = 'The status is unavailable.';
  var FORGET_BLOCKED = 'Turn off the tunnel to forget this source device.';
  var NOT_TRUSTED_RUNNING = 'The source device forgot this target device. The tunnel keeps running until you turn it off.';
  var PORT_CHANGED = 'The source device changed its port. Turn the tunnel off and on.';

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

  function object(value) {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }

  function text(value) {
    return typeof value === 'string' ? value : '';
  }

  function finite(value) {
    var n = typeof value === 'number' ? value : parseFloat(value);
    return isFinite(n) ? n : null;
  }

  function action(id) {
    return id && ACTION_LABELS[id] ? { id: id, label: ACTION_LABELS[id] } : null;
  }

  function formatInt(value) {
    var n = Math.round(finite(value) || 0);
    if (Math.abs(n) < 1000) return String(n);
    if (Math.abs(n) < 1000000) {
      var k = n / 1000;
      return (Math.abs(k) >= 100 ? Math.round(k) : k.toFixed(1).replace(/\.0$/, '')) + 'k';
    }
    var m = n / 1000000;
    return (Math.abs(m) >= 100 ? Math.round(m) : m.toFixed(1).replace(/\.0$/, '')) + 'M';
  }

  function formatBytes(value) {
    var n = finite(value) || 0;
    if (n < 1024) return Math.round(n) + ' B';
    var units = ['KB', 'MB', 'GB', 'TB'];
    var index = -1;
    do {
      n = n / 1024;
      index += 1;
    } while (n >= 1024 && index < units.length - 1);
    return (n >= 100 ? Math.round(n) : n.toFixed(1).replace(/\.0$/, '')) + ' ' + units[index];
  }

  function formatDuration(totalSeconds) {
    var seconds = Math.max(0, Math.floor(finite(totalSeconds) || 0));
    if (seconds < 60) return seconds + 's';
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + 'm ' + (seconds % 60) + 's';
    var hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + 'h ' + (minutes % 60) + 'm';
    return Math.floor(hours / 24) + 'd ' + (hours % 24) + 'h';
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
    var ms = parseTimeMs(value);
    if (ms === null) return 'n/a';
    var date = new Date(ms);
    function two(n) { return n < 10 ? '0' + n : String(n); }
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

  function forgetMessage(forget) {
    var state = text(object(forget).state);
    if (state === 'pending') return 'Forgetting this source device.';
    if (state === 'confirmed') return 'Forgotten. The source device removed this target device.';
    if (state === 'not_delivered') return 'The source device did not answer. This target device forgot the pairing, but the source device may still trust it.';
    return null;
  }

  function pingLine(status) {
    var data = object(status);
    if (data.running !== true || data.mode !== 'phone') return null;
    if (data.icmp_enabled === true) return 'Ping is on.';
    if (data.icmp_enabled === false) return 'Ping is off.';
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
    var message = text(data.last_stop_message);
    return message ? 'Last stop: ' + message : null;
  }

  function failureProto(group) {
    var value = text(object(group).proto).toLowerCase();
    return value === 'tcp' || value === 'udp' || value === 'dns' ? value : 'other';
  }

  function failureFamily(group) {
    var value = text(object(group).family).toLowerCase();
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
    var port = finite(object(group).port);
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
    return trimmed(object(group).name) || trimmed(object(group).example_ip) || 'an unknown address';
  }

  function orderedFailureGroups(groups) {
    return groups.slice().sort(function (left, right) {
      var leftCount = Math.max(finite(object(left).count) || 1, 1);
      var rightCount = Math.max(finite(object(right).count) || 1, 1);
      if (leftCount !== rightCount) return rightCount - leftCount;
      if (failureProto(left) !== failureProto(right)) return failureProto(left) < failureProto(right) ? -1 : 1;
      if (failureFamily(left) !== failureFamily(right)) return failureFamily(left) < failureFamily(right) ? -1 : 1;
      var leftReason = failureReason(object(left).reason).raw;
      var rightReason = failureReason(object(right).reason).raw;
      if (leftReason !== rightReason) return leftReason < rightReason ? -1 : 1;
      if (failurePhaseRank(object(left).phase) !== failurePhaseRank(object(right).phase)) {
        return failurePhaseRank(object(left).phase) - failurePhaseRank(object(right).phase);
      }
      var leftPort = finite(object(left).port);
      var rightPort = finite(object(right).port);
      if ((leftPort === null ? Number.MAX_SAFE_INTEGER : leftPort) !== (rightPort === null ? Number.MAX_SAFE_INTEGER : rightPort)) {
        return (leftPort === null ? Number.MAX_SAFE_INTEGER : leftPort) - (rightPort === null ? Number.MAX_SAFE_INTEGER : rightPort);
      }
      var leftName = failureTarget(left);
      var rightName = failureTarget(right);
      if (leftName !== rightName) return leftName < rightName ? -1 : 1;
      var leftIp = trimmed(object(left).example_ip) || '';
      var rightIp = trimmed(object(right).example_ip) || '';
      return leftIp < rightIp ? -1 : leftIp > rightIp ? 1 : 0;
    });
  }

  function failureRows(failures) {
    var groups = Array.isArray(object(failures).groups) ? object(failures).groups : [];
    return orderedFailureGroups(groups).map(function (group, index) {
      var count = Math.max(Math.round(finite(object(group).count) || 1), 1);
      var port = finite(object(group).port);
      var reason = failureReason(object(group).reason);
      var kind = failureKind(group);
      var family = failureFamily(group);
      var target = failureTarget(group);
      var phaseToken = failurePhase(object(group).phase);
      var detailParts = [];
      if (family === 'ipv4') detailParts.push('IPv4');
      if (family === 'ipv6') detailParts.push('IPv6');
      if (trimmed(object(group).name) && trimmed(object(group).example_ip)) detailParts.push(trimmed(object(group).example_ip));
      if (finite(object(group).code) !== null) detailParts.push('code ' + Math.round(finite(object(group).code)));
      var summary = count + ' ' + (count === 1 ? 'time' : 'times') + ': ' +
        (kind.id === 'dns' ? 'DNS lookup for ' : kind.word + ' to ') + target +
        (port === null ? '' : ' port ' + Math.round(port)) + ' ' + reason.phrase;
      var clause = failurePhaseClause(object(group).phase);
      if (clause) summary += ' ' + clause;
      return {
        id: index + '-' + [failureProto(group), family, port === null ? '' : port, reason.raw, phaseToken || '', trimmed(object(group).name) || '', trimmed(object(group).example_ip) || ''].join('|'),
        count: count,
        kind: kind.table,
        target: target,
        phase: failurePhaseLabel(object(group).phase),
        phaseToken: phaseToken,
        phaseWord: failurePhaseWord(object(group).phase),
        reason: reason.table,
        summary: summary,
        detail: detailParts.join(', ')
      };
    });
  }

  function failureReport(failures) {
    var data = object(failures);
    var groups = orderedFailureGroups(Array.isArray(data.groups) ? data.groups : []);
    var total = Math.max(Math.round(finite(data.total) || 0), 0);
    var dropped = Math.max(Math.round(finite(data.dropped) || 0), 0);
    var lines = [
      'HotspotShade simulated failure report',
      'Data: simulated by DemoBackend',
      'Total: ' + total + ' failed connection' + (total === 1 ? '' : 's') + ', ' + dropped + ' dropped.'
    ];
    groups.forEach(function (group) {
      var kind = failureKind(group);
      var reason = failureReason(object(group).reason);
      var parts = [
        Math.max(Math.round(finite(object(group).count) || 1), 1) + 'x',
        kind.table.toLowerCase(),
        failureFamily(group),
        finite(object(group).port) === null ? '-' : String(Math.round(finite(object(group).port))),
        reason.raw,
        failurePhaseWord(object(group).phase),
        trimmed(object(group).name) || '-',
        trimmed(object(group).example_ip) || '-'
      ];
      if (finite(object(group).code) !== null) parts.push('code ' + Math.round(finite(object(group).code)));
      lines.push(parts.join(' '));
    });
    return lines.join('\n');
  }

  function statusFreshness(failureSince, nowMs, hasStatus) {
    if (!hasStatus) return 'fresh';
    var since = finite(failureSince);
    var now = finite(nowMs);
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
    var freshness = input.freshness === 'stale' || input.freshness === 'unavailable'
      ? input.freshness
      : 'fresh';
    var busy = text(input.busy);
    var error = text(input.error);
    var pairState = text(pair.state);
    var running = hasStatus && status.running === true;
    var paired = hasStatus && status.paired === true;
    var phone = object(status.phone);
    var phoneState = text(phone.state) || 'unknown';
    var phoneMessage = text(phone.message);
    var forgetBlocked = input.forgetBlocked === true;
    var demo = hasStatus && status.demo === true;
    var checked = hasStatus ? checkedText(phone.checked_at, input.nowSeconds) : null;
    var unavailable = freshness === 'unavailable';
    var pairing = pairState === 'connecting' || pairState === 'confirm' || pairState === 'starting';
    var attention = [];

    var title = 'Starting HotspotShade';
    var subtitle = 'The app is reading the demo status.';
    var kind = 'busy';
    var primary = null;
    var secondary = null;

    if (!hasStatus) {
      if (error) {
        title = 'Needs attention';
        subtitle = error;
        kind = 'attention';
        primary = action('retry');
      }
      return result();
    }

    if (unavailable) {
      title = 'Status unavailable';
      subtitle = 'The engine did not answer.';
      kind = 'attention';
      primary = action('checkNow');
    } else if (busy) {
      if (busy === 'start') {
        title = 'Starting the tunnel';
        subtitle = 'This can take a minute.';
      } else if (busy === 'stop') {
        title = 'Turning off';
        subtitle = 'This can take a minute.';
      } else if (busy === 'pair') {
        title = 'Pairing';
        subtitle = 'Connecting to your source device.';
      } else if (busy === 'forget') {
        title = 'Forgetting this source device';
        subtitle = 'The request is in progress.';
      } else {
        title = 'Checking the source device';
        subtitle = 'The result updates when the check finishes.';
      }
      kind = 'busy';
    } else if (error) {
      title = 'Needs attention';
      subtitle = error;
      kind = 'attention';
      primary = action('retry');
    } else if (pairing) {
      title = 'Pairing';
      subtitle = 'Connecting to your source device.';
      kind = 'pairing';
    } else if (running) {
      title = 'On';
      subtitle = phoneMessage || 'The tunnel is on.';
      kind = 'on';
      primary = action('turnOff');
      if (forgetBlocked) {
        secondary = action('turnOffAndForget');
      } else if (freshness === 'stale') {
        secondary = action('checkNow');
      }
      if (phoneState === 'not_trusted') attention.push(NOT_TRUSTED_RUNNING);
    } else if (!paired) {
      var forgetText = forgetMessage(status.forget);
      var trusted = phone.trusted_by_source === true;
      title = 'Not paired';
      if (forgetText) subtitle = forgetText;
      else if (trusted) subtitle = 'The source device still knows this target device. Press Pair to continue.';
      else subtitle = 'Pair with your source device to use it.';
      kind = 'off';
      primary = action('pair');
      if (forgetBlocked) {
        secondary = action('turnOffAndForget');
      } else if (freshness === 'stale') {
        secondary = action('checkNow');
      }
    } else if (phoneState === 'not_trusted') {
      title = 'Not trusted';
      subtitle = phoneMessage || 'The source device does not know this target device.';
      kind = 'attention';
      primary = action('pairAgain');
    } else if (phoneState === 'ready' || phoneState === 'connected') {
      title = 'Ready';
      subtitle = phoneMessage || 'The source device is ready.';
      kind = 'off';
      primary = action('turnOn');
    } else if (phoneState === 'proxy_off') {
      title = 'Paired';
      subtitle = phoneMessage || 'Start the proxy on your source device.';
      kind = 'off';
    } else if (phoneState === 'not_running') {
      title = 'Waiting for your source device';
      subtitle = phoneMessage || 'Open HotspotShade on your source device.';
      kind = 'off';
    } else if (phoneState === 'no_hotspot') {
      title = 'Waiting for your source device';
      subtitle = phoneMessage || 'Connect this target device to the source device hotspot.';
      kind = 'off';
    } else if (phoneState === 'not_responding') {
      title = 'Waiting for your source device';
      subtitle = phoneMessage || 'Open HotspotShade on your source device and keep it open.';
      kind = 'off';
    } else {
      title = 'Status unavailable';
      subtitle = phoneMessage || 'The engine sent a status that this app does not know.';
      kind = 'attention';
    }

    if (paired && !running && !pairing && !secondary) {
      if (forgetBlocked) secondary = action('turnOffAndForget');
      else if (freshness === 'stale') secondary = action('checkNow');
      else secondary = action('forget');
    }

    if (forgetBlocked) attention.unshift(FORGET_BLOCKED);
    if (phone.port_changed === true) attention.push(PORT_CHANGED);
    if (freshness === 'stale') attention.push(STALE_TEXT);
    attention = unique(attention);

    if (secondary && forgetBlocked && freshness === 'stale') {
      secondary = action('turnOffAndForget');
    }

    function result() {
      var source;
      var connection;
      if (!hasStatus) {
        source = { value: 'Loading', details: ['Reading the demo backend.'] };
        connection = { value: 'Loading', details: ['Reading the demo backend.'] };
      } else if (unavailable) {
        source = { value: UNAVAILABLE_TEXT, details: ['Check the status again.'] };
        connection = { value: UNAVAILABLE_TEXT, details: ['Check the status again.'] };
      } else {
        source = sourceCard();
        connection = connectionCard();
      }
      return {
        kind: kind,
        title: title,
        subtitle: subtitle,
        primary: primary,
        secondary: secondary,
        attention: attention,
        source: source,
        connection: connection,
        checked: checked,
        demo: demo,
        stale: freshness === 'stale',
        unavailable: unavailable
      };
    }

    function sourceCard() {
      var value;
      var details = [];
      if (phoneState === 'not_trusted') {
        value = 'Not trusted';
        details.push('Pair again to restore trust.');
      } else if (paired) {
        value = 'Paired';
        if (phoneMessage) details.push(phoneMessage);
        else if (running) details.push('The tunnel uses this source device.');
        else details.push('The pairing is saved.');
      } else {
        value = 'Not paired';
        var forgetText = forgetMessage(status.forget);
        if (forgetText) details.push(forgetText);
        else if (phone.trusted_by_source === true) details.push('The source device still knows this target device. Press Pair to continue.');
        else details.push('Pair when you are ready.');
      }
      if (phone.port_changed === true && details.indexOf(PORT_CHANGED) === -1) {
        details.push(PORT_CHANGED);
      }
      return { value: value, details: unique(details) };
    }

    function connectionCard() {
      var value;
      if (busy === 'start') value = 'Starting';
      else if (busy === 'stop') value = 'Turning off';
      else if (running) value = 'Tunnel on';
      else value = 'Tunnel off';
      var details = [];
      var ping = pingLine(status);
      var connections = connectionsLine(status);
      var stop = lastStopLine(status);
      if (ping) details.push(ping);
      if (connections) details.push(connections);
      if (stop) details.push(stop);
      if (!details.length) details.push(running ? 'The tunnel is ready.' : 'No connection yet.');
      return { value: value, details: details };
    }

    function unique(items) {
      var seen = {};
      return items.filter(function (item) {
        if (!item || seen[item]) return false;
        seen[item] = true;
        return true;
      });
    }

    return result();
  }

  function pairingView(pair, busy) {
    var data = object(pair);
    var state = text(data.state);
    var active = state === 'connecting' || state === 'confirm' || state === 'starting';
    var code = text(data.code);
    var message;
    if (state === 'connecting' || state === 'starting') {
      message = 'Connecting to your source device.';
    } else if (state === 'confirm') {
      message = 'Check that both screens show the same code.';
    } else if (state === 'paired') {
      message = 'The pairing is saved.';
    } else if (state === 'failed') {
      message = text(data.error) || 'The pairing failed. Try again.';
    } else {
      message = 'Pair when you are ready.';
    }
    return {
      active: active,
      state: state || 'idle',
      code: code || null,
      message: message,
      busy: busy === 'pair'
    };
  }

  return {
    DEMO_TITLE: DEMO_TITLE,
    DEMO_BANNER: DEMO_BANNER,
    STALE_TEXT: STALE_TEXT,
    FORGET_BLOCKED: FORGET_BLOCKED,
    NOT_TRUSTED_RUNNING: NOT_TRUSTED_RUNNING,
    formatInt: formatInt,
    formatBytes: formatBytes,
    formatDuration: formatDuration,
    formatClock: formatClock,
    checkedText: checkedText,
    forgetMessage: forgetMessage,
    pingLine: pingLine,
    connectionsLine: connectionsLine,
    lastStopLine: lastStopLine,
    failureReason: failureReason,
    failurePhase: failurePhase,
    failurePhaseLabel: failurePhaseLabel,
    failurePhaseWord: failurePhaseWord,
    failurePhaseClause: failurePhaseClause,
    failureRows: failureRows,
    failureReport: failureReport,
    statusFreshness: statusFreshness,
    deriveDashboard: deriveDashboard,
    pairingView: pairingView
  };
});
