# Android background status availability

Status: implementation and tests under review. The responder has a status-only
policy and the host fences one run and one token epoch. Service lifecycle hooks
exist, but `BACKGROUND_STATUS_ENABLED` is false. The background listener is
not active in this build. The ownership and handoff sections below describe the
intended behavior if the gate is enabled after review and device testing.

## Problem

The target device probes TCP port 18090 on the source device gateway. Protocol
v1 has one port for pairing, status, and presence. It has no separate health
message.

The Android activity currently stops the pairing listener in `onStop`. While
the source proxy foreground service keeps running, the target device then gets
a refused connection on port 18090. The target maps a refusal to `not_running`.
After 90 seconds of continuous source device silence it stops the tunnel with
`source_device_gone`.

That result is wrong. The source proxy is still serving traffic. The target
needs an authenticated status answer while the source app is in the background.

## Goal and non-goals

Goal:

- Keep the authenticated status channel on the live hotspot address and port
  18090 while the source proxy runs in its foreground service and the activity
  is not visible.
- Use the same trust store, responder state machine, status payload, and socket
  rules as the visible pairing listener.
- Answer only a status request from a target key that this app already trusts
  in the current process.
- Do not pair, re-pair, or forget in the background. Do not show a prompt, post
  a pairing notification, add trust, remove trust, or disclose the token.

Non-goals:

- No background pairing approval flow.
- No second status port, plaintext heartbeat, or external relay.
- No change to protocol v1 and no target-side change.
- No autonomous proxy restart and no persistent tunnel.
- No route, TUN device, or interface change.
- No bypass of the existing in-process trust confirmation rule.

## Ownership and handoff

One process-wide rule: exactly one listener may bind port 18090, and it always
binds only the controller's live hotspot address.

| Condition | Port 18090 owner |
|---|---|
| Activity visible | Existing `PairingCoordinator` and `PairingServer` |
| Activity not visible and a proxy run is live | New `BackgroundStatusHost` |
| Activity not visible and no proxy run is live | Nobody |

The new host is
`android/app/src/main/java/com/hotspotshade/source/BackgroundStatusHost.kt`.

It polls every 500 ms. Each tick:

1. Read the process visibility. A foreground activity means the host closes
   its listener and leaves the port to the activity.
2. Read `SourceProxyRuntime.binding()` and the token epoch.
3. Require a live run (`RUNNING` or `WAITING_FOR_NETWORK`), a bound IPv4
   hotspot address, and a usable proxy port other than 18090.
4. Keep a live listener only when the address, the proxy port, the run
   identity, and the token epoch all match the values that created it. The
   proxy run refuses a token rotation, so a live listener does not need a
   Keystore read on every poll.
5. If the address, port, run identity, or token epoch changed, or the listener
   stopped, close the old listener and load the stored token for the new one.
   A missing, unreadable, or unusable token opens nothing. The load must return
   while the epoch is still the one that the tick observed.
6. Bind `PairingServer` on that exact address and port 18090. A bind failure is
   retried on the next tick.

The host never calls the hotspot finder itself. The controller binding is the
only address source, so a stopped or moved hotspot closes the listener. The
host never writes a route or creates a device.

### Run identity and token epoch

`SourceProxyBinding.runId` names one controller run for the life of the app
process. A new controller gets a new value, even when it binds the same address
and port. A live report that no controller owns takes its own value. The host
stores the run identity and token epoch with the listener.

Every credential and status build rechecks all three values:

- the run identity still matches the listener;
- the live address and port still match the credentials;
- the token epoch still matches the epoch that loaded the token.

A mismatch returns no credentials and no status, so the responder sends a
fixed rejection. The next tick closes the listener. A stop and a restart
between two ticks therefore cannot answer from the old listener, and a
rotation cannot keep serving the old token.

The epoch is process-local. A write that bypasses `SourceTokenGuard` does not
move it. The token store, the proxy, and the pairing admin must keep using the
guard for this fence to hold.

### Activity visible to background

`MainActivity.onStop` still stops `PairingViewModel` and its listener. Within
one 500 ms tick the host sees that the process is no longer foreground and the
controller binding is still live. It binds port 18090. If the old listener is
still closing, the bind fails and the next tick retries.

The target probes every 2 seconds and keeps a fresh probe for 10 seconds. The
short handoff fits well inside the 90 second stop limit.

### Background to activity visible

The host sees the foreground activity within one 500 ms tick and closes its
listener. `PairingViewModel.start()` starts the normal listener again. The
pairing coordinator already retries a failed bind every 3 seconds. A bind that
loses this short race is retried with no change to its logic.

### Proxy stop or hotspot loss

The controller sets its binding inactive before the service finishes. The host
closes the listener within one tick. The target then sees a refused connection.
That is correct: there is no proxy to report as ready. The target's normal
90 second rule may stop its tunnel, which is the intended no-persistent-proxy
behavior.

A hotspot loss makes the controller stop the run. The host follows the binding,
so it never keeps listening on an address that is no longer the hotspot.

## Authentication and status behavior

The host constructs the same `PairingResponder` and `PairingServer` classes as
the visible listener, with `PairingResponderMode.STATUS_ONLY`. All of these
stay in place:

- the target must prove its X25519 key;
- the target key must be in the trust store;
- the status request and answer use the v1 sealed exchange;
- the status payload names only the live bound address and port;
- connection limits, idle timeouts, challenge budgets, and invalid-message
  budgets are unchanged;
- the host loads the stored token when it tries to create a listener, holds it
  only while that listener is open, and clears its own reference on close. It
  does not read the Keystore on every poll.

A status-only HELLO from an unknown target key is rejected before a challenge.
A known target key with the status flag gets the normal authenticated status
answer. The answer has `proxy_running = true`, the current connection count,
the live port, and the live hotspot host.

### Status-only responder policy

`PairingResponderMode.STATUS_ONLY` is an explicit policy in the responder, not a
host convention. At the HELLO it rejects every flag value except the status
flag. That covers a pairing request (flag 0), a known-target re-pair (flag 0
with a trusted key), Forget (flag 2), and any malformed flag. The rejection
runs before trust is read for the request, before a challenge charge, before an
ephemeral secret exists, before a credential callback can run, and before a
prompt can be created. A rejected request cannot add or remove trust.

The responder repeats the policy at the REVEAL and authenticated-command
boundaries, and the success path refuses to seal credentials in status-only
mode. Those checks are defense in depth. The visible listener keeps
`PairingResponderMode.FULL` and its v1 behavior unchanged.

There is no UI in the background. The host still passes a prompt callback that
denies any prompt at once. It does not display a code, post a notification, or
add trust. The notification path in `PairingViewModel` is not used. In the
status-only policy a prompt should not exist at all, so the callback is only a
second fail-closed layer.

## Transport v1 limits to respect

These are not optional details. They decide whether the fix is safe.

- The target only probes port 18090. Do not add a second port or a new
  discovery path.
- A refused connection maps to `not_running`. Continuous refusal or silence
  for 90 seconds stops the target tunnel.
- A plaintext `Busy`, `NotActive`, `Rejected`, or similar answer is unverified.
  It is not presence and does not reset the silence timer. Do not add a
  plaintext keepalive as a fallback.
- Only an authenticated status answer resets the target's presence timer.
- The target does not authenticate the source device's static identity in v1.
  The status exchange is encrypted and integrity-protected for the session, but
  a peer at the gateway can complete its own handshake. This host does not
  worsen that existing limit and must not claim to fix it.
- A stored target key is pending confirmation after a process restart. The
  trust store does not report it as active until the person confirms it in the
  current process. Do not bypass this to make background status work.
- If the host cannot bind, cannot load the token, or has no active trust, the
  target eventually stops. That is the correct fail-closed result. There is no
  unsafe fallback.

## Integration

The service integration already exists behind
`SourceProxyServiceLifecycle.BACKGROUND_STATUS_ENABLED`. The service creates the
host in `onCreate`, starts it for a run request, stops it on every terminal
report and in `onDestroy`, and restarts it for a new run. Keep that gate closed
until the service owner reviews the status-only responder policy, the run
identity fence, and the token epoch fence. The host has no separate service
setting to enable.

The host is safe to start before the controller has bound. It opens nothing
until the binding is live. `SourceProxyService.onDestroy` is the required stop
point because it runs on normal stop, automatic stop, and service destruction.
A skipped `onDestroy` (process kill) closes the sockets with the process.

The activity keeps its current `onStart` and `onStop` calls. `MainActivity` is
not the owner of the background listener.

If the service owner prefers an explicit activity callback instead of the
process-importance check, pass a different `visible` lambda to
`BackgroundStatusHost`. The port handoff and security rules are the same. The
process-importance check is used here so the service can integrate without an
edit to the UI lifecycle.

## Tests

`android/app/src/test/java/com/hotspotshade/source/BackgroundStatusHostTest.kt`
holds these deterministic host tests with a fake listener:

- a visible process does not bind;
- the listener closes when the activity returns;
- an idle or stopped run opens nothing;
- a waiting run keeps the listener;
- a stopped run closes the listener;
- a changed hotspot address rebinds;
- a changed run identity rebinds at the same address and port;
- a changed token epoch rebinds and reloads the token;
- a live listener does not reload the token every tick;
- a missing token after a stopped run does not open;
- a failed bind is retried;
- a prompt is denied without display or notification;
- stop is idempotent and does not restart.

`android/app/src/test/java/com/hotspotshade/source/BackgroundStatusHostWiringTest.kt`
drives the real `PairingServer` and `PairingResponder` behind the host over
loopback:

- a trusted target gets an authenticated status answer;
- a trusted re-pair is rejected without a token or trust write;
- a trusted Forget is rejected without a trust mutation;
- unknown pairing and status requests are rejected with no prompt and no
  trust write;
- a changed run identity rejects on the old listener before the next tick;
- a changed token epoch rejects on the old listener and reloads the new token;
- a stopped run rejects an authenticated status before the tick closes the
  listener;
- stop closes a real listener and leaves it closed.

`BackgroundStatusRunIdentityTest` covers the process runtime fence: a live report
gets a nonzero identity, a new live run gets a different value at the same
address and port, repeated reports keep one value, and a stopped report has no
identity.

`PairingResponderTest` also covers the status-only HELLO gate directly: known
re-pair, known Forget, unknown pairing, unknown status, and the unchanged full
mode behavior. The existing `PairingServerTest` and pairing parity tests
continue to cover the wire exchange, trust checks, budgets, and status payload.

No test in this change creates a route, a TUN device, or a real hotspot. All
sockets are loopback sockets. The tests do not prove carrier, hotspot, OEM
background, or physical-device behavior.

Follow-up tests that are still needed:

- emulator test: start the real service, approve one target, move the activity
  to the background, run the Rust target probe against the current binding, and
  confirm `ready` or `connected` with a fresh `checked_at`;
- emulator test: background the app, attempt an unknown pairing, and confirm no
  prompt, no notification, no trust entry, and a rejection;
- emulator test: background the app, attempt a known re-pair and Forget, and
  confirm both are rejected with no trust change;
- emulator test: stop the proxy and confirm the status listener is gone;
- real phone test: foreground service through screen lock and a real hotspot
  loss, including OEM background limits.

The emulator and JVM tests do not prove carrier, hotspot, or real OEM behavior.

## Residual v1 and process trust limits

These limits remain. Do not describe the background listener as stronger than
the visible listener.

- Protocol v1 does not authenticate the source device's static identity. The
  status exchange is encrypted and integrity-protected for the session, but a
  peer at the gateway can complete its own handshake. This change does not fix
  that.
- The trust store still requires in-process confirmation after a process
  restart. A stored key is not active until the person confirms it in the
  current process. The background listener does not bypass that rule.
- The token epoch is process-local and only moves when the code uses
  `SourceTokenGuard`. A write that bypasses the guard is not fenced.
- The run identity is process-local. It is not a device attestation and it does
  not identify a different process that shares the same hotspot address.
- The trust store and token store are in-process APIs. Code already running in
  this app process can inspect them directly. The listener is not a security
  boundary against a compromised process, root, or a debugger.
- Android may stop the foreground service under memory pressure or OEM policy.
  The target then stops after its normal silence limit. Do not add an
  auto-restart or a keep-alive workaround in this change.
- The process-importance check is a heuristic. An explicit lifecycle callback
  is clearer if a service or UI owner can provide one.
- A JVM loopback pass does not prove the phone network stack, a real hotspot,
  carrier behavior, or OEM background limits.

## Rollout and open decisions

- The service integration stays behind
  `SourceProxyServiceLifecycle.BACKGROUND_STATUS_ENABLED`. The service owner
  gates it after review. Until then the target still sees the old behavior
  after `onStop`.
- `PairingServer.kt` and `PairingCoordinator.kt` are owned by another active
  change. The background host consumes their interfaces and does not edit them.
- The service owner may pass an explicit lifecycle callback instead of the
  process-importance check. That changes the visibility source only, not the
  status-only policy or the run and token fences.
