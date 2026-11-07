# Android start during a pending tethering reading

Status: implemented. `SourceProxyController` runs the first hotspot probe and
the session setup on one background task queue. It waits for a pending reading
with the same bound as the evidence, and it never holds the controller lock
across a probe or a wait.

## Problem

On Android 16 (API 36) or later the hotspot finder reads the public tethering
callback. A successful registration can start in
`TetheredInterfaceState.AwaitingFirstReading` before the platform delivers the
current set. While that state lasts the finder returns `HotspotProbe.Pending`
and never guesses a name. That part is correct: a pending reading must not bind
an unconfirmed interface.

The earlier `SourceProxyController.start()` called `findHotspotAddress()` once,
and `openSession()` called it again after the cellular network arrives. Both
calls mapped `Pending` to `null`. `start()` turned that null into
`SourceProxyStopReason.HOTSPOT_NOT_FOUND` and stopped the run. The person then
saw "Hotspot not found" and was told to turn on the hotspot, even when the
hotspot was on and the platform was about to deliver a valid set. The same
false start could happen after a failed registration was retried and the retry
succeeded but the callback was slow.

The evidence now bounds the pending state at
`TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS` (3 seconds). That
shortens the window but does not remove it. A start inside the window still
reports the wrong reason.

## Required behavior

1. A pending probe never binds an interface. No name rule runs while the
   evidence reports `AwaitingFirstReading`.
2. A start that sees `Pending` waits a bounded time for a real reading. The
   bound is the shorter of the caller's deadline and the evidence pending
   timeout, with a small poll interval. Do not wait forever, and do not treat
   the wait as a hotspot loss.
3. The wait never runs on the main thread and never holds the controller lock.
   A probe reads platform state, so the wait belongs on the controller queue.
4. The wait ends at once on user stop, service destroy, controller terminal
   state, or a stop reason that already ended the run. A late result must not
   bind after a stop.
5. A second start during the wait is refused. It must not create a second
   listener, a second watch, or a second run lease.
6. At the deadline with no reading, report `HOTSPOT_NOT_FOUND` once. Do not
   report `HOTSPOT_LOST`, because no run was bound.
7. An `Observed` probe with a confirmed candidate continues the normal start
   path. An `Observed` probe with no candidate, or `Unknown`, takes the normal
   not-found path. A late callback after the terminal state changes nothing.

## Implementation

`SourceProxyController` keeps the existing state machine and adds one internal
`starting` flag. The public state stays `IDLE` during the bounded wait, so the
app keeps showing the existing `STARTING` phase from its start-pending flag.

1. `start()` checks the token and takes the run lease as before. It does not
   call `findHotspotAddress()`. It marks the start in progress under the lock,
   creates one `SourceProxyTaskQueue`, and submits one bounded wait to it. The
   production queue is one daemon thread per controller.
2. The wait loops with a 250 ms poll until the probe is not `Pending`, the
   monotonic deadline passes, or a stop, terminal state, or newer attempt ends
   the run. The deadline is `DEFAULT_PENDING_WAIT_MILLIS`, which aliases
   `TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS` so the two bounds
   stay aligned.
3. On a confirmed address, the same task publishes `WAITING_FOR_NETWORK` and
   starts the existing monitor. On the deadline with no reading it reports
   `HOTSPOT_NOT_FOUND` once, releases the run lease, and binds nothing. An
   `Observed` probe with no confirmed candidate, or `Unknown`, takes the same
   not-found path at once.
4. `openSession()` creates the cellular session at once and submits its hotspot
   wait and listener setup to the same queue. It therefore never blocks the
   network monitor thread for the bound. A stop is handled by the attempt
   number under the lock. The session setup rechecks the attempt after every
   factory step and before it binds a listener, so a late result closes its new
   resources instead of publishing them.
5. `finish()` clears `starting`, moves the attempt, shuts the queue down, and
   drops queued work before it closes the monitor, server, and watch. A wait
   that has not started is dropped, and a sleeping wait is interrupted. The
   controller cannot publish a listener after a stop.
6. The run lease stays held until the last in-flight task returns. A task that
   is already inside `serverFactory`, `newServer.start()`, or `watchFactory`
   may still own a listener when the stop arrives. `finish()` transfers the
   lease to that task instead of releasing it under the worker, so a token
   rotation cannot replace the token while a late listener is still bound. The
   task closes its listener and then releases the lease. The stop never waits
   for the worker under the controller lock.
7. A shutdown that runs on the worker thread does not interrupt that thread.
   The cleanup that follows the stop uses the same thread. A shutdown from
   another thread still interrupts a sleeping wait.

## Tests

`SourceProxyControllerTest` covers the race cases with a manual task queue and
a fake monotonic clock. The in-flight close and queue tests use real daemon
threads and latches. No hotspot, device, adapter, or route is used.

- A finder that returns `Pending` twice and then `Observed` starts normally.
  The expected bound address is used, and no `HOTSPOT_NOT_FOUND` is reported.
- A finder that stays `Pending` until the deadline reports one
  `HOTSPOT_NOT_FOUND`, binds nothing, does not guess a candidate, and ignores a
  late observed reading.
- A user stop during the wait reports `USER_STOP`, binds nothing, and shuts the
  queue down.
- A second start during the wait returns false and creates no second run.
- Repeated network availability creates no second listener.
- A token rotation is refused during the pending wait and succeeds after the
  deadline releases the run lease.
- A pending `openSession()` that becomes observed starts the listener without a
  terminal `HOTSPOT_NOT_FOUND`.
- A pending `openSession()` that reaches its deadline stops with
  `HOTSPOT_NOT_FOUND` once and closes the cellular session.
- A user stop during the pending `openSession()` wait reports `USER_STOP`,
  closes the cellular session, and shuts the queue down.
- A user stop during session setup stops before the listener is constructed, so
  no server or watch is created and the session is closed.
- A real thread blocks inside `newServer.start()` while another thread stops
  the controller. The stop returns without waiting, the run lease is still
  held, and the worker closes the late listener before the lease is released.
- A real thread blocks inside `watchFactory` after the listener is bound. The
  same lease and close checks hold for that step.
- The production queue shuts itself down on its own worker without interrupting
  that worker, and a shutdown from another thread still interrupts a bounded
  wait.
- The controller and `TetheredInterfaceEvidence` share one fake monotonic clock.
  The controller does not report not found until the evidence is unavailable at
  the same 3 second bound.
- `SourceProxyRuntime.requestStart()` keeps a live report for an attached
  active controller, and the service records the controller snapshot again for
  a repeated start request.

## Limitations

The controller aliases the evidence bound, so the two stay aligned when either
changes. A slow OEM binder can still miss the bound; the run then reports not
found and the person can start again. That is bounded and visible, which is
safer than binding an interface that the platform never named.

The public state stays `IDLE` during the bounded wait. It does not publish an
intermediate state, because `IDLE` is the state that means no run has bound
anything. A UI that reads only the controller state, without a separate
start-pending flag, shows the off state for up to the bound. The app shows
`STARTING` from its view-model start-pending flag in the normal case. The
foreground notification uses its waiting text during this short window and
never reports a hotspot loss.

The hotspot watch has a separate bound. A pending probe is uncertain, and four
consecutive pending probes count as one uncertain miss. A bound run therefore
cannot stay blind while the tethering callback is stuck. The start path has no
bound run, so it uses the bounded wait in this note and reports
`HOTSPOT_NOT_FOUND`, not `HOTSPOT_LOST`.

A new start request that arrives while the previous controller is still closing
a late listener is refused with `START_FAILED`, because the token lease is not
free yet. The person can start again after the close finishes. The controller
never queues or retries that request on its own. A factory call that never
returns keeps the lease, and so blocks a rotation, until it returns; the stop
itself still returns without waiting for it.

The app no longer stays on `STARTING` when a repeated start finds an active
controller. The runtime keeps the live report, and the service records the
controller snapshot again. These are JVM tests for the status path; they do not
start the Android service or prove device behavior.
