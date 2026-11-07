# HotspotShade for iOS

HotspotShade on the source device accepts SOCKS5 TCP CONNECT requests. It requires username and password authentication. It creates one cellular connection for each accepted flow. It does not provide BIND or UDP ASSOCIATE.

The app picks a proxy port from 20000 to 59999 and saves it. The pairing channel sends the port and the token to a paired target device. You can choose a port in Settings, Advanced.

The source device provides the connection. A target device is any device that needs internet access. This README uses these two terms.

## Internal names

The product name is HotspotShade. Some internal identifiers keep the old name: the bundle identifier `local.hotspotproxy.app`, the Xcode target and scheme `HotspotProxy`, the folder `ios/HotspotProxy/`, the executable name `HotspotProxy`, and the app bundle `HotspotProxy.app` inside the IPA. The display name comes from `Info.plist` and is HotspotShade. The identifiers stay so that an update keeps the stored pairing trust and token. A new bundle identifier installs as a new app. The new app has no stored trust and no stored token.

## Run on a source device

1. Install Xcode with an iOS SDK. Open Xcode and accept its license and component prompts.
2. Open `ios/HotspotProxy.xcodeproj` in Xcode.
3. In Xcode settings, add your Apple ID under Accounts. A free Apple ID can use a Personal Team.
4. Select the HotspotProxy target. Open Signing & Capabilities. Select your team and enable automatic signing. Change the bundle identifier to a unique value if signing requires it.
5. Connect the source device to the build machine with a cable. Unlock it and trust the build machine when prompted. Enable Developer Mode on the source device if Xcode requests it. Follow the device prompts and restart if required.
6. Select the source device as the run destination. Choose the Release build configuration (Product > Scheme > Edit Scheme, then Run > Info > Build Configuration), then click Run. A Debug build is for the Simulator or the host harness. Trust the developer certificate on the source device if iOS requests it.
7. Enable cellular data and Personal Hotspot on the source device. Connect the target device to the hotspot. Open HotspotShade on the source device.
8. Tap Start. Allow Local Network access if iOS asks. Allow Location when iOS asks, so the app can stay awake.
9. On the target device, pair HotspotShade with this app. See "Pair with a target device" below. For other SOCKS5 clients, open Settings, then Manual connection. It shows the SOCKS5 username, the hotspot address, and the proxy port. Tap Copy connection details to copy those three values; the copy holds no token. Set the password to the source token: open Advanced, tap Show token, and read it. The token hides again after 30 seconds. Enable remote DNS or use a `socks5h` proxy URL. The app does not need a paired target device for this path.

10. Keep the app open in the foreground and keep the screen on, or turn on "Help keep running in the background" below. Tap Stop when finished.

A free Personal Team has provisioning and device limits. Its development provisioning profile expires after seven days, so you may need to build and install the app again. Apple can change these limits.

The app looks for exactly one active, non-loopback bridge with IPv4 address `172.20.10.1` and netmask `255.255.255.240`, and binds the listener to that address. The bridge name need not be `bridge100`. Discovery keeps the interface name with the address, because a replacement bridge can reuse the same address. A running proxy or pairing listener stops when a complete check names a different interface at the same address. Enable Personal Hotspot and connect the target device before starting the proxy. If the observation is missing, unsupported, unreadable, or ambiguous, startup fails. Start says which one it saw: a missing hotspot asks for Personal Hotspot, an unsupported link names the link, an unreadable list says the app cannot read the network interfaces, and an ambiguous result says the app found two possible hotspot links and cannot tell which one is the hotspot. Apple does not provide a public API that identifies this link as Personal Hotspot, so the bridge and address are compatibility evidence, not proof. This check passed on one physical iPhone on 2026-11-06 (see "Physical device release check"); its behavior across iOS versions and devices remains under review. Configurations using a different address or prefix are not supported. A port conflict also appears in the Dashboard. Choose another port if it is in use.

The listener reports Listening only after it reports `.ready`. While it reports `.waiting`, the app shows Starting and does not claim that it listens. One waiting episode has a 10 second bound. If it is still waiting when the bound is checked, the run ends with a plain message, and the app does not start a replacement listener. A ready state observed at that check wins, even if the bound passed while the app was suspended. When the app becomes active, it reads the listener state once: a ready, failed, or cancelled event that arrived with no callback is applied, and an active wait keeps its remaining bound. An intentional stop is not changed. See `ios/tests/ProxyListenerLifecycleTests.swift` for the fake-listener checks.

## Simulator test override

For a simulator UI smoke test that uses Keychain, build with simulator code
signing enabled. For example, use `xcodebuild` with
`-scheme HotspotProxy -configuration Debug -sdk iphonesimulator` and
`CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=-`. This produces an ad hoc signed
simulator app and needs no developer certificate. The CI simulator compile uses
`CODE_SIGNING_ALLOWED=NO`; that compile checks the build but is not a Keychain
runtime test. On iOS 27.2 Simulator, a linker-signed build with signing disabled
returned Keychain error `-34018` before token loading. Do not clear Keychain or
replace a token to resolve a signing error. Preserve an existing installation
and use a separate bundle identifier for an isolated smoke test.

On 2026-11-06 an ad hoc signed Debug build with a separate bundle identifier
opened on the iPhone 18 Pro iOS 27.2 Simulator. The Dashboard showed Off and
Settings showed no paired target devices. The isolated test app was then
uninstalled. This was a UI startup smoke check; it did not verify Keychain
durability, proxy traffic, pairing, a hotspot, or a physical device.

A Debug build can use a different hotspot interface and address. The app can then run in the iOS Simulator against a mimicked hotspot subnet.

Set two UserDefaults keys:

- `debug.hotspotInterface`: the interface name. It must match `[a-z]{1,8}[0-9]{0,3}`.
- `debug.hotspotAddress`: an IPv4 address in 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16. The address 172.20.10.1 is valid only with a `bridgeN` interface name.

The loopback pair `lo0` with `127.0.0.1` is also valid. It lets a test on the same Mac reach the listener without a mimicked hotspot interface. It never reaches another device.

Both keys must hold a valid value. If one key is missing or invalid, the app uses the normal bridge discovery. A Release build ignores both keys.

A Debug Simulator build can also replace the cellular pin with the host network path. Set `debug.mockCellularPath` to `YES` and set the hotspot override. The mocked path needs both keys, and it exists only in a Debug build for the Simulator. The key alone does nothing. A Release build, a device build, and a normal Debug run keep the cellular pin.

In Xcode, add launch arguments to the scheme:

```
-debug.hotspotInterface lo0 -debug.hotspotAddress 127.0.0.1 -debug.mockCellularPath YES
```

Or use `en0` and a private address from the list above for a mimicked hotspot. Do not set `debug.hotspotInterface` or `debug.hotspotAddress` on a device. Use a Release build on a phone; these overrides are for a Simulator or the host harness.

The Xcode Debug configuration defines the `DEBUG` compilation condition. A Release build holds no code from the override section.

`scripts/ios_source_proxy_flow_test.sh` compiles the same proxy sources on the build Mac and runs the real Rust target client through loopback TCP, a `localhost` domain target, and two UDP datagrams, plus a wrong-token check and a refused destination. It also checks that the pairing listener admits the real check while four silent sockets are held and closes a silent socket after 10 seconds. The script needs port 18090 free, sets no route, and creates no interface. It does not prove the Simulator network stack, carrier behavior, or a physical hotspot.

On 2026-11-06 the expanded test also passed against the isolated Debug app on
the iPhone 18 Pro Simulator with the loopback overrides: TCP, domain TCP, and
UDP completed and the client reported `audit=(7, 0)`. The proxy was stopped,
the test app was uninstalled, and port 18090 was free afterward. This does not
verify a physical hotspot or cellular path.

On 2026-11-06 a separately identified, ad hoc signed Debug app ran on the
iPhone 18 Pro iOS 27.2 Simulator with the loopback and mock-cellular overrides.
The real Rust client paired with the app after the simulator prompt was
approved, sent traffic through its proxy to a loopback echo server, and
checked wrong-token and refused-destination behavior. The client reported
`IOS_SIM_PROXY_OK audit=(5, 0)`. A separate silent pairing socket closed after
about 10.7 seconds. The app's proxy was stopped and the isolated app was
uninstalled afterward. The simulator executable SHA-256 was
`beecaf0c35e335a4a9a6c55fcdd9ca7b9a13fc24067ae8f10c6f65a9f4c7ecfd`;
the non-ignored iOS file manifest before and after the run was
`b07c743ad58e3ce14384a044afd2a8561d4145f906e0e4c8769827752187e46c`.
The first attempt exposed a test assumption: an evicted silent socket can
close with a reset instead of EOF. The test now accepts either closure. This
was a dirty working-tree build, not complete build provenance. The override
does not verify physical hotspot discovery, cellular binding, or carrier
behavior.

After the manual-connection screen was added, a fresh ad hoc Debug build was
tested on the same simulator with the loopback overrides. The real Rust client
paired after the matching code was approved and passed the proxy traffic,
wrong-token, refused-destination, and silent-listener checks: two tests passed
with `IOS_SIM_PROXY_OK audit=(5, 0)`. The simulator proxy was stopped, the
separately identified test app was removed, and port 18090 was free afterward.
The simulator executable SHA-256 was
`963aca2f946da4b7912642dd0a8cef6bb53af2f1ecea609b4e757e29e24c51eb`.
This was a working-tree build and does not verify a physical hotspot or carrier.

## Physical device release check

On 2026-11-06 the signed 0.1.0 (1) release candidate ran on a physical iPhone.
Its proxy started, and the hotspot check accepted the real Personal Hotspot
bridge at `172.20.10.1/28`. No tunnel test has run with this build yet, so this
result covers app launch and hotspot discovery only. It does not prove relay
traffic, cellular binding, carrier behavior, or throughput.

## Manual connection

Settings has a "Manual connection" section for a SOCKS5 client that does not use pairing. It shows the SOCKS5 username `hotspotshade`, the hotspot address, and the proxy port. "Copy connection details" copies those three values. The copied text holds no token.

The password is the source token. It is in Settings, Advanced, behind Show token. The token hides again after 30 seconds. Use remote DNS, for example a `socks5h` proxy URL, so names resolve on the source device. A client that resolves a name itself sends that lookup outside the proxy.

The port is the saved proxy port. Start the proxy before another device connects. The section says when the address is missing, when the port is not valid, and when the proxy is stopped. It never claims that a connection works while the proxy is off.

## Pair with a target device

HotspotShade on a target device can get the proxy port and token from this app. You do not need to copy the token.

1. Open the app on the source device. Turn on the hotspot.
2. On the target device, start pairing in HotspotShade.
3. The app shows "Allow this target device?" with a six-digit code.
   The code does not provide a complete defense against an active attacker on
   the hotspot. The app limits unknown pairing challenges while it runs.
4. Check that the target device shows the same code. Tap Allow. Tap Deny if the codes differ or if you did not start the pairing.

The pairing listener uses TCP port 18090 and binds to the hotspot address only. It runs while the app is open and the hotspot interface is present. It runs when the proxy is stopped. The app checks the hotspot every 5 seconds while the proxy is stopped and every 2 seconds while the proxy runs. It does not poll the hotspot while the app is in the background. The listener stops after observed absence for 75 seconds while the proxy is stopped or 30 seconds while it runs. An unreadable check, a long gap between checks, or a change in scene activity resets the observation period. A complete check that names a different interface at the same address is a link change, so the listener stops at once, closes its open pairing sockets, and does not treat the old link as still present. A hotspot address on a link type this build does not support also stops it. The next complete check may bind a new listener. The interface name is one local record. It does not prove that Personal Hotspot is on, and two links that reuse the same name and address cannot be told apart. A starting or waiting pairing listener gets 5 seconds to become ready while the app is active. A temporary wait does not immediately cancel the listener or its pairing sessions. If the wait continues, the app closes the listener and retries after at least 10 seconds. A bind failure appears in Recent activity, and the Dashboard pairing line and Settings row show that pairing is not available. That line clears when the hotspot has been absent or changed for the same observation period, or when pairing is suspended, so a hotspot that is simply off does not blame the pairing port.

Network.framework binds a listener to an address, not an interface name. It has no public initializer that turns an interface name into `NWInterface`, so the app cannot set `requiredInterface` from the discovered name. It checks the interface identity separately and stops the listener when the identity changes.

The listener accepts at most 4 pairing sockets. A socket that sends no complete frame within 10 seconds is closed. When a new target device connects and every socket is in use, the app closes the oldest socket that has not sent a complete frame. It never closes the socket that owns the prompt the person is looking at. A socket that sent a complete frame is a pairing session, so the pairing state machine owns its deadline. That keeps the 120 second background prompt extension from being cut short by a separate socket timer. A final reply send has its own 5 second bound, so a stuck send cannot hold a slot after the state machine removed the session.

iOS can stop the pairing listener while the app is suspended and send no error. When the app returns to the foreground and the hotspot is present, the app replaces a listener that is not ready. The app shows the prompt only while it is in the foreground. A pending decision gets 120 seconds when the app goes to the background. The pairing request expires if you do not answer in time. After 3 denied or failed pairings within 60 seconds, the app refuses pairings for 30 seconds.

Settings, Paired target devices, lists each trusted target device. A paired target device gets the port and token without a prompt. The app stores only their public keys, as base64 strings in UserDefaults. Each row shows a short label: "Target device" and the first four bytes of the SHA-256 digest of the stored public key, as eight lowercase hex digits. The label does not show the key. It is the same label that the Android app shows for the same key. Two keys can share a label with a low probability, so Forget acts on the full key and never on the label. Each row has a Forget button. Its accessibility label is "Forget" and the row label. It asks for confirmation first, then removes only that key. "Forget all target devices" asks for confirmation and removes every entry. With no saved target device, Settings says "No target devices are saved" and explains how to pair, and shows no Forget all button. It also says the pairing listener runs only while the app is open, Personal Hotspot is on, and the app has a saved token. It leaves that sentence out while the pairing unavailable line is showing. The Forget confirmation for one target device says that, if the target device has the saved token, it can still connect with it. All Settings confirmations (forget one, forget all, and the gated token actions) share one dialog, so only one can be open at a time. A stored entry that is not valid base64 can never match a key. It is not listed, but it counts and Forget all clears it. Forget, either kind, removes trust only. It does not revoke a saved token, and the token does not change. A power loss before the trust change is durable can restore a forgotten entry. Token rotation is disabled pending review, so this build has no reviewed revocation path. A forgotten target device must pair again; a target device that is still trusted can pair again without a prompt.

The pairing sends the token encrypted. The SOCKS5 control channel still sends the token in clear on the hotspot link. See "Pairing" in `PHONE_PROXY.md` for the protocol and the threat model.

### The one status display

The Dashboard and Settings read one state. The state has four values:

| State | Text | Meaning |
|---|---|---|
| Not paired | "Not paired. Open HotspotShade on your target device to pair." | No target device is paired. |
| Pairing | "Pairing in progress. Check the code on your target device." | A pairing code waits for your answer and the listener is ready. |
| Paired | "Paired with 1 target device." or "Paired with N target devices." | At least one target device is paired. None uses the proxy now. |
| In use | "A target device is using the proxy now." | An authenticated session had traffic in the last 60 seconds. |

The usage card title is "Target device connected" only in the in-use state. It is "Waiting for your target device." in the other states. Settings shows the pairing state while a pairing prompt is active. When no pairing is active and the trust list is empty, it says "No target devices are paired." The app has no separate ready state. A code without a ready listener is stale, so it does not claim that a pairing runs.

When the pairing listener cannot bind or become ready, the Dashboard pairing line and the Settings row say "Pairing is not available. Another app may be using the pairing port. HotspotShade tries again while it is open." A timeout, a denial, or a 30 second lockout leaves one plain line for 60 seconds or until the next pairing event. The line names no code, address, or device.

## Recent activity and the connection counters

Open "Recent activity" with the clock button. It shows plain events by default, for example "Proxy started.", "A target device was added.", and "A target device was removed." Tap "Details" to see the technical log.

The technical log omits a clean SOCKS authentication-only check with no request. It still records failed authentication and requests. A client that connects without sending data appears when it closes, or after the 30 second handshake bound.

The Dashboard shows the trusted target device count, and Settings lists the devices. The app publishes the count on every change, so a remote Forget updates both screens at once.

The Dashboard shows up to four lines for the connection attempts. The first line has this form:

```
12 attempts. 9 worked. 3 did not.
```

The first line counts finished attempts only. A cancelled attempt appears in the attempt count. The next line appears only when an attempt was cancelled:

```
2 were cancelled by the target device.
```

The next line appears when at least one attempt did not work:

```
Did not work: 96 web, 24 DNS lookups, 15 other connections.
```

The last line gives the most common reason over real failures only, for example "Most common reason: the website refused the connection." When the most common failure is a DNS lookup that could not be reached, the line says "Most common reason: the name lookup did not finish." When a deadline follows an unreachable wait, the line says "Most common reason: the connection did not become ready in time." When a deadline has no definitive answer, the line says "Most common reason: the connection timed out." It does not blame the website.

The full attempt ledger is: attempts = worked + did not work + cancelled + closed before a result + still running. A cancelled attempt is not a failure and not a success. The target device gave up on the connection. An attempt that ends before a result is not a failure. The app counts it separately and does not show it as a failure.

The counters count final results only. They count each final result by kind. They count a failed result by reason. The kinds are web (TCP port 80 or 443), other TCP, UDP, and DNS lookups on port 53. The reasons are refused, not ready, timed out, unreachable, and other. A cancelled attempt is not a reason. A tie in the kind line uses the order web, other TCP, UDP, DNS. Before any result, the first line says "No finished connections yet." With no attempts, it says "No connections yet." The counters reset when the proxy starts. They hold counts only, no addresses. ICMP is not counted.

The number is not a tunnel failure rate. A refused destination counts as "did not work". A DNS lookup on port 53 also counts. A slow cellular connection can miss the 4 second connect deadline, so it counts as "did not work" even when the network is healthy. Read the number as a summary of final connection outcomes on this proxy.

Earlier builds counted local interface-down waits as unreachable waits. A wait
count from those builds does not distinguish a local path failure from a
destination network or host that reported unreachable. The current app counts
local interface-down waits as other.

## Connect deadline and connect log

The app gives each destination connection 4 seconds to become ready. The target device has its own 5 second CONNECT timeout. The target timer starts before the request reaches the app, so it can fire first. The source deadline does not guarantee an answer before the target timeout. If the connection is not ready in time, the app cancels it and sends a SOCKS failure reply: code 5 when the destination refused the connection, code 1 (general failure) in all other cases. Code 4 (host unreachable) is only for a real unreachable failure. A deadline does not prove that the destination is unreachable, so code 1 keeps the target device from blaming it. The target device then gets a definitive answer in most cases, and the session slot frees. A final failure uses code 4 for a destination network or host that reported unreachable, code 5 for a refusal, and code 1 for every other error. The other errors include a DNS error, a local permission error, and a local interface error. `ENETDOWN` and `EHOSTDOWN` say that the local cellular path is down. They do not prove that the destination is unreachable, so they use code 1 and the reason other.

A connection that reports `.waiting` is retried once after 1.5 seconds. The retry uses the same host, port, and cellular pin, and it stays inside the same 4 second deadline. A second wait does not start a second retry. A short wait keeps the same connection: Network framework can make it ready when the path returns. An earlier build canceled the connection after 250 ms. That discarded connections that were still viable and started many extra connects. `.unreachable` is reported only for a real destination error. A deadline after a path wait is reported as "not ready", not as a slow website and not as an unreachable host. The path wait can be a destination error or a local interface error. The attempt keeps its wait. A retry starts a new connection inside the same attempt, so a deadline after that retry still reports the attempt wait: "not ready", or refused after a refusal. The reply code uses only the new connection, so a stale refusal is not sent. A refusal is an answer from the network, so it stays refused.

The app sets TCP keepalive on its listener and destination sockets: 60 seconds idle, 10 seconds interval, 3 probes. A carrier NAT can drop an idle mapping with no error at either end. The keepalive keeps an idle mapping and detects a peer that is gone. It is not application traffic. An established open TCP relay is not closed for application silence. A UDP flow and a half-closed flow close after 300 seconds without traffic. A remote service or the target device can still close its own end of an idle TCP relay.

The diagnostics also count waits and failures by destination family: IPv4, IPv6, or a name. A count shows that events occurred for that family. It does not show the failure rate for that family because the report does not count all attempts by family. One attempt can produce more than one wait. The line holds no address, host, or port.

The Details log shows one line for each failed, cancelled, or slow destination. The line names the kind and the result in words only:

- `A web connection timed out.`
- `A web connection did not become ready in time.`
- `A connection to another service was slow.`
- `A UDP flow was cancelled by the target device.`
- `A name lookup did not finish.`

A connection is slow when it is ready after more than 1500 ms. The app shows at most 8 of these lines in 10 seconds. It then shows one line "N more connect log lines suppressed". The list keeps the last 50 lines.

Privacy: these lines do not show a host, address, port, or timing. The app keeps them in the on-screen list only. It never stores them, never sends them to the target device, and never writes them to a file. They disappear when the app quits.

## Session capacity and queues

The proxy accepts up to 288 sessions: up to 256 relay sessions and 32 setup sessions. The observed open-file limit can give a lower total, with a proportional setup reserve. The app never reports 256 relay sessions unless the observed limit allows that cap.

At startup the app raises the soft file limit toward 4096 and derives the limit from the observed limit. It reserves three open files for each session: the client socket, the destination socket, and one retry socket. It also reserves 32 files for the app. At 4096 the startup limit is 288 sessions.

The open-file budget also covers a stop and a start that overlap. A stopped run can still own sockets while the next run accepts sessions. The app counts a session of the stopped run until its close routine reports that it requested cancellation. The app keeps the reservation if that callback does not arrive. A new run gets only the remaining estimated descriptor budget. After several rapid restarts, the new run can start with fewer sessions. If the budget has no session, Start fails with a plain message. Reopen the app if a close callback does not arrive. Network.framework cancellation is asynchronous, so the callback does not prove that every OS descriptor has closed. The app does not restart the proxy by itself. The diagnostics report shows the limit of the current run.

When the current limit gives fewer than 224 relay sessions, the Dashboard shows a warning before Start. The earlier app gave 224 relay sessions at a 256-session total with the 32 setup slots. The app does not claim the higher cap when the observed limit does not allow it. The warning also says when a previous run lowers the current limit. Close other apps and restart HotspotShade to try for a higher limit.

The app does not listen when the open-file limit is unknown or too low to hold one session. It shows the reason in the Dashboard. It does not report Listening while it cannot accept a session.

The capacity rule uses the session phase. A handshake has 30 seconds. A destination connect has 8 seconds, twice the source device connect deadline. When the request is complete, the connect bound ends. The server answers the relay request on its own queue, and that wait has its own 2 second bound. A UDP flow and a half-closed TCP flow close after 300 seconds without traffic. An established open TCP relay has no silence bound and is never evicted at capacity. ICMP echo sessions keep their own request, idle, and lifetime bounds.

The proxy reserves 32 of the 288 slots for setup sessions. At the full total, relay sessions use the other 256. A lower total keeps a proportional reserve. A presence check authenticates and sends no request, so it uses a setup slot and can run while relay slots are full. The reserve is not a guarantee: unauthenticated clients can fill all setup slots before a presence check starts. A presence check is only availability information from a paired target device. It does not start or stop the proxy. The pairing channel has its own listener on TCP port 18090, and it does not use a proxy session. The automatic stop uses the hotspot check. The diagnostics report shows the session limit and the refusal counts. It does not claim that a presence check succeeds.

At capacity, the proxy closes one session only when that session passed its phase bound. It closes a stale handshake, a stale connect, a stale relay wait, a stale UDP flow, or a stale half-closed flow. It never closes a healthy open TCP relay for silence. It also does not close a session while its final SOCKS reply is in flight or while an ICMP echo command owns it. Those sessions have their own bounds. If no stale session exists, the proxy refuses the new session. A refused connection is cancelled before a session starts. A refused relay request gets SOCKS error code 1 before the proxy sends any success reply. It also gets an error when the relay decision does not answer inside its own bound. The app counts connection refusals, relay refusals, and evictions by phase in its diagnostics. An eviction of an idle UDP or half-closed flow records an idle end.

A relay wait timer and a late relay grant can both fail the same request. The app sends one final failure reply only. A second failure path does not close the session and does not cancel the reply. The reply leaves, or its 5 second deadline closes the session.

One session keeps one phase timer. Traffic does not create a timer for each chunk, so the timer count does not grow with the transfer rate.

An eviction, a stop, and a listener failure close the session on its own queue. The close block holds the session strongly until it runs, so the last reference cannot go away first. The app records the end of each established relay once. A stop or a listener failure records the end before the run generation changes, so a late close cannot count it again or add it to the next run.

The app raises the open-file soft limit toward 4096 at startup. The diagnostics report shows the result as "raised", "already high", or "could not raise". A refused raise can still give a smaller usable limit. An unknown limit stops the start.

Each UDP-over-TCP session has one bounded queue in each direction. A queue holds at most 64 datagrams, about 94 KB at the largest datagram size. When a queue is full, it drops the oldest datagram and keeps the flow open. One writer sends each direction in order. The diagnostics report shows the largest queue and the total drops.

### Queue rule

The server owns one serial queue for shared state: the session table, the counters, the trust count, the snapshot, and the pairing state. Each session owns one serial queue under one shared concurrent parent. A session queue runs the socket handlers of that session only, so one slow session cannot delay another. A session callback returns to the server queue before it touches shared state. A session queue never reads or writes shared state. The ICMP echo selector and its tasks run on the server queue.

## Diagnostics

Settings, Advanced has "Copy diagnostics". It copies a plain-text report to the pasteboard. The report holds:

- The line "HotspotShade diagnostics"
- The app version and the iOS version
- The proxy state
- The connection summary, and a cancelled line when one is needed
- The connect time buckets
- The wait counts by error
- The wait and failure counts by destination family (IPv4, IPv6, names)
- Retries started and retries that worked
- Deadline fires
- Sessions: the peak, the limit of the current run, the relay cap, the setup reserve, and the current setup and relay counts
- Capacity: connection refusals, relay refusals, and evictions by phase, including the relay wait
- A capacity warning when the relay cap is below 224
- UDP queue peak and drops
- Established relay starts and ends, and the newest 10 second buckets with an end
- The file limit result and the open-file budget
- The count of close callbacks still missing after 10 seconds, when it is not zero
- Low Power Mode
- Thermal state
- The keep-awake state
- One line for each destination-privacy capability and a capability flags line

The established relay line says "no observation" before a relay carries payload. Otherwise it counts TCP and UDP relay starts. A start is one destination connection that answered and then carried payload in either direction. A destination that only became ready is not an established relay. The end line counts clean ends, client socket errors, destination socket errors, idle ends, other ends, and UDP ends. A client error is on the connection to the target device. A destination error is on the cellular connection to the destination. An error is not proof of packet loss on the cellular path. A proxy stop or a listener failure records an established relay that was still open as other. The report keeps the side and the reason for a TCP end. It counts a UDP end only as a total, so the line says that the side and the reason are not kept.

The bucket line keeps the last 300 seconds in 10 second buckets. It lists the newest eight buckets with an end. The age is in seconds before the report. The app recomputes the ages when you copy the report, so a report copied later does not show stale ages. A late event outside the window still counts in the totals, but it does not add a timeline row. The line holds counts only. The report does not name the destination, the application, or the carrier. One bucket does not prove the cause of a slow or stalled screen.

The report holds counts, states, and versions. It holds no address, host, port, token, pairing code, or website. The Settings note says this to the person.

## Destination privacy

Settings has a "Destination privacy" section. It is a report, not a control. No row turns a mechanism on, and the app sends no privacy setting to a target device:

| Row | State | What it says |
|---|---|---|
| Byte relay | On | The app opens the destination connection and copies bytes in both directions. It forwards TLS bytes unchanged. |
| Destination names | May be visible | The relay adds no concealment. The carrier can see the destination address and the traffic shape, and it may see the destination name of a TLS connection. An application that uses Encrypted Client Hello keeps its own name hidden. |
| Encrypted Client Hello (ECH) | Not available | The relay opens no TLS session of its own, so it cannot add ECH to a flow. An application that supports ECH can still use it on its own. |
| Server name override | Not available | The relay never parses or rewrites TLS, so the app cannot change the server name. |
| Handshake shaping | Not available in this build | The relay does not re-frame the TLS handshake in this build, and there is no control for it. |
| Relay lifetime | Not guaranteed | iOS can suspend the app in the background. The keep-awake option below uses location updates, and the app has no Network Extension, so a sustained relay in the background is not guaranteed. |
| TLS termination | Not used | The app does not end TLS, present a certificate, or read the destination name. No certificate is installed on your target device. |

The same rows appear in the diagnostics report, followed by one line that lists every capability flag as yes or no. This build reports every flag as no. The text holds no name, address, port, token, or key.

The section does not claim that every destination name is visible. An application can conceal its own name. The relay adds no concealment either way, and the destination address and the traffic shape may stay visible.

## Background operation

"Help keep running in the background" is on by default. The app asks for the Location permission the first time you turn the setting on or tap Start while it is on. The app requests location updates while the proxy runs. It asks for accuracy to the nearest ten meters and uses no distance filter. It does not pause the updates by itself. It discards the locations. The iOS location indicator appears and battery use is higher.

While the proxy runs and Location is allowed, the keep-awake card tells the
truth about the location updates:

| Last fix | Text |
|---|---|
| Less than 60 seconds ago | "Location updates are active. iOS can still pause the app." |
| 60 to 300 seconds ago | "Location updates stopped. Open HotspotShade to restart." |
| More than 300 seconds ago, or no fix | "No location yet." |

When the setting is off, the card says "Keep running in the background is off. Turn it on in Settings." Before the first Location answer it says "Allow Location when iOS asks, so the app can stay awake." Once Location is granted and the proxy is stopped, it says "Starts when the proxy starts."

After a location error or a system pause, the app restarts the updates 2 seconds later. It allows at most 5 restarts in 10 minutes. After that it shows "Location updates keep stopping. Open HotspotShade to restart."

When Location is denied, restricted, or off in Settings, or when an Allow Once permission expired, the app shows "Location is off, so iOS can pause the app. Open Settings to turn it on." with an Open Settings button.

The app does not stop the proxy when it enters the background. When "Help keep running in the background" is off or the Location permission is missing, nothing keeps the app awake, so iOS can suspend it. While iOS suspends the app, its timers do not run and the pairing listener cannot answer the target device. When the app runs again, it checks the hotspot and resumes listening if the interface is present. The Dashboard shows a plain warning in that case. After a pause, Recent activity reports a gap over one minute. If the app ended while listening, the Dashboard offers Start again. The app does not restart the proxy by itself.

The keep-awake option makes a suspension less likely. It is not a guarantee. iOS can still suspend the app in the background, and this app has no Network Extension. Settings reports the relay lifetime as "Not guaranteed" for that reason. Keep the app open while it relays.

## Last stop

The Dashboard shows one line with the last stop. The line survives an app restart, including a restart after iOS closed the app. The line has this form:

```
Last stop: The app was closed by iOS. 14:32.
```

The reasons are "You stopped it.", "The hotspot address was lost.", "The hotspot link changed.", "The hotspot link is not supported.", "The proxy stopped because of an error.", "Location turned off.", and "The app was closed by iOS." A new Start clears the line.

## Notifications

The app asks for notification permission once, at the first Start. After the person denies it, the app does not ask again. Settings always shows the current notification state. When notifications are off, it shows this note with an Open Settings button:

```
Notifications are off. You will not see a message when the proxy stops.
```

The app sends a stop notification only while the app is not active. It cannot send one while iOS has suspended the app. A push notification needs a server, and this project has no server. The app therefore sends no notification after a suspension. The Dashboard and the last-stop line show the result when the app runs again.

## Automatic stop when the hotspot disconnects

While the proxy runs, the app checks for the supported bridge and address once a second. The proxy stops when observations show that the address is missing for at least 20 seconds. A complete check that names a different interface at the same address is a known link change, so the proxy stops at once. A hotspot address on a link type this build does not support also stops it. An unreadable interface list or hotspot address, a gap over 5 seconds, or a scene change starts a fresh observation window. This can delay a stop when the app is suspended or the system delays checks. The interface name is one local record. It does not prove that the Personal Hotspot switch is on, and two links that reuse the same name and address cannot be told apart. A missing address does not prove the switch is off either. The app does not restart the proxy by itself. Start it again after the hotspot returns.

The app can see only its own network interfaces. It cannot see which clients are connected. If the hotspot stays on and the target device joins another network, the address stays present and the proxy keeps listening. The listener binds to the hotspot address only, so no other network can reach it. Network.framework has no public way to bind the listener to an interface name, so the app checks the interface identity separately.

## App Review note

The `location` background mode exists only to keep the app alive while the proxy runs. The app requests location updates and discards every value. It does not store or send a location. Apple can reject an App Store submission that uses the location background mode for this purpose. That does not matter for a sideloaded install. See "Install without Xcode (unsigned IPA)" below.

## Security and limits

Copy token writes a local-only item to the general pasteboard, with a
system-managed 120-second expiration. It remains available after Hide or when
the app leaves the foreground. Other local apps may read it, and clearing it
cannot revoke a copy already read. When the token changes, the app clears the
pasteboard if its change count still matches the recorded copy. These checks
and writes are not atomic: another app's newer item can be cleared, or an
interleaved write can leave the token copy untracked until it expires. A crash
or app restart also loses the in-memory record.

Copy connection details replaces any token copy on the pasteboard. It writes
the address, port, and SOCKS5 username, and it holds no token. The app stops
tracking the token copy at that point, so a later token change does not clear
this item. The connection copy also uses a 120-second expiration, but it is not
a secret.

The token authenticates the target device to the source device. Settings hides the token. Tap Show token to see it for 30 seconds. The token hides again when the app leaves the foreground. The token and SOCKS5 control channel are not encrypted. Anyone who can observe the local link can learn the token. Token rotation is disabled pending review. This build has no reliable revocation path for an exposed token. A target device that is still in the trust list can pair again without a prompt, so Forget that device as well if it must be kept out. Its saved token can still authenticate until the credential changes. The listener accepts connections on the identified hotspot IPv4 address. The proxy compares the token in constant time to avoid a timing signal. That is hardening only: the token still crosses the hotspot link in cleartext.

### Token storage

The app keeps the token in one Keychain generic-password item. The service is `local.hotspotproxy.app` and the account is `proxyToken`. The item uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `synchronizable` is false. It does not sync through iCloud Keychain, and its device-bound protection prevents use on another device. Same-device backup and restore behavior has not been verified. The app never writes the token to UserDefaults, to a log, or to the diagnostics report.

An earlier build saved the token in UserDefaults under `proxyToken`. When the Keychain is empty and the old value is valid, the app adds it to the Keychain and verifies the result. Normal migration retains the old plaintext copy, which can be included in backups; the reviewed rotation path that would remove it is disabled. If the two copies differ at any other time, the app keeps both, suspends pairing, and refuses to start the proxy. When a conflict or an unreadable Keychain leaves the app with no usable token at launch, the Dashboard shows Needs attention with the same plain storage message.


A present empty or non-string old value is ambiguous. The app preserves it and does not generate a token. Restoring an older backup or downgrading the app can also restore an older credential. If that copy differs from the Keychain token, the app reports a conflict and uses neither value. It does not treat the restored copy as the current credential. If the Keychain item is also gone, a valid restored copy is migrated and used. That can reinstate an older token. The app cannot tell a legitimate upgrade copy from a restored backup with these stores alone. This build cannot revoke a token that an external process or an older build writes back later. The app either reports a conflict or, when the Keychain item is also gone, migrates the only remaining copy.

### Token rotation and recovery

Token rotation is disabled in this build. The Settings control is disabled, and its note says that rotation is unavailable pending review. Do not treat it as a revocation path. New rotations are dormant code behind a review gate and are not reachable until the gate is opened after an independent review. Recovery of an existing rotation record runs on launch and on a read retry. The dormant rotation path also runs it before an attempt and during its confirmation read after certain failures. Recovery can remove the observed old copy and clear the record. This build writes no new record.

The person would need a stopped proxy, no pending start, a readable saved token, and no old-copy conflict. The app would suspend the pairing listener before it changes storage. A pairing reply already sent to the network cannot be recalled, and neither can a proxy session that the app already admitted. A token change decides what the app offers and accepts next. It does not end a session that is already running, and a target device keeps any token it already received until the proxy stops. That is why a rotation requires a stopped proxy and no pending start, and why the app suspends pairing before it changes storage.

The dormant staged write uses the Keychain item `proxyToken.recoveryIntent` with the same after-first-unlock, this-device-only protection. The record holds a format version, a random transaction identifier, a stage, and SHA-256 digests of the old and new tokens. It never holds a token. The order is:

1. Write and read back a `prepared` intent record.
2. Re-read the old token.
3. Write the new token to `proxyToken` and read it back.
4. Write and read back a `committed` intent record.
5. Remove the observed old UserDefaults copy, if any, and confirm it is gone.
6. Delete the intent record and confirm it is absent.

On launch, on a read retry, and before it starts a new rotation, the app resolves an existing intent before it reads the token. This recovery runs in this build. Only a new rotation is disabled:

- `prepared` with the old token current: the rotation did not land. The app clears the intent, keeps the old token, and resumes pairing with it.
- `prepared` or `committed` with the new token current: the rotation landed. The app removes a stale old copy that the intent names, clears the intent, and adopts the new token.
- `committed` with the old token current, a missing or invalid token, a damaged or unknown intent version, or a third value: the app changes nothing, keeps the intent, and suspends pairing and the proxy. It does not create a replacement.
- The new token is current but the old copy is a different value: the app keeps both, keeps the intent, and suspends pairing. It does not delete the unknown copy.
- A legacy copy removal or intent delete fails: the app keeps the intent and reports a retryable failure. A later activation or restart retries. Pairing stays down until the state is confirmed.

The staged rotation assumes one cooperating writer. The app would be the only process that writes these items, and the old UserDefaults key is written only by an earlier build that is not running at the same time. Keychain and UserDefaults have no compare-and-swap. A different process that changes an item between the app's last read and its write is not excluded, and this build has no conditional Keychain replacement. The app detects a changed value at every read boundary and fails closed, but a write-write race after the final check can still replace that value. Restoring a backup or downgrading the app can also reintroduce an older credential. The app detects some of those states as a conflict on the next launch. It cannot establish revocation across an external writer, a backup restore, or a downgrade. These limits are unverified on a device.

The intent record and the token item are separate items, and the stores have no transaction across them. A power loss can lose the token write while the later intent delete survives. The next launch then finds no intent and an old Keychain item. If the old UserDefaults copy is gone or equal, the app silently reinstates that old token. It adopts the value with no conflict and no warning, and it uses a credential that the rotation was meant to replace. No record remains that would let the app detect the case. A read-back therefore does not prove that either item survives a crash or power loss.

Repair of an invalid Keychain item remains unavailable. Validation does not identify the item for a conditional delete. The store keeps an invalid item and any valid old copy untouched. A rotation record that is short, damaged, or from an unknown version is rejected as unknown. The app never treats that as proof that no rotation is pending, so it blocks token use and creation across restarts. This build writes no such record, but a development build of this unreleased work, a restore, or an external writer can leave one. Contact support before removing saved data.

For a fresh installation with no saved item, the app adds a new token and reads it back before use. A locked or unreadable Keychain blocks use. After an uncertain first load, same-launch retries only read and never create or migrate a token. If no token is found, the app reports `tokenUnavailableAfterFailure` and asks the person to reopen the app to retry setup. A fresh installation with a transient first read can therefore need a reopen. The app retries reads on activation or protected-data availability while the failure can clear. A conflict, a damaged rotation record, or a refused recovery is not re-read during the same launch, because the app has no automatic repair or delete for those states. Reopen the app to read the stores again. An external writer or a restore can change the saved bytes before that, and only a launch or a support step observes the new state. Forgetting a target device, or all of them, removes trust entries only; a target device that saved the token can still authenticate after you forget it, because the token did not change. This build has no reviewed rotation path to revoke it. A trusted target device can pair again without a prompt because trust survives.

The lifecycle serializes launch, retry, start reservation, gated rotation, recovery, and pairing updates with one recursive lock. The proxy start reserves the token boundary across the token copy and the point where its start request becomes visible. Rotation is refused while that reservation or a proxy start is active, and the review gate is closed in this build. A failed rotation that does not invalidate the saved token re-reads the stores before the app keeps that token or resumes pairing. The confirmation read is a new store transaction after the rotation returns, so a store callback cannot start another transaction. The lifecycle suspends pairing before entering the store, and it holds no store transaction while calling the pairing listener.

The storage tests use fakes. They do not prove crash durability, restore behavior, Keychain entitlement behavior, or exclusion of external writers on a device. The staged rotation and recovery matrix covers each simulated crash point in the test file, restart recovery, a changed old copy, a downgrade copy, a damaged intent, a failed intent delete, and a stored value that changes while the app runs. Those results do not enable a new rotation and do not prove a real Keychain transaction. Existing intent recovery still runs in this build. The token and SOCKS5 control channel travel in cleartext on the local link; avoid using the proxy on an untrusted hotspot.

The hotspot Wi-Fi link does not provide end-to-end encryption to the destination. SOCKS5 forwards the application's own TLS traffic. Use TLS in each application. A later version can add TLS or WireGuard protection for the proxy control channel.

The app requires an available cellular path for each destination connection. DNS for domain requests is resolved by the networking stack of the source device. This app has no custom DNS leak controls. IPv4 and IPv6 destinations are supported when the cellular network supports them. An experimental authenticated command carries UDP datagrams over a TCP stream per flow (command `0x80`). A second command carries ICMP echo requests over the cellular path. The echo path uses the cellular interface only, allows 8 outstanding echoes, and does not support traceroute or path-MTU discovery. ICMP is not counted in the connection counters. The UDP-over-TCP path is experimental. The scoped diagnostic tests it. See `PHONE_PROXY.md`. Standard SOCKS5 UDP ASSOCIATE, BIND, traffic accounting, and automatic target device proxy configuration are not supported. For TCP, an EOF closes the other connection's write side. The relay carries a clean EOF that arrives with the last SOCKS request field. This path still needs a live source device test. The reverse direction stays open until it also ends. A half-closed session can remain until the five-minute idle timeout. The app permits up to 288 sessions: up to 256 relay sessions and 32 setup sessions. A lower file limit gives a lower total. Without background location, iOS can suspend the proxy when the app enters the background. Screen lock can also interrupt it.

The simulator build does not verify Personal Hotspot access, cellular routing, or device behavior. Test these on a real source device and target device.

## Install without Xcode (unsigned IPA)

CI builds an **unsigned** IPA on every push. Download it from the `ios` job artifact `HotspotShade-iOS-unsigned-ipa` in GitHub Actions. A tagged release (`v*`) attaches the same file to the GitHub Release.

The IPA has no code signature, no certificate, and no provisioning profile. iOS refuses to run it until a tool signs it with a certificate that you own. The project does not sign it for you and does not hold any signing material.

1. Download `HotspotShade-iOS-unsigned.ipa`.
2. Sign and install it with a sideloading tool that uses your own Apple ID or your own developer certificate and provisioning profile. Examples of such tools are AltStore and Sideloadly. This project does not test or endorse them.
3. Trust the developer profile on the source device if iOS asks. Enable Developer Mode if iOS asks.
4. Follow steps 7 to 10 of "Run on a source device" above to use the app.

A free Apple ID profile expires after seven days. Sign and install again when it expires. The bundle identifier in the IPA is `local.hotspotproxy.app`. Your tool can change it if signing requires a unique value. A changed bundle identifier installs as a new app, and the new app has no stored pairing trust and no stored token.

To build the IPA yourself, run `scripts/build_ipa.sh` on a build machine with macOS and Xcode. The default output is `build/HotspotShade-iOS-unsigned.ipa`.
