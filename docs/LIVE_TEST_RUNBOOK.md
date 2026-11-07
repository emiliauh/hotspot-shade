# Live test runbook

This is the operator script for two live tests: (A) iPhone to macOS and (B)
iPhone to Windows. It is a procedure, not evidence. A pass applies only to the
builds, devices, and network that were tested on that day.

Read `AGENTS.md` safety rules and `docs/PHYSICAL_DEVICE_VALIDATION.md` first.
The owner must approve the phone install, the live hotspot, the tunnel start,
and every `sudo` read before it happens. Stop at the first stop condition in
`docs/PHYSICAL_DEVICE_VALIDATION.md` section 3.7.

Rules for both paths:

- Keep the iPhone app open in the foreground with the screen on. iOS can
  suspend it, and a suspended app cannot answer.
- Never write a token, pairing code, identity key, SSID, carrier account, or the
  address of personal traffic into a record. Name a fixed public page "public
  test endpoint A", never a personal destination.
- Run one tunnel at a time. Do not test on a device that someone is using.
- Do not restart either app while a tunnel runs.
- Never delete a route, a state file, or a device to make a later step pass.

## A. iPhone to macOS

### A1. Preconditions

- The iPhone build is signed with the owner's team, bundle
  `local.hotspotproxy.app`, and the provisioning profile has not expired. State
  whether the install replaces an existing app or adds a new bundle id. A new
  bundle id carries no stored trust.
- The Mac app, helper, and engine are signed with one Developer ID team, use the
  hardened runtime, and carry no `get-task-allow`. An unsigned or ad hoc app
  fails closed at Turn on.
- The start right comes from the current template. Read it with owner approval:
  `sudo security authorizationdb read dev.hotspotshade.tunnel.start`. Its
  `timeout` must be 1 to 60 seconds; 30 is expected. A zero-second right from an
  earlier install is refused before any prompt.
- The coordinator that matches the installed delivery reports no file journal,
  no service journal, no cleanup block, no launch intent, and no start journal.
- No VPN, network extension, content filter, or other tunnel is active. No root
  engine runs. The user engine from the open app is expected and must run as
  your account.
- Cellular data and Personal Hotspot are on. The Mac is joined to the hotspot,
  and that interface is the default route.
- On the iPhone, open HotspotShade and tap Start. Allow Local Network and
  Location if iOS asks.
- The Mac app opens its real Dashboard with no administrator prompt. Only Turn
  on may prompt.

### A2. Read-only snapshot before Turn on

Save the output in a private directory, for example
`~/hs-live/<date>-mac-before/`. Record the default interface and gateway as
labels, not addresses.

```sh
route -n get default
netstat -rn -f inet
netstat -rn -f inet6
ifconfig
scutil --nwi
BIN=/absolute/path/to/hotspotshade; "$BIN" probe
sudo lsof -nP -iTCP -sTCP:LISTEN
COORD='/Library/Application Support/HotspotShade/local-preview/coordinator/hotspotshade-installer-coordinator'
sudo "$COORD" preview-status
```

Use the `coordinator/` path under the delivery that is installed. A staged
delivery may live in `local-preview` or `local-preview-unprivileged`. Do not mix
a coordinator with another delivery. From `probe`, record only the TTL and the
audit count, not the account id or the DNS servers. From `preview-status`,
record the six lines: file journal, service journal, cleanup block, launch
intent, start journal, backup orphans.

### A3. Pair

1. On the Mac, press Pair with source device.
2. Both screens show a six-digit code in groups of three. Compare them.
3. On the iPhone, tap Allow only when the codes match and you started the pair.
   Tap Deny if the codes differ or if you did not start it.
4. Expect the Mac to show Paired, and the iPhone to show "Paired with 1 target
   device." Record which happened, not the code.

A previously trusted target pairs without a prompt. Record that too.

### A4. Turn on

1. Press Turn on in the Mac app.
2. Approve the one macOS administrator prompt.
3. Expect "Starting the tunnel", then On and "The tunnel is on." This can take
   a minute.
4. If the app says the signed helper is needed, or the prompt is denied or
   times out, stop. Turn on failed closed and no route should have changed.
5. Do not retry Turn on in the same run without recording the exact message.

### A5. While on

- iPhone: the Dashboard shows "A target device is using the proxy now." and the
  usage card title is "Target device connected". The counters move.
- Mac: the app shows On. Settings, Advanced, App details shows a ready service
  state, and Activity shows new lines.
- Load one fixed public test page twice, for example `https://example.com`.
  Confirm it loads and the iPhone counters increase. Do not sign in anywhere.
- Press Check now. The source device must stay answered.
- TTL: the engine keeps `ttl_bad` in its status. The macOS app's Copy
  diagnostics does not print it today. If the engine web page is open, read the
  "TTL violations" line. Otherwise record "not exposed" and do not claim a TTL
  pass from a working page.
- A non-zero TTL count is a stop condition. Turn off and copy diagnostics.

### A6. Turn off

1. Press Turn off in the Mac app. Expect "Turning off", then Ready, or
   "Waiting for your source device" if the source has not answered yet. The
   pairing stays.
2. Confirm the app reports the stop. Do not quit the app before it does.
3. Stop the proxy on the iPhone. Expect Off.
4. If the phone stops first, or the hotspot drops, record that as the stop path
   and still run A7.

### A7. After snapshot and what counts as clean

Repeat the A2 commands into `<date>-mac-after/` and compare.

Clean when all of these hold:

- `route -n get default` names the same interface and gateway as the snapshot.
- No `0.0.0.0/1` or `128.0.0.0/1` route points at a `utun`, and no new `utun`
  exists.
- No new `2000::/3` blackhole remains.
- `pgrep -fl hotspotshade` shows no root engine. The user engine may remain
  while the app is open.
- `preview-status` reports: file journal none, service journal absent, cleanup
  block absent, launch intent absent, start journal absent, backup orphans none.
- No new listener except a GUI listener on `127.0.0.1` while the app is open.
- The iPhone shows Off and the tunnel does not restart.

Small metric or ordering differences are normal. A leftover `/1` route is not.

### A8. If cleanup is uncertain

- Stop testing. Do not start another tunnel.
- Preserve the exact app message, the `preview-status` output, and both
  snapshots in the private record.
- Do not delete routes, `utun` devices, `/var/db/hotspotshade` files, or the
  start right by guesswork.
- Follow the inspection and containment steps in `macos/Helper/README.md`,
  "Recovery after a cleanup block or leftover intent". That procedure does not
  clear the block.
- This tree has no reviewed clear command. When the delivery ships one, named in
  its notes, run only that command, once, with owner approval and its own
  record. `preview-uninstall` is not a clear: it refuses while a cleanup block
  or a journal is present.

## B. iPhone to Windows

Live Windows hotspot testing has not run on a Windows host. The WinUI 2 app is
the app to test. Build, sign, and install it with
`windows/BUILD_AND_TEST_ON_PC.md`. Do not use the console TestLauncher or a
Visual Studio loose-file deployment for Turn on.

### B1. Preconditions

- Windows 10 version 2004 (build 19041) or later, x64. The signed-in account is
  an administrator. Approval with a different account is refused by design.
- The package is installed in a WindowsApps store:
  `Get-AppxPackage HotspotShade.Windows` returns it.
- The official x64 `wintun.dll` sits next to the engine and carries the
  WireGuard signature. It is not committed to the repository.
- The iPhone build, hotspot, and foreground app are as in A1.
- No VPN, second default route, split default route, virtual adapter, or filter
  driver. The iPhone hotspot adapter is the physical default route and its
  gateway is the iPhone.
- No `HotspotShade-Tunnel*` adapter, no `/1` or `2000::/3` route on it, and no
  `hotspotshade` process.

### B2. Read-only snapshot before Turn on

Save the output in a private folder, for example `C:\hs-live\before\`.

```powershell
New-Item -ItemType Directory -Force C:\hs-live\before | Out-Null
route print > C:\hs-live\before\routes.txt
netsh interface ipv4 show route > C:\hs-live\before\ipv4-routes.txt
Get-NetAdapter > C:\hs-live\before\adapters.txt
Get-NetRoute -AddressFamily IPv6 | Sort-Object DestinationPrefix > C:\hs-live\before\routes-v6.txt
Get-Process hotspotshade -ErrorAction SilentlyContinue
```

Record the default interface, the gateway label, and whether a
`HotspotShade-Tunnel*` adapter exists. Do not record MAC addresses. Stop if a
VPN or an unexplained adapter is active.

### B3. Pair

1. Start HotspotShade from the Start menu. No UAC prompt may appear. If one
   does, stop and report it.
2. Wait for "Starting HotspotShade" to end and for a real state, typically Not
   paired.
3. Press Pair with source device. Compare the six digits on both screens.
4. On the iPhone, tap Allow only when the codes match and you started the pair.
5. Expect Ready and the line that Windows asks for administrator approval when
   you turn on the tunnel. Record success, not the code.

A previously trusted target pairs without a prompt. Record that.

### B4. Turn on

1. Press Turn on.
2. Approve the one UAC prompt. It names `HotspotShade.WinUI2.Elevate.exe`.
3. Expect "Starting the tunnel", then On. Settings, Advanced shows "Engine:
   Administrator engine".
4. If Turn on is unavailable, record the exact reason (pairing handoff, missing
   `wintun.dll`, not installed from a package, wrong approving account) and
   stop.
5. If the engine refuses with "The source device must be the default gateway of
   a physical hotspot adapter...", record `source_gateway_unproven` and stop.
   No route should have changed.

### B5. While on

- iPhone: "A target device is using the proxy now." and the counters move.
- Windows: On, Activity shows lines, and Check now stays answered.
- Load one fixed public test page twice, for example `https://example.com`.
  Confirm it loads and the iPhone counters increase. Do not sign in anywhere.
- Settings, Advanced, Copy diagnostics: `Cleanup blocked: no` and
  `TTL audit failures: 0`. The Dashboard shows a TTL line only when the count is
  above zero.
- A non-zero TTL count is a stop condition. Turn off and keep the report.
- This mode forwards IPv6. Do not expect a `2000::/3` blackhole.
- Windows has no hotspot link observer. Do not test or claim an automatic stop
  here.

### B6. Turn off

1. Press Turn off. Expect "Turning off", then Ready, and Settings, Advanced
   shows "Engine: Standard user engine".
2. Turn off shows no UAC prompt.
3. Stop the proxy on the iPhone. Expect Off.
4. Quit the Windows app only after the stop is confirmed.

### B7. After snapshot and what counts as clean

Repeat B2 into `C:\hs-live\after\`, then compare:

```powershell
fc C:\hs-live\before\routes.txt C:\hs-live\after\routes.txt
fc C:\hs-live\before\routes-v6.txt C:\hs-live\after\routes-v6.txt
Get-NetAdapter | Where-Object Name -like 'HotspotShade-Tunnel*'
Get-NetTCPConnection -State Listen
Get-Process hotspotshade, HotspotShade.WinUI2.Broker, HotspotShade.WinUI2.Elevate -ErrorAction SilentlyContinue
```

Clean when all of these hold:

- No `0.0.0.0/1`, `128.0.0.0/1`, or `2000::/3` route remains on a
  `HotspotShade-Tunnel*` adapter.
- No `HotspotShade-Tunnel*` adapter remains.
- No tunnel listener remains. A GUI listener on `127.0.0.1` may remain while
  the app is open.
- After Quit, no HotspotShade process remains. While the app is open, one
  broker and one standard-user engine may remain.
- The iPhone shows Off and the tunnel does not restart.

Small metric, gateway, or Wi-Fi differences are normal. A leftover `/1` route is
not.

### B8. If cleanup is uncertain

- Stop testing. Do not press Turn on again.
- Preserve the exact Dashboard or dialog message, the diagnostics text, and
  both route files.
- Do not delete routes, the Wintun adapter, or app state by guesswork.
- If the app says it could not confirm the stop, or that the administrator
  engine exited without a confirmed stop, run only the read-only B7 checks
  first.
- Removal, when the owner approves it, is limited to objects on
  `HotspotShade-Tunnel*`, as written in `windows/BUILD_AND_TEST_ON_PC.md`
  section 9. Never remove a route on another adapter.
- If an adapter remains with no owner, restart Windows. Wintun removes an
  adapter whose owner is gone.
- Windows has no reviewed clear for a cleanup block. Stop and escalate.

## C. What to record

Write one private record per platform. Do not commit it unless the owner asks
and it is redacted.

- Test id, date, owner approval reference, and tester role.
- Build identity: source revision, app, engine, and helper versions and hashes,
  and the signing team name. Never the certificate or key.
- OS versions: iOS, macOS or Windows. Carrier and plan: "not recorded by
  policy".
- Hotspot band, channel width, and security type. No SSID.
- Pairing path: prompt shown or known target, and success or failure.
- App states before, during, and after: iPhone, target app, stop reason and
  message.
- `probe` TTL and audit count. `ttl_bad` if the build exposes it, otherwise
  "not exposed".
- Cleanup evidence: the diff result and the exact objects checked.
- Every stop condition or warning, with host names and resolver addresses
  removed.
- Limitations, and a redaction check that found no token, code, key, SSID,
  personal address, DNS name, or MAC address.

A pass does not prove carrier behavior, background relay, other applications,
another build, or another network.
