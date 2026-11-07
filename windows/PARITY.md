# Windows app parity

This file compares the WinUI 2 app with the macOS target app in
`macos/HotspotShadeKit`. The Windows app is wired to the real engine through
the full-trust broker and has no demo mode. It has not been built or run on
Windows yet; every "Matched" row is a code and model match, checked by the
hermetic Core tests, not a Windows host result. Read `README.md` for the
architecture and `BUILD_AND_TEST_ON_PC.md` for the first test.

Status values:

- **Matched**: the same visible meaning and capability, from the same engine
  data.
- **Partial**: the same meaning, with a platform limit or a missing data source.
- **Different**: a native Windows pattern replaces the macOS pattern.
- **Missing**: not built for Windows. The app does not offer it and does not
  simulate it.

## Main surface

| Area | macOS target app | Windows app | Status |
|---|---|---|---|
| One main window | Sidebar with Dashboard, Activity, and Settings | `NavigationView` with Dashboard, Activity, and the built-in Settings item | Matched |
| Settings surface | Separate Settings window with General, Pairing, and Advanced | Settings page with a `Pivot` and the same three tabs | Different |
| Engine start screen | Starting HotspotShade, then a retry error | "Starting HotspotShade", then the broker or engine failure with Try again | Matched |
| Demo mode | None. The app runs the bundled engine as the signed-in user. | None. No demo, preview, or simulated data. | Matched |
| Minimum size | 780 by 560 | UWP caps the preferred minimum at 500 by 500. Responsive layout. | Partial |
| Closing the window | App and menu bar item stay alive | Closing the window quits; the broker stops the tunnel and both engines | Different |

## Dashboard

| Area | macOS target app | Windows app | Status |
|---|---|---|---|
| Status header | Title, subtitle, status mark, checked time | Same, from the ported derive table | Matched |
| Primary and secondary action | From the state table | Same table (`DashboardPresenter`) | Matched |
| Source device and Connection cards | Value and detail lines | Same lines, plus the administrator engine line while On | Matched |
| Attention list | Plain lines with inline actions | Same, with `HyperlinkButton` actions | Matched |
| Admin note | "macOS asks for administrator authorization when you turn on the tunnel." | "Windows asks for administrator approval when you turn on the tunnel." | Matched |
| Stale and unavailable status | 3 seconds stale, 10 seconds unavailable | Same, driven by the real poll | Matched |
| Unknown service state and cleanup block | No On or Off claim, no start | Same | Matched |
| Unconfirmed stop | Cleanup mark, Turn off again, no start | Same, owned by the broker phase | Matched |
| Lost elevated engine | Final route mark, no retry | Same, until the broker restarts | Partial |
| Source device warning | After 10 seconds of failure while running | Same | Matched |
| TTL audit failure | Shown beside On | Same | Matched |
| Wi-Fi advice | Band and signal advice | Not built | Missing |

## Pairing

| Area | macOS target app | Windows app | Status |
|---|---|---|---|
| Pairing panel | Replaces the cards, waiting state, code in two groups, three steps | Same | Matched |
| Copy code and Cancel | Present | Present, Esc cancels | Matched |
| Pairing result | Engine paired or failed state | Same, polled every 700 ms | Matched |
| Automatic pairing | Once per launch and every 10 seconds | Manual Pair only | Missing |
| Forget | Cautious result text, blocked while running | Same, with Turn off and forget and a confirmation dialog | Matched |
| Pairing during a tunnel | Refused | Refused by the window and the broker | Matched |

## Activity

| Area | macOS target app | Windows app | Status |
|---|---|---|---|
| Log list | Engine log with time and message | `/api/logs` through the broker, newest first | Matched |
| Details toggle | Level and sequence | Same | Matched |
| Loading, empty, unavailable | Present | Present | Matched |
| Live updates | Polls | Every 2 seconds while visible | Matched |

## Settings

| Area | macOS target app | Windows app | Status |
|---|---|---|---|
| Let ping work | UserDefaults, next start | Local settings, sent as `experimental_icmp` on the next Turn on | Matched |
| Appearance | Follows macOS | System, Light, or Dark page theme | Different |
| Notifications | Permission and system settings | Not built | Missing |
| Launch at login | Login item | Not built | Missing |
| Recent failures | Engine groups with Count, Kind, Target, Stage, Reason | Same, loaded when Advanced opens or on Refresh | Matched |
| Copy report | Engine failure report | Same columns as text | Matched |
| App details | Version, OS, status | Version, Windows, engine role, status | Matched |
| Copy diagnostics | Counters, timing, queues, failures | App and status lines plus the engine `/api/diagnostics` answer | Partial |
| Destination privacy card | Read-only capability card | Same fixed text | Matched |

## Menu and keyboard

| Area | macOS target app | Windows app | Status |
|---|---|---|---|
| Menu | Menu bar and menu bar extra | In-window WinUI 2 `MenuBar` with the same actions and state-dependent enablement | Different |
| Menu bar extra | Status item | UWP has no tray icon | Missing |
| Shortcuts | Command 1, 2, comma, R | Ctrl+1, Ctrl+2, Ctrl+3, F5, Ctrl+K | Different |
| Quit | Stops the engine before quit | Quit confirms while On; the broker stops the tunnel and both engines | Matched |

## Privilege and engine

| Area | macOS target app | Windows app | Status |
|---|---|---|---|
| App open | User engine, no prompt | User engine through the broker, no prompt | Matched |
| Tunnel start | One administrator authorization, protected helper | One UAC prompt, elevated starter | Different |
| Credential handoff | User engine writes a private descriptor, helper passes it, root engine imports it | Same shape with an inherited pipe; the starter duplicates it and never reads it. The engine side is in the current Rust source; neither side has run on Windows. | Partial |
| Confirmed stop | Returns to the user engine | Same | Matched |
| Automatic stop | Hotspot loss and source device loss | The engine stops on the first refused gateway check (`hotspot_lost`) or after 90 seconds of source device silence (`source_device_gone`); the broker returns to the user engine and keeps the stop reason. Unverified on Windows. | Matched |
| Direct mode | Command line only | Not offered | Matched |
| Package | Signed app bundle | Sideload MSIX signed with a local test certificate | Partial |
| Architecture | arm64 | x64 | Different |

## Accessibility and display

| Area | macOS target app | Windows app | Status |
|---|---|---|---|
| Headings | Combined labels | Level 1 and level 2 headings | Partial |
| Live status | Accessibility label on the header | Polite live region with the full status as its name | Matched |
| Pairing code | Read as a code | Read digit by digit | Matched |
| Status mark | Hidden from assistive technology | Hidden with `AccessibilityView` Raw | Matched |
| Keyboard access | Full keyboard access | Menu accelerators, `NavigationView`, `Pivot`, tab order, Esc | Partial |
| Light, dark, high contrast | Full | Theme dictionaries; some popups follow the system theme | Partial |
| Narrator, text scale, reduced motion | Tested on macOS | Not tested on Windows | Missing |

## Incomplete parity summary

1. Nothing has run on Windows. The first build, the UAC prompt, the broker
   lifetime across suspension, the handle duplication, the live tunnel, and
   the cleanup need the owner's PC test.
2. The pairing handoff (`--handoff-fd` and `--credentials-fd`) exists in the
   engine source and the app, and is unverified on Windows. An older engine
   makes the app show Turn on as unavailable.
3. No notifications, launch at login, tray icon, Wi-Fi advice, or automatic
   pairing on Windows. Automatic stop exists in the engine for both a refused
   gateway check and source device silence, and is unverified on Windows.
4. No signed release package, installer, update path, or ARM64 build.

This app is not production ready. It is the release candidate for the first
real Windows test.
