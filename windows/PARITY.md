# Windows prototype parity

This file compares the WinUI 2 prototype with the macOS target app in
`macos/HotspotShadeKit`. The comparison is incomplete by design. The prototype
has no engine. Read `README.md` for the architecture and the limits.

Status values:

- **Matched**: the prototype has the same visible meaning and capability.
- **Partial**: the prototype has the same visible meaning, but a platform limit
  or a missing data source reduces the capability.
- **Different**: the prototype uses a native Windows pattern instead of the
  macOS pattern.
- **Missing**: the prototype does not have the feature.

## Main surface

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| One main window | Sidebar with Dashboard, Activity, and Settings at the bottom | `NavigationView` with Dashboard, Activity, and the built-in Settings item | Matched |
| Settings surface | Separate Settings window with General, Pairing, and Advanced tabs | Settings page with a `Pivot` and the same three tabs | Different |
| Sidebar status mark | A status dot next to Dashboard | Not shown in the sidebar. The Dashboard header shows the mark. | Missing |
| Window frame | Native macOS frame and controls | Native UWP title bar and window controls | Different |
| Minimum size | 780 by 560 | `SetPreferredMinSize` caps at 500 by 500, so 780 by 560 is not enforced. Preferred launch size is 1000 by 720. Responsive layout. | Partial |
| Demo label | Demo mode labels on the Dashboard and Settings | Persistent `InfoBar` on every page, plus labels on Dashboard, Activity, Settings, failures, and reports | Matched |
| Engine start screen | Starting HotspotShade with a retry error | Not present. There is no engine to start. | Different |
| Closing the window | App and menu bar item stay alive | Closing the window closes the app. There is no tray. | Different |

## Dashboard

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Status header | Title, subtitle, status mark, checked time | Same text table, status mark, checked time | Matched |
| Primary action | One main action from the state table | Same action model | Matched |
| Secondary action | Forget, Check now, or Turn off and forget | Same action model | Matched |
| Source device card | One value line and detail lines | Same | Matched |
| Connection card | Tunnel value, ping, connections, last stop | Same, with simulated values | Matched |
| Attention card | Plain lines with optional inline action | Same, with HyperlinkButton actions | Matched |
| Pair hint | Shown in the calm Unpaired state | Same | Matched |
| Status unavailable | No On or Off claim after 10 seconds | Scenario sets the same visible state. No live poll drives it. | Partial |
| Stale status | Line after 3 seconds and Check now | Scenario sets the same visible state. No live poll drives it. | Partial |
| On, source device stopped | Attention line | Scenario sets the same visible state | Matched |
| On, not trusted | Attention line and Turn off | Scenario sets the same visible state | Matched |
| Not trusted | Attention state and Pair again | Same | Matched |
| Waiting for source device | No primary action, Forget available | Same | Matched |
| Error state | Needs attention and Try again | Same | Matched |

## Pairing

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Pairing panel | Replaces the dashboard cards | Replaces the dashboard content | Matched |
| Waiting state | Spinner and waiting text | Spinner and waiting text | Matched |
| Code format | Six digits in two groups | `482 193` | Matched |
| Steps | Three plain steps | Three plain steps | Matched |
| Copy code | Copies the code | Copies the simulated code | Matched |
| Cancel | Stops this pairing | Returns to Unpaired | Matched |
| Source device approval | Real source device approval | Explicit Simulate approval button | Different |
| Pairing failure | Engine failure state | Explicit Simulate a failed pairing button | Different |
| Pairing replacement | A failed attempt keeps the old credentials | Starting a simulated pairing clears the old simulated pairing. | Different |
| Automatic pairing | Starts once per launch and retries every 10 seconds | Missing. There is no engine or source device. | Missing |
| Pairing policy | Cancel, Forget, and rejected token stop automatic pairing | Missing. The demo has no stored policy. | Missing |
| Pairing security | Encrypted pairing and token in engine memory | Missing. No pairing protocol and no credential. | Missing |

## Activity

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Log list | Engine log with time and message | Simulated local list with time and message | Partial |
| Details toggle | Adds level and sequence | Same | Matched |
| Refresh | Reads the engine log | Reloads the local simulated list with a loading state | Partial |
| Empty state | No activity yet | Same | Matched |
| Loading state | Loading activity | Same | Matched |
| Unavailable state | App cannot read activity | Same, tied to the unavailable scenario | Partial |
| Live updates | Polls the engine | Missing. The page does not poll. | Missing |

The Windows preview showed an Activity spacing and row alignment defect. The
layout is updated, but the new layout still needs a visual review with Details
on and off. macOS and Linux behavior is unchanged.

## Settings, General

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Let ping work | Stored in UserDefaults, applies to the next start | Stored in local settings, applies to the next simulated start | Partial |
| Ping status line | From the engine | Simulated line, on or off | Partial |
| Notifications | Permission state and Open System Settings | Text only. No permission request and no toast. | Missing |
| Launch at login | Real login item when the app is signed | Disabled control with an explanation | Missing |
| Appearance | Follows macOS appearance | System, Light, or Dark page theme | Different |

## Settings, Pairing

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Pairing state | Engine state and source device message | Simulated state and message | Partial |
| Pair | Starts real pairing | Starts the simulated pairing and opens Dashboard | Partial |
| Cancel | Cancels real pairing | Cancels the simulated pairing | Partial |
| Forget | Forgets real credentials, blocked while running | Forgets the simulated pairing, blocked while running | Partial |
| Turn off and forget | Stops the tunnel, waits, then forgets | Stops the simulated tunnel after 900 ms, then forgets | Partial |
| Forget result text | Confirmed or not delivered | Confirmed only. Not delivered is not reachable. | Partial |

## Settings, Advanced

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Recent failures | Engine failure groups with Count, Kind, Target, Stage, Reason | Five fixed simulated groups with the same columns | Partial |
| Failure loading | Refresh reads the engine | Refresh shows a loading state then fixed data | Partial |
| Failure empty state | No failed connections yet | Same | Matched |
| Failure unavailable or error | Possible engine states | Enum values exist. No UI path because there is no engine. | Missing |
| Copy report | Copies the engine failure report | Copies a simulated report with example addresses and fixed stage labels | Partial |
| Wi-Fi advice | Reads band and signal while visible | Empty state only. No network read. | Missing |
| App details | Version, macOS version, mode, status | Version, Windows, mode, status, no engine | Partial |
| Copy diagnostics | Relay counters, timing, queues, failures | Simulated summary with no counters or timing | Partial |

## Menu and keyboard

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Native menu bar | macOS menu bar and a menu bar extra | WinUI 2 `MenuBar` inside the window | Different |
| Status menu | Menu bar extra with status and actions | Missing | Missing |
| Section shortcuts | Command 1 and Command 2 | Ctrl+1, Ctrl+2, Ctrl+3 | Different |
| Refresh shortcut | Command R | F5 and Ctrl+K | Different |
| Settings shortcut | Command comma | Ctrl+3 | Different |
| Quit row | Stops the engine before quit | Missing. There is no engine to stop. | Different |
| Menu item enablement | State-dependent | Demo actions are always available. Settings actions use state. | Partial |
| Toolbar refresh spinner | Spinner replaces the icon in place | Spinner replaces the icon and label in the button | Partial |

## Status and notifications

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Poll interval | 1 second visible, 5 seconds hidden | No poll | Missing |
| Freshness windows | 3 seconds stale, 10 seconds unavailable | Scenario only | Partial |
| Source device warning | 10 seconds of continuous failure while running | Scenario only | Partial |
| Notifications | Permission, policy, auto stop, source trouble | Missing | Missing |
| Notification settings | Opens System Settings | Missing | Missing |

## Accessibility and display

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Headings | Combined accessibility labels | Level 1 and level 2 headings on titles and cards | Partial |
| Live status | Accessibility label on the header | Polite live region on the dashboard title and pairing state | Partial |
| Status mark | Hidden from assistive technology | Decorative ellipses hidden with AccessibilityView Raw | Matched |
| Card reading | Cards combine children | Native child reading order. No combined card label. | Different |
| Focus | Native SwiftUI focus | Native WinUI focus visuals | Different |
| Keyboard access | Full keyboard access | Menu accelerators, NavigationView, Pivot, and tab order | Partial |
| Narrator | Not applicable | Not tested | Missing |
| Light and dark | Full | Full for page content. The native title bar and some popups follow the system theme. | Partial |
| High contrast | macOS increase contrast | Theme dictionary with system colors | Partial |
| Text scaling | Dynamic Type | Native text styles and wrapping, not tested at 200 percent | Partial |
| Reduced motion | Respects reduce motion | No custom storyboards. ProgressRing remains. Not tested. | Partial |
| Localization | English strings | English strings | Missing |

## Platform and product

| Area | macOS target app | Windows prototype | Status |
|---|---|---|---|
| Engine | Rust engine inside the app bundle | None | Missing |
| Tunnel | Verified utun tunnel | None. No Wintun, routes, DNS, or IPv6 policy. | Missing |
| Privilege | Administrator prompt for the engine | AppContainer, no elevation | Missing |
| Service boundary | Loopback service with a per-launch descriptor secret | None. An AppContainer cannot use loopback without an exemption. | Missing |
| Automatic stop | Hotspot loss and source device loss | None | Missing |
| Ping | Experimental echo relay | Simulated line only | Missing |
| Package | Signed app bundle | Unsigned UWP debug deployment | Missing |
| Architecture | arm64 | x64 only | Missing |
| Windows CI | Not applicable | No CI job. This prototype is isolated. | Missing |
| Installer and updates | App bundle | None | Missing |
| Production readiness | Prototype, verified on macOS | **Not production ready** | Missing |

## Incomplete parity summary

The prototype is a user interface translation, not a port of the product. The
largest gaps are:

1. No engine and no tunnel.
2. No privileged process or service boundary. UWP cannot hold one.
3. No automatic pairing, poll, notifications, or launch at login.
4. No real diagnostics or failure data.
5. No separate Settings window or menu bar extra.
6. No signed package, installer, localization, ARM64 build, or CI job.
7. A Windows host preview exposed clipped page content. The viewport width
   change needs a new visual review at wide and narrow sizes. Narrator, high
   contrast, text scale, and reduced motion also need review.

The Windows host test must decide whether the visible design is acceptable.
Even a full pass of the manual checklist would not make this prototype
production ready. This prototype is not production ready.
