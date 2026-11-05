# Disposable Linux test VM

A prepared Linux VM image holds the tools for the Linux and Electron checks: Rust, Node.js, GTK, WebKitGTK, Xvfb, and cached dependencies. A disposable clone passed the Linux foundation tests, mock source device tests, direct-mode tunnel tests, and desktop demo tests. These tests do not prove a live Linux hotspot, carrier, or physical-device result.

The image is a test tool, not a release artifact. Its source tree is a point-in-time copy. Refresh it with the reviewed source under test. Do not copy personal files, tokens, identity keys, certificates, provisioning profiles, packet captures, or machine-specific configuration into the VM or image. Review untracked files before including them. The general archive test runner must not create a TUN device or change routes. The tunnel test in the "Linux tunnel start test" section is a separate opt-in run. It creates a TUN device, a network namespace, and policy routes inside the disposable VM.

For a full run against current source, create and review a `.tar.gz` archive whose top level contains `rust/`, `desktop/`, `linux/`, `gui_assets/`, and `assets/`. Include the source and lockfiles required by the build. Exclude `.git`, build artifacts, and all private data. Run:

```sh
scripts/linux_vm_test.sh /path/to/reviewed-source.tar.gz
```

The script creates a private disposable clone through the configured VM provider, copies the reviewed archive, extracts it into a new directory, runs the full Rust tests, Linux clippy, and desktop tests and Linux Electron demo tests offline, and deletes the clone on exit. A failure can leave a clone if the platform cannot delete it. Check the VM list when the script reports a cleanup error. The image must already contain the dependencies needed by the archive. This script does not run a visual webview test. The helper script uses the VM provider configured for the project. If your provider differs, create the clone and run the same checks manually.

Create an isolated clone from the prepared image. Use a unique name for each run. Keep the clone private, and use no network and no SSH when the dependencies are cached. Use the provider console or command runner to inspect the clone. For an offline check with the cached source and dependencies:

```sh
cd ~/hotspotshade/rust
export CARGO_NET_OFFLINE=true
cargo test --locked --lib pairing::tests::
cargo test --locked --lib phone::tests::
cargo test --locked --lib phone_server::tests::
cargo test --locked --lib platform_linux::
cargo test --locked --lib environment_linux::
```

Those filtered tests do not replace the full Linux suite. Run the full suite against the reviewed current source as integration work advances. A Linux desktop visual test needs Xvfb and a window manager; a passing Rust test does not show that the webview displays status.

Delete the clone when the run ends. An ephemeral clone also deletes itself when it stops. The prepared image is separate from a disposable clone. Keep it private. Do not delete the image as part of a disposable test run.

## Linux tunnel start test

This test runs on a disposable Linux VM with root. It changes the kernel routing state inside that VM only. Do not run it on a host that carries other traffic.

### Design

The Linux service start supports direct mode and source device proxy mode. Direct mode has no source device and re-originates each inner IPv4 flow over a normalized outer socket. Source device proxy mode sends each inner flow through the source device proxy. Both modes use a dedicated routing table and two policy rules for each address family.

| Object | Family | Value |
|---|---|---|
| Table | IPv4 and IPv6 | 700 |
| Rule, priority 17000 | IPv4 and IPv6 | `oif <physical> lookup main` |
| Rule, priority 17001 | IPv4 and IPv6 | `lookup 700` |
| Route | IPv4 | `0.0.0.0/1 dev hs-tun<N> table 700 proto 196` |
| Route | IPv4 | `128.0.0.0/1 dev hs-tun<N> table 700 proto 196` |
| Route | IPv6 forward | `2000::/3 dev hs-tun<N> table 700 proto 196 metric 1024` |
| Route | IPv6 block | `2000::/3 blackhole table 700 proto 196 metric 1024` |

The lower priority rule sends every output packet to table 700. The higher priority rule matches only a socket that is bound to the physical interface. Every outer socket sets `SO_BINDTODEVICE` in `rust/src/normalization.rs`. The relay, the source device probe, and the diagnostic sockets therefore use table main and the physical link. The tunnel table never captures an outer socket.

The design uses the output-interface selector instead of a fwmark or a source selector. A fwmark rule needs a mark on every inner packet. The local stack has no path to mark an application packet before the route lookup, and a netfilter rule would add a dependency. A source selector is evaluated before the kernel chooses a source address for an unbound socket, so it does not match local applications. The output-interface selector is the part that separates the bound outer sockets from unbound local traffic. The live VM test uses a non-local source device address so a broken outer rule cannot hide behind the local table.

Do not add the lower priority rule without the `oif` rule. A plain rule also captures the relay's own sockets. The relay then fails because the tunnel route does not name the physical device. A live check with the rules in place must show table main for a lookup with `oif <physical>` and table 700 for an unbound lookup.

### Ownership and cleanup

At install the manager reads the dedicated table and the rule list with netlink. It refuses to start when table 700 has any route or when priority 17000 or 17001 is in use. An empty table and free priorities are the ownership precondition. The manager then creates every object with `NLM_F_CREATE | NLM_F_EXCL`, so a concurrent object makes the add fail. It records the table id, both rule priorities, every rule selector, and every route key before the add.

Cleanup reads each object again and compares it with the record. A rule must match the family, prefix lengths, destination and source addresses, TOS, table, priority, action, rule flags, input and output interface names, goto target, protocol, mark, mark mask, flow, tunnel id, suppress values, l3mdev, uid range, IP protocol, port ranges, port masks, DSCP, DSCP mask, and flow label. An unknown selector blocks the delete. Detached and unresolved rule state bits are not selectors, so cleanup ignores them. A route must match the family, prefix, source length and source, TOS, table, protocol, type, output interface, metric, preferred source, and flow. It must have no gateway, multipath, encapsulation, or nexthop object. For a blackhole route the output interface is not a selector, because the kernel reports the loopback interface for it. A matching object is deleted. An absent object is already clean. A different object at the same key, or a failed read, is left in place, kept in the record, and reported. Stop is idempotent.

An add can be applied before its ACK arrives. When the ACK times out, the manager reads the object list again. It keeps the record only when the object is present and matches the record. The rollback then removes an add that the kernel applied without an answer. A read failure keeps the record for a later cleanup attempt. On a different add error, the manager removes the record because the object was not proven.

An IPv4 route has no metric by default. The kernel gives an IPv6 route the default metric 1024. The manager records 1024 as part of the IPv6 ownership key.

Linux gives a route and a rule no creator identity. A privileged process can create an identical object. The dedicated table, the fixed priorities, the empty-table precondition, and the exclusion adds reduce the risk. They do not prove the creator. The cleanup check and the delete are not atomic. Do not describe the route ownership as complete.

If the physical link is gone before cleanup, the kernel (tested on 6.1) keeps the rule, stores the output interface name, and marks the rule detached. The manager still reads the name, matches the record, and deletes the rule by priority and table. A VM test confirmed this. Do not remove a rule that you cannot match to the record.

The routes point at the TUN device. A crash that closes the descriptor removes the device, its address, and its device-bound routes. The policy rules are not bound to the device. A crash leaves the two rules for each address family, and table 700 stays selected for unbound traffic. In forward mode the table is empty, so the kernel falls through to table main and traffic keeps working. The next start refuses because the priorities are in use. Remove the stale rules before a new start:

```sh
sudo ip rule del priority 17001 table 700
sudo ip rule del priority 17000 table main
```

Run the command for IPv4 and IPv6 as needed. Keep the table id and the priorities in one place: `TUNNEL_TABLE`, `OUTER_RULE_PRIORITY`, and `TUNNEL_RULE_PRIORITY` in `rust/src/platform_linux.rs`.

### IPv6

Direct mode defaults to block and accepts explicit forward. Source device proxy mode always forwards IPv6. The block policy installs one blackhole route in table 700 only. It never changes table main.

The start gate verifies the block policy. It reads table 700 and requires exactly the recorded `2000::/3` blackhole with protocol 196. It sends one fake `RTM_GETROUTE` FIB match for each default probe. The kernel reports a blackhole FIB entry as `EINVAL`, so every probe must get `EINVAL`. A unicast reply or a missing route is a bypass. Another kernel error is inconclusive, not a success. A more-specific route or a higher-priority rule can still bypass the blackhole. Do not describe the block as fail-closed.

The blackhole route has no real output interface. The kernel reports the loopback interface for it. The route ownership key ignores the output interface only when both route types are blackhole. Cleanup still compares the family, prefix, table, protocol, type, metric, preferred source, and flow.

### Test network

The test needs an outer destination that is not a local address. A local destination uses the local table and would hide a broken `oif` rule. The test creates a network namespace and a veth pair:

```
host:  hs-host0  10.213.0.1/24
netns: hs-src0   10.213.0.2/24
```

The mock source device listens on `10.213.0.2`. The engine pins its outer sockets to `hs-host0`. The source device address is not local, so the outer route must come from table main through the `oif` rule. The test removes the namespace, the pair, and every engine object when it ends.

The direct-mode test adds the inner destination `203.0.113.10/32` to the source device namespace and a main-table host route `203.0.113.10/32 dev hs-host0`. An echo server in the namespace listens on that address and port 80. The inner flow from the target device enters the TUN. The outer socket is pinned to `hs-host0` and uses the main-table host route. If the outer socket is not pinned, the policy rule sends it to table 700 and the flow loops back into the TUN and fails. The test therefore proves the pin for this flow.

The link-loss test sets `hs-host0` down. The worker reads the netlink link state and the IPv4 address every 2 seconds. After 20 seconds of continuous loss it stops, removes the routes and device, and records `hotspot_lost`. The test sets the link up again and compares the restored routing state.

### Procedure

Build the test binary and the CLI in the VM:

```sh
cd ~/hotspotshade/rust
cargo build --locked --tests
cargo build --locked
```

Run the serial tunnel tests as root. The binary name has a hash:

```sh
cd ~/hotspotshade/rust
binary=$(find target/debug/deps -maxdepth 1 -type f \
  -name 'linux_tunnel_vm-*' -perm -u+x | sort | tail -1)
sudo -n -E "$binary" --ignored --test-threads=1 --nocapture
```

The reviewed-source workflow wraps these steps:

```sh
scripts/linux_vm_test.sh --tunnel /path/to/reviewed-source.tar.gz
```

The script creates the disposable clone, runs the full suite, builds the engine, runs the tunnel tests as root, checks that no route, rule, link, namespace, or TUN device remains, prints the log, and deletes the clone.

The tunnel suite covers:

- a direct-mode TCP flow through the TUN to an echo server in the source namespace, with an outer TTL audit of 65 and no source device app;
- an IPv6 block start with a verified blackhole in table 700 and a rejected IPv6 probe;
- an explicit IPv6 forward start with the `2000::/3` route to the TUN;
- automatic stop after the physical link goes down, with route, rule, address, and TUN cleanup;
- a source device proxy TCP flow through the TUN to the mock source device, with an outer TTL audit of 65 and one outer connection per inner flow;
- a source device proxy IPv6 TCP flow through the TUN to the mock source device, with a clean TTL audit and one outer connection for the flow;
- a SIGTERM stop that restores the pre-test routes, rules, TUN, and addresses;
- a SIGKILL run that shows the TUN and its address are gone and reports the remaining policy rules.

On 2026-11-05 a disposable Linux VM passed `cargo test --locked` with 733 library tests and every integration test, and the serial ignored suite with 10 tests. The same run left no `hs-tun`, `hs-host0`, `hs-src0`, network namespace, policy rule at priority 17000 or 17001, or route in table 700.

The IPv6 flow uses the source address that the kernel selects on the test host. It does not add an address to the TUN. A host without an IPv6 source address cannot start an inner IPv6 flow. The test proves the TUN, relay, and source device IPv6 path only on a host with IPv6.

The crash test prints the leftover policy rules. A pass requires the empty diff, not only a process exit code.

Clean up the clone after the run. The provider CLI or console can delete it.

## Android build environment

A prepared Linux VM image adds Android command-line tools, SDK platforms and build tools, NDK 30, JDK 21, and four Rust Android targets. It is a build environment. It does not establish Android support or test a real device.

Create a disposable clone with a unique name. Use no network and no SSH when the dependencies are cached. Run the environment check:

```sh
/opt/android-sdk/verify-android-env.sh
```

The prepared environment built a minimal unsigned APK and Rust libraries for four Android architectures without internet access. It has no emulator image or Gradle dependency cache. A build that needs new dependencies requires outbound access. Delete the clone after the build. Do not add credentials, signing keys, or personal data to the image. Refresh the image when its tools or cached dependencies become stale.
