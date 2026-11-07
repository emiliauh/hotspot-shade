# Disposable Linux test VM

**Current transfer gate:** The source snapshot helper and the VM archive
verification path are being repaired after an independent security review.
Do not use the commands below to transfer the current checkout until both
repairs have passed a new independent review and the exact archive and its
contents have been reviewed. The earlier VM results do not establish that the
current dirty checkout was tested.

The latest harness review also found that a shared Cargo target directory can
reuse stale build results and that code under test can forge the fixed status
file. Do not treat a new VM result as evidence until those findings and the
CLI dependency integrity question have been resolved and independently reviewed.
An independent review also reproduced a mismatch between the snapshot
helper's tar header parser and bsdtar on macOS: a crafted numeric field could
hide an entry from the validator. The review found incomplete path-collision
checks as well. The helper must be repaired and reviewed again before its
verification result is trusted.

The independent review of Linux platform source SHA-256 `ab0ba779...` found
that an IPv6 `RTA_CACHEINFO` attribute emitted by the reviewed kernel versions
was treated as unmodeled. That snapshot can refuse block-mode startup and IPv6
cleanup or recovery. Later source repairs for cache information, expiry, and
clone ownership received hermetic review, followed by a lint correction. The
earlier VM results do not test those later bytes. See `LINUX_ROUTE_RECOVERY.md`
for the reviewed snapshots and remaining limits; fresh disposable-VM evidence
is still required for the build under test.

A prepared Linux VM image holds the tools for the Linux and Electron checks: Rust, Node.js, GTK, WebKitGTK, Xvfb, and cached dependencies. A disposable clone passed the Linux foundation tests, mock source device tests, direct-mode tunnel tests, and desktop demo tests. These tests do not prove a live Linux hotspot, carrier, or physical-device result.

The 2026-11-05 preflight found that the prepared image's cached source is stale
and partial: it has no `linux/` directory or Linux helper source. Its Electron
package availability was not verified. The preflight created and deleted
disposable VMs but uploaded no source archive and ran no build or tunnel test.
Those image contents cannot establish results for the current tree.

The image is a test tool, not a release artifact. Its source tree is a point-in-time copy. Refresh it with the reviewed source under test. Do not copy personal files, tokens, identity keys, certificates, provisioning profiles, packet captures, or machine-specific configuration into the VM or image. Review untracked files before including them. The general archive test runner must not create a TUN device or change routes. The tunnel test in the "Linux tunnel start test" section is a separate opt-in run. It creates a TUN device, a network namespace, and policy routes inside the disposable VM.

For a new cloud sandbox, the contributor guide prefers Boat. Its sandboxes have
a public IPv4 address by default, and `boat scp` is a separate transfer path;
neither the Freestyle harness nor its isolated upload checks cover it. Do not
copy this working tree, use a recursive upload, or assume the sandbox is offline.
First review the exact archive and its contents, establish a reviewed transfer
and verification procedure, and confirm the sandbox network and credential
settings. Use `--no-env` to avoid account environment secrets, and explicitly
stop or delete a disposable sandbox after preserving the required evidence.
Boat is Ubuntu; it does not establish native macOS, Windows, or physical
hotspot behavior. See the current [Boat CLI documentation](https://docs.boat.dev/llms.txt).

For a full run against current source, the archive must contain the reviewed
source and lockfiles needed by the build, without `.git`, build artifacts, or
private data. The old one-argument invocation is no longer valid. This guide
requires independently reviewed SHA-256 pins for both the archive (`--sha256`)
and the snapshot helper (`--helper-sha256`). The helper pin can instead be
provided through `HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256`. A digest supplied by
the same untrusted source as its file is not an independent review record. Do
not upload an archive before the gate has passed review.

The script uses Freestyle CLI 0.2.21 to create a private disposable clone,
disables automatic VM restart, copies the reviewed archive, extracts it into a
new directory, runs the full
Rust tests, Linux clippy, desktop tests, and Linux Electron demo tests offline,
and deletes the clone on exit. The CLI version is pinned to keep the lifecycle
commands reproducible. A failure can leave a clone if the platform cannot delete
it. Check the VM list when the script reports a cleanup error. The image must
already contain the dependencies needed by the archive. This script does not
run a visual webview test. If your provider differs, create the clone and run
the same checks manually.

The harness creates its private archive and its pinned helper copy through
unpredictable names and noclobber descriptors, then writes through those
descriptors. A symlink planted at a predictable copy path is therefore not
followed. Cleanup checks each private root first. It refuses to change
permissions through a root that another process replaced with a symlink, unlinks
only that name, and reports a cleanup failure. The remaining races are real: a
same-user process still has the caller's file access, a helper can leave a
background process, a change made and reverted between two hashes is not
visible, and a check and a use are not atomic. This is not a sandbox.

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

Before installing new objects, the manager may recover objects named by an
eligible stale claim. Recovery can remove recorded objects without a prompt
when its ownership checks pass. The subsequent install reads the dedicated
table and rule list with netlink and refuses if table 700 is not empty or
priority 17000 or 17001 is in use. Those reads are snapshots and may omit an
object. The manager creates new objects with `NLM_F_CREATE | NLM_F_EXCL`, so
a concurrent conflicting object makes the add fail. It records the table id,
both rule priorities, every rule selector, and every route key before the add.
The claim and its predecessor records must be reviewed before any live start;
see [LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md).

Cleanup reads each recorded key and requires one clean, fully matching object
in a conservative delete-candidate set. A rule comparison includes its prefix,
TOS, table, priority, action, interface names, protocol, and other modeled
selectors. Unknown attributes block deletion. A route comparison includes its
prefix, source, TOS, table, protocol, type, scope, output interface, metric,
preferred source, and flow; gateway, multipath, encapsulation, nexthop, or an
unmodeled attribute makes it unclean. The candidate model does not rely on
zero TOS or source length to exclude a foreign object. IPv6 delete ignores
route type, and a nexthop object can ignore output interface, so those shapes
remain candidates. A second read must confirm one exact candidate before a
delete. A conflicting candidate or failed read blocks that delete. An absent
object is not deleted, and cleanup requires two complete absence rounds before
dropping its record. This agreement is evidence, not proof: repeated dump
omissions can hide an object, and a read and delete are not atomic. A single
IPv6 delete can also remove ECMP siblings that a dump did not show. See
[LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md) for the current review limits.

An add can be applied before its ACK arrives. The manager records the intended
object before the add and retains that record when the outcome is unknown.
Rollback deletes only a confirmed matching object and uses the same two-round
absence rule. A definite add failure can drop the in-memory object record.
Repeatedly omitted objects can still outlive the claim after cleanup accepts
two absence rounds; no test here proves that cannot happen.

An IPv4 route has no metric by default. The kernel gives an IPv6 route the default metric 1024. The manager records 1024 as part of the IPv6 ownership key.

Linux gives a route and a rule no creator identity. A privileged process can create an identical object. The dedicated table, the fixed priorities, the empty-table precondition, and the exclusion adds reduce the risk. They do not prove the creator. The cleanup check and the delete are not atomic. Do not describe the route ownership as complete.

If the physical link is gone before cleanup, the kernel (tested on 6.1) keeps the rule, stores the output interface name, and marks the rule detached. The manager still reads the name, matches the record, and deletes the rule by priority and table. A VM test confirmed this. Do not remove a rule that you cannot match to the record.

Closing the TUN descriptor removes the device, its address, and its
device-bound routes. The policy rules are not device-bound and can survive a
crash. The IPv6 blackhole is also not device-bound and can survive. A later
start with the route-claim code can remove recorded objects without a prompt if
its recovery checks pass; otherwise it refuses. This behavior still needs an
independent review and a VM crash-recovery test.

Do not delete rules or routes by priority, table, or prefix alone. Those keys
can match objects created by another process. Inspect the recorded claim and
current objects, and stop if ownership is uncertain. Any manual cleanup needs
the device owner's approval. The manual delete examples in
`LINUX_ROUTE_RECOVERY.md` are not approved for use pending their correction.
Keep the table id and priorities in `TUNNEL_TABLE`, `OUTER_RULE_PRIORITY`, and
`TUNNEL_RULE_PRIORITY` in `rust/src/platform_linux.rs`.

### IPv6

Direct mode defaults to block and accepts explicit forward. Source device proxy mode always forwards IPv6. The block policy installs one blackhole route in table 700 only. It never changes table main.

The start gate verifies the block policy. It reads table 700 and requires exactly the recorded `2000::/3` blackhole with protocol 196. It sends one fake `RTM_GETROUTE` FIB match for each default probe. The kernel reports a blackhole FIB entry as `EINVAL`, so every probe must get `EINVAL`. A unicast reply or a missing route is a bypass. Another kernel error is inconclusive, not a success. A more-specific route or a higher-priority rule can still bypass the blackhole. Do not describe the block as fail-closed.

The blackhole route has no real output interface. The kernel reports the
loopback interface for it. The full record comparison handles that blackhole
shape, but the IPv6 delete candidate model does not use route type to separate
a blackhole from a unicast route. A visible conflicting candidate blocks the
delete. The IPv6 parser accepts one default `RTA_PREF` byte and treats a
nondefault value as unclean. These changes still need independent review and
live-kernel verification for the current source snapshot.

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

Build the test binary and the CLI in a fresh target directory in the VM. This
prevents a binary left by an earlier build from being mistaken for the current
source:

```sh
cd ~/hotspotshade/rust
export CARGO_TARGET_DIR="$(mktemp -d /tmp/hotspotshade-cargo.XXXXXXXX)"
cargo build --locked --test linux_tunnel_vm --bin hotspotshade
```

Run the serial tunnel tests as root. The binary name has a hash:

```sh
cd ~/hotspotshade/rust
binary=$(find "$CARGO_TARGET_DIR/debug/deps" -maxdepth 1 -type f \
  -name 'linux_tunnel_vm-*' -perm -u+x)
test -n "$binary" && test "$(printf '%s\n' "$binary" | wc -l | tr -d ' ')" = 1
sudo -n -E env HS_DISPOSABLE_LINUX_VM=1 "$binary" \
  --ignored --test-threads=1 --nocapture \
  --skip linux_vm_mock_source --skip linux_vm_direct_echo
```

The opt-in is a reminder, not an automatic proof that the VM is disposable.
Do not set it on a host with a network configuration that must be preserved.
The run should report eight passing scenarios and two filtered helper entry
points. The scenarios still invoke those helpers as child processes.

The reviewed-source workflow is intended to wrap these steps after the transfer
gate is repaired and reviewed. The old `--tunnel` invocation without digest
arguments is no longer valid; do not use it.

The current `--tunnel` harness is diagnostic only and always reports failure.
The root test process can alter any status file used to report its own result,
so its exit status cannot establish a trusted pass. It attempts to run the
tests and cleanup inside the disposable clone, then deletes the clone. A future
trusted tunnel result needs a separately reviewed result boundary and cleanup
evidence; passing the transfer gate alone would not provide either.

The tunnel suite covers:

- a direct-mode TCP flow through the TUN to an echo server in the source namespace, with an outer TTL audit of 65 and no source device app;
- an IPv6 block start with a verified blackhole in table 700 and a rejected IPv6 probe;
- an explicit IPv6 forward start with the `2000::/3` route to the TUN;
- automatic stop after the physical link goes down, with route, rule, address, and TUN cleanup;
- a source device proxy TCP flow through the TUN to the mock source device, with an outer TTL audit of 65 and one outer connection per inner flow;
- a source device proxy IPv6 TCP flow through the TUN to the mock source device, with a clean TTL audit and one outer connection for the flow;
- a SIGTERM stop that restores the pre-test routes, rules, TUN, and addresses;
- a SIGKILL run that shows the TUN and its address are gone and reports the remaining policy rules.

A start after that SIGKILL can read the private route claim and remove its
recorded objects before installing new ones if every recovery check passes.
Otherwise it refuses. The serial suite does not yet include that recovery
start; the hermetic coverage is in
[LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md). A start from a build before
the claim existed keeps the old refusal.

On 2026-11-05 a disposable Linux VM passed `cargo test --locked` with 733 library tests and every integration test. The route-recovery tests in `platform_linux` were added after that run. The serial ignored suite reported 10 passes: eight tunnel scenarios and two helper entry points that return immediately when not invoked as child processes. The same run left no `hs-tun`, `hs-host0`, `hs-src0`, network namespace, policy rule at priority 17000 or 17001, or route in table 700.

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
