# iPhone and Mac preview test

This is a draft for the first test of the current preview. It does not establish
that a build is ready. Before using it, review it against the exact signed app,
helper and engine being tested, and record their build identifiers. The iPhone
app must be signed for the device with the selected Apple team. The Mac app must
open its real interface and support pairing without an administrator prompt or
privileged engine. Starting a tunnel is the point where it may ask for an
administrator authorization.

The device owner must approve the phone installation and the live hotspot and
tunnel test before either happens. Explain whether the phone build replaces an
existing app: changing its bundle identifier creates a separate app and does
not carry its stored trust. Keep the installed Mac preview's removal and
recovery instructions available. Do not print or record tokens, identity keys,
authorization forms, or personal traffic.

1. Install the approved signed iPhone build. Unlock the phone and follow its
   trust or Developer Mode prompts if needed. Leave existing app data alone
   unless the owner explicitly requests removal.
2. Enable cellular data and Personal Hotspot on the iPhone. Connect the Mac to
   that hotspot and ensure it is the default route; the Mac app currently uses
   the default interface. Check `route -n get default` and, if needed, adjust
   network service priority or disconnect other interfaces. Open HotspotShade on
   both devices. Start the source proxy on the iPhone and allow Local Network
   access on either device if requested. Keep the iPhone app in the foreground
   with its screen on for the initial test.
3. Confirm that the Mac app opens its real interface and shows source status
   without requesting administrator authorization. Pair the devices. On first
   pairing, compare the displayed code before approving; a previously trusted
   target may pair without a prompt. Record whether pairing succeeds, not the
   code or credentials.
4. Before starting the tunnel, save read-only snapshots from `route -n get default`,
   `netstat -rn -f inet`, `netstat -rn -f inet6`, `ifconfig`, and `scutil --nwi`.
   Verify the installed start right has the expected 30-second timeout. After
   the owner approves the live tunnel test, turn it on in the Mac app, which
   currently supports source device proxy mode. Allow administrator authorization. Check
   that both apps report the expected running state and try a small, ordinary
   web request. Capture diagnostics while the tunnel is running. The current app
   does not expose a TTL audit count; a working page alone does not prove the
   TTL or that all traffic uses the tunnel.
5. Turn the tunnel off in the Mac app, confirm the app reports that it stopped,
   then stop the iPhone proxy. Check the Mac's route and interface state against
   a read-only snapshot taken immediately before starting. If cleanup is
   uncertain or the network does not recover, stop testing and preserve the
   diagnostic message; do not delete routes or state files by guesswork. To
   clear a durable cleanup block on this preview, follow the recovery section
   of `macos/Helper/README.md`: check the routes first, then run the placed
   coordinator's `preview-clear-cleanup-block` as root. Review any
   diagnostic report before sharing it because it may contain destinations.

Record the OS versions, build identifiers, hotspot transport, observed app
states, available TTL evidence, and cleanup result. A pass applies only to that build,
device pair and network; it does not prove background operation, every carrier,
or that other applications cannot bypass the tunnel.

For the current Mac preview, the previous signed delivery remains at
`/Library/Application Support/HotspotShade/local-preview`. The new delivery is
staged separately at `local-preview-unprivileged` under that same directory.
The earlier candidate is at `local-preview-next`. These are staging copies,
not evidence of a running tunnel. Keep the old delivery until replacement and
rollback have been verified. After the owner is finished with the preview, use
the matching coordinator's reviewed removal path for the installed service;
remove the staging copies separately. Preserve the state directory and the
target identity key unless the owner specifically asks to remove them. Never
delete a cleanup marker or a route solely to make a subsequent start succeed.

The coordinator only supports first installation. The existing install on this
Mac uses a zero-second right; a newer coordinator cannot remove that older set.
Do not overwrite the old coordinator. Inspect the state with its `preview-status`
and use that same coordinator's `preview-uninstall` before placing a replacement.
Stop if it reports active work, journals, cleanup blocks, or refuses removal.
Preserve the old delivery and app for rollback. Install matching app, helper,
engine, and right together; do not mix versions. The current signed delivery is
superseded by the authorization fix and must be rebuilt before installation.
