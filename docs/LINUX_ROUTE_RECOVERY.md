# Linux crash-time route and rule recovery

This note describes the crash gap for the Linux target and the recovery that
`rust/src/platform_linux.rs` now implements. It records what the hermetic tests
cover and what still needs a disposable Linux VM or a live hotspot.

## Source revision and drift

This note was updated against a working tree based on commit `1a37ed7` on
2026-11-05. The platform file read for this note had SHA-256
`1a79e18bebae05dc50ec13b7595581f65e33143254919c2ab901e6df7c4006f7`. This is a
read record, not a current pin. The working tree may change before final
review.

`rust/src/service.rs` changed repeatedly during this update and remains under
active edit. No hash is pinned. The start order below was read from the tree at
the time and may drift; do not treat it as current.

The predecessor-cap and shared-selector passages were re-read separately
against platform file
SHA-256 `1751c938da024133abf8e2422893866840d6f444e793a64f3ec8431129db05c7`.
That partial re-read does not review the rest of the file. The unresolved
findings below may already be under repair.

The selector and IPv6 parser passages were updated separately against
`platform_linux.rs` SHA-256
`ab0ba779030498daef36188edaacf87ec916112d5f6b4a62279c3528825d6c5c`.
That working-tree snapshot is uncommitted and under independent review. It is
not approval for a live start or recovery. Other passages may still reflect
the older snapshots above.

An independent review of that `ab0ba779...` snapshot found a blocking IPv6
parser defect: the kernel's `RTA_CACHEINFO` route-dump attribute was treated as
unmodeled, making the route unclean. The review concluded that this can block
IPv6 block-mode start and prevent cleanup or recovery. A later working-tree
repair, SHA-256
`158a67cad415effef386e7ae4becbde41db319357eb946c68f435aa103650199`,
accepts one 32-byte `RTA_CACHEINFO` attribute without using its contents as
ownership evidence. Its author reports passing hermetic Linux tests using
synthetic replies. An independent review is underway; neither those tests nor
the earlier source review establish behavior in a live VM or approve a start.

The independent review of `158a67...` confirmed the cache-info and preference
layout against kernel source and a read-only route dump. It also found that the
parser ignores a nonzero cache expiry. A foreign expiring route with otherwise
matching fields could therefore be mistaken for a recorded route. The app does
not intentionally create expiring routes. A follow-up repair and review are
required; do not use this snapshot for a live start or recovery. The read-only
dump did not exercise table 700, a tunnel, deletion, or claim recovery.

A later uncommitted follow-up, SHA-256
`26754b616bddb4aebcd5788e3b0c665d1a3c2f5435ba590ade8bfc2bd68a4595`,
uses nonzero cache expiry as negative ownership evidence and keeps the route as
a delete candidate. It also checks the kernel's `RTM_F_CLONED` value `0x200`.
An independent review found that the preceding follow-up had incorrectly used
`0x2`; this revision corrects it and adds literal-value tests. Hermetic tests
also exercise cleanup and stale-claim recovery refusing an expiring or cloned
block route without deleting it. This revision still needs independent review.
The current parser accepts at most one `RTA_CACHEINFO` value of 32 bytes. It
reads the native-endian expiry field at byte offset 8; any nonzero value is
negative ownership evidence. An expiring block route is refused by the start
check and by stale-claim recovery, and cleanup keeps it as a delete candidate
without claiming it is owned.
Zero expiry or an absent cache-info attribute does not prove ownership; kernel
expiry conversion can also round a short remaining lifetime to zero. These
tests do not establish live table 700, tunnel, or power-loss behavior.

An independent re-review confirmed that follow-up's route semantics but found
an unnecessary cast that failed Linux clippy. The later working-tree file
`ff0e8fb3aeb6c88720b9979622809e13e0cdd11ae0fb7d3b4f55a499d7cfdc06`
removes that cast. A fresh network-isolated Linux container run of
`cargo clippy --locked --offline --all-targets -- -D warnings` passed against a
copy of the current tree. It is a compile and lint check, not a live-route
test; the uncommitted source still needs CI and live VM validation.

The working tree had uncommitted changes in both files, so the commit id alone
does not identify what was read. The source is under independent review. A
later edit to either file can invalidate part of this note.

No build, test, VM, or live hotspot run was made for this update. The test
counts below are source counts. The earlier container result is labelled as
earlier evidence.

## The gap

A normal stop removes the routes, the policy rules, the address, and the TUN
device. A crash that skips cleanup, such as `SIGKILL`, closes the TUN
descriptor. The kernel then removes the device, the address, and the
device-bound routes. The policy rules are not bound to the device, so all four
survive:

| Object | IPv4 | IPv6 |
|---|---|---|
| Rule, priority 17000 | `oif <physical> lookup main` | same |
| Rule, priority 17001 | `lookup 700` | same |

In block mode the `2000::/3` blackhole in table 700 also survives, because it
is not bound to the device. The two policy rules then keep selecting table 700
for every unbound socket, so IPv6 stays blocked after the crash. Before this
claim existed, the next start refused while priority 17000 or 17001 was in use,
and an operator had to delete the rules by hand.

## The claim

The route manager writes a small private text file before it adds the first
object. A run removes the file only after the last object it wrote is proven
gone, and a recovered record can stay in the file after its objects are gone:

```
/run/hotspotshade/route-claim
```

The current format is version 3. The header is `hotspotshade-route-claim 3`.
The file holds the kernel boot id, the network namespace device and inode, the
writer pid, the TUN name and index, the outer interface name, and the IPv6
policy. It can also hold up to four `prior` lines. Each `prior` line names a
tunnel name, index, outer interface, and IPv6 policy in the same shape as the
current record. The parser accepts version 2 records with or without
predecessor lines. Version 1 is refused because it has no namespace field. A
run that writes its own record writes version 3.

The encoded shape is:

```
hotspotshade-route-claim 3
boot <uuid>
netns <device> <inode>
pid <pid>
tun <name> <index>
outer <name>
ipv6 block|forward
prior <name> <index> <outer> block|forward
```

A `prior` line can appear up to four times, including in a version 2 record.
The parser skips empty lines and accepts a missing `pid` as zero. The encoder
writes a `pid` line and does not emit empty lines.

The table, priorities, protocol marker, prefixes, and route types are not
stored. They are rebuilt from the module constants (`TUNNEL_TABLE`,
`OUTER_RULE_PRIORITY`, `TUNNEL_RULE_PRIORITY`, `ROUTE_PROTOCOL_ID`, the two
IPv4 `/1` prefixes, and `2000::/3`) for the current record and for every
predecessor. A predecessor can therefore keep an older name, index, outer
interface, or IPv6 policy covered, while the table, priority, protocol, metric,
route type, and prefix still come from the constants. Route and rule keys are
deduplicated across the current and predecessor records. A claim cannot name an
arbitrary table, priority, protocol, metric, route type, or prefix.

The bound is `MAX_CLAIM_PRIORS`, four distinct predecessor records. A
predecessor is distinct by its tunnel name, index, outer interface, and IPv6
policy. A replacement that would need a fifth keeps the newest four only when
recovery completed two consecutive absence reads over the recorded selectors.
Without that evidence, it refuses and leaves the old claim in place. The reads
are evidence, not a guarantee: a kernel dump can repeatedly omit an object.
The current run still adopts all recovered selectors for its own cleanup, but a
crash after replacement can leave a hidden object without its dropped selector
in the claim. There is no approved operator path for resolving such ambiguity.

The properties that bound how the claim is opened and changed:

- The parent directory is created with mode 0700. The file is created with mode
  0600 and no symlink following. The service account must own both. A stricter
  mode is accepted; a group or other permission bit is refused.
- The manager holds an exclusive nonblocking `flock` on the file for the whole
  tunnel lifetime. A live process therefore makes a later start fail with
  `WouldBlock` before it reads or changes any route or rule. The kernel drops
  the lock on any process exit, including `SIGKILL`, so a free lock is the first
  liveness test.
- A free lock alone is not proof that the path names the locked file. Another
  process can unlink the path between the open and the lock, and then the lock
  protects an unlinked inode. After the lock the start compares the device and
  inode of the locked descriptor with the path under the lock and requires
  exactly one link. A second hard link would let another path change the file
  that the lock covers, so it is refused. A mismatch closes the descriptor and
  retries a bounded number of times. A handle on a replaced, unlinked, or
  hard-linked file never becomes the claim.
- The manager removes the claim only when the path still names the file that
  holds the lock. A replacement file that another process made at the path is
  left in place and reported. A compliant peer cannot replace the path while
  the lock is held, because it takes the same lock before it unlinks.
- The claim lives on `/run`, which is normally a tmpfs. A reboot clears the
  claim together with the kernel objects that it describes.
- The complete file is written and synced before the first add. The truncate
  runs after the write, so an interrupted replacement leaves trailing text that
  the strict parser refuses instead of an empty claim. A failed replacement
  restores the previous bytes. If that restore also fails, the manager sets its
  preserve flag, attempts to write the fixed invalid text
  `hotspotshade-route-claim damaged`, and keeps the file. A release does not
  unlink a preserved file, even when the fixed text write also fails. The
  reader accepts at most 4096 bytes; a larger file is invalid. The encoder stays
  well below that bound.
- A process that changes its network namespace or boot identity after it takes
  the claim cannot read or replace the record. `claim_start` and
  `install_verified` refuse and keep the claim.

## Unresolved review findings

Independent review found unresolved safety and availability limits:

- The conservative selector model allows recorded rules at one priority or
  routes at one prefix only when each delete selects one recorded object.
  A block and forward route at the same IPv6 prefix and metric are ambiguous
  and recovery refuses them. The current implementation still needs
  independent review and live kernel evidence.
- The four-predecessor cap now permits compaction after two recovery absence
  reads. A consistently omitted object can still survive after its selector is
  dropped from the durable replacement. Independent review is required.
- Ordinary cleanup and rollback now keep foreign objects with nonzero TOS,
  source fields, or unmodeled attributes in the candidate set. The model also
  treats IPv6 route type as nonselecting and retains nexthop and multipath
  candidates without relying on their output interface. An unknown attribute
  makes a route unclean; IPv6 scope is preserved. These changes need review.
- The IPv6 parser accepts one default `RTA_PREF` byte, rejects duplicates and
  malformed lengths, and marks a nondefault preference unclean. A kernel that
  supplies a nondefault preference for an owned route can block cleanup.

These are unresolved until final code review. An ambiguous selector can leave a
claim that blocks every later start, and the safe clear refuses a valid current
record. A claim blocked by one of these
shapes is not a manual deletion task. Keep the claim and the objects, record the
inspection output, and escalate.

## Recovery

The start takes the claim before it creates the TUN device or changes a link or
route. It reads the file and adopts the objects only when every condition holds:

1. The locked descriptor is still the file at the claim path. The parent
   directory and the file are private to the service account. The file is
   regular, has one link, and is not a symlink.
2. The content parses under version 3 or version 2. A version 2 record with or
   without predecessor lines is accepted. An unknown header, an unknown line, a
   duplicate line, a zero tunnel or predecessor index, `ipv6 inherit`, a
   predecessor with the tunnel name equal to its outer name, a predecessor that
   repeats the current record, a duplicate predecessor, more than four
   predecessor lines, or a TUN name equal to the outer name makes the claim
   invalid. A file larger than 4096 bytes is invalid.
3. The recorded boot id is the current boot id. A kernel object cannot survive a
   reboot, so a claim from an earlier boot is discarded without touching a
   route or a rule.
4. The recorded network namespace is the current network namespace. Netlink
   route and rule state belongs to one namespace, so a claim from another
   namespace is left in place and refused.
5. The lookup of every claimed tunnel name succeeds and proves the name absent,
   and the lookup of every recorded index proves that no interface uses it.
   Only `ENODEV` and `ENXIO` prove absence. Any other lookup error is
   inconclusive. The start already holds the claim before it creates a device,
   so a claimed device that still exists at any index is ambiguous. A free name
   whose recorded index now belongs to another interface is also ambiguous,
   because a recorded route names the index, not the name. This applies to the
   current record and every predecessor. Both the start path and the standalone
   `recover_stale` call refuse these cases.
6. Every live rule at priority 17000 or 17001 is an exact match for one of the
   recorded rules, for its own family. The recorded rules cover the current
   outer interface and every predecessor outer interface. They carry protocol
   196 and the outer rule carries the output interface name. Any other rule at
   those priorities makes the result inconclusive, even if the recorded rules
   are also present. Different recorded outer interfaces can share a priority
   when each encoded delete selector matches only its own rule.
7. Every live route in table 700 is a clean exact match for one of the recorded
   routes. The recorded routes cover the current index and policy and every
   predecessor index and policy. The scope, protocol, type, output interface,
   and metric are compared. Any other route in table 700 makes the result
   inconclusive. Recorded routes can share a prefix only when each modeled
   delete selects its own route. A block and forward route at `2000::/3`
   with the same metric are ambiguous and recovery refuses them.
8. Every read succeeds. A netlink read failure is inconclusive, not an absence.

A read that omits a recorded object is not an absence. Under concurrent churn a
kernel dump can omit a stable route or rule without setting `NLM_F_DUMP_INTR`.
The recovery therefore never deletes a recorded object that the read did not
show, and it never treats one read as proof that the object is gone. It repeats
the read, and it deletes a recorded object only when one read shows an exact
match and a second read of the same key also shows one exact match.

A round counts as an absence round only when it deletes nothing and no read in
it shows a recorded object. That includes the delete confirmation read. A
recorded object that the first read of a round shows and the confirmation read
omits is not deleted, and that round does not count. The recovery succeeds only
after two consecutive absence rounds. Those rounds are evidence, not a
guarantee: a kernel that omits the object on every read can still hide it. A
list that keeps changing, or an object that keeps showing on one read and
vanishing on the next, uses the bounded rounds and then fails closed with the
claim in place.

The first read is all or nothing. An inconclusive first read deletes no object
and leaves the claim in place. A conclusive first read deletes the recorded
routes, then the recorded rules, and reads again. If a later read shows an
unrecorded object, the recovery stops, keeps the claim, and reports the reason.
The objects removed before that read stay removed, and the claim remains the
record for the next start. A failed delete stops the recovery with the
remaining objects still recorded, so the next start can try again. A recorded
object that is genuinely gone stays in the record until the absence rounds
agree. It is never deleted from a key alone.

A successful recovery does not release the claim record. The start never clears
a recovered record: `claim_start` reads the table and both reserved priorities,
but that read is one snapshot and a dump can omit a stable object. It keeps the
file and the lock. Only a replacement write changes the record.

`install_verified` runs the same complete read again. When it shows table 700
and both priorities free, the start builds a record for this run and absorbs the
recovered record, and that record's predecessors, as `prior` lines. The union
is deduplicated and limited to four distinct predecessors. The method writes and
syncs the replacement before the first add. When the install completes every
add, the run ends the recovered state in memory; the file now covers both the
current objects and the predecessor selectors. The ordinary cleanup reads every
key in that union before it removes the claim.

If either read shows an object, the start is refused and the recovered record
stays on disk. If the replacement write fails, the previous bytes are restored;
if that restore also fails, the manager attempts to mark the file damaged and
keeps it. If a later add fails, the rollback uses the same union of current and
predecessor keys, and the file keeps the replacement record. A refused start or
a failed install releases only the lock and keeps the record. A failed cleanup
keeps both the record and the lock in this process until it exits. The next
start adopts the record again under the same exact-match rules. A replacement
that needs a fifth distinct predecessor retains the newest four only after the
two recovery absence reads. The same run adopts the full previous selector set
for cleanup, but the durable replacement cannot retain the dropped selector.

A crash in that window leaves the recovered record or the replacement record,
not an empty file, so the next start can still adopt it. The standalone
`recover_stale` call is not an install: it keeps a non-empty recovered record
after a successful recovery and releases only the lock. It removes only an
empty claim.

The delete request covers every key in the current and predecessor union. A
route delete writes zero TOS and source length without a source attribute; it
also writes the recorded family, destination, table, protocol, type, scope, and
any recorded output interface and metric. The kernel's treatment of all these
fields is not established by the fake-control tests. The rule delete
sends the family, priority, table, action, protocol, and, for the outer rule,
the output interface name. A rule delete by interface name does not fail when
the device is gone: the kernel leaves the name in the rule and compares the
stored name. The fake kernel in the tests models the selectors that the tests
list. It is not evidence that the source comment is complete or that every
source or TOS field is sent.

The selectors are not a creator identity. A foreign object that carries the same
selectors is indistinguishable from the recorded one. The delete request also
carries fewer selectors than the full record: a route's preferred source and
flow class, and a rule's mark, uid range, and other optional selectors, are not
in the request. The model does not assume zero source or TOS narrows the match.
The per-key check requires exactly one clean, fully matching object from its
conservative candidate set. The check reads twice and deletes only when both
reads select one exact recorded match. The read, the comparison, and the delete
are still separate calls. An object that a dump omits on both reads is not seen
by the check, so it can still receive a delete whose selectors match it. A
predecessor selector set has the same limit: a foreign object that reuses an old
index and matches the recorded selectors is indistinguishable from the
predecessor object.

A strict table read treats the table as absent only when the dump ends with
`NLMSG_DONE` carrying `-ENOENT`, the reply held no data message, and no message
carried `NLM_F_DUMP_INTR`. An `NLMSG_ERROR` with `ENOENT`, an `ENOENT` that
follows a data message, or a flagged reply is a failed read, not an empty table.
Even an accepted empty table is a snapshot: a route can appear after it.

The ordinary cleanup uses the same rule over every recorded key, including
predecessor keys adopted at install. It removes the claim only when two
consecutive absence rounds agree that every recorded object is gone, the path
still names the locked file, and the release has no recovered record or
preserved damaged state. A round in which a read showed a recorded object does
not count. If a cleanup failure keeps a record, the claim stays and this
process keeps its lock until it exits. A second start refuses while the process
lives. The kernel releases the lock when the process exits, including on
`SIGKILL`, and the next start can then adopt the record under the same
exact-match rules. A recovered record that no install replaced is kept by the
release, and only the lock is released.

## Adds with an unknown outcome

The manager records each rule and route before it sends the add. The kernel can
apply an add and then lose the answer. The manager therefore separates two
kinds of failure:

- A definite failure drops the record. That is a kernel answer, such as
  `EEXIST`, or a failure before the request left the process: the socket, the
  bind, or the send. The kernel did not apply the add.
- Any other failure has an unknown outcome. That includes an answer timeout, a
  receive or poll error, and a malformed answer. The manager keeps the record
  and does not read the object again to decide. One read that omits the object
  is not proof that the add failed.

The rollback then runs the ordinary cleanup over the current and predecessor
keys. It deletes an object only when two reads show the exact record, and it
drops the record only after the absence rounds. A kept record for an add that
the kernel did not apply costs only those reads.

## Start ordering and the empty claim

`rust/src/platform_linux.rs` owns the claim and the route objects. The Linux
start order is in `rust/src/service.rs`. This section describes that order as it
stands. It is not a change to `service.rs`.

The service first captures physical link evidence. If that read fails, it does
not attempt stale route recovery. If it succeeds, the service retains open
sysfs link and device descriptors and their canonical paths across the steps
below. It compares them again after recovery, before source device
authentication, and during route setup. A changed identity refuses the start.

1. The service creates the route manager for `hs-tun<unit>` and calls
   `claim_start_with_outer`. That call takes the claim lock, recovers a stale
   record, rechecks the retained physical outer identity before every delete of
   a stale object, and reads table 700 and both reserved priorities. A held
   lock, a failed outer recheck, an inconclusive recovery, a used priority, a
   route in table 700, or a failed read refuses the start. No TUN device,
   address, or route exists yet, and the source device token has not left the
   process.
2. The service proves the outer link with a read-only check.
3. In source device proxy mode, the service validates the source device
   destination and runs the authenticated source device check. The token
   leaves the process here.
4. The service opens the TUN device, proves its identity, and adds the link
   address.
5. `install_verified` reads table 700 and both reserved priorities again. It
   refuses if either read shows an object. Otherwise it writes and syncs a
   replacement record that absorbs a recovered record as a predecessor, then
   adds the rules and the routes. A failed write restores the previous bytes or
   attempts to mark the file damaged. A failed add rolls back the recorded
   objects under the ordinary cleanup rule. The file is kept while it holds a
   recovered record or an unproven or preserved state, and removed only after
   the absence rounds.

These checks are snapshots, not an atomic device reservation. A device can
change after a check and before socket binding, token transmission, or a route
operation. The descriptors and inode comparisons do not prove hardware identity
and cannot rule out every kernel or sysfs identity reuse. The link monitor
checks the retained identity; a confirmed change or absence counts as link
loss, while a failed observation remains inconclusive.

The step 1 read is a snapshot. A dump can omit an object, and another process
can add one after the read. Authentication, TUN creation, and address
assignment therefore happen before the step 5 read, which can still refuse the
start. On that refusal the service removes the routes and the link address and
closes the TUN device. Before step 5 writes a replacement, the claim holds no
record of this run. It either holds no record or the recovered record it kept.

The claim file after a refused or failed start:

- An empty claim names no object. The manager holds it while it lives. When
  the service drops the manager, the cleanup finds no record and removes the
  empty file under the lock. The service log carries the refusal reason. The
  file does not.
- A recovered record stays in the file whether the later read succeeds or
  refuses the start. `claim_start` never clears it. `install_verified` replaces
  it only after its own complete read, and the replacement absorbs it as a
  predecessor. A refused start or a failed install releases only the lock and
  keeps a record: the recovered record before the write, or the replacement
  after it.
- A replacement record that this run wrote stays until the cleanup proves every
  current and predecessor object is gone. A failed cleanup keeps the file and
  the lock until the process exits.
- A failed replacement write restores the previous bytes, or attempts to write
  the fixed damaged text and keeps the file when the restore also fails.

An empty claim with no preserved state is never kept as a marker. It holds no
information that a later start could use, and a later start treats an empty
file as clean. A file that a failed write preserved can read as empty and is
still kept, because the write may have lost a record.

## Who can hold the claim lock

The start takes the lock without waiting and does not retry on a held lock. A
running tunnel holds the lock for its whole life. The start holds it through
setup and the tunnel lifetime; the standalone `recover_stale` library call
holds it for the recovery. Two other calls take the same lock for a moment:

- `inspect_route_claim`, which the Linux service status answer runs as
  `route_claim` on every status request. A desktop app that polls the status
  therefore takes the lock briefly on each poll.
- `clear_corrupt_route_claim`.

A start that overlaps a status inspection, a clear, or another recovery is
refused with a held-lock error. That refusal is not proof that a tunnel or
another live owner exists. A later start can succeed. In the same way, a status
answer with `locked: true` can mean that a start, another status request, a
clear, a recovery, or the running tunnel in this same process holds the lock.
It is not proof of a foreign owner.

## Claim inspection and the safe clear

`inspect_route_claim` changes no file, route, or rule. It reports whether the
claim is present, whether a process held the lock at that moment, whether the
file is a private single-link file, whether the content is empty or parses
under version 3 or version 2, the writer pid, and whether the record matches the
current boot and network namespace. On Linux the service status answer carries
this as `route_claim`, with `present`, `locked`, `private`, `usable`,
`same_boot`, `same_namespace`, `stale_pid`, and `problem`. The inspection never
deletes a route, a rule, or the claim. It takes the claim lock for a moment to
read the record, so it can briefly refuse a start. See "Who can hold the claim
lock".

`clear_corrupt_route_claim` is a library function for a claim that cannot
describe a live object. It removes only the claim file, never a route or a
rule. It refuses unless all of these hold:

- No other process holds the claim lock at that moment.
- The path is a regular single-link file, and the locked descriptor is still
  the file at the claim path.
- The content is empty, or it is a valid record from an earlier boot.

A valid record from the current boot and network namespace can still describe a
live object. The clear refuses it even when its owner or mode is wrong; the next
start must recover it. A valid record from another network namespace in the
current boot is left in place. A non-empty file that does not parse, is not
text, or is larger than 4096 bytes may still name live objects, so it is refused
for manual inspection instead of being removed. An empty file is removed even
when its owner or mode is wrong, because it names no object. The single-link
rule still applies. `Service::clear_route_claim` runs the same check and refuses
while a tunnel runs or while cleanup is blocked.

The clear is an inaccessible foundation today. No CLI command, engine API
route, browser GUI control, or Linux desktop app action calls
`Service::clear_route_claim`, so no operator can currently invoke it. Do not
delete the claim file, a route, or a rule by hand as a substitute. A valid
foreign claim from the current boot therefore blocks every later start in this
namespace. `clear_corrupt_route_claim` refuses it and leaves it in place, so
exposing that function would not remove it. A non-empty damaged claim is worse:
the safe clear refuses it by design, so exposing that function would not remove
it either. Treat both as a blocked state to report, not as a manual cleanup
task.

## Refusal cases and the manual fallback

The start or recovery refuses, and leaves all objects in place, when any of
these hold:

- Another process holds the claim lock. A tunnel may be running, or a status
  inspection, a clear, or a recovery may hold the lock for a moment. A later
  start can succeed.
- The claim is damaged, too large, not text, a symlink, a hard link, a FIFO,
  or another special file, or the file or its directory has the wrong owner or
  mode.
- The claim uses version 1 or another header, has more than four predecessor
  lines, a duplicate or malformed predecessor, or a predecessor that repeats
  the current record.
- The claim path does not name the file that this start locked, and the bounded
  retry still cannot obtain a private single-link file at the path. A handle on
  the replaced or unlinked file is dropped. The retry may take the file that the
  path names now. An unlink never removes a replacement that another process
  made.
- The claim names another network namespace.
- A replacement would need a fifth distinct predecessor and the required two
  recovery absence reads have not been established. The old claim is retained.
- Table 700 holds a route that the claim does not record, or a reserved
  priority holds a rule that the claim does not record.
- An encoded delete selector can match more than one live rule or route, or
  matches an object other than the recorded object. Shared priority or prefix
  alone does not require refusal.
- A read fails.
- The lookup of a claimed tunnel name or recorded index fails for any reason
  other than `ENODEV` or `ENXIO`.
- A claimed tunnel name still resolves to a device at any index.
- Another interface now uses a recorded index. The recovery cannot tell whether
  a recorded route would name the crashed tunnel or the new device.
- A replacement write fails and cannot restore the previous bytes. The manager
  attempts to mark the file damaged and keeps it. A damaged non-empty file
  blocks later starts.

A run from a build before the claim existed can leave policy rules with no
claim. That case keeps the old refusal. Inspect both address families and table
700 without changing them:

```sh
ip -4 rule show
ip -6 rule show
ip -4 route show table 700
ip -6 route show table 700
```

Do not delete an object based only on a priority, table, prefix, or a recorded
predecessor: that can match another process's object. There is no approved
manual deletion procedure here. An experienced administrator must compare the
record and current state, and obtain the device owner's approval before any
cleanup. If ownership is uncertain, leave the object in place. Do not flush
table 700. Do not delete the claim file either. A valid foreign claim from the
current boot blocks the start, and `clear_corrupt_route_claim` refuses it and is
not reachable from any shipped interface. A non-empty damaged claim blocks the
start and the safe clear refuses it, because it may name live objects. Record
the inspection output, keep the object and the claim, and escalate to the
maintainer. A later build needs a reviewed procedure before a foreign claim is
cleared. No control can safely remove a damaged claim without an inspection of
the kernel state.

## Proof

The claim tests are in `rust/src/platform_linux.rs`, module
`platform_linux::tests::route_recovery`. The netlink dump-shape tests are in the
parent `platform_linux::tests` module. The claim tests use the in-memory control
layer and a unique temporary claim path. They create no TUN device, change no
route, use no root, and resolve no host interface. The tests cover:

- a forward-mode claim with all four rules and three routes;
- a block-mode claim with the surviving blackhole;
- a partial claim whose missing objects are already clean;
- a recorded route or rule that one complete dump omits, which is deleted on a
  later read and never released from a single read;
- a recorded rule hidden for five consecutive dumps, which survives the start
  and install reads and is caught by the add and the rollback;
- an ordinary cleanup with one omitted route or rule and one with a rule that
  keeps returning;
- a foreign route or rule that appears only on a later read, which keeps the
  claim and the record;
- a foreign rule that appears on the second read before a delete, which blocks
  that delete and leaves both the recorded rule and the foreign rule in place;
- a recorded route that a concurrent writer recreates after every delete, which
  exhausts the bounded rounds and keeps the claim;
- a recorded route that every round shows on its first read and omits on the
  delete confirmation read, in recovery and in the ordinary cleanup, and a
  recorded rule with the same pattern in the cleanup. Each keeps the claim and
  the record, and a later run with complete reads removes the object;
- an add that the kernel applies before its answer times out, where the next
  rule read omits it. The record is kept and the rollback removes the rule;
- the split between a definite add failure and an add with an unknown outcome;
- the parent module's strict absent-table shape (`NLMSG_DONE` with `ENOENT`, no
  data, no interrupt), and its refused shapes: `ENOENT` after a data message,
  `ENOENT` on an interrupted dump, `ENOENT` as `NLMSG_ERROR`, and another
  negative done status;
- a live owner that holds the lock;
- a claim file that another process replaced between the open and the lock, an
  empty replacement, and a replacement that holds a different and non-empty
  record;
- a claim path that another process removed before the lock, so the retry
  creates and locks a fresh empty claim;
- a hard-linked claim file, which is refused and left in place;
- a FIFO at the claim path, which is refused without blocking the start;
- an unlink that would remove a replacement file, and an unlink after the path
  is already gone;
- a device lookup that fails with `EIO` or `EPERM`, and a library
  `NotFound` or `ENOENT` error, all of which are inconclusive;
- a device lookup that fails with `ENODEV` or `ENXIO`, which proves absence;
- a claimed device that still exists, with and without a conclusive lookup;
- a free tunnel name whose recorded index now belongs to another interface, and
  an index lookup that fails for another reason, both of which are refused;
- a claim from another network namespace, which is left in place;
- a claim from an earlier boot, which is discarded without a kernel change;
- a damaged claim, a symlink, a failing read, and a claim directory or file that
  is not private to the service account;
- a foreign route in table 700, a rule with a foreign selector or protocol, and
  a route that disagrees with the claimed policy;
- a refused install or start with an empty claim, which removes the empty file
  when the manager is released;
- a recovery whose reads agree that a route or rule is gone, followed by a
  start or install read that shows it. The start is refused, the recovered
  record stays on disk, and the next start adopts it again;
- a recovery that rechecks the retained outer identity before every delete and
  preserves the claim when the recheck fails;
- a recovered record kept after a successful recovery, after a later start read
  shows an object, after a refused install, and across a repeated
  `claim_start`. `claim_start` never clears it; only the install replacement
  changes it;
- a replacement that absorbs a predecessor with another index and IPv6 policy.
  The cleanup then reads and removes the keys for both records;
- a replacement after the manager's recorded network namespace changed, which is
  refused and leaves the record unchanged;
- a failed replacement write that restores the previous bytes, and a failed
  restore that attempts to write the fixed damaged text, keeps the file, and
  makes the next start and the safe clear refuse it;
- the standalone `RouteManager::recover_stale` call, which keeps a non-empty
  record after recovery;
- the strict claim format, including a version 2 record without predecessors, a
  version 1 record that is refused, a duplicate predecessor line, a zero
  predecessor index, and the current tunnel name used as the outer name;
- the read-only inspection for a current, foreign-namespace, earlier-boot, and
  damaged claim;
- the safe clear for an empty and an earlier-boot claim, and its refusal of a
  damaged, current-boot, foreign-namespace, or live-locked claim;
- two managers that compete for the claim, and a failed cleanup that keeps the
  lock after the manager drops until a modeled process exit releases it;
- the route and rule delete selectors that the tests model, including protocol,
  scope, metric, output interface, and table.

The four-predecessor bound, the strict test helper's refusal to drop a
predecessor without absence evidence, the refusal of a predecessor whose tunnel
name equals its outer name, and the refusal of the current record as its own
predecessor are source rules in `ClaimRecord` and its parser. The production
recovered-record path permits compaction after two absence reads. Source tests
include both compaction and refusal without that evidence; they do not prove
that a kernel dump cannot omit an object.

The source suite includes fake-control cases for different-outer same-priority
rules and refusal of ambiguous block/forward same-prefix routes. Those tests do
not establish live kernel selector behavior. The delete selector tests cover the fields named in
the test model. They do not establish that the source comment lists every field
or that source and TOS are sent.

Local result:

The earlier version of this note recorded a run against an intermediate tree,
before the version 3 predecessor record, the index reuse check, and the
retained recovered record. That run is historical evidence for the recovery
core, not evidence for this revision:

- `cargo check --target x86_64-unknown-linux-gnu --lib --tests --locked` passed
  with the rustup 1.99 toolchain.
- `cargo fmt --manifest-path rust/Cargo.toml -- --check` passed.
- The 44 tests then in `platform_linux::tests::route_recovery` passed in a
  Debian bookworm container with the `rust:1.99-slim-bookworm` image. The
  container used the committed lockfile and an offline cargo registry. It is
  not a disposable Linux VM.
- The same container ran the whole `platform_linux` test module: 178 tests
  passed, 0 failed. The run created no TUN device and changed no route.
- That run also showed a real gap: a foreign rule that differed only in
  `uid_range` was deleted, because the rule delete request does not carry
  `uid_range`. The confirmation read now blocks that delete. The test uses a
  foreign rule with another protocol, a selector the request does carry, so the
  test proves the later-read revalidation rather than relying on the gap.
- `platform_linux.rs` is compiled only for `target_os = "linux"`, so a Windows
  cross-check does not type-check it. The Linux-target check above is the
  applicable gate.

The earlier static read counted 61 `route_recovery` tests and 198 tests in the
file. Those counts describe that older snapshot, not the current source.

For the `ab0ba779...` snapshot, the repair worker reports 221 Linux platform
tests and 1169 library tests passing in a non-root Linux container, plus a
full `cargo test --locked` and clippy run. The fake control layer does not
establish kernel delete semantics. These results have not been independently
reproduced for this documentation update, and concurrent edits elsewhere in
the tree may affect the wider test totals. Independent review is in progress.

That container is not a disposable Linux VM. It is not a hotspot. No TUN
device, policy rule, or table 700 route was created by those tests. The VM
tunnel procedure in `docs/LINUX_TEST_VM.md` still needs a run to confirm the
start, stop, `SIGTERM`, and `SIGKILL` scenarios against a real kernel. A live
hotspot test is still open.

## Limits

- Linux gives a route and a rule no creator identity. The claim is a record
  that this project wrote, not a kernel attestation. A privileged process can
  create the same file and the same objects, including valid predecessor lines.
  The private directory, the lock, the identity check, the exact selectors, and
  the empty-table precondition reduce that risk. They do not prove the creator.
  This is a crash-cleanup aid, not a secure recovery mechanism and not an
  ownership proof.
- A predecessor record is a selector set, not a snapshot of the old objects. It
  keeps an old name, index, outer interface, and IPv6 policy covered so a later
  cleanup can still read those keys. It does not prove that those objects
  existed, that they are gone, or that the old device still has that identity.
- The four-predecessor bound trades retained history for availability after
  two absence reads. A repeatedly omitted object can outlive the selector
  dropped from the durable record, particularly if this run crashes before its
  full in-memory cleanup. Without the two reads the replacement is refused.
  There is no approved operator procedure that proves ownership or resolves
  this ambiguity.
- Shared priorities and prefixes are permitted only when their encoded delete
  selectors distinguish the recorded objects. A selector that can match more
  than one live object remains ambiguous and is not used for deletion. The
  fake-control cases need independent review and live kernel evidence.
- The route delete writes zero TOS and source length without a source attribute.
  The per-key model does not use those fields to exclude foreign candidates.
  It also does not use IPv6 type as a filter, and a nexthop or multipath route
  stays a candidate regardless of output interface. Independent review and a
  disposable-VM comparison against the kernel remain necessary.
- One IPv6 delete can remove ECMP siblings. The model refuses a request with
  multiple visible candidates, but a dump that omits a sibling cannot protect
  that unobserved object. The fake removes one route and does not model ECMP
  sibling deletion.
- A kernel dump can omit a stable route or rule without setting
  `NLM_F_DUMP_INTR`. One complete dump is never proof that an object is absent.
  Two consecutive absence rounds are evidence, not proof: a kernel that omits
  the object on every read can still hide it from the recovery. The delete
  confirmation read has the same limit: it shows that the key looked the
  same on two reads, not that no other object exists at that key. An object
  omitted from every read remains unobserved. Ordinary cleanup or rollback can
  accept two absence rounds and remove the claim while that object remains. A
  delete can also match a foreign object omitted by both confirmation reads.
- The delete selectors are not a creator identity. A foreign object that carries
  the same family, prefix, table, protocol, type, scope, output interface, and
  metric is indistinguishable from the recorded route. A foreign rule with the
  same family, priority, table, action, protocol, and output interface name is
  likewise indistinguishable. The recovery sends a delete only after a read
  shows the exact recorded object, but the kernel matches selectors, not the
  record.
- The read, the comparison, and the delete are not atomic. A privileged process
  can change an object between them, including after a delete.
- The identity check and the unlink are separate calls. A process that ignores
  the lock can replace the path between them. This removes the cooperative race
  between two hotspotshade starts, not an uncooperative privileged process. The
  unlink also does not roll back a replacement that it has already removed. The
  single-link check is a snapshot: a privileged process can add a hard link
  after the check.
- The device lookup and the delete are separate calls. A device can appear or
  disappear between them. The lookup runs once per recovery for each claimed
  name and recorded index, not before every round. An index can be reused after
  the lookup and before a delete. The index reuse check lowers the chance of
  acting on a new device; it does not prove the old device or the index owner.
- The claim is scoped to one boot. Kernel objects do not survive a reboot, so an
  earlier-boot claim is cleared without touching the kernel. A non-tmpfs `/run`
  does not change that: the boot id check still discards the record. For a
  same-boot claim, a recorded object that no read shows stays in the record
  until two absence rounds agree.
- No clear control is reachable from any shipped interface. A valid foreign
  claim from the current boot blocks every later start, and the safe clear
  refuses it. A non-empty damaged claim blocks the start and the safe clear
  refuses it, because it may name live objects. Do not delete the claim by hand.
- The recovery runs on the next start, not at boot and not on a timer. The
  project has no daemon, no boot service, and no automatic restart, so a crash
  leaves the stale rules in place until a person starts the tunnel again.
- The recovery does not touch a higher-priority policy rule, a more-specific
  route in another table, or any object outside table 700 and the two reserved
  priorities. The tunnel is still not fail-closed.
- A second concurrent start is refused by the lock. It cannot merge its
  objects with the first run.
- A cleanup failure keeps the claim lock while the process lives. A person who
  wants a later start to adopt the record before the process exits must stop
  the process first. The safe clear does not touch the recorded objects, so it
  cannot repair a conflicting rule or route.
- A recovered record that no install replaced stays in the file after only the
  lock is released. It is not a reservation of the tunnel name or index. If
  another interface later takes a recorded index, the next start refuses at the
  index reuse check and keeps the claim. The person must wait for the index to
  be free or inspect the record and the kernel state.
- The read-only inspection can report `locked` for this same process when a
  tunnel runs, because the lock is held by the open claim file. That means the
  claim is in use, not that another process owns it.
- A status request takes the claim lock for a moment. A start that overlaps it
  is refused and does not retry. A desktop app that polls the status can
  therefore cause an occasional refusal that does not mean a tunnel runs.
- The start-time precondition read runs before the source device check, the
  TUN device, and the link address. A dump can omit an object on that read, so
  the start can authenticate to the source device and create the TUN device and
  address before the install read refuses it. The service then removes what it
  created. The install read is also a snapshot.
- An add with an unknown outcome keeps its record. If the kernel did not apply
  it, the rollback spends its absence rounds on an object that never existed.
  A foreign object that appears at that key with the same selectors in that
  window is indistinguishable from the recorded one.
- No live test of this revision has run on a real kernel or hotspot. The
  predecessor record, the index reuse check, the retained recovered record, and
  the damaged-claim refusal are read from the source and covered in part by the
  hermetic tests. The unresolved shapes and the repair are under independent
  review. This note does not claim final semantics, safety, or carrier,
  hotspot, or physical-device behavior.
