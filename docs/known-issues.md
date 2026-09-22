# Known issues, unverified properties and approximations

This file is the project's integrity record. It lists, without hedging:

1. review findings that were **not** fixed, and why;
2. properties that can only be verified **with root and real traffic**, i.e. every
   claim the automated test suite does *not* back;
3. every place where our behaviour is an **approximation** of nfqws/tpws rather
   than a copy.

It is written to be read by somebody deciding whether to trust this software, so
nothing here is softened. If a statement elsewhere in the repository contradicts
this file, this file is right.

Last updated: the integration pass that applied the two adversarial reviews
(engine/desync/transport correctness + netcfg/daemon/probe safety).

---

## 1. Findings that were NOT fixed

### 1.1 `--wssize` can never reach the SYN (fidelity, MINOR)

`internal/desync/op_misc.go`.

nfqws' `tcp_rewrite_winsize` rewrites the client's advertised window from the
connection's first packet, SYN included — and the window-scale half of
`--wssize=<n>:<shift>` **only exists on the SYN**, because that is where the
option lives. Our plan model has no segment kind meaning "re-emit the intercepted
packet with these header fields changed": the window can only ride a `Seg`, and a
bare SYN with no `syndata` op produces no segment at all. So:

* the window rewrite applies to data packets only;
* the window-scale shift is **unreachable** on every real configuration.

The op says so at runtime (it appends an explicit note to `Plan.Degraded`
explaining that the transport must rewrite the intercepted packet itself), and
`TestWSSizeOnASyn` pins that behaviour. Closing it properly needs a contract
change — a `SegRewrite` kind, or `Plan.RewriteWindow` — which is out of scope for
an integration pass whose remit was "do not change the meaning of the contract
types unless a FATAL finding requires it". **No shipped flowseal strategy uses
`wssize`**, which is why this stayed a documented gap instead of a rushed contract
change.

### 1.2 IPv4 header options are dropped from re-emitted segments (MINOR, partial fix)

`internal/proto/packet.go` builds every IPv4 packet with `out[0] = 0x45`, i.e. a
fixed 20-byte header. The DSCP/ECN byte and the IPv6 traffic class + flow label
**are** now carried through (`Pkt.TrafficClass`, `Pkt.FlowLabel`, asserted by
`TestTrafficClassAndFlowLabelSurvive`), which was the part of the finding with a
real consequence — silently disabling ECN for a connection and making our segments
distinguishable from the ones we forward.

An IPv4 **option block** (record-route, timestamp, IPSec-style options) on a
client's outbound packet is still discarded by a re-emitted segment. This is
untouched because carrying it means variable-length header construction in
`Tmpl.Marshal` plus matching changes in `IPFragment` and `fragmentForMTU`, and
IPv4 options on ordinary client traffic are essentially extinct (most transit
networks drop them). If you rely on them, this transport will break them.

### 1.3 `zaprctl restore-backup` does not exist (MINOR, partial fix)

The reviewer asked for three things about `<state>/backup/`: bound the number of
copies, verify each one, and add a command to restore one. The first two are done
(`maxKeptBackups = 5`, `pruneBackupsLocked`, and the backup is re-read and
byte-compared before the patch proceeds — `TestPruneBackupsKeepsTheNewest`,
`TestBackupPfConfRefusesAConcurrentWriter`).

There is still **no `zaprctl restore-backup`**. Restoring by hand is
`sudo cp <state>/backup/pf.conf.<n>.bak /etc/pf.conf && sudo pfctl -f /etc/pf.conf`.
Note that the automatic restore paths never read a backup file: they restore from
the in-memory original, which is the safer choice and is why a corrupt backup
cannot make a failed patch worse.

### 1.4 One `*Journal` per state directory is a convention, not a mechanism (MINOR, partial fix)

The concrete bug — the daemon and the divert transport each opening their own
journal handle with independently seeded sequence counters, so records collided,
sorted out of write order and one handle's rewrite unlinked the other's file — is
fixed by giving the transport the daemon's `*netcfg.PF` (`divert.Options.PF`,
mirroring `proxy.Options.PF`). There is now exactly one `PF`, and therefore one
journal, in the daemon.

`netcfg.OpenJournal` itself will still hand out two independent handles for the
same directory if two callers ask. Today the only other caller is
`diag.Repair`, which runs when no daemon owns the directory. A package-level
registry keyed by absolute path would make the invariant structural; it was not
added because refcounted `Close` semantics are easy to get subtly wrong and the
remaining exposure is a code path that by construction does not overlap.

### 1.5 `--hostlist-auto` does not implement the failure half (approximation)

See §3.6. The retransmission half is wired end to end and tested; connection-
failure counting (`AutoList.Fail`, nfqws' `--hostlist-auto-fail-threshold`) is
**not** wired, deliberately.

### 1.6 The socket directory is warned about, not refused (MINOR, deliberate deviation)

`internal/ctl/server.go:checkSocketDir`. macOS ships `/var/run` as
`drwxrwxr-x root:daemon`: group-writable and not sticky. A process in group
`daemon` can pre-create `/var/run/zapret-mac.sock` (the daemon then refuses to
start — a denial of service) or replace the socket file after our rename, so
unprivileged clients talk to an impostor.

We **refuse** to bind in a *world*-writable non-sticky directory and only **warn**
loudly about a group-writable one. Refusing on group-writable would make the stock
default path unusable on every Mac, and the exposure is limited to processes
already running as a system group. Closing it entirely is the operator's call:
`--socket <root-owned 0755 dir>/zapret-mac.sock`.

Socket *creation* was already safe and still is: `clearStaleSocket` refuses a path
that exists and is not a socket, and the listener binds at `<path>.tmp` and
renames, so there is no umask window.

### 1.7 RPC arguments are narrowed, not sandboxed (MINOR, partial fix)

`use <name>` from the control socket is now confined to the installed strategies
directory (a path, `..`, or a resolved location outside `<data>/strategies` is
refused), and `test --targets` rejects loopback, link-local, unspecified and
multicast destinations. The `--strategy` **flag** is deliberately not confined:
that is the operator's own argv, not a message from another process.

`test --targets` still accepts arbitrary *public* and RFC 1918 hosts, so any member
of group `admin` can make the root daemon open outbound connections of their
choosing. On macOS `admin` implies `sudo`, so this is not a privilege boundary
being crossed — it is a wider surface than the protocol strictly needs, and it is
left open because probing a LAN host is a legitimate diagnostic.

*Confirmed clean, not merely assumed:* no `exec.Command` anywhere in the tree takes
a shell string; anchor names and pf table names are regex-validated before they
reach argv or a system file; the 32k-entry table load goes through stdin, not argv.

---

## 2. Properties that can only be verified with root and real traffic

The test suite runs **without root and without network access**. Everything below
is therefore *reasoned* and, where possible, *probed by `zaprctl probe` on a real
machine* — but it is not covered by `go test`.

### 2.1 The whole premise of the divert transport

That `pass out quick route-to (utunN peer) ... no state` actually hands an outbound
packet to a `read(2)` on our utun, and that not re-emitting it is a drop. This is
what `zaprctl probe` stage 6 exists to answer, and it needs root plus a real
interface. Nothing in `go test` proves it.

### 2.2 That a BPF write reaches the wire and bypasses pf

`BIOCSHDRCMPLT` plus a raw Ethernet frame write on the uplink. Verified by
`zaprctl probe` stage 7 (it writes a packet and captures it on a second BPF handle).
The *loop-breaking* property — that our own injections do not come back through the
utun — is argued from the fact that a BPF write skips `ip_output` and therefore pf,
and is enforced belt-and-braces by `user { > root }` on the steering rule (forced
on when the SOCK_RAW fallback is in use, because that path *does* traverse pf).
Neither is unit-tested.

### 2.3 That the peer accepts what we build

Every packet this project emits is byte-asserted in `go test` (checksums
recomputed, headers re-parsed, `docs/parity.md` records exact wire images). That
proves the packets are *well formed*. It does not prove that a real server's TCP
accepts them, that a real DPI box is fooled, or that a given strategy works against
a given ISP. Only `zaprctl test` against real hosts answers that.

### 2.4 Every privileged netcfg operation

`pfctl -E` / `-X` reference counting, loading a ruleset into the anchor, `pfctl -T`
table population, `/etc/pf.conf` patch-and-reload, `/etc/hosts` pinning, DNS cache
flush, `route` changes. The tests exercise the *pure* halves — the planner, the
marker stripper, the rule renderer, the journal, the atomic writer, the symlink and
concurrent-writer guards — against temp files, and use `pfctl -n -f` (which works
unprivileged) to parse-check generated rulesets. Anything that changes kernel state
is skipped with an explicit reason.

### 2.5 The dead-man's switch actually firing

`zapretd guard` is unit-testable only in pieces. That it *is* run by launchd every
5 seconds, that it takes the instance lock when the daemon is gone, and that
flushing the anchor restores networking after a `kill -9` — all of that needs root
and a real install. **This is the recovery path for the worst failure mode this
project has**, so it is worth stating plainly:

* the guard job is installed by `zapretd install-daemon` (skip it with
  `--no-guard`, and then accept the consequence);
* the manual escape hatch is printed in the startup banner, in
  `install-daemon`'s epilogue, and here:
  **`sudo pfctl -a zapret-mac -F all`**;
* if the guard job is not installed and the daemon is SIGKILLed, outbound
  connections on the strategy's port window are dropped by pf until something
  runs that command (or the daemon starts again, whose `rollbackPrevious` does it).

### 2.6 The instance lock under launchd

`flock` on `<state>/zapretd.lock` is taken as the first act of `Run`. That it
prevents a hand-started `sudo zapretd --foreground` from rolling back the live
daemon's changes is argued from flock semantics (process-scoped, released by the
kernel on death) and is not covered by a test that starts two daemons.

### 2.7 `SoftResourceLimits` and `StartInterval` in the plist

The XML is rendered deterministically and lint-checked with `plutil` by
`launchd.WritePlist`. That launchd *honours* `SoftResourceLimits.NumberOfFiles` at
4096 for a system daemon, and re-runs the guard every 5 s, is Apple's behaviour, not
ours, and is not asserted anywhere.

---

## 3. Where we approximate nfqws/tpws rather than copy it

### 3.1 `tlsrec` and the length-changing `tamper` knobs are proxy-only

nfqws offers only the length-*preserving* tamper knobs, precisely because
rewriting a packet in place must not move the TCP sequence space. `--tlsrec`,
`--hostdot`, `--hosttab`, `--hostpad`, `--methodspace`, `--methodeol`,
`--unixeol` and `--hostnospace` are tpws (stream relay) features.

Our packet-level transport now **refuses** them and says so in `Plan.Degraded`,
because emitting a different byte count than the client's kernel numbered
desynchronises the connection's sequence space for the rest of its life (the server
ACKs bytes the client never sent, the client discards that ACK, every later segment
lands at the wrong offset, and the retransmission fails identically). The proxy
transport runs them fully. `BuildPlanPackets` additionally refuses any plan whose
real segments do not tile the intercepted payload exactly once, and the datapath
then forwards the application's own packet.

Consequence: a strategy that uses those knobs does *less* on the divert transport
than the same strategy does under tpws. `zaprctl explain <name>` prints exactly
which op is affected.

### 3.2 Profile selection is per-flow, not per-packet

nfqws re-evaluates its `--new` chain per packet and caches into conntrack. We cache
on the flow, and — since this pass — deliberately keep the decision **open** while
the hostname is unknown, so a ClientHello can still reach a hostlist-gated profile
that sits earlier in the chain than an ipset-only one. A provisional match is run
for the current packet but not remembered.

The observable difference from nfqws: while the host is unknown we may run a later
profile's ops on a SYN that nfqws would also have run them on, and once the host is
known the decision is final for the flow's lifetime (nfqws would re-search if its
ctrack entry were evicted).

### 3.3 `--wssize` numbers are passed through unscaled

`Seg.Window` is defined as the TCP window *field*. nfqws' `tcp_rewrite_winsize`
divides the requested window by the scale the connection negotiated, so
`--wssize=<n>:<shift>` yields an *effective* window of `n`. We put `n` in the field,
so against a peer that scales we advertise `n << shift`. Pre-dividing here would
misreport what goes on the wire; the arithmetic belongs to whichever layer knows the
negotiated scale, and that layer does not exist yet. Combined with §1.1, `wssize` is
the least faithful op in the set.

### 3.4 `--ip-id` cannot be expressed for UDP

`desync.Dgram` has no `IPID` field, so a QUIC/Discord profile that sets `--ip-id`
gets a note in `Plan.Degraded` instead of an effect. The datagrams follow Darwin's
own behaviour (a random id per packet, `net.inet.ip.random_id`), which is also what
makes a decoy indistinguishable from real traffic — so the practical loss is small,
but it is a loss.

### 3.5 `multidisorder` under the proxy transport is emulated, not performed

A byte-stream relay cannot hand the kernel out-of-order segments. `Degrade` keeps
the segments in ascending order and marks the first one TTL 1 (tpws' `--disorder`
trick): that copy dies in transit, the later segments arrive first, and the client's
retransmission delivers the head afterwards. The observable order on the wire is the
reversed one; the order in the plan cannot be.

### 3.6 `--hostlist-auto` learns from retransmissions only

Wired end to end as of this pass, and tested (`TestAutoHostlistIsWired`):

* a profile that names `hostlist_auto` treats the learned list as an extra
  inclusion hostlist, so a learned host is desynced from the next packet on;
* a flow whose host is **not** on the list is put in monitor mode — nfqws desyncs
  nothing there either — and its client retransmissions feed
  `AutoList.Retrans`; three of them (nfqws' default threshold) add the host;
* the daemon opens the file, registers it, flushes it every GC interval and at
  shutdown.

**Not implemented:** `AutoList.Fail` / `--hostlist-auto-fail-threshold`, which
counts *connection failures* (reset or no data). Detecting that reliably needs
inbound RST/timeout correlation, and a false positive there adds a host that does
not need desyncing to a persistent on-disk list — a user-visible behaviour change
for an unshipped feature. Retransmission counting is the half nfqws itself calls
"proof the handshake is being dropped", so that is the half we do.

Also: a monitored flow is re-evaluated against the profile chain on every data
packet instead of being fast-pathed. That is correct (the verdict genuinely can
change) but costs more per packet than a settled flow. No shipped strategy uses
`hostlist_auto`, so this costs nothing on a stock install.

### 3.7 Repeat copies are byte-identical

`--dpi-desync-repeats=N` re-emits **one** buffer N times. That matches nfqws (it
builds the fake once and sends it N times); what varies per *desync* is the
`ModifyTLSFake` mutation, and `docs/parity.md` asserts that a second flow gets a
different one. If you expected 6 differently randomised fakes inside one flow, that
is not what either implementation does.

### 3.8 Discord decoys carry no lowered TTL

No flowseal `.bat` sets `--dpi-desync-ttl` on any profile, and neither does any of
the 21 converted `strategies/*.toml`, so `Seg/Dgram.TTL == 0` and the transport uses
the client's own TTL. `docs/parity.md` asserts this at both the wire and the
strategy-source level, so a future strategy that adds a TTL fails the test rather
than silently diverging. In that slot the decoy's harmlessness replaces the short
TTL.

### 3.9 The utun MTU is the uplink's minus 24 bytes

We author every re-emitted packet and write it straight to the link layer, so the
kernel never fragments for us, and `ipfrag1` (+8) and `hopbyhop2` (+16) insert bytes
*after* the application chose its packet size. On IPv6 nothing can be fragmented
after the fact. Capping the utun at `uplinkMTU - 24` makes the application produce
packets that still fit; the cost is 24 bytes of every application's maximum segment
size inside the steered window. nfqws on Linux does not pay this because the divert
socket does not change the path MTU.

### 3.10 Inbound traffic is never steered, so there is no userspace TCP stack

This is the design, not a limitation, but it has one consequence worth naming: the
divert transport cannot do anything that requires *reading* the server's replies in
userspace. Autottl gets its hop count from a read-only BPF tap instead; when that
tap is unavailable it falls back to the midpoint of the allowed TTL range, which is
an estimate, not a measurement, and `zaprctl status` says so.

### 3.11 The proxy transport completes a TCP handshake the `block` op would suppress

At packet level nfqws can drop the SYN. A socket-level relay has already dialled
upstream by the time it sees the first payload (deliberately — a
server-speaks-first protocol could not be relayed otherwise), so `block` closes an
established connection instead of preventing one.

### 3.12 The relay has an idle timeout nfqws has no equivalent of

`Options.RelayIdleTimeout` (default 120 s) tears down a spliced connection that
moves no bytes in either direction. This exists because the pool is bounded and a
stalled peer used to hold a slot for ever; it means a legitimately idle
long-poll/keep-alive connection older than the timeout is closed by us rather than
by either endpoint. Raise it if that matters for your workload.

---

## 4. Test-suite honesty notes

* `go test ./...` and `go test -race ./internal/...` are both clean. Nothing is
  skipped except privileged checks, each with an explicit `t.Skip` reason naming
  the privilege it needs.
* Five engine tests that were `t.Skip`ed as bug reproductions in the previous wave
  are now **active**: the FastPath-on-an-undecided-flow bug, the hostlist profile
  being unreachable after a SYN, the sweep deleting the entry that triggered it, the
  concurrency races, and the unwired `--hostlist-auto`.
* `internal/diag/engine_race_repro_test.go` was an env-gated reproducer; it is now
  an unconditional regression test.
* Two tests were changed because they encoded behaviour that the FATAL finding
  about length-changing rewrites proved wrong:
  `TestTamperLengthChangeIsReportedAtPacketLevel` now asserts that packet level
  *refuses* (and adds a ProxyCaps case asserting it is emitted there), and
  `TestTamperReadsParamsTamper` was moved to `ProxyCaps` because every knob it sets
  changes the payload length. Neither assertion was weakened; both were made
  correct.
* `TestWSSizeCutoff` gained `HaveISN: true` on its three sequence fixtures plus a
  new case for "the SYN was never observed", which is the new guard.
* One pre-existing flake was fixed rather than tolerated: `ctl.Client.LogTail`
  reported `ENOTCONN` from `CloseWrite` as an error when the server had answered
  and closed first.

---

## Update: the pf.conf edit is gone (verified on hardware)

`zaprctl probe` ran on the target machine (macOS 26.5.1, arm64, SIP enabled) with
all ten stages PASS and the verdict `full-parity-possible`. Two things changed as
a result, and one honest caveat was added.

**1. Confirmed, not assumed.** These were previously listed here as "cannot be
verified without root". They now are verified:

| property | evidence from the run |
|---|---|
| `route-to` delivers an outbound packet to our utun fd | stage 6: SYN 192.168.0.99 -> 1.1.1.1, ttl 64, seq 3631706651, read off `utun9` with the `{0,0,0,2}` prefix |
| the packet needs no checksum repair | stage 6: `ip_checksum_already_correct: true`, `tcp_checksum_already_correct: true` |
| a BPF write reaches the NIC and completes the flow | stage 7: 78 bytes to `/dev/bpf1`, own frame seen by a second reader, `stage6_dial_result: COMPLETED` |
| `--ip-id=zero` survives on the BPF path | stage 7: `egress_frame_ip_id: 0x0000` |
| `--ip-id=zero` is impossible on the SOCK_RAW path | earlier run: kernel replaced `ip_id 0` with `0xf7a0`, with `net.inet.ip.rfc6864=1` already set |
| `DIOCNATLOOK` recovers the pre-translation destination | stage 9: recovered `1.1.1.1:443` exactly, struct layout `sizeof=84`, `DIOCNATLOOK=0xc0544417` |

**2. `/etc/pf.conf` is no longer modified at all.** A stock file declares
`anchor "com.apple/*"` and `rdr-anchor "com.apple/*"`; the trailing `/*` makes pf
evaluate every nested sub-anchor, and a sub-anchor is created by the act of
loading rules into it. So rules go into `com.apple/zapret-mac` and are live
immediately. The run proves it: the rule was applied via
`apple-wildcard-subanchor`, stage 6 then passed, and `/etc/pf.conf` was
byte-identical afterwards (same sha256 and mtime).

This removes an entire class of risk that the safety review was built around:
no atomic system-file rewrite, no backup to restore, no drift-versus-backup
question, no window where a half-written `/etc/pf.conf` exists.

**3. The new caveat, stated plainly.** We borrow Apple's anchor namespace.
Nothing observed flushes `com.apple/*` wholesale — services flush their own leaf
anchor — but if something did, our rules would go with it. `PF.Verify` treats a
missing wildcard anchor point as `ErrAnchorUnreferenced` and the daemon reloads,
so the failure is detected rather than silent. The old behaviour is still
available via `PFOpts.ForcePfConfAnchor` for a customised `/etc/pf.conf` that has
no wildcard anchor points.

**Still unverified**, and deliberately so: whether the Discord-voice fake
datagrams actually defeat TSPU, and whether the fake QUIC Initial does. Those are
properties of the censor, not of this machine, and no local test can answer them.
