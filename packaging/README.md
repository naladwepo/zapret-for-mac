# packaging — install and remove zapret-mac by hand

This directory holds the reference LaunchDaemon plist and the exact commands the
Makefile runs, so the whole thing can be installed, inspected and removed without
`make`.

Everything below needs `sudo` where shown and nothing else: no SIP change, no
kext, no entitlement, no reboot.

| what | where |
|---|---|
| daemon | `/usr/local/libexec/zapretd` |
| CLI | `/usr/local/bin/zaprctl` |
| data (strategies, lists, fakes, state) | `/Library/Application Support/zapret-mac` |
| LaunchDaemon plist | `/Library/LaunchDaemons/io.zapretmac.zapretd.plist` |
| launchd label | `io.zapretmac.zapretd` (service name `system/io.zapretmac.zapretd`) |
| log | `/var/log/zapret-mac.log`, errors in `/var/log/zapret-mac.err.log` |
| control socket | `/var/run/zapret-mac.sock`, root:admin 0660 |

## io.zapretmac.zapretd.plist

The plist in this directory is the reference copy: `RunAtLoad`, `KeepAlive` as
`SuccessfulExit=false` (restart after a crash, stay down after a clean
`zaprctl stop`), `ProcessType=Interactive` (the datapath must not be CPU-throttled
like a background job) and `ThrottleInterval=10`.

`zapretd install-daemon` generates the same plist from the flags you give it and
lints it with `plutil` before installing — that is the recommended route, and the
only difference from this file is that install-daemon defaults its log to
`/var/log/zapretd.log`. Pass `--log`, `--stdout` and `--stderr` (as in step 4
below) if you want the `zapret-mac.log` paths this reference file uses.

Whatever is installed, the daemon reports the path it believes launchd captures:

```bash
zaprctl status | grep log
```

## Install by hand

### 1. Build

```bash
cd /path/to/zapret-mac
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
for cmd in zapretd zaprctl; do
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o "bin/$cmd" "./cmd/$cmd/"
done
```

### 2. Check what this machine can actually do (optional, recommended)

```bash
sudo ./bin/zaprctl probe
```

`full-parity-possible` means the packet datapath (`divert`) works here.
`proxy-only` means you get the socket-level fallback, which cannot honour
`fake`/`seqovl`/UDP — see what that costs before you install:

```bash
./bin/zaprctl list --transport proxy
./bin/zaprctl explain general --transport proxy
```

### 3. Directories and files

```bash
DATA="/Library/Application Support/zapret-mac"
sudo install -d -m 0755 /usr/local/libexec /usr/local/bin "$DATA" \
  "$DATA/lists" "$DATA/fakes" "$DATA/strategies"
sudo install -d -m 0700 "$DATA/state"

sudo install -m 0755 bin/zapretd /usr/local/libexec/zapretd
sudo install -m 0755 bin/zaprctl /usr/local/bin/zaprctl
sudo install -m 0644 lists/*.txt       "$DATA/lists/"
sudo install -m 0644 fakes/*.bin       "$DATA/fakes/"
sudo install -m 0644 strategies/*.toml "$DATA/strategies/"
```

### 4. Register the daemon

Either let the daemon write and bootstrap the plist (it lints it first, creates
the state directory and boots out an older copy of the job):

```bash
sudo /usr/local/libexec/zapretd install-daemon \
  --plist  /Library/LaunchDaemons/io.zapretmac.zapretd.plist \
  --data   "/Library/Application Support/zapret-mac" \
  --transport divert \
  --allow-vpn \
  --stdout /var/log/zapret-mac.log \
  --stderr /var/log/zapret-mac.err.log \
  --log    /var/log/zapret-mac.log
```

…or install the reference plist yourself:

```bash
sudo install -m 0644 -o root -g wheel \
  packaging/io.zapretmac.zapretd.plist \
  /Library/LaunchDaemons/io.zapretmac.zapretd.plist
sudo plutil -lint /Library/LaunchDaemons/io.zapretmac.zapretd.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.zapretmac.zapretd.plist
sudo launchctl enable system/io.zapretmac.zapretd
```

launchd refuses a plist that is group- or world-writable, which is why the mode
is `0644` and the owner `root:wheel`.

### 5. First run

```bash
zaprctl status          # exits 3 while the daemon is not running
zaprctl list            # strategies, and what this transport cannot honour
sudo zaprctl use general
zaprctl test            # does YouTube/Discord actually open
```

On macOS 13 and newer the job appears in System Settings → General → Login Items
& Extensions, enabled. It is a notification, not a permission prompt.

The daemon patches `/etc/pf.conf` once, adding a marker-delimited block:

```
# >>> zapret-mac >>>
rdr-anchor "zapret-mac"
anchor "zapret-mac"
# <<< zapret-mac <<<
```

Without those two statements pf never evaluates our anchor. A byte-exact backup
goes to `/Library/Application Support/zapret-mac/state/pf.conf.<nanos>.bak` and
the change is recorded in `state/journal.jsonl`, which is what `zaprctl doctor
--repair` and `uninstall-daemon` replay to undo it.

## Remove everything

### The short way

```bash
sudo zaprctl stop                                     # datapath down, pf rules gone
sudo /usr/local/libexec/zapretd uninstall-daemon \
  --plist /Library/LaunchDaemons/io.zapretmac.zapretd.plist \
  --data  "/Library/Application Support/zapret-mac"
sudo rm -f /usr/local/libexec/zapretd /usr/local/bin/zaprctl
sudo rm -rf "/Library/Application Support/zapret-mac"
sudo rm -f /var/log/zapret-mac.log /var/log/zapret-mac.err.log
```

`uninstall-daemon` boots the job out, removes the plist, flushes the anchor,
removes our block from `/etc/pf.conf`, releases the pf reference (`pfctl -X`),
removes our block from `/etc/hosts`, flushes the DNS cache, clears the rollback
journal and deletes a stale control socket. It keeps `--keep-pf` and
`--keep-hosts` for the case where you want those two left alone. It never
deletes the data directory or the log — the two `rm` lines above do that.

### The manual way, step by step

```bash
# 1. stop the datapath (removes the pf rules of our anchor)
sudo zaprctl stop

# 2. remove the /etc/hosts pinning block, if it was ever applied
sudo zaprctl hosts remove

# 3. unload the service AND its anchor guard
sudo launchctl bootout system/io.zapretmac.zapretd
sudo launchctl bootout system/io.zapretmac.zapretd.guard
sudo rm -f /Library/LaunchDaemons/io.zapretmac.zapretd.plist
sudo rm -f /Library/LaunchDaemons/io.zapretmac.zapretd.guard.plist

# 4. pf: flush the anchor, unpatch pf.conf, release our reference
sudo pfctl -a zapret-mac -F all
sudo /usr/bin/sed -i '' '/^# >>> zapret-mac >>>$/,/^# <<< zapret-mac <<<$/d' /etc/pf.conf
sudo pfctl -f /etc/pf.conf
sudo pfctl -X "$(cat '/Library/Application Support/zapret-mac/state/pf.token')"

# 5. binaries, data, logs
sudo rm -f /usr/local/libexec/zapretd /usr/local/bin/zaprctl
sudo rm -f /var/run/zapret-mac.sock
sudo rm -rf "/Library/Application Support/zapret-mac"
sudo rm -f /var/log/zapret-mac.log /var/log/zapret-mac.err.log
```

Step 4 is the one worth reading twice, and the reason to prefer the tool over
`sed`:

```bash
sudo zaprctl doctor --repair
```

With the daemon down it replays the rollback journal, which restores the exact
bytes of `/etc/pf.conf` from the backup instead of deleting lines by pattern, and
releases the pf reference the daemon took with `pfctl -E`. Each `-E` increments a
reference count and only the matching `-X <token>` decrements it; pf stays enabled
while any reference is outstanding. The token is the number in
`state/pf.token` — that is the file the manual `pfctl -X` above reads, and if you
delete the state directory before releasing it the only remaining way to turn pf
off is `sudo pfctl -d`, which disables it for the whole system, other tools
included. So: release first, delete afterwards. Run

```bash
sudo zaprctl doctor
```

afterwards: it exits 0 when nothing of ours is left.

### Verify nothing is left

```bash
launchctl print system/io.zapretmac.zapretd         # should say "Could not find service"
launchctl print system/io.zapretmac.zapretd.guard   # ditto
grep -n zapret /etc/pf.conf /etc/hosts              # should print nothing
sudo pfctl -s Anchors                               # should not list zapret-mac
ls -l /var/run/zapret-mac.sock                      # should not exist
```

## The anchor guard, and the one recovery command

`install-daemon` installs a **second**, tiny launchd job:
`io.zapretmac.zapretd.guard`, plist at
`/Library/LaunchDaemons/io.zapretmac.zapretd.guard.plist`, `StartInterval 5`,
argv `zapretd guard --data "/Library/Application Support/zapret-mac"`.

Why it exists: the divert transport's steering rule is
`pass out quick route-to (utunN 198.18.0.2) ... no state`. The utun exists only
while the daemon's kernel-control socket is open, so it dies with the process — but
the pf rules do not, and xnu's `pf_route()` **drops** a packet whose `route-to`
interface has gone away. A `kill -9` on the daemon therefore black-holes every
outbound connection on the strategy's port window. The guard runs every 5 seconds,
tries to take the daemon's instance lock (`<state>/zapretd.lock`), and if it
succeeds — nobody owns the anchor — flushes it and releases the pf reference.

Skip it with `install-daemon --no-guard` if you would rather not have a periodic
job, and then remember the manual escape hatch, which is also printed in the
daemon's startup banner:

```bash
sudo pfctl -a zapret-mac -F all
```

That empties only our own anchor and always restores normal networking. `sudo
zapretd guard --verbose` does the same thing plus the pf-reference release, and
reports what it found.
