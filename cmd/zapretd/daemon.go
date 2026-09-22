//go:build darwin

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/ctl"
	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/diag"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/lists"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
	"github.com/naladwepo/zapret-for-mac/internal/transport"
	"github.com/naladwepo/zapret-for-mac/internal/transport/divert"
	"github.com/naladwepo/zapret-for-mac/internal/transport/proxy"
	"github.com/naladwepo/zapret-for-mac/internal/vpn"
)

// ---------------------------------------------------------------------------
// the transport seam
// ---------------------------------------------------------------------------

// transportFactory builds a datapath. The daemon is passed in because each
// implementation needs more than transport.Config describes — the pf anchor, the
// state directory, the exclusion table — and all of that is daemon
// configuration.
type transportFactory func(d *Daemon, cfg transport.Config) (transport.Transport, error)

// transportFactories maps a datapath name to its constructor. It is a map rather
// than a switch so `--transport` validation, the auto-probe order and the
// "what is linked into this build" diagnostics all read from one place.
var transportFactories = map[string]transportFactory{
	transportDivert: func(d *Daemon, cfg transport.Config) (transport.Transport, error) {
		return divert.New(cfg, d.divertOptions())
	},
	transportProxy: func(d *Daemon, cfg transport.Config) (transport.Transport, error) {
		return proxy.NewWithOptions(cfg, d.proxyOptions())
	},
}

// transportNames lists the linked datapaths, sorted.
func transportNames() []string {
	out := make([]string, 0, len(transportFactories))
	for n := range transportFactories {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Transport names.
const (
	transportDivert = "divert"
	transportProxy  = "proxy"
)

// warner is implemented by a transport that collected non-fatal findings while
// starting (a tunnel default route, a degraded injector, an unavailable tap).
// They belong in `zaprctl status`, not only in the log.
type warner interface{ Warnings() []string }

// divertOptions is everything the packet datapath needs beyond transport.Config.
//
// It builds its own netcfg.PF from Anchor+StateDir, so the daemon deliberately
// holds no pf reference of its own: two components taking `pfctl -E` tokens
// against the same state directory would release each other's.
func (d *Daemon) divertOptions() divert.Options {
	return divert.Options{
		Anchor:          d.opts.anchor,
		StateDir:        d.dirs.state,
		PfConfPath:      d.opts.pfConfPath,
		PF:              d.pf,
		ExcludeTable:    divert.DefaultExcludeTable,
		ExcludePrefixes: d.excludePrefixes(),
		// TargetTable stays empty on purpose: the steered set is the strategy's
		// PORT window, exactly as in winws. Restricting it to the ipset would
		// hide every hostlist-matched flow from the engine.
		DryRun: d.opts.dryRun,
		Logf:   d.log.netcfgLogf,
	}
}

// proxyOptions configures the degraded datapath. It accepts the daemon's own PF,
// which is what makes the drift watcher able to compare the loaded ruleset
// against what pf actually holds.
func (d *Daemon) proxyOptions() proxy.Options {
	return proxy.Options{
		Anchor:   d.opts.anchor,
		StateDir: d.dirs.state,
		PF:       d.pf,
		DryRun:   d.opts.dryRun,
		Logf:     d.log.netcfgLogf,
		// Leaving the (empty, inert) anchor statements in /etc/pf.conf across a
		// stop avoids rewriting a system file on every restart; uninstall and
		// `zaprctl doctor --repair` remove them.
		KeepAnchorStatements: true,
	}
}

// excludePrefixes loads flowseal's ipset-exclude lists. Destinations in them are
// never steered into userspace at all, which is both cheaper and safer than
// letting the engine skip them.
func (d *Daemon) excludePrefixes() []netip.Prefix {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	for _, name := range []string{"ipset-exclude.txt", "ipset-exclude-user.txt"} {
		path := filepath.Join(d.dirs.lists, name)
		b, err := os.ReadFile(path)
		if err != nil {
			d.log.Debugf("exclude list %s: %v", path, err)
			continue
		}
		ps, err := netcfg.ParsePrefixList(b)
		if err != nil {
			d.log.Printf("exclude list %s: %v (using the entries that parsed)", path, err)
		}
		for _, p := range ps {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// transportCaps is the capability set each datapath is contractually able to
// provide (see desync.FullCaps / desync.ProxyCaps). The engine and the strategy
// compiler need it BEFORE a transport instance exists, because the transport is
// constructed with the engine already inside it. After construction the real
// Caps() is compared against this and, on a mismatch, everything is rebuilt with
// the real one — an engine gated on the wrong caps would silently run ops the
// wire cannot carry.
func transportCaps(name string) desync.Caps {
	switch name {
	case transportDivert:
		return desync.FullCaps()
	case transportProxy:
		return desync.ProxyCaps()
	}
	return desync.Caps{}
}

// ---------------------------------------------------------------------------
// resolved paths
// ---------------------------------------------------------------------------

// dirs are the directories the daemon reads its data from. Each is resolved
// once at start: <data>/<name> when it exists, otherwise the repository checkout
// the binary was built in, so `sudo ./bin/zapretd --foreground` works before
// `make install` has ever run.
type dirs struct {
	data       string
	strategies string
	lists      string
	fakes      string
	state      string
	hostsSrc   string
	active     string // file remembering the last activated strategy
}

// resolveDirs fills in every path, logging where each came from.
func resolveDirs(o options, log *logger) dirs {
	d := dirs{data: o.dataDir}
	d.state = filepath.Join(o.dataDir, "state")
	d.strategies = findDataDir(o.dataDir, "strategies", log)
	d.lists = findDataDir(o.dataDir, "lists", log)
	d.fakes = findDataDir(o.dataDir, "fakes", log)
	d.active = filepath.Join(d.state, "active-strategy")
	d.hostsSrc = findHostsSource(o.dataDir, log)
	return d
}

// findDataDir prefers <data>/<name>, then the same directory next to (or above)
// the executable, then the working directory.
func findDataDir(dataDir, name string, log *logger) string {
	installed := filepath.Join(dataDir, name)
	if dirHasFiles(installed) {
		return installed
	}
	for _, base := range checkoutRoots() {
		cand := filepath.Join(base, name)
		if dirHasFiles(cand) {
			log.Printf("%s: %s is empty or missing, using the checkout copy %s", name, installed, cand)
			return cand
		}
	}
	// Return the installed path anyway: the error the loader produces then names
	// the directory the user is supposed to populate.
	return installed
}

// findHostsSource locates the hosts file whose entries `zaprctl hosts apply`
// pins. flowseal ships it as service/hosts.
func findHostsSource(dataDir string, log *logger) string {
	cands := []string{filepath.Join(dataDir, "hosts")}
	for _, base := range checkoutRoots() {
		cands = append(cands,
			filepath.Join(base, "hosts"),
			filepath.Join(base, ".upstream", "service", "hosts"))
	}
	for _, c := range cands {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Size() > 0 {
			if c != cands[0] {
				log.Debugf("hosts source: using %s", c)
			}
			return c
		}
	}
	return cands[0]
}

// checkoutRoots lists plausible repository roots: the executable's directory and
// its two parents (bin/ inside a checkout, or PREFIX/libexec), plus the working
// directory.
func checkoutRoots() []string {
	var out []string
	if exe, err := os.Executable(); err == nil {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		dir := filepath.Dir(exe)
		out = append(out, dir, filepath.Dir(dir), filepath.Dir(filepath.Dir(dir)))
	}
	if wd, err := os.Getwd(); err == nil {
		out = append(out, wd)
	}
	return out
}

// dirHasFiles reports whether dir exists and holds at least one regular file.
func dirHasFiles(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

// pfVerifyInterval is how often the drift watcher re-checks pf. Anything that
// runs `pfctl -f /etc/pf.conf` (a macOS update, a VPN client, Internet Sharing)
// silently drops our anchor, and the user's only symptom is that the bypass
// stopped working.
const pfVerifyInterval = 30 * time.Second

// pfRepairCooldown keeps a permanent drift (someone actively fighting us over
// /etc/pf.conf) from turning into a repair loop.
const pfRepairCooldown = 2 * time.Minute

// detectBudget bounds the capability probe run at startup. The probe's own
// default is 6s; this is the ceiling the daemon puts on it so a wedged pfctl
// cannot stall the boot.
const detectBudget = 20 * time.Second

// datapathStartWait and datapathStopWait bound how long the start and stop
// commands wait for the supervisor to reach the requested state. Both are under
// ctl.DefaultTimeout's successor used by the CLI for these commands, so a slow
// datapath produces a precise error instead of a timed-out RPC.
const (
	datapathStartWait = 12 * time.Second
	datapathStopWait  = 10 * time.Second
)

// selftestBudget bounds the whole connectivity self-test, and selftestProbe one
// target inside it. The product of the probe count and selftestProbe has to stay
// under the control socket's SelftestTimeout, or a fully blocked network would
// time out the RPC instead of reporting that everything is blocked.
const (
	selftestBudget = 60 * time.Second
	selftestProbe  = 4 * time.Second
)

// Daemon owns every piece of runtime state. It implements ctl.Handler.
type Daemon struct {
	opts    options
	log     *logger
	dirs    dirs
	started time.Time

	pf    *netcfg.PF
	hosts *netcfg.Hosts

	// wake nudges the supervisor to re-evaluate the desired state.
	wake chan struct{}

	mu      sync.Mutex
	enabled bool // desired datapath state
	running bool // actual datapath state

	strat     *strategy.Strategy
	stratPath string
	eng       *engine.Engine
	fakes     desync.FakeSet

	tr            transport.Transport
	trName        string
	trReason      string
	caps          desync.Caps
	datapathStart time.Time
	lastErr       string
	restarts      int64
	// trChoice is the transport the capability probe picked (or --transport),
	// and detected the probe's full result, kept for `zaprctl caps`/`doctor`.
	trChoice string
	detected diag.Capabilities
	// lastStats keeps the counters of a transport that has gone away, so a
	// restart does not appear to reset the daemon's whole history.
	lastStats ctl.StatsData

	pfDrift      string
	pfVerifiedAt time.Time
	warnings     []string

	// sessionCancel cancels the context of the running datapath session.
	sessionCancel context.CancelFunc
	// flagStrategy is --strategy, remembered separately from opts so nothing
	// mutates the option struct while other goroutines read it.
	flagStrategy string
}

// newDaemon builds a daemon from its options. Nothing is touched until Run.
func newDaemon(o options, log *logger) *Daemon {
	return &Daemon{
		opts:         o,
		log:          log,
		started:      time.Now(),
		wake:         make(chan struct{}, 1),
		flagStrategy: o.strategy,
	}
}

// Run performs startup, serves the control socket and supervises the datapath
// until ctx is cancelled. Every privileged change is undone before it returns.
func (d *Daemon) Run(ctx context.Context) error {
	d.dirs = resolveDirs(d.opts, d.log)
	if err := os.MkdirAll(d.dirs.state, 0o700); err != nil {
		return fmt.Errorf("create state directory %s: %w", d.dirs.state, err)
	}

	// THE FIRST privileged act, before the journal is opened and long before
	// rollbackPrevious touches pf: claim the state directory. Everything below
	// mutates state that is shared per data directory, and the control socket —
	// which used to be the only single-instance guard — is not bound until five
	// steps later. See instance.go.
	lock, err := acquireInstanceLock(d.dirs.state)
	if err != nil {
		return err
	}
	defer lock.Release()

	d.pf = netcfg.NewPF(d.opts.anchor, netcfg.PFOpts{
		PfConfPath: d.opts.pfConfPath,
		StateDir:   d.dirs.state,
		DryRun:     d.opts.dryRun,
		Logf:       d.log.netcfgLogf,
	})
	d.hosts = netcfg.NewHosts(d.opts.hostsPath, d.dirs.state)
	d.hosts.SetLogf(d.log.netcfgLogf)
	d.hosts.SetDryRun(d.opts.dryRun)

	// A previous run that was SIGKILLed may have left a pf token, an anchor
	// ruleset and a patched /etc/pf.conf behind. Undo all of it before touching
	// anything, so we start from a known state instead of stacking a second set
	// of changes on top of a half-applied one.
	d.rollbackPrevious()

	if err := d.pf.Preflight(); err != nil {
		return fmt.Errorf("preflight failed: %w", err)
	}
	pre := d.pf.LastPreflight()
	for _, w := range pre.Warnings {
		d.addWarning(w)
	}
	if pre.VPNActive {
		if d.opts.allowVPN {
			d.log.Printf("split-routing VPN detected on %s; direct targets will be re-emitted through the physical uplink",
				pre.DefaultIface)
		} else {
			d.log.Printf("WARNING: the IPv4 default route goes through a tunnel (%s). "+
				"Configure split routing or disconnect the VPN before starting the datapath.", pre.DefaultIface)
		}
	}
	if len(pre.ForeignAnchors) > 0 {
		d.log.Printf("WARNING: /etc/pf.conf also references foreign pf anchors %v; another network tool may fight us over the ruleset",
			pre.ForeignAnchors)
	}

	// The anchor statements are the one pf change that is not transport specific
	// — both datapaths need them, and so does the capability probe below, which
	// cannot prove steering while a rule loaded into our anchor would never be
	// evaluated. Patching here also gets the /etc/pf.conf reload out of the way
	// before any anchor holds rules, because that reload flushes them.
	if patched, err := d.pf.EnsureAnchorStatements(); err != nil {
		if !d.opts.dryRun {
			return fmt.Errorf("cannot make pf evaluate our anchor %q: %w", d.opts.anchor, err)
		}
		// A dry run cannot even validate the candidate ruleset without /dev/pf,
		// which is exactly the situation --dry-run exists to tolerate.
		d.log.Printf("dry run: cannot check the %s patch (%v); continuing", d.pf.PfConfPath(), err)
	} else if patched {
		d.log.Printf("patched %s so pf evaluates the %q anchor", d.pf.PfConfPath(), d.opts.anchor)
	} else if d.pf.Mode() == netcfg.AnchorModeWildcard {
		// The preferred outcome: our rules live under the wildcard anchor point
		// the stock configuration already declares, so no system file was
		// touched and there is nothing to roll back on this front.
		d.log.Printf("pf anchor %q reached through the wildcard anchor point; %s untouched",
			d.pf.EffectiveAnchor(), d.pf.PfConfPath())
	}
	// Taking the `pfctl -E` reference and loading rules is left to the datapath:
	// it is the component that knows its own ruleset, and a second reference
	// taken here would only fight with its own.
	detectCtx, cancelDetect := context.WithTimeout(ctx, detectBudget)
	d.detectTransport(detectCtx)
	cancelDetect()
	if ctx.Err() != nil {
		d.cleanup()
		return nil
	}

	if err := d.loadActiveStrategy(); err != nil {
		return err
	}

	srv := ctl.NewServer(d, ctl.ServerOpts{
		Path:  d.opts.socketPath,
		Group: d.opts.socketGroup,
		Logf:  func(f string, a ...any) { d.log.Debugf(f, a...) },
	})
	if err := srv.Listen(); err != nil {
		// Refusing to continue is deliberate: a daemon nobody can talk to
		// cannot be stopped cleanly, and two daemons stealing each other's
		// packets is worse than none.
		d.cleanup()
		return fmt.Errorf("control socket: %w", err)
	}
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		if err := srv.Serve(); err != nil {
			d.log.Printf("control socket: %v", err)
		}
	}()

	// The banner goes out before the datapath starts: if starting it wedges or
	// crashes, the log still says exactly what was about to be attempted.
	d.banner()

	d.setEnabled(true)
	superDone := make(chan struct{})
	go func() {
		defer close(superDone)
		d.supervise(ctx)
	}()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		d.watchPF(ctx)
	}()

	<-ctx.Done()
	d.log.Printf("shutting down")

	d.setEnabled(false)
	d.cancelSession()
	_ = srv.Close()
	<-srvDone
	<-superDone
	<-watchDone
	d.cleanup()
	d.log.Printf("stopped")
	return nil
}

// banner logs the one screen an operator needs to trust what is running.
func (d *Daemon) banner() {
	d.mu.Lock()
	strat, path, trName, reason, caps := d.strat, d.stratPath, d.trName, d.trReason, d.caps
	d.mu.Unlock()

	name := "(none)"
	profiles := 0
	var tcp, udp []string
	if strat != nil {
		name, profiles = strat.Name, len(strat.Profiles)
		tcp, udp = portSetStrings(strat.WindowTCP), portSetStrings(strat.WindowUDP)
	}
	if trName == "" {
		// The banner is printed before the datapath starts, so name the one the
		// capability probe chose and keep its reason: that decision is the single
		// most important line in the log.
		trName = d.plannedTransport() + " (starting)"
		if reason == "" && d.opts.transport == "auto" {
			reason = "auto: no probe result yet"
		}
	}
	d.log.Printf("zapret-mac %s starting: pid %d, data %s", version, os.Getpid(), d.dirs.data)
	d.log.Printf("  strategy   %s (%d profiles) from %s", name, profiles, path)
	d.log.Printf("  transport  %s%s", trName, ifNotEmpty(" — ", reason))
	d.log.Printf("  window     tcp %s / udp %s", joinOr(tcp, "none"), joinOr(udp, "none"))
	d.log.Printf("  pf         anchor %q, token %s, conf %s", d.opts.anchor, orNone(d.pf.Token()), d.pf.PfConfPath())
	d.log.Printf("  caps       %s", capsSummary(caps))
	if strat != nil {
		if unsup := strat.Unsupported(caps); len(unsup) > 0 {
			d.log.Printf("  DEGRADED   this transport cannot honour: %s", strings.Join(unsup, "; "))
		}
	}
	d.log.Printf("  control    %s (group %s, mode %#o)", d.opts.socketPath, d.opts.socketGroup, ctl.SocketMode)
	if d.opts.blockQUIC {
		d.log.Printf("  quic       blocked (UDP/443 dropped so browsers fall back to TCP)")
	}
	if d.opts.noExemptRoot {
		d.log.Printf("  direct VPN sockets root-owned traffic included (--no-exempt-root); BPF reinjection bypasses pf")
	}
	if d.opts.dryRun {
		d.log.Printf("  DRY RUN    no privileged change will actually be made")
	}
	// The one line an operator needs when something goes wrong. The pflog
	// transport blocks originals before re-injecting transformed copies, so stale
	// rules must be removed if the process dies. The periodic guard normally does
	// that automatically; this is the manual escape hatch.
	d.log.Printf("  RECOVERY   if connections on the window ports stop working: sudo pfctl -a %s -F all",
		d.pf.EffectiveAnchor())
}

// cleanup reverts everything the daemon still owns. It is safe to call twice and
// runs on every exit path.
func (d *Daemon) cleanup() {
	// Persist anything the self-learning hostlists learned before the process goes
	// away; the datapath flushes them periodically, but the last window's worth of
	// learning would otherwise be lost on every stop.
	d.mu.Lock()
	eng := d.eng
	d.mu.Unlock()
	if eng != nil {
		if err := eng.FlushAutoLists(); err != nil {
			d.log.Printf("persisting a self-learning hostlist failed: %v", err)
		}
	}
	if err := d.pf.FlushRules(); err != nil {
		d.log.Printf("flushing the %q anchor failed: %v (run `sudo zaprctl doctor --repair`)", d.opts.anchor, err)
	}
	if err := d.pf.Release(); err != nil {
		d.log.Printf("releasing the pf reference failed: %v (run `sudo pfctl -X <token>` or `sudo zaprctl doctor --repair`)", err)
	}
	// The anchor statements in /etc/pf.conf are left in place on purpose: an
	// empty anchor is a no-op, and rewriting a system file on every restart is
	// the riskier choice. `zapretd uninstall-daemon` and
	// `zaprctl doctor --repair` remove them.
	if j := d.pf.Journal(); j != nil {
		// Everything reversible has now been reverted, so the next start must not
		// try to undo it again — EXCEPT the /etc/hosts record, which describes a
		// change that deliberately outlives the process ("zaprctl hosts apply").
		// Clearing that one used to make `zaprctl doctor --repair` unable to find
		// the pinned block it is supposed to be able to remove.
		if err := j.ClearExcept(netcfg.StepHosts); err != nil {
			d.log.Debugf("clearing the rollback journal failed: %v", err)
		}
	}
	if err := d.pf.Close(); err != nil {
		d.log.Debugf("closing pf state failed: %v", err)
	}
	if err := d.hosts.Close(); err != nil {
		d.log.Debugf("closing hosts state failed: %v", err)
	}
}

// rollbackPrevious replays the journal of a previous unclean exit.
//
// The hosts block is deliberately NOT reverted: pinning it is an explicit user
// action ("zaprctl hosts apply") that must survive a crash, so its record is
// kept for `zaprctl doctor --repair` instead.
func (d *Daemon) rollbackPrevious() {
	j := d.pf.Journal()
	if j == nil {
		return
	}
	entries, err := j.Entries()
	if err != nil {
		d.log.Printf("cannot read the rollback journal: %v", err)
		return
	}
	if len(entries) == 0 {
		return
	}
	d.log.Printf("a previous run left %d unreverted change(s); rolling them back before starting", len(entries))
	kept := 0
	err = j.Rollback(func(step string, data map[string]string) error {
		switch step {
		case netcfg.StepPfToken:
			token := data["token"]
			if token == "" {
				return nil
			}
			d.log.Printf("rollback: releasing leaked pf reference %s", token)
			if out, rerr := runCmd(netcfg.DefaultPfctlPath, "-X", token); rerr != nil {
				// A token that is already gone is the common case after a
				// reboot; that is success, not failure.
				if strings.Contains(strings.ToLower(out), "not found") ||
					strings.Contains(strings.ToLower(out), "invalid") {
					return nil
				}
				return fmt.Errorf("pfctl -X %s: %w (%s)", token, rerr, strings.TrimSpace(out))
			}
			return nil
		case netcfg.StepPfRules, netcfg.StepPfTable:
			d.log.Printf("rollback: flushing the %q anchor", d.opts.anchor)
			return d.pf.FlushRules()
		case netcfg.StepPfConf:
			d.log.Printf("rollback: removing our statements from %s", d.pf.PfConfPath())
			if rerr := d.pf.RemoveAnchorStatements(); rerr != nil {
				if errors.Is(rerr, netcfg.ErrPfConfDrift) {
					// The block was removed; the file had also been edited by
					// someone else. Report, do not retry.
					d.log.Printf("rollback: %v (our block was still removed)", rerr)
					return nil
				}
				return rerr
			}
			return nil
		case netcfg.StepUtun:
			// A utun exists only while its kernel-control socket is open, so a
			// dead daemon's interface is already gone.
			d.log.Debugf("rollback: utun %s was released with the crashed process", data["iface"])
			return nil
		case netcfg.StepRoute:
			dst, iface := data["dst"], data["iface"]
			if dst == "" {
				return nil
			}
			args := []string{"-n", "delete", dst}
			if iface != "" {
				args = append(args, "-interface", iface)
			}
			d.log.Printf("rollback: deleting route %s", dst)
			if out, rerr := runCmd("/sbin/route", args...); rerr != nil {
				if strings.Contains(strings.ToLower(out), "not in table") {
					return nil
				}
				return fmt.Errorf("route delete %s: %w (%s)", dst, rerr, strings.TrimSpace(out))
			}
			return nil
		case netcfg.StepHosts:
			kept++
			return errKeepJournalEntry
		default:
			d.log.Printf("rollback: unknown journal step %q, leaving it for `zaprctl doctor --repair`", step)
			return fmt.Errorf("unknown step %q", step)
		}
	})
	if kept > 0 {
		d.log.Printf("rollback: kept %d /etc/hosts record(s): the pinned block is a deliberate change, remove it with `zaprctl hosts remove`", kept)
	}
	if err != nil && !onlyKeptEntries(err) {
		d.log.Printf("rollback did not finish: %v; the records are kept for `zaprctl doctor --repair`", err)
	}
}

// errKeepJournalEntry tells Journal.Rollback to keep a record without treating
// it as a failure.
var errKeepJournalEntry = errors.New("record kept on purpose")

// onlyKeptEntries reports whether every rollback failure was a deliberate keep.
func onlyKeptEntries(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	for _, line := range strings.Split(msg, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.Contains(line, errKeepJournalEntry.Error()) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// strategy handling
// ---------------------------------------------------------------------------

// loadActiveStrategy resolves and compiles the strategy the daemon should run,
// with the capabilities of the transport it is about to select.
func (d *Daemon) loadActiveStrategy() error {
	spec := d.currentSpec()
	name := d.plannedTransport()
	s, path, err := d.compileStrategy(spec, transportCaps(name))
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.strat, d.stratPath = s, path
	d.fakes = d.loadFakes()
	d.caps = transportCaps(name)
	d.eng = engine.New(s, d.caps, d.fakes)
	d.mu.Unlock()
	return nil
}

// plannedTransport is the transport the daemon will try first, used to pick the
// caps a strategy is compiled against before anything is running.
func (d *Daemon) plannedTransport() string {
	switch d.opts.transport {
	case transportDivert, transportProxy:
		return d.opts.transport
	}
	d.mu.Lock()
	name, choice := d.trName, d.trChoice
	d.mu.Unlock()
	if name != "" {
		return name
	}
	if choice != "" {
		return choice
	}
	return transportDivert // before the probe has run, assume the full datapath
}

// compileStrategy resolves spec (a name or a path) and compiles it.
func (d *Daemon) compileStrategy(spec string, caps desync.Caps) (*strategy.Strategy, string, error) {
	path, err := d.resolveStrategyPath(spec)
	if err != nil {
		return nil, "", err
	}
	s, err := strategy.Load(path, strategy.LoadOpts{
		ListsDir: d.dirs.lists,
		FakesDir: d.dirs.fakes,
		Caps:     caps,
	})
	if err != nil {
		return nil, path, fmt.Errorf("strategy %s: %w", path, err)
	}
	return s, path, nil
}

// resolveStrategyPath maps "general", "general (ALT2)", "general-alt2" or a
// path to a .toml file on disk. Accepting flowseal's own display spelling
// matters: it is what the user reads in every guide.
func (d *Daemon) resolveStrategyPath(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = DefaultStrategy
	}
	if strings.ContainsRune(spec, os.PathSeparator) || strings.HasSuffix(strings.ToLower(spec), ".toml") {
		if _, err := os.Stat(spec); err == nil {
			return spec, nil
		}
		joined := filepath.Join(d.dirs.strategies, filepath.Base(spec))
		if _, err := os.Stat(joined); err == nil {
			return joined, nil
		}
		return "", fmt.Errorf("strategy file %q not found (also looked in %s)", spec, d.dirs.strategies)
	}

	want := normaliseStrategyName(spec)
	direct := filepath.Join(d.dirs.strategies, want+".toml")
	if _, err := os.Stat(direct); err == nil {
		return direct, nil
	}
	ents, err := os.ReadDir(d.dirs.strategies)
	if err != nil {
		return "", fmt.Errorf("strategy directory %s: %w; install the strategies with `sudo make install`", d.dirs.strategies, err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".toml") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		names = append(names, base)
		if normaliseStrategyName(base) == want {
			return filepath.Join(d.dirs.strategies, e.Name()), nil
		}
	}
	sort.Strings(names)
	return "", fmt.Errorf("no strategy called %q in %s; installed: %s", spec, d.dirs.strategies, joinOr(names, "(none)"))
}

// normaliseStrategyName folds flowseal's display spelling onto the file naming
// convention: "general (ALT2)" and "General-Alt2" both become "general-alt2".
func normaliseStrategyName(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// readActiveName reads the strategy `zaprctl use` last activated.
func (d *Daemon) readActiveName() string {
	b, err := os.ReadFile(d.dirs.active)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeActiveName remembers the activated strategy so a restart keeps it. It is
// data, not a system change, so it needs no journal entry.
func (d *Daemon) writeActiveName(name string) error {
	if err := os.MkdirAll(filepath.Dir(d.dirs.active), 0o700); err != nil {
		return err
	}
	tmp := d.dirs.active + ".tmp"
	if err := os.WriteFile(tmp, []byte(name+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.dirs.active)
}

// defaultFakeFile lists the blob names the engine-wide fallback FakeSet is built
// from. Per-op fakes named in a strategy always win; this set is what an op that
// names none falls back to, mirroring nfqws' built-in defaults.
var defaultFakeFile = struct {
	TLS, QUIC  string
	Discord    []string
	STUN       []string
	UnknownUDP []string
}{
	TLS:        "tls_clienthello_www_google_com.bin",
	QUIC:       "quic_initial_www_google_com.bin",
	Discord:    []string{"ACTIVE_DISCORD_UDP.bin"},
	STUN:       []string{"stun.bin", "stun2.bin"},
	UnknownUDP: []string{"ACTIVE_GAME_UDP.bin"},
}

// loadFakes builds the fallback FakeSet from the fakes directory. A missing blob
// is logged and skipped rather than fatal: only a strategy that actually needs
// it will fail, and then the error names the file.
func (d *Daemon) loadFakes() desync.FakeSet {
	var fs desync.FakeSet
	one := func(name string) []byte {
		if name == "" {
			return nil
		}
		b, err := strategy.LoadFake(d.dirs.fakes, name)
		if err != nil {
			d.log.Debugf("fake %s unavailable: %v", name, err)
			return nil
		}
		return b
	}
	many := func(names []string) [][]byte {
		var out [][]byte
		for _, n := range names {
			if b := one(n); len(b) > 0 {
				out = append(out, b)
			}
		}
		return out
	}
	fs.TLS = one(defaultFakeFile.TLS)
	if len(fs.TLS) == 0 {
		// zapret's built-in ClientHello: "--dpi-desync-fake-tls=!" means this
		// blob, not "no fake", so a TLS fake is always available.
		if b, err := strategy.LoadFake(d.dirs.fakes, "!"); err == nil {
			fs.TLS = b
		}
	}
	fs.QUIC = one(defaultFakeFile.QUIC)
	fs.Discord = many(defaultFakeFile.Discord)
	fs.STUN = many(defaultFakeFile.STUN)
	fs.UnknownUDP = many(defaultFakeFile.UnknownUDP)
	return fs
}

// ---------------------------------------------------------------------------
// supervisor
// ---------------------------------------------------------------------------

// supervise keeps the datapath running while it is enabled, restarting it with
// exponential backoff after a transient failure.
func (d *Daemon) supervise(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if !d.isEnabled() {
			select {
			case <-ctx.Done():
				return
			case <-d.wake:
			}
			continue
		}
		start := time.Now()
		err := d.session(ctx)
		ran := time.Since(start)
		if ctx.Err() != nil {
			return
		}
		if !d.isEnabled() {
			d.log.Printf("datapath stopped on request")
			backoff = time.Second
			continue
		}
		if ran > time.Minute {
			// A datapath that ran for a while and then died is a fresh
			// incident, not an escalating failure.
			backoff = time.Second
		}
		if err != nil {
			d.setLastErr(err.Error())
			d.log.Printf("datapath failed: %v — retrying in %s", err, backoff)
		} else {
			d.log.Printf("datapath exited without an error — retrying in %s", backoff)
		}
		d.mu.Lock()
		d.restarts++
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-d.wake:
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// session runs one datapath instance to completion. It walks the candidate list
// (one entry for an explicit --transport, the detected one plus its fallback for
// auto) and returns when the running datapath's Start returns.
func (d *Daemon) session(parent context.Context) error {
	cands, err := d.candidates()
	if err != nil {
		return err
	}
	var last error
	for i, name := range cands {
		reason := d.selectionReason(name, i)
		tr, s, caps, err := d.build(name)
		if err != nil {
			last = err
			d.log.Printf("cannot start the %s datapath: %v", name, err)
			continue
		}

		ctx, cancel := context.WithCancel(parent)
		d.mu.Lock()
		d.sessionCancel = cancel
		d.mu.Unlock()
		errCh := make(chan error, 1)
		go func() { errCh <- tr.Start(ctx) }()

		// Give Start a moment to fail outright (no utun, no /dev/bpf, port in
		// use) before we conclude anything from a packet counter.
		select {
		case serr := <-errCh:
			cancel()
			_ = tr.Close()
			last = fmt.Errorf("%s datapath: %w", name, serr)
			d.log.Printf("%v", last)
			continue
		case <-ctx.Done():
			cancel()
			<-errCh
			_ = tr.Close()
			return parent.Err()
		case <-time.After(400 * time.Millisecond):
		}

		d.activate(tr, name, reason, s, caps)
		d.log.Printf("datapath %s is running (%s)", name, reason)
		serr := <-errCh
		d.deactivate(tr)
		cancel()
		if cerr := tr.Close(); cerr != nil {
			d.log.Printf("closing the %s datapath: %v", name, cerr)
		}
		if parent.Err() != nil {
			return nil
		}
		return serr
	}
	if last == nil {
		last = errors.New("no datapath could be started")
	}
	return last
}

// candidates returns the transports to try, in order.
//
// For an explicit --transport there is exactly one. For "auto" the first entry is
// what the capability probe concluded (see detectTransport) and, when that is the
// packet datapath, the proxy follows it as a fallback for the case where starting
// it fails outright after all.
func (d *Daemon) candidates() ([]string, error) {
	if len(transportFactories) == 0 {
		// Defensive: transportFactories is a package-level literal, so this can
		// only happen if someone edits it to nothing.
		return nil, errors.New("this build has no datapath linked in; rebuild with internal/transport/{divert,proxy}")
	}
	switch d.opts.transport {
	case transportDivert, transportProxy:
		if _, ok := transportFactories[d.opts.transport]; !ok {
			return nil, fmt.Errorf("--transport %s is not linked into this build (available: %s)",
				d.opts.transport, strings.Join(transportNames(), ", "))
		}
		return []string{d.opts.transport}, nil
	}

	// The packet datapath now has a second interceptor: PF block+log through a
	// dedicated pflog interface.  The legacy capability probe only knows how to
	// test route-to/utun, so a failed steering result must not suppress this new
	// path. Start performs the definitive privileged check and proxy remains the
	// safe fallback.
	return []string{transportDivert, transportProxy}, nil
}

// detectTransport answers "which datapath works on THIS machine" with the
// reversible capability probe in internal/diag, and remembers the answer.
//
// The probe is the real experiment, not an inference: it creates a utun, loads a
// narrow `pass out quick route-to (utunN …)` rule into our (still empty) anchor,
// makes one TCP connect to 198.51.100.7:443 and checks whether the segment
// materialises on the utun file descriptor. It also opens /dev/bpf and writes a
// frame, and reaches DIOCNATLOOK for the proxy fallback. Everything it changes it
// changes back before returning.
//
// It runs BEFORE the datapath and only for --transport auto: an explicit choice
// is honoured without argument, and re-probing on every supervisor restart would
// mean touching pf while the previous rules are still being torn down.
func (d *Daemon) detectTransport(ctx context.Context) {
	if d.opts.transport != "auto" {
		d.mu.Lock()
		d.trChoice = d.opts.transport
		d.trReason = "requested with --transport " + d.opts.transport
		d.mu.Unlock()
		return
	}

	opts := diag.DetectOpts{
		Anchor:     d.opts.anchor,
		PfConfPath: d.opts.pfConfPath,
		Iface:      d.opts.iface,
		UtunUnit:   d.opts.utunUnit,
		Logf:       func(f string, a ...any) { d.log.Debugf(f, a...) },
	}
	if addr, port, ok := parseProbeAddr(d.opts.probeAddr); ok {
		opts.Target, opts.Port = addr, port
	} else if d.opts.probeAddr != "" {
		d.log.Printf("--probe-addr %q is not an IP[:port]; using the default probe target", d.opts.probeAddr)
	}
	caps, err := diag.Detect(ctx, opts)
	if err != nil {
		d.log.Printf("the capability probe failed (%v); trying the packet datapath first anyway", err)
		d.mu.Lock()
		d.trChoice = transportDivert
		d.trReason = "auto: the capability probe failed, trying the packet datapath first"
		d.mu.Unlock()
		return
	}

	d.log.Printf("capability probe: %s", caps.Summary())
	for _, n := range caps.Notes {
		d.log.Printf("  probe: %s", n)
	}
	if caps.TunnelDefaultRoute != "" && !d.opts.allowVPN {
		d.addWarning("the default route goes through " + caps.TunnelDefaultRoute +
			": a full-tunnel VPN carries traffic past the point where we could desync it")
	}

	choice, reason := transportDivert, ""
	switch caps.Transport() {
	case diag.TransportDivert:
		if caps.SteerOK {
			reason = "auto: the probe steered a real segment into " + caps.UtunName +
				" and wrote a frame on " + caps.Iface + " — full winws-class datapath"
		} else {
			reason = "auto: utun and BPF work; steering could not be proven yet (" +
				firstNote(caps.Notes, "no reason recorded") + ") — trying the packet datapath"
		}
	case diag.TransportProxy:
		choice = transportProxy
		reason = "auto: the packet datapath was ruled out by the probe (" +
			firstNote(caps.Notes, "no reason recorded") + "); falling back to the socket-level proxy"
		d.addWarning("running the degraded proxy datapath: fake/rst/seqovl ops of the strategy cannot be honoured")
	default:
		choice = transportProxy
		reason = "auto: the probe could run neither datapath cleanly; trying the proxy, which needs the least"
		d.addWarning("the capability probe could not confirm either datapath: " +
			firstNote(caps.Notes, "see the log"))
	}
	d.mu.Lock()
	d.trChoice, d.trReason, d.detected = choice, reason, caps
	d.mu.Unlock()
	d.log.Printf("transport decision: %s (%s)", choice, reason)
}

// parseProbeAddr accepts "198.51.100.7", "198.51.100.7:443" or a bare ":8443".
// Only a literal address is allowed: the probe has to steer to a destination pf
// can match without a DNS lookup that would itself be steered.
func parseProbeAddr(s string) (netip.Addr, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, 0, false
	}
	host, portStr := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, portStr = h, p
	}
	port := 0
	if portStr != "" {
		v, err := strconv.Atoi(portStr)
		if err != nil || v < 1 || v > 65535 {
			return netip.Addr{}, 0, false
		}
		port = v
	}
	if host == "" {
		// ":8443" keeps the default target and only overrides the port.
		return netip.Addr{}, port, port != 0
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return a, port, true
}

// firstNote returns the first probe note, or fallback when there is none. The
// notes are ordered by the check that produced them, so the first one is the
// earliest thing that went wrong.
func firstNote(notes []string, fallback string) string {
	if len(notes) == 0 {
		return fallback
	}
	return firstLine(notes[0])
}

// selectionReason explains, in the log and in `zaprctl caps`, why this datapath
// is the one running.
func (d *Daemon) selectionReason(name string, idx int) string {
	d.mu.Lock()
	chosen, reason := d.trChoice, d.trReason
	d.mu.Unlock()
	if name == chosen && reason != "" {
		return reason
	}
	if idx > 0 {
		return "fell back to " + name + " after the " + chosen + " datapath could not be started"
	}
	if d.opts.transport != "auto" {
		return "requested with --transport " + d.opts.transport
	}
	return "auto"
}

// build compiles the strategy for name's capabilities, builds a fresh engine and
// constructs the transport.
//
// When the constructed transport reports different capabilities than the
// contract documents, everything is rebuilt once with the real set: the engine's
// caps decide which ops run, so a mismatch would mean planning packets the wire
// cannot carry.
func (d *Daemon) build(name string) (transport.Transport, *strategy.Strategy, desync.Caps, error) {
	caps := transportCaps(name)
	for attempt := 0; attempt < 2; attempt++ {
		spec := d.currentSpec()
		s, path, err := d.compileStrategy(spec, caps)
		if err != nil {
			return nil, nil, caps, err
		}
		d.mu.Lock()
		d.stratPath = path
		fakes := d.fakes
		d.mu.Unlock()
		if len(fakes.TLS) == 0 && len(fakes.QUIC) == 0 {
			fakes = d.loadFakes()
		}
		eng := engine.New(s, caps, fakes)
		d.registerAutoLists(eng, s)

		f := transportFactories[name]
		tr, err := f(d, transport.Config{
			Strategy:           s,
			Engine:             eng,
			Iface:              d.opts.iface,
			UtunUnit:           d.opts.utunUnit,
			TunLocal:           d.opts.tunLocal,
			TunPeer:            d.opts.tunPeer,
			ProxyPort:          d.opts.proxyPort,
			BlockQUIC:          d.opts.blockQUIC,
			ExemptRoot:         !d.opts.noExemptRoot,
			AllowTunnelDefault: d.opts.allowVPN,
			Verbose:            d.opts.verbose,
		})
		if err != nil {
			return nil, nil, caps, fmt.Errorf("build the %s datapath: %w", name, err)
		}
		real := tr.Caps()
		if real == caps || attempt == 1 {
			d.mu.Lock()
			d.strat, d.eng, d.caps, d.fakes = s, eng, caps, fakes
			d.mu.Unlock()
			return tr, s, caps, nil
		}
		d.log.Printf("the %s datapath reports capabilities that differ from its contract (%s); "+
			"rebuilding the engine against what it actually provides", name, capsSummary(real))
		_ = tr.Close()
		caps = real
	}
	return nil, nil, caps, fmt.Errorf("cannot agree on the capabilities of the %s datapath", name)
}

// registerAutoLists opens the --hostlist-auto file of every profile that names one
// and hands it to the engine.
//
// Without this the whole self-learning-hostlist feature was dead code:
// strategy.Filter.AutoHostlist was compiled, engine.SetAutoList existed, and
// nothing ever called it. A list that cannot be opened is a warning, not a fatal
// error — the profile then behaves as if no auto list were configured, which is the
// same as the old behaviour.
//
// No shipped flowseal strategy uses hostlist_auto, so on a stock install this is a
// no-op.
func (d *Daemon) registerAutoLists(eng *engine.Engine, s *strategy.Strategy) {
	if eng == nil || s == nil {
		return
	}
	seen := make(map[string]bool)
	for _, prof := range s.Profiles {
		path := prof.Filter.AutoHostlist
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		al, err := lists.NewAutoList(path)
		if err != nil {
			d.addWarning(fmt.Sprintf("profile %q names hostlist_auto %s, which cannot be opened (%v); "+
				"that profile will match as if no learned list existed", prof.Name, path, err))
			continue
		}
		eng.SetAutoList(path, al)
		d.log.Printf("self-learning hostlist %s registered (%d host(s) already learned)",
			path, al.Set().Len())
	}
}

// currentSpec is the strategy the daemon should (re)load.
//
// The already-resolved path wins, which is what makes `zaprctl use` stick for
// the rest of this process's life even when --strategy was baked into the plist;
// after a restart the flag is authoritative again, as documented on
// install-daemon.
func (d *Daemon) currentSpec() string {
	d.mu.Lock()
	path, flag := d.stratPath, d.flagStrategy
	d.mu.Unlock()
	if path != "" {
		return path
	}
	if flag != "" {
		return flag
	}
	return d.readActiveName()
}

// activate records a running transport.
func (d *Daemon) activate(tr transport.Transport, name, reason string, s *strategy.Strategy, caps desync.Caps) {
	d.mu.Lock()
	d.tr, d.trName, d.trReason = tr, name, reason
	d.strat, d.caps = s, caps
	d.running = true
	d.datapathStart = time.Now()
	d.lastErr = ""
	d.mu.Unlock()
}

// deactivate clears the running transport, keeping its final counters so a
// restart does not appear to reset the daemon's whole history.
func (d *Daemon) deactivate(tr transport.Transport) {
	snap := statsToData(tr.Stats())
	d.mu.Lock()
	if d.tr == tr {
		d.tr = nil
		d.running = false
		d.sessionCancel = nil
	}
	d.lastStats = addStats(d.lastStats, snap)
	d.mu.Unlock()
}

func (d *Daemon) isEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled
}

func (d *Daemon) setEnabled(v bool) {
	d.mu.Lock()
	changed := d.enabled != v
	d.enabled = v
	d.mu.Unlock()
	if changed {
		d.kick()
	}
}

func (d *Daemon) setLastErr(msg string) {
	d.mu.Lock()
	d.lastErr = msg
	d.mu.Unlock()
}

// kick wakes the supervisor without blocking.
func (d *Daemon) kick() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// cancelSession stops the running datapath by closing it; the supervisor sees
// Start return and honours the desired state.
func (d *Daemon) cancelSession() {
	d.mu.Lock()
	tr, cancel := d.tr, d.sessionCancel
	d.mu.Unlock()
	// Both halves are needed and the order matters: cancelling the context is
	// what a transport blocked in poll(2) on its own timeout notices, and Close
	// is what one blocked in accept(2) notices. Neither alone covers both.
	if cancel != nil {
		cancel()
	}
	if tr == nil {
		return
	}
	if err := tr.Close(); err != nil {
		d.log.Debugf("closing the datapath: %v", err)
	}
}

// addWarning records a startup warning shown by `zaprctl status`.
func (d *Daemon) addWarning(w string) {
	if w == "" {
		return
	}
	d.mu.Lock()
	d.warnings = append(d.warnings, w)
	d.mu.Unlock()
}

// ---------------------------------------------------------------------------
// pf drift watcher
// ---------------------------------------------------------------------------

// watchPF re-verifies pf periodically and repairs what it can. A macOS update,
// a VPN client or Internet Sharing reloading /etc/pf.conf silently removes our
// anchor, and without this the bypass would just quietly stop working.
func (d *Daemon) watchPF(ctx context.Context) {
	t := time.NewTicker(pfVerifyInterval)
	defer t.Stop()
	var lastRepair time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// Only meaningful while a datapath is up: with it stopped the anchor is
		// deliberately empty, and reporting that as drift would be noise.
		if !d.isEnabled() || !d.isRunning() {
			continue
		}
		err := d.pf.Verify()
		d.mu.Lock()
		d.pfVerifiedAt = time.Now()
		if err == nil {
			d.pfDrift = ""
		} else {
			d.pfDrift = firstLine(err.Error())
		}
		d.mu.Unlock()
		if err == nil {
			continue
		}
		d.log.Printf("pf drift detected: %v", err)
		if time.Since(lastRepair) < pfRepairCooldown {
			d.log.Printf("skipping the repair: the last one was %s ago and something keeps reverting it",
				ctl.FormatDuration(time.Since(lastRepair)))
			continue
		}
		lastRepair = time.Now()
		d.repairPF(err)
	}
}

// repairPF re-applies whatever drifted.
//
// Everything pf-side belongs to the datapath — the anchor statements in
// /etc/pf.conf, the `pfctl -E` reference and the rules themselves — so the repair
// is a datapath restart. That also re-creates the utun and re-arms the injector,
// which is what a ruleset flush usually takes down with it.
func (d *Daemon) repairPF(cause error) {
	switch {
	case errors.Is(cause, netcfg.ErrPfDisabled):
		d.log.Printf("pf was disabled by something else; restarting the datapath to take a fresh reference")
	case errors.Is(cause, netcfg.ErrAnchorUnreferenced):
		d.log.Printf("%s no longer references the %q anchor (an OS update or a VPN reloaded it); "+
			"restarting the datapath to re-patch and reload", d.pf.PfConfPath(), d.opts.anchor)
	case errors.Is(cause, netcfg.ErrRulesDrift):
		d.log.Printf("our anchor's rules were replaced; restarting the datapath to reload them")
	default:
		d.log.Printf("restarting the datapath to reconcile pf")
	}
	if !d.isEnabled() {
		d.log.Printf("the datapath is stopped, so nothing is repaired; `zaprctl start` when you want it back")
		return
	}
	d.cancelSession()
	d.kick()
}

// ---------------------------------------------------------------------------
// ctl.Handler
// ---------------------------------------------------------------------------

// Version reports the running build.
func (d *Daemon) Version() (ctl.VersionData, error) {
	exe, _ := os.Executable()
	return ctl.VersionData{
		Version: version,
		Go:      runtime.Version(),
		PID:     os.Getpid(),
		Started: d.started.Format(time.RFC3339),
		Binary:  exe,
	}, nil
}

// Status assembles the whole state in one pass.
func (d *Daemon) Status() (ctl.StatusData, error) {
	d.mu.Lock()
	strat, path, trName, reason := d.strat, d.stratPath, d.trName, d.trReason
	running, enabled := d.running, d.enabled
	dpStart, warnings, lastErr := d.datapathStart, append([]string(nil), d.warnings...), d.lastErr
	drift, verified := d.pfDrift, d.pfVerifiedAt
	d.mu.Unlock()
	caps, capWarn := d.liveCaps()
	warnings = append(warnings, capWarn...)

	st := ctl.StatusData{
		Version:         version,
		PID:             os.Getpid(),
		Running:         running,
		Transport:       trName,
		TransportReason: reason,
		StrategyPath:    path,
		UptimeSec:       time.Since(d.started).Seconds(),
		Stats:           d.statsSnapshot(),
		IPSet:           ctl.IPSetUnknown,
		BlockQUIC:       d.opts.blockQUIC,
		LogPath:         d.opts.logPath,
		DataDir:         d.dirs.data,
	}
	if st.Transport == "" {
		// Name the transport that WOULD run rather than "(none)": the caps and
		// the unsupported-op list below describe it, and "(none)" would make
		// them look like they describe nothing.
		st.Transport = d.plannedTransport() + " (not running)"
	}
	if running && !dpStart.IsZero() {
		st.DatapathUptimeSec = time.Since(dpStart).Seconds()
	}
	if strat != nil {
		st.Strategy = strat.Name
		st.Profiles = len(strat.Profiles)
		st.WindowTCP = portSetStrings(strat.WindowTCP)
		st.WindowUDP = portSetStrings(strat.WindowUDP)
		st.Unsupported = strat.Unsupported(caps)
	}
	st.Caps = d.capsFrom(caps, trName, reason, strat)

	st.PF = d.pfData(drift, verified)
	if mode, _, _, err := d.ipsetState(); err == nil {
		st.IPSet = mode
	} else {
		warnings = append(warnings, "cannot read the ipset list: "+firstLine(err.Error()))
	}
	if entries, err := d.hosts.Applied(); err == nil {
		for _, e := range entries {
			st.HostsEntries += len(e.Names)
		}
	}

	if !enabled {
		warnings = append(warnings, "the datapath is stopped (`zaprctl start` to resume)")
	} else if !running {
		msg := "the datapath is not running"
		if lastErr != "" {
			msg += ": " + lastErr
		}
		warnings = append(warnings, msg)
	}
	if len(st.Unsupported) > 0 {
		warnings = append(warnings, fmt.Sprintf("the %s datapath cannot honour %d op(s) of this strategy: %s",
			st.Transport, len(st.Unsupported), strings.Join(st.Unsupported, "; ")))
	}
	if st.PF.Drift != "" {
		warnings = append(warnings, "pf drift: "+st.PF.Drift)
	}
	st.Warnings = ctl.SortedUnique(warnings)
	return st, nil
}

// Stats returns the counters.
func (d *Daemon) Stats() (ctl.StatsData, error) { return d.statsSnapshot(), nil }

// statsSnapshot merges the live transport's counters with those of transports
// that have already been replaced by a restart.
func (d *Daemon) statsSnapshot() ctl.StatsData {
	d.mu.Lock()
	tr, base, name, eng, restarts := d.tr, d.lastStats, d.trName, d.eng, d.restarts
	d.mu.Unlock()

	out := base
	if tr != nil {
		out = addStats(base, statsToData(tr.Stats()))
	}
	out.Transport = name
	out.Restarts = restarts
	if eng != nil {
		out.FlowsActive = int64(eng.FlowCount())
		// Engine.Counters() is an atomic snapshot, so reading it from the
		// control-socket goroutine while the datapath writes is well defined.
		out.Degraded = eng.Counters().Degraded
	}
	return out
}

// statsToData converts the transport contract's Stats to the wire DTO.
func statsToData(s transport.Stats) ctl.StatsData {
	return ctl.StatsData{
		Transport:   s.Transport,
		FlowsActive: s.FlowsActive,
		FlowsTotal:  s.FlowsTotal,
		PktsIn:      s.PktsIn,
		PktsOut:     s.PktsOut,
		PktsInject:  s.PktsInject,
		PktsDropped: s.PktsDropped,
		BytesIn:     s.BytesIn,
		BytesOut:    s.BytesOut,
		Matched:     s.Matched,
		Desyncs:     s.Desyncs,
		Errors:      s.Errors,
		QueueDrop:   s.QueueDrop,
	}
}

// addStats sums two counter snapshots (FlowsActive is a gauge, so b wins).
func addStats(a, b ctl.StatsData) ctl.StatsData {
	return ctl.StatsData{
		Transport:   b.Transport,
		FlowsActive: b.FlowsActive,
		FlowsTotal:  a.FlowsTotal + b.FlowsTotal,
		PktsIn:      a.PktsIn + b.PktsIn,
		PktsOut:     a.PktsOut + b.PktsOut,
		PktsInject:  a.PktsInject + b.PktsInject,
		PktsDropped: a.PktsDropped + b.PktsDropped,
		BytesIn:     a.BytesIn + b.BytesIn,
		BytesOut:    a.BytesOut + b.BytesOut,
		Matched:     a.Matched + b.Matched,
		Desyncs:     a.Desyncs + b.Desyncs,
		Degraded:    a.Degraded + b.Degraded,
		Errors:      a.Errors + b.Errors,
		QueueDrop:   a.QueueDrop + b.QueueDrop,
		Restarts:    b.Restarts,
	}
}

// Caps reports the capability matrix of the running transport.
func (d *Daemon) Caps() (ctl.CapsData, error) {
	d.mu.Lock()
	name, reason, strat := d.trName, d.trReason, d.strat
	d.mu.Unlock()
	caps, warns := d.liveCaps()
	if name == "" {
		name = d.plannedTransport() + " (not started)"
		caps = transportCaps(d.plannedTransport())
		reason = "no datapath is running yet; this is what " + d.plannedTransport() + " would provide"
	}
	out := d.capsFrom(caps, name, reason, strat)
	for _, w := range warns {
		out.Reason += "; " + w
	}
	return out, nil
}

// liveCaps returns the capabilities in force right now.
//
// A transport may report LESS after starting than its contract promised — the
// divert datapath does exactly that when it has to fall back from the BPF
// injector to SOCK_RAW, which costs per-packet TTL and header fooling. Reporting
// the pre-start set then would tell the user a fake-based strategy is fully
// active when it is not.
func (d *Daemon) liveCaps() (desync.Caps, []string) {
	d.mu.Lock()
	tr, caps := d.tr, d.caps
	d.mu.Unlock()
	if tr == nil {
		return caps, nil
	}
	var warns []string
	if w, ok := tr.(warner); ok {
		warns = append(warns, w.Warnings()...)
	}
	if live := tr.Caps(); live != caps {
		warns = append(warns, fmt.Sprintf(
			"the datapath now provides %s but the engine was built for %s: the difference is degraded or skipped",
			capsSummary(live), capsSummary(caps)))
		caps = live
	}
	return caps, warns
}

// capsFrom renders a Caps plus the active strategy's unmet requirements.
func (d *Daemon) capsFrom(caps desync.Caps, name, reason string, strat *strategy.Strategy) ctl.CapsData {
	out := ctl.CapsData{
		Transport:    name,
		Reason:       reason,
		Inject:       caps.Inject,
		Seq:          caps.Seq,
		DropOriginal: caps.DropOriginal,
		PerPacketTTL: caps.PerPacketTTL,
		Fooling:      caps.Fooling,
		IPID:         caps.IPID,
		UDP:          caps.UDP,
		IPv6ExtHdr:   caps.IPv6ExtHdr,
		Frag:         caps.Frag,
		Segment:      caps.Segment,
		TLSRec:       caps.TLSRec,
	}
	if strat != nil {
		out.Strategy = strat.Name
		out.Unsupported = strat.Unsupported(caps)
	}
	return out
}

// pfData collects the pf view. It costs two pfctl invocations, which is fine for
// an on-demand command.
func (d *Daemon) pfData(drift string, verified time.Time) ctl.PFData {
	out := ctl.PFData{Anchor: d.pf.EffectiveAnchor(), Token: d.pf.Token(), Drift: drift}
	if !verified.IsZero() {
		out.LastVerify = verified.Format(time.RFC3339)
	}
	if on, err := d.pf.Enabled(); err == nil {
		out.Enabled = on
	}
	if d.pf.Mode() == netcfg.AnchorModeWildcard {
		// A stock macOS ruleset reaches com.apple/<name> through
		// anchor "com.apple/*"; no literal statement for our child exists.
		out.AnchorReferenced = true
	} else if b, err := os.ReadFile(d.pf.PfConfPath()); err == nil {
		out.AnchorReferenced = netcfg.AnchorStatementsPresent(b, d.opts.anchor)
	}
	filter, ferr := d.pf.Rules()
	nat, nerr := d.pf.NatRules()
	if ferr == nil {
		out.RuleLines += countNonEmpty(filter)
	}
	if nerr == nil {
		out.RuleLines += countNonEmpty(nat)
	}
	return out
}

// Start brings the datapath up and waits briefly for it to actually run, so the
// CLI can report a failure instead of a hopeful "ok".
func (d *Daemon) Start(transport string) error {
	if transport != "" {
		switch transport {
		case "auto", "divert", "proxy":
		default:
			return fmt.Errorf("unknown transport %q; use auto, divert or proxy", transport)
		}
		d.mu.Lock()
		changed := d.opts.transport != transport
		d.opts.transport = transport
		d.mu.Unlock()
		// An override only means something if the datapath is rebuilt with it:
		// the transport instance is created once per session, so a running
		// datapath has to go down first.
		//
		// The comparison is against the transport that is actually RUNNING, not
		// against the previous option value, and it waits for a starting
		// datapath to settle first. launchd brings the daemon up with its own
		// choice, so `zaprctl start --transport divert` typically lands while
		// that first session is still being built: isRunning() is false, no
		// restart happens, and the session finishes on the old transport — which
		// is exactly the silent no-op this parameter exists to prevent.
		if changed {
			d.waitDatapathSettled(3 * time.Second)
			if cur := d.currentTransportName(); cur != "" && cur != transport {
				d.log.Printf("switching datapath from %q to %q on request", cur, transport)
				if err := d.Stop(); err != nil {
					return fmt.Errorf("cannot stop the current datapath to switch transport: %w", err)
				}
			}
		}
	}
	if d.isEnabled() && d.isRunning() {
		return nil
	}
	d.setEnabled(true)
	// Bounded well under the control socket's own deadline: a datapath that has
	// not come up in this long is failing, not slow, and the caller deserves the
	// reason rather than a timed-out RPC.
	deadline := time.Now().Add(datapathStartWait)
	for time.Now().Before(deadline) {
		if d.isRunning() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	d.mu.Lock()
	last := d.lastErr
	d.mu.Unlock()
	if last != "" {
		return fmt.Errorf("the datapath did not come up: %s", last)
	}
	return fmt.Errorf("the datapath did not come up within %s; see `zaprctl logs`", datapathStartWait)
}

// Stop takes the datapath down and removes its pf rules, leaving the daemon
// itself running so it can be started again without sudo.
func (d *Daemon) Stop() error {
	d.setEnabled(false)
	d.cancelSession()
	deadline := time.Now().Add(datapathStopWait)
	for time.Now().Before(deadline) {
		if !d.isRunning() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if d.isRunning() {
		return fmt.Errorf("the datapath did not stop within %s; see `zaprctl logs`", datapathStopWait)
	}
	// The anchor holds the transport's steering rules. Flushing it here makes
	// "stopped" mean "no pf rule of ours is in the way", even if the transport's
	// own cleanup failed.
	if err := d.pf.FlushRules(); err != nil {
		return fmt.Errorf("the datapath stopped but flushing the %q anchor failed: %w", d.opts.anchor, err)
	}
	return nil
}

func (d *Daemon) isRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

// Reload re-reads the active strategy (and the lists and fakes it names) from
// disk. Flows keep running; if the steered port window changed, the datapath is
// restarted because the window is baked into the pf rules.
func (d *Daemon) Reload() error {
	d.mu.Lock()
	old, caps, tr := d.strat, d.caps, d.tr
	d.mu.Unlock()

	spec := d.currentSpec()
	s, path, err := d.compileStrategy(spec, caps)
	if err != nil {
		return err
	}
	fakes := d.loadFakes()

	windowChanged := old == nil || !samePortSet(old.WindowTCP, s.WindowTCP) || !samePortSet(old.WindowUDP, s.WindowUDP)

	d.mu.Lock()
	d.strat, d.stratPath, d.fakes = s, path, fakes
	eng := d.eng
	d.mu.Unlock()

	if eng != nil {
		eng.Reload(s)
	}
	if tr != nil {
		if err := tr.Reload(s); err != nil {
			return fmt.Errorf("the %s datapath refused the new strategy: %w", d.trName, err)
		}
	}
	d.log.Printf("reloaded strategy %s from %s", s.Name, path)
	if windowChanged && d.isEnabled() {
		d.log.Printf("the steered port window changed; restarting the datapath so pf gets the new rules")
		d.cancelSession()
		d.kick()
	}
	return nil
}

// Use switches to another strategy and remembers it for the next start.
//
// The name is CONFINED to the installed strategies directory: everything in the
// admin group can reach the control socket, and `use /some/path.toml` would make
// the root daemon read (and report parse errors from) any file that user chose.
// The --strategy flag is deliberately not confined — that is the operator's own
// argv, not a message from another process.
func (d *Daemon) Use(name string) (ctl.UseData, error) {
	d.mu.Lock()
	caps := d.caps
	d.mu.Unlock()
	if (caps == desync.Caps{}) {
		caps = transportCaps(d.plannedTransport())
	}
	if err := checkStrategyName(name); err != nil {
		return ctl.UseData{}, err
	}
	s, path, err := d.compileStrategy(name, caps)
	if err != nil {
		return ctl.UseData{}, err
	}
	if !underDir(d.dirs.strategies, path) {
		return ctl.UseData{}, fmt.Errorf("strategy %q resolves to %s, which is outside %s; "+
			"install it there first", name, path, d.dirs.strategies)
	}
	if err := d.writeActiveName(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))); err != nil {
		return ctl.UseData{}, fmt.Errorf("cannot remember the active strategy: %w", err)
	}

	d.mu.Lock()
	old := d.strat
	d.strat, d.stratPath, d.fakes = s, path, d.loadFakes()
	eng, tr := d.eng, d.tr
	d.mu.Unlock()

	if eng != nil {
		eng.Reload(s)
	}
	restarted := false
	if tr != nil {
		if err := tr.Reload(s); err != nil {
			return ctl.UseData{}, fmt.Errorf("the %s datapath refused strategy %s: %w", d.trName, s.Name, err)
		}
	}
	if old == nil || !samePortSet(old.WindowTCP, s.WindowTCP) || !samePortSet(old.WindowUDP, s.WindowUDP) {
		if d.isEnabled() {
			d.cancelSession()
			d.kick()
			restarted = true
		}
	}
	out := ctl.UseData{
		Strategy:    s.Name,
		Path:        path,
		Restarted:   restarted,
		Unsupported: s.Unsupported(caps),
	}
	if len(out.Unsupported) > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%s cannot honour %d of this strategy's ops; they will be degraded or skipped",
			d.transportLabel(), len(out.Unsupported)))
	}
	if !d.isRunning() {
		out.Warnings = append(out.Warnings,
			"the datapath is not running, so this takes effect when it starts (`zaprctl start`)")
	}
	d.log.Printf("activated strategy %s (%s)%s", s.Name, path, ifTrue(restarted, ", datapath restarting"))
	return out, nil
}

// List enumerates the installed strategies, marking what the active transport
// cannot honour.
func (d *Daemon) List() (ctl.ListData, error) {
	d.mu.Lock()
	caps, active, trName := d.caps, "", d.trName
	if d.strat != nil {
		active = d.strat.Name
	}
	d.mu.Unlock()
	if (caps == desync.Caps{}) {
		caps = transportCaps(d.plannedTransport())
	}
	ss, err := strategy.LoadDir(d.dirs.strategies, strategy.LoadOpts{
		ListsDir: d.dirs.lists,
		FakesDir: d.dirs.fakes,
		Caps:     caps,
	})
	if err != nil {
		return ctl.ListData{}, err
	}
	if trName == "" {
		trName = d.plannedTransport() + " (not running)"
	}
	out := ctl.ListData{Active: active, Transport: trName, Dir: d.dirs.strategies}
	for _, s := range ss {
		out.Strategies = append(out.Strategies, ctl.StrategyInfo{
			Name:        s.Name,
			Description: s.Description,
			Summary:     s.Summary(),
			Profiles:    len(s.Profiles),
			Unsupported: s.Unsupported(caps),
			Active:      s.Name == active,
		})
	}
	return out, nil
}

// LogTail serves history and, with Follow, streams new lines.
func (d *Daemon) LogTail(ctx context.Context, opt ctl.LogTailOpts, emit func(ctl.LogChunk) error) error {
	n := opt.Lines
	if n <= 0 {
		n = 200
	}
	var sub <-chan string
	var release func()
	if opt.Follow {
		// Subscribe BEFORE snapshotting the history, so a line logged in
		// between is duplicated rather than lost.
		sub, release = d.log.Subscribe()
		defer release()
	}
	hist := d.log.Lines(n)
	const chunkLines = 200
	for i := 0; i < len(hist); i += chunkLines {
		end := i + chunkLines
		if end > len(hist) {
			end = len(hist)
		}
		if err := emit(ctl.LogChunk{Lines: hist[i:end]}); err != nil {
			return err
		}
	}
	if !opt.Follow {
		return nil
	}
	// Batch what arrives so a chatty datapath does not turn into one write per
	// line, but never hold a line longer than a blink.
	flush := time.NewTicker(200 * time.Millisecond)
	defer flush.Stop()
	var pending []string
	for {
		select {
		case <-ctx.Done():
			if len(pending) > 0 {
				_ = emit(ctl.LogChunk{Lines: pending})
			}
			return nil
		case line, ok := <-sub:
			if !ok {
				if len(pending) > 0 {
					return emit(ctl.LogChunk{Lines: pending})
				}
				return nil
			}
			pending = append(pending, line)
			if len(pending) >= chunkLines {
				if err := emit(ctl.LogChunk{Lines: pending}); err != nil {
					return err
				}
				pending = nil
			}
		case <-flush.C:
			if len(pending) == 0 {
				continue
			}
			if err := emit(ctl.LogChunk{Lines: pending}); err != nil {
				return err
			}
			pending = nil
		}
	}
}

// ---------------------------------------------------------------------------
// hosts / ipset
// ---------------------------------------------------------------------------

// HostsApply pins the entries of the hosts source file into /etc/hosts inside
// our marker block, then flushes the DNS cache so the change takes effect for
// processes that already resolved those names.
func (d *Daemon) HostsApply() (ctl.HostsData, error) {
	b, err := os.ReadFile(d.dirs.hostsSrc)
	if err != nil {
		return ctl.HostsData{}, fmt.Errorf("cannot read the hosts source %s: %w; "+
			"put flowseal's service/hosts there or run `sudo make install`", d.dirs.hostsSrc, err)
	}
	entries, perr := netcfg.ParseHostsFile(b)
	var warns []string
	if perr != nil {
		// Lenient on purpose: the well-formed lines are still worth pinning.
		d.log.Printf("hosts source %s: %v", d.dirs.hostsSrc, perr)
		warns = append(warns, perr.Error())
	}
	if len(entries) == 0 {
		return ctl.HostsData{}, fmt.Errorf("the hosts source %s has no usable entries", d.dirs.hostsSrc)
	}
	if err := d.hosts.Apply(entries); err != nil {
		return ctl.HostsData{}, err
	}
	out := ctl.HostsData{
		Path:       d.hosts.Path(),
		SourcePath: d.dirs.hostsSrc,
		Applied:    true,
		Entries:    len(entries),
	}
	for _, e := range entries {
		out.Names += len(e.Names)
	}
	out.Warnings = append(out.Warnings, warns...)
	out.Warnings = append(out.Warnings, d.flushDNS()...)
	d.log.Printf("pinned %d hosts entries (%d names) into %s from %s", out.Entries, out.Names, out.Path, out.SourcePath)
	if d.opts.dryRun {
		out.Warnings = append(out.Warnings, "dry run: nothing was actually written to "+out.Path)
	} else {
		out.DNSFlushed = len(out.Warnings) == len(warns)
	}
	return out, nil
}

// flushDNS flushes the resolver cache after a hosts change, returning a warning
// instead of an error when it cannot: the pinning itself has already happened,
// and a stale cache entry expires on its own.
//
// A dry run skips it. Flushing is harmless, but --dry-run promises that no
// system state is touched, and a promise with exceptions is not one.
func (d *Daemon) flushDNS() []string {
	if d.opts.dryRun {
		return []string{"dry run: the DNS cache was not flushed"}
	}
	if err := netcfg.FlushDNSCache(); err != nil {
		d.log.Printf("flushing the DNS cache failed: %v", err)
		return []string{"the DNS cache could not be flushed (" + firstLine(err.Error()) +
			"); run `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`"}
	}
	return nil
}

// HostsRemove removes our block from the hosts file.
func (d *Daemon) HostsRemove() (ctl.HostsData, error) {
	if err := d.hosts.Remove(); err != nil {
		return ctl.HostsData{}, err
	}
	out := ctl.HostsData{Path: d.hosts.Path(), SourcePath: d.dirs.hostsSrc}
	out.Warnings = d.flushDNS()
	out.DNSFlushed = len(out.Warnings) == 0
	d.log.Printf("removed our block from %s", out.Path)
	return out, nil
}

// ipsetPath is the list file the tri-state switch operates on.
func (d *Daemon) ipsetPath() string { return filepath.Join(d.dirs.lists, "ipset-all.txt") }

// ipsetState reads the current mode, exactly the way flowseal's service.bat
// decides it: an empty file means "no restriction", a file holding the
// documentation sentinel means "match nothing", anything else is a real list.
func (d *Daemon) ipsetState() (mode string, entries int, backup bool, err error) {
	path := d.ipsetPath()
	f, rerr := os.Open(path)
	if rerr != nil {
		return ctl.IPSetUnknown, 0, false, fmt.Errorf("cannot read %s: %w", path, rerr)
	}
	defer f.Close()
	// Scanned line by line rather than read whole: the real list is half a
	// megabyte of prefixes and `zaprctl status` asks for this on every call.
	sentinel := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		entries++
		if strings.Contains(t, ctl.IPSetSentinel) {
			sentinel = true
		}
	}
	if serr := sc.Err(); serr != nil {
		return ctl.IPSetUnknown, entries, false, fmt.Errorf("reading %s: %w", path, serr)
	}
	if _, serr := os.Stat(path + ".backup"); serr == nil {
		backup = true
	}
	switch {
	case entries == 0:
		return ctl.IPSetAny, 0, backup, nil
	case sentinel:
		return ctl.IPSetNone, entries, backup, nil
	default:
		return ctl.IPSetLoaded, entries, backup, nil
	}
}

// IPSet reads or sets the tri-state switch. Setting it rewrites the list file
// and reloads the strategy, because ipsets are read when a strategy is compiled.
func (d *Daemon) IPSet(mode string) (ctl.IPSetData, error) {
	path := d.ipsetPath()
	cur, entries, backup, err := d.ipsetState()
	if err != nil && mode == "" {
		return ctl.IPSetData{Mode: ctl.IPSetUnknown, Path: path}, err
	}
	if mode == "" || mode == cur {
		return ctl.IPSetData{Mode: cur, Path: path, Entries: entries, Backup: backup}, nil
	}
	backupPath := path + ".backup"

	switch mode {
	case ctl.IPSetLoaded:
		if !backup {
			return ctl.IPSetData{Mode: cur, Path: path, Entries: entries},
				fmt.Errorf("cannot switch to %q: there is no %s to restore the real list from; "+
					"reinstall the lists (`sudo make install`) or update them first", mode, backupPath)
		}
		if err := os.Rename(backupPath, path); err != nil {
			return ctl.IPSetData{}, fmt.Errorf("restoring %s from %s: %w", path, backupPath, err)
		}
	case ctl.IPSetNone, ctl.IPSetAny:
		if cur == ctl.IPSetLoaded {
			// Keep the real list: it is 32k prefixes nobody wants to re-download.
			_ = os.Remove(backupPath)
			if err := os.Rename(path, backupPath); err != nil {
				return ctl.IPSetData{}, fmt.Errorf("backing up %s to %s: %w", path, backupPath, err)
			}
		}
		body := []byte(nil)
		if mode == ctl.IPSetNone {
			body = []byte(ctl.IPSetSentinel + "\n")
		}
		if err := writeFileAtomic(path, body); err != nil {
			return ctl.IPSetData{}, err
		}
	default:
		return ctl.IPSetData{}, fmt.Errorf("ipset mode %q is unknown", mode)
	}

	newMode, newEntries, newBackup, _ := d.ipsetState()
	out := ctl.IPSetData{Mode: newMode, Previous: cur, Path: path, Entries: newEntries, Backup: newBackup}
	if err := d.Reload(); err != nil {
		return out, fmt.Errorf("ipset is now %q but reloading the strategy failed: %w", newMode, err)
	}
	out.Reloaded = true
	d.log.Printf("ipset switch: %s -> %s (%d entries in %s)", cur, newMode, newEntries, path)
	return out, nil
}

// writeFileAtomic replaces path via a temp file and rename, so a reader never
// sees a half-written list.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// selftest
// ---------------------------------------------------------------------------

// Selftest measures the endpoints this tool exists to unblock and reports what
// happened to each one.
//
// The probe list, the per-class error classification ("timeout", "rst",
// "tls-handshake" — the signatures that distinguish DPI from a broken uplink) and
// the aggregate verdict all come from internal/diag, which is also what
// `zaprctl doctor` and the strategy auto-picker use, so a target that fails here
// fails there identically.
//
// Probes run one at a time on purpose: sequential runs let the engine's desync
// counter be attributed to the target being measured, which answers the question
// behind the whole test — not "does the site load" but "did we touch this flow at
// all". The budget is bounded so a fully blocked network still answers within the
// control socket's timeout.
func (d *Daemon) Selftest(args map[string]string) (ctl.SelftestData, error) {
	probes := diag.DefaultProbes()
	if raw := strings.TrimSpace(args["targets"]); raw != "" {
		parsed, err := probesFrom(raw)
		if err != nil {
			return ctl.SelftestData{}, err
		}
		probes = parsed
	}
	if want := strings.TrimSpace(args["strategy"]); want != "" {
		d.mu.Lock()
		active := ""
		if d.strat != nil {
			active = d.strat.Name
		}
		d.mu.Unlock()
		if normaliseStrategyName(want) != normaliseStrategyName(active) {
			if _, err := d.Use(want); err != nil {
				return ctl.SelftestData{}, fmt.Errorf("cannot activate %q for the test: %w", want, err)
			}
			// Give a restarted datapath a moment to load its rules, or the first
			// probes would measure a window with no interception in it.
			time.Sleep(time.Second)
		}
	}

	d.mu.Lock()
	stratName, trName, running := "", d.trName, d.running
	if d.strat != nil {
		stratName = d.strat.Name
	}
	d.mu.Unlock()

	if trName == "" {
		trName = d.plannedTransport() + " (not running)"
	}
	out := ctl.SelftestData{Strategy: stratName, Transport: trName, OK: true}
	if !running {
		out.Warnings = append(out.Warnings,
			"the datapath is not running: this measures your plain connection, not the bypass")
	}

	ctx, cancel := context.WithTimeout(context.Background(), selftestBudget)
	defer cancel()
	ropts := diag.RunOpts{
		Timeout: selftestProbe,
		Logf:    func(f string, a ...any) { d.log.Debugf(f, a...) },
	}
	results := make([]diag.Result, 0, len(probes))
	for i, p := range probes {
		if ctx.Err() != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"stopped after %d of %d targets: the %s budget was exhausted", i, len(probes), selftestBudget))
			break
		}
		before := d.desyncCount()
		r := diag.RunProbe(ctx, p, ropts)
		results = append(results, r)
		tt := testTargetFrom(r)
		tt.Desynced = d.desyncCount() > before
		out.Targets = append(out.Targets, tt)
		if !r.OK {
			out.OK = false
		}
	}
	sum := diag.Summarise(results)
	out.Warnings = append(out.Warnings, sum.Verdict())
	d.log.Printf("selftest: %s", sum.Verdict())
	return out, nil
}

// checkStrategyName rejects a control-socket argument that is a path rather than
// an installed strategy's name.
func checkStrategyName(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return nil // "" means "the default", resolved below
	}
	if strings.ContainsRune(n, os.PathSeparator) || strings.Contains(n, "..") || filepath.IsAbs(n) {
		return fmt.Errorf("strategy %q looks like a path; `use` takes the NAME of an installed strategy "+
			"(see `zaprctl list`). Start the daemon with --strategy <path> if you really mean a file "+
			"outside the strategies directory", name)
	}
	return nil
}

// underDir reports whether path is dir itself or inside it, after resolving both.
//
// Both sides go through the same resolver, because resolving only one of them turns
// macOS' /var -> /private/var symlink into a false "outside".
func underDir(dir, path string) bool {
	da, err1 := filepath.Abs(dir)
	pa, err2 := filepath.Abs(path)
	if err1 != nil || err2 != nil {
		return false
	}
	da, pa = resolveExisting(da), resolveExisting(pa)
	rel, err := filepath.Rel(da, pa)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// resolveExisting resolves symlinks in p, falling back to resolving p's parent and
// rejoining the last element when p itself does not exist. Without the fallback a
// non-existent path stays unresolved while the directory it is compared against
// does not, and the comparison is meaningless.
func resolveExisting(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	dir, base := filepath.Split(p)
	if dir == "" || base == "" {
		return p
	}
	if r, err := filepath.EvalSymlinks(filepath.Clean(dir)); err == nil {
		return filepath.Join(r, base)
	}
	return p
}

// checkProbeHost rejects a control-socket probe target that points back at this
// machine or at link-local space.
//
// A root daemon that connects wherever an admin-group client asks is a wider
// surface than the protocol needs: loopback and link-local (including the
// 169.254.169.254 metadata address) are the addresses where "the root daemon
// connected for me" actually buys something. Public and RFC 1918 destinations stay
// allowed, because probing a LAN host is a legitimate diagnostic.
func checkProbeHost(host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return nil
	}
	// The caller may hand us "host", "host:port" or "[v6]:port".
	if bare, _, err := net.SplitHostPort(h); err == nil {
		h = bare
	}
	h = strings.Trim(h, "[]")
	addr, err := netip.ParseAddr(h)
	if err != nil {
		// A hostname: leave it. Resolving it here would only move the check to a
		// name that can resolve differently a moment later.
		return nil
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback():
		return fmt.Errorf("probe target %q is a loopback address; the daemon will not be used to reach "+
			"services on this machine", host)
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return fmt.Errorf("probe target %q is link-local; refusing (169.254.0.0/16 and fe80::/10 are not "+
			"DPI-relevant destinations)", host)
	case addr.IsUnspecified(), addr.IsMulticast():
		return fmt.Errorf("probe target %q is not a unicast destination", host)
	}
	return nil
}

// probesFrom turns a caller's target list into probes. Three spellings are
// accepted, because all three are things a user will type:
//
//	name=https://host/path   flowseal's targets.txt syntax (parsed by diag)
//	https://host/ , tls://host:443 , ping://host   an explicit probe URL
//	host, host:443, host:80  a bare endpoint
//
// A bare endpoint on port 80 becomes an HTTP probe and anything else a TLS
// handshake probe, because the TLS ClientHello is what DPI acts on: a bare TCP
// connect to 443 succeeds even when the bypass is doing nothing.
func probesFrom(raw string) ([]diag.Probe, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	var out []diag.Probe
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || strings.HasPrefix(f, "#") {
			continue
		}
		switch {
		case strings.Contains(f, "="), strings.HasPrefix(f, "PING:"):
			parsed, err := diag.ParseTargets(strings.NewReader(f))
			if err != nil {
				return nil, fmt.Errorf("target %q: %w", f, err)
			}
			out = append(out, parsed...)
		case strings.HasPrefix(f, "https://"), strings.HasPrefix(f, "http://"),
			strings.HasPrefix(f, "tls://"), strings.HasPrefix(f, "ping://"):
			if err := checkProbeHost(probeLabel(f)); err != nil {
				return nil, err
			}
			out = append(out, diag.Probe{Name: probeLabel(f), URL: f})
		default:
			host, port := f, "443"
			if h, p, err := net.SplitHostPort(f); err == nil {
				host, port = h, p
			}
			if host == "" {
				return nil, fmt.Errorf("target %q has no host", f)
			}
			if err := checkProbeHost(host); err != nil {
				return nil, err
			}
			if port == "80" {
				out = append(out, diag.Probe{Name: f, URL: "http://" + host + "/"})
				continue
			}
			out = append(out, diag.Probe{Name: f, URL: "tls://" + net.JoinHostPort(host, port)})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable targets in %q; write a host, a host:port or a URL", raw)
	}
	return out, nil
}

// probeLabel shortens a URL to the host, which is what a table column wants.
func probeLabel(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return u
	}
	return s
}

// testTargetFrom converts one probe result into the wire DTO.
func testTargetFrom(r diag.Result) ctl.TestTarget {
	tt := ctl.TestTarget{Target: r.Name, SNI: r.SNI, OK: r.OK}
	if tt.Target == "" {
		tt.Target = r.URL
	}
	// The comparable latency: time to first body byte where there is a body, the
	// handshake for a TLS-only probe, the connect for a bare TCP one.
	switch {
	case r.FirstByteTime > 0:
		tt.MS = r.FirstByteTime.Milliseconds()
	case r.TLSTime > 0:
		tt.MS = r.TLSTime.Milliseconds()
	case r.ConnectTime > 0:
		tt.MS = r.ConnectTime.Milliseconds()
	default:
		tt.MS = r.TotalTime.Milliseconds()
	}
	var parts []string
	if r.Class != "" && r.Class != diag.ClassOK {
		parts = append(parts, r.Class)
	}
	if r.Status != 0 {
		parts = append(parts, fmt.Sprintf("HTTP %d", r.Status))
	}
	if r.TLSVersion != "" {
		// diag already spells it "TLS1.3"; do not print "TLS TLS1.3".
		v := r.TLSVersion
		if !strings.HasPrefix(strings.ToUpper(v), "TLS") {
			v = "TLS " + v
		}
		if r.ALPN != "" {
			v += "/" + r.ALPN
		}
		parts = append(parts, v)
	}
	if r.BytesPerSec > 0 {
		parts = append(parts, fmt.Sprintf("%.0f KiB/s", r.BytesPerSec/1024))
	}
	if r.ServerIP != "" {
		parts = append(parts, "via "+r.ServerIP)
	}
	if r.Control {
		parts = append(parts, "control endpoint")
	}
	if r.Err != "" {
		parts = append(parts, firstLine(r.Err))
	}
	tt.Detail = strings.Join(parts, ", ")
	return tt
}

// desyncCount reads the engine's desync counter.
//
// Engine.Counters() reads atomics, so this is safe from the control-socket
// goroutine; the five fields are not one atomic snapshot, which is fine because
// nothing here derives control flow from them.
func (d *Daemon) desyncCount() int64 {
	d.mu.Lock()
	eng := d.eng
	d.mu.Unlock()
	if eng == nil {
		return 0
	}
	return eng.Counters().Desyncs
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

// Doctor runs the diagnostics.
//
// The machine-wide half is internal/diag: pf state, leftovers from a crashed
// run, conflicting tools, the /etc/hosts block, the resolver comparison and the
// reversible capability probe. This method adds only what diag cannot know — the
// live datapath's state — and translates the findings into the control protocol.
//
// The repair path here deliberately does NOT replay the rollback journal: those
// records describe the live daemon's own pf.conf patch and its datapath's pf
// reference, and undoing them while running would break the very thing being
// repaired. diag.Repair refuses for the same reason when DaemonRunning is true.
// `zaprctl doctor --repair` with no daemon listening is the path that reverts a
// crashed run.
func (d *Daemon) Doctor(repair bool) (ctl.DoctorData, error) {
	out := ctl.DoctorData{
		Version:       version,
		UID:           os.Geteuid(),
		Root:          os.Geteuid() == 0,
		DaemonRunning: true,
	}
	d.mu.Lock()
	strat, trName, running, enabled := d.strat, d.trName, d.running, d.enabled
	drift, lastErr, restarts := d.pfDrift, d.lastErr, d.restarts
	d.mu.Unlock()
	caps, capWarn := d.liveCaps()
	out.Transport = trName

	add := func(name string, ok bool, sev, detail, fix string) {
		out.Checks = append(out.Checks, ctl.Check{Name: name, OK: ok, Severity: sev, Detail: detail, Fix: fix})
	}

	// ---- what only the daemon knows -------------------------------------
	dpDetail := "stopped on request"
	switch {
	case running:
		dpDetail = fmt.Sprintf("%s running for %s, %d restart(s)", trName,
			ctl.FormatDuration(d.datapathUptime()), restarts)
	case lastErr != "":
		dpDetail = "not running: " + lastErr
	}
	add("datapath", running, ctl.SevError, dpDetail, "zaprctl start")
	if !enabled {
		add("datapath enabled", false, ctl.SevWarn, "the datapath was stopped on request", "zaprctl start")
	}
	if strat == nil {
		add("strategy", false, ctl.SevError, "no strategy is loaded", "zaprctl use general")
	} else {
		add("strategy", true, ctl.SevInfo, strat.Summary(), "")
		if unsup := strat.Unsupported(caps); len(unsup) > 0 {
			add("strategy fits the transport", false, ctl.SevWarn,
				fmt.Sprintf("%s cannot honour: %s", d.transportLabel(), strings.Join(unsup, "; ")),
				"pick a strategy without those ops, or fix whatever forced the fallback transport")
		} else {
			add("strategy fits the transport", true, ctl.SevInfo, "every op is supported", "")
		}
	}
	for _, w := range capWarn {
		add("transport capabilities", false, ctl.SevWarn, w, "")
	}
	if drift != "" {
		add("pf ruleset stable", false, ctl.SevWarn, drift, "sudo zaprctl doctor --repair")
	}
	for _, dir := range []struct{ label, path string }{
		{"strategies", d.dirs.strategies},
		{"lists", d.dirs.lists},
		{"fakes", d.dirs.fakes},
	} {
		ok := dirHasFiles(dir.path)
		fix := ""
		if !ok {
			fix = "sudo make install"
		}
		add(dir.label+" directory", ok, ctl.SevError, dir.path, fix)
	}

	// ---- the machine-wide half ------------------------------------------
	findings, err := diag.Doctor(context.Background(), d.doctorOpts(running))
	if err != nil {
		add("system diagnostics", false, ctl.SevError, err.Error(),
			"see `zaprctl logs`; run `sudo zaprctl doctor` again once the cause is gone")
	}
	for _, f := range findings {
		out.Checks = append(out.Checks, ctl.Check{
			Name: f.Title, OK: f.OK(), Severity: f.Severity, Detail: f.Detail, Fix: f.Fix,
		})
	}

	if j := d.pf.Journal(); j != nil {
		out.JournalPath = j.Path()
		if entries, jerr := j.Entries(); jerr == nil {
			out.JournalPending = len(entries)
		}
	}

	if repair {
		out.Repaired = d.repairNow(&out)
	}
	return out, nil
}

// doctorOpts describes our installation to internal/diag. Every path and every
// piece of strategy context comes from the running daemon, because the
// authoritative copy of the ipset tri-state is the one the active strategy
// compiled, not whatever is on disk right now.
func (d *Daemon) doctorOpts(running bool) diag.DoctorOpts {
	d.mu.Lock()
	strat, caps := d.strat, d.caps
	d.mu.Unlock()

	o := diag.DoctorOpts{
		Anchor:            d.opts.anchor,
		PfConfPath:        d.opts.pfConfPath,
		HostsPath:         d.opts.hostsPath,
		StateDir:          d.dirs.state,
		UpstreamHostsPath: d.dirs.hostsSrc,
		DaemonRunning:     &running,
		Logf:              func(f string, a ...any) { d.log.Debugf(f, a...) },
		Detect: diag.DetectOpts{
			Anchor:     d.opts.anchor,
			PfConfPath: d.opts.pfConfPath,
			Iface:      d.opts.iface,
			// With a datapath up, the steering experiment must not go near our
			// anchor: it holds the live rules. The probe reports the rest
			// (utun, BPF, natlook, uplink) either way.
			SkipSteer: running,
			Logf:      func(f string, a ...any) { d.log.Debugf(f, a...) },
		},
	}
	if strat != nil {
		o.Strategy = strat.Name
		o.StrategyUnsupported = strat.Unsupported(caps)
	}
	if mode, entries, _, err := d.ipsetState(); err == nil {
		o.IPSets = []diag.IPSetInfo{{
			Name:  filepathBase(d.ipsetPath()),
			Any:   mode == ctl.IPSetAny,
			None:  mode == ctl.IPSetNone,
			Count: entries,
		}}
	}
	return o
}

// datapathUptime is how long the current datapath has been running.
func (d *Daemon) datapathUptime() time.Duration {
	d.mu.Lock()
	start, running := d.datapathStart, d.running
	d.mu.Unlock()
	if !running || start.IsZero() {
		return 0
	}
	return time.Since(start)
}

// repairNow applies the in-daemon repairs and returns what it did.
//
// It never replays the rollback journal: those records describe THIS daemon's
// live pf.conf patch and pf reference, and reverting them while running would
// break the thing being repaired. `zaprctl doctor --repair` performs that
// rollback itself when no daemon is listening, which is the only situation where
// it is the right move.
func (d *Daemon) repairNow(out *ctl.DoctorData) []string {
	var done []string
	if !d.isEnabled() {
		d.setEnabled(true)
		done = append(done, "re-enabled the datapath")
	}
	switch {
	case !d.isRunning():
		d.kick()
		done = append(done, "asked the supervisor to start the datapath")
	case d.pfDriftPresent():
		d.cancelSession()
		d.kick()
		done = append(done, "restarted the datapath so it re-patches pf and reloads its rules")
	}
	if pfd := d.pfData("", time.Time{}); !pfd.AnchorReferenced && d.isRunning() {
		// The datapath is up but the main ruleset lost our statements: patch it
		// here so the fix is immediate, then let the restart above reload rules.
		if patched, err := d.pf.EnsureAnchorStatements(); err != nil {
			out.Checks = append(out.Checks, ctl.Check{
				Name: "repair pf.conf", OK: false, Severity: ctl.SevError, Detail: err.Error(),
				Fix: "check " + d.pf.PfConfPath() + " by hand; a backup is in " + filepath.Join(d.dirs.state, "backup"),
			})
		} else if patched {
			done = append(done, "re-patched "+d.pf.PfConfPath())
			d.cancelSession()
			d.kick()
		}
	}
	if len(done) == 0 {
		done = append(done, "nothing needed repairing")
	}
	for _, s := range done {
		d.log.Printf("doctor --repair: %s", s)
	}
	return done
}

func (d *Daemon) pfDriftPresent() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pfDrift != ""
}

// transportLabel names the active transport for a message.
func (d *Daemon) transportLabel() string {
	d.mu.Lock()
	name := d.trName
	d.mu.Unlock()
	if name == "" {
		// Not running: name the datapath that would run, because that is whose
		// capabilities the caller is being told about.
		return "the " + d.plannedTransport() + " datapath (not running)"
	}
	return "the " + name + " datapath"
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// runCmdTimeout bounds every helper this file forks. Its callers run on the
// startup path, BEFORE the control socket exists, so an unbounded exec would
// wedge Run() where nothing can query or stop it while launchd still sees a
// healthy job. pfctl blocking on a wedged /dev/pf is exactly the failure mode the
// rollback path is there to clean up after.
const runCmdTimeout = 20 * time.Second

// runCmd executes a helper and returns its combined output. It is always bounded
// (see runCmdTimeout) and reports a timeout as an error, so the journal entry
// stays for a later repair run instead of being dropped as "handled".
func runCmd(prog string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s timed out after %s: %w", prog, runCmdTimeout, ctx.Err())
	}
	return string(out), err
}

// portSetStrings renders a compiled port window the way a strategy file writes
// it ("443", "19294-19344").
func portSetStrings(ps strategy.PortSet) []string {
	out := make([]string, 0, len(ps))
	for _, r := range ps {
		if r.Lo == r.Hi {
			out = append(out, strconv.Itoa(int(r.Lo)))
			continue
		}
		out = append(out, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
	}
	return out
}

// samePortSet compares two windows; a changed window means the pf rules must be
// rewritten.
func samePortSet(a, b strategy.PortSet) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// capsSummary renders the capabilities that are present, for one log line.
func capsSummary(c desync.Caps) string {
	var on []string
	for _, r := range (ctl.CapsData{
		Inject: c.Inject, Seq: c.Seq, DropOriginal: c.DropOriginal, PerPacketTTL: c.PerPacketTTL,
		Fooling: c.Fooling, IPID: c.IPID, UDP: c.UDP, IPv6ExtHdr: c.IPv6ExtHdr, Frag: c.Frag,
		Segment: c.Segment, TLSRec: c.TLSRec,
	}).Rows() {
		if r.Have {
			on = append(on, r.Name)
		}
	}
	return joinOr(on, "none")
}

func countNonEmpty(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func joinOr(v []string, empty string) string {
	if len(v) == 0 {
		return empty
	}
	return strings.Join(v, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func ifNotEmpty(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

func ifTrue(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}

// ---------------------------------------------------------------------------
// VPN control
// ---------------------------------------------------------------------------

// vpnStateFile records what a `vpn stop` unloaded, so `vpn start` restores
// exactly that and nothing else.
func (d *Daemon) vpnStateFile() string {
	return filepath.Join(d.dirs.state, "vpn-stopped.json")
}

// tunnelDefaults lists tunnel interfaces holding an IPv4 default route. This is
// the one condition that makes the packet datapath refuse to run.
func tunnelDefaults() ([]string, error) {
	routes, err := netcfg.DefaultRoutes4()
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, r := range routes {
		if r.IsTunnel && !seen[r.Iface] {
			seen[r.Iface] = true
			out = append(out, r.Iface)
		}
	}
	return out, nil
}

// VPN implements the ctl "vpn" command.
//
// It runs in the daemon rather than in zaprctl because stopping a system VPN
// means `launchctl bootout system/<label>`, which needs root — and the daemon
// already has it. The CLI stays unprivileged.
func (d *Daemon) VPN(action string, force bool) (ctl.VPNData, error) {
	rep, err := vpn.Detect(tunnelDefaults)
	if err != nil {
		return ctl.VPNData{}, err
	}
	out := ctl.VPNData{
		TunnelDefaults: rep.TunnelDefaults,
		Unattributed:   rep.Unattributed,
		Blocking:       rep.Blocking(),
	}
	for _, f := range rep.Findings {
		p := ctl.VPNProvider{Name: f.Provider, AppRunning: f.AppRunning}
		for _, j := range f.Jobs {
			p.Jobs = append(p.Jobs, j.Domain+"/"+j.Label)
		}
		for _, pr := range f.Processes {
			p.PIDs = append(p.PIDs, pr.PID)
		}
		out.Providers = append(out.Providers, p)
	}

	switch action {
	case "", "status":
		return out, nil

	case "stop":
		if !rep.Blocking() && len(rep.Findings) == 0 {
			return out, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		res, serr := vpn.Stop(ctx, rep, tunnelDefaults, vpn.StopOpts{
			Force:     force,
			StateFile: d.vpnStateFile(),
			Logf:      d.log.Printf,
		})
		out.Actions = res.Stopped
		out.Restore = res.Restore
		out.TunnelDefaults = res.Remaining
		out.Blocking = len(res.Remaining) > 0
		return out, serr

	case "start":
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		res, serr := vpn.Start(ctx, d.vpnStateFile())
		out.Actions = res.Stopped
		return out, serr

	default:
		return out, fmt.Errorf("unknown vpn action %q; use status, stop or start", action)
	}
}

// currentTransportName reports the transport of the running datapath, "" when
// none is running.
func (d *Daemon) currentTransportName() string {
	if !d.isRunning() {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.trName
}

// waitDatapathSettled waits until the datapath is running or the budget expires.
// It exists so a transport override issued moments after launchd started the
// daemon acts on a real session rather than on an empty one.
func (d *Daemon) waitDatapathSettled(budget time.Duration) {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if d.isRunning() || !d.isEnabled() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
