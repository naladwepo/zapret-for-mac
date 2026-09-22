//go:build darwin

package divert

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
	"github.com/naladwepo/zapret-for-mac/internal/transport"
)

// Defaults for the pf objects this transport owns.
const (
	// DefaultAnchor is the pf anchor the steering ruleset lives in.
	DefaultAnchor = "zapret-mac"
	// DefaultExcludeTable is zapret's <nozapret> equivalent: destinations that
	// must never be steered.
	DefaultExcludeTable = "zmx"
	// DefaultTargetTable restricts steering to an address set (flowseal's ipset
	// mode). Empty by default, i.e. every destination in the port window.
	DefaultTargetTable = "zmt"
	// DefaultMTU is used when the uplink's MTU cannot be read.
	DefaultMTU = 1500
)

// readPollInterval bounds how long the datapath blocks in poll(2) before it
// rechecks ctx. It costs nothing while traffic flows (poll returns as soon as a
// packet arrives) and only bounds shutdown latency when idle.
const readPollInterval = 200 * time.Millisecond

// gcInterval is how often idle flows are evicted from the engine.
const gcInterval = 30 * time.Second

// injectHeadroom is how far below the uplink MTU the utun is configured.
//
// We author every re-emitted packet ourselves and write it straight to the link
// layer, so the kernel never fragments for us. Two ops insert bytes AFTER the
// application chose its packet size: --dpi-desync=ipfrag1 adds an 8-byte IPv6
// Fragment header and --dpi-desync-fooling=hopbyhop2 adds two 8-byte hop-by-hop
// headers. 24 bytes of headroom means a full-size packet still fits after both,
// on IPv6, where nothing can be fragmented after the fact.
const injectHeadroom = 24

// minTunMTU keeps a pathologically small uplink MTU from producing a utun that
// cannot carry a TCP handshake at all.
const minTunMTU = 1280

// errStopDuringSetup aborts setup at a step boundary because Close was called.
// Start turns it into a clean teardown, not a failure the operator has to act on.
var errStopDuringSetup = errors.New("divert: stopped while starting up")

// maxConsecutiveReadErrors stops a hard spin if the utun descriptor goes bad in
// a way that keeps returning an error immediately.
const maxConsecutiveReadErrors = 64

// shutdownGrace bounds how long Close waits for a goroutine to leave poll(2)
// before closing the descriptor anyway. It is comfortably above both poll
// intervals, so it is only ever reached if a goroutine is genuinely stuck.
const shutdownGrace = 2 * time.Second

// Options carries everything the divert transport needs that transport.Config
// does not describe: the pf objects it owns, the address sets to install, and
// the knobs a test or `zaprctl doctor` needs.
type Options struct {
	// Anchor is the pf anchor name; empty means DefaultAnchor.
	Anchor string
	// StateDir is where the pf token, the rollback journal and the byte-exact
	// /etc/pf.conf backup live. Required for a reversible install.
	StateDir string
	// PfConfPath and PfctlPath override the stock locations (tests).
	PfConfPath string
	PfctlPath  string

	// PF, when non-nil, is used instead of one built from Anchor/StateDir. The
	// daemon passes its own so that:
	//
	//   - LoadRules records its baseline on the object the daemon's drift watcher
	//     calls Verify() on. Without this the transport loaded rules into a
	//     private PF, the daemon's PF never saw a LoadRules, its haveBase stayed
	//     false, and Verify() silently skipped the one comparison it exists for —
	//     so a VPN or an OS update running `pfctl -f /etc/pf.conf` wiped our
	//     anchor's rules and `zaprctl status` reported no drift;
	//   - there is one journal per state directory. Two PF instances each opened
	//     their own append handle with an independently seeded sequence counter,
	//     so records collided, sorted into an order that was not the write order,
	//     and a rewrite by one handle unlinked the file the other kept appending
	//     to.
	//
	// A PF supplied here belongs to the caller: teardown flushes the anchor and
	// releases the reference, but never closes it.
	PF *netcfg.PF

	// ExcludeTable / TargetTable name the pf tables the steering rules refer
	// to. Empty ExcludeTable disables the exclusion; empty TargetTable steers
	// every destination.
	ExcludeTable string
	TargetTable  string
	// ExcludePrefixes / TargetPrefixes are the contents of those tables.
	ExcludePrefixes []netip.Prefix
	TargetPrefixes  []netip.Prefix

	// IPv6 additionally installs inet6 steering rules. It needs an IPv6
	// point-to-point pair on the utun; when that cannot be assigned the
	// transport logs why and stays IPv4-only.
	IPv6 bool
	// TunLocal6 / TunPeer6 override DefaultTunLocal6 / DefaultTunPeer6.
	TunLocal6 string
	TunPeer6  string

	// PreferRaw skips the BPF injector and uses the SOCK_RAW fallback. It
	// exists so an operator can reproduce the degraded path deliberately.
	PreferRaw bool
	// NoObserve disables the inbound BPF tap (autottl then falls back to the
	// engine's midpoint estimate).
	NoObserve bool
	// DryRun passes through to netcfg: every pf mutation is validated and
	// logged without being applied.
	DryRun bool

	// Logf receives progress and warnings; nil discards them.
	Logf func(format string, args ...any)
}

// counters holds the transport's statistics. Every field is written only by the
// datapath goroutine but read by Stats() from another one, hence the atomics.
type counters struct {
	pktsIn      atomic.Int64
	pktsOut     atomic.Int64
	pktsInject  atomic.Int64
	pktsDropped atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	errs        atomic.Int64
	// tapDrop is the tap's absolute BIOCGSTATS drop count (a Store, because the
	// kernel counter is itself cumulative); utunDrop counts our own ENOBUFS
	// reads. Stats reports the sum, which is why they cannot share a field.
	tapDrop  atomic.Int64
	utunDrop atomic.Int64
	// csumFixed counts intercepted packets whose checksums had to be repaired
	// before re-emission (see NormaliseChecksums).
	csumFixed atomic.Int64
}

// Transport is the packet-level datapath: pf steers a port window into a utun we
// own, reading from the utun is the interception, not re-emitting is the drop
// verdict, and re-emission is a raw Ethernet write that bypasses pf.
//
// It implements transport.Transport.
type Transport struct {
	cfg  transport.Config
	opts Options
	eng  *engine.Engine

	mu    sync.Mutex
	strat *strategy.Strategy
	route netcfg.Route
	mtu   int
	utun  *utunHandle // legacy field kept for on-disk/API compatibility; unused by pflog transport
	plog  *pflogHandle
	inj   injector
	obs   *observer
	pf    *netcfg.PF
	// ownPF is true when this transport built its own PF and must therefore close
	// it (releasing the journal's append handle) on the way out. A PF handed in
	// through Options belongs to the caller.
	ownPF bool
	caps  desync.Caps
	// loadedRules is the ruleset currently in the anchor, so Reload can tell
	// whether the port window actually changed.
	loadedRules string
	// warnings are the loud-but-not-fatal findings from Start.
	warnings []string

	// lifeMu serialises setup against teardown. Without it a Close() that lands
	// while setup is mid-flight tears down the handles that exist at that instant
	// and the rest of setup then installs state nobody ever unwinds — leaving pf
	// route-to'ing the whole port window at a dead utun, with Start still
	// reporting success. It is a separate lock from mu, which guards field reads
	// on the datapath and must never be held across a syscall.
	lifeMu sync.Mutex

	// ipidSeq is the running ip_id block allocator. Touched only by the
	// datapath goroutine.
	ipidSeq uint16

	// closed is the transport's own stop signal (Close), independent of the ctx
	// handed to Start. done is closed when the datapath loop has returned, so
	// Close can wait for it instead of pulling file descriptors out from under a
	// goroutine that is sitting in poll(2) — closing an fd another thread is
	// polling is exactly the kind of race that shows up once a month in
	// production and never in a test.
	closeOnce sync.Once
	closed    chan struct{}
	doneOnce  sync.Once
	done      chan struct{}
	running   atomic.Bool

	// obsCancel stops the inbound tap's goroutine and obsDone reports that it
	// has actually returned, for the same reason.
	obsCancel context.CancelFunc
	obsDone   chan struct{}

	st counters
}

// New builds a divert transport. Nothing privileged happens until Start.
func New(cfg transport.Config, opts Options) (*Transport, error) {
	if cfg.Engine == nil {
		return nil, errors.New("divert: transport.Config.Engine is required")
	}
	if cfg.Strategy == nil {
		return nil, errors.New("divert: transport.Config.Strategy is required")
	}
	if opts.Anchor == "" {
		opts.Anchor = DefaultAnchor
	}
	if opts.ExcludeTable == "" && len(opts.ExcludePrefixes) > 0 {
		opts.ExcludeTable = DefaultExcludeTable
	}
	if opts.TargetTable == "" && len(opts.TargetPrefixes) > 0 {
		opts.TargetTable = DefaultTargetTable
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &Transport{
		cfg:    cfg,
		opts:   opts,
		eng:    cfg.Engine,
		strat:  cfg.Strategy,
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}, nil
}

// Name implements transport.Transport.
func (t *Transport) Name() string { return "divert" }

// Caps implements transport.Transport. Before Start it reports the full set,
// because that is what the engine must be built with; after Start it reports what
// the injector actually delivers, so an operator sees the reduction the
// SOCK_RAW fallback imposes.
func (t *Transport) Caps() desync.Caps {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.caps == (desync.Caps{}) {
		return desync.FullCaps()
	}
	return t.caps
}

// Uplink reports the route the datapath attached to: the interface whose link
// layer every re-emitted packet is written on. Zero-valued before Start.
func (t *Transport) Uplink() netcfg.Route {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.route
}

// Warnings returns the non-fatal findings from Start (a tunnel default route, a
// degraded injector, an unavailable tap). The daemon surfaces them in
// `zaprctl status`.
func (t *Transport) Warnings() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.warnings...)
}

// warn records a warning and logs it immediately: the operator has to see these
// even if nothing ever asks for Warnings().
func (t *Transport) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	t.mu.Lock()
	dup := false
	for _, w := range t.warnings {
		if w == msg {
			dup = true
			break
		}
	}
	if !dup {
		t.warnings = append(t.warnings, msg)
	}
	t.mu.Unlock()
	if !dup {
		t.opts.Logf("divert: WARNING: %s", msg)
	}
}

// Start brings the datapath up and blocks until ctx is cancelled, Close is
// called, or the datapath fails fatally. Everything it installs is undone on the
// way out, including on panic.
func (t *Transport) Start(ctx context.Context) error {
	if err := t.setup(ctx); err != nil {
		// Unwind whatever did come up before the failure.
		t.teardown()
		if errors.Is(err, errStopDuringSetup) {
			// Close() landed mid-setup. Everything installed so far has just been
			// undone, so this is a clean stop, not a startup failure.
			t.opts.Logf("divert: stop requested during startup; nothing left installed")
			return nil
		}
		return err
	}
	t.running.Store(true)
	defer func() {
		t.running.Store(false)
		t.doneOnce.Do(func() { close(t.done) })
		t.teardown()
	}()
	return t.run(ctx)
}

// setup performs the five privileged steps in order. Each one is undone by
// teardown in reverse.
//
// It holds lifeMu for its whole duration and checks for a Close() between steps,
// so a stop that arrives mid-setup either waits for a complete install (which
// teardown then unwinds) or aborts at the next boundary. Both outcomes leave
// every installed handle in t.*, which is the only place teardown looks.
func (t *Transport) setup(ctx context.Context) error {
	t.lifeMu.Lock()
	defer t.lifeMu.Unlock()

	// 1. Resolve the uplink.
	route, err := t.resolveUplink()
	if err != nil {
		return err
	}
	mtu := route.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
		t.warn("could not read the MTU of %s, assuming %d", route.Iface, mtu)
	}
	t.mu.Lock()
	t.route, t.mtu = route, mtu
	t.mu.Unlock()
	t.opts.Logf("divert: uplink %s, local %s, gateway %s, mac %s, mtu %d",
		route.Iface, route.Local, route.Gateway, route.MAC, mtu)

	// 2. Create a dedicated pflog interface. PF will log the packet there and
	// block the original; unlike route-to/utun, this works on current Tahoe
	// kernels where steering to a utun is silently ignored.
	if err := t.stopRequested(); err != nil {
		return err
	}
	plog, err := createPFLog()
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.plog = plog
	t.mu.Unlock()
	t.opts.Logf("divert: interception through %s (DLT_PFLOG)", plog.Name())

	if err := t.stopRequested(); err != nil {
		return err
	}
	// 3. Open the injector.
	inj, err := t.openInjector(route, mtu)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.inj, t.caps = inj, inj.Caps()
	t.mu.Unlock()
	if lim := inj.Limits(); lim != "" {
		t.warn("%s", lim)
	}

	if err := t.stopRequested(); err != nil {
		return err
	}
	// 4. Install the pf ruleset.
	if err := t.setupPF(); err != nil {
		return err
	}

	if err := t.stopRequested(); err != nil {
		return err
	}
	// 5. Start the optional inbound tap.
	if !t.opts.NoObserve {
		t.startObserver(ctx, route.Iface)
	}
	return nil
}

// stopRequested reports a Close() or a cancelled start context as an error, so
// setup can abort between two privileged steps instead of finishing an install
// nobody wants.
func (t *Transport) stopRequested() error {
	select {
	case <-t.closed:
		return errStopDuringSetup
	default:
		return nil
	}
}

// tunnelDefaultIface returns the name of the first tunnel interface holding an
// IPv4 default route, or "" when none does. Pure, so the refusal logic is
// testable without a VPN on the machine.
func tunnelDefaultIface(routes []netcfg.Route) string {
	for _, r := range routes {
		if r.IsTunnel {
			return r.Iface
		}
	}
	return ""
}

// resolveUplink finds the interface to attach to and refuses, loudly, to run on
// a tunnel that a VPN owns.
//
// A full-tunnel VPN makes the whole design pointless: the traffic we would steer
// leaves through the tunnel, our BPF write would target the wrong link, and the
// DPI we are trying to defeat never sees the packets anyway.
func (t *Transport) resolveUplink() (netcfg.Route, error) {
	// DefaultRoute4 sorts non-tunnel routes first, so it answers "which link
	// should a BPF write target" — not "is a VPN carrying the traffic". Those
	// are different questions and conflating them is what let the datapath start
	// under an active VPN and break connectivity: ask the full list.
	if routes, rerr := netcfg.DefaultRoutes4(); rerr == nil {
		if tun := tunnelDefaultIface(routes); tun != "" && !t.cfg.AllowTunnelDefault {
			return netcfg.Route{}, fmt.Errorf("divert: refusing to start: %s holds an IPv4 default route, "+
				"so a full-tunnel VPN is active. The kernel would pick source addresses from that tunnel, and "+
				"re-emitting those packets on the physical link would break every steered connection, censored "+
				"or not. Disconnect the VPN (a paused app is not enough — check `ifconfig %s`), or accept the "+
				"breakage explicitly with --allow-vpn", tun, tun)
		}
	}

	def, derr := netcfg.DefaultRoute4()
	if derr == nil && def.IsTunnel {
		t.warn("the IPv4 default route goes through %s, a tunnel interface: a full-tunnel VPN "+
			"carries the traffic this transport would steer, so desync has nothing to act on",
			def.Iface)
	}

	if t.cfg.Iface == "" {
		if derr != nil {
			return netcfg.Route{}, fmt.Errorf("divert: cannot determine the uplink: %w", derr)
		}
		if def.IsTunnel {
			return netcfg.Route{}, fmt.Errorf("divert: refusing to start on the tunnel interface %s "+
				"(the IPv4 default route); disconnect the VPN, or name the physical uplink explicitly "+
				"with Config.Iface if you know what you are doing", def.Iface)
		}
		return def, nil
	}

	r, err := netcfg.RouteForIface(t.cfg.Iface)
	if err != nil {
		return netcfg.Route{}, fmt.Errorf("divert: uplink %q: %w", t.cfg.Iface, err)
	}
	if r.IsTunnel {
		t.warn("uplink %s was pinned explicitly but is a tunnel interface; a raw Ethernet write "+
			"needs a real link layer and will fail there", r.Iface)
	}
	return r, nil
}

// tunPair resolves the IPv4 point-to-point pair, avoiding a collision with an
// address some other interface already holds.
func (t *Transport) tunPair() (netip.Addr, netip.Addr, error) {
	local, err := parseAddrDefault(t.cfg.TunLocal, DefaultTunLocal)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("divert: TunLocal: %w", err)
	}
	peer, err := parseAddrDefault(t.cfg.TunPeer, DefaultTunPeer)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("divert: TunPeer: %w", err)
	}
	if !local.Is4() || !peer.Is4() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("divert: the utun point-to-point pair must be IPv4, got %s -> %s", local, peer)
	}
	chosen, chosenPeer, moved, err := pickTunPair(local, peer)
	if err != nil {
		t.warn("could not verify that %s/%s are free: %v", local, peer, err)
		return local, peer, nil
	}
	if moved {
		t.opts.Logf("divert: %s/%s collide with an existing interface address, using %s/%s instead",
			local, peer, chosen, chosenPeer)
	}
	return chosen, chosenPeer, nil
}

// tunPair6 resolves the IPv6 point-to-point pair, falling back to the RFC 5180
// benchmarking range.
func (t *Transport) tunPair6() (netip.Addr, netip.Addr) {
	local, err := parseAddrDefault(t.opts.TunLocal6, DefaultTunLocal6)
	if err != nil || !local.Is6() {
		local = netip.MustParseAddr(DefaultTunLocal6)
	}
	peer, err := parseAddrDefault(t.opts.TunPeer6, DefaultTunPeer6)
	if err != nil || !peer.Is6() {
		peer = netip.MustParseAddr(DefaultTunPeer6)
	}
	return local, peer
}

// parseAddrDefault parses s, substituting def when s is empty.
func parseAddrDefault(s, def string) (netip.Addr, error) {
	if strings.TrimSpace(s) == "" {
		s = def
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", s)
	}
	return a.Unmap(), nil
}

// openInjector opens the BPF injector, falling back to SOCK_RAW when BPF is
// unavailable, and reports the capability reduction honestly.
func (t *Transport) openInjector(route netcfg.Route, mtu int) (injector, error) {
	if !t.opts.PreferRaw {
		inj, err := newBPFInjector(route, mtu)
		if err == nil {
			t.opts.Logf("divert: injecting through %s on %s, next hop %s",
				inj.Device(), route.Iface, inj.GatewayMAC())
			return inj, nil
		}
		t.warn("BPF injector unavailable (%v); falling back to SOCK_RAW + IP_HDRINCL", err)
	}
	inj, err := newRawInjector(mtu)
	if err != nil {
		return nil, fmt.Errorf("divert: no usable injector: %w", err)
	}
	t.opts.Logf("divert: injecting through a raw socket (degraded)")
	return inj, nil
}

// setupPF installs the steering ruleset: patch the main ruleset so our anchor is
// evaluated, take a pf reference, load the rules, then fill the tables.
//
// Tables are populated AFTER the ruleset is loaded, and then verified: a ruleset
// load re-declares every table it mentions, and populating first would risk the
// addresses being dropped by that load. The verification pass costs one
// `pfctl -T show` and makes the order question moot.
func (t *Transport) setupPF() error {
	pf := t.opts.PF
	ownPF := false
	if pf == nil {
		pf = netcfg.NewPF(t.opts.Anchor, netcfg.PFOpts{
			PfConfPath: t.opts.PfConfPath,
			StateDir:   t.opts.StateDir,
			PfctlPath:  t.opts.PfctlPath,
			DryRun:     t.opts.DryRun,
			Logf:       t.opts.Logf,
		})
		ownPF = true
	}
	t.mu.Lock()
	t.pf, t.ownPF = pf, ownPF
	t.mu.Unlock()

	if patched, err := pf.EnsureAnchorStatements(); err != nil {
		return fmt.Errorf("divert: cannot make pf evaluate anchor %q: %w", t.opts.Anchor, err)
	} else if patched {
		t.opts.Logf("divert: %s now references anchor %q", pf.PfConfPath(), t.opts.Anchor)
	}
	if err := pf.Enable(); err != nil {
		return fmt.Errorf("divert: cannot enable pf: %w", err)
	}

	rules, err := t.steerRules()
	if err != nil {
		return err
	}
	if rules == "" {
		return fmt.Errorf("divert: strategy %q declares no TCP or UDP port window, so there is "+
			"nothing to steer", t.strategyName())
	}
	if err := pf.LoadRules(rules); err != nil {
		return fmt.Errorf("divert: cannot load the steering ruleset: %w", err)
	}
	t.mu.Lock()
	t.loadedRules = rules
	t.mu.Unlock()

	t.syncTable(pf, t.opts.ExcludeTable, t.opts.ExcludePrefixes)
	t.syncTable(pf, t.opts.TargetTable, t.opts.TargetPrefixes)
	return nil
}

// syncTable replaces a pf table's contents and verifies the count landed. A
// table failure is a warning, not a fatal error: an empty exclude table means
// "nothing excluded" and an empty target table means "every destination", both of
// which are safe, working configurations.
func (t *Transport) syncTable(pf *netcfg.PF, name string, prefixes []netip.Prefix) {
	if name == "" || len(prefixes) == 0 {
		return
	}
	if err := pf.TableReplace(name, prefixes); err != nil {
		t.warn("cannot populate pf table <%s> with %d prefix(es): %v", name, len(prefixes), err)
		return
	}
	if t.opts.DryRun {
		return
	}
	if n, err := pf.TableCount(name); err == nil && n == 0 {
		// The ruleset load wiped it after all; one retry settles it.
		if err := pf.TableReplace(name, prefixes); err != nil {
			t.warn("pf table <%s> came back empty and refilling it failed: %v", name, err)
		}
	}
}

// steerRules renders the anchor ruleset for the active strategy's port window.
func (t *Transport) steerRules() (string, error) {
	t.mu.Lock()
	strat, plog, utun, inj := t.strat, t.plog, t.utun, t.inj
	t.mu.Unlock()
	if strat == nil {
		return "", errors.New("divert: no strategy loaded")
	}
	if plog == nil && utun == nil {
		return "", errors.New("divert: no packet interceptor is up yet")
	}

	exemptRoot := t.cfg.ExemptRoot
	if inj != nil && inj.Name() == "raw" && !exemptRoot {
		// A raw-socket send goes through ip_output and therefore through pf, so
		// without `user { > root }` our own injections would match the steering
		// rule and come straight back at us through the utun. This is not a
		// preference, it is the loop breaker.
		exemptRoot = true
		t.warn("ExemptRoot was off but the raw-socket injector requires it (otherwise our own " +
			"injections loop back through the utun); enabling it")
	}
	if !exemptRoot {
		t.warn("ExemptRoot is off: root-owned traffic stays inside the steered window. That is safe " +
			"for the BPF injector, which bypasses pf, but any socket the daemon itself opens on a " +
			"window port will be steered into its own datapath")
	}

	if plog == nil {
		o := netcfg.SteerOpts{
			Utun: utun.Name, TunPeer: utun.Peer.String(),
			TCPPorts: portRanges(strat.WindowTCP), UDPPorts: portRanges(strat.WindowUDP),
			ExcludeTable: t.opts.ExcludeTable, TargetTable: t.opts.TargetTable,
			ExemptRoot: exemptRoot, BlockQUIC: t.cfg.BlockQUIC,
		}
		rules := netcfg.SteerRules(o)
		if t.opts.IPv6 && utun.HaveIPv6 {
			o6 := o
			o6.IPv6, o6.TunPeer6, o6.NoLoopbackPass = true, utun.Peer6.String(), true
			rules = mergeRulesets(rules, netcfg.SteerRules(o6))
		}
		return rules, nil
	}

	o := netcfg.LogDropOpts{
		PFLog:        plog.Name(),
		Iface:        t.route.Iface,
		TCPPorts:     portRanges(strat.WindowTCP),
		UDPPorts:     portRanges(strat.WindowUDP),
		ExcludeTable: t.opts.ExcludeTable,
		TargetTable:  t.opts.TargetTable,
		ExemptRoot:   exemptRoot,
	}
	rules := netcfg.LogDropRules(o)
	if t.opts.IPv6 {
		o6 := o
		o6.IPv6 = true
		rules = mergeRulesets(rules, netcfg.LogDropRules(o6))
	}
	return rules, nil
}

// mergeRulesets concatenates two rendered rulesets, dropping the exact duplicate
// lines the second one repeats (the `table <...> persist` declarations, which pf
// only wants once per anchor). No line is reordered: pf's filter semantics are
// order sensitive.
func mergeRulesets(a, b string) string {
	seen := make(map[string]bool)
	var out []string
	for _, chunk := range []string{a, b} {
		for _, line := range strings.Split(chunk, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// portRanges converts a strategy port window into netcfg's representation.
func portRanges(ps strategy.PortSet) []netcfg.PortRange {
	if len(ps) == 0 {
		return nil
	}
	out := make([]netcfg.PortRange, 0, len(ps))
	for _, r := range ps {
		out = append(out, netcfg.PortRange{r.Lo, r.Hi})
	}
	return out
}

// windowUnion is the set of ports the inbound tap should watch: replies come back
// from a port we steered towards, on either protocol.
func windowUnion(s *strategy.Strategy) []netcfg.PortRange {
	if s == nil {
		return nil
	}
	out := portRanges(s.WindowTCP)
	return append(out, portRanges(s.WindowUDP)...)
}

// startObserver brings up the read-only inbound tap. Failure is logged and
// ignored: autottl then falls back to the engine's midpoint estimate.
func (t *Transport) startObserver(ctx context.Context, iface string) {
	t.mu.Lock()
	strat := t.strat
	t.mu.Unlock()

	obs, err := newObserver(iface, windowUnion(strat))
	if err != nil {
		t.warn("inbound tap unavailable (%v); autottl will use the engine's estimated hop count "+
			"instead of a measured one", err)
		return
	}
	t.mu.Lock()
	t.obs = obs
	t.mu.Unlock()
	t.opts.Logf("divert: inbound tap on %s via %s (kernel port filter: %v)",
		iface, obs.Device(), obs.Filtered())

	octx, cancel := context.WithCancel(ctx)
	obsDone := make(chan struct{})
	t.mu.Lock()
	t.obsCancel, t.obsDone = cancel, obsDone
	t.mu.Unlock()

	go func() {
		defer close(obsDone)
		err := obs.Run(octx, t.eng.OnInbound, func(total uint64) {
			t.st.tapDrop.Store(int64(total))
		})
		if err != nil && octx.Err() == nil {
			t.opts.Logf("divert: inbound tap stopped: %v", err)
		}
	}()
	// Close() must stop the tap too, not only a cancelled ctx.
	go func() {
		select {
		case <-t.closed:
			cancel()
		case <-octx.Done():
		}
	}()
}

// ---------------------------------------------------------------------------
// datapath
// ---------------------------------------------------------------------------

// run is the datapath loop: one goroutine, one reusable read buffer, and no
// allocation per packet beyond what proto.Parse and Tmpl.Marshal require.
func (t *Transport) run(ctx context.Context) error {
	t.mu.Lock()
	plog := t.plog
	t.mu.Unlock()
	if plog == nil {
		return errors.New("divert: datapath started without pflog")
	}

	// The utun hands us at most one MTU-sized packet plus the 4-byte framing
	// header; the slack absorbs a larger MTU set behind our back.
	buf := make([]byte, pflogBufLen)
	lastGC := time.Now()
	consecutiveErrs := 0

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.closed:
			return nil
		default:
		}

		ver, pkt, ok, err := plog.Read(buf, readPollInterval)
		if err != nil {
			// A closed or revoked descriptor is fatal; anything else is counted
			// and retried, because dropping the datapath over one bad read would
			// take the user's network with it.
			if errors.Is(err, unix.EBADF) || errors.Is(err, unix.ENXIO) {
				return fmt.Errorf("divert: pflog read failed fatally: %w", err)
			}
			t.st.errs.Add(1)
			if errors.Is(err, unix.ENOBUFS) {
				t.st.utunDrop.Add(1)
			}
			consecutiveErrs++
			if consecutiveErrs > maxConsecutiveReadErrors {
				return fmt.Errorf("divert: %d consecutive pflog read errors, last: %w",
					consecutiveErrs, err)
			}
			continue
		}
		consecutiveErrs = 0
		// The sweep has to happen on the BUSY path too. Checking it only when
		// poll(2) timed out meant the flow table was never swept while traffic
		// flowed — which is precisely when it needs sweeping.
		if time.Since(lastGC) >= gcInterval {
			lastGC = time.Now()
			t.eng.GC()
			if err := t.eng.FlushAutoLists(); err != nil {
				t.opts.Logf("divert: persisting a self-learning hostlist failed: %v", err)
			}
		}
		if !ok {
			continue
		}
		t.handle(ver, pkt)
	}
}

// handle processes one intercepted packet. It must never drop a packet it did not
// deliberately decide to drop: everything unparseable, fragmented or not TCP/UDP
// is forwarded verbatim.
func (t *Transport) handle(ver uint8, raw []byte) {
	t.st.pktsIn.Add(1)
	t.st.bytesIn.Add(int64(len(raw)))

	p, err := proto.Parse(raw)
	if err != nil {
		// Non-initial IP fragments carry no L4 header, and a malformed packet is
		// not ours to interpret. Both go out untouched, framed by the address
		// family the utun itself reported.
		t.forward(ver, raw)
		return
	}
	// A BPF write skips the kernel's transmit path, so the checksums have to be
	// right in the buffer already. See NormaliseChecksums for why this is a safety
	// net rather than an expected fixup.
	if fixIP, fixL4 := NormaliseChecksums(p); fixIP || fixL4 {
		n := t.st.csumFixed.Add(1)
		if n == 1 {
			t.warn("the kernel handed us a packet with an unset checksum "+
				"(ip=%v l4=%v); repairing it before re-emitting, and every one after it silently",
				fixIP, fixL4)
		}
	}

	var plan *desync.Plan
	switch {
	case p.IsTCP():
		plan, err = t.eng.OnTCP(p)
	case p.IsUDP():
		plan, err = t.eng.OnUDP(p)
	default:
		t.forward(ver, raw)
		return
	}
	if err != nil {
		t.st.errs.Add(1)
		if t.cfg.Verbose > 0 {
			t.opts.Logf("divert: engine refused %s:%d -> %s:%d: %v",
				p.Src, p.SrcPort, p.Dst, p.DstPort, err)
		}
		t.forward(ver, raw)
		t.forgetIfClosing(p)
		return
	}

	if plan != nil {
		t.emitPlan(ver, p, plan, raw)
	} else {
		t.forward(ver, raw)
	}
	t.forgetIfClosing(p)
}

// emitPlan builds the plan's packets, injects them, and forwards the original
// only when the plan did not claim it.
func (t *Transport) emitPlan(ver uint8, p *proto.Pkt, plan *desync.Plan, raw []byte) {
	pkts, ids, err := BuildPlan(p, plan, BuildOpts{IPIDStart: t.ipidSeq})
	if err != nil {
		t.st.errs.Add(1)
		t.opts.Logf("divert: cannot build the plan for %s:%d -> %s:%d: %v",
			p.Src, p.SrcPort, p.Dst, p.DstPort, err)
		// The safe fallback is always the application's own packet.
		t.forward(ver, raw)
		return
	}
	// Reserve exactly the ip_id values the plan issued, so the next plan continues
	// the sequence contiguously. Counting wire packets instead would skip values
	// whenever a packet was fragmented (both halves share one id).
	t.ipidSeq += uint16(ids)

	sent := 0
	for _, out := range pkts {
		// Every packet the plan produced is well formed, so its own version
		// nibble is authoritative here.
		if err := t.inject(ipVersionOf(out), out); err != nil {
			t.st.errs.Add(1)
			if t.cfg.Verbose > 0 {
				t.opts.Logf("divert: injecting %d bytes failed: %v", len(out), err)
			}
			continue
		}
		sent++
		t.st.pktsInject.Add(1)
		t.st.bytesOut.Add(int64(len(out)))
	}

	if plan.DropOriginal {
		if sent == 0 && len(pkts) > 0 {
			// Every packet of the plan failed to reach the wire (an oversize frame
			// rejected by bpfwrite, a transient ENOBUFS). Dropping the original as
			// well would silently lose the application's request, and its
			// retransmission would take the identical path. Forward it instead:
			// no desync is always better than no data.
			t.warn("a whole plan failed to inject (%d packet(s)); forwarding the "+
				"application's own packet instead of dropping it", len(pkts))
			t.forward(ver, raw)
			return
		}
		t.st.pktsDropped.Add(1)
		if t.cfg.Verbose > 1 && len(plan.Degraded) > 0 {
			t.opts.Logf("divert: plan degraded: %s", strings.Join(plan.Degraded, ", "))
		}
		return
	}
	t.forward(ver, raw)
}

// forward re-emits the application's own packet unchanged.
func (t *Transport) forward(ver uint8, raw []byte) {
	if err := t.inject(ver, raw); err != nil {
		t.st.errs.Add(1)
		if t.cfg.Verbose > 0 {
			t.opts.Logf("divert: forwarding %d bytes failed: %v", len(raw), err)
		}
		return
	}
	t.st.pktsOut.Add(1)
	t.st.bytesOut.Add(int64(len(raw)))
}

// inject writes one packet through the active injector.
func (t *Transport) inject(ver uint8, pkt []byte) error {
	t.mu.Lock()
	inj := t.inj
	t.mu.Unlock()
	if inj == nil {
		return errors.New("divert: no injector")
	}
	return inj.Inject(ver, pkt)
}

// forgetIfClosing drops the engine's flow state once the client half closes or
// resets, so a long-lived process cycling through ports does not accumulate
// entries between GC sweeps.
func (t *Transport) forgetIfClosing(p *proto.Pkt) {
	if !p.IsTCP() || p.Flags&(proto.TCPFin|proto.TCPRst) == 0 {
		return
	}
	t.eng.Forget(desync.FlowKey{
		Src: p.Src, Dst: p.Dst,
		SrcPort: p.SrcPort, DstPort: p.DstPort,
		Proto: proto.IPProtoTCP,
	})
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

// Reload swaps the active strategy. Established flows keep the profile they
// already matched (the engine caches it), and the pf ruleset is only reloaded
// when the port window actually changed — reloading it needlessly would flush pf
// state for every steered connection.
func (t *Transport) Reload(s *strategy.Strategy) error {
	if s == nil {
		return errors.New("divert: Reload needs a strategy")
	}
	t.mu.Lock()
	t.strat = s
	pf, plog := t.pf, t.plog
	t.mu.Unlock()

	t.eng.Reload(s)

	if pf == nil || plog == nil {
		return nil // not started yet; Start will render the new window
	}
	rules, err := t.steerRules()
	if err != nil {
		return err
	}
	t.mu.Lock()
	same := rules == t.loadedRules
	t.mu.Unlock()
	if same {
		t.opts.Logf("divert: strategy %q loaded, port window unchanged", s.Name)
		return nil
	}
	if err := pf.LoadRules(rules); err != nil {
		return fmt.Errorf("divert: cannot load the steering ruleset for strategy %q: %w", s.Name, err)
	}
	t.mu.Lock()
	t.loadedRules = rules
	t.mu.Unlock()
	t.syncTable(pf, t.opts.ExcludeTable, t.opts.ExcludePrefixes)
	t.syncTable(pf, t.opts.TargetTable, t.opts.TargetPrefixes)
	t.opts.Logf("divert: steering ruleset reloaded for strategy %q", s.Name)
	return nil
}

// Stats implements transport.Transport.
func (t *Transport) Stats() transport.Stats {
	t.mu.Lock()
	name := "divert"
	if t.inj != nil {
		name = "divert/" + t.inj.Name()
	}
	t.mu.Unlock()

	c := t.eng.Counters()
	return transport.Stats{
		Transport:   name,
		FlowsActive: int64(t.eng.FlowCount()),
		FlowsTotal:  c.FlowsTotal,
		PktsIn:      t.st.pktsIn.Load(),
		PktsOut:     t.st.pktsOut.Load(),
		PktsInject:  t.st.pktsInject.Load(),
		PktsDropped: t.st.pktsDropped.Load(),
		BytesIn:     t.st.bytesIn.Load(),
		BytesOut:    t.st.bytesOut.Load(),
		Desyncs:     c.Desyncs,
		Matched:     c.Matched,
		Errors:      t.st.errs.Load() + c.Errors,
		QueueDrop:   t.st.tapDrop.Load() + t.st.utunDrop.Load(),
	}
}

// Close stops the datapath and undoes everything Start installed. It is safe to
// call twice and safe to call without Start.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	if t.running.Load() {
		// Let the datapath notice the signal and return; its own defer then does
		// the teardown, and this call becomes the idempotent second one.
		select {
		case <-t.done:
		case <-time.After(shutdownGrace):
			t.opts.Logf("divert: the datapath did not stop within %s, tearing down anyway", shutdownGrace)
		}
	}
	return t.teardown()
}

// teardown unwinds the five setup steps in reverse order, doing every step even
// if an earlier one failed: leaving pf enabled or the anchor loaded would break
// the user's network, so a partial failure must not stop the rest.
//
// Everything it undoes is also recorded in netcfg's journal, so a SIGKILLed
// daemon leaves nothing that `zaprctl doctor --repair` cannot roll back.
func (t *Transport) teardown() error {
	t.lifeMu.Lock()
	defer t.lifeMu.Unlock()

	t.mu.Lock()
	obs, pf, utun, plog, inj := t.obs, t.pf, t.utun, t.plog, t.inj
	ownPF := t.ownPF
	obsCancel, obsDone := t.obsCancel, t.obsDone
	t.obs, t.pf, t.utun, t.plog, t.inj = nil, nil, nil, nil, nil
	t.ownPF = false
	t.obsCancel, t.obsDone = nil, nil
	t.mu.Unlock()

	if obs == nil && pf == nil && utun == nil && plog == nil && inj == nil && obsCancel == nil {
		// Nothing to claim: either nothing was installed or a previous teardown
		// already unwound it. Deliberately NOT a latch — an earlier no-op call
		// must not stop a later one from unwinding a real install (that is exactly
		// how a Close() racing setup() used to leave the pf ruleset and the pf
		// reference behind for the rest of uptime).
		return nil
	}

	var errs []string
	add := func(step string, err error) {
		if err != nil {
			errs = append(errs, step+": "+err.Error())
			t.opts.Logf("divert: teardown: %s failed: %v", step, err)
		}
	}

	// The tap first: it is read-only and holds nothing the rest depends on. Its
	// goroutine has to be gone before the descriptor is, or the close would land
	// under a live poll(2).
	if obsCancel != nil {
		obsCancel()
	}
	if obsDone != nil {
		select {
		case <-obsDone:
		case <-time.After(shutdownGrace):
			t.opts.Logf("divert: the inbound tap did not stop within %s", shutdownGrace)
		}
	}
	if obs != nil {
		add("closing the inbound tap", obs.Close())
	}
	if pf != nil {
		// Flushing the anchor removes the steering rules and the tables in one
		// step; the anchor statements in /etc/pf.conf are left in place on
		// purpose, because they are inert without rules and removing them would
		// mean another /etc/pf.conf write on every stop.
		add("flushing the pf anchor", pf.FlushRules())
		add("releasing the pf token", pf.Release())
		if ownPF {
			// Only a PF this transport built is ours to close. Close releases the
			// journal's lazily opened append handle; leaking one per datapath
			// restart exhausted the process' descriptors after a few hours of a
			// late-stage failure loop.
			add("closing pf state", pf.Close())
		}
	}
	// The utun goes after pf: while a route-to rule still names it, destroying it
	// would make pf drop the steered packets instead of passing them.
	if utun != nil {
		add("closing the utun", utun.Close())
	}
	if plog != nil {
		add("closing the pflog interceptor", plog.Close())
	}
	if inj != nil {
		add("closing the injector", inj.Close())
	}

	if len(errs) > 0 {
		return fmt.Errorf("divert: teardown incomplete: %s", strings.Join(errs, "; "))
	}
	t.opts.Logf("divert: stopped, all changes undone")
	return nil
}

// RemoveAnchorStatements deletes our marker block from the main pf ruleset. It is
// deliberately NOT part of teardown (see there); `zaprctl uninstall` and
// `zaprctl doctor --repair` call it.
func (t *Transport) RemoveAnchorStatements() error {
	t.mu.Lock()
	pf := t.pf
	t.mu.Unlock()
	if pf == nil {
		pf = t.opts.PF
	}
	if pf == nil {
		pf = netcfg.NewPF(t.opts.Anchor, netcfg.PFOpts{
			PfConfPath: t.opts.PfConfPath,
			StateDir:   t.opts.StateDir,
			PfctlPath:  t.opts.PfctlPath,
			DryRun:     t.opts.DryRun,
			Logf:       t.opts.Logf,
		})
	}
	return pf.RemoveAnchorStatements()
}

// strategyName is the active strategy's name, for messages.
func (t *Transport) strategyName() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.strat == nil {
		return "<none>"
	}
	return t.strat.Name
}

// compile-time proof that the contract is satisfied.
var _ transport.Transport = (*Transport)(nil)
