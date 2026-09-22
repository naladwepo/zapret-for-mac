//go:build darwin

// The embedded capability probe answers, on the machine it runs on, one question that
// decides this project's entire feature set: can a userspace program on macOS
// intercept, inspect and re-emit its own outbound TCP packets?
//
// macOS has no divert socket and its pf has neither divert-to nor
// divert-packet, so the nfqws/winws intercept-mangle-reinject core cannot be
// ported directly. The design under test instead steers a narrow port window
// into a utun with a pf "pass out route-to (utunN peer)" rule, reads the packets
// off the utun file descriptor, and re-emits them with a raw Ethernet write on
// the physical interface (which bypasses pf and therefore does not loop). The
// degraded fallback is a pf rdr plus a DIOCNATLOOK userspace relay.
//
// The probe runs ten stages, each printing PASS/FAIL/SKIP with a one-line
// reason, and each undoing whatever it changed — on normal exit, on SIGINT or
// SIGTERM, and on panic. It never writes /etc/pf.conf, never changes the
// default route, never touches DNS, never leaves pf enabled or rules loaded,
// and never sends traffic anywhere except --target and the local gateway.
//
// Usage:
//
//	sudo zaprctl probe [--iface en0] [--target 1.1.1.1] [--port 443]
//	                  [--utun-unit 9] [--json] [--timeout 8s]
//
// The exit status is always 0 — a FAIL is data, not a crash — except 2 when the
// probe is not run as root.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Verdicts the probe can reach.
const (
	verdictFullParity = "full-parity-possible"
	verdictProxyOnly  = "proxy-only"
	verdictUnclear    = "inconclusive"
)

// natlookListenPort is the loopback port the DIOCNATLOOK stage redirects to.
const natlookListenPort = 19988

// stageStatus is the outcome of a single stage.
type stageStatus string

const (
	statusPass stageStatus = "PASS"
	statusFail stageStatus = "FAIL"
	statusSkip stageStatus = "SKIP"
)

// stageResult is one row of the report.
type stageResult struct {
	Stage  int            `json:"stage"`
	Name   string         `json:"name"`
	Status stageStatus    `json:"status"`
	Detail string         `json:"detail"`
	Data   map[string]any `json:"data,omitempty"`
}

// report is the whole machine-readable output.
type report struct {
	Tool      string        `json:"tool"`
	StartedAt string        `json:"started_at"`
	Target    string        `json:"target"`
	Iface     string        `json:"iface"`
	Stages    []stageResult `json:"stages"`
	Verdict   string        `json:"verdict"`
	Rationale string        `json:"rationale"`
	Warnings  []string      `json:"warnings,omitempty"`
	Notes     []string      `json:"notes,omitempty"`
}

// cleanupEntry is one undo action, run LIFO.
type cleanupEntry struct {
	name string
	fn   func() error
}

// capturedPkt is a packet read off the utun together with its framing prefix.
type capturedPkt struct {
	prefix []byte
	data   []byte
	at     time.Time
}

// probe holds the configuration, everything the stages discover, and the
// cleanup stack.
type probe struct {
	// configuration
	ifaceFlag   string
	target      netip.Addr
	port        int
	utunUnit    int
	jsonOut     bool
	replaceMain bool
	timeout     time.Duration
	started     time.Time

	// output
	results  []stageResult
	warnings []string
	notes    []string

	// discovered state
	env         envInfo
	ifaces      map[int]*ifaceInfo
	route       routeInfo
	allDefaults []routeInfo
	haveRoute   bool
	gwMAC       net.HardwareAddr
	utun        *utunHandle
	tunLocal    netip.Addr
	tunPeer     netip.Addr

	// pf state
	pfFD            int
	pfToken         string
	pfEnabledBefore bool
	pfRulePath      string
	pfMainReplaced  bool
	pfAnchorLoaded  bool
	appleSubLoaded  bool
	pfConfBefore    fileWitness
	pfConfAfter     fileWitness

	// datapath state
	bpfW      *bpfHandle
	bpfR      *bpfHandle
	raw       *rawSender
	firstPkt  *capturedPkt
	emitted   []byte // the IPv4 packet stage 7 handed to the wire
	emitSport uint16
	emitSeq   uint32
	dialCh    chan error
	dialErr   error
	dialKnown bool
	utunPkts  chan capturedPkt
	stopRead  chan struct{}
	readerWG  sync.WaitGroup

	// cleanup
	mu          sync.Mutex
	cleanups    []cleanupEntry
	cleanupDone bool
	// cleanupRunning guards against the signal handler re-entering a cleanup that
	// a stage's defer is already draining.
	cleanupRunning bool
	cleanupLog     []string
}

func runEmbeddedProbe(args []string) {
	// The probe historically used package flag globals. Give it a private flag
	// set now that it lives inside the user-facing CLI, and pass only the probe
	// arguments (not the top-level `probe` command) to it.
	flag.CommandLine = flag.NewFlagSet("zaprctl probe", flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	os.Args = append([]string{"zaprctl probe"}, args...)
	p := &probe{pfFD: -1, started: time.Now()}
	var targetStr string
	flag.StringVar(&p.ifaceFlag, "iface", "", "physical interface to use (default: the interface carrying the IPv4 default route)")
	flag.StringVar(&targetStr, "target", "1.1.1.1", "target IPv4 address; the only remote address the probe ever contacts")
	flag.IntVar(&p.port, "port", 443, "target TCP port")
	flag.IntVar(&p.utunUnit, "utun-unit", 9, "preferred utun unit number (falls back to a kernel-chosen unit if busy)")
	flag.BoolVar(&p.jsonOut, "json", false, "emit a machine-readable JSON report instead of the table")
	flag.BoolVar(&p.replaceMain, "replace-main-ruleset", false,
		"allow the probe to load a temporary MAIN pf ruleset (pfctl -f -) when our anchor is not reachable.\n"+
			"\tThis is off by default because it flushes every dynamically populated com.apple/* sub-anchor\n"+
			"\t(Internet Sharing NAT, AirDrop, screen sharing) and would wipe a running zapretd's steering rules.\n"+
			"\tWithout it, stages 5/6/9 report SKIP instead of replacing the machine's live ruleset.")
	flag.DurationVar(&p.timeout, "timeout", 8*time.Second, "per-operation budget for waits (packet arrival, handshake completion, captures)")
	flag.Parse()

	addr, err := netip.ParseAddr(targetStr)
	if err != nil || !addr.Is4() {
		fmt.Fprintf(os.Stderr, "zaprctl probe: --target must be a literal IPv4 address, got %q\n", targetStr)
		os.Exit(2)
	}
	p.target = addr
	if p.port < 1 || p.port > 65535 {
		fmt.Fprintf(os.Stderr, "zaprctl probe: --port out of range: %d\n", p.port)
		os.Exit(2)
	}
	if p.utunUnit < 0 || p.utunUnit > 1000 {
		fmt.Fprintf(os.Stderr, "zaprctl probe: --utun-unit out of range: %d\n", p.utunUnit)
		os.Exit(2)
	}
	if p.timeout < time.Second {
		p.timeout = time.Second
	}

	// Cleanup must also happen when the operator interrupts the run.
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, unix.SIGINT, unix.SIGTERM)
	go func() {
		s := <-sigc
		fmt.Fprintf(os.Stderr, "\nzaprctl probe: %v received, undoing all changes...\n", s)
		p.cleanup()
		for _, l := range p.cleanupLog {
			fmt.Fprintf(os.Stderr, "  cleanup: %s\n", l)
		}
		// Non-zero: an interrupted probe produced no verdict, and a script must not
		// read "exit 0" as "every capability was proven".
		os.Exit(exitInterrupted)
	}()

	os.Exit(p.run())
}

// run executes all ten stages and emits the report. Cleanup is guaranteed by
// the deferred call, including on panic.
func (p *probe) run() (code int) {
	defer func() {
		if r := recover(); r != nil {
			p.cleanup()
			p.add(0, "internal", statusFail,
				fmt.Sprintf("probe panicked: %v", r),
				map[string]any{"stack": string(debug.Stack())})
			p.emit()
			code = 0
		}
	}()
	defer p.cleanup()

	notRoot := p.stage1Environment()
	p.stage2DefaultRoute()
	p.stage3GatewayMAC()
	if notRoot {
		for _, s := range []struct {
			n    int
			name string
		}{
			{4, "utun create"}, {5, "pf availability"}, {6, "route-to delivers to utun"},
			{7, "BPF write"}, {8, "SOCK_RAW fallback"}, {9, "DIOCNATLOOK"},
			{10, "cleanup verification"},
		} {
			p.add(s.n, s.name, statusSkip, "requires root (re-run under sudo)", nil)
		}
		p.emit()
		return 2
	}

	p.stage4UTUN()
	p.stage5PF()
	p.stage6RouteToGate()
	p.stage7BPFWrite()
	p.stage8RawSocket()
	p.stage9Natlook()
	p.stage10Cleanup()

	p.emit()
	return 0
}

// ---------------------------------------------------------------------------
// bookkeeping
// ---------------------------------------------------------------------------

// add records a stage outcome.
func (p *probe) add(stage int, name string, st stageStatus, detail string, data map[string]any) {
	p.results = append(p.results, stageResult{Stage: stage, Name: name, Status: st, Detail: detail, Data: data})
}

// warn records a warning shown prominently above the table.
func (p *probe) warn(format string, args ...any) {
	p.warnings = append(p.warnings, fmt.Sprintf(format, args...))
}

// note records an explanatory remark printed after the verdict.
func (p *probe) note(format string, args ...any) {
	p.notes = append(p.notes, fmt.Sprintf(format, args...))
}

// onCleanup pushes an undo action onto the LIFO cleanup stack.
func (p *probe) onCleanup(name string, fn func() error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanups = append(p.cleanups, cleanupEntry{name: name, fn: fn})
}

// cleanup runs every registered undo action in reverse order. It is idempotent
// and safe to call from the signal handler, the panic handler and stage 10.
func (p *probe) cleanup() {
	p.mu.Lock()
	if p.cleanupRunning {
		// Re-entered from the signal handler while a stage's defer is already
		// draining: let the first caller finish the stack.
		p.mu.Unlock()
		return
	}
	p.cleanupRunning = true
	p.cleanupDone = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.cleanupRunning = false
		p.mu.Unlock()
	}()

	// Drain in a LOOP rather than snapshotting once: a stage running concurrently
	// with the signal handler can still push an undo action, and a snapshot-and-
	// latch cleanup would never run it.
	for {
		p.mu.Lock()
		if len(p.cleanups) == 0 {
			p.mu.Unlock()
			return
		}
		e := p.cleanups[len(p.cleanups)-1]
		p.cleanups = p.cleanups[:len(p.cleanups)-1]
		p.mu.Unlock()
		err := func() (err error) {
			// A failing undo action must not prevent the remaining ones.
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("panicked: %v", r)
				}
			}()
			return e.fn()
		}()
		p.mu.Lock()
		if err != nil {
			p.cleanupLog = append(p.cleanupLog, fmt.Sprintf("%s: FAILED: %v", e.name, err))
		} else {
			p.cleanupLog = append(p.cleanupLog, e.name+": ok")
		}
		p.mu.Unlock()
	}
}

// exitInterrupted is the exit status of a probe that was interrupted: it produced
// no verdict, so it must not look like a successful run.
const exitInterrupted = 3

// tokenWitnessPath is where an interrupted probe leaves its pf reference token, so
// a SIGKILLed run can still be cleaned up by hand.
const tokenWitnessPath = "/tmp/zapret-mac-probe.pf-token"

// writeTokenWitness persists the pf reference token. Failures are reported as a
// note, never fatal: the probe changes nothing that depends on it.
func (p *probe) writeTokenWitness(token string) {
	if err := os.WriteFile(tokenWitnessPath, []byte(token+"\n"), 0o600); err != nil {
		p.note("could not record the pf token in %s (%v); if this run is killed with -9, release the "+
			"reference by hand with `sudo pfctl -X %s`", tokenWitnessPath, err, token)
		return
	}
	p.onCleanup("remove "+tokenWitnessPath, func() error { return os.Remove(tokenWitnessPath) })
	p.note("the pf reference token is recorded in %s; if this run is killed with -9, release it with "+
		"`sudo pfctl -X $(cat %s)`", tokenWitnessPath, tokenWitnessPath)
}

// findStage returns a previously recorded stage result.
func (p *probe) findStage(n int) (stageResult, bool) {
	for _, r := range p.results {
		if r.Stage == n {
			return r, true
		}
	}
	return stageResult{}, false
}

// stageIs reports whether stage n finished with the given status.
func (p *probe) stageIs(n int, st stageStatus) bool {
	r, ok := p.findStage(n)
	return ok && r.Status == st
}

// budget clamps a wait to the --timeout budget.
func (p *probe) budget(d time.Duration) time.Duration { return min(d, p.timeout) }

// targetAddrPort is the probe's single permitted remote endpoint.
func (p *probe) targetAddrPort() string {
	return net.JoinHostPort(p.target.String(), strconv.Itoa(p.port))
}

// ---------------------------------------------------------------------------
// stage 1: environment
// ---------------------------------------------------------------------------

// stage1Environment reports uid, macOS/Darwin version, architecture and SIP
// state. It returns true when the probe is not running as root, in which case
// every privileged stage is skipped.
func (p *probe) stage1Environment() (notRoot bool) {
	p.env = gatherEnv()
	data := map[string]any{
		"uid":                    p.env.UID,
		"euid":                   p.env.EUID,
		"kern.osrelease":         p.env.OSRelease,
		"kern.osproductversion":  p.env.ProductVersion,
		"kern.osversion":         p.env.OSVersion,
		"hw.machine":             p.env.Machine,
		"sip":                    p.env.SIP,
		"sip_detail":             p.env.SIPDetail,
		"csr_active_config_read": p.env.CSRConfigKnown,
	}
	if p.env.CSRConfigKnown {
		data["csr_active_config"] = fmt.Sprintf("%#x", p.env.CSRConfig)
	}
	if len(p.env.Errors) > 0 {
		data["errors"] = strings.Join(p.env.Errors, "; ")
	}
	desc := fmt.Sprintf("uid=%d euid=%d, macOS %s (Darwin %s, build %s), %s, SIP %s",
		p.env.UID, p.env.EUID, p.env.ProductVersion, p.env.OSRelease, p.env.OSVersion,
		p.env.Machine, p.env.SIP)
	if p.env.EUID != 0 {
		p.add(1, "environment", statusFail, desc+" — NOT root, privileged stages skipped", data)
		p.warn("Not running as root: stages 4-10 need root. Re-run with: sudo %s", strings.Join(os.Args, " "))
		return true
	}
	p.add(1, "environment", statusPass, desc, data)
	if p.env.SIP != "enabled" {
		p.note("SIP is %s (%s). Nothing this probe does requires SIP to be off.", p.env.SIP, p.env.SIPDetail)
	}
	return false
}

// ---------------------------------------------------------------------------
// stage 2: default route
// ---------------------------------------------------------------------------

// stage2DefaultRoute reads the IPv4 default route out of the kernel routing
// table via the route sysctl (never by shelling out to route(8) or netstat(1)),
// and reports the outgoing interface, gateway, local address and MAC. It also
// detects whether the default route currently points at a tunnel interface,
// which means a VPN is intercepting everything the later stages measure.
func (p *probe) stage2DefaultRoute() {
	ifaces, err := interfaceTable()
	if err != nil {
		p.add(2, "default route", statusFail, "cannot read NET_RT_IFLIST: "+err.Error(), nil)
		return
	}
	p.ifaces = ifaces

	routes, err := defaultRoutes(ifaces)
	if err != nil {
		p.add(2, "default route", statusFail, "cannot read NET_RT_DUMP: "+err.Error(), nil)
		return
	}
	p.allDefaults = routes

	var tunnels []string
	for _, r := range routes {
		if r.IsTunnel {
			tunnels = append(tunnels, fmt.Sprintf("%s (gw %s)", r.IfName, addrOrDash(r.Gateway)))
		}
	}

	var chosen routeInfo
	found := false
	switch {
	case p.ifaceFlag != "":
		for _, r := range routes {
			if r.IfName == p.ifaceFlag {
				chosen, found = r, true
				break
			}
		}
		if !found {
			if r, ok := gatewayRouteForIface(ifaces, p.ifaceFlag); ok {
				chosen, found = r, true
				p.note("--iface %s does not carry the default route; using its first gateway route (%s) instead.",
					p.ifaceFlag, addrOrDash(r.Gateway))
			}
		}
	case len(routes) > 0:
		// defaultRoutes sorts non-tunnel routes first, so this prefers the
		// physical link when both a VPN and a physical default route exist.
		chosen, found = routes[0], true
	}

	data := map[string]any{
		"default_route_count": len(routes),
	}
	if len(tunnels) > 0 {
		data["tunnel_default_routes"] = strings.Join(tunnels, ", ")
	}
	all := make([]string, 0, len(routes))
	for _, r := range routes {
		all = append(all, fmt.Sprintf("%s via %s (flags %#x, local %s, mac %s)",
			r.IfName, addrOrDash(r.Gateway), r.Flags, addrOrDash(r.LocalIPv4), macOrDash(r.MAC)))
	}
	if len(all) > 0 {
		data["routes"] = strings.Join(all, " | ")
	}

	if !found {
		p.add(2, "default route", statusFail, "no usable IPv4 default route found", data)
		return
	}
	p.route = chosen
	p.haveRoute = true

	data["iface"] = chosen.IfName
	data["ifindex"] = chosen.IfIndex
	data["gateway"] = addrOrDash(chosen.Gateway)
	data["local_ipv4"] = addrOrDash(chosen.LocalIPv4)
	data["mac"] = macOrDash(chosen.MAC)
	data["flags"] = fmt.Sprintf("%#x", chosen.Flags)
	data["is_tunnel"] = chosen.IsTunnel

	detail := fmt.Sprintf("%s via %s, local %s, mac %s",
		chosen.IfName, addrOrDash(chosen.Gateway), addrOrDash(chosen.LocalIPv4), macOrDash(chosen.MAC))

	status := statusPass
	if !chosen.LocalIPv4.IsValid() || len(chosen.MAC) != 6 {
		// Stage 7 needs both; say so now rather than failing mysteriously later.
		status = statusFail
		detail += " — missing local IPv4 and/or MAC, the Ethernet re-emit stage cannot run"
	}

	if len(tunnels) > 0 {
		p.warn("A VPN-style default route is active: %s. Stages 5-9 then measure the VPN path, "+
			"not the physical one — re-run this probe with the VPN switched off before trusting the verdict.",
			strings.Join(tunnels, ", "))
	}
	if chosen.IsTunnel {
		p.warn("The interface the probe selected (%s) IS a tunnel. Every packet-level measurement below "+
			"describes the VPN datapath. Turn the VPN off, or pass --iface <physical>, and re-run.", chosen.IfName)
	}
	p.add(2, "default route", status, detail, data)
}

// addrOrDash renders an address, or "-" when it is not set.
func addrOrDash(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}

// macOrDash renders a hardware address, or "-" when it is not set.
func macOrDash(m net.HardwareAddr) string {
	if len(m) == 0 {
		return "-"
	}
	return m.String()
}

// ---------------------------------------------------------------------------
// stage 3: gateway MAC
// ---------------------------------------------------------------------------

// stage3GatewayMAC resolves the gateway's link-layer address from the ARP table
// (route sysctl NET_RT_FLAGS with RTF_LLINFO, family AF_INET), priming the cache
// with a single UDP datagram to the gateway and retrying once if needed.
func (p *probe) stage3GatewayMAC() {
	if !p.haveRoute {
		p.add(3, "gateway MAC", statusSkip, "no default route from stage 2", nil)
		return
	}
	data := map[string]any{}
	if !p.route.Gateway.IsValid() {
		// A point-to-point link (utun, ppp) has no ARP: the route's gateway is
		// the interface itself.
		if len(p.route.GatewayMAC) == 6 {
			p.gwMAC = p.route.GatewayMAC
			data["source"] = "RTAX_GATEWAY sockaddr_dl on the default route"
			data["mac"] = p.gwMAC.String()
			p.add(3, "gateway MAC", statusPass, "link-layer gateway "+p.gwMAC.String(), data)
			return
		}
		p.add(3, "gateway MAC", statusSkip,
			fmt.Sprintf("%s has no IPv4 gateway (point-to-point link); there is no ARP entry to resolve", p.route.IfName),
			data)
		return
	}
	mac, primed, err := resolveGatewayMAC(p.route.Gateway)
	data["gateway"] = p.route.Gateway.String()
	data["arp_primed_with_udp_probe"] = primed
	if err != nil {
		data["error"] = err.Error()
		p.add(3, "gateway MAC", statusFail,
			fmt.Sprintf("could not resolve %s: %v", p.route.Gateway, err), data)
		return
	}
	p.gwMAC = mac
	data["mac"] = mac.String()
	detail := fmt.Sprintf("%s is at %s", p.route.Gateway, mac)
	if primed {
		detail += " (after one UDP probe to populate the ARP cache)"
	}
	p.add(3, "gateway MAC", statusPass, detail, data)
}

// ---------------------------------------------------------------------------
// stage 4: utun
// ---------------------------------------------------------------------------

// pickTunnelAddrs chooses the point-to-point /31 pair for the probe utun. It
// prefers the documented 198.18.0.1 -> 198.18.0.2 (RFC 2544 benchmarking space,
// which never appears in real traffic), but a VPN client may already own those
// addresses, so a free pair is substituted rather than creating an ambiguous
// duplicate.
func pickTunnelAddrs(ifaces map[int]*ifaceInfo) (local, peer netip.Addr, substituted bool) {
	inUse := map[netip.Addr]bool{}
	for _, inf := range ifaces {
		for _, ip := range inf.IPv4 {
			inUse[ip] = true
		}
	}
	try := func(a, b [4]byte) (netip.Addr, netip.Addr, bool) {
		x, y := netip.AddrFrom4(a), netip.AddrFrom4(b)
		return x, y, !inUse[x] && !inUse[y]
	}
	if l, r, ok := try([4]byte{198, 18, 0, 1}, [4]byte{198, 18, 0, 2}); ok {
		return l, r, false
	}
	for _, base := range []byte{18, 19} {
		for third := 1; third < 256; third++ {
			if l, r, ok := try([4]byte{198, base, byte(third), 1}, [4]byte{198, base, byte(third), 2}); ok {
				return l, r, true
			}
		}
	}
	// Every candidate is taken; fall back to the documented pair and let the
	// kernel report whatever it thinks of that.
	return netip.AddrFrom4([4]byte{198, 18, 0, 1}), netip.AddrFrom4([4]byte{198, 18, 0, 2}), false
}

// stage4UTUN creates the utun via the AF_SYSTEM kernel control socket and
// configures it entirely with ioctls.
func (p *probe) stage4UTUN() {
	local, peer, substituted := pickTunnelAddrs(p.ifaces)
	p.tunLocal, p.tunPeer = local, peer

	h, err := createUTUN(p.utunUnit, local, peer, 1500)
	data := map[string]any{
		"requested_unit": p.utunUnit,
		"local":          local.String(),
		"peer":           peer.String(),
		"netmask":        "255.255.255.255",
		"mtu":            1500,
	}
	if substituted {
		data["address_substituted"] = true
		p.note("198.18.0.1/198.18.0.2 were already assigned to another interface, so the probe utun uses %s -> %s instead.",
			local, peer)
	}
	if err != nil {
		if h != nil {
			data["ifname"] = h.Name
		}
		p.add(4, "utun create", statusFail, err.Error(), data)
		return
	}
	p.utun = h
	p.onCleanup("close utun "+h.Name+" (destroys the interface)", func() error {
		if p.stopRead != nil {
			close(p.stopRead)
			p.stopRead = nil
		}
		p.readerWG.Wait()
		return h.Close()
	})

	data["ifname"] = h.Name
	data["unit_fallback"] = h.FellBack
	data["framing"] = h.FramingNote()
	if len(h.ConfigErrors) > 0 {
		data["config_warnings"] = strings.Join(h.ConfigErrors, "; ")
	}
	detail := fmt.Sprintf("%s up, %s -> %s/32, mtu 1500; %s", h.Name, local, peer, h.FramingNote())
	if h.FellBack {
		detail = fmt.Sprintf("requested unit %d was unavailable, kernel assigned %s; ", p.utunUnit, h.Name) + detail
	}
	p.add(4, "utun create", statusPass, detail, data)
}

// ---------------------------------------------------------------------------
// stage 5: pf
// ---------------------------------------------------------------------------

// stage5PF opens /dev/pf, enables pf with a reference token, loads the route-to
// rule into a dedicated anchor, and then determines the thing that trips up
// every naive macOS pf integration: an anchor is only evaluated if the MAIN
// ruleset contains an anchor statement pointing at it, and a stock
// /etc/pf.conf only anchors "com.apple/*". The probe must not patch
// /etc/pf.conf, so when the anchor turns out to be unreachable the same rule is
// instead spliced into a temporary copy of the main ruleset, and the original is
// restored during cleanup.
func (p *probe) stage5PF() {
	data := map[string]any{}
	p.pfConfBefore = witnessFile(pfConfPath)
	data["pf.conf_before"] = p.pfConfBefore.String()

	fd, err := openPFDevice()
	if err != nil {
		p.add(5, "pf availability", statusFail, err.Error(), data)
		return
	}
	p.pfFD = fd
	p.onCleanup("close "+pfDevice, func() error {
		if p.pfFD >= 0 {
			err := unix.Close(p.pfFD)
			p.pfFD = -1
			return err
		}
		return nil
	})

	enabledBefore, infoRes := pfStatusEnabled()
	p.pfEnabledBefore = enabledBefore
	data["pf_enabled_before"] = enabledBefore
	if infoRes.Err != nil {
		data["pfctl_-s_info_error"] = infoRes.Err.Error()
	}

	// The release action is registered around pfEnable, not after it: a SIGINT
	// arriving in between used to hold the reference for the rest of uptime with
	// the token printed nowhere persistent. p.pfToken is read at cleanup time, so
	// registering first is safe and the undo is a no-op while it is empty.
	p.onCleanup("pfctl -X <token> (release the pf enable reference)", func() error {
		if p.pfToken == "" {
			return nil
		}
		r := pfRelease(p.pfToken)
		if r.Err != nil {
			return fmt.Errorf("%v: %s", r.Err, oneLine(r.combined()))
		}
		return nil
	})
	token, enRes := pfEnable()
	data["pfctl_-E"] = oneLine(enRes.combined())
	if enRes.Err != nil {
		data["pfctl_-E_error"] = enRes.Err.Error()
	}
	if token != "" {
		p.pfToken = token
		data["token"] = token
		// Persist it too: if this process is SIGKILLed the token is the only way
		// anybody can ever drop the reference again.
		p.writeTokenWitness(token)
	} else {
		p.note("pfctl -E did not print a Token line, so no reference was taken; pf is left exactly as it was found (enabled=%v).", enabledBefore)
	}

	if p.utun == nil {
		p.add(5, "pf availability", statusFail, "no utun from stage 4, so the route-to rule cannot be built", data)
		return
	}

	rule := routeToRule(p.utun.Name, p.tunPeer, p.target, p.port)
	data["rule"] = rule

	dry := pfLoadAnchor(probeAnchor, rule+"\n", true)
	data["anchor_dry_run"] = oneLine(dry.combined())
	if dry.Err != nil {
		data["anchor_dry_run_error"] = dry.Err.Error()
		p.add(5, "pf availability", statusFail,
			fmt.Sprintf("pfctl -a %s -n -f - rejected the rule: %s", probeAnchor, oneLine(dry.combined())), data)
		return
	}

	load := pfLoadAnchor(probeAnchor, rule+"\n", false)
	data["anchor_load"] = oneLine(load.combined())
	if load.Err != nil {
		data["anchor_load_error"] = load.Err.Error()
		p.add(5, "pf availability", statusFail,
			fmt.Sprintf("pfctl -a %s -f - failed: %s", probeAnchor, oneLine(load.combined())), data)
		return
	}
	p.pfAnchorLoaded = true
	p.onCleanup("pfctl -a "+probeAnchor+" -F all (flush the probe anchor)", func() error {
		r := pfFlushAnchor(probeAnchor)
		if r.Err != nil {
			return fmt.Errorf("%v: %s", r.Err, oneLine(r.combined()))
		}
		return nil
	})

	shown := pfAnchorRules(probeAnchor)
	data["anchor_rules"] = oneLine(shown.Stdout)
	anchorHasRule := strings.Contains(shown.Stdout, "route-to") && strings.Contains(shown.Stdout, p.utun.Name)
	data["anchor_contains_rule"] = anchorHasRule

	mainRules := pfMainRules()
	mainNat := pfMainNat()
	data["main_ruleset_filter"] = oneLine(mainRules.Stdout)
	data["main_ruleset_nat"] = oneLine(mainNat.Stdout)
	reachable := anchorReachable(mainRules.Stdout, probeAnchor) || anchorReachable(mainNat.Stdout, probeAnchor)
	data["anchor_reachable_from_main_ruleset"] = reachable
	data["pf.conf_addition_needed"] = pfConfAddition(probeAnchor)

	if reachable {
		p.pfRulePath = "anchor"
		p.add(5, "pf availability", statusPass,
			fmt.Sprintf("anchor %q loaded and reachable from the main ruleset; rule active via the anchor", probeAnchor), data)
		return
	}

	// The anchor exists and holds the rule, but nothing references it, so pf will
	// never evaluate it. Before considering the destructive main-ruleset splice,
	// try the sub-anchor nested under the wildcard anchor point /etc/pf.conf
	// already declares: that makes the rule live with no file edit at all.
	if err := p.installViaAppleSubAnchor(mainRules.Stdout, mainNat.Stdout, []string{}, []string{rule}, data); err == nil {
		p.pfRulePath = "apple-wildcard-subanchor"
		data["rule_applied_via"] = p.pfRulePath
		p.add(5, "pf availability", statusPass, fmt.Sprintf(
			"anchor %q is not reachable (a stock /etc/pf.conf only anchors \"com.apple/*\"), so the rule was "+
				"loaded into the sub-anchor %q instead: the wildcard anchor point already in /etc/pf.conf "+
				"evaluates it, so pf applies the rule with NO edit to /etc/pf.conf and no main-ruleset replacement",
			probeAnchor, appleSubAnchor), data)
		return
	} else {
		data["apple_subanchor_error"] = err.Error()
	}

	// Last resort: splice into a temporary copy of the main ruleset.
	if err := p.installMainRuleset([]string{}, []string{rule}, data, "main_ruleset_splice"); err != nil {
		data["main_splice_error"] = err.Error()
		if errors.Is(err, errMainRulesetRefused) {
			// A deliberate refusal, not a capability failure: say SKIP and say how
			// to get an answer without it.
			p.add(5, "pf availability", statusSkip, fmt.Sprintf(
				"anchor %q is not reachable from the main ruleset (a stock /etc/pf.conf only anchors "+
					"\"com.apple/*\"), and the probe will not replace the machine's main ruleset to work "+
					"around that: %v", probeAnchor, err), data)
			return
		}
		p.add(5, "pf availability", statusFail, fmt.Sprintf(
			"anchor %q is NOT reachable: the main ruleset contains no anchor statement naming it "+
				"(a stock /etc/pf.conf only anchors \"com.apple/*\"), and the main-ruleset fallback also failed: %v",
			probeAnchor, err), data)
		return
	}
	p.pfRulePath = "main-ruleset-splice"
	data["rule_applied_via"] = p.pfRulePath
	p.add(5, "pf availability", statusFail, fmt.Sprintf(
		"anchor %q is NOT reachable — the main ruleset has no anchor statement naming it, because a stock "+
			"/etc/pf.conf only contains the com.apple anchor points. /etc/pf.conf was NOT modified; the rule was "+
			"instead spliced into a temporary main ruleset (restored in cleanup) so stage 6 can still be answered. "+
			"To make the anchor reachable, /etc/pf.conf would need: %s",
		probeAnchor, pfConfAddition(probeAnchor)), data)
}

// errMainRulesetRefused reports that the probe declined to replace the machine's
// main pf ruleset.
var errMainRulesetRefused = errors.New("replacing the main pf ruleset was not authorised")

// installViaAppleSubAnchor makes rules live without editing /etc/pf.conf and
// without replacing the main ruleset, by loading them into a sub-anchor nested
// under the wildcard anchor point the stock configuration already declares
// (`anchor "com.apple/*"` and its rdr/nat siblings).
//
// Loading rules into a sub-anchor CREATES it, and a wildcard anchor point
// evaluates every sub-anchor beneath it — so this is a pure runtime operation
// with no persistent footprint. Cleanup flushes the sub-anchor, which removes it
// again. Compared with the main-ruleset splice this touches nothing that belongs
// to anybody else: other com.apple/* sub-anchors are separate namespaces and are
// left exactly as they are.
func (p *probe) installViaAppleSubAnchor(mainRules, mainNat string, translation, filter []string, data map[string]any) error {
	coveredFilter := wildcardAnchorCovers(mainRules, appleSubAnchor)
	coveredNat := wildcardAnchorCovers(mainNat, appleSubAnchor)
	data["apple_subanchor"] = appleSubAnchor
	data["apple_subanchor_filter_wildcard_covers"] = coveredFilter
	data["apple_subanchor_nat_wildcard_covers"] = coveredNat

	if len(filter) > 0 && !coveredFilter {
		return fmt.Errorf("the main ruleset declares no wildcard filter anchor covering %q", appleSubAnchor)
	}
	if len(translation) > 0 && !coveredNat {
		return fmt.Errorf("the main ruleset declares no wildcard rdr/nat anchor covering %q", appleSubAnchor)
	}

	rules := strings.Join(append(append([]string{}, translation...), filter...), "\n") + "\n"
	if dry := pfLoadAnchor(appleSubAnchor, rules, true); dry.Err != nil {
		return fmt.Errorf("pfctl -a %s -n -f - rejected the ruleset: %v: %s",
			appleSubAnchor, dry.Err, oneLine(dry.combined()))
	}

	// Register the undo before the load, so a signal landing in between still
	// removes the rules. Flushing an empty sub-anchor is a harmless no-op.
	if !p.appleSubLoaded {
		p.appleSubLoaded = true
		p.onCleanup("pfctl -a "+appleSubAnchor+" -F all (flush the borrowed sub-anchor)", func() error {
			r := pfFlushAnchor(appleSubAnchor)
			if r.Err != nil {
				return fmt.Errorf("%v: %s", r.Err, oneLine(r.combined()))
			}
			return nil
		})
	}

	if ld := pfLoadAnchor(appleSubAnchor, rules, false); ld.Err != nil {
		return fmt.Errorf("pfctl -a %s -f - failed: %v: %s", appleSubAnchor, ld.Err, oneLine(ld.combined()))
	}
	shown := pfAnchorRules(appleSubAnchor)
	data["apple_subanchor_rules"] = oneLine(shown.Stdout)
	if strings.TrimSpace(shown.Stdout) == "" {
		return fmt.Errorf("pfctl accepted the load but %q reports no rules", appleSubAnchor)
	}
	return nil
}

// installMainRuleset loads a temporary main ruleset built from the text of
// /etc/pf.conf plus the supplied rules, and registers the restore action. The
// file itself is only read.
//
// WHY THIS IS GATED. `pfctl -f -` installs the argument AS the kernel's main
// ruleset, which flushes every anchor a system service populated at runtime —
// exactly what /etc/pf.conf's own comment warns about ("Care must be taken to
// ensure that the main ruleset does not get flushed, as the nested anchors rely on
// the anchor point being present"). On a stock machine the probe's anchor is never
// reachable, so this used to run on EVERY probe run, emptying Internet Sharing's
// NAT, AirDrop and screen-sharing rules — and wiping a running zapretd's steering
// rules, which finding 6 made undetectable. It now requires
// --replace-main-ruleset and refuses outright while a daemon is live.
func (p *probe) installMainRuleset(translation, filter []string, data map[string]any, key string) error {
	if !p.replaceMain {
		data[key+"_refused"] = "not authorised: pass --replace-main-ruleset"
		return fmt.Errorf("%w: it would flush every dynamically populated com.apple/* sub-anchor "+
			"(Internet Sharing NAT, AirDrop, screen sharing). Re-run with --replace-main-ruleset if you "+
			"accept that, or make the %q anchor reachable by adding to %s: %s",
			errMainRulesetRefused, probeAnchor, pfConfPath, pfConfAddition(probeAnchor))
	}
	if who := liveDaemonEvidence(); who != "" {
		data[key+"_refused"] = "a zapretd appears to be running: " + who
		return fmt.Errorf("%w: %s is present, so a zapret-mac daemon is running and replacing the main "+
			"ruleset would silently wipe its steering rules. Stop it first: sudo zaprctl stop",
			errMainRulesetRefused, who)
	}

	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", pfConfPath, err)
	}
	ruleset := spliceMainRuleset(string(conf), translation, filter)
	data[key] = ruleset

	if chk := pfCheckMain(ruleset); chk.Err != nil {
		return fmt.Errorf("pfctl -n -f - rejected the spliced ruleset: %v: %s", chk.Err, oneLine(chk.combined()))
	}
	// Register the restore BEFORE the load. A SIGINT landing between a successful
	// pfctl -f - and the onCleanup() call used to leave the spliced ruleset — rdr
	// rules and all — loaded until the next reboot. The undo is idempotent, so
	// registering it for a load that then fails costs one extra pfctl.
	if !p.pfMainReplaced {
		p.pfMainReplaced = true
		p.onCleanup("pfctl -f "+pfConfPath+" (restore the original main ruleset)", func() error {
			r := pfRestoreMain()
			if r.Err != nil {
				return fmt.Errorf("%v: %s", r.Err, oneLine(r.combined()))
			}
			return nil
		})
	}
	if ld := pfLoadMain(ruleset); ld.Err != nil {
		return fmt.Errorf("pfctl -f - failed: %v: %s", ld.Err, oneLine(ld.combined()))
	}
	p.warn("the machine's MAIN pf ruleset was replaced for the duration of this run; every anchor a system "+
		"service had populated at runtime (com.apple/* sub-anchors: Internet Sharing NAT, AirDrop, screen "+
		"sharing) was flushed by that load and only comes back when its owner re-adds it. It is restored "+
		"from %s in cleanup.", pfConfPath)
	return nil
}

// liveDaemonEvidence returns a short description of a running zapret-mac daemon,
// or "" when none can be found. It is deliberately conservative: any evidence at
// all is enough to refuse.
func liveDaemonEvidence() string {
	for _, path := range []string{"/var/run/zapret-mac.sock"} {
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return path
		}
	}
	if out := pfAnchorRules(zapretMacAnchor); strings.TrimSpace(out.Stdout) != "" {
		return "a non-empty pf anchor " + strconv.Quote(zapretMacAnchor)
	}
	return ""
}

// ---------------------------------------------------------------------------
// stage 6: the hard gate
// ---------------------------------------------------------------------------

// stage6RouteToGate is the decision point for the whole project: it dials the
// target while reading the utun file descriptor, and reports whether pf's
// route-to actually handed the outbound SYN to userspace. A PASS means
// winws-class parity is reachable on macOS; a FAIL means only the socket-level
// proxy transport can be shipped.
func (p *probe) stage6RouteToGate() {
	if p.utun == nil {
		p.add(6, "route-to delivers to utun", statusSkip, "no utun from stage 4", nil)
		return
	}
	if p.pfRulePath == "" {
		p.add(6, "route-to delivers to utun", statusSkip, "the route-to rule was never made active in stage 5", nil)
		return
	}
	data := map[string]any{
		"rule_applied_via": p.pfRulePath,
		"dial":             p.targetAddrPort(),
	}

	p.startUtunReader()
	p.startDial()

	wait := p.budget(4 * time.Second)
	var cp capturedPkt
	got := false
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case c, ok := <-p.utunPkts:
		if ok {
			cp, got = c, true
		}
	case <-timer.C:
	}

	if !got {
		// Surface an immediate dial error: it usually explains the silence.
		select {
		case err := <-p.dialCh:
			p.dialErr, p.dialKnown = err, true
			if err != nil {
				data["dial_error"] = errnoName(err)
			} else {
				data["dial_error"] = "none (connection completed through the normal stack)"
			}
		default:
		}
		data["packet_arrived"] = false
		p.add(6, "route-to delivers to utun", statusFail, fmt.Sprintf(
			"no packet appeared on %s within %s while dialing %s: pf route-to did not hand the outbound "+
				"segment to the utun file descriptor, so intercept-mangle-reinject is not available",
			p.utun.Name, wait, p.targetAddrPort()), data)
		return
	}

	p.firstPkt = &cp
	data["packet_arrived"] = true
	data["af_prefix"] = hex.EncodeToString(cp.prefix)
	data["af_prefix_expected"] = "00000002 = htonl(AF_INET)"
	data["packet_len"] = len(cp.data)
	data["hexdump_first_64"] = hexdump(cp.data, 64)

	info, ok := parseIPv4(cp.data)
	if !ok {
		data["parse"] = "not a well-formed IPv4 packet"
		p.add(6, "route-to delivers to utun", statusPass, fmt.Sprintf(
			"a %d-byte datagram arrived on %s but it is not parseable as IPv4 (prefix %s)",
			len(cp.data), p.utun.Name, hex.EncodeToString(cp.prefix)), data)
		return
	}
	data["ip_version"] = info.Version
	data["ip_header_len"] = info.IHL
	data["src"] = info.Src.String()
	data["dst"] = info.Dst.String()
	data["ttl"] = info.TTL
	data["ip_id"] = fmt.Sprintf("%#04x", info.ID)
	data["ip_proto"] = info.Proto
	data["ip_checksum"] = fmt.Sprintf("%#04x", info.HdrCsum)
	data["ip_checksum_computed"] = fmt.Sprintf("%#04x", info.HdrCsumCalc)
	data["ip_checksum_already_correct"] = info.HdrCsumOK
	if info.HasTCP {
		data["tcp_src_port"] = info.SrcPort
		data["tcp_dst_port"] = info.DstPort
		data["tcp_flags"] = fmt.Sprintf("%#02x (%s)", info.TCPFlags, info.TCPFlagsText)
		data["tcp_seq"] = info.Seq
		data["tcp_ack"] = info.Ack
		data["tcp_window"] = info.Window
		data["tcp_payload_len"] = info.PayloadLen
		data["tcp_checksum"] = fmt.Sprintf("%#04x", info.TCPCsum)
		data["tcp_checksum_computed"] = fmt.Sprintf("%#04x", info.TCPCsumCalc)
		data["tcp_checksum_already_correct"] = info.TCPCsumOK
		p.emitSport, p.emitSeq = info.SrcPort, info.Seq
	}

	csumNote := "both checksums already correct — packets can be re-emitted unmodified"
	switch {
	case !info.HdrCsumOK && !(info.HasTCP && info.TCPCsumOK):
		csumNote = "NEITHER checksum is valid — both must be recomputed before re-emitting"
	case !info.HdrCsumOK:
		csumNote = "IPv4 header checksum is NOT valid — it must be recomputed before re-emitting"
	case info.HasTCP && !info.TCPCsumOK:
		csumNote = "TCP checksum is NOT valid (likely offloaded) — it must be recomputed before re-emitting"
	}
	data["checksum_conclusion"] = csumNote

	flags := "no TCP header"
	if info.HasTCP {
		flags = fmt.Sprintf("%s seq=%d", info.TCPFlagsText, info.Seq)
	}
	p.add(6, "route-to delivers to utun", statusPass, fmt.Sprintf(
		"prefix %s, IPv%d %s -> %s ttl=%d %s; %s",
		hex.EncodeToString(cp.prefix), info.Version, info.Src, info.Dst, info.TTL, flags, csumNote), data)
}

// startUtunReader spawns the single reader that drains the utun descriptor for
// the rest of the run. Stage 6 takes the first packet; stage 7 forwards the rest.
func (p *probe) startUtunReader() {
	p.utunPkts = make(chan capturedPkt, 512)
	p.stopRead = make(chan struct{})
	stop := p.stopRead
	pkts := p.utunPkts
	h := p.utun
	p.readerWG.Add(1)
	go func() {
		defer p.readerWG.Done()
		defer close(pkts)
		for {
			select {
			case <-stop:
				return
			default:
			}
			prefix, pkt, err := h.read(200 * time.Millisecond)
			if err != nil {
				// The descriptor was closed by cleanup, or the read failed
				// irrecoverably; either way there is nothing more to read.
				return
			}
			if len(pkt) == 0 {
				continue
			}
			cp := capturedPkt{
				prefix: append([]byte(nil), prefix...),
				data:   append([]byte(nil), pkt...),
				at:     time.Now(),
			}
			select {
			case pkts <- cp:
			case <-stop:
				return
			default:
				// Channel full: drop rather than stall the reader.
			}
		}
	}()
}

// startDial opens the TCP connection whose packets the probe is trying to catch.
// The 3-second timeout is deliberately short: if route-to works, the SYN appears
// on the utun immediately.
func (p *probe) startDial() {
	p.dialCh = make(chan error, 1)
	ch := p.dialCh
	addr := p.targetAddrPort()
	go func() {
		d := net.Dialer{Timeout: 3 * time.Second}
		c, err := d.Dial("tcp4", addr)
		if err == nil {
			c.Close()
		}
		ch <- err
	}()
}

// ---------------------------------------------------------------------------
// stage 7: BPF write
// ---------------------------------------------------------------------------

// stage7BPFWrite re-emits the captured packet by hand: it opens a BPF
// descriptor on the physical interface, sets BIOCSHDRCMPLT so the kernel
// transmits the supplied Ethernet header verbatim (bypassing pf, which is what
// prevents the re-emitted packet from matching our own route-to rule again), and
// writes one frame. If stage 6 produced a real packet, the forwarder keeps
// relaying utun traffic so the TCP handshake can complete end to end — the
// strongest possible evidence that the full read-from-utun/write-to-BPF datapath
// works.
func (p *probe) stage7BPFWrite() {
	if !p.haveRoute || len(p.route.MAC) != 6 || !p.route.LocalIPv4.IsValid() {
		p.add(7, "BPF write", statusSkip, "stage 2 did not yield a local IPv4 and MAC for the egress interface", nil)
		return
	}
	if len(p.gwMAC) != 6 {
		p.add(7, "BPF write", statusSkip, "stage 3 did not yield the gateway MAC, so no Ethernet header can be built", nil)
		return
	}
	data := map[string]any{
		"iface":     p.route.IfName,
		"eth_dst":   p.gwMAC.String(),
		"eth_src":   p.route.MAC.String(),
		"ethertype": "0x0800",
	}

	// The reader is opened first (and before the write) so it can witness our
	// own frame leaving the interface.
	reader, rerr := openBPF(p.route.IfName, false, true, tcpToHostFilter(p.target))
	if rerr != nil {
		data["reader_error"] = rerr.Error()
	} else {
		p.bpfR = reader
		p.onCleanup("close BPF reader "+reader.Device, reader.Close)
		data["reader_device"] = reader.Device
		data["reader_datalink"] = reader.Datalink
		data["reader_buflen"] = reader.BufLen
	}

	writer, werr := openBPF(p.route.IfName, true, false, nil)
	if werr != nil {
		data["writer_error"] = werr.Error()
		p.add(7, "BPF write", statusFail, "cannot open a BPF descriptor for writing: "+werr.Error(), data)
		return
	}
	p.bpfW = writer
	p.onCleanup("close BPF writer "+writer.Device, writer.Close)
	data["writer_device"] = writer.Device
	data["writer_datalink"] = writer.Datalink
	if writer.Datalink != dltEN10MB {
		data["writer_datalink_warning"] = fmt.Sprintf(
			"datalink is %d, not DLT_EN10MB(%d); an Ethernet header is the wrong framing for this interface",
			writer.Datalink, dltEN10MB)
	}

	synthesised := p.firstPkt == nil
	var pkt []byte
	if synthesised {
		sport := uint16(30000 + rand.IntN(30000))
		seq := rand.Uint32()
		pkt = buildSYN(p.route.LocalIPv4, p.target, sport, uint16(p.port), uint16(rand.IntN(65536)), seq)
		p.emitSport, p.emitSeq = sport, seq
		data["packet_source"] = fmt.Sprintf("synthesised SYN %s:%d -> %s (stage 6 produced none)",
			p.route.LocalIPv4, sport, p.targetAddrPort())
	} else {
		pkt = p.firstPkt.data
		data["packet_source"] = "the unmodified packet captured in stage 6"
	}
	p.emitted = pkt

	frame, err := ethFrame(p.gwMAC, p.route.MAC, 0x0800, pkt)
	if err != nil {
		data["frame_error"] = err.Error()
		p.add(7, "BPF write", statusFail, err.Error(), data)
		return
	}
	data["frame_len"] = len(frame)

	n, werr := writer.writeFrame(frame)
	data["bytes_written"] = n
	if werr != nil {
		data["write_error"] = werr.Error()
		p.add(7, "BPF write", statusFail, "write to the BPF descriptor failed: "+werr.Error(), data)
		return
	}

	// Keep relaying so the handshake can finish. Without this only the SYN gets
	// through and the dial always times out.
	forwarded := 0
	if !synthesised {
		forwarded = p.forwardUntilDial(writer, p.budget(4*time.Second))
		data["packets_forwarded_utun_to_bpf"] = forwarded
	}

	dialDetail := "not applicable (no dial was in flight)"
	if p.dialKnown {
		if p.dialErr == nil {
			dialDetail = "COMPLETED"
		} else {
			dialDetail = "failed: " + errnoName(p.dialErr)
		}
	} else if p.dialCh != nil {
		dialDetail = "still pending after the forward window"
	}
	data["stage6_dial_result"] = dialDetail

	// Look for our own frame on the wire.
	egress := false
	if p.bpfR != nil {
		frames, ferr := p.bpfR.readFrames(time.Now().Add(p.budget(1500*time.Millisecond)), 512)
		if ferr != nil {
			data["reader_read_error"] = ferr.Error()
		}
		data["frames_captured"] = len(frames)
		for _, f := range frames {
			if ip, ok := ethPayload(f); ok {
				if fi, ok := parseIPv4(ip); ok && fi.HasTCP && fi.SrcPort == p.emitSport && fi.Seq == p.emitSeq {
					egress = true
					data["egress_frame_ip_id"] = fmt.Sprintf("%#04x", fi.ID)
					data["egress_frame_ttl"] = fi.TTL
					break
				}
			}
		}
	}
	data["own_frame_seen_by_second_bpf_reader"] = egress

	if recv, drop, serr := writer.stats(); serr == nil {
		data["writer_bpf_recv"] = recv
		data["writer_bpf_drop"] = drop
	} else {
		data["writer_bpf_stats_error"] = serr.Error()
	}
	if p.bpfR != nil {
		if recv, drop, serr := p.bpfR.stats(); serr == nil {
			data["reader_bpf_recv"] = recv
			data["reader_bpf_drop"] = drop
			if drop > 0 {
				data["reader_bpf_drop_note"] = "the reader's kernel buffer overflowed; capture-based conclusions may be incomplete"
			}
		} else {
			data["reader_bpf_stats_error"] = serr.Error()
		}
	}

	switch {
	case p.dialKnown && p.dialErr == nil:
		p.add(7, "BPF write", statusPass, fmt.Sprintf(
			"wrote %d bytes to %s on %s and forwarded %d further packet(s) from the utun; the stage 6 TCP dial to %s "+
				"COMPLETED, so the full read-from-utun then write-to-BPF datapath works end to end",
			n, writer.Device, p.route.IfName, forwarded, p.targetAddrPort()), data)
	case egress:
		p.add(7, "BPF write", statusPass, fmt.Sprintf(
			"wrote %d bytes to %s on %s and observed the frame leaving the interface on a second BPF reader; "+
				"the stage 6 dial %s", n, writer.Device, p.route.IfName, dialDetail), data)
	case synthesised:
		p.add(7, "BPF write", statusFail, fmt.Sprintf(
			"wrote %d bytes to %s on %s without error, but the synthesised frame was not observed on a second "+
				"BPF reader, so egress is unconfirmed (note that a frame injected through BPF is not always "+
				"visible to other BPF listeners on the same interface)", n, writer.Device, p.route.IfName), data)
	default:
		p.add(7, "BPF write", statusFail, fmt.Sprintf(
			"wrote %d bytes to %s on %s without error, but the stage 6 dial %s and the frame was not observed "+
				"on the second BPF reader", n, writer.Device, p.route.IfName, dialDetail), data)
	}
}

// forwardUntilDial relays every packet the utun produces to the BPF writer until
// the dial resolves or the window closes, returning the number of packets
// forwarded (excluding the first one, which stage 7 already wrote).
func (p *probe) forwardUntilDial(w *bpfHandle, window time.Duration) int {
	deadline := time.Now().Add(window)
	count := 0
	for time.Now().Before(deadline) {
		if p.dialKnown {
			break
		}
		select {
		case err := <-p.dialCh:
			p.dialErr, p.dialKnown = err, true
			// Drain anything already queued before declaring the window over.
			for {
				select {
				case cp, ok := <-p.utunPkts:
					if !ok {
						return count
					}
					if p.relay(w, cp.data) {
						count++
					}
					continue
				default:
				}
				break
			}
			return count
		case cp, ok := <-p.utunPkts:
			if !ok {
				return count
			}
			if p.relay(w, cp.data) {
				count++
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	select {
	case err := <-p.dialCh:
		p.dialErr, p.dialKnown = err, true
	default:
	}
	return count
}

// relay wraps one IPv4 packet in an Ethernet header and writes it out.
func (p *probe) relay(w *bpfHandle, pkt []byte) bool {
	frame, err := ethFrame(p.gwMAC, p.route.MAC, 0x0800, pkt)
	if err != nil {
		return false
	}
	if _, err := w.writeFrame(frame); err != nil {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// stage 8: SOCK_RAW
// ---------------------------------------------------------------------------

// stage8RawSocket exercises the other re-emit path: an AF_INET/SOCK_RAW socket
// with IP_HDRINCL. It also answers whether the kernel overwrites a zero IP ID,
// which decides whether an --ip-id=zero style option is achievable on the raw
// path: the packet is sent with ip_id == 0 and the BPF reader from stage 7 is
// used to see what actually went out.
func (p *probe) stage8RawSocket() {
	if !p.haveRoute || !p.route.LocalIPv4.IsValid() {
		p.add(8, "SOCK_RAW fallback", statusSkip, "no local IPv4 from stage 2", nil)
		return
	}
	base := p.emitted
	if base == nil {
		sport := uint16(30000 + rand.IntN(30000))
		seq := rand.Uint32()
		base = buildSYN(p.route.LocalIPv4, p.target, sport, uint16(p.port), 0, seq)
		p.emitSport, p.emitSeq = sport, seq
	}
	// ip_id = 0 on the wire is the question being asked. The IPv4 header
	// checksum is left for the kernel to fill in (hostOrderIPv4 zeroes it),
	// which is the documented IP_HDRINCL behaviour; the TCP checksum does not
	// cover ip_id so it stays valid.
	pkt := make([]byte, len(base))
	copy(pkt, base)
	if len(pkt) >= 6 {
		pkt[4], pkt[5] = 0, 0
	}

	data := map[string]any{
		"packet_len": len(pkt),
		"sent_ip_id": "0x0000",
		"dst":        p.target.String(),
		"host_order_fields": "ip_len and ip_off are byte-swapped to host order for sendto(); " +
			"every other field stays network order (Darwin ip_output assigns both as plain host integers, " +
			"so an IP_HDRINCL sender must match that)",
		// xnu bsd/netinet/raw_ip.c, rip_output():
		//   if (ip->ip_id == 0 && !(rfc6864 && IP_OFF_IS_ATOMIC(ntohs(ip->ip_off))))
		//           ip->ip_id = ip_randomid(m);
		// So a zero IP ID only survives when net.inet.ip.rfc6864 is on AND the
		// kernel's ntohs() view of ip_off has IP_DF set with no fragment offset.
		// Whether that holds while ip_off is also host-ordered for ip_output is
		// precisely what this stage measures rather than assumes.
		"kernel_ip_id_rule": "xnu rip_output() rewrites ip_id when it is 0 unless " +
			"net.inet.ip.rfc6864 is set and IP_OFF_IS_ATOMIC(ntohs(ip_off)) holds",
	}
	if v, ok := sysctlInt("net.inet.ip.rfc6864"); ok {
		data["net.inet.ip.rfc6864"] = v
	} else {
		data["net.inet.ip.rfc6864"] = "unavailable"
	}

	// Clear anything the reader queued earlier so a later capture can only be
	// this send.
	drained := 0
	if p.bpfR != nil {
		if old, err := p.bpfR.readFrames(time.Now().Add(150*time.Millisecond), 4096); err == nil {
			drained = len(old)
		}
	}
	data["frames_drained_before_send"] = drained

	sender, err := newRawSender()
	if err != nil {
		data["error"] = err.Error()
		p.add(8, "SOCK_RAW fallback", statusFail, err.Error(), data)
		return
	}
	p.raw = sender
	p.onCleanup("close SOCK_RAW socket", sender.Close)

	wire, err := sender.send(pkt, p.target)
	data["bytes_handed_to_sendto"] = len(wire)
	data["sendto_hexdump"] = hexdump(wire, 64)
	if err != nil {
		data["error"] = err.Error()
		p.add(8, "SOCK_RAW fallback", statusFail, err.Error(), data)
		return
	}

	idNote := "undetermined (no BPF reader available to observe the wire)"
	achievable := "unknown"
	if p.bpfR != nil {
		frames, ferr := p.bpfR.readFrames(time.Now().Add(p.budget(1500*time.Millisecond)), 512)
		if ferr != nil {
			data["capture_error"] = ferr.Error()
		}
		data["frames_captured_after_send"] = len(frames)
		found := false
		for _, f := range frames {
			ip, ok := ethPayload(f)
			if !ok {
				continue
			}
			fi, ok := parseIPv4(ip)
			if !ok || !fi.HasTCP || fi.SrcPort != p.emitSport || fi.Seq != p.emitSeq {
				continue
			}
			found = true
			data["observed_ip_id"] = fmt.Sprintf("%#04x", fi.ID)
			data["observed_ip_checksum_valid"] = fi.HdrCsumOK
			data["observed_tcp_checksum_valid"] = fi.TCPCsumOK
			data["observed_ttl"] = fi.TTL
			if fi.ID == 0 {
				idNote = "the kernel preserved ip_id == 0"
				achievable = "yes"
			} else {
				idNote = fmt.Sprintf("the kernel replaced ip_id 0 with %#04x", fi.ID)
				achievable = "no"
			}
			break
		}
		if !found {
			idNote = "undetermined (the sent packet was not seen on the BPF reader)"
		}
	}
	data["ip_id_zero_achievable_on_raw_path"] = achievable
	data["ip_id_observation"] = idNote

	p.add(8, "SOCK_RAW fallback", statusPass, fmt.Sprintf(
		"socket(AF_INET, SOCK_RAW, IPPROTO_RAW) + IP_HDRINCL accepted a %d-byte packet for %s; %s",
		len(wire), p.target, idNote), data)
}

// ---------------------------------------------------------------------------
// stage 9: DIOCNATLOOK
// ---------------------------------------------------------------------------

// stage9Natlook exercises the proxy transport's one hard requirement: recovering
// a redirected connection's original destination.
//
// macOS pf cannot redirect outbound packets, so a locally generated connection
// is first forced onto lo0 with route-to, where the inbound rdr rule fires and
// rewrites the destination to the local listener. DIOCNATLOOK then reads the
// pre-translation address back out of pf's state table.
func (p *probe) stage9Natlook() {
	data := map[string]any{
		"struct_layout": natlookLayout(),
		"layout_source": "verified by compiling xnu's pfvar.h (bsd/net/pfvar.h, as vendored by zapret at " +
			"/opt/zapret/tpws/macos/net/pfvar.h) against this machine's SDK and printing sizeof/offsetof/DIOCNATLOOK; " +
			"the same values are asserted at compile time in pf_darwin.go",
		"direction": fmt.Sprintf("PF_OUT (%d)", pfDirOut),
	}
	if p.pfFD < 0 {
		p.add(9, "DIOCNATLOOK", statusSkip, "/dev/pf was never opened in stage 5", data)
		return
	}

	// The stage 5 rule steers this same target/port into the utun. If it is
	// still live it would compete with the loopback route-to below, so drop it
	// first; the cleanup flush stays registered and is idempotent.
	if p.pfAnchorLoaded {
		fl := pfFlushAnchor(probeAnchor)
		data["stage5_anchor_flushed"] = oneLine(fl.combined())
		if fl.Err != nil {
			data["stage5_anchor_flush_error"] = fl.Err.Error()
		}
	}

	rdr := rdrRule(p.target, p.port, natlookListenPort)
	pass := routeToLoopbackRule(p.target, p.port)
	data["rdr_rule"] = rdr
	data["filter_rule"] = pass

	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", natlookListenPort))
	if err != nil {
		data["listen_error"] = err.Error()
		p.add(9, "DIOCNATLOOK", statusFail, fmt.Sprintf("cannot listen on 127.0.0.1:%d: %v", natlookListenPort, err), data)
		return
	}
	defer ln.Close()

	// Same order as stage 5: the borrowed wildcard sub-anchor first (no file
	// edit, no main-ruleset replacement), the destructive splice only as a
	// last resort.
	subErr := p.installViaAppleSubAnchor(pfMainRules().Stdout, pfMainNat().Stdout,
		[]string{rdr}, []string{pass}, data)
	if subErr != nil {
		data["apple_subanchor_error"] = subErr.Error()
		if err := p.installMainRuleset([]string{rdr}, []string{pass}, data, "stage9_ruleset"); err != nil {
			data["ruleset_error"] = err.Error()
			st := statusFail
			if errors.Is(err, errMainRulesetRefused) {
				st = statusSkip
			}
			p.add(9, "DIOCNATLOOK", st, "cannot install the rdr ruleset: "+err.Error(), data)
			return
		}
	} else {
		data["rdr_applied_via"] = appleSubAnchor
	}

	dialErr := make(chan error, 1)
	go func() {
		d := net.Dialer{Timeout: 3 * time.Second}
		c, err := d.Dial("tcp4", p.targetAddrPort())
		if err == nil {
			// Hold the connection briefly so the pf state still exists when
			// DIOCNATLOOK runs.
			time.Sleep(500 * time.Millisecond)
			c.Close()
		}
		dialErr <- err
	}()

	tl, ok := ln.(*net.TCPListener)
	if ok {
		_ = tl.SetDeadline(time.Now().Add(p.budget(5 * time.Second)))
	}
	conn, aerr := ln.Accept()
	if aerr != nil {
		data["accept_error"] = aerr.Error()
		select {
		case de := <-dialErr:
			if de != nil {
				data["dial_error"] = errnoName(de)
			} else {
				data["dial_error"] = "none — the dial succeeded without being redirected to the listener"
			}
		case <-time.After(3 * time.Second):
		}
		p.add(9, "DIOCNATLOOK", statusFail, fmt.Sprintf(
			"the connection to %s was never redirected to 127.0.0.1:%d (accept: %v), so pf's rdr on lo0 did not "+
				"fire and there is no state entry to look up", p.targetAddrPort(), natlookListenPort, aerr), data)
		return
	}
	defer conn.Close()

	local, lok := conn.LocalAddr().(*net.TCPAddr)
	remote, rok := conn.RemoteAddr().(*net.TCPAddr)
	if !lok || !rok {
		p.add(9, "DIOCNATLOOK", statusFail, "accepted connection has non-TCP addresses", data)
		return
	}
	localAP := netip.AddrPortFrom(mustAddr4(local.IP), uint16(local.Port))
	remoteAP := netip.AddrPortFrom(mustAddr4(remote.IP), uint16(remote.Port))
	data["accepted_local"] = localAP.String()
	data["accepted_remote"] = remoteAP.String()

	orig, nerr := natlook(p.pfFD, remoteAP, localAP)
	if nerr != nil {
		data["natlook_error"] = nerr.Error()
		p.add(9, "DIOCNATLOOK", statusFail, fmt.Sprintf(
			"the connection was redirected to the local listener, but %v", nerr), data)
		return
	}
	data["recovered_original_destination"] = orig.String()
	want := netip.AddrPortFrom(p.target, uint16(p.port))
	data["expected_original_destination"] = want.String()
	if orig != want {
		p.add(9, "DIOCNATLOOK", statusFail, fmt.Sprintf(
			"DIOCNATLOOK returned %s but the original destination was %s", orig, want), data)
		return
	}
	p.add(9, "DIOCNATLOOK", statusPass, fmt.Sprintf(
		"connection redirected to 127.0.0.1:%d and DIOCNATLOOK recovered the original destination %s exactly",
		natlookListenPort, orig), data)
}

// mustAddr4 converts a net.IP to a 4-byte netip.Addr, unmapping IPv4-in-IPv6.
func mustAddr4(ip net.IP) netip.Addr {
	if a, ok := netip.AddrFromSlice(ip); ok {
		return a.Unmap()
	}
	return netip.Addr{}
}

// ---------------------------------------------------------------------------
// stage 10: cleanup verification
// ---------------------------------------------------------------------------

// stage10Cleanup runs every undo action, then proves the machine was left as it
// was found: pf's own status is printed and /etc/pf.conf is shown to be
// byte-identical (same size, mtime and SHA-256) to the witness taken in stage 5.
func (p *probe) stage10Cleanup() {
	p.cleanup()
	data := map[string]any{
		"actions": strings.Join(p.cleanupLog, " | "),
	}
	failed := 0
	for _, l := range p.cleanupLog {
		if strings.Contains(l, "FAILED") {
			failed++
		}
	}
	data["failed_actions"] = failed

	_, info := pfStatusEnabled()
	data["pfctl_-s_info"] = info.combined()
	if info.Err != nil {
		data["pfctl_-s_info_error"] = info.Err.Error()
	}

	after := pfMainRules()
	data["main_ruleset_after"] = oneLine(after.Stdout)
	data["probe_rule_still_present"] = strings.Contains(after.Stdout, probeAnchor) ||
		(p.utun != nil && strings.Contains(after.Stdout, p.utun.Name))

	p.pfConfAfter = witnessFile(pfConfPath)
	data["pf.conf_before"] = p.pfConfBefore.String()
	data["pf.conf_after"] = p.pfConfAfter.String()
	unchanged := p.pfConfBefore.same(p.pfConfAfter)
	data["pf.conf_unchanged"] = unchanged

	status := statusPass
	detail := fmt.Sprintf("%d undo action(s) all succeeded; %s is byte-identical (sha256 and mtime unchanged)",
		len(p.cleanupLog), pfConfPath)
	if p.pfConfBefore.Err != "" || p.pfConfAfter.Err != "" {
		status = statusFail
		detail = fmt.Sprintf("could not witness %s (before: %q, after: %q)", pfConfPath, p.pfConfBefore.Err, p.pfConfAfter.Err)
	} else if !unchanged {
		status = statusFail
		detail = fmt.Sprintf("%s CHANGED during the run — before %s, after %s", pfConfPath, p.pfConfBefore, p.pfConfAfter)
	} else if failed > 0 {
		status = statusFail
		detail = fmt.Sprintf("%d of %d undo action(s) failed: %s", failed, len(p.cleanupLog),
			strings.Join(p.cleanupLog, " | "))
	}
	p.add(10, "cleanup verification", status, detail, data)
}

// ---------------------------------------------------------------------------
// verdict and output
// ---------------------------------------------------------------------------

// verdict distils the ten stages into the single architectural answer the rest
// of the project depends on.
func (p *probe) verdict() (string, string) {
	stage6 := p.stageIs(6, statusPass)
	stage7 := p.stageIs(7, statusPass)
	stage8 := p.stageIs(8, statusPass)
	stage9 := p.stageIs(9, statusPass)

	vpn := false
	for _, r := range p.allDefaults {
		if r.IsTunnel {
			vpn = true
		}
	}
	vpnSuffix := ""
	if vpn {
		vpnSuffix = " NOTE: a VPN default route was active, so these measurements describe the VPN path; re-run with the VPN off to confirm."
	}

	if p.env.EUID != 0 {
		return verdictUnclear, "The probe was not run as root, so no packet-level stage could execute." + vpnSuffix
	}

	switch {
	case stage6 && stage7:
		return verdictFullParity, "pf route-to delivered the outbound segment to the utun descriptor and the packet " +
			"was successfully re-emitted on the physical interface, so the read-mangle-reinject core that winws " +
			"gets from WinDivert is reproducible on this machine." + vpnSuffix
	case stage6 && stage8:
		return verdictFullParity, "pf route-to delivered the outbound segment to the utun descriptor and the raw " +
			"SOCK_RAW/IP_HDRINCL path accepted the re-emit, so full parity is reachable even though the BPF " +
			"Ethernet write did not confirm egress." + vpnSuffix
	case stage6:
		return verdictUnclear, "Packets can be read off the utun, but neither the BPF Ethernet write nor the raw " +
			"socket could be confirmed to put them back on the wire, so the reinject half of the datapath is unproven." + vpnSuffix
	case stage9:
		return verdictProxyOnly, "pf route-to never handed the outbound segment to the utun descriptor, so packet " +
			"mangling is unavailable; the pf rdr plus DIOCNATLOOK relay does work, so ship the socket-level proxy " +
			"transport only." + vpnSuffix
	default:
		return verdictUnclear, "Neither the utun interception path nor the rdr/DIOCNATLOOK relay could be " +
			"demonstrated; the earlier stage failures have to be resolved before the architecture can be chosen." + vpnSuffix
	}
}

// emit writes the report in the requested format.
func (p *probe) emit() {
	v, rationale := p.verdict()
	if p.jsonOut {
		p.emitJSON(v, rationale)
		return
	}
	p.emitTable(v, rationale)
}

// emitJSON prints the machine-readable report.
func (p *probe) emitJSON(v, rationale string) {
	iface := p.ifaceFlag
	if iface == "" {
		iface = p.route.IfName
	}
	r := report{
		Tool:      "zaprctl probe",
		StartedAt: p.started.Format(time.RFC3339),
		Target:    p.targetAddrPort(),
		Iface:     iface,
		Stages:    p.results,
		Verdict:   v,
		Rationale: rationale,
		Warnings:  p.warnings,
		Notes:     append(p.notes, p.cleanupLog...),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "zaprctl probe: cannot encode JSON report: %v\n", err)
	}
}

// emitTable prints the compact aligned human-readable report.
func (p *probe) emitTable(v, rationale string) {
	w := os.Stdout
	iface := p.ifaceFlag
	if iface == "" {
		iface = p.route.IfName
	}
	utun := "-"
	if p.utun != nil {
		utun = p.utun.Name
	}
	fmt.Fprintf(w, "zaprctl probe  target=%s  iface=%s  utun=%s  %s\n",
		p.targetAddrPort(), orDash(iface), utun, p.started.Format(time.RFC3339))
	fmt.Fprintln(w, strings.Repeat("=", 100))

	if len(p.warnings) > 0 {
		for _, warn := range p.warnings {
			fmt.Fprintln(w, "!! WARNING")
			for _, l := range wrap(warn, 94) {
				fmt.Fprintf(w, "!! %s\n", l)
			}
		}
		fmt.Fprintln(w, strings.Repeat("=", 100))
	}

	fmt.Fprintf(w, "%-3s %-30s %-7s %s\n", "#", "STAGE", "STATUS", "DETAIL")
	fmt.Fprintln(w, strings.Repeat("-", 100))
	for _, r := range p.results {
		lines := wrap(r.Detail, 56)
		if len(lines) == 0 {
			lines = []string{""}
		}
		fmt.Fprintf(w, "%-3d %-30s %-7s %s\n", r.Stage, truncate(r.Name, 30), r.Status, lines[0])
		for _, l := range lines[1:] {
			fmt.Fprintf(w, "%-3s %-30s %-7s %s\n", "", "", "", l)
		}
	}
	fmt.Fprintln(w, strings.Repeat("-", 100))
	fmt.Fprintf(w, "VERDICT: %s\n", v)
	for _, l := range wrap(rationale, 96) {
		fmt.Fprintf(w, "  %s\n", l)
	}

	if len(p.notes) > 0 {
		fmt.Fprintln(w, "\nNOTES")
		for _, n := range p.notes {
			for i, l := range wrap(n, 94) {
				if i == 0 {
					fmt.Fprintf(w, "  - %s\n", l)
				} else {
					fmt.Fprintf(w, "    %s\n", l)
				}
			}
		}
	}

	if len(p.cleanupLog) > 0 {
		fmt.Fprintln(w, "\nCLEANUP")
		for _, l := range p.cleanupLog {
			fmt.Fprintf(w, "  - %s\n", l)
		}
	}

	fmt.Fprintln(w, "\nDETAILS")
	for _, r := range p.results {
		if len(r.Data) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  [%d] %s (%s)\n", r.Stage, r.Name, r.Status)
		keys := make([]string, 0, len(r.Data))
		for k := range r.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := fmt.Sprintf("%v", r.Data[k])
			if strings.Contains(val, "\n") {
				fmt.Fprintf(w, "      %s:\n", k)
				for _, l := range strings.Split(val, "\n") {
					fmt.Fprintf(w, "        %s\n", l)
				}
				continue
			}
			fmt.Fprintf(w, "      %-38s %s\n", k+":", val)
		}
	}
}

// oneLine collapses multi-line command output into a single line for the table.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	fields := strings.Split(s, "\n")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return strings.Join(out, " / ")
}

// orDash renders an empty string as "-".
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// truncate shortens s to at most n runes, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// wrap breaks s into lines of at most width characters, splitting on spaces.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, wd := range words[1:] {
		if len(cur)+1+len(wd) > width {
			lines = append(lines, cur)
			cur = wd
			continue
		}
		cur += " " + wd
	}
	return append(lines, cur)
}
