//go:build darwin

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/naladwepo/zapret-for-mac/internal/ctl"
	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/diag"
	"github.com/naladwepo/zapret-for-mac/internal/launchd"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
	"github.com/naladwepo/zapret-for-mac/internal/vpn"
)

// happRoutingProfile is the documented payload accepted by
// happ://routing/onadd/<base64>. String booleans are intentional: Happ's public
// profile format spells them this way.
type happRoutingProfile struct {
	Name              string            `json:"Name"`
	GlobalProxy       string            `json:"GlobalProxy"`
	RemoteDNSType     string            `json:"RemoteDNSType"`
	RemoteDNSDomain   string            `json:"RemoteDNSDomain"`
	RemoteDNSIP       string            `json:"RemoteDNSIP"`
	DomesticDNSType   string            `json:"DomesticDNSType"`
	DomesticDNSDomain string            `json:"DomesticDNSDomain"`
	DomesticDNSIP     string            `json:"DomesticDNSIP"`
	GeoIPURL          string            `json:"Geoipurl"`
	GeoSiteURL        string            `json:"Geositeurl"`
	DNSHosts          map[string]string `json:"DnsHosts"`
	DirectSites       []string          `json:"DirectSites"`
	DirectIP          []string          `json:"DirectIp"`
	ProxySites        []string          `json:"ProxySites"`
	ProxyIP           []string          `json:"ProxyIp"`
	BlockSites        []string          `json:"BlockSites"`
	BlockIP           []string          `json:"BlockIp"`
	DomainStrategy    string            `json:"DomainStrategy"`
	FakeDNS           string            `json:"FakeDNS"`
	RouteOrder        string            `json:"RouteOrder"`
}

// ---------------------------------------------------------------------------
// transport selection
// ---------------------------------------------------------------------------

// The values --transport accepts. They are the same spellings zapretd's own
// --transport takes, so a user only has to learn one vocabulary.
const (
	// transportAuto reports whatever the running daemon chose.
	transportAuto = "auto"
	// transportDivert is the packet datapath (utun + BPF injection).
	transportDivert = diag.TransportDivert
	// transportProxy is the socket-level fallback (pf rdr + relay).
	transportProxy = diag.TransportProxy
)

// validateTransport rejects a --transport value we cannot answer for.
func (c *cli) validateTransport() error {
	c.transport = strings.ToLower(strings.TrimSpace(c.transport))
	switch c.transport {
	case "":
		c.transport = transportAuto
		return nil
	case transportAuto, transportDivert, transportProxy:
		return nil
	}
	return fmt.Errorf("--transport %q is unknown; use %s (ask the daemon), %s (the packet datapath) or %s (the socket-level fallback)",
		c.transport, transportAuto, transportDivert, transportProxy)
}

// transportCapsFor returns the capability set a named transport provides. These
// are the same constructors the daemon uses, so an offline answer and a live one
// cannot disagree about what a transport can do.
func transportCapsFor(name string) (desync.Caps, bool) {
	switch name {
	case transportDivert:
		return desync.FullCaps(), true
	case transportProxy:
		return desync.ProxyCaps(), true
	}
	return desync.Caps{}, false
}

// transportReason is the one-paragraph explanation of what a transport is, used
// when we answer for a transport nobody probed.
func transportReason(name string) string {
	switch name {
	case transportDivert:
		return "the packet datapath: pf steers the port window into a utun the daemon owns and " +
			"re-emits with a BPF write, so every byte of the headers is ours — full winws-class parity."
	case transportProxy:
		return "the socket-level fallback: pf rdr into a userspace relay (what tpws does on macOS). " +
			"TCP only, byte-level tricks only: no injected packets, no sequence control, no UDP."
	}
	return ""
}

// capsView is the answer to "whose capabilities are we talking about". Every
// command that reports capability consequences resolves one of these first, so
// list, caps, explain and use cannot contradict each other.
type capsView struct {
	// Requested is the --transport value that produced this view.
	Requested string
	// Name is the transport the matrix belongs to.
	Name string
	// Label is Name plus why we are reporting it, for a header line.
	Label string
	// Reason is the long form printed by `caps`.
	Reason string
	// Caps is the matrix itself.
	Caps desync.Caps
	// Live is true when this is the transport the daemon is actually running.
	Live bool
	// DaemonUp is true when the daemon answered at all.
	DaemonUp bool
	// DaemonErr says why it did not answer, when it did not, short enough for a
	// header: "no daemon is running" or "the daemon did not answer".
	DaemonErr string
	// DaemonErrDetail is the socket error behind DaemonErr, when there was one.
	DaemonErrDetail string
	// NotRunning is true when the daemon was asked and did not answer, so the
	// matrix is an assumption and the command must exit with exitNotRunning.
	NotRunning bool
	// Active is the strategy the daemon has activated, or the one remembered on
	// disk when the daemon is down.
	Active string
	// daemon is the daemon's own answer, kept so `caps` can print its Reason and
	// Unsupported verbatim instead of recomputing them.
	daemon *ctl.CapsData
}

// capsView resolves --transport into a concrete capability matrix.
//
// With --transport auto it asks the daemon, because only the daemon knows which
// datapath actually came up on this machine. With an explicit transport it
// answers from the transport's own capability constructor and does NOT need a
// daemon at all: "what would the socket-level fallback do to this strategy" is a
// question a user must be able to ask before installing anything.
func (c *cli) capsView(ctx context.Context) (capsView, error) {
	v := capsView{Requested: c.transport}
	live, lerr := c.client().Caps(ctx)
	running := lerr == nil
	v.DaemonUp = running
	switch {
	case running:
	case ctl.IsNotRunning(lerr):
		v.DaemonErr = "no daemon is running"
	case c.transport == transportAuto:
		// Only "auto" actually needs the daemon: it is the daemon that knows
		// which datapath came up. Anything else (a socket we may not talk to,
		// a timeout) is fatal there and merely a missing detail here.
		return v, lerr
	default:
		v.DaemonErr, v.DaemonErrDetail = "the daemon did not answer", firstLine(lerr.Error())
	}

	if c.transport == transportAuto {
		if running {
			cd := live
			v.Label, v.Reason = cd.Transport, cd.Reason
			v.Name = bareTransport(cd.Transport)
			v.Caps, v.Live, v.Active, v.daemon = capsFrom(cd), true, cd.Strategy, &cd
			return v, nil
		}
		v.NotRunning = true
		v.Name, v.Caps = transportDivert, desync.FullCaps()
		v.Label = transportDivert + " (assumed)"
		v.Reason = "the daemon is not running, so nothing was probed: this is what the packet " +
			"datapath provides when it starts. `sudo zaprctl doctor` proves it on this machine."
		v.Active = c.activeName()
		return v, nil
	}

	caps, ok := transportCapsFor(c.transport)
	if !ok {
		// validateTransport runs before every command, so this cannot happen
		// unless a new selector is added without a Caps constructor.
		return v, fmt.Errorf("no capability set is defined for transport %q", c.transport)
	}
	v.Name, v.Caps = c.transport, caps
	v.Label = c.transport + " (requested)"
	v.Reason = transportReason(c.transport)
	switch {
	case !running:
		v.Active = c.activeName()
		v.Label = fmt.Sprintf("%s (requested; %s)", c.transport, v.DaemonErr)
		v.Reason += fmt.Sprintf(" Nothing was probed (%s%s), and this answer does not need a daemon.",
			v.DaemonErr, ifNotEmpty(": ", v.DaemonErrDetail))
	case bareTransport(live.Transport) == c.transport:
		v.Live, v.Active, v.daemon = true, live.Strategy, &live
		// The daemon's own label already carries any caveat ("proxy (not
		// started)"); only a bare name needs saying that this is the live one.
		v.Label = live.Transport
		if v.Label == c.transport {
			v.Label += " (the running datapath)"
		}
	default:
		v.Active = live.Strategy
		v.Label = fmt.Sprintf("%s (requested; the running datapath is %s)", c.transport, live.Transport)
		v.Reason += fmt.Sprintf(" The running datapath is %s, so this is a what-if, not the current state.",
			live.Transport)
	}
	return v, nil
}

// bareTransport takes the transport name out of a daemon label such as
// "proxy (not started)": the label is written for a human, while --transport and
// every suggested command need the bare token.
func bareTransport(label string) string {
	tok := strings.ToLower(strings.TrimSpace(label))
	if i := strings.IndexAny(tok, " \t("); i > 0 {
		tok = tok[:i]
	}
	switch tok {
	case transportDivert, transportProxy, diag.TransportNone:
		return tok
	}
	return label
}

// selector is the --transport value that reproduces this view, or "" when the
// view describes something --transport cannot name — a daemon that reported
// transport "none", for instance.
func (v capsView) selector() string {
	switch v.Name {
	case transportDivert, transportProxy:
		return v.Name
	}
	return ""
}

// transportFlag renders the --transport option that reproduces this view, so a
// suggested command can be pasted as printed.
func (v capsView) transportFlag() string {
	if s := v.selector(); s != "" {
		return " --transport " + s
	}
	return ""
}

// capsFrom converts the wire matrix back into the engine's Caps.
func capsFrom(d ctl.CapsData) desync.Caps {
	return desync.Caps{
		Inject: d.Inject, Seq: d.Seq, DropOriginal: d.DropOriginal,
		PerPacketTTL: d.PerPacketTTL, Fooling: d.Fooling, IPID: d.IPID,
		UDP: d.UDP, IPv6ExtHdr: d.IPv6ExtHdr, Frag: d.Frag,
		Segment: d.Segment, TLSRec: d.TLSRec,
	}
}

// capsData renders a view as the wire matrix, so the human and JSON printers of
// `caps` have one input whether the numbers came from the daemon or from us.
func (c *cli) capsData(v capsView) ctl.CapsData {
	if v.daemon != nil && v.Requested == transportAuto {
		return *v.daemon
	}
	out := ctl.CapsData{
		Transport:    v.Label,
		Reason:       v.Reason,
		Inject:       v.Caps.Inject,
		Seq:          v.Caps.Seq,
		DropOriginal: v.Caps.DropOriginal,
		PerPacketTTL: v.Caps.PerPacketTTL,
		Fooling:      v.Caps.Fooling,
		IPID:         v.Caps.IPID,
		UDP:          v.Caps.UDP,
		IPv6ExtHdr:   v.Caps.IPv6ExtHdr,
		Frag:         v.Caps.Frag,
		Segment:      v.Caps.Segment,
		TLSRec:       v.Caps.TLSRec,
	}
	if v.Active == "" {
		return out
	}
	s, err := c.loadStrategy(v.Active, v.Caps)
	if err != nil {
		// A missing or broken active strategy must not sink the matrix; the
		// capability half is what the user asked about.
		out.Reason += fmt.Sprintf("; the strategy %q does not load here: %v", v.Active, firstLine(err.Error()))
		return out
	}
	out.Strategy = s.Name
	out.Unsupported = s.Unsupported(v.Caps)
	return out
}

// noteView prints the one-line caveat that belongs on stderr, so a piped table
// stays clean while the reader still learns the answer was not probed.
func (c *cli) noteView(v capsView) {
	if c.json {
		return
	}
	switch {
	case v.NotRunning:
		fmt.Fprintf(c.err, "zaprctl: the daemon is not running; assuming the packet datapath's capabilities\n")
	case v.Requested == transportAuto || v.Live:
	case !v.DaemonUp:
		fmt.Fprintf(c.err, "zaprctl: %s%s; this is what the %s transport would do\n",
			v.DaemonErr, ifNotEmpty(": ", v.DaemonErrDetail), v.Name)
	default:
		fmt.Fprintf(c.err, "zaprctl: reporting the %s transport on request; the running datapath is a different one\n", v.Name)
	}
}

// viewExit is the exit code a read-only capability query ends with: 3 when the
// answer had to be assumed because no daemon answered, 0 otherwise. An explicit
// --transport never yields 3: that question does not need a daemon.
func viewExit(v capsView) int {
	if v.NotRunning {
		return exitNotRunning
	}
	return exitOK
}

// missingCaps lists the capability names need has and have lacks, in the same
// spelling and order internal/strategy uses.
func missingCaps(have, need desync.Caps) []string {
	var missing []string
	check := func(n, h bool, name string) {
		if n && !h {
			missing = append(missing, name)
		}
	}
	check(need.Inject, have.Inject, "inject")
	check(need.Seq, have.Seq, "seq")
	check(need.DropOriginal, have.DropOriginal, "drop")
	check(need.PerPacketTTL, have.PerPacketTTL, "per-packet-ttl")
	check(need.Fooling, have.Fooling, "fooling")
	check(need.IPID, have.IPID, "ip-id")
	check(need.UDP, have.UDP, "udp")
	check(need.IPv6ExtHdr, have.IPv6ExtHdr, "ipv6-exthdr")
	check(need.Frag, have.Frag, "frag")
	check(need.Segment, have.Segment, "segment")
	check(need.TLSRec, have.TLSRec, "tlsrec")
	return missing
}

// ---------------------------------------------------------------------------
// status / stats
// ---------------------------------------------------------------------------

// cmdStatus prints the one screen that answers "is this working?".
func (c *cli) cmdStatus(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("status", "status [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("status", rest); code != parseContinue {
		return code
	}
	st, err := c.client().Status(ctx)
	if err != nil {
		if ctl.IsNotRunning(err) {
			return c.offlineStatus()
		}
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(st)
	}

	state := "running"
	if !st.Running {
		state = "STOPPED"
	}
	fmt.Fprintf(c.out, "zapret-mac %s — datapath %s (pid %d)\n", st.Version, state, st.PID)
	c.kv("transport", "%s%s", st.Transport, ifNotEmpty(" — ", st.TransportReason))
	strat := st.Strategy
	if strat == "" {
		strat = "(none)"
	}
	c.kv("strategy", "%s (%d profiles)%s", strat, st.Profiles, ifNotEmpty(" — ", st.StrategyPath))
	c.kv("window", "tcp %s / udp %s", joinOr(st.WindowTCP, "none"), joinOr(st.WindowUDP, "none"))
	c.kv("uptime", "%s (datapath %s, %d restart(s))", secs(st.UptimeSec), secs(st.DatapathUptimeSec), st.Stats.Restarts)
	c.kv("flows", "%d active, %d total", st.Stats.FlowsActive, st.Stats.FlowsTotal)
	c.kv("packets", "in %d, out %d, injected %d, dropped %d, queue-drop %d",
		st.Stats.PktsIn, st.Stats.PktsOut, st.Stats.PktsInject, st.Stats.PktsDropped, st.Stats.QueueDrop)
	c.kv("bytes", "in %s, out %s", humanBytes(st.Stats.BytesIn), humanBytes(st.Stats.BytesOut))
	c.kv("desync", "matched %d, fired %d, degraded %d, errors %d",
		st.Stats.Matched, st.Stats.Desyncs, st.Stats.Degraded, st.Stats.Errors)

	pfState := "disabled"
	if st.PF.Enabled {
		pfState = "enabled"
	}
	ref := "NOT referenced by pf.conf"
	if st.PF.AnchorReferenced {
		ref = "referenced"
	}
	c.kv("pf", "%s, anchor %q %s, %d rule line(s), token %s",
		pfState, st.PF.Anchor, ref, st.PF.RuleLines, orNone(st.PF.Token))
	if st.PF.Drift != "" {
		c.kv("", "drift: %s", st.PF.Drift)
	}
	c.kv("ipset", "%s", st.IPSet)
	c.kv("hosts", "%d name(s) pinned in /etc/hosts", st.HostsEntries)
	if st.BlockQUIC {
		c.kv("quic", "blocked (UDP/443 dropped so browsers fall back to TCP)")
	}
	c.kv("log", "%s", orNone(st.LogPath))

	if len(st.Unsupported) > 0 {
		fmt.Fprintf(c.out, "\nthis transport cannot honour %d op(s) of the active strategy:\n", len(st.Unsupported))
		for _, u := range st.Unsupported {
			fmt.Fprintf(c.out, "  ! %s\n", u)
		}
		fmt.Fprintf(c.out, "  see `zaprctl explain %s` for what that changes, op by op\n", st.Strategy)
	}
	if len(st.Warnings) > 0 {
		fmt.Fprintf(c.out, "\nwarnings:\n")
		for _, w := range st.Warnings {
			fmt.Fprintf(c.out, "  ! %s\n", w)
		}
	}
	return exitOK
}

// offlineStatus reports what can be learned without the daemon. It still exits
// with the "not running" code, because that is the answer to the question asked.
func (c *cli) offlineStatus() int {
	if c.json {
		_ = c.printJSON(ctl.StatusData{Version: version, Running: false,
			Warnings: []string{"the zapret-mac daemon is not running"}})
		return exitNotRunning
	}
	fmt.Fprintf(c.out, "zapret-mac %s — daemon NOT RUNNING\n", version)
	if loaded, err := launchd.Loaded(launchd.DefaultLabel); err == nil {
		if loaded {
			pid, _ := launchd.PID(launchd.DefaultLabel)
			if pid > 0 {
				c.kv("launchd", "system/%s loaded, pid %d (but the socket does not answer)", launchd.DefaultLabel, pid)
			} else {
				c.kv("launchd", "system/%s loaded but not running", launchd.DefaultLabel)
			}
		} else {
			c.kv("launchd", "system/%s is not loaded — run `sudo make install`", launchd.DefaultLabel)
		}
	} else {
		c.kv("launchd", "cannot ask launchctl: %v", err)
	}
	c.kv("socket", "%s (absent or not listening)", c.socket)
	if b, err := os.ReadFile(netcfg.DefaultPfConfPath); err == nil {
		if netcfg.AnchorStatementsPresent(b, c.anchor) {
			c.kv("pf.conf", "still references anchor %q — `sudo zaprctl doctor --repair` cleans up", c.anchor)
		} else {
			// Not an anomaly: the daemon prefers the wildcard sub-anchor
			// "com.apple/<anchor>", which the stock ruleset already evaluates, so
			// an untouched pf.conf is the normal, healthy state.
			c.kv("pf.conf", "untouched (rules go into the wildcard sub-anchor com.apple/%s — no edit needed)", c.anchor)
		}
	}
	// netcfg.DefaultRoutes4 sorts non-tunnel first, so DefaultRoute4 reports the
	// physical uplink even while a VPN owns the actual default route. That is the
	// right answer for the transport (it is the link a BPF write must target) but
	// the wrong one to show alone: a full-tunnel VPN makes the steering pointless,
	// which is exactly what the daemon warns about at startup. Report both.
	if routes, err := netcfg.DefaultRoutes4(); err == nil && len(routes) > 0 {
		r := routes[0]
		c.kv("route", "default via %s on %s%s", r.Gateway, r.Iface, ifTrue(r.IsTunnel, " (TUNNEL — a VPN is active)"))
		for _, t := range routes[1:] {
			if t.IsTunnel {
				c.kv("", "! %s also holds a default route (a VPN is active): traffic may never reach "+
					"the DPI we fool, and re-emission on %s would target the wrong link",
					t.Iface, r.Iface)
			}
		}
	}
	fmt.Fprintf(c.out, "\nstart it with:  sudo zaprctl start\n")
	return exitNotRunning
}

// cmdStats prints the counters alone.
func (c *cli) cmdStats(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("stats", "stats [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("stats", rest); code != parseContinue {
		return code
	}
	s, err := c.client().Stats(ctx)
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(s)
	}
	t := newTable("COUNTER", "VALUE")
	t.add("transport", s.Transport)
	t.add("flows-active", fmt.Sprint(s.FlowsActive))
	t.add("flows-total", fmt.Sprint(s.FlowsTotal))
	t.add("pkts-in", fmt.Sprint(s.PktsIn))
	t.add("pkts-out", fmt.Sprint(s.PktsOut))
	t.add("pkts-inject", fmt.Sprint(s.PktsInject))
	t.add("pkts-dropped", fmt.Sprint(s.PktsDropped))
	t.add("bytes-in", fmt.Sprint(s.BytesIn))
	t.add("bytes-out", fmt.Sprint(s.BytesOut))
	t.add("matched", fmt.Sprint(s.Matched))
	t.add("desyncs", fmt.Sprint(s.Desyncs))
	t.add("degraded", fmt.Sprint(s.Degraded))
	t.add("errors", fmt.Sprint(s.Errors))
	t.add("queue-drop", fmt.Sprint(s.QueueDrop))
	t.add("restarts", fmt.Sprint(s.Restarts))
	t.render(c.out)
	return exitOK
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

// cmdList prints the strategy menu, marking what the selected transport cannot
// honour.
//
// The NOT HONOURED column carries two kinds of loss, because a user needs both:
// ops that cannot run at all (fake, rst, syndata under the socket-level
// fallback) and ops that run with a parameter dropped — "multisplit(-seqovl)" is
// the one that matters, since the overlap is the whole trick in most flowseal
// strategies and the op itself passes the static capability gate.
func (c *cli) cmdList(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("list", "list [--transport auto|divert|proxy] [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("list", rest); code != parseContinue {
		return code
	}
	v, err := c.capsView(ctx)
	if err != nil {
		return c.fail(err)
	}
	c.noteView(v)

	var data ctl.ListData
	if v.Live && v.Requested == transportAuto {
		// The daemon owns the installed set: it may read a different data
		// directory than this binary would find.
		if data, err = c.client().List(ctx); err != nil {
			return c.fail(err)
		}
	} else if data, err = c.localList(v); err != nil {
		return c.fail(err)
	}
	data.Transport = v.Label
	if data.Active == "" {
		data.Active = v.Active
	}

	// Parameter-level losses need the compiled strategy, which only a local read
	// gives us; the daemon's ListData has the op-level answer only. Missing
	// files simply produce no annotation — never a guess.
	compiled := c.localStrategies(v.Caps)
	rows := make([]ctl.StrategyInfo, len(data.Strategies))
	partial := make([][]string, len(data.Strategies))
	for i := range data.Strategies {
		rows[i] = data.Strategies[i]
		s := compiled[data.Strategies[i].Name]
		if s == nil {
			continue
		}
		p := s.ParamDegradations(v.Caps)
		if len(p) == 0 {
			continue
		}
		partial[i] = p
		// The JSON payload carries the long form; Unsupported is the one field a
		// script greps for "what do I lose".
		data.Strategies[i].Unsupported = append(append([]string(nil), rows[i].Unsupported...), p...)
	}

	if c.json {
		_ = c.printJSON(data)
		return viewExit(v)
	}
	if len(data.Strategies) == 0 {
		fmt.Fprintf(c.out, "no strategies in %s — run `sudo make install`\n", data.Dir)
		return viewExit(v)
	}
	fmt.Fprintf(c.out, "strategies in %s (transport %s)\n\n", data.Dir, data.Transport)
	t := newTable("", "NAME", "PROFILES", "NOT HONOURED", "OPS")
	for i, s := range rows {
		active := ""
		if s.Active || (data.Active != "" && s.Name == data.Active) {
			active = "*"
		}
		ops := s.Summary
		if j := strings.Index(ops, "ops: "); j >= 0 {
			ops = ops[j+len("ops: "):]
		}
		t.add(active, s.Name, fmt.Sprint(s.Profiles), notHonouredCell(s.Unsupported, partial[i]), ops)
	}
	t.render(c.out)
	fmt.Fprintf(c.out, "\n* = active.  \"-\" = this transport runs the whole strategy.\n")
	fmt.Fprintf(c.out, "name(-param) = the op runs but that parameter is dropped.\n\n")
	next := newTable()
	next.add("  zaprctl caps"+v.transportFlag(), "the capability matrix behind that column")
	next.add("  zaprctl explain <name>"+v.transportFlag(), "every profile and op with its real parameters")
	next.add("  sudo zaprctl use <name>", "switch (it refuses a strategy this transport degrades")
	next.add("", "unless you add --force)")
	next.render(c.out)
	return viewExit(v)
}

// notHonouredCell renders the NOT HONOURED column: the op names that cannot run,
// then the ops that run with a parameter dropped. Tokens are deduplicated —
// several profiles losing the same parameter is one fact, not three.
func notHonouredCell(unsupported, partial []string) string {
	var parts []string
	seen := make(map[string]struct{}, len(unsupported)+len(partial))
	add := func(tok string) {
		if tok == "" {
			return
		}
		if _, dup := seen[tok]; dup {
			return
		}
		seen[tok] = struct{}{}
		parts = append(parts, tok)
	}
	for _, line := range unsupported {
		add(opOfLine(line))
	}
	for _, line := range partial {
		add(shortLoss(line))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// opOfLine takes the op name out of a strategy.Unsupported line, which reads
// "fake (needs inject, per-packet-ttl)".
func opOfLine(line string) string {
	name, _, _ := strings.Cut(line, " (")
	return strings.TrimSpace(name)
}

// shortLoss squeezes one strategy.ParamDegradations line into a table cell:
// "multisplit: seqovl 681 will be dropped (needs seq); ..." becomes
// "multisplit(-seqovl)". The long form is what --json and `explain` print.
func shortLoss(line string) string {
	head, tail, ok := strings.Cut(line, ":")
	name := strings.TrimSpace(head)
	if !ok {
		return name
	}
	param := strings.TrimSpace(tail)
	if i := strings.IndexAny(param, " \t"); i > 0 {
		param = param[:i]
	}
	if param == "" {
		return name
	}
	return name + "(-" + param + ")"
}

// localList compiles the installed strategies without a daemon, or for a
// transport the daemon is not running.
func (c *cli) localList(v capsView) (ctl.ListData, error) {
	dir := c.findDir("strategies")
	ss, err := strategy.LoadDir(dir, strategy.LoadOpts{
		ListsDir: c.findDir("lists"),
		FakesDir: c.findDir("fakes"),
		Caps:     v.Caps,
	})
	if err != nil {
		return ctl.ListData{}, err
	}
	out := ctl.ListData{Dir: dir, Active: v.Active}
	for _, s := range ss {
		info := ctl.StrategyInfo{
			Name:        s.Name,
			Description: s.Description,
			Summary:     s.Summary(),
			Profiles:    len(s.Profiles),
			Active:      v.Active != "" && s.Name == v.Active,
			Unsupported: s.Unsupported(v.Caps),
		}
		if p := c.strategyPath(s.Name); fileExists(p) {
			info.Path = p
		}
		out.Strategies = append(out.Strategies, info)
	}
	return out, nil
}

// localStrategies compiles every installed strategy against caps, keyed by name.
//
// It is best effort: callers use it only to enrich an answer they already have,
// so an unreadable directory yields nil rather than an error. One LoadDir call
// shares the parsed hostlists across all 21 strategies, which a per-file Load
// would not.
func (c *cli) localStrategies(caps desync.Caps) map[string]*strategy.Strategy {
	ss, err := strategy.LoadDir(c.findDir("strategies"), strategy.LoadOpts{
		ListsDir: c.findDir("lists"),
		FakesDir: c.findDir("fakes"),
		Caps:     caps,
	})
	if err != nil {
		return nil
	}
	out := make(map[string]*strategy.Strategy, len(ss))
	for _, s := range ss {
		out[s.Name] = s
	}
	return out
}

// loadStrategy compiles one strategy by name (or path) against caps.
func (c *cli) loadStrategy(name string, caps desync.Caps) (*strategy.Strategy, error) {
	return strategy.Load(c.strategyPath(name), strategy.LoadOpts{
		ListsDir: c.findDir("lists"),
		FakesDir: c.findDir("fakes"),
		Caps:     caps,
	})
}

// findDir resolves a data subdirectory the way the daemon does: the installed
// copy first, then the checkout the binary was built in.
func (c *cli) findDir(name string) string {
	installed := filepath.Join(c.dataDir, name)
	if dirHasFiles(installed) {
		return installed
	}
	var roots []string
	if exe, err := os.Executable(); err == nil {
		if r, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = r
		}
		d := filepath.Dir(exe)
		roots = append(roots, d, filepath.Dir(d), filepath.Dir(filepath.Dir(d)))
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd)
	}
	for _, r := range roots {
		if cand := filepath.Join(r, name); dirHasFiles(cand) {
			return cand
		}
	}
	return installed
}

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

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// ---------------------------------------------------------------------------
// use
// ---------------------------------------------------------------------------

// useResult is the JSON shape of `zaprctl use`. It is ctl.UseData plus the two
// facts the wire type cannot carry: whether the switch actually happened, and
// what the transport would have degraded.
type useResult struct {
	Strategy    string   `json:"strategy"`
	Path        string   `json:"path,omitempty"`
	Transport   string   `json:"transport,omitempty"`
	Activated   bool     `json:"activated"`
	Restarted   bool     `json:"restarted"`
	Forced      bool     `json:"forced"`
	Unsupported []string `json:"unsupported,omitempty"`
	Degraded    []string `json:"degraded,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// cmdUse switches strategy, refusing by default to activate one the ACTIVE
// transport cannot honour.
//
// Silently activating a fake-based strategy under the socket-level fallback is
// the single most misleading thing this tool could do: every counter would move,
// nothing would be faked, and the user would blame the strategy. So the check
// happens BEFORE the switch and --force is required to go through with it.
func (c *cli) cmdUse(ctx context.Context, args []string) int {
	force := false
	rest, code := c.parseCmd("use", "use <strategy> [--force] [--json]", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&force, "force", false, "activate even when this transport cannot honour some ops")
	})
	if code != parseContinue {
		return code
	}
	if len(rest) == 0 {
		fmt.Fprintf(c.err, "zaprctl use: which strategy? Try `zaprctl list`.\n")
		return exitError
	}
	name := strings.Join(rest, " ") // accept flowseal's "general (ALT2)" spelling

	// The check must describe the transport that will run the strategy, so it
	// asks the daemon; --transport is honoured for a what-if, and then --force
	// is still what actually decides.
	v, err := c.capsView(ctx)
	if err != nil {
		return c.fail(err)
	}
	var unsupported, degraded []string
	checked := false
	if s, lerr := c.loadStrategy(name, v.Caps); lerr == nil {
		unsupported, degraded, checked = s.Unsupported(v.Caps), s.ParamDegradations(v.Caps), true
	} else if !c.json && fileExists(c.strategyPath(name)) {
		// A file we can see but not compile is worth a word; a name we cannot
		// find at all is the daemon's error to report (it reads its own data
		// directory and lists the installed names), and blocking the switch over
		// our own path resolution would be wrong either way.
		fmt.Fprintf(c.err, "zaprctl use: cannot pre-check %s here (%v); switching without the capability check\n",
			name, firstLine(lerr.Error()))
	}

	if checked && !force && (len(unsupported) > 0 || len(degraded) > 0) {
		res := useResult{
			Strategy: name, Transport: v.Label, Activated: false,
			Unsupported: unsupported, Degraded: degraded,
			Error: "refused: the " + v.Name + " transport cannot honour this strategy; re-run with --force",
		}
		if c.json {
			_ = c.printJSON(res)
			return exitError
		}
		fmt.Fprintf(c.err, "zaprctl: NOT switching to %s — the %s transport cannot honour it.\n", name, v.Name)
		fmt.Fprintf(c.err, "  transport %s\n\n", v.Label)
		for _, u := range unsupported {
			fmt.Fprintf(c.err, "  ! %s — cannot run at all\n", u)
		}
		for _, d := range degraded {
			fmt.Fprintf(c.err, "  ~ %s\n", d)
		}
		fmt.Fprintln(c.err)
		next := newTable()
		next.add(fmt.Sprintf("  zaprctl explain %s%s", name, v.transportFlag()), "what exactly changes")
		next.add("  zaprctl list"+v.transportFlag(), "a strategy this transport can run")
		next.add(fmt.Sprintf("  sudo zaprctl use %s --force", name), "activate anyway")
		next.render(c.err)
		return exitError
	}

	data, err := c.client().Use(ctx, name)
	if err != nil {
		return c.fail(err)
	}
	res := useResult{
		Strategy: data.Strategy, Path: data.Path, Transport: v.Label,
		Activated: true, Restarted: data.Restarted, Forced: force,
		Unsupported: data.Unsupported, Degraded: degraded, Warnings: data.Warnings,
	}
	if len(res.Unsupported) == 0 {
		res.Unsupported = unsupported
	}
	if c.json {
		return c.printJSON(res)
	}
	fmt.Fprintf(c.out, "active strategy: %s\n", data.Strategy)
	if data.Path != "" {
		c.kv("file", "%s", data.Path)
	}
	if data.Restarted {
		c.kv("datapath", "restarting (the steered port window changed, so pf needs new rules)")
	} else {
		c.kv("datapath", "no restart needed (same port window; established flows are preserved)")
	}
	for _, w := range data.Warnings {
		fmt.Fprintf(c.out, "  ! %s\n", w)
	}
	for _, u := range res.Unsupported {
		fmt.Fprintf(c.out, "  ! not honoured: %s\n", u)
	}
	for _, d := range res.Degraded {
		fmt.Fprintf(c.out, "  ~ %s\n", d)
	}
	return exitOK
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

// explainData is the JSON shape of `zaprctl explain`.
type explainData struct {
	Strategy    string `json:"strategy"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source,omitempty"`
	Path        string `json:"path"`
	// Transport is the label of the transport this explanation is written for.
	Transport string `json:"transport"`
	// TransportName is that transport's bare name ("divert" / "proxy").
	TransportName string `json:"transport_name"`
	// TransportRequested echoes --transport.
	TransportRequested string           `json:"transport_requested"`
	Active             bool             `json:"active"`
	WindowTCP          []string         `json:"window_tcp,omitempty"`
	WindowUDP          []string         `json:"window_udp,omitempty"`
	Profiles           []explainProfile `json:"profiles"`
	// Unsupported and Degraded repeat the per-op verdicts as the two summary
	// lists the other commands print.
	Unsupported []string `json:"unsupported,omitempty"`
	Degraded    []string `json:"degraded,omitempty"`
}

// explainProfile is one compiled --new chain element.
type explainProfile struct {
	Index         int           `json:"index"`
	Name          string        `json:"name"`
	Filter        explainFilter `json:"filter"`
	Start         string        `json:"start,omitempty"`
	Cutoff        string        `json:"cutoff,omitempty"`
	OnUnsupported string        `json:"on_unsupported"`
	Ops           []explainOp   `json:"ops"`
}

// explainFilter is a profile's match condition: the names as written in the file
// plus the size of what those names actually loaded.
type explainFilter struct {
	Proto                  string   `json:"proto"`
	Ports                  []string `json:"ports,omitempty"`
	L3                     string   `json:"l3"`
	L7                     []string `json:"l7,omitempty"`
	Hostlist               []string `json:"hostlist,omitempty"`
	HostlistDomains        []string `json:"hostlist_domains,omitempty"`
	HostlistEntries        int      `json:"hostlist_entries,omitempty"`
	HostlistExclude        []string `json:"hostlist_exclude,omitempty"`
	HostlistExcludeDomains []string `json:"hostlist_exclude_domains,omitempty"`
	HostlistExcludeEntries int      `json:"hostlist_exclude_entries,omitempty"`
	HostlistAuto           string   `json:"hostlist_auto,omitempty"`
	IPSet                  []string `json:"ipset,omitempty"`
	IPSetEntries           int      `json:"ipset_entries,omitempty"`
	IPSetExclude           []string `json:"ipset_exclude,omitempty"`
	IPSetExcludeEntries    int      `json:"ipset_exclude_entries,omitempty"`
	// IPSetNone is true when the ipset holds only flowseal's sentinel, i.e. the
	// profile can never match anything (`zaprctl ipset none`).
	IPSetNone bool `json:"ipset_none,omitempty"`
	// IPSetAny is true when the ipset file was empty, which zapret reads as "no
	// restriction".
	IPSetAny bool `json:"ipset_any,omitempty"`
}

// explainOp is one compiled technique with its resolved parameters.
type explainOp struct {
	Op    string `json:"op"`
	Phase string `json:"phase"`
	// Params are rendered "name value" lines, in a fixed order.
	Params []string `json:"params,omitempty"`
	// Needs lists the capabilities this transport lacks for the op.
	Needs []string `json:"needs,omitempty"`
	// Lost lists parameters of an op that DOES run but which this transport
	// silently drops.
	Lost []string `json:"lost,omitempty"`
	// Verdict is runs | degraded | skipped | error.
	Verdict string `json:"verdict"`
	Note    string `json:"note,omitempty"`
}

// cmdExplain prints a compiled strategy in human form: the answer to "what does
// this strategy actually do", which on Windows means reading the .bat file.
func (c *cli) cmdExplain(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("explain", "explain <strategy> [--transport auto|divert|proxy] [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if len(rest) == 0 {
		fmt.Fprintf(c.err, "zaprctl explain: which strategy? Try `zaprctl list`.\n")
		return exitError
	}
	name := strings.Join(rest, " ")

	v, err := c.capsView(ctx)
	if err != nil {
		return c.fail(err)
	}
	c.noteView(v)

	path := c.strategyPath(name)
	s, err := c.loadStrategy(name, v.Caps)
	if err != nil {
		fmt.Fprintf(c.err, "zaprctl explain: %v\n", err)
		if !fileExists(path) {
			fmt.Fprintf(c.err, "  %s does not exist; `zaprctl list` shows the installed names\n", path)
		}
		return exitError
	}

	data := explainData{
		Strategy:           s.Name,
		Description:        s.Description,
		Source:             s.Source,
		Path:               path,
		Transport:          v.Label,
		TransportName:      v.Name,
		TransportRequested: v.Requested,
		Active:             v.Active != "" && v.Active == s.Name,
		WindowTCP:          portSetStrings(s.WindowTCP),
		WindowUDP:          portSetStrings(s.WindowUDP),
		Unsupported:        s.Unsupported(v.Caps),
		Degraded:           s.ParamDegradations(v.Caps),
	}
	raw := rawFilters(path, len(s.Profiles))
	for i, p := range s.Profiles {
		ep := explainProfile{
			Index:         i + 1,
			Name:          p.Name,
			Start:         counterString(p.Start),
			Cutoff:        counterString(p.Cutoff),
			OnUnsupported: unsupportedPolicy(p.OnUnsupported),
			Filter:        buildExplainFilter(p.Filter, rawAt(raw, i)),
		}
		for _, co := range p.Ops {
			eo := explainOp{
				Op:     co.Op.Name(),
				Phase:  phaseName(co.Op.Phase()),
				Params: opParamLines(co),
				Needs:  missingCaps(v.Caps, co.Op.Requires()),
			}
			eo.Verdict, eo.Note = opVerdict(co, p.OnUnsupported, eo.Needs, v)
			if len(eo.Needs) == 0 {
				// An op that cannot run at all has no parameters left to lose,
				// which is also why strategy.ParamDegradations skips it.
				eo.Lost = paramLossLines(co, v.Caps)
			}
			ep.Ops = append(ep.Ops, eo)
		}
		data.Profiles = append(data.Profiles, ep)
	}

	if c.json {
		_ = c.printJSON(data)
		return viewExit(v)
	}
	c.printExplain(data)
	return viewExit(v)
}

// printExplain renders the human form.
func (c *cli) printExplain(d explainData) {
	fmt.Fprintf(c.out, "strategy %s%s\n", d.Strategy, ifTrue(d.Active, "  (active)"))
	c.kv("file", "%s", d.Path)
	if d.Description != "" {
		c.kv("about", "%s", d.Description)
	}
	if d.Source != "" {
		c.kv("source", "%s (upstream flowseal .bat)", d.Source)
	}
	c.kv("transport", "%s", d.Transport)
	c.kv("window", "tcp %s", joinOr(d.WindowTCP, "none"))
	c.kv("", "udp %s", joinOr(d.WindowUDP, "none"))
	c.kv("profiles", "%d, first match wins", len(d.Profiles))

	for _, p := range d.Profiles {
		fmt.Fprintf(c.out, "\n[%d/%d] %s\n", p.Index, len(d.Profiles), p.Name)
		for i, line := range filterLines(p.Filter) {
			key := ""
			if i == 0 {
				key = "filter"
			}
			c.kv(key, "%s", line)
		}
		if p.Start != "" {
			c.kv("start", "%s", p.Start)
		}
		if p.Cutoff != "" {
			c.kv("cutoff", "%s", p.Cutoff)
		}
		c.kv("ops", "%d, applied in this order (on_unsupported = %s)", len(p.Ops), p.OnUnsupported)
		for i, op := range p.Ops {
			fmt.Fprintf(c.out, "    %d. %s  [%s phase]\n", i+1, op.Op, op.Phase)
			for _, pl := range op.Params {
				fmt.Fprintf(c.out, "       %s\n", pl)
			}
			for _, l := range op.Lost {
				fmt.Fprintf(c.out, "       ~ %s\n", l)
			}
			if len(op.Needs) == 0 {
				continue
			}
			fmt.Fprintf(c.out, "       ! needs %s, which this transport does not have\n", strings.Join(op.Needs, ", "))
			fmt.Fprintf(c.out, "         -> %s: %s\n", strings.ToUpper(op.Verdict), op.Note)
		}
	}

	if len(d.Unsupported) == 0 && len(d.Degraded) == 0 {
		fmt.Fprintf(c.out, "\nthe %s transport runs every op of this strategy as written.\n", d.TransportName)
		return
	}
	fmt.Fprintf(c.out, "\nwhat the %s transport loses:\n", d.TransportName)
	for _, u := range d.Unsupported {
		fmt.Fprintf(c.out, "  ! %s\n", u)
	}
	for _, g := range d.Degraded {
		fmt.Fprintf(c.out, "  ~ %s\n", g)
	}
}

// filterLines renders a filter as the lines of a detail block.
func filterLines(f explainFilter) []string {
	var out []string
	head := f.Proto
	if len(f.Ports) > 0 {
		head += ", ports " + strings.Join(f.Ports, ", ")
	} else {
		head += ", any port"
	}
	if f.L3 != "any" {
		head += ", " + f.L3
	}
	if len(f.L7) > 0 {
		head += ", l7 " + strings.Join(f.L7, "/")
	}
	out = append(out, head)
	add := func(label string, names, inline []string, entries int, extra string) {
		if len(names) == 0 && len(inline) == 0 {
			return
		}
		parts := append([]string(nil), names...)
		for _, d := range inline {
			parts = append(parts, d+" (inline)")
		}
		line := fmt.Sprintf("%-22s %s", label, strings.Join(parts, ", "))
		if entries > 0 {
			line += fmt.Sprintf(" — %d entr%s loaded", entries, plural(entries, "y", "ies"))
		}
		if extra != "" {
			line += " — " + extra
		}
		out = append(out, line)
	}
	add("hostlist", f.Hostlist, f.HostlistDomains, f.HostlistEntries, "")
	add("hostlist_exclude", f.HostlistExclude, f.HostlistExcludeDomains, f.HostlistExcludeEntries, "")
	ipsetNote := ""
	switch {
	case f.IPSetNone:
		ipsetNote = "sentinel only, so this profile currently matches NOTHING (`zaprctl ipset loaded` to fill it)"
	case f.IPSetAny:
		ipsetNote = "the file is empty, which zapret reads as \"no ipset restriction\""
	}
	add("ipset", f.IPSet, nil, f.IPSetEntries, ipsetNote)
	add("ipset_exclude", f.IPSetExclude, nil, f.IPSetExcludeEntries, "")
	if f.HostlistAuto != "" {
		out = append(out, fmt.Sprintf("%-22s %s (self-learning, written by the daemon)", "hostlist_auto", f.HostlistAuto))
	}
	return out
}

// buildExplainFilter merges the compiled filter (sizes, tri-state) with the
// names the file was written with.
func buildExplainFilter(f strategy.Filter, raw *strategy.FilterSpec) explainFilter {
	out := explainFilter{
		Proto:        protoName(f.Proto),
		Ports:        portSetStrings(f.Ports),
		L3:           l3Name(f.L3),
		L7:           l7Names(f.L7),
		HostlistAuto: f.AutoHostlist,
	}
	if raw != nil {
		out.Hostlist = raw.Hostlist
		out.HostlistDomains = raw.HostlistDomains
		out.HostlistExclude = raw.HostlistExclude
		out.HostlistExcludeDomains = raw.HostlistExcludeDomains
		out.IPSet = raw.IPSet
		out.IPSetExclude = raw.IPSetExclude
	} else {
		// Without the raw file the loaded paths are still better than nothing.
		if f.Hostlist != nil {
			out.Hostlist = baseNames(f.Hostlist.Files)
		}
		if f.HostlistExclude != nil {
			out.HostlistExclude = baseNames(f.HostlistExclude.Files)
		}
		if f.IPSet != nil {
			out.IPSet = baseNames(f.IPSet.Files)
		}
		if f.IPSetExclude != nil {
			out.IPSetExclude = baseNames(f.IPSetExclude.Files)
		}
	}
	if f.Hostlist != nil {
		out.HostlistEntries = f.Hostlist.Len()
	}
	if f.HostlistExclude != nil {
		out.HostlistExcludeEntries = f.HostlistExclude.Len()
	}
	if f.IPSet != nil {
		out.IPSetEntries = f.IPSet.Len()
		out.IPSetNone = f.IPSet.IsNone()
		out.IPSetAny = f.IPSet.Any
	}
	if f.IPSetExclude != nil {
		out.IPSetExcludeEntries = f.IPSetExclude.Len()
	}
	return out
}

// rawFilters re-reads the strategy file for the filter fields as written: the
// compiled Filter keeps parsed sets, not the hostlist/ipset file names a user
// recognises. Best effort — a mismatch or a read error only costs the names.
func rawFilters(path string, want int) []strategy.FilterSpec {
	var f strategy.File
	if _, err := toml.DecodeFile(path, &f); err != nil || len(f.Profiles) != want {
		return nil
	}
	out := make([]strategy.FilterSpec, 0, want)
	for i := range f.Profiles {
		out = append(out, f.Profiles[i].Filter)
	}
	return out
}

func rawAt(raw []strategy.FilterSpec, i int) *strategy.FilterSpec {
	if i < 0 || i >= len(raw) {
		return nil
	}
	return &raw[i]
}

// opVerdict says what the transport will do with an op, mirroring
// internal/engine's gate exactly (see Engine.run).
func opVerdict(co strategy.CompiledOp, policy desync.Unsupported, missing []string, v capsView) (verdict, note string) {
	if len(missing) == 0 {
		return "runs", ""
	}
	switch policy {
	case desync.UnsupSkip:
		return "skipped", "on_unsupported = skip, so the op is counted in `degraded` and the rest of the profile still runs"
	case desync.UnsupError:
		return "error", "on_unsupported = error, so the profile refuses to run: the payload is counted in `errors` and nothing is desynced"
	}
	if _, ok := co.Op.(desync.Degrader); ok {
		return "degraded", fmt.Sprintf("on_unsupported = degrade, so %s runs its socket-level approximation (send() boundaries, TCP_MAXSEG) instead of the real technique", co.Op.Name())
	}
	return "skipped", fmt.Sprintf("on_unsupported = degrade, but %s has no socket-level approximation, so it is skipped entirely on the %s transport", co.Op.Name(), v.Name)
}

// paramLossLines lists the parameters of an op that runs but whose effect this
// transport will drop at runtime.
//
// strategy.ParamDegradations is the authority for the summary lists every other
// command prints; the rule is one line long (an overlap has to be placed BELOW
// the window, which needs Caps.Seq), and having it here is what lets `explain`
// attach the loss to the op it belongs to instead of to the strategy as a whole.
func paramLossLines(co strategy.CompiledOp, have desync.Caps) []string {
	var out []string
	if co.Params.Seqovl > 0 && !have.Seq {
		out = append(out, fmt.Sprintf("seqovl %d is DROPPED: this transport cannot lower the TCP sequence, "+
			"so the split still happens but without the sub-window overlap", co.Params.Seqovl))
	}
	return out
}

// opParamLines renders one op's real parameters: what the loader resolved, not
// what the TOML says. Only knobs that are actually in effect appear.
func opParamLines(co strategy.CompiledOp) []string {
	p, spec := co.Params, co.Spec
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	if p.Repeats > 1 {
		add("repeats %d (each injected packet is sent %d times)", p.Repeats, p.Repeats)
	}
	switch {
	case p.TTLAuto:
		add("ttl auto: hop count to the peer %+d, clamped to %d..%d", p.TTLDelta, p.TTLMin, p.TTLMax)
	case p.TTL > 0:
		add("ttl %d (fixed)", p.TTL)
	}
	if p.Fool != desync.FoolNone {
		line := "fooling " + strings.Join(foolNames(p.Fool), ",")
		def := desync.DefaultFoolParams()
		var mods []string
		if p.Fool&desync.FoolBadSeq != 0 && p.FoolP.BadSeqIncrement != def.BadSeqIncrement {
			mods = append(mods, fmt.Sprintf("badseq %+d", p.FoolP.BadSeqIncrement))
		}
		if p.Fool&desync.FoolDataNoAck != 0 && p.FoolP.BadAckIncrement != def.BadAckIncrement {
			mods = append(mods, fmt.Sprintf("badack %+d", p.FoolP.BadAckIncrement))
		}
		if p.Fool&desync.FoolTS != 0 && p.FoolP.TSIncrement != def.TSIncrement {
			mods = append(mods, fmt.Sprintf("ts %+d", p.FoolP.TSIncrement))
		}
		if len(mods) > 0 {
			line += " (" + strings.Join(mods, ", ") + ")"
		}
		add("%s", line)
	}
	if len(p.SplitPos) > 0 {
		add("split-pos %s", strings.Join(posSpecStrings(p.SplitPos), ", "))
	}
	if p.Seqovl > 0 {
		line := fmt.Sprintf("seqovl %d bytes below the window", p.Seqovl)
		if len(p.SeqovlPattern) > 0 {
			line += fmt.Sprintf(", filled from %s (%d bytes on disk)", blobName(spec.SeqovlPattern), len(p.SeqovlPattern))
		} else {
			line += ", filled with the payload's own leading bytes"
		}
		add("%s", line)
	}
	if len(p.Pattern) > 0 {
		add("pattern %s (%d bytes) — the filler the fake half of the split carries", blobName(spec.Pattern), len(p.Pattern))
	}
	addBlob := func(label, spec string, b []byte) {
		if len(b) == 0 {
			return
		}
		add("%s %s (%d bytes)", label, blobName(spec), len(b))
	}
	addBlob("fake tls", spec.Fake.TLS, p.FakeTLS)
	addBlob("fake http", spec.Fake.HTTP, p.FakeHTTP)
	addBlob("fake quic", spec.Fake.QUIC, p.FakeQUIC)
	addBlob("fake syndata", spec.Fake.SynData, p.FakeSynData)
	addBlobList := func(label string, specs []string, bs [][]byte) {
		for i, b := range bs {
			name := ""
			if i < len(specs) {
				name = specs[i]
			}
			add("%s %s (%d bytes)", label, blobName(name), len(b))
		}
	}
	addBlobList("fake discord", spec.Fake.Discord, p.FakeDiscord)
	addBlobList("fake stun", spec.Fake.STUN, p.FakeSTUN)
	addBlobList("fake unknown-udp", spec.Fake.UnknownUDP, p.FakeUnknownUDP)
	if m := tlsModStrings(p.TLSMod); len(m) > 0 {
		add("fake-tls-mod %s", strings.Join(m, ","))
	}
	if p.HostFakeHost != "" {
		add("mod host=%s (the hostname the fake half carries)", p.HostFakeHost)
	}
	if p.AltOrder != 0 {
		add("mod altorder=%d (emission order variant)", p.AltOrder)
	}
	if p.MidHostSet {
		add("mod midhost=%s", posSpecString(p.MidHost))
	}
	if co.Op.Name() == "udplen" {
		add("udplen increment %+d", p.UDPLenIncrement)
		if len(p.UDPLenPattern) > 0 {
			add("udplen padding from %s (%d bytes)", blobName(spec.UDPLenPattern), len(p.UDPLenPattern))
		}
	}
	if p.WSSize > 0 {
		line := fmt.Sprintf("wssize %d", p.WSSize)
		if p.WSSizeScale > 0 {
			line += fmt.Sprintf(":%d (window scale shift)", p.WSSizeScale)
		}
		if p.WSSizeCutoffKind != 0 {
			line += fmt.Sprintf(", until %c%d", p.WSSizeCutoffKind, p.WSSizeCutoffN)
		}
		add("%s", line)
	}
	if p.IPID != desync.IPIDDefault {
		add("ip-id %s", ipidName(p.IPID))
	}
	// The loader fills the fragment positions with nfqws' defaults for every op,
	// so they are only worth printing for the two ops that read them.
	if co.Op.Name() == "ipfrag1" || co.Op.Name() == "ipfrag2" {
		add("fragment position %d on tcp, %d on udp (counted from the L4 header, rounded down to 8)",
			p.FragPosTCP, p.FragPosUDP)
	}
	out = append(out, tamperLines(p.Tamper)...)
	if p.AnyProtocol {
		add("any-protocol: matches even when the payload is not a recognised L7")
	}
	return out
}

// tamperLines renders the in-place L7 mangling knobs.
func tamperLines(t proto.TamperOpts) []string {
	var out []string
	add := func(s string) { out = append(out, s) }
	if t.HostCase {
		add("hostcase: rewrite the Host: header name as hoSt:")
	}
	if t.HostSpell != "" {
		add("hostspell " + t.HostSpell)
	}
	if t.HostNoSpace {
		add("hostnospace: drop the space after Host:")
	}
	if t.HostDot {
		add("hostdot: append a dot to the hostname")
	}
	if t.HostTab {
		add("hosttab: use a tab after Host:")
	}
	if t.HostPad > 0 {
		add(fmt.Sprintf("hostpad %d bytes of junk headers before Host:", t.HostPad))
	}
	if t.DomCase {
		add("domcase: mixed-case the domain")
	}
	if t.MethodSpace {
		add("methodspace: extra space after the HTTP method")
	}
	if t.MethodEOL {
		add("methodeol: newline before the method")
	}
	if t.UnixEOL {
		add("unixeol: LF instead of CRLF")
	}
	return out
}

// ---------------------------------------------------------------------------
// rendering helpers for explain
// ---------------------------------------------------------------------------

// portSetStrings renders a compiled port set the way the strategy file writes it.
func portSetStrings(ps strategy.PortSet) []string {
	out := make([]string, 0, len(ps))
	for _, r := range ps {
		if r.Lo == r.Hi {
			out = append(out, fmt.Sprint(r.Lo))
			continue
		}
		out = append(out, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
	}
	return out
}

// counterString renders a --dpi-desync-start/-cutoff bound, or "" when unset.
func counterString(c strategy.Counter) string {
	if c.Kind == 0 {
		return ""
	}
	kind := map[byte]string{'n': "packet", 'd': "data packet", 's': "relative sequence"}[c.Kind]
	return fmt.Sprintf("%c%d (%s %d)", c.Kind, c.N, kind, c.N)
}

func protoName(p uint8) string {
	switch p {
	case proto.IPProtoTCP:
		return "tcp"
	case proto.IPProtoUDP:
		return "udp"
	}
	return "tcp+udp"
}

func l3Name(l3 uint8) string {
	switch l3 {
	case 4:
		return "ipv4"
	case 6:
		return "ipv6"
	}
	return "any"
}

// l7Names renders an L7 bitmask with zapret's own --filter-l7 spellings.
func l7Names(m proto.L7) []string {
	if m == 0 {
		return nil
	}
	if m == proto.L7Any {
		return []string{"any"}
	}
	var out []string
	for name, bit := range proto.L7Names {
		if name == "any" {
			continue
		}
		if m&bit != 0 {
			out = append(out, name)
		}
	}
	return sortedStrings(out)
}

// foolOrder fixes the order fooling modes are printed in: zapret's own option
// order, not map iteration order.
var foolOrder = []struct {
	bit  desync.Fooling
	name string
}{
	{desync.FoolBadSum, "badsum"},
	{desync.FoolBadSeq, "badseq"},
	{desync.FoolMD5Sig, "md5sig"},
	{desync.FoolTS, "ts"},
	{desync.FoolDataNoAck, "datanoack"},
	{desync.FoolHopByHop, "hopbyhop"},
	{desync.FoolHopByHop2, "hopbyhop2"},
}

func foolNames(f desync.Fooling) []string {
	var out []string
	for _, e := range foolOrder {
		if f&e.bit != 0 {
			out = append(out, e.name)
		}
	}
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

// markerNames inverts proto.MarkerNames once, so a split position can be printed
// with the marker spelling the strategy file used.
var markerNames = func() map[proto.HostlistMarker]string {
	out := make(map[proto.HostlistMarker]string, len(proto.MarkerNames))
	for name, m := range proto.MarkerNames {
		out[m] = name
	}
	return out
}()

// posSpecString renders one split position: "midsld+1", "sniext", "2".
func posSpecString(p desync.PosSpec) string {
	if p.Marker == proto.MarkerAbs {
		return fmt.Sprintf("%d", p.Offset)
	}
	name := markerNames[p.Marker]
	if name == "" {
		name = fmt.Sprintf("marker#%d", p.Marker)
	}
	if p.Offset == 0 {
		return name
	}
	return fmt.Sprintf("%s%+d", name, p.Offset)
}

func posSpecStrings(ps []desync.PosSpec) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, posSpecString(p))
	}
	return out
}

func ipidName(m desync.IPIDMode) string {
	switch m {
	case desync.IPIDZero:
		return "zero"
	case desync.IPIDRandom:
		return "random"
	case desync.IPIDSeq:
		return "seq (sequential across the emitted packets)"
	case desync.IPIDSeqGroup:
		return "seq-group (a fake reuses the ip_id of the part it stands in for)"
	case desync.IPIDSame:
		return "same (copy the intercepted packet's ip_id)"
	}
	return "default"
}

func tlsModStrings(m desync.TLSMod) []string {
	var out []string
	if m.None {
		out = append(out, "none")
	}
	if m.Rnd {
		out = append(out, "rnd")
	}
	if m.RndSNI {
		out = append(out, "rndsni")
	}
	if m.DupSID {
		out = append(out, "dupsid")
	}
	if m.PadEncap {
		out = append(out, "padencap")
	}
	if m.SNI != "" {
		out = append(out, "sni="+m.SNI)
	}
	return out
}

func phaseName(p desync.Phase) string {
	switch p {
	case desync.PhaseSyn:
		return "syn"
	case desync.PhaseFake:
		return "fake"
	case desync.PhaseSplit:
		return "split"
	case desync.PhaseModify:
		return "modify"
	}
	return "unknown"
}

func unsupportedPolicy(u desync.Unsupported) string {
	switch u {
	case desync.UnsupSkip:
		return "skip"
	case desync.UnsupError:
		return "error"
	}
	return "degrade"
}

// blobName renders a fake-payload spec: a file name as written, or "inline hex"
// for a 0x... literal.
func blobName(spec string) string {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "":
		return "(built-in default)"
	case strings.HasPrefix(strings.ToLower(spec), "0x"):
		return "inline hex literal"
	}
	return spec
}

func baseNames(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, filepath.Base(p))
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

// cmdStart brings the datapath up, loading the launchd job first when the daemon
// process itself is not running.
func (c *cli) cmdStart(ctx context.Context, args []string) int {
	var stopVPN, forceVPN bool
	rest, code := c.parseCmd("start", "start [--transport auto|divert|proxy] [--stop-vpn [--force]] [--json]", args,
		func(fs *flag.FlagSet) {
			fs.BoolVar(&stopVPN, "stop-vpn", false,
				"stop VPN software holding a tunnel default route first (it blocks the packet datapath)")
			fs.BoolVar(&forceVPN, "force", false,
				"with --stop-vpn: escalate to SIGTERM/SIGKILL if unloading the launchd job was not enough")
		})
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("start", rest); code != parseContinue {
		return code
	}
	// For every other command --transport only chooses whose capabilities to
	// report. For start it selects the datapath to actually bring up, and the
	// daemon restarts a running one to honour it.
	want := c.transport
	if want == "auto" && !c.transportSet {
		want = ""
	}
	// The daemon waits for the supervisor to actually reach "running" before it
	// answers, so this needs more room than a status poll.
	cl := c.lifecycleClient()
	if err := cl.Ping(ctx); err != nil {
		if !ctl.IsNotRunning(err) {
			return c.fail(err)
		}
		if code := c.bootDaemon(ctx, false); code != exitOK {
			return code
		}
	}
	if stopVPN {
		v, verr := c.client().VPN(ctx, "stop", forceVPN)
		c.printVPN(v)
		if verr != nil {
			fmt.Fprintf(c.err, "zaprctl: could not clear the VPN: %v\n", verr)
			return exitError
		}
		fmt.Fprintln(c.out)
	}
	st, err := cl.StartOn(ctx, want)
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(st)
	}
	fmt.Fprintf(c.out, "datapath %s on transport %s\n", runningWord(st.Running), orNone(st.Transport))
	// Asking for a datapath and quietly getting another one is exactly the
	// failure this flag exists to prevent, so say it loudly.
	if want != "" && want != "auto" && st.Transport != want {
		fmt.Fprintf(c.out, "  ! you asked for transport %q but %q is running — see the warnings below and `zaprctl logs`\n",
			want, orNone(st.Transport))
	}
	for _, w := range st.Warnings {
		fmt.Fprintf(c.out, "  ! %s\n", w)
	}
	return exitOK
}

// cmdStop takes the datapath down, leaving the daemon able to start it again.
func (c *cli) cmdStop(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("stop", "stop [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("stop", rest); code != parseContinue {
		return code
	}
	st, err := c.lifecycleClient().Stop(ctx)
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(st)
	}
	fmt.Fprintf(c.out, "datapath stopped; pf rules removed. The daemon is still running (`zaprctl start` to resume).\n")
	return exitOK
}

// cmdRestart stops and starts the datapath, or restarts the whole job when the
// daemon is not answering.
func (c *cli) cmdRestart(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("restart", "restart [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("restart", rest); code != parseContinue {
		return code
	}
	cl := c.lifecycleClient()
	if err := cl.Ping(ctx); err != nil {
		if !ctl.IsNotRunning(err) {
			return c.fail(err)
		}
		if code := c.bootDaemon(ctx, true); code != exitOK {
			return code
		}
		st, serr := cl.Status(ctx)
		if serr != nil {
			return c.fail(serr)
		}
		if c.json {
			return c.printJSON(st)
		}
		fmt.Fprintf(c.out, "daemon restarted; datapath %s on transport %s\n",
			runningWord(st.Running), orNone(st.Transport))
		return exitOK
	}
	if _, err := cl.Stop(ctx); err != nil {
		return c.fail(err)
	}
	st, err := cl.Start(ctx)
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(st)
	}
	fmt.Fprintf(c.out, "datapath restarted on transport %s\n", orNone(st.Transport))
	return exitOK
}

// cmdReload re-reads the active strategy from disk.
func (c *cli) cmdReload(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("reload", "reload [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("reload", rest); code != parseContinue {
		return code
	}
	st, err := c.client().Reload(ctx)
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(st)
	}
	fmt.Fprintf(c.out, "reloaded strategy %s\n", orNone(st.Strategy))
	return exitOK
}

// bootDaemon loads (or kickstarts) the launchd job and waits for its socket.
func (c *cli) bootDaemon(ctx context.Context, restart bool) int {
	if os.Geteuid() != 0 {
		fmt.Fprintf(c.err, "zaprctl: the daemon is not running and loading it needs root.\n  sudo zaprctl %s\n",
			strings.Join(c.argv, " "))
		return exitDenied
	}
	loaded, err := launchd.Loaded(launchd.DefaultLabel)
	if err != nil {
		fmt.Fprintf(c.err, "zaprctl: cannot ask launchctl about system/%s: %v\n", launchd.DefaultLabel, err)
		return exitError
	}
	if !loaded {
		if _, serr := os.Stat(launchd.DefaultPlistPath); serr != nil {
			fmt.Fprintf(c.err, "zaprctl: the daemon is not installed (%s is missing).\n  sudo make install\n",
				launchd.DefaultPlistPath)
			return exitError
		}
		if berr := launchd.Bootstrap(launchd.DefaultPlistPath); berr != nil && !errors.Is(berr, launchd.ErrAlreadyLoaded) {
			fmt.Fprintf(c.err, "zaprctl: %v\n", berr)
			return exitError
		}
	} else if kerr := launchd.Kickstart(launchd.DefaultLabel, restart); kerr != nil {
		fmt.Fprintf(c.err, "zaprctl: %v\n", kerr)
		return exitError
	}
	// The daemon has to preflight pf and load its ruleset before it listens.
	cl := c.client()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return exitError
		}
		if err := cl.Ping(ctx); err == nil {
			return exitOK
		}
		time.Sleep(250 * time.Millisecond)
	}
	fmt.Fprintf(c.err, "zaprctl: the daemon did not come up within 25s; check %s\n", launchd.DefaultStdoutPath)
	return exitError
}

func runningWord(b bool) string {
	if b {
		return "running"
	}
	return "NOT running"
}

// ---------------------------------------------------------------------------
// caps
// ---------------------------------------------------------------------------

// cmdCaps prints the capability matrix and what it costs the active strategy.
//
// With --transport it answers for a transport that is not running, which is the
// only way to see — before installing — which ops of a strategy the socket-level
// fallback would have to drop.
func (c *cli) cmdCaps(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("caps", "caps [--transport auto|divert|proxy] [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("caps", rest); code != parseContinue {
		return code
	}
	v, err := c.capsView(ctx)
	if err != nil {
		return c.fail(err)
	}
	c.noteView(v)
	caps := c.capsData(v)
	if c.json {
		_ = c.printJSON(caps)
		return viewExit(v)
	}
	fmt.Fprintf(c.out, "capability matrix — transport %s\n", caps.Transport)
	if caps.Reason != "" {
		for _, line := range wrapText(caps.Reason, wrapWidth-2) {
			fmt.Fprintf(c.out, "  %s\n", line)
		}
	}
	fmt.Fprintln(c.out)
	t := newTable("CAPABILITY", "HAVE", "WHAT IT BUYS")
	for _, r := range caps.Rows() {
		t.add(r.Name, mark(r.Have), r.What)
	}
	t.render(c.out)
	if caps.Strategy == "" {
		fmt.Fprintf(c.out, "\nno strategy is active, so nothing is measured against this matrix.\n"+
			"  zaprctl list%s   what each installed strategy loses here\n", v.transportFlag())
		return viewExit(v)
	}
	// Parameters a transport drops at runtime are invisible to CapsData.Unsupported
	// (see strategy.ParamDegradations), and the op's own Plan note only reaches a
	// --verbose log. Recompute them from the strategy file so `caps` is the one
	// place that answers "what will actually happen" — live and offline alike.
	partial := c.paramDegradations(caps.Strategy, capsFrom(caps))
	if len(caps.Unsupported) == 0 && len(partial) == 0 {
		fmt.Fprintf(c.out, "\nstrategy %s: every op is fully supported.\n", caps.Strategy)
		return viewExit(v)
	}
	if len(caps.Unsupported) > 0 {
		fmt.Fprintf(c.out, "\nstrategy %s — these ops CANNOT be honoured by this transport:\n", caps.Strategy)
		for _, u := range caps.Unsupported {
			fmt.Fprintf(c.out, "  ! %s\n", u)
		}
	}
	if len(partial) > 0 {
		fmt.Fprintf(c.out, "\nstrategy %s — these ops RUN but lose part of the trick:\n", caps.Strategy)
		for _, d := range partial {
			fmt.Fprintf(c.out, "  ~ %s\n", d)
		}
	}
	fmt.Fprintf(c.out, "\nEach profile's on_unsupported setting decides whether such an op is\n"+
		"degraded to a socket-level approximation, skipped, or fatal:\n\n")
	next := newTable()
	next.add(fmt.Sprintf("  zaprctl explain %s%s", caps.Strategy, v.transportFlag()), "op by op")
	next.add("  zaprctl list"+v.transportFlag(), "a strategy that fits this transport")
	next.render(c.out)
	return viewExit(v)
}

// paramDegradations recomputes the parameter-level losses of one strategy under
// the given capabilities.
//
// It reads the strategy file rather than the wire, because ctl.CapsData carries
// only the boolean matrix and the all-or-nothing Unsupported list. Any failure is
// silent: this is advisory detail on a command whose main answer is the matrix.
func (c *cli) paramDegradations(name string, caps desync.Caps) []string {
	if name == "" {
		return nil
	}
	s, err := c.loadStrategy(name, caps)
	if err != nil {
		return nil
	}
	return s.ParamDegradations(caps)
}

// activeName reads the strategy the daemon last activated. The state directory is
// always <data>/state, never searched for in the checkout, so this matches
// zapretd's own resolution.
func (c *cli) activeName() string {
	b, err := os.ReadFile(filepath.Join(c.dataDir, "state", "active-strategy"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// strategyPath resolves a strategy name to its .toml the way the daemon does.
func (c *cli) strategyPath(name string) string {
	if strings.HasSuffix(name, ".toml") {
		return name
	}
	return filepath.Join(c.findDir("strategies"), name+".toml")
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

// cmdDoctor runs diagnostics: through the daemon when it is up (it knows the
// datapath's state), locally otherwise — which is exactly when a crashed run has
// to be cleaned up.
//
// Its exit code reports FINDINGS, not reachability: a daemon that is not running
// is one of the findings, so doctor exits 1 (problems) rather than 3.
func (c *cli) cmdDoctor(ctx context.Context, args []string) int {
	repair := false
	rest, code := c.parseCmd("doctor", "doctor [--repair] [--json]", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&repair, "repair", false, "fix what can be fixed (needs root)")
	})
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("doctor", rest); code != parseContinue {
		return code
	}

	data, err := c.client().WithTimeout(60*time.Second).Doctor(ctx, repair)
	if err != nil {
		if !ctl.IsNotRunning(err) {
			return c.fail(err)
		}
		data = c.localDoctor(ctx, repair)
	}
	if c.json {
		code := exitOK
		if errs, _ := data.Problems(); errs > 0 {
			code = exitError
		}
		_ = c.printJSON(data)
		return code
	}

	who := "daemon"
	if !data.DaemonRunning {
		who = "local (no daemon running)"
	}
	fmt.Fprintf(c.out, "diagnostics — zapret-mac %s, uid %d, source: %s\n\n", data.Version, data.UID, who)
	for _, ch := range data.Checks {
		c.printCheck(ch)
	}
	if len(data.Repaired) > 0 {
		fmt.Fprintf(c.out, "\nrepaired:\n")
		for _, r := range data.Repaired {
			fmt.Fprintf(c.out, "  - %s\n", r)
		}
	}
	errs, warns := data.Problems()
	fmt.Fprintf(c.out, "\n%d problem(s), %d warning(s)", errs, warns)
	if data.JournalPending > 0 {
		fmt.Fprintf(c.out, ", %d pending rollback record(s) in %s", data.JournalPending, data.JournalPath)
	}
	fmt.Fprintln(c.out)
	if errs > 0 && !repair {
		fmt.Fprintf(c.out, "try:  sudo zaprctl doctor --repair\n")
	}
	if errs > 0 {
		return exitError
	}
	return exitOK
}

// localDoctor diagnoses (and with repair, cleans up after) a daemon that is not
// running.
//
// The analysis is internal/diag's, the same code the daemon runs, so a machine
// diagnosed with the daemon down and one diagnosed with it up produce comparable
// findings. Only the framing differs: here nothing can be said about a live
// datapath, and here --repair is allowed to replay the rollback journal — with
// the daemon up those records describe state in active use, which is why
// diag.Repair refuses in that case.
func (c *cli) localDoctor(ctx context.Context, repair bool) ctl.DoctorData {
	root := os.Geteuid() == 0
	out := ctl.DoctorData{Version: version, UID: os.Geteuid(), Root: root, DaemonRunning: false}
	add := func(name string, ok bool, sev, detail, fix string) {
		out.Checks = append(out.Checks, ctl.Check{Name: name, OK: ok, Severity: sev, Detail: detail, Fix: fix})
	}
	stateDir := filepath.Join(c.dataDir, "state")
	running := false

	add("daemon running", false, ctl.SevError, "nothing is listening on "+c.socket, "sudo zaprctl start")
	add("root privileges", root,
		ctl.SevWarn, fmt.Sprintf("uid %d — diagnostics only; repairing needs root", os.Geteuid()),
		"sudo zaprctl doctor --repair")
	if loaded, err := launchd.Loaded(launchd.DefaultLabel); err == nil {
		add("launchd job", loaded, ctl.SevError,
			fmt.Sprintf("system/%s is %s", launchd.DefaultLabel, ifElse(loaded, "loaded", "not loaded")),
			"sudo make install")
	} else {
		add("launchd job", false, ctl.SevWarn, err.Error(), "run this as root")
	}
	for _, name := range []string{"strategies", "lists", "fakes"} {
		dir := c.findDir(name)
		add(name+" directory", dirHasFiles(dir), ctl.SevError, dir, "sudo make install")
	}
	if fi, err := os.Lstat(c.socket); err == nil && fi.Mode()&os.ModeSocket != 0 {
		add("stale control socket", false, ctl.SevWarn,
			fmt.Sprintf("%s exists (%s) but nobody answers", c.socket, fi.Mode()),
			"sudo zaprctl doctor --repair")
	}

	opts := diag.DoctorOpts{
		Anchor:            c.anchor,
		StateDir:          stateDir,
		UpstreamHostsPath: c.hostsSource(),
		DaemonRunning:     &running,
		// The capability probe needs root and makes real (reversible) pf and
		// utun changes; unprivileged it would only add noise, so skip it there.
		SkipDetect: !root,
		Detect:     diag.DetectOpts{Anchor: c.anchor},
	}
	findings, err := diag.Doctor(ctx, opts)
	if err != nil {
		add("system diagnostics", false, ctl.SevError, err.Error(), "")
	}
	for _, f := range findings {
		out.Checks = append(out.Checks, ctl.Check{
			Name: f.Title, OK: f.OK(), Severity: f.Severity, Detail: f.Detail, Fix: f.Fix,
		})
	}
	if j, jerr := netcfg.OpenJournal(stateDir); jerr == nil {
		out.JournalPath = j.Path()
		if entries, eerr := j.Entries(); eerr == nil {
			out.JournalPending = len(entries)
		}
		_ = j.Close()
	} else {
		add("rollback journal", false, ctl.SevWarn,
			fmt.Sprintf("cannot open the journal in %s: %v", stateDir, jerr), "sudo zaprctl doctor --repair")
	}

	if !repair {
		return out
	}
	if !root {
		out.Repaired = append(out.Repaired, "nothing: --repair needs root (sudo zaprctl doctor --repair)")
		return out
	}
	fixed, rerr := diag.Repair(ctx, opts)
	if rerr != nil {
		out.Repaired = append(out.Repaired, "repair failed: "+firstLine(rerr.Error()))
	}
	for _, f := range fixed {
		line := f.Title
		if f.Detail != "" {
			line += ": " + f.Detail
		}
		out.Repaired = append(out.Repaired, line)
	}
	// Removing a socket nobody is listening on is ours to do, not diag's: it
	// knows nothing about where our control socket lives.
	if fi, err := os.Lstat(c.socket); err == nil && fi.Mode()&os.ModeSocket != 0 {
		if err := os.Remove(c.socket); err == nil {
			out.Repaired = append(out.Repaired, "removed the stale socket "+c.socket)
		}
	}
	if len(out.Repaired) == 0 {
		out.Repaired = append(out.Repaired, "nothing needed repairing")
	}
	return out
}

// hostsSource locates flowseal's service/hosts, which the doctor compares the
// pinned /etc/hosts block against. An empty result disables the comparison.
func (c *cli) hostsSource() string {
	cands := []string{filepath.Join(c.dataDir, "hosts")}
	if exe, err := os.Executable(); err == nil {
		if r, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = r
		}
		d := filepath.Dir(exe)
		for _, base := range []string{d, filepath.Dir(d), filepath.Dir(filepath.Dir(d))} {
			cands = append(cands, filepath.Join(base, "hosts"), filepath.Join(base, ".upstream", "service", "hosts"))
		}
	}
	if wd, err := os.Getwd(); err == nil {
		cands = append(cands, filepath.Join(wd, "hosts"), filepath.Join(wd, ".upstream", "service", "hosts"))
	}
	for _, p := range cands {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Size() > 0 {
			return p
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

// cmdTest runs the connectivity self-test through the daemon, so the flows it
// creates go through the live datapath.
func (c *cli) cmdTest(ctx context.Context, args []string) int {
	strat := ""
	suite := "all"
	rest, code := c.parseCmd("test", "test [--suite all|discord] [--strategy X] [target...] [--json]", args, func(fs *flag.FlagSet) {
		fs.StringVar(&strat, "strategy", "", "activate this strategy first")
		fs.StringVar(&suite, "suite", "all", "probe suite: all or discord")
	})
	if code != parseContinue {
		return code
	}
	if os.Geteuid() == 0 {
		return c.fail(errors.New("test must run without sudo: the default pf rules exempt root traffic, so a root probe bypasses zapret; run `zaprctl test` as your user (the control socket grants access to the admin group)"))
	}
	// The probes MUST run in this process, not in the daemon.
	//
	// The steering ruleset carries `user { > root }` so root-owned traffic is
	// never intercepted (that is the loop breaker for our own injected packets).
	// A selftest executed inside the root daemon therefore measures the bare,
	// censored path and reports failures for endpoints that work perfectly in a
	// normal application — which is precisely what happened: the browser played
	// YouTube while this command called it blocked. Running here, as the
	// invoking user, measures what applications actually experience.
	if suite != "all" && suite != "discord" {
		return c.fail(fmt.Errorf("unknown test suite %q; use all or discord", suite))
	}
	if suite != "all" && len(rest) > 0 {
		return c.fail(errors.New("custom targets cannot be combined with --suite"))
	}
	data, err := c.selftestLocal(ctx, rest, strat, suite)
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		code := exitOK
		if !data.OK {
			code = exitError
		}
		_ = c.printJSON(data)
		return code
	}
	fmt.Fprintf(c.out, "connectivity self-test — strategy %s, transport %s\n\n",
		orNone(data.Strategy), orNone(data.Transport))
	t := newTable("", "TARGET", "MS", "DESYNC", "DETAIL")
	for _, r := range data.Targets {
		fired := "-"
		if r.Desynced {
			fired = "fired"
		}
		t.add(tag(r.OK, ctl.SevError), r.Target, fmt.Sprint(r.MS), fired, r.Detail)
	}
	t.render(c.out)
	if len(data.Warnings) > 0 {
		fmt.Fprintln(c.out)
		for _, w := range data.Warnings {
			fmt.Fprintf(c.out, "  ! %s\n", w)
		}
	}
	if data.OK {
		fmt.Fprintf(c.out, "\nall targets reachable\n")
		return exitOK
	}
	fmt.Fprintf(c.out, "\nsome targets failed — try another strategy (`zaprctl list`) or `zaprctl caps`\n")
	return exitError
}

// ---------------------------------------------------------------------------
// hosts / ipset
// ---------------------------------------------------------------------------

// cmdHosts applies or removes the /etc/hosts pinning block.
func (c *cli) cmdHosts(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("hosts", "hosts apply | remove [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if len(rest) == 0 {
		fmt.Fprintf(c.err, "zaprctl hosts: say `apply` or `remove`\n")
		return exitError
	}
	cl := c.client()
	var (
		data ctl.HostsData
		err  error
	)
	// Leading dashes are tolerated because internal/diag's own fix text says
	// `zaprctl hosts --apply`, and a user who copies a suggested command should
	// not be told it is wrong.
	switch strings.ToLower(strings.TrimLeft(rest[0], "-")) {
	case "apply", "add", "install":
		data, err = cl.HostsApply(ctx)
	case "remove", "rm", "delete", "uninstall":
		data, err = cl.HostsRemove(ctx)
	default:
		fmt.Fprintf(c.err, "zaprctl hosts: unknown action %q; use `apply` or `remove`\n", rest[0])
		return exitError
	}
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(data)
	}
	if data.Applied {
		fmt.Fprintf(c.out, "pinned %d entries (%d names) into %s\n", data.Entries, data.Names, data.Path)
		c.kv("source", "%s", data.SourcePath)
	} else {
		fmt.Fprintf(c.out, "removed our block from %s\n", data.Path)
	}
	c.kv("dns cache", "%s", ifElse(data.DNSFlushed, "flushed", "NOT flushed"))
	for _, w := range data.Warnings {
		fmt.Fprintf(c.out, "  ! %s\n", w)
	}
	return exitOK
}

// cmdIPSet reads or flips flowseal's tri-state ipset switch.
func (c *cli) cmdIPSet(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("ipset", "ipset [loaded|none|any] [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	mode := ""
	if len(rest) > 0 {
		mode = strings.ToLower(strings.TrimSpace(rest[0]))
		switch mode {
		case ctl.IPSetLoaded, ctl.IPSetNone, ctl.IPSetAny:
		default:
			fmt.Fprintf(c.err, "zaprctl ipset: unknown mode %q; use %s, %s or %s (or no argument to query)\n",
				mode, ctl.IPSetLoaded, ctl.IPSetNone, ctl.IPSetAny)
			return exitError
		}
	}
	data, err := c.client().IPSet(ctx, mode)
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(data)
	}
	if data.Previous != "" {
		fmt.Fprintf(c.out, "ipset filter: %s -> %s\n", data.Previous, data.Mode)
	} else {
		fmt.Fprintf(c.out, "ipset filter: %s\n", data.Mode)
	}
	c.kv("file", "%s (%d entries)", data.Path, data.Entries)
	c.kv("backup", "%s", ifElse(data.Backup, "present", "none"))
	if data.Reloaded {
		c.kv("strategy", "reloaded, the change is live")
	}
	fmt.Fprintf(c.out, `
  loaded  only the destinations in ipset-all.txt are desynced
  none    the list holds only %s, so ipset-gated profiles never match
  any     the list is empty, which zapret reads as "no ipset restriction"
`, ctl.IPSetSentinel)
	return exitOK
}

// ---------------------------------------------------------------------------
// logs / version
// ---------------------------------------------------------------------------

// logLine is one line of `zaprctl logs --json`: newline-delimited JSON objects,
// one per log line, so following a live stream stays parseable.
type logLine struct {
	Line string `json:"line"`
}

// cmdLogs tails the daemon's log: from its in-memory ring over the socket, or
// straight from the launchd-captured file with --file.
func (c *cli) cmdLogs(ctx context.Context, args []string) int {
	n, follow, file := 200, false, ""
	rest, code := c.parseCmd("logs", "logs [-n N] [-f] [--file PATH] [--json]", args, func(fs *flag.FlagSet) {
		fs.IntVar(&n, "n", 200, "how many recent lines to print")
		fs.BoolVar(&follow, "f", false, "keep streaming new lines")
		fs.StringVar(&file, "file", "", "read this log file directly instead of asking the daemon")
	})
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("logs", rest); code != parseContinue {
		return code
	}
	if file != "" {
		return c.tailFile(ctx, file, n, follow)
	}
	err := c.client().LogTail(ctx, ctl.LogTailOpts{Lines: n, Follow: follow}, c.emitLogLine)
	if err != nil {
		if ctl.IsNotRunning(err) {
			fmt.Fprintf(c.err, "zaprctl: the daemon is not running; its file log is %s\n",
				launchd.DefaultStdoutPath)
			fmt.Fprintf(c.err, "  zaprctl logs --file %s -n %d%s\n", launchd.DefaultStdoutPath, n, ifTrue(follow, " -f"))
			return exitNotRunning
		}
		return c.fail(err)
	}
	return exitOK
}

// emitLogLine prints one log line, as text or as one JSON object per line.
func (c *cli) emitLogLine(line string) error {
	if !c.json {
		_, err := fmt.Fprintln(c.out, line)
		return err
	}
	b, err := json.Marshal(logLine{Line: line})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.out, "%s\n", b)
	return err
}

// tailFile prints the last n lines of a file and, with follow, everything
// appended afterwards.
func (c *cli) tailFile(ctx context.Context, path string, n int, follow bool) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(c.err, "zaprctl: %v\n", err)
		return exitError
	}
	defer f.Close()

	// Read at most the last 1 MiB: a log can be arbitrarily large and the tail
	// is all anybody wants.
	const window = 1 << 20
	fi, err := f.Stat()
	if err != nil {
		fmt.Fprintf(c.err, "zaprctl: %v\n", err)
		return exitError
	}
	start := int64(0)
	if fi.Size() > window {
		start = fi.Size() - window
	}
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && len(buf) > 0 {
		// A short read at EOF is fine; anything else is not.
		if !errors.Is(err, io.EOF) {
			fmt.Fprintf(c.err, "zaprctl: read %s: %v\n", path, err)
			return exitError
		}
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // the first line is probably truncated
	}
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		if err := c.emitLogLine(l); err != nil {
			fmt.Fprintf(c.err, "zaprctl: %v\n", err)
			return exitError
		}
	}
	if !follow {
		return exitOK
	}
	off := fi.Size()
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	pending := ""
	for {
		select {
		case <-ctx.Done():
			return exitOK
		case <-tick.C:
		}
		st, err := f.Stat()
		if err != nil {
			fmt.Fprintf(c.err, "zaprctl: %v\n", err)
			return exitError
		}
		if st.Size() < off {
			// Rotated by newsyslog: start over from the new beginning.
			off = 0
		}
		if st.Size() == off {
			continue
		}
		chunk := make([]byte, st.Size()-off)
		read, rerr := f.ReadAt(chunk, off)
		if read > 0 {
			pending += string(chunk[:read])
			for {
				i := strings.IndexByte(pending, '\n')
				if i < 0 {
					break
				}
				if err := c.emitLogLine(pending[:i]); err != nil {
					fmt.Fprintf(c.err, "zaprctl: %v\n", err)
					return exitError
				}
				pending = pending[i+1:]
			}
			off += int64(read)
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			fmt.Fprintf(c.err, "zaprctl: read %s: %v\n", path, rerr)
			return exitError
		}
	}
}

// versionPayload is the shape of `zaprctl version --json`.
type versionPayload struct {
	Client        string           `json:"client"`
	Go            string           `json:"go"`
	DaemonRunning bool             `json:"daemon_running"`
	Daemon        *ctl.VersionData `json:"daemon,omitempty"`
}

// cmdVersion prints both versions, which is how a stale installed daemon is
// spotted after a rebuild. It exits with the "not running" code when there is no
// daemon to compare against, the same as every other query.
func (c *cli) cmdVersion(ctx context.Context, args []string) int {
	rest, code := c.parseCmd("version", "version [--json]", args, nil)
	if code != parseContinue {
		return code
	}
	if code := c.noArgs("version", rest); code != parseContinue {
		return code
	}
	v, err := c.client().Version(ctx)
	if err != nil {
		if !ctl.IsNotRunning(err) {
			return c.fail(err)
		}
		if c.json {
			_ = c.printJSON(versionPayload{Client: version, Go: goVersion(), DaemonRunning: false})
			return exitNotRunning
		}
		fmt.Fprintf(c.out, "zaprctl %s (%s)\nzapretd: not running\n", version, goVersion())
		return exitNotRunning
	}
	if c.json {
		return c.printJSON(versionPayload{Client: version, Go: goVersion(), DaemonRunning: true, Daemon: &v})
	}
	fmt.Fprintf(c.out, "zaprctl %s (%s)\n", version, goVersion())
	fmt.Fprintf(c.out, "zapretd %s (%s), pid %d, up since %s\n", v.Version, v.Go, v.PID, v.Started)
	if v.Binary != "" {
		c.kv("binary", "%s", v.Binary)
	}
	if v.Version != version {
		fmt.Fprintf(c.out, "\n  ! the running daemon is a different build than this CLI; restart it with\n"+
			"    sudo zaprctl restart\n")
	}
	return exitOK
}

// ---------------------------------------------------------------------------
// tiny helpers
// ---------------------------------------------------------------------------

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

func ifElse(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// cmdVPN inspects, stops or restores VPN software that holds a tunnel default
// route.
//
// It exists because that condition is the single most common reason the packet
// datapath cannot run, and because "just kill the VPN" is the wrong advice: a
// VPN client killed outright can leave routes, DNS settings and firewall rules
// behind, which is a worse state than the one it was in. The daemon therefore
// unloads the launchd job (letting the client tear its own tunnel down) and only
// signals processes with --force.
func (c *cli) cmdVPN(ctx context.Context, args []string) int {
	var force bool
	rest, code := c.parseCmd("vpn", "vpn [status|stop|start] [--force] [--json]", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&force, "force", false,
			"escalate to SIGTERM and SIGKILL when unloading the launchd job was not enough "+
				"(a killed VPN can leave routes and DNS behind)")
	})
	if code != parseContinue {
		return code
	}
	action := "status"
	if len(rest) > 0 {
		action = rest[0]
	}
	if len(rest) > 1 {
		fmt.Fprintf(c.err, "zaprctl vpn: unexpected argument %q\n", rest[1])
		return exitError
	}
	switch action {
	case "status", "stop", "start":
	default:
		fmt.Fprintf(c.err, "zaprctl vpn: unknown action %q; use status, stop or start\n", action)
		return exitError
	}

	v, err := c.client().VPN(ctx, action, force)
	// The detection half needs no daemon and no root, and the stop half only
	// needs root — so when there is no daemon (or it predates this command),
	// do the work here instead of making the user install something first.
	if err != nil && (ctl.IsNotRunning(err) || strings.Contains(err.Error(), "unknown command")) {
		v, err = c.vpnLocal(ctx, action, force)
	}
	if err != nil {
		// A detection-only run must still print what it found, because the error
		// is usually "the tunnel is still up", and the findings say why.
		if action == "status" || len(v.Providers) == 0 {
			return c.fail(err)
		}
		c.printVPN(v)
		fmt.Fprintf(c.err, "zaprctl vpn: %v\n", err)
		return exitError
	}
	if c.json {
		return c.printJSON(v)
	}
	c.printVPN(v)
	return exitOK
}

// printVPN renders the VPN report.
func (c *cli) printVPN(v ctl.VPNData) {
	if len(v.Providers) == 0 && len(v.TunnelDefaults) == 0 {
		fmt.Fprintln(c.out, "no VPN software detected and no tunnel holds a default route")
		return
	}
	for _, p := range v.Providers {
		fmt.Fprintf(c.out, "%s\n", p.Name)
		if p.AppRunning {
			fmt.Fprintf(c.out, "  app        running\n")
		}
		for _, j := range p.Jobs {
			fmt.Fprintf(c.out, "  launchd    %s\n", j)
		}
		if len(p.PIDs) > 0 {
			fmt.Fprintf(c.out, "  processes  %v\n", p.PIDs)
		}
	}
	if len(v.TunnelDefaults) > 0 {
		fmt.Fprintf(c.out, "\ntunnel default route: %s — zapret needs split-routing mode while this is held\n",
			strings.Join(v.TunnelDefaults, ", "))
	} else {
		fmt.Fprintln(c.out, "\nno tunnel holds a default route — the packet datapath can run")
	}
	for _, u := range v.Unattributed {
		fmt.Fprintf(c.out, "  ! %s is not recognised as any known VPN, so it will never be touched automatically\n", u)
	}
	for _, a := range v.Actions {
		fmt.Fprintf(c.out, "  + %s\n", a)
	}
	if len(v.Restore) > 0 {
		fmt.Fprintln(c.out, "\nto bring it back:")
		fmt.Fprintln(c.out, "  sudo zaprctl vpn start")
		for _, r := range v.Restore {
			fmt.Fprintf(c.out, "  (or: %s)\n", r)
		}
	}
}

// vpnLocal answers the vpn command without a daemon.
//
// Detection is unprivileged; stopping needs root because it unloads a system
// launchd job, so that path says exactly which command to re-run under sudo
// rather than failing obscurely deep inside launchctl.
func (c *cli) vpnLocal(ctx context.Context, action string, force bool) (ctl.VPNData, error) {
	rep, err := vpn.Detect(localTunnelDefaults)
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
	case "status", "":
		return out, nil
	case "stop", "start":
		if os.Geteuid() != 0 {
			return out, fmt.Errorf("stopping a system VPN needs root and no daemon is running: sudo %s",
				strings.Join(append([]string{"zaprctl", "vpn", action}, boolFlag("--force", force)...), " "))
		}
		state := filepath.Join(c.dataDir, "vpn-stopped.json")
		if action == "start" {
			res, serr := vpn.Start(ctx, state)
			out.Actions = res.Stopped
			return out, serr
		}
		res, serr := vpn.Stop(ctx, rep, localTunnelDefaults, vpn.StopOpts{
			Force: force, StateFile: state,
			Logf: func(f string, a ...any) { fmt.Fprintf(c.err, "  "+f+"\n", a...) },
		})
		out.Actions, out.Restore = res.Stopped, res.Restore
		out.TunnelDefaults, out.Blocking = res.Remaining, len(res.Remaining) > 0
		return out, serr
	}
	return out, fmt.Errorf("unknown vpn action %q", action)
}

// boolFlag renders a flag only when it is set, for building a retry command.
func boolFlag(name string, on bool) []string {
	if on {
		return []string{name}
	}
	return nil
}

// localTunnelDefaults lists tunnel interfaces holding an IPv4 default route.
func localTunnelDefaults() ([]string, error) {
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

// cmdRouter generates routing policy for the VPN client detected on the target
// machine. Happ is the only supported routing-profile adapter.
func (c *cli) cmdRouter(ctx context.Context, args []string) int {
	var install bool
	var output string
	rest, code := c.parseCmd("router", "router happ [--install] [--output FILE] [--json]", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&install, "install", false, "open the generated profile in Happ and make it active")
		fs.StringVar(&output, "output", "", "also write the readable JSON profile to FILE")
	})
	if code != parseContinue {
		return code
	}
	if len(rest) != 1 {
		return c.fail(fmt.Errorf("usage: zaprctl router happ"))
	}
	client := strings.ToLower(rest[0])
	if client != "happ" {
		return c.fail(fmt.Errorf("router: client %q is not supported; this router is available only for Happ (use `zaprctl router happ`)", rest[0]))
	}
	if !happConnected() && install {
		return c.fail(errors.New("router happ: Happ is not connected; connect the Happ profile first, then retry (or omit --install to only print/save the profile)"))
	}

	profile, err := c.happProfile()
	if err != nil {
		return c.fail(err)
	}
	body, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return c.fail(err)
	}
	body = append(body, '\n')
	link := "happ://routing/onadd/" + base64.StdEncoding.EncodeToString(body)

	if output != "" {
		if err := os.WriteFile(output, body, 0o600); err != nil {
			return c.fail(fmt.Errorf("write Happ profile %s: %w", output, err))
		}
	}
	if install {
		if err := exec.CommandContext(ctx, "/usr/bin/open", link).Run(); err != nil {
			return c.fail(fmt.Errorf("open Happ routing profile: %w", err))
		}
	}
	if c.json {
		return c.printJSON(struct {
			Profile   happRoutingProfile `json:"profile"`
			DeepLink  string             `json:"deep_link"`
			Installed bool               `json:"opened_in_happ"`
		}{profile, link, install})
	}
	if output != "" {
		fmt.Fprintf(c.out, "Happ routing profile written to %s\n", output)
	}
	if install {
		fmt.Fprintln(c.out, "Happ profile opened: Russia and zapret hostlists are Direct; every other destination stays Proxy.")
		fmt.Fprintln(c.out, "Accept the profile in Happ, then reconnect the VPN once so the new routing takes effect.")
		return exitOK
	}
	fmt.Fprintln(c.out, link)
	fmt.Fprintln(c.out, "\nOpen this link in Happ, activate the profile, then reconnect the VPN.")
	return exitOK
}

const happAgentLabel = "io.zapretmac.happ-agent"

func (c *cli) cmdAutostart(ctx context.Context, args []string) int {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}
	if len(args) > 1 || (action != "install" && action != "remove" && action != "status") {
		return c.fail(errors.New("usage: zaprctl autostart install|remove|status"))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return c.fail(err)
	}
	path := filepath.Join(home, "Library", "LaunchAgents", happAgentLabel+".plist")
	domain := "gui/" + strconv.Itoa(os.Getuid())
	switch action {
	case "status":
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", domain+"/"+happAgentLabel).CombinedOutput()
		if err != nil {
			fmt.Fprintf(c.out, "Happ autostart: disabled (%s)\n", strings.TrimSpace(string(out)))
			return exitOK
		}
		fmt.Fprintln(c.out, "Happ autostart: enabled")
		return exitOK
	case "remove":
		_, _ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", domain+"/"+happAgentLabel).CombinedOutput()
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return c.fail(err)
		}
		fmt.Fprintln(c.out, "Happ autostart removed")
		return exitOK
	case "install":
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return c.fail(err)
		}
		program, err := os.Executable()
		if err != nil {
			return c.fail(err)
		}
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>%s</string><string>happ-agent</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>%s</string>
<key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, happAgentLabel, xmlEscape(program), filepath.Join(home, "Library", "Logs", "zapret-happ-agent.log"), filepath.Join(home, "Library", "Logs", "zapret-happ-agent.err.log"))
		if err := os.WriteFile(path, []byte(plist), 0o600); err != nil {
			return c.fail(err)
		}
		_, _ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", domain+"/"+happAgentLabel).CombinedOutput()
		if out, err := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", domain, path).CombinedOutput(); err != nil {
			return c.fail(fmt.Errorf("bootstrap Happ agent: %s: %w", strings.TrimSpace(string(out)), err))
		}
		fmt.Fprintln(c.out, "Happ autostart installed: VPN launch and routing refresh enabled")
		return exitOK
	}
	return exitOK
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return strings.ReplaceAll(s, "'", "&apos;")
}

func (c *cli) cmdHappAgent(ctx context.Context) int {
	_ = exec.CommandContext(ctx, "/usr/bin/open", "-a", "Happ").Run()
	var last [32]byte
	for {
		profile, err := c.happProfile()
		if err == nil {
			body, _ := json.Marshal(profile)
			h := sha256.Sum256(body)
			if h != last {
				if link, lerr := happLink(profile); lerr == nil {
					_ = exec.CommandContext(ctx, "/usr/bin/open", link).Run()
					last = h
				}
			}
		}
		if !happConnected() {
			startLastHappService(ctx)
		}
		select {
		case <-ctx.Done():
			return exitOK
		case <-time.After(10 * time.Second):
		}
	}
}

func startLastHappService(ctx context.Context) {
	b, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--nc", "list").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, "su.ffg.happ") {
			continue
		}
		name := happServiceName(line)
		if name != "" {
			_, _ = exec.CommandContext(ctx, "/usr/sbin/scutil", "--nc", "start", name).CombinedOutput()
		}
		return
	}
}

func happServiceName(line string) string {
	if !strings.Contains(line, "su.ffg.happ") {
		return ""
	}
	parts := strings.SplitN(line, "\"", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

// cmdProbe is the single user-facing entry point for the reversible machine
// capability test. The implementation lives in probe.go so the repository no
// longer installs a second capability-probe application.
func (c *cli) cmdProbe(args []string) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(c.err, "zaprctl probe: needs root; retry with: sudo zaprctl probe")
		return exitDenied
	}
	runEmbeddedProbe(args)
	return exitOK // runEmbeddedProbe exits after emitting its report
}

// happConnected checks the service state and the actual Network Extension.
// scutil can report (Disconnected) while Happ's Tunnel.appex still owns a
// default route, so neither the service listing nor a utun alone is enough.
func happConnected() bool {
	b, err := exec.Command("/usr/sbin/scutil", "--nc", "list").Output()
	if err == nil && happServiceConnected(string(b)) {
		return true
	}
	rep, err := vpn.Detect(localTunnelDefaults)
	if err != nil || len(rep.TunnelDefaults) == 0 {
		return false
	}
	for _, f := range rep.Findings {
		if f.Provider != "Happ" {
			continue
		}
		for _, p := range f.Processes {
			if strings.Contains(p.Path, "/Happ.app/Contents/PlugIns/Tunnel.appex/") {
				return true
			}
		}
	}
	return false
}

func happServiceConnected(list string) bool {
	for _, line := range strings.Split(list, "\n") {
		if strings.Contains(line, "su.ffg.happ") &&
			(strings.Contains(line, "(Connected)") || strings.Contains(line, "(Connecting)")) {
			return true
		}
	}
	return false
}

func (c *cli) happProfile() (happRoutingProfile, error) {
	domains, err := readRouteDomains(c.findDir("lists"),
		"list-general.txt", "list-google.txt", "list-general-user.txt",
		"list-exclude.txt", "list-exclude-user.txt", "list-vk.txt")
	if err != nil {
		return happRoutingProfile{}, err
	}
	directSites := []string{"geosite:tld-ru", "geosite:category-ru"}
	for _, domain := range domains {
		directSites = append(directSites, "domain:"+domain)
	}
	return happRoutingProfile{
		Name:              "zapret-mac: RU + domestic services direct + RKN bypass",
		GlobalProxy:       "true",
		RemoteDNSType:     "DoH",
		RemoteDNSDomain:   "https://cloudflare-dns.com/dns-query",
		RemoteDNSIP:       "1.1.1.1",
		DomesticDNSType:   "DoH",
		DomesticDNSDomain: "https://dns.google/dns-query",
		DomesticDNSIP:     "8.8.8.8",
		GeoIPURL:          "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
		GeoSiteURL:        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
		DNSHosts:          map[string]string{"cloudflare-dns.com": "1.1.1.1", "dns.google": "8.8.8.8"},
		DirectSites:       directSites,
		DirectIP: []string{"geoip:ru", "geoip:private", "10.0.0.0/8", "172.16.0.0/12",
			"192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"},
		ProxySites:     []string{},
		ProxyIP:        []string{},
		BlockSites:     []string{},
		BlockIP:        []string{},
		DomainStrategy: "IPIfNonMatch",
		FakeDNS:        "false",
		RouteOrder:     "direct-block-proxy",
	}, nil
}

func happLink(profile happRoutingProfile) (string, error) {
	body, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return "", err
	}
	return "happ://routing/onadd/" + base64.StdEncoding.EncodeToString(append(body, '\n')), nil
}

func readRouteDomains(dir string, names ...string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for _, name := range names {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && strings.HasSuffix(name, "-user.txt") {
				continue
			}
			return nil, fmt.Errorf("read routing hostlist %s: %w", path, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			host := strings.ToLower(strings.Trim(strings.TrimSpace(line), "."))
			if host == "" || strings.ContainsAny(host, " /\\\t") || seen[host] {
				continue
			}
			seen[host] = true
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out, nil
}

// cmdAutopick sweeps the installed strategies and leaves the best one running.
//
// This is the macOS answer to the Windows ritual of double-clicking one .bat
// after another: DPI behaviour differs per ISP and per point in time, so which
// strategy works is an empirical question. The picker activates each candidate,
// measures it against a short probe set, ranks by (targets passed, median
// first-byte latency) and stops early on a perfect score.
func (c *cli) cmdAutopick(ctx context.Context, args []string) int {
	var (
		dryRun    bool
		maxCand   int
		skipUnsup bool
		noEarly   bool
		suite     string
		rounds    int
	)
	rest, code := c.parseCmd("autopick", "autopick [--suite all|discord] [--rounds N] [--dry-run] [--max N] [--skip-unsupported] [--no-early-stop] [--json]",
		args, func(fs *flag.FlagSet) {
			fs.StringVar(&suite, "suite", "all", "probe suite: all or discord")
			fs.IntVar(&rounds, "rounds", 1, "repeat each candidate's probe set N times (1-10)")
			fs.BoolVar(&dryRun, "dry-run", false, "only report which strategies the active transport fully supports")
			fs.IntVar(&maxCand, "max", 0, "test at most N strategies (0 = all)")
			fs.BoolVar(&skipUnsup, "skip-unsupported", false,
				"skip strategies the transport cannot fully honour instead of measuring them anyway")
			fs.BoolVar(&noEarly, "no-early-stop", false, "keep testing after a candidate scores perfectly")
		})
	if code != parseContinue {
		return code
	}
	if os.Geteuid() == 0 && !dryRun {
		return c.fail(errors.New("autopick must run without sudo: the default pf rules exempt root traffic, so root probes cannot rank zapret strategies; run `zaprctl autopick` as your user (the control socket grants access to the admin group)"))
	}
	if code := c.noArgs("autopick", rest); code != parseContinue {
		return code
	}
	if suite != "all" && suite != "discord" {
		return c.fail(fmt.Errorf("unknown autopick suite %q; use all or discord", suite))
	}
	if rounds < 1 || rounds > 10 {
		return c.fail(fmt.Errorf("--rounds must be between 1 and 10, got %d", rounds))
	}

	cl := c.client().WithTimeout(2 * time.Minute)
	st, err := cl.Status(ctx)
	if err != nil {
		return c.fail(err)
	}
	caps := capsFrom(st.Caps)

	opts := diag.PickOpts{
		StrategyDir: c.findDir("strategies"),
		LoadOpts: strategy.LoadOpts{
			ListsDir: c.findDir("lists"),
			FakesDir: c.findDir("fakes"),
			Caps:     caps,
		},
		Caps:            caps,
		MaxCandidates:   maxCand,
		SkipUnsupported: skipUnsup,
		NoEarlyStop:     noEarly,
		DryRun:          dryRun,
		Rounds:          rounds,
		Logf:            func(f string, a ...any) { fmt.Fprintf(c.err, "  "+f+"\n", a...) },
		Client: diag.ClientFuncs{
			ActivateFn: func(ctx context.Context, name string) error {
				_, err := cl.Use(ctx, name)
				return err
			},
			ActiveFn: func(ctx context.Context) (string, error) {
				s, err := cl.Status(ctx)
				return s.Strategy, err
			},
		},
	}
	if suite == "discord" {
		opts.Probes = diag.DiscordPickProbes()
		opts.Run = diag.RunOpts{Concurrency: 2, Timeout: 6 * time.Second}
	}

	res, err := diag.Pick(ctx, opts)
	if err != nil {
		return c.fail(err)
	}
	if c.json {
		return c.printJSON(res)
	}

	fmt.Fprintf(c.out, "autopick — suite %s, transport %s, %d candidate(s) measured\n\n", suite, st.Transport, res.Tested)
	fmt.Fprintf(c.out, "  %-28s %-8s %-9s %s\n", "STRATEGY", "PASSED", "MEDIAN", "NOTE")
	for _, cand := range res.Ranked {
		note := ""
		switch {
		case cand.BreaksTraffic:
			note = "BREAKS TRAFFIC — controls failed with it active and recovered without it"
		case cand.Skipped != "":
			note = cand.Skipped
		case len(cand.Unsupported) > 0:
			note = "degraded: " + strings.Join(cand.Unsupported, ", ")
		}
		median := "-"
		if cand.Score.MedianFirstByte > 0 {
			median = cand.Score.MedianFirstByte.Round(time.Millisecond).String()
		}
		marker := " "
		if cand.Name == res.Best {
			marker = "*"
		}
		fmt.Fprintf(c.out, "%s %-28s %d/%-6d %-9s %s\n", marker, cand.Name,
			cand.Score.Passed, cand.Score.Targets, median, note)
	}

	fmt.Fprintln(c.out)
	switch {
	case res.DryRun:
		fmt.Fprintln(c.out, "dry run: nothing was activated")
	case res.Best == "":
		fmt.Fprintf(c.out, "no strategy passed a single target probe; restored %q\n", res.Original)
		fmt.Fprintln(c.out, "that usually means the block is not TCP-DPI: check `zaprctl doctor` for DNS poisoning,")
		fmt.Fprintln(c.out, "and confirm the same targets fail with the datapath stopped (`sudo zaprctl stop`)")
		return exitError
	default:
		fmt.Fprintf(c.out, "best: %s (%d/%d targets)%s — now active\n", res.Best,
			res.BestScore.Passed, res.BestScore.Targets, earlyStopNote(res.StoppedEarly))
		if suite == "discord" {
			fmt.Fprintln(c.out, "verify with: zaprctl test --suite discord")
		} else {
			fmt.Fprintln(c.out, "verify with: zaprctl test")
		}
	}
	return exitOK
}

func earlyStopNote(early bool) string {
	if early {
		return ", stopped early on a perfect score"
	}
	return ""
}

// selftestLocal runs the probe set in the CLI process, so the traffic traverses
// the datapath exactly like an ordinary application's would.
//
// The daemon is still consulted, for two things only: switching strategy when
// --strategy was given, and reporting which strategy/transport is live so the
// output says what was measured. When no daemon answers, the probes still run
// and the report simply says so — a bare-path measurement is a useful baseline.
func (c *cli) selftestLocal(ctx context.Context, targets []string, strat, suite string) (ctl.SelftestData, error) {
	var out ctl.SelftestData

	cl := c.client()
	if strat != "" {
		if _, err := cl.Use(ctx, strat); err != nil {
			return out, fmt.Errorf("cannot activate %q for the test: %w", strat, err)
		}
	}
	if st, err := cl.Status(ctx); err == nil {
		out.Strategy, out.Transport = st.Strategy, st.Transport
		out.Warnings = append(out.Warnings, st.Warnings...)
		if !st.Running {
			out.Warnings = append(out.Warnings,
				"the datapath is not running, so this measures the bare path")
		}
	} else if ctl.IsNotRunning(err) {
		out.Warnings = append(out.Warnings,
			"no daemon is running, so this measures the bare path (a baseline, not the bypass)")
	} else {
		return out, err
	}

	probes := diag.DefaultProbes()
	if suite == "discord" {
		probes = diag.DiscordProbes()
	}
	if len(targets) > 0 {
		var custom []diag.Probe
		for _, t := range targets {
			p, err := probeFromTarget(t)
			if err != nil {
				return out, err
			}
			custom = append(custom, p)
		}
		probes = custom
	}

	results, err := diag.Run(ctx, probes, diag.RunOpts{})
	if err != nil {
		return out, err
	}
	blocked := 0
	failed := 0
	for _, r := range results {
		tt := ctl.TestTarget{
			Target: r.Name, OK: r.OK, MS: r.FirstByteTime.Milliseconds(),
			SNI: r.SNI, Detail: probeDetail(r),
		}
		out.Targets = append(out.Targets, tt)
		if !r.OK {
			failed++
			// A DPI signature is what separates censorship from a dead link:
			// a timeout or an injected reset on a name that resolves fine.
			if diag.Blocked(r.Class) {
				blocked++
			}
		}
	}
	out.OK = failed == 0
	if failed > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%d/%d probes failed, %d with a DPI signature (timeout, injected RST, broken handshake)",
			failed, len(results), blocked))
	}
	return out, nil
}

// probeFromTarget turns a "host" or "host:port" argument into a probe.
func probeFromTarget(t string) (diag.Probe, error) {
	host := strings.TrimSpace(t)
	if host == "" {
		return diag.Probe{}, fmt.Errorf("empty target")
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return diag.Probe{Name: host, URL: "https://" + host + "/", Expect: 0}, nil
}

// probeDetail renders one probe result compactly, without repeating the target
// name the table already prints.
func probeDetail(r diag.Result) string {
	var parts []string
	if r.Kind == "stun" && r.OK {
		parts = append(parts, "STUN binding response")
	}
	if r.Kind == "wss" && r.OK {
		parts = append(parts, "WebSocket upgraded")
	}
	if r.Status != 0 {
		parts = append(parts, fmt.Sprintf("HTTP %d", r.Status))
	}
	if r.TLSVersion != "" {
		v := r.TLSVersion
		if r.ALPN != "" {
			v += "/" + r.ALPN
		}
		parts = append(parts, v)
	}
	if r.TLSTime > 0 {
		parts = append(parts, "tls "+r.TLSTime.Round(time.Millisecond).String())
	}
	if r.BytesPerSec > 0 {
		parts = append(parts, fmt.Sprintf("%.0f KiB/s", r.BytesPerSec/1024))
	}
	if r.ServerIP != "" {
		parts = append(parts, "via "+r.ServerIP)
	}
	if !r.OK {
		reason := r.Class
		if r.Err != "" {
			reason += ": " + r.Err
		}
		parts = append(parts, reason)
	}
	if r.Control {
		parts = append(parts, "control endpoint")
	}
	return strings.Join(parts, ", ")
}
