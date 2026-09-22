package netcfg

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// /etc/pf.conf anchor statements
//
// A top-level pf anchor is dead weight unless the main ruleset names it, and on
// macOS the main ruleset is /etc/pf.conf, which ships only the com.apple
// anchors plus a `load anchor` line. So exactly one edit to a system file is
// unavoidable — the same edit zapret's own common/pf.sh performs on macOS:
//
//	sed -i '' -e '/^rdr-anchor "com\.apple\/\*"$/i rdr-anchor "zapret"'
//	sed -i '' -e '/^anchor "com\.apple\/\*"$/i anchor "zapret"'
//
// Note that upstream performs TWO separate insertions, and it has to: macOS pf
// is the old OpenBSD grammar and enforces a strict section order (options,
// normalization, queueing, translation, filtering). A single contiguous block
// containing both `rdr-anchor` (translation) and `anchor` (filtering) placed
// above `scrub-anchor "com.apple/*"` is rejected outright — verified on this
// machine:
//
//	/tmp/t1.conf:3: Rules must be in order: options, normalization, queueing,
//	                translation, filtering
//
// We therefore emit two marker-delimited blocks that share the same marker
// text: the rdr-anchor goes at the head of the translation section (ahead of
// com.apple's, because old-grammar translation rules are first-match-wins) and
// the filter anchor goes at the head of the filter section (ahead of
// `anchor "com.apple/*"`, so that a `quick` rule of ours is always reached).
// ---------------------------------------------------------------------------

// maxMarkerBlockLines bounds how far the stripper will look for a closing
// marker. A block we wrote is 3-4 lines; refusing to scan further means a
// corrupted/orphaned opening marker can never swallow foreign configuration.
const maxMarkerBlockLines = 8

// markerBegin and markerEnd delimit the block netcfg inserts into a system
// configuration file. The anchor name is embedded so two zapret-mac
// installations with different anchor names cannot clobber each other.
func markerBegin(name string) string { return "# >>> " + name + " >>>" }
func markerEnd(name string) string   { return "# <<< " + name + " <<<" }

// reTranslationLine matches the first line of pf's translation section:
// nat/rdr/binat rules and their anchor forms. Anchored at ^ so it can never
// match `scrub-anchor` or `dummynet-anchor`, and the keyword must be followed by
// whitespace or end of line for the same reason as reFilterLine.
var reTranslationLine = regexp.MustCompile(`^(nat|rdr|binat)(-anchor)?([ \t]|$)`)

// reFilterLine matches the first line of pf's filter section.
//
// The keyword must be followed by whitespace or end of line, NOT merely a word
// boundary: `\b` also matches before '-', so `pass-through = "{ 80 }"` — a
// perfectly ordinary pf macro — used to be taken for the start of the filter
// section, and both statements were then inserted above it (and above any
// options statement), which a stricter ruleset rejects outright.
var reFilterLine = regexp.MustCompile(`^(anchor|pass|block|antispoof)([ \t]|$)`)

// reMacroLine matches a pf macro definition (`name = value`). A macro is never
// part of the ordered rule sequence, so it can never be a section boundary.
var reMacroLine = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*[ \t]*=`)

// reAnchorStatement extracts the anchor name from any anchor statement,
// including the typed forms. `load anchor "x" from "y"` deliberately does not
// match: it is not part of the ordered rule sequence.
var reAnchorStatement = regexp.MustCompile(`^(?:(?:nat|rdr|binat|scrub|dummynet)-)?anchor\s+"([^"]+)"`)

// pfConfPlan is the outcome of planning an /etc/pf.conf patch.
type pfConfPlan struct {
	// Content is the file as it should end up. Equal to the input when no
	// change is needed.
	Content []byte
	// Changed reports whether Content differs from the input.
	Changed bool
	// Note describes what was done, for the log.
	Note string
}

// planPfConf computes the patched form of a main pf configuration file.
//
// It is pure and total: it first strips every trace of our own statements
// (marker blocks and bare `anchor "<name>"` / `rdr-anchor "<name>"` lines),
// then re-inserts them at grammatically legal positions. That makes the
// operation idempotent AND self-repairing — a half-applied patch from a crashed
// run converges to the correct shape. Foreign lines are never reordered,
// rewritten or removed.
func planPfConf(orig []byte, anchor string) pfConfPlan {
	lines, _ := splitLines(orig)
	base, removed := stripOurStatements(lines, anchor)

	transIdx, filterIdx := sectionInsertPoints(base)

	var out []string
	emitted := false
	for i, line := range base {
		if transIdx >= 0 && i == transIdx && filterIdx == transIdx {
			// Both statements land at the same point: one block, rdr first.
			out = append(out, markerBegin(anchor),
				`rdr-anchor "`+anchor+`"`,
				`anchor "`+anchor+`"`,
				markerEnd(anchor))
			emitted = true
		} else {
			if transIdx >= 0 && i == transIdx {
				out = append(out, markerBegin(anchor),
					`rdr-anchor "`+anchor+`"`,
					markerEnd(anchor))
				emitted = true
			}
			if filterIdx >= 0 && i == filterIdx {
				out = append(out, markerBegin(anchor),
					`anchor "`+anchor+`"`,
					markerEnd(anchor))
				emitted = true
			}
		}
		out = append(out, line)
	}
	if !emitted {
		// No recognisable translation or filter section: append at the end,
		// translation before filtering so the section order still holds.
		out = append(out, markerBegin(anchor),
			`rdr-anchor "`+anchor+`"`,
			`anchor "`+anchor+`"`,
			markerEnd(anchor))
	}

	// ALWAYS terminate the file. pfctl cannot parse a main ruleset whose last
	// line has no newline ("b.conf:1: syntax error"), so faithfully preserving a
	// missing final byte would make our own candidate fail checkCandidate, turn
	// EnsureAnchorStatements into a hard error, and leave launchd crash-looping
	// the daemon every 10 seconds. Adding one byte is the same documented
	// exception the hosts patcher already takes.
	content := joinLines(out, true)
	plan := pfConfPlan{Content: content, Changed: !bytesEqual(content, orig)}
	switch {
	case !plan.Changed:
		plan.Note = "already patched"
	case removed > 0:
		plan.Note = fmt.Sprintf("re-applied anchor statements (%d stale line(s) replaced)", removed)
	default:
		plan.Note = "inserted anchor statements"
	}
	return plan
}

// planPfConfRemoval computes the file with only our own statements taken out.
//
// Like planPfConf it terminates the file, because a pf.conf without a final
// newline does not parse and checkCandidate would reject the removal.
func planPfConfRemoval(orig []byte, anchor string) pfConfPlan {
	lines, _ := splitLines(orig)
	base, removed := stripOurStatements(lines, anchor)
	content := joinLines(base, len(base) > 0)
	return pfConfPlan{
		Content: content,
		Changed: !bytesEqual(content, orig),
		Note:    fmt.Sprintf("removed %d line(s)", removed),
	}
}

// stripOurStatements removes our marker blocks and any bare anchor statement
// naming our anchor, returning the surviving lines and how many were dropped.
//
// An opening marker with no closing marker within maxMarkerBlockLines drops
// only the marker line itself: a truncated write must never be able to delete
// unrelated configuration.
func stripOurStatements(lines []string, anchor string) ([]string, int) {
	begin := markerBegin(anchor)
	end := markerEnd(anchor)
	stmtFilter := `anchor "` + anchor + `"`
	stmtRdr := `rdr-anchor "` + anchor + `"`

	out := make([]string, 0, len(lines))
	removed := 0
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == begin {
			closeAt := -1
			for j := i + 1; j < len(lines) && j <= i+maxMarkerBlockLines; j++ {
				if strings.TrimSpace(lines[j]) == end {
					closeAt = j
					break
				}
			}
			if closeAt >= 0 {
				removed += closeAt - i + 1
				i = closeAt
				continue
			}
			removed++
			continue
		}
		if t == end {
			// Orphaned closing marker.
			removed++
			continue
		}
		if t == stmtFilter || t == stmtRdr {
			removed++
			continue
		}
		out = append(out, lines[i])
	}
	return out, removed
}

// sectionInsertPoints returns the line indices at which the translation and
// filter statements must be inserted. Either may be -1 when the corresponding
// section is absent.
func sectionInsertPoints(lines []string) (transIdx, filterIdx int) {
	transIdx, filterIdx = -1, -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if reMacroLine.MatchString(t) {
			// `pass-through = "{ 80 }"` is a macro, not a rule.
			continue
		}
		if transIdx < 0 && reTranslationLine.MatchString(t) {
			transIdx = i
		}
		if filterIdx < 0 && reFilterLine.MatchString(t) {
			filterIdx = i
		}
		if transIdx >= 0 && filterIdx >= 0 {
			break
		}
	}
	switch {
	case filterIdx < 0 && transIdx < 0:
		// Nothing recognisable; caller appends.
	case filterIdx < 0:
		// Translation section only: put the filter anchor right after the
		// translation one so the order still holds.
		filterIdx = transIdx
	case transIdx < 0 || transIdx > filterIdx:
		// A filter line precedes every translation line (or there are none):
		// both statements go at the filter boundary, translation first.
		transIdx = filterIdx
	}
	return transIdx, filterIdx
}

// AnchorStatementsPresent reports whether text (the content of a main pf
// configuration file) already contains both statements needed for the named
// anchor to be evaluated.
func AnchorStatementsPresent(text []byte, anchor string) bool {
	haveFilter, haveRdr := false, false
	stmtFilter := `anchor "` + anchor + `"`
	stmtRdr := `rdr-anchor "` + anchor + `"`
	for _, line := range strings.Split(string(text), "\n") {
		switch strings.TrimSpace(line) {
		case stmtFilter:
			haveFilter = true
		case stmtRdr:
			haveRdr = true
		}
	}
	return haveFilter && haveRdr
}

// WildcardAnchorCovers reports whether text (a pf.conf, or the output of
// `pfctl -s rules` / `-s nat`) declares a WILDCARD anchor point whose path
// covers sub.
//
// A trailing /* on an anchor path means pf evaluates every sub-anchor nested
// there, and loading rules into a sub-anchor is what creates it. That is what
// lets us install rules without editing /etc/pf.conf: a stock file already
// carries `anchor "com.apple/*"` and `rdr-anchor "com.apple/*"`, so
// "com.apple/zapret-mac" is evaluated the moment it holds rules.
func WildcardAnchorCovers(text, sub string) bool {
	for _, line := range strings.Split(text, "\n") {
		m := reAnchorStatement.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		path := m[1]
		if !strings.HasSuffix(path, "/*") {
			continue
		}
		if strings.HasPrefix(sub, strings.TrimSuffix(path, "*")) {
			return true
		}
	}
	return false
}

// AnchorNames lists every anchor named by an anchor statement in text, in file
// order and without duplicates. Used by Preflight to spot another bypass tool
// or VPN that already owns rules in the main ruleset.
func AnchorNames(text []byte) []string {
	var out []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(text), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		m := reAnchorStatement.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}

// ---------------------------------------------------------------------------
// rule generation — pure, side-effect free, unit-testable
// ---------------------------------------------------------------------------

// PortRange is an inclusive TCP/UDP port range expressed as {lo, hi}. It
// deliberately mirrors strategy.PortRange's shape without importing that
// package, so rule generation stays dependency-free and testable in isolation.
// Convert a strategy.PortSet with:
//
//	pairs := make([][2]uint16, len(ps))
//	for i, r := range ps { pairs[i] = [2]uint16{r.Lo, r.Hi} }
type PortRange = [2]uint16

// FormatPorts renders port ranges as a pf port list, e.g.
// "{ 80 443 19294:19344 }". It returns "" for an empty set, which callers must
// treat as "emit no rule" rather than "match any port".
//
// pf's range separator inside a list is a colon, not a dash: `19294:19344`.
// Order is preserved (flowseal's windows are written in a deliberate order) and
// a reversed pair is normalised by swapping.
func FormatPorts(ranges []PortRange) string {
	if len(ranges) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("{")
	for _, r := range ranges {
		lo, hi := r[0], r[1]
		if lo > hi {
			lo, hi = hi, lo
		}
		sb.WriteByte(' ')
		sb.WriteString(strconv.FormatUint(uint64(lo), 10))
		if hi != lo {
			sb.WriteByte(':')
			sb.WriteString(strconv.FormatUint(uint64(hi), 10))
		}
	}
	sb.WriteString(" }")
	return sb.String()
}

// ParsePortSpecs converts strategy-file port strings ("443", "19294-19344",
// "19294:19344") into ranges. It exists so the transports can hand netcfg a
// strategy's WindowSpec verbatim without netcfg importing the strategy
// package.
func ParsePortSpecs(specs []string) ([]PortRange, error) {
	out := make([]PortRange, 0, len(specs))
	for _, s := range specs {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		sep := strings.IndexAny(t, "-:")
		if sep < 0 {
			p, err := parsePort(t)
			if err != nil {
				return nil, fmt.Errorf("netcfg: port spec %q: %w", s, err)
			}
			out = append(out, PortRange{p, p})
			continue
		}
		lo, err := parsePort(strings.TrimSpace(t[:sep]))
		if err != nil {
			return nil, fmt.Errorf("netcfg: port spec %q: %w", s, err)
		}
		hi, err := parsePort(strings.TrimSpace(t[sep+1:]))
		if err != nil {
			return nil, fmt.Errorf("netcfg: port spec %q: %w", s, err)
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		out = append(out, PortRange{lo, hi})
	}
	return out, nil
}

// parsePort parses a decimal port in 1..65535.
func parsePort(s string) (uint16, error) {
	if s == "" {
		return 0, errors.New("empty port")
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("not a number")
	}
	if n == 0 || n > 65535 {
		return 0, fmt.Errorf("out of range: %d", n)
	}
	return uint16(n), nil
}

// SteerOpts parameterises the divert transport's ruleset.
type SteerOpts struct {
	// Utun is the tunnel interface the daemon owns, e.g. "utun9". Required.
	Utun string
	// TunPeer is the far-side address of the utun point-to-point link, e.g.
	// "198.18.0.2". route-to needs an address on the target interface;
	// steering is what makes the utun both the interception queue and the
	// drop verdict.
	TunPeer string
	// TunPeer6 is the IPv6 equivalent, used only when IPv6 is set. Empty
	// means "reuse TunPeer", which is only valid if it is an IPv6 literal.
	TunPeer6 string

	// TCPPorts / UDPPorts are the port windows (--wf-tcp / --wf-udp). Empty
	// means "no rule for that protocol", never "all ports": steering every
	// port would put the whole machine through userspace.
	TCPPorts []PortRange
	UDPPorts []PortRange
	// TCPPortsRaw / UDPPortsRaw override the formatted port list with a
	// pre-rendered pf list such as "{ 80 443 }". Used by `zaprctl` when the
	// operator supplies the window textually.
	TCPPortsRaw string
	UDPPortsRaw string

	// ExcludeTable is the pf table of destinations that must never be
	// steered (zapret's <nozapret>). Empty disables the exclusion.
	ExcludeTable string
	// TargetTable restricts steering to destinations in that table
	// (flowseal's ipset mode). Empty steers every destination.
	TargetTable string

	// ExemptRoot adds `user { > root }`, which keeps root-owned traffic out
	// of the window. That is the loop breaker: the daemon re-emits packets
	// as root via BPF, and BPF writes bypass pf, but any socket the daemon
	// itself opens must also stay unsteered.
	ExemptRoot bool

	// BlockQUIC installs a `block return-icmp` rule for UDP/443, forcing
	// browsers back to TCP instead of desyncing QUIC.
	BlockQUIC bool
	// BlockQUICPorts overrides the ports BlockQUIC covers (default 443).
	BlockQUICPorts []PortRange

	// IPv6 emits inet6 rules instead of inet.
	IPv6 bool

	// NoLoopbackPass suppresses the leading `pass quick on lo0 all`. That
	// rule exists so loopback traffic (including anything the daemon talks to
	// locally) is short-circuited before the steering rules are considered;
	// switch it off only if the surrounding ruleset already does it.
	NoLoopbackPass bool
}

// SteerRules renders the divert transport's anchor ruleset.
//
// Shape (verified to parse with `pfctl -a zapret-mac -n -f -` on macOS 15):
//
//	table <zmx> persist
//	pass quick on lo0 all
//	pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to ! <zmx> port { 80 443 } user { > root } no state
//	pass out quick route-to (utun9 198.18.0.2) inet proto udp from any to ! <zmx> port { 443 19294:19344 } user { > root } no state
//	block return-icmp out quick inet proto udp from any to <zmt> port 443
//
// Two properties of macOS pf drive the exact text:
//
//   - route options must PRECEDE the protospec. `pass out quick inet proto tcp
//     ... route-to (...)` is a syntax error here; `pass out quick route-to
//     (...) inet proto tcp ...` is not.
//   - `no state` keeps pf from creating state for the steered flow. We only
//     ever steer the outbound direction; inbound packets must keep taking the
//     normal path, and a state entry would try to route them back through the
//     utun.
//
// The one place this deviates from the shape above is rule ORDER: the
// BlockQUIC rule is emitted BEFORE the UDP steering rule. Both rules carry
// `quick`, so with the block rule last it could never fire whenever UDP/443 is
// inside the window — which it always is in flowseal's strategies — making the
// option a silent no-op. Blocking and desyncing the same datagram are mutually
// exclusive by nature, so the block wins.
func SteerRules(o SteerOpts) string {
	var b ruleBuilder

	b.table(o.ExcludeTable)
	b.table(o.TargetTable)

	if !o.NoLoopbackPass {
		b.line("pass quick on lo0 all")
	}

	af := "inet"
	peer := o.TunPeer
	if o.IPv6 {
		af = "inet6"
		if o.TunPeer6 != "" {
			peer = o.TunPeer6
		}
	}
	dst := destClause(o.TargetTable, o.ExcludeTable)
	user := ""
	if o.ExemptRoot {
		user = " user { > root }"
	}

	if o.BlockQUIC {
		// return-icmp on inet, return-icmp6 on inet6: an ICMP port-unreachable
		// makes the client fail over to TCP immediately instead of waiting for
		// the QUIC handshake to time out.
		ret := "return-icmp"
		if o.IPv6 {
			ret = "return-icmp6"
		}
		ports := o.BlockQUICPorts
		if len(ports) == 0 {
			ports = []PortRange{{443, 443}}
		}
		b.linef("block %s out quick %s proto udp from any to %s port %s",
			ret, af, dst, FormatPorts(ports))
	}

	if pl := portList(o.TCPPortsRaw, o.TCPPorts); pl != "" && o.Utun != "" && peer != "" {
		b.linef("pass out quick route-to (%s %s) %s proto tcp from any to %s port %s%s no state",
			o.Utun, peer, af, dst, pl, user)
	}
	if pl := portList(o.UDPPortsRaw, o.UDPPorts); pl != "" && o.Utun != "" && peer != "" {
		b.linef("pass out quick route-to (%s %s) %s proto udp from any to %s port %s%s no state",
			o.Utun, peer, af, dst, pl, user)
	}
	return b.String()
}

// LogDropOpts parameterises the macOS pflog interception rules.  PF logs the
// original packet to a dedicated pflog interface and then blocks it; userspace
// re-emits either the original or a desynchronised packet through BPF.
type LogDropOpts struct {
	PFLog string
	// Iface limits interception to the physical uplink. This is essential
	// beside a split-routing VPN: traffic already routed into utun must remain
	// in the VPN, while Direct traffic leaving en0 is the only traffic zapret
	// should block and re-emit.
	Iface        string
	TCPPorts     []PortRange
	UDPPorts     []PortRange
	ExcludeTable string
	TargetTable  string
	ExemptRoot   bool
	IPv6         bool
}

// LogDropRules renders the rules for the pflog+BPF packet transport.  `quick`
// is essential: no later pass rule may override the drop verdict after the
// packet has been queued for userspace processing.
func LogDropRules(o LogDropOpts) string {
	var b ruleBuilder
	b.table(o.ExcludeTable)
	b.table(o.TargetTable)
	b.line("pass quick on lo0 all")
	if o.PFLog == "" {
		return b.String()
	}
	af := "inet"
	if o.IPv6 {
		af = "inet6"
	}
	dst := destClause(o.TargetTable, o.ExcludeTable)
	user := ""
	if o.ExemptRoot {
		user = " user { > root }"
	}
	if pl := FormatPorts(o.TCPPorts); pl != "" {
		if o.Iface != "" {
			b.linef("block out log (all, to %s) quick on %s %s proto tcp from any to %s port %s%s no state",
				o.PFLog, o.Iface, af, dst, pl, user)
		} else {
			b.linef("block out log (all, to %s) quick %s proto tcp from any to %s port %s%s no state",
				o.PFLog, af, dst, pl, user)
		}
	}
	if pl := FormatPorts(o.UDPPorts); pl != "" {
		if o.Iface != "" {
			b.linef("block out log (all, to %s) quick on %s %s proto udp from any to %s port %s%s no state",
				o.PFLog, o.Iface, af, dst, pl, user)
		} else {
			b.linef("block out log (all, to %s) quick %s proto udp from any to %s port %s%s no state",
				o.PFLog, af, dst, pl, user)
		}
	}
	return b.String()
}

// RedirOpts parameterises the proxy transport's ruleset.
type RedirOpts struct {
	// ListenAddr is the address the local listener is bound to. Defaults to
	// 127.0.0.1 (inet) or fe80::1 (inet6), matching zapret's tpws setup.
	ListenAddr string
	// ListenPort is the local listener's port. Required.
	ListenPort int

	// TCPPorts is the set of destination ports to redirect. UDP cannot be
	// proxied, which is why there is no UDP field.
	TCPPorts []PortRange
	// TCPPortsRaw overrides TCPPorts with a pre-rendered pf port list.
	TCPPortsRaw string

	// ExcludeTable / TargetTable behave as in SteerOpts, and constrain the
	// `route-to` rule only: the rdr rule matches `to any`, because only a
	// connection the route-to rule already pushed onto lo0 can ever reach it.
	ExcludeTable string
	TargetTable  string

	// ExemptRoot adds `user { > root }` to the route-to rule so the proxy's
	// own upstream connections are not redirected back into itself.
	ExemptRoot bool

	// IPv6 emits inet6 rules instead of inet.
	IPv6 bool

	// Ifaces optionally restricts the route-to rule to these outbound
	// interfaces (zapret's IFACE_WAN). Empty means every interface.
	Ifaces []string
}

// RedirectRules renders the proxy transport's anchor ruleset, following
// zapret's common/pf.sh macOS shape:
//
//	table <zmx> persist
//	rdr pass on lo0 inet proto tcp from ! 127.0.0.0/8 to any port { 80 443 } -> 127.0.0.1 port 10800
//	pass out quick route-to (lo0 127.0.0.1) inet proto tcp from any to ! <zmx> port { 80 443 } user { > root }
//
// macOS pf cannot redirect an outbound packet, so the only way to hand a
// locally originated connection to a local listener is to force it onto lo0
// with `route-to (lo0 127.0.0.1)` and then `rdr` it on lo0 — the trick tpws
// uses. The listener recovers the pre-translation destination with
// ioctl(DIOCNATLOOK) on /dev/pf.
//
// Two deliberate differences from upstream:
//   - `rdr pass` instead of a bare `rdr`. Upstream relies on the main ruleset
//     having no default block; `rdr pass` makes the redirect self-sufficient.
//   - `quick` on the route-to rule. Our anchor is evaluated before
//     `anchor "com.apple/*"`, and filter rules are last-match-wins, so without
//     `quick` a later system rule could silently drop the route-to.
func RedirectRules(o RedirOpts) string {
	var b ruleBuilder

	b.table(o.ExcludeTable)
	b.table(o.TargetTable)

	af := "inet"
	loopSrc := "! 127.0.0.0/8"
	listen := o.ListenAddr
	if o.IPv6 {
		af = "inet6"
		loopSrc = "! ::1"
		if listen == "" {
			listen = "fe80::1"
		}
	} else if listen == "" {
		listen = "127.0.0.1"
	}

	pl := portList(o.TCPPortsRaw, o.TCPPorts)
	if pl == "" || o.ListenPort <= 0 || o.ListenPort > 65535 {
		return b.String()
	}

	b.linef("rdr pass on lo0 %s proto tcp from %s to any port %s -> %s port %d",
		af, loopSrc, pl, listen, o.ListenPort)

	dst := destClause(o.TargetTable, o.ExcludeTable)
	user := ""
	if o.ExemptRoot {
		user = " user { > root }"
	}
	ifaces := o.Ifaces
	if len(ifaces) == 0 {
		ifaces = []string{""}
	}
	for _, ifn := range ifaces {
		// pf's old grammar fixes the clause order as
		// action dir [log] [quick] [on ifspec] [route] [af] [protospec] ...
		// so `quick` must precede `on <iface>`, and the route option must
		// follow it. `pass out on en0 quick route-to (...)` is a syntax error.
		on := ""
		if ifn != "" {
			on = " on " + ifn
		}
		b.linef("pass out quick%s route-to (lo0 %s) %s proto tcp from any to %s port %s%s",
			on, listen, af, dst, pl, user)
	}
	return b.String()
}

// destClause renders the `to ...` operand. A target table wins over an exclude
// table because old-grammar pf allows only one destination operand per rule;
// when both are configured the target table is the narrower statement and the
// exclusions are expected to have been subtracted from it already.
func destClause(target, exclude string) string {
	switch {
	case target != "":
		return "<" + target + ">"
	case exclude != "":
		return "! <" + exclude + ">"
	default:
		return "any"
	}
}

// portList picks the pre-rendered list when supplied, else formats ranges.
func portList(raw string, ranges []PortRange) string {
	if s := strings.TrimSpace(raw); s != "" {
		return s
	}
	return FormatPorts(ranges)
}

// ruleBuilder accumulates ruleset lines and de-duplicates table declarations.
type ruleBuilder struct {
	lines  []string
	tables map[string]bool
}

// table declares a persistent pf table once. `persist` keeps the table alive
// across ruleset reloads even when no rule currently references it, which is
// what lets TableReplace repopulate it independently of rule loading.
func (b *ruleBuilder) table(name string) {
	if name == "" {
		return
	}
	if b.tables == nil {
		b.tables = make(map[string]bool)
	}
	if b.tables[name] {
		return
	}
	b.tables[name] = true
	b.lines = append(b.lines, "table <"+name+"> persist")
}

func (b *ruleBuilder) line(s string) { b.lines = append(b.lines, s) }

func (b *ruleBuilder) linef(format string, args ...any) {
	b.lines = append(b.lines, fmt.Sprintf(format, args...))
}

// String renders the ruleset. An empty ruleset is the empty string, which
// pfctl accepts as "flush this anchor".
func (b *ruleBuilder) String() string {
	if len(b.lines) == 0 {
		return ""
	}
	return strings.Join(b.lines, "\n") + "\n"
}

// ---------------------------------------------------------------------------
// text helpers
// ---------------------------------------------------------------------------

// splitLines splits b on '\n' and reports whether the input ended with a
// newline, so joinLines can reproduce the file's trailing byte exactly. CRLF
// input keeps its '\r' on every preserved line (comparisons are done on
// TrimSpace'd copies); inserted lines use bare '\n', which pf parses either
// way.
func splitLines(b []byte) ([]string, bool) {
	s := string(b)
	if s == "" {
		return nil, false
	}
	trailing := strings.HasSuffix(s, "\n")
	if trailing {
		s = s[:len(s)-1]
	}
	return strings.Split(s, "\n"), trailing
}

// joinLines is splitLines' inverse.
func joinLines(lines []string, trailingNewline bool) []byte {
	if len(lines) == 0 {
		if trailingNewline {
			return []byte("\n")
		}
		return nil
	}
	s := strings.Join(lines, "\n")
	if trailingNewline {
		s += "\n"
	}
	return []byte(s)
}

// bytesEqual compares two byte slices, treating nil and empty as equal.
func bytesEqual(a, b []byte) bool {
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

// readFileIfExists reads path, returning (nil, false, nil) when it is absent.
func readFileIfExists(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}
