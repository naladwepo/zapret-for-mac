package engine

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/lists"
	"github.com/naladwepo/zapret-for-mac/internal/proto"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// The engine is driven here exactly the way the transports drive it: real
// compiled strategies (the shipped strategies/*.toml plus small inline ones for
// the cases no flowseal file exercises), hand-built packets that went through
// proto.Tmpl.Marshal + proto.Parse, and no network access at all.
//
// Tests that describe a behaviour engine.go does NOT have yet are t.Skip'ed with
// the defect spelled out; their bodies are the reproduction and pass once the
// defect is fixed.

const (
	testListsDir  = "../../lists"
	testFakesDir  = "../../fakes"
	testStratsDir = "../../strategies"
)

// loadShipped compiles one of the converted flowseal strategies.
func loadShipped(t *testing.T, name string) *strategy.Strategy {
	t.Helper()
	s, err := strategy.Load(filepath.Join(testStratsDir, name), strategy.LoadOpts{
		ListsDir: testListsDir, FakesDir: testFakesDir,
	})
	if err != nil {
		t.Fatalf("strategy.Load(%s): %v", name, err)
	}
	return s
}

// loadInline compiles a strategy written by the test, resolving lists and fakes
// against the real directories so the compiled form is the production one.
func loadInline(t *testing.T, body string) *strategy.Strategy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inline.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write inline strategy: %v", err)
	}
	s, err := strategy.Load(path, strategy.LoadOpts{ListsDir: testListsDir, FakesDir: testFakesDir})
	if err != nil {
		t.Fatalf("strategy.Load(inline):\n%s\n%v", body, err)
	}
	return s
}

// readBlob loads one fake payload fixture.
func readBlob(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testFakesDir, name))
	if err != nil {
		t.Fatalf("read fake %s: %v", name, err)
	}
	return b
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

// pktSpec is one packet to synthesise. Zero fields mean the obvious default:
// TTL 64, window 64240, TCP with PSH|ACK when flags is zero.
type pktSpec struct {
	src, dst netip.Addr
	sport    uint16
	dport    uint16
	seq, ack uint32
	flags    uint8
	ttl      uint8
	window   uint16
	opts     []byte
	payload  []byte
	udp      bool
}

// build marshals the spec into wire bytes and parses them back, so every test
// packet is a real IP packet with consistent headers.
func (s pktSpec) build() *proto.Pkt {
	tm := proto.Tmpl{
		Src: s.src, Dst: s.dst, SrcPort: s.sport, DstPort: s.dport,
		Seq: s.seq, Ack: s.ack, Flags: s.flags, Window: s.window,
		TCPOpts: s.opts, TTL: s.ttl, Payload: s.payload, UDP: s.udp,
	}
	raw, err := tm.Marshal()
	if err != nil {
		panic("Tmpl.Marshal: " + err.Error())
	}
	p, err := proto.Parse(raw)
	if err != nil {
		panic("proto.Parse: " + err.Error())
	}
	return p
}

func mkPkt(t *testing.T, s pktSpec) *proto.Pkt {
	t.Helper()
	return s.build()
}

// keyOf is the client->server flow key of an outbound packet.
func keyOf(p *proto.Pkt) desync.FlowKey {
	return desync.FlowKey{Src: p.Src, Dst: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort, Proto: p.Proto}
}

// flowState returns a copy of the tracked flow, failing when it is gone. It
// deliberately does not use Engine.flow, which would create the entry and skew
// Counters.FlowsTotal.
func flowState(t *testing.T, e *Engine, key desync.FlowKey) desync.Flow {
	t.Helper()
	e.flowsMu.Lock()
	defer e.flowsMu.Unlock()
	fe, ok := e.flows[key]
	if !ok {
		t.Fatalf("no flow tracked for %+v", key)
	}
	return fe.f
}

func hasFlow(e *Engine, key desync.FlowKey) bool {
	e.flowsMu.Lock()
	defer e.flowsMu.Unlock()
	_, ok := e.flows[key]
	return ok
}

// backdate ages every tracked flow by d, which is how an idle flow is simulated
// without a fake clock (flowEntry.seen is package-private state).
func backdate(e *Engine, d time.Duration) {
	e.flowsMu.Lock()
	defer e.flowsMu.Unlock()
	for _, fe := range e.flows {
		fe.seen = fe.seen.Add(-d)
	}
}

// tlsHello builds a minimal well-formed ClientHello carrying sni (no SNI
// extension at all when sni is empty).
func tlsHello(sni string) []byte {
	var exts []byte
	if sni != "" {
		name := []byte(sni)
		var body []byte
		body = append(body, byte((len(name)+3)>>8), byte(len(name)+3))
		body = append(body, 0x00, byte(len(name)>>8), byte(len(name)))
		body = append(body, name...)
		exts = append(exts, 0x00, 0x00, byte(len(body)>>8), byte(len(body)))
		exts = append(exts, body...)
	}
	// supported_versions, so a hello without SNI still has an extensions block.
	exts = append(exts, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 32)
	body = append(body, make([]byte, 32)...) // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// httpGet builds a minimal HTTP request, the other L7 the engine classifies on
// TCP.
func httpGet(host string) []byte {
	return []byte("GET /index.html HTTP/1.1\r\nHost: " + host + "\r\nAccept: */*\r\n\r\n")
}

// discordIPDiscovery is the 74-byte Discord voice IP-discovery request zapret
// keys its voice desync on: type 0x0001 plus the fixed 70-byte body.
func discordIPDiscovery() []byte {
	b := make([]byte, 74)
	b[0], b[1] = 0x00, 0x01
	b[2], b[3] = 0x00, 70
	return b
}

// splitLens describes a plan's segments compactly for failure messages.
func splitLens(p *desync.Plan) []int {
	out := make([]int, 0, len(p.Segs))
	for _, s := range p.Segs {
		out = append(out, len(s.Data))
	}
	return out
}

// hasSegs reports whether a plan put anything on the wire.
func hasSegs(p *desync.Plan) bool {
	return p != nil && (len(p.Segs) > 0 || len(p.Dgrams) > 0)
}

// ---------- profile selection ----------

// threeWaySplit is a strategy whose three profiles all match TCP/443, cutting
// the payload at different offsets so the plan says which one ran.
const threeWaySplit = `
name = "order"
[[profile]]
name = "first"
[profile.filter]
proto = "tcp"
ports = ["443"]
[[profile.ops]]
op = "multisplit"
pos = ["2"]

[[profile]]
name = "second"
[profile.filter]
proto = "tcp"
ports = ["443"]
[[profile.ops]]
op = "multisplit"
pos = ["5"]

[[profile]]
name = "third"
[profile.filter]
[[profile.ops]]
op = "multisplit"
pos = ["9"]
`

// TestProfileSelectionFirstMatchWins pins winws' --new chain semantics: the
// profiles are tried in file order and the first whose filter matches runs, even
// when a later one matches too.
func TestProfileSelectionFirstMatchWins(t *testing.T) {
	e := New(loadInline(t, threeWaySplit), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	hello := tlsHello("a.example")

	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40000, dport: 443, seq: 1001, ack: 1, payload: hello})
	plan, err := e.OnTCP(p)
	if err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if plan == nil || len(plan.Segs) != 2 {
		t.Fatalf("plan = %+v, want two segments", plan)
	}
	if got := len(plan.Segs[0].Data); got != 2 {
		t.Fatalf("first segment is %d bytes (lens %v), want the 2-byte cut of the FIRST profile", got, splitLens(plan))
	}
	f := flowState(t, e, keyOf(p))
	if !f.Matched || f.ProfileIdx != 0 {
		t.Fatalf("flow decided %d (matched=%v), want profile 0", f.ProfileIdx, f.Matched)
	}
	if e.Counters().Matched != 1 {
		t.Fatalf("Counters.Matched = %d, want 1", e.Counters().Matched)
	}
}

// hostGated is a strategy whose only profile is gated on an inline hostlist.
const hostGated = `
name = "gated"
[[profile]]
name = "gated"
[profile.filter]
proto = "tcp"
ports = ["443"]
hostlist_domains = ["a.example"]
[[profile.ops]]
op = "multisplit"
pos = ["2"]
`

// TestHostlistGatedProfileNeedsHostname checks both halves of the hostlist gate
// on the packet that reveals the hostname: a ClientHello for a listed host
// matches, one for an unlisted host does not and settles the flow for good.
func TestHostlistGatedProfileNeedsHostname(t *testing.T) {
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")

	t.Run("listed", func(t *testing.T) {
		e := New(loadInline(t, hostGated), desync.FullCaps(), desync.FakeSet{})
		p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40100, dport: 443, seq: 1001, ack: 1, payload: tlsHello("a.example")})
		plan, err := e.OnTCP(p)
		if err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
		if !hasSegs(plan) {
			t.Fatalf("plan = %+v, want the gated profile to run", plan)
		}
		f := flowState(t, e, keyOf(p))
		if f.ProfileIdx != 0 || f.Host != "a.example" || f.L7 != proto.L7TLS {
			t.Fatalf("flow = %+v, want profile 0 / host a.example / TLS", f)
		}
	})

	t.Run("unlisted_is_final", func(t *testing.T) {
		e := New(loadInline(t, hostGated), desync.FullCaps(), desync.FakeSet{})
		p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40101, dport: 443, seq: 1001, ack: 1, payload: tlsHello("b.example")})
		plan, err := e.OnTCP(p)
		if err != nil || plan != nil {
			t.Fatalf("OnTCP = (%v, %v), want (nil, nil) for an unlisted host", plan, err)
		}
		f := flowState(t, e, keyOf(p))
		if !f.Matched || f.ProfileIdx != -1 {
			t.Fatalf("flow = %+v, want a final \"no profile\" decision", f)
		}
		if !f.FastPath {
			t.Fatalf("flow = %+v, want FastPath after a final no-match", f)
		}
		if e.Counters().Matched != 0 {
			t.Fatalf("Counters.Matched = %d, want 0", e.Counters().Matched)
		}
	})

	t.Run("no_sni_does_not_match", func(t *testing.T) {
		e := New(loadInline(t, hostGated), desync.FullCaps(), desync.FakeSet{})
		p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40102, dport: 443, seq: 1001, ack: 1, payload: tlsHello("")})
		plan, err := e.OnTCP(p)
		if err != nil || plan != nil {
			t.Fatalf("OnTCP = (%v, %v), want (nil, nil) for a hello without SNI", plan, err)
		}
	})
}

// TestHostlistGateDeferredAcrossSyn is the deferral the code documents but does
// not implement: a flow whose hostname is not known yet must stay undecided, so
// the ClientHello that follows the SYN can still match a hostlist-gated profile.
func TestHostlistGateDeferredAcrossSyn(t *testing.T) {
	e := New(loadInline(t, hostGated), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")

	syn := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40110, dport: 443, seq: 5000, flags: proto.TCPSyn})
	if _, err := e.OnTCP(syn); err != nil {
		t.Fatalf("OnTCP(syn): %v", err)
	}
	f := flowState(t, e, keyOf(syn))
	if f.Matched || f.FastPath {
		t.Fatalf("after the SYN the flow is %+v, want an undecided flow off the fast path", f)
	}

	hello := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40110, dport: 443, seq: 5001, ack: 1, payload: tlsHello("a.example")})
	plan, err := e.OnTCP(hello)
	if err != nil {
		t.Fatalf("OnTCP(hello): %v", err)
	}
	if !hasSegs(plan) {
		t.Fatalf("plan = %+v, want the gated profile to run once the SNI is known", plan)
	}
	if f = flowState(t, e, keyOf(hello)); f.ProfileIdx != 0 {
		t.Fatalf("flow decided %d, want profile 0", f.ProfileIdx)
	}
}

// TestProfileDecisionCachedOnFlow pins the caching: once a flow has a profile,
// later packets reuse it without re-evaluating a single filter, even when their
// payload would have selected a different profile.
func TestProfileDecisionCachedOnFlow(t *testing.T) {
	e := New(loadInline(t, `
name = "cache"
[[profile]]
name = "for-a"
[profile.filter]
proto = "tcp"
ports = ["443"]
hostlist_domains = ["a.example"]
[[profile.ops]]
op = "multisplit"
pos = ["2"]

[[profile]]
name = "for-b"
[profile.filter]
proto = "tcp"
ports = ["443"]
hostlist_domains = ["b.example"]
[[profile.ops]]
op = "multisplit"
pos = ["9"]
`), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")

	first := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40200, dport: 443, seq: 1001, ack: 1, payload: tlsHello("a.example")})
	plan, err := e.OnTCP(first)
	if err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if len(plan.Segs) != 2 || len(plan.Segs[0].Data) != 2 {
		t.Fatalf("first plan lens %v, want a 2-byte first segment", splitLens(plan))
	}

	// A second payload on the same flow, whose SNI names the other profile.
	second := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40200, dport: 443, seq: 1200, ack: 1, payload: tlsHello("b.example")})
	plan, err = e.OnTCP(second)
	if err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if len(plan.Segs) != 2 || len(plan.Segs[0].Data) != 2 {
		t.Fatalf("second plan lens %v, want the CACHED 2-byte cut of profile 0", splitLens(plan))
	}
	f := flowState(t, e, keyOf(second))
	if f.ProfileIdx != 0 {
		t.Fatalf("flow decided %d, want the cached profile 0", f.ProfileIdx)
	}
	if e.Counters().Matched != 1 {
		t.Fatalf("Counters.Matched = %d, want 1 (the decision is made once per flow)", e.Counters().Matched)
	}
}

// TestReloadKeepsCachedProfileIndex pins the documented Reload behaviour: a live
// flow keeps running with the profile INDEX it cached, so a swapped strategy
// changes what that index means and an index past the new chain runs nothing.
func TestReloadKeepsCachedProfileIndex(t *testing.T) {
	e := New(loadInline(t, threeWaySplit), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")

	// Settle a flow on profile index 0 of the current strategy.
	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40300, dport: 443, seq: 1001, ack: 1, payload: tlsHello("a.example")})
	if _, err := e.OnTCP(p); err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if f := flowState(t, e, keyOf(p)); f.ProfileIdx != 0 {
		t.Fatalf("flow decided %d, want 0", f.ProfileIdx)
	}

	// The new strategy's profile 0 cuts at 7; the live flow must follow it.
	e.Reload(loadInline(t, `
name = "reloaded"
[[profile]]
name = "only"
[profile.filter]
proto = "tcp"
ports = ["443"]
[[profile.ops]]
op = "multisplit"
pos = ["7"]
`))
	if e.Strategy().Name != "reloaded" {
		t.Fatalf("Strategy().Name = %q after Reload", e.Strategy().Name)
	}
	p2 := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40300, dport: 443, seq: 1200, ack: 1, payload: tlsHello("a.example")})
	plan, err := e.OnTCP(p2)
	if err != nil {
		t.Fatalf("OnTCP after Reload: %v", err)
	}
	if len(plan.Segs) != 2 || len(plan.Segs[0].Data) != 7 {
		t.Fatalf("plan lens %v, want the reloaded profile 0 (7-byte cut)", splitLens(plan))
	}

	// A strategy with no profile at that index leaves the flow with nothing to run.
	e.Reload(&strategy.Strategy{Name: "empty"})
	p3 := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40300, dport: 443, seq: 1400, ack: 1, payload: tlsHello("a.example")})
	plan, err = e.OnTCP(p3)
	if plan != nil || err != nil {
		t.Fatalf("OnTCP = (%v, %v), want (nil, nil) when the cached index is out of range", plan, err)
	}
}

// TestNilStrategy pins the "not activated yet" behaviour of both entry points.
func TestNilStrategy(t *testing.T) {
	e := New(nil, desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40400, dport: 443, seq: 1001, ack: 1, payload: tlsHello("a.example")})
	if plan, err := e.OnTCP(p); plan != nil || err != nil {
		t.Fatalf("OnTCP = (%v, %v), want (nil, nil)", plan, err)
	}
	u := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 40400, dport: 443, udp: true, payload: []byte("x")})
	if plan, err := e.OnUDP(u); plan != nil || err != nil {
		t.Fatalf("OnUDP = (%v, %v), want (nil, nil)", plan, err)
	}
	if _, err := e.PlanStream(keyOf(p), tlsHello("a.example")); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("PlanStream err = %v, want ErrNoProfile", err)
	}
	if e.FlowCount() != 0 {
		t.Fatalf("FlowCount = %d, want 0 (no strategy, no state)", e.FlowCount())
	}
}

// ---------- the real general.toml against realistic flows ----------

// TestGeneralStrategyGoogleTLS drives the shipped general.toml with a
// googlevideo ClientHello: it must land on the list-google profile and produce
// flowseal's "pos=1 seqovl=681" plan, with --ip-id=zero tagging every segment.
func TestGeneralStrategyGoogleTLS(t *testing.T) {
	s := loadShipped(t, "general.toml")
	e := New(s, desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "142.250.1.1")
	hello := tlsHello("rr1---sn-x.googlevideo.com")

	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41000, dport: 443, seq: 1001, ack: 7, payload: hello})
	plan, err := e.OnTCP(p)
	if err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	f := flowState(t, e, keyOf(p))
	if f.ProfileIdx < 0 {
		t.Fatalf("no profile selected for a googlevideo ClientHello")
	}
	if got := s.Profiles[f.ProfileIdx].Name; got != "p4-tcp-443" {
		t.Fatalf("selected profile %q, want p4-tcp-443 (the list-google one)", got)
	}
	if got := s.Profiles[f.ProfileIdx].Ops[0].Params.Seqovl; got != 681 {
		t.Fatalf("profile seqovl = %d, want 681", got)
	}

	if len(plan.Segs) != 2 {
		t.Fatalf("plan has %d segments (lens %v), want 2", len(plan.Segs), splitLens(plan))
	}
	pattern := readBlob(t, "tls_clienthello_www_google_com.bin")
	if len(pattern) != 681 {
		t.Fatalf("seqovl pattern fixture is %d bytes, want 681", len(pattern))
	}
	want := append(append([]byte{}, pattern...), hello[:1]...)
	if plan.Segs[0].SeqOff != -681 {
		t.Fatalf("first segment SeqOff = %d, want -681 (the overlap sits below the window)", plan.Segs[0].SeqOff)
	}
	if !bytes.Equal(plan.Segs[0].Data, want) {
		t.Fatalf("first segment is %d bytes, want the 681-byte pattern plus payload[:1]", len(plan.Segs[0].Data))
	}
	if plan.Segs[1].SeqOff != 1 || !bytes.Equal(plan.Segs[1].Data, hello[1:]) {
		t.Fatalf("second segment = (off %d, %d bytes), want (1, %d)", plan.Segs[1].SeqOff, len(plan.Segs[1].Data), len(hello)-1)
	}
	for i, sg := range plan.Segs {
		if sg.IPID != desync.IPIDZero {
			t.Fatalf("segment %d IPID = %v, want IPIDZero (the profile's ip_id op)", i, sg.IPID)
		}
	}
	if !plan.DropOriginal {
		t.Fatal("plan does not claim the original packet")
	}
	if len(plan.Degraded) != 0 {
		t.Fatalf("Degraded = %q under FullCaps, want nothing", plan.Degraded)
	}
	if e.Counters().Matched != 1 || e.Counters().Desyncs != 1 || e.Counters().FlowsTotal != 1 {
		t.Fatalf("counters = %+v, want one match, one desync, one flow", e.Counters())
	}
}

// TestGeneralStrategyDiscordMedia pins the hostlist_domains profile: a
// discord.media ClientHello on 2053 is what flowseal's third --new chain element
// exists for.
func TestGeneralStrategyDiscordMedia(t *testing.T) {
	s := loadShipped(t, "general.toml")
	e := New(s, desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "162.159.130.234")

	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41100, dport: 2053, seq: 1001, ack: 7, payload: tlsHello("discord.media")})
	plan, err := e.OnTCP(p)
	if err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	f := flowState(t, e, keyOf(p))
	if f.ProfileIdx < 0 || s.Profiles[f.ProfileIdx].Name != "p3-tcp-2053_2083_2087_2096_8443" {
		t.Fatalf("selected profile %d, want the hostlist_domains profile p3", f.ProfileIdx)
	}
	if !hasSegs(plan) || plan.Segs[0].SeqOff != -681 {
		t.Fatalf("plan = %+v, want the seqovl 681 split", plan)
	}
}

// TestGeneralStrategyExcludedHost pins the exclusion lists: a host on
// list-exclude.txt must select nothing at all, on every profile of the chain.
func TestGeneralStrategyExcludedHost(t *testing.T) {
	s := loadShipped(t, "general.toml")
	e := New(s, desync.FullCaps(), desync.FakeSet{})
	cli := mustAddr(t, "192.0.2.10")
	// 1.1.1.1 is inside ipset-all.txt, so only the hostname can stop the
	// ipset-gated profiles from matching.
	srv := mustAddr(t, "1.1.1.1")

	for _, host := range []string{"mail.ru", "vkplay.ru", "vkplay.live", "vk.com", "userapi.com"} {
		p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41200, dport: 443, seq: 1001, ack: 7, payload: tlsHello(host)})
		plan, err := e.OnTCP(p)
		if plan != nil || err != nil {
			t.Fatalf("OnTCP(%s) = (%v, %v), want (nil, nil) for an excluded host", host, plan, err)
		}
		f := flowState(t, e, keyOf(p))
		if !f.Matched || f.ProfileIdx != -1 || !f.FastPath {
			t.Fatalf("flow(%s) = %+v, want a final no-match on the fast path", host, f)
		}
	}
	if e.Counters().Matched != 0 || e.Counters().Desyncs != 0 {
		t.Fatalf("counters = %+v, want no match and no desync", e.Counters())
	}
}

func TestCloudGamingStrategyExcludedVKPlay(t *testing.T) {
	s := loadShipped(t, "cloud-gaming.toml")
	e := New(s, desync.FullCaps(), desync.FakeSet{})
	cli := mustAddr(t, "192.0.2.10")
	srv := mustAddr(t, "95.163.61.43")

	for _, host := range []string{"vkplay.ru", "vkplay.live", "playkey.net", "vk.com", "userapi.com"} {
		p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41250, dport: 443, seq: 1001, ack: 7, payload: tlsHello(host)})
		plan, err := e.OnTCP(p)
		if plan != nil || err != nil {
			t.Fatalf("OnTCP(%s) = (%v, %v), want (nil, nil) for an excluded host", host, plan, err)
		}
		f := flowState(t, e, keyOf(p))
		if !f.Matched || f.ProfileIdx != -1 || !f.FastPath {
			t.Fatalf("flow(%s) = %+v, want a final no-match on the fast path", host, f)
		}
	}
}

// TestGeneralStrategyQUIC pins the UDP/443 QUIC profile: a real QUIC Initial is
// classified, its SNI decrypted, and the profile's six fake QUIC datagrams are
// planned in front of the original one.
func TestGeneralStrategyQUIC(t *testing.T) {
	s := loadShipped(t, "general.toml")
	e := New(s, desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "1.1.1.1")
	initial := readBlob(t, "quic_initial_www_google_com.bin")

	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41300, dport: 443, udp: true, payload: initial})
	plan, err := e.OnUDP(p)
	if err != nil {
		t.Fatalf("OnUDP: %v", err)
	}
	f := flowState(t, e, keyOf(p))
	if f.L7 != proto.L7QUIC || f.Host != "www.google.com" {
		t.Fatalf("flow classified as %v host %q, want QUIC / www.google.com", f.L7, f.Host)
	}
	if f.ProfileIdx < 0 || s.Profiles[f.ProfileIdx].Name != "p6-udp-443" {
		t.Fatalf("selected profile %d, want p6-udp-443", f.ProfileIdx)
	}
	if len(plan.Dgrams) != 2 {
		t.Fatalf("plan has %d datagrams, want a fake and the original", len(plan.Dgrams))
	}
	if plan.Dgrams[0].Kind != desync.SegFake || plan.Dgrams[0].Repeats != 6 {
		t.Fatalf("first datagram = (kind %v, repeats %d), want (SegFake, 6)", plan.Dgrams[0].Kind, plan.Dgrams[0].Repeats)
	}
	if !bytes.Equal(plan.Dgrams[0].Data, initial) {
		t.Fatal("the fake datagram is not the profile's quic_initial_www_google_com.bin blob")
	}
	if plan.Dgrams[1].Kind != desync.SegData || !bytes.Equal(plan.Dgrams[1].Data, initial) {
		t.Fatal("the real datagram is missing from the plan")
	}
	if !plan.DropOriginal {
		t.Fatal("plan does not claim the original datagram")
	}
}

// TestGeneralStrategyDiscordVoice pins the voice profile: a Discord IP-discovery
// datagram on 50001 selects the l7=discord/stun profile and gets the
// ACTIVE_DISCORD_UDP fake, six times.
func TestGeneralStrategyDiscordVoice(t *testing.T) {
	s := loadShipped(t, "general.toml")
	e := New(s, desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "66.22.200.5")

	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41400, dport: 50001, udp: true, payload: discordIPDiscovery()})
	plan, err := e.OnUDP(p)
	if err != nil {
		t.Fatalf("OnUDP: %v", err)
	}
	f := flowState(t, e, keyOf(p))
	if f.L7 != proto.L7Discord {
		t.Fatalf("flow classified as %v, want L7Discord", f.L7)
	}
	if f.ProfileIdx < 0 || s.Profiles[f.ProfileIdx].Name != "p2-udp-19294-19344_50000-50100" {
		t.Fatalf("selected profile %d, want the Discord voice profile p2", f.ProfileIdx)
	}
	if len(plan.Dgrams) != 2 || plan.Dgrams[0].Kind != desync.SegFake || plan.Dgrams[0].Repeats != 6 {
		t.Fatalf("plan = %+v, want six repeats of one fake plus the original", plan)
	}
	if !bytes.Equal(plan.Dgrams[0].Data, readBlob(t, "ACTIVE_DISCORD_UDP.bin")) {
		t.Fatal("the fake datagram is not ACTIVE_DISCORD_UDP.bin")
	}
}

// TestGeneralStrategyUnmatchedUDPFlowShortCircuits pins the UDP no-match path:
// a QUIC Initial to an address outside ipset-all.txt whose SNI is not on
// list-general.txt matches nothing, and the flow then skips parsing entirely.
func TestGeneralStrategyUnmatchedUDPFlowShortCircuits(t *testing.T) {
	e := New(loadShipped(t, "general.toml"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "203.0.113.9")
	initial := readBlob(t, "quic_initial_www_google_com.bin")

	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41500, dport: 443, udp: true, payload: initial})
	plan, err := e.OnUDP(p)
	if plan != nil || err != nil {
		t.Fatalf("OnUDP = (%v, %v), want (nil, nil)", plan, err)
	}
	f := flowState(t, e, keyOf(p))
	if !f.Matched || f.ProfileIdx != -1 || !f.FastPath {
		t.Fatalf("flow = %+v, want a final no-match on the fast path", f)
	}
	// A second datagram must not be classified again.
	if _, err := e.OnUDP(p); err != nil {
		t.Fatalf("OnUDP: %v", err)
	}
	f = flowState(t, e, keyOf(p))
	if f.Pkts != 2 || f.DataPkts != 2 {
		t.Fatalf("flow counters = (%d, %d), want (2, 2)", f.Pkts, f.DataPkts)
	}
}

// TestOnUDPEmptyPayload pins that an empty datagram is counted but never planned
// for: there is nothing to classify and nothing to split.
func TestOnUDPEmptyPayload(t *testing.T) {
	e := New(loadShipped(t, "general.toml"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "1.1.1.1")
	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41600, dport: 443, udp: true})
	plan, err := e.OnUDP(p)
	if plan != nil || err != nil {
		t.Fatalf("OnUDP = (%v, %v), want (nil, nil)", plan, err)
	}
	f := flowState(t, e, keyOf(p))
	if f.Pkts != 1 || f.DataPkts != 0 || f.Matched {
		t.Fatalf("flow = %+v, want one packet, no data packet, no decision", f)
	}
}

// TestGeneralStrategyHostlistProfileWinsAfterSyn is the production sequence:
// SYN first, ClientHello second. The hostlist-gated google profile must still
// win, which today it cannot because the SYN already settled the flow on the
// ipset-only profile that sits later in the chain.
func TestGeneralStrategyHostlistProfileWinsAfterSyn(t *testing.T) {
	s := loadShipped(t, "general.toml")
	e := New(s, desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "142.250.1.1")

	syn := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41700, dport: 443, seq: 5000, flags: proto.TCPSyn})
	if _, err := e.OnTCP(syn); err != nil {
		t.Fatalf("OnTCP(syn): %v", err)
	}
	hello := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 41700, dport: 443, seq: 5001, ack: 7, payload: tlsHello("rr1---sn-x.googlevideo.com")})
	plan, err := e.OnTCP(hello)
	if err != nil {
		t.Fatalf("OnTCP(hello): %v", err)
	}
	f := flowState(t, e, keyOf(hello))
	if f.ProfileIdx < 0 || s.Profiles[f.ProfileIdx].Name != "p4-tcp-443" {
		t.Fatalf("selected profile %d (%s), want p4-tcp-443", f.ProfileIdx, s.Profiles[max(f.ProfileIdx, 0)].Name)
	}
	if plan.Segs[0].SeqOff != -681 {
		t.Fatalf("first segment SeqOff = %d, want -681 (list-google seqovl)", plan.Segs[0].SeqOff)
	}
}

// ---------- start / cutoff counters ----------

// counterStrategy is one profile whose window is set by the caller.
func counterStrategy(t *testing.T, start, cutoff string) *strategy.Strategy {
	t.Helper()
	return loadInline(t, `
name = "window"
[[profile]]
name = "p"
start = "`+start+`"
cutoff = "`+cutoff+`"
[profile.filter]
proto = "tcp"
ports = ["443"]
[[profile.ops]]
op = "multisplit"
pos = ["2"]
`)
}

// TestCutoffPacketCounter pins --dpi-desync-cutoff=n3: the packet number counts
// every client packet, the SYN included, and the flow goes to the fast path on
// the first packet past the bound.
func TestCutoffPacketCounter(t *testing.T) {
	e := New(counterStrategy(t, "", "n3"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 42000, DstPort: 443, Proto: proto.IPProtoTCP}
	hello := tlsHello("a.example")

	if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 42000, dport: 443, seq: 1000, flags: proto.TCPSyn})); err != nil {
		t.Fatalf("OnTCP(syn): %v", err)
	}
	// Packets 2 and 3 of the flow are inside the window, packet 4 is not.
	want := []bool{true, true, false, false}
	seq := uint32(1001)
	for i, wantSegs := range want {
		p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 42000, dport: 443, seq: seq, ack: 1, payload: hello})
		plan, err := e.OnTCP(p)
		if err != nil {
			t.Fatalf("data packet %d: %v", i+1, err)
		}
		if hasSegs(plan) != wantSegs {
			t.Fatalf("data packet %d (flow packet %d): desync=%v, want %v", i+1, i+2, hasSegs(plan), wantSegs)
		}
		f := flowState(t, e, key)
		if wantFast := !wantSegs; f.FastPath != wantFast {
			t.Fatalf("data packet %d: FastPath = %v, want %v", i+1, f.FastPath, wantFast)
		}
		seq += uint32(len(hello))
	}
	if f := flowState(t, e, key); f.Pkts != 5 || f.DataPkts != 4 {
		t.Fatalf("flow counted (%d, %d) packets, want (5, 4)", f.Pkts, f.DataPkts)
	}
}

// TestCutoffDataPacketCounter pins --dpi-desync-cutoff=d2: only packets carrying
// payload count, so a bare ACK in between does not consume the window.
func TestCutoffDataPacketCounter(t *testing.T) {
	e := New(counterStrategy(t, "", "d2"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 42100, DstPort: 443, Proto: proto.IPProtoTCP}
	hello := tlsHello("a.example")
	send := func(spec pktSpec) *desync.Plan {
		t.Helper()
		plan, err := e.OnTCP(mkPkt(t, spec))
		if err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
		return plan
	}

	send(pktSpec{src: cli, dst: srv, sport: 42100, dport: 443, seq: 1000, flags: proto.TCPSyn})
	if plan := send(pktSpec{src: cli, dst: srv, sport: 42100, dport: 443, seq: 1001, ack: 1, payload: hello}); !hasSegs(plan) {
		t.Fatal("data packet 1 was not desynced")
	}
	// A bare ACK: counted as a packet, not as a data packet, and never planned for.
	if plan := send(pktSpec{src: cli, dst: srv, sport: 42100, dport: 443, seq: 1001, ack: 2, flags: proto.TCPAck}); plan != nil {
		t.Fatalf("bare ACK produced a plan: %+v", plan)
	}
	if f := flowState(t, e, key); f.Pkts != 3 || f.DataPkts != 1 {
		t.Fatalf("after the ACK the flow counted (%d, %d), want (3, 1)", f.Pkts, f.DataPkts)
	}
	if plan := send(pktSpec{src: cli, dst: srv, sport: 42100, dport: 443, seq: 1200, ack: 2, payload: hello}); !hasSegs(plan) {
		t.Fatal("data packet 2 was not desynced, even though the ACK should not count")
	}
	if plan := send(pktSpec{src: cli, dst: srv, sport: 42100, dport: 443, seq: 1400, ack: 2, payload: hello}); hasSegs(plan) {
		t.Fatal("data packet 3 was desynced past cutoff d2")
	}
	if f := flowState(t, e, key); !f.FastPath {
		t.Fatal("the flow is not on the fast path after the cutoff")
	}
}

// TestCutoffSequenceCounter pins --dpi-desync-cutoff=s5000: the bound is the
// relative sequence number, measured from the ISN the SYN carried, and the last
// packet exactly at the bound is still inside it.
func TestCutoffSequenceCounter(t *testing.T) {
	e := New(counterStrategy(t, "", "s5000"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	const isn = 1_000_000
	key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 42200, DstPort: 443, Proto: proto.IPProtoTCP}
	hello := tlsHello("a.example")

	if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 42200, dport: 443, seq: isn, flags: proto.TCPSyn})); err != nil {
		t.Fatalf("OnTCP(syn): %v", err)
	}
	if f := flowState(t, e, key); f.ISN != isn {
		t.Fatalf("ISN = %d, want %d", f.ISN, isn)
	}
	for _, tc := range []struct {
		off      uint32
		wantSegs bool
	}{{1, true}, {5000, true}, {5001, false}} {
		p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 42200, dport: 443, seq: isn + tc.off, ack: 1, payload: hello})
		plan, err := e.OnTCP(p)
		if err != nil {
			t.Fatalf("seq offset %d: %v", tc.off, err)
		}
		if hasSegs(plan) != tc.wantSegs {
			t.Fatalf("seq offset %d: desync=%v, want %v", tc.off, hasSegs(plan), tc.wantSegs)
		}
	}
	if f := flowState(t, e, key); !f.FastPath {
		t.Fatal("the flow is not on the fast path after the sequence cutoff")
	}
}

// TestStartCounters pins --dpi-desync-start for all three kinds. Unlike the
// cutoff, a start bound that is not reached yet must NOT arm the fast path: a
// later packet of the same flow still has to be examined.
func TestStartCounters(t *testing.T) {
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	hello := tlsHello("a.example")
	const isn = 4_000_000

	for _, tc := range []struct {
		start string
		// offs are (seq offset from the ISN, want desync) in send order.
		offs []struct {
			off      uint32
			wantSegs bool
		}
	}{
		{"n3", []struct {
			off      uint32
			wantSegs bool
		}{{1, false}, {200, true}}}, // SYN is packet 1, so data packet 2 is packet 3
		{"d2", []struct {
			off      uint32
			wantSegs bool
		}{{1, false}, {200, true}}},
		{"s100", []struct {
			off      uint32
			wantSegs bool
		}{{99, false}, {100, true}}},
	} {
		t.Run(tc.start, func(t *testing.T) {
			e := New(counterStrategy(t, tc.start, ""), desync.FullCaps(), desync.FakeSet{})
			key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 42300, DstPort: 443, Proto: proto.IPProtoTCP}
			if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 42300, dport: 443, seq: isn, flags: proto.TCPSyn})); err != nil {
				t.Fatalf("OnTCP(syn): %v", err)
			}
			for i, step := range tc.offs {
				p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 42300, dport: 443, seq: isn + step.off, ack: 1, payload: hello})
				plan, err := e.OnTCP(p)
				if err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
				if hasSegs(plan) != step.wantSegs {
					t.Fatalf("step %d (seq offset %d): desync=%v, want %v", i, step.off, hasSegs(plan), step.wantSegs)
				}
				if f := flowState(t, e, key); f.FastPath {
					t.Fatalf("step %d: a start bound must never arm the fast path", i)
				}
			}
		})
	}
}

// ---------- SYN handling ----------

// TestSYNResetsFlowStateOnPortReuse pins the fast-port-reuse case: a fresh SYN
// on a 4-tuple that already carries state must restart the flow, or the new
// connection would inherit the old ISN, counters, cutoff and profile decision.
func TestSYNResetsFlowStateOnPortReuse(t *testing.T) {
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")

	t.Run("isn_counters_and_cutoff", func(t *testing.T) {
		e := New(counterStrategy(t, "", "d1"), desync.FullCaps(), desync.FakeSet{})
		key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 43000, DstPort: 443, Proto: proto.IPProtoTCP}
		hello := tlsHello("a.example")
		send := func(spec pktSpec) *desync.Plan {
			t.Helper()
			plan, err := e.OnTCP(mkPkt(t, spec))
			if err != nil {
				t.Fatalf("OnTCP: %v", err)
			}
			return plan
		}

		send(pktSpec{src: cli, dst: srv, sport: 43000, dport: 443, seq: 1000, flags: proto.TCPSyn})
		if plan := send(pktSpec{src: cli, dst: srv, sport: 43000, dport: 443, seq: 1001, ack: 1, payload: hello}); !hasSegs(plan) {
			t.Fatal("the first data packet was not desynced")
		}
		// Past cutoff d1: the flow is decided, desynced and on the fast path.
		send(pktSpec{src: cli, dst: srv, sport: 43000, dport: 443, seq: 1200, ack: 1, payload: hello})
		if before := flowState(t, e, key); !before.FastPath || !before.Desynced || !before.Matched {
			t.Fatalf("flow before reuse = %+v, want decided/desynced/fast-path", before)
		}

		send(pktSpec{src: cli, dst: srv, sport: 43000, dport: 443, seq: 777_000, flags: proto.TCPSyn})
		f := flowState(t, e, key)
		switch {
		case f.ISN != 777_000:
			t.Fatalf("ISN = %d after the new SYN, want 777000", f.ISN)
		case f.Pkts != 1 || f.DataPkts != 0:
			t.Fatalf("counters = (%d, %d) after the new SYN, want (1, 0)", f.Pkts, f.DataPkts)
		case f.FastPath:
			t.Fatal("the reused flow is still on the fast path")
		case f.Desynced:
			t.Fatal("the reused flow still claims a desync from the previous connection")
		}
		// And the new connection's first data packet is desynced again, which the
		// cutoff of the previous connection would have suppressed.
		if plan := send(pktSpec{src: cli, dst: srv, sport: 43000, dport: 443, seq: 777_001, ack: 1, payload: hello}); !hasSegs(plan) {
			t.Fatal("the reused flow's first data packet was not desynced")
		}
	})

	// The profile decision is re-made from scratch on the SYN. Proving that needs
	// two profiles the SYN itself tells apart: an L7-gated one cannot match a bare
	// SYN, so a flow that had settled on it must move to the unconstrained one.
	t.Run("profile_decision", func(t *testing.T) {
		e := New(loadInline(t, `
name = "reuse"
[[profile]]
name = "http-only"
[profile.filter]
proto = "tcp"
ports = ["443"]
l7 = ["http"]
[[profile.ops]]
op = "multisplit"
pos = ["2"]

[[profile]]
name = "anything"
[profile.filter]
proto = "tcp"
ports = ["443"]
[[profile.ops]]
op = "multisplit"
pos = ["9"]
`), desync.FullCaps(), desync.FakeSet{})
		key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 43100, DstPort: 443, Proto: proto.IPProtoTCP}
		req := httpGet("a.example")

		plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 43100, dport: 443, seq: 1001, ack: 1, payload: req}))
		if err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
		if len(plan.Segs) != 2 || len(plan.Segs[0].Data) != 2 {
			t.Fatalf("plan lens %v, want the l7=http profile's 2-byte cut", splitLens(plan))
		}
		if f := flowState(t, e, key); f.ProfileIdx != 0 || f.L7 != proto.L7HTTP {
			t.Fatalf("flow = %+v, want profile 0 and L7HTTP", f)
		}

		if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 43100, dport: 443, seq: 500_000, flags: proto.TCPSyn})); err != nil {
			t.Fatalf("OnTCP(syn): %v", err)
		}
		if f := flowState(t, e, key); f.ProfileIdx != 1 {
			t.Fatalf("after the reuse SYN the flow is on profile %d, want the decision re-made (1)", f.ProfileIdx)
		}
		plan, err = e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 43100, dport: 443, seq: 500_001, ack: 1, payload: req}))
		if err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
		if len(plan.Segs) != 2 || len(plan.Segs[0].Data) != 9 {
			t.Fatalf("plan lens %v, want the 9-byte cut of the profile the SYN selected", splitLens(plan))
		}
	})
}

// ---------- autottl ----------

// autoTTLStrategy is one fake op whose TTL spec the caller chooses.
func autoTTLStrategy(t *testing.T, ttl string) *strategy.Strategy {
	t.Helper()
	return loadInline(t, `
name = "autottl"
[[profile]]
name = "p"
[profile.filter]
proto = "tcp"
ports = ["443"]
[[profile.ops]]
op = "fake"
ttl = "`+ttl+`"
[profile.ops.fake]
tls = "tls_clienthello_www_google_com.bin"
`)
}

// TestAutoTTLFromInboundSample pins the hop inference: an inbound TTL of 58 is
// six hops from a 64 start, and the fake goes out at hops+delta clamped into the
// configured range.
func TestAutoTTLFromInboundSample(t *testing.T) {
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	for _, tc := range []struct {
		spec    string
		inbound uint8
		want    uint8
	}{
		{"auto:-1:3-20", 58, 5},  // 6 hops - 1
		{"auto:+2:3-20", 58, 8},  // 6 hops + 2
		{"auto:-1:8-20", 58, 8},  // 5 clamped up to the minimum
		{"auto:-1:3-4", 58, 4},   // 5 clamped down to the maximum
		{"auto:-1:3-20", 250, 4}, // 255 start: 5 hops - 1
	} {
		t.Run(fmt.Sprintf("%s_ttl%d", tc.spec, tc.inbound), func(t *testing.T) {
			e := New(autoTTLStrategy(t, tc.spec), desync.FullCaps(), desync.FakeSet{})
			key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 44000, DstPort: 443, Proto: proto.IPProtoTCP}

			// The flow has to exist before OnInbound can attach a hop count to it.
			if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 44000, dport: 443, seq: 100, flags: proto.TCPSyn})); err != nil {
				t.Fatalf("OnTCP(syn): %v", err)
			}
			e.OnInbound(mkPkt(t, pktSpec{src: srv, dst: cli, sport: 443, dport: 44000, seq: 9, ack: 101, flags: proto.TCPSyn | proto.TCPAck, ttl: tc.inbound}))
			f := flowState(t, e, key)
			if want := HopsFromTTL(tc.inbound); f.Hops != want {
				t.Fatalf("Hops = %d, want %d", f.Hops, want)
			}

			plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 44000, dport: 443, seq: 101, ack: 10, payload: tlsHello("a.example")}))
			if err != nil {
				t.Fatalf("OnTCP: %v", err)
			}
			if len(plan.Segs) == 0 || plan.Segs[0].Kind != desync.SegFake {
				t.Fatalf("plan = %+v, want a fake segment first", plan)
			}
			if plan.Segs[0].TTL != tc.want {
				t.Fatalf("fake TTL = %d, want %d (hops %d, spec %s)", plan.Segs[0].TTL, tc.want, f.Hops, tc.spec)
			}
			// The real payload never carries the forged TTL.
			if plan.Segs[len(plan.Segs)-1].TTL != 0 {
				t.Fatalf("the real segment carries TTL %d, want 0", plan.Segs[len(plan.Segs)-1].TTL)
			}
		})
	}
}

// TestAutoTTLFallbackWithoutSample pins the no-inbound-sample case (the first
// datagram of a QUIC or voice flow): the fake TTL is the midpoint of the
// configured range, and always inside it.
func TestAutoTTLFallbackWithoutSample(t *testing.T) {
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	for _, tc := range []struct {
		spec     string
		min, max uint8
		want     uint8
	}{
		{"auto", 3, 20, 11},
		{"auto:-1:5-9", 5, 9, 7},
		{"auto:-1:7-7", 7, 7, 7},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			e := New(autoTTLStrategy(t, tc.spec), desync.FullCaps(), desync.FakeSet{})
			plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 44100, dport: 443, seq: 10, ack: 1, payload: tlsHello("a.example")}))
			if err != nil {
				t.Fatalf("OnTCP: %v", err)
			}
			got := plan.Segs[0].TTL
			if got != tc.want {
				t.Fatalf("fallback TTL = %d, want %d", got, tc.want)
			}
			if got < tc.min || got > tc.max {
				t.Fatalf("fallback TTL %d is outside the configured range %d..%d", got, tc.min, tc.max)
			}
		})
	}
}

// TestHopsFromTTL pins the hop inference itself, including every standard
// initial value and the degenerate TTL 0.
func TestHopsFromTTL(t *testing.T) {
	for _, tc := range []struct {
		ttl  uint8
		want uint8
	}{
		{0, 0},
		{1, 63},
		{58, 6},
		{63, 1},
		{64, 0},
		{65, 63},
		{120, 8},
		{127, 1},
		{128, 0},
		{129, 126},
		{250, 5},
		{254, 1},
		{255, 0},
	} {
		if got := HopsFromTTL(tc.ttl); got != tc.want {
			t.Errorf("HopsFromTTL(%d) = %d, want %d", tc.ttl, got, tc.want)
		}
	}
}

// TestOnInboundKeepsFirstSampleAndIgnoresUnknownFlows pins the two remaining
// OnInbound rules: the first hop count wins (a later route change must not move
// the fake TTL under a live flow), and an inbound packet for a flow we do not
// track must not create one.
func TestOnInboundKeepsFirstSampleAndIgnoresUnknownFlows(t *testing.T) {
	e := New(autoTTLStrategy(t, "auto"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 44200, DstPort: 443, Proto: proto.IPProtoTCP}

	if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 44200, dport: 443, seq: 100, flags: proto.TCPSyn})); err != nil {
		t.Fatalf("OnTCP(syn): %v", err)
	}
	e.OnInbound(mkPkt(t, pktSpec{src: srv, dst: cli, sport: 443, dport: 44200, ack: 101, flags: proto.TCPAck, ttl: 58}))
	e.OnInbound(mkPkt(t, pktSpec{src: srv, dst: cli, sport: 443, dport: 44200, ack: 101, flags: proto.TCPAck, ttl: 40}))
	if f := flowState(t, e, key); f.Hops != 6 {
		t.Fatalf("Hops = %d after a second sample, want the first one (6)", f.Hops)
	}

	before := e.FlowCount()
	e.OnInbound(mkPkt(t, pktSpec{src: srv, dst: cli, sport: 443, dport: 59999, ack: 1, flags: proto.TCPAck, ttl: 58}))
	if got := e.FlowCount(); got != before {
		t.Fatalf("FlowCount = %d after an inbound packet for an untracked flow, want %d", got, before)
	}
}

// ---------- Caps gating ----------

// capsStrategy is flowseal's flagship recipe (a fake decoy, an overlapping
// multisplit and --ip-id=zero) with the on_unsupported policy under test.
func capsStrategy(t *testing.T, policy string) *strategy.Strategy {
	t.Helper()
	return loadInline(t, `
name = "caps"
[[profile]]
name = "p"
on_unsupported = "`+policy+`"
[profile.filter]
proto = "tcp"
ports = ["443"]
[[profile.ops]]
op = "fake"
ttl = "5"
[profile.ops.fake]
tls = "tls_clienthello_www_google_com.bin"
[[profile.ops]]
op = "multisplit"
pos = ["1"]
seqovl = 681
seqovl_pattern = "tls_clienthello_www_google_com.bin"
[[profile.ops]]
op = "ip_id"
mode = "zero"
`)
}

// TestCapsGatingFullVsProxy runs one strategy under both transports' Caps and
// pins exactly which ops survive: everything under FullCaps, and only the
// segmentation (without its sub-window overlap) under ProxyCaps.
func TestCapsGatingFullVsProxy(t *testing.T) {
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	hello := tlsHello("a.example")
	s := capsStrategy(t, "degrade")

	t.Run("full", func(t *testing.T) {
		e := New(s, desync.FullCaps(), desync.FakeSet{})
		plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 45000, dport: 443, seq: 10, ack: 1, payload: hello}))
		if err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
		if len(plan.Degraded) != 0 {
			t.Fatalf("Degraded = %q, want nothing under FullCaps", plan.Degraded)
		}
		if len(plan.Segs) != 3 {
			t.Fatalf("plan has %d segments (lens %v), want fake + two split parts", len(plan.Segs), splitLens(plan))
		}
		if plan.Segs[0].Kind != desync.SegFake || plan.Segs[0].TTL != 5 {
			t.Fatalf("segment 0 = (kind %v, ttl %d), want the fake at TTL 5", plan.Segs[0].Kind, plan.Segs[0].TTL)
		}
		if plan.Segs[1].SeqOff != -681 {
			t.Fatalf("segment 1 SeqOff = %d, want -681 (seqovl needs Caps.Seq)", plan.Segs[1].SeqOff)
		}
		for i, sg := range plan.Segs {
			if sg.IPID != desync.IPIDZero {
				t.Fatalf("segment %d IPID = %v, want IPIDZero", i, sg.IPID)
			}
		}
		if e.Counters().Degraded != 0 {
			t.Fatalf("Counters.Degraded = %d, want 0", e.Counters().Degraded)
		}
	})

	t.Run("proxy", func(t *testing.T) {
		e := New(s, desync.ProxyCaps(), desync.FakeSet{})
		plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 45001, dport: 443, seq: 10, ack: 1, payload: hello}))
		if err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
		// fake needs inject/per-packet-ttl/fooling and ip_id needs ip-id: both are
		// gated off. multisplit needs only Segment+DropOriginal, so it runs, but
		// its overlap needs Caps.Seq and is dropped with a note of its own.
		if len(plan.Segs) != 2 {
			t.Fatalf("plan has %d segments (lens %v), want the two split parts only", len(plan.Segs), splitLens(plan))
		}
		for i, sg := range plan.Segs {
			if sg.Kind != desync.SegData {
				t.Fatalf("segment %d is kind %v, want data only (no injection under ProxyCaps)", i, sg.Kind)
			}
			if sg.SeqOff < 0 {
				t.Fatalf("segment %d SeqOff = %d, want a non-negative offset under ProxyCaps", i, sg.SeqOff)
			}
			if sg.IPID != desync.IPIDDefault {
				t.Fatalf("segment %d IPID = %v, want IPIDDefault", i, sg.IPID)
			}
		}
		if !plan.DropOriginal {
			t.Fatal("plan does not claim the original payload")
		}
		wantDegraded := []string{
			"fake",
			"multisplit: seqovl 681 dropped, transport cannot choose TCP sequence numbers",
			"ip_id",
		}
		if len(plan.Degraded) != len(wantDegraded) {
			t.Fatalf("Degraded = %q, want %q", plan.Degraded, wantDegraded)
		}
		for i := range wantDegraded {
			if plan.Degraded[i] != wantDegraded[i] {
				t.Fatalf("Degraded[%d] = %q, want %q", i, plan.Degraded[i], wantDegraded[i])
			}
		}
		// Only the two capability-gated ops are counted; the seqovl note is the
		// op's own honesty, not an engine degradation.
		if e.Counters().Degraded != 2 {
			t.Fatalf("Counters.Degraded = %d, want 2", e.Counters().Degraded)
		}
	})
}

// disorderStrategy is one op that HAS a socket-level approximation, so degrade
// and skip are observably different.
func disorderStrategy(t *testing.T, policy string) *strategy.Strategy {
	t.Helper()
	return loadInline(t, `
name = "disorder"
[[profile]]
name = "p"
on_unsupported = "`+policy+`"
[profile.filter]
proto = "tcp"
ports = ["443"]
[[profile.ops]]
op = "multidisorder"
pos = ["2"]
`)
}

// TestCapsGatingDegradeRunsTheApproximation pins the default policy: an op that
// implements desync.Degrader gets its approximation on the wire, and the plan
// says what was approximated.
func TestCapsGatingDegradeRunsTheApproximation(t *testing.T) {
	e := New(disorderStrategy(t, "degrade"), desync.ProxyCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 45100, dport: 443, seq: 10, ack: 1, payload: tlsHello("a.example")}))
	if err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if len(plan.Segs) != 2 {
		t.Fatalf("plan has %d segments, want the emulated disorder's two", len(plan.Segs))
	}
	if plan.Segs[0].TTL != 1 {
		t.Fatalf("first segment TTL = %d, want 1 (the tpws --disorder emulation)", plan.Segs[0].TTL)
	}
	if len(plan.Degraded) != 2 || plan.Degraded[1] != "multidisorder" {
		t.Fatalf("Degraded = %q, want the emulation note plus \"multidisorder\"", plan.Degraded)
	}
	if e.Counters().Degraded != 1 {
		t.Fatalf("Counters.Degraded = %d, want 1", e.Counters().Degraded)
	}
}

// TestCapsGatingSkipPolicy pins on_unsupported="skip": the op is dropped without
// running its approximation, so nothing at all is planned.
func TestCapsGatingSkipPolicy(t *testing.T) {
	e := New(disorderStrategy(t, "skip"), desync.ProxyCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 45200, dport: 443, seq: 10, ack: 1, payload: tlsHello("a.example")}))
	if err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if len(plan.Segs) != 0 || len(plan.Dgrams) != 0 || plan.DropOriginal {
		t.Fatalf("plan = %+v, want an empty plan that leaves the original packet alone", plan)
	}
	if len(plan.Degraded) != 1 || plan.Degraded[0] != "multidisorder" {
		t.Fatalf("Degraded = %q, want exactly [\"multidisorder\"] with no approximation note", plan.Degraded)
	}
	if e.Counters().Degraded != 1 || e.Counters().Desyncs != 0 {
		t.Fatalf("counters = %+v, want one degradation and no desync", e.Counters())
	}
}

// TestCapsGatingErrorPolicy pins on_unsupported="error": the profile fails with
// an UnsupportedError that names the op and every missing capability, and the
// transport is handed no plan at all.
func TestCapsGatingErrorPolicy(t *testing.T) {
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	for _, tc := range []struct {
		op          string
		body        string
		wantMissing []string
	}{
		{"fake", `
[[profile.ops]]
op = "fake"
ttl = "5"
[profile.ops.fake]
tls = "tls_clienthello_www_google_com.bin"
`, []string{"inject", "per-packet-ttl", "fooling"}},
		{"multidisorder", `
[[profile.ops]]
op = "multidisorder"
pos = ["2"]
`, []string{"seq"}},
		{"ip_id", `
[[profile.ops]]
op = "ip_id"
mode = "zero"
`, []string{"ip-id"}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			e := New(loadInline(t, `
name = "err"
[[profile]]
name = "p"
on_unsupported = "error"
[profile.filter]
proto = "tcp"
ports = ["443"]
`+tc.body), desync.ProxyCaps(), desync.FakeSet{})

			plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 45300, dport: 443, seq: 10, ack: 1, payload: tlsHello("a.example")}))
			if plan != nil {
				t.Fatalf("plan = %+v, want nil when the profile errors", plan)
			}
			var ue *UnsupportedError
			if !errors.As(err, &ue) {
				t.Fatalf("err = %v (%T), want *UnsupportedError", err, err)
			}
			if ue.Op != tc.op {
				t.Fatalf("UnsupportedError.Op = %q, want %q", ue.Op, tc.op)
			}
			if len(ue.Missing) != len(tc.wantMissing) {
				t.Fatalf("Missing = %q, want %q", ue.Missing, tc.wantMissing)
			}
			for i := range tc.wantMissing {
				if ue.Missing[i] != tc.wantMissing[i] {
					t.Fatalf("Missing = %q, want %q", ue.Missing, tc.wantMissing)
				}
			}
			msg := ue.Error()
			for _, want := range append([]string{tc.op}, tc.wantMissing...) {
				if !bytes.Contains([]byte(msg), []byte(want)) {
					t.Fatalf("error message %q does not name %q", msg, want)
				}
			}
			if e.Counters().Errors != 1 {
				t.Fatalf("Counters.Errors = %d, want 1", e.Counters().Errors)
			}
		})
	}
}

// TestProxyCapsSeesNoUDP pins that a transport without Caps.UDP is never handed
// a datagram plan, whatever the strategy says.
func TestProxyCapsSeesNoUDP(t *testing.T) {
	e := New(loadShipped(t, "general.toml"), desync.ProxyCaps(), desync.FakeSet{})
	if e.Caps().UDP {
		t.Fatal("ProxyCaps claims UDP")
	}
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "1.1.1.1")
	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 45400, dport: 443, udp: true, payload: readBlob(t, "quic_initial_www_google_com.bin")})
	plan, err := e.OnUDP(p)
	if plan != nil || err != nil {
		t.Fatalf("OnUDP = (%v, %v), want (nil, nil) without Caps.UDP", plan, err)
	}
	if e.FlowCount() != 0 {
		t.Fatalf("FlowCount = %d, want 0 (the datagram was never tracked)", e.FlowCount())
	}
}

// ---------- the proxy transport's entry point ----------

// TestPlanStream drives the socket-level entry point against general.toml: the
// same profile selection, byte-range segments only, and ErrNoProfile when
// nothing matches.
func TestPlanStream(t *testing.T) {
	s := loadShipped(t, "general.toml")
	cli := mustAddr(t, "192.0.2.10")
	hello := tlsHello("rr1---sn-x.googlevideo.com")

	t.Run("matched", func(t *testing.T) {
		e := New(s, desync.ProxyCaps(), desync.FakeSet{})
		key := desync.FlowKey{Src: cli, Dst: mustAddr(t, "142.250.1.1"), SrcPort: 46000, DstPort: 443, Proto: proto.IPProtoTCP}
		plan, err := e.PlanStream(key, hello)
		if err != nil {
			t.Fatalf("PlanStream: %v", err)
		}
		if len(plan.Segs) != 2 {
			t.Fatalf("plan has %d segments (lens %v), want two", len(plan.Segs), splitLens(plan))
		}
		for i, sg := range plan.Segs {
			if sg.SeqOff < 0 {
				t.Fatalf("segment %d SeqOff = %d: a stream relay cannot send below the window", i, sg.SeqOff)
			}
		}
		if plan.Segs[0].SeqOff != 0 || len(plan.Segs[0].Data) != 1 || plan.Segs[1].SeqOff != 1 {
			t.Fatalf("segments = %v at offsets %d/%d, want a cut at 1", splitLens(plan), plan.Segs[0].SeqOff, plan.Segs[1].SeqOff)
		}
		f := flowState(t, e, key)
		if f.ProfileIdx < 0 || s.Profiles[f.ProfileIdx].Name != "p4-tcp-443" {
			t.Fatalf("selected profile %d, want p4-tcp-443", f.ProfileIdx)
		}
		if f.Pkts != 1 || f.DataPkts != 1 {
			t.Fatalf("flow counted (%d, %d), want (1, 1)", f.Pkts, f.DataPkts)
		}
	})

	t.Run("excluded", func(t *testing.T) {
		e := New(s, desync.ProxyCaps(), desync.FakeSet{})
		key := desync.FlowKey{Src: cli, Dst: mustAddr(t, "1.1.1.1"), SrcPort: 46001, DstPort: 443, Proto: proto.IPProtoTCP}
		plan, err := e.PlanStream(key, tlsHello("mail.ru"))
		if plan != nil || !errors.Is(err, ErrNoProfile) {
			t.Fatalf("PlanStream = (%v, %v), want (nil, ErrNoProfile)", plan, err)
		}
		f := flowState(t, e, key)
		if !f.Matched || f.ProfileIdx != -1 {
			t.Fatalf("flow = %+v, want a final no-match", f)
		}
	})

	t.Run("decision_is_cached", func(t *testing.T) {
		e := New(s, desync.ProxyCaps(), desync.FakeSet{})
		key := desync.FlowKey{Src: cli, Dst: mustAddr(t, "142.250.1.1"), SrcPort: 46002, DstPort: 443, Proto: proto.IPProtoTCP}
		if _, err := e.PlanStream(key, hello); err != nil {
			t.Fatalf("PlanStream: %v", err)
		}
		// A second payload naming another host still runs the cached profile.
		plan, err := e.PlanStream(key, tlsHello("discord.media"))
		if err != nil {
			t.Fatalf("PlanStream: %v", err)
		}
		if len(plan.Segs) != 2 || plan.Segs[0].SeqOff != 0 || len(plan.Segs[0].Data) != 1 {
			t.Fatalf("plan = %v, want the cached profile's cut at 1", splitLens(plan))
		}
		if e.Counters().Matched != 1 {
			t.Fatalf("Counters.Matched = %d, want 1", e.Counters().Matched)
		}
	})
}

// ---------- retransmissions, flow table lifetime ----------

// TestRetransmissionCounting pins the --hostlist-auto input: a client packet
// repeating the previous data packet's sequence number is a retransmission, and
// it is still counted after the desync window has closed.
func TestRetransmissionCounting(t *testing.T) {
	e := New(counterStrategy(t, "", "d1"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	key := desync.FlowKey{Src: cli, Dst: srv, SrcPort: 47000, DstPort: 443, Proto: proto.IPProtoTCP}
	hello := tlsHello("a.example")
	send := func(seq uint32, flags uint8, payload []byte) {
		t.Helper()
		if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 47000, dport: 443, seq: seq, ack: 1, flags: flags, payload: payload})); err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
	}

	send(1000, proto.TCPSyn, nil)
	send(1001, 0, hello)
	if f := flowState(t, e, key); f.Retrans != 0 {
		t.Fatalf("Retrans = %d after the first data packet, want 0", f.Retrans)
	}
	send(1001, 0, hello) // retransmission
	if f := flowState(t, e, key); f.Retrans != 1 {
		t.Fatalf("Retrans = %d after one repeat, want 1", f.Retrans)
	}
	send(1001, 0, hello) // and another, past the cutoff
	f := flowState(t, e, key)
	if !f.FastPath {
		t.Fatal("the flow is not on the fast path, so this no longer tests counting past the cutoff")
	}
	if f.Retrans != 2 {
		t.Fatalf("Retrans = %d, want 2 (retransmissions are counted past the cutoff too)", f.Retrans)
	}
	send(1001+uint32(len(hello)), 0, hello) // a new segment
	if f := flowState(t, e, key); f.Retrans != 2 {
		t.Fatalf("Retrans = %d after a fresh segment, want it unchanged at 2", f.Retrans)
	}
	// A bare ACK repeating the sequence number is not a data retransmission.
	send(1001, proto.TCPAck, nil)
	if f := flowState(t, e, key); f.Retrans != 2 {
		t.Fatalf("Retrans = %d after a bare ACK, want it unchanged at 2", f.Retrans)
	}
}

// TestForgetDropsFlow pins the FIN/RST path: Forget removes the state at once.
func TestForgetDropsFlow(t *testing.T) {
	e := New(counterStrategy(t, "", ""), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 47100, dport: 443, seq: 1000, flags: proto.TCPSyn})
	if _, err := e.OnTCP(p); err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if e.FlowCount() != 1 {
		t.Fatalf("FlowCount = %d, want 1", e.FlowCount())
	}
	e.Forget(keyOf(p))
	if e.FlowCount() != 0 || hasFlow(e, keyOf(p)) {
		t.Fatalf("FlowCount = %d after Forget, want 0", e.FlowCount())
	}
	// Forgetting twice, or a key that was never tracked, is harmless.
	e.Forget(keyOf(p))
	e.Forget(desync.FlowKey{})
	if e.FlowCount() != 0 {
		t.Fatalf("FlowCount = %d, want 0", e.FlowCount())
	}
}

// TestGCEvictsIdleFlows pins the periodic sweep: a flow idle past flowTTL is
// evicted, an active one is kept, and a packet on an evicted flow starts fresh.
func TestGCEvictsIdleFlows(t *testing.T) {
	e := New(counterStrategy(t, "", ""), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	idle := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 47200, dport: 443, seq: 1000, flags: proto.TCPSyn})
	if _, err := e.OnTCP(idle); err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	backdate(e, flowTTL+time.Minute)

	active := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 47201, dport: 443, seq: 2000, flags: proto.TCPSyn})
	if _, err := e.OnTCP(active); err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if e.FlowCount() != 2 {
		t.Fatalf("FlowCount = %d, want 2", e.FlowCount())
	}

	e.GC()
	if hasFlow(e, keyOf(idle)) {
		t.Fatal("the idle flow survived GC")
	}
	if !hasFlow(e, keyOf(active)) {
		t.Fatal("GC evicted the active flow")
	}
	if e.FlowCount() != 1 {
		t.Fatalf("FlowCount = %d after GC, want 1", e.FlowCount())
	}

	// Traffic on the evicted flow is tracked again, as a new flow.
	if _, err := e.OnTCP(idle); err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if f := flowState(t, e, keyOf(idle)); f.Pkts != 1 {
		t.Fatalf("the re-created flow counted %d packets, want 1", f.Pkts)
	}
	if e.Counters().FlowsTotal != 3 {
		t.Fatalf("Counters.FlowsTotal = %d, want 3", e.Counters().FlowsTotal)
	}
}

// synFlows offers n distinct flows to the engine, one SYN each.
func synFlows(t *testing.T, e *Engine, n int) {
	t.Helper()
	cli := mustAddr(t, "192.0.2.10")
	for i := 0; i < n; i++ {
		// Vary the address as well as the port, so the key space is not capped by
		// the 16-bit port range.
		srv := netip.AddrFrom4([4]byte{198, 51, 100, byte(i / 256)})
		p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: uint16(1024 + i%256), dport: 443, seq: 1000, flags: proto.TCPSyn})
		if _, err := e.OnTCP(p); err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
	}
}

// TestFlowTableDoesNotGrowWithoutBound hammers the table with far more flows
// than its 4096-entry sweep threshold: nothing may leak per packet, and once the
// flows fall idle the whole table must be reclaimable in one sweep.
func TestFlowTableDoesNotGrowWithoutBound(t *testing.T) {
	e := New(counterStrategy(t, "", ""), desync.FullCaps(), desync.FakeSet{})
	const flows = 6000
	synFlows(t, e, flows)
	count := e.FlowCount()
	t.Logf("%d flows offered, %d tracked, %d created in total", flows, count, e.Counters().FlowsTotal)
	if count > flows {
		t.Fatalf("FlowCount = %d for %d distinct flows: the table is leaking entries", count, flows)
	}
	if e.Counters().FlowsTotal != flows {
		t.Fatalf("Counters.FlowsTotal = %d, want %d (one entry per flow, not per packet)", e.Counters().FlowsTotal, flows)
	}
	backdate(e, flowTTL+time.Minute)
	e.GC()
	if e.FlowCount() != 0 {
		t.Fatalf("FlowCount = %d after a full sweep, want 0", e.FlowCount())
	}
}

// TestFlowTableSweepsItselfPastTheThreshold pins the automatic sweep: once the
// table is over its 4096-entry threshold, a new flow triggers a collection of
// the stale entries without anybody calling GC.
func TestFlowTableSweepsItselfPastTheThreshold(t *testing.T) {
	e := New(counterStrategy(t, "", ""), desync.FullCaps(), desync.FakeSet{})
	synFlows(t, e, 4096)
	if e.FlowCount() != 4096 {
		t.Fatalf("FlowCount = %d, want the table filled to the sweep threshold", e.FlowCount())
	}
	backdate(e, flowTTL+time.Minute)

	// One more flow crosses the threshold and must collect the 4096 stale ones.
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "203.0.113.55")
	if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 61234, dport: 443, seq: 1000, flags: proto.TCPSyn})); err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	// At most the newcomer survives (today it is swept along with the rest; see
	// TestFlowCreatedWhileTableFullKeepsState).
	if got := e.FlowCount(); got > 1 {
		t.Fatalf("FlowCount = %d after the automatic sweep, want the stale entries gone", got)
	}
}

// TestFlowCreatedWhileTableFullKeepsState is the state loss the 4096-entry
// sweep causes for the flow that triggers it.
func TestFlowCreatedWhileTableFullKeepsState(t *testing.T) {
	e := New(counterStrategy(t, "", ""), desync.FullCaps(), desync.FakeSet{})
	synFlows(t, e, 4096)
	if e.FlowCount() != 4096 {
		t.Fatalf("FlowCount = %d, want the table filled to 4096", e.FlowCount())
	}

	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "203.0.113.44")
	syn := mkPkt(t, pktSpec{src: cli, dst: srv, sport: 61000, dport: 443, seq: 999_000, flags: proto.TCPSyn})
	if _, err := e.OnTCP(syn); err != nil {
		t.Fatalf("OnTCP(syn): %v", err)
	}
	if !hasFlow(e, keyOf(syn)) {
		t.Fatal("the flow created past the sweep threshold was dropped immediately")
	}
	if f := flowState(t, e, keyOf(syn)); f.ISN != 999_000 {
		t.Fatalf("ISN = %d, want 999000", f.ISN)
	}
	// Its second packet must find the same entry, not create another one.
	created := e.Counters().FlowsTotal
	if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 61000, dport: 443, seq: 999_001, ack: 1, payload: tlsHello("a.example")})); err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if e.Counters().FlowsTotal != created {
		t.Fatalf("Counters.FlowsTotal went %d -> %d: the second packet re-created the flow", created, e.Counters().FlowsTotal)
	}
	if f := flowState(t, e, keyOf(syn)); f.Pkts != 2 || f.DataPkts != 1 {
		t.Fatalf("flow counted (%d, %d) packets, want (2, 1)", f.Pkts, f.DataPkts)
	}
}

// ---------- concurrency ----------

// TestConcurrentOnTCP hammers the engine from several goroutines over
// overlapping and distinct flow keys, which is exactly how the divert transport
// would use it from more than one reader.
func TestConcurrentOnTCP(t *testing.T) {
	e := New(loadShipped(t, "general.toml"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "142.250.1.1")
	hello := tlsHello("rr1---sn-x.googlevideo.com")

	const goroutines, perGoroutine, distinctPorts = 8, 50, 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				// Half the goroutines share one port block (overlapping keys), the
				// other half use their own (distinct keys).
				port := uint16(30000 + (g%2)*1000 + i%distinctPorts)
				p := pktSpec{src: cli, dst: srv, sport: port, dport: 443, seq: uint32(1000 + i), ack: 1, payload: hello}.build()
				if _, err := e.OnTCP(p); err != nil {
					t.Errorf("OnTCP: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	wantFlows := int64(2 * distinctPorts)
	if e.Counters().FlowsTotal != wantFlows || int64(e.FlowCount()) != wantFlows {
		t.Fatalf("flows = %d tracked / %d created, want %d of each", e.FlowCount(), e.Counters().FlowsTotal, wantFlows)
	}
	if e.Counters().Matched != wantFlows {
		t.Fatalf("Counters.Matched = %d, want one match per flow (%d)", e.Counters().Matched, wantFlows)
	}
	if want := int64(goroutines * perGoroutine); e.Counters().Desyncs != want {
		t.Fatalf("Counters.Desyncs = %d, want %d", e.Counters().Desyncs, want)
	}
}

// TestSequentialCountersAreExact is the single-goroutine half of the counter
// contract: with no concurrency the totals are exact, which is what makes the
// concurrent test above a real assertion rather than a guess.
func TestSequentialCountersAreExact(t *testing.T) {
	e := New(loadShipped(t, "general.toml"), desync.FullCaps(), desync.FakeSet{})
	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "142.250.1.1")
	hello := tlsHello("rr1---sn-x.googlevideo.com")
	const flows, perFlow = 20, 5
	for f := 0; f < flows; f++ {
		for i := 0; i < perFlow; i++ {
			p := mkPkt(t, pktSpec{src: cli, dst: srv, sport: uint16(48000 + f), dport: 443,
				seq: uint32(1000 + i*len(hello)), ack: 1, payload: hello})
			if _, err := e.OnTCP(p); err != nil {
				t.Fatalf("OnTCP: %v", err)
			}
		}
	}
	want := Counters{Matched: flows, Desyncs: flows * perFlow, FlowsTotal: flows}
	if e.Counters() != want {
		t.Fatalf("counters = %+v, want %+v", e.Counters(), want)
	}
}

// ---------- known gap ----------

// TestAutoHostlistIsWired documents that nothing consumes the retransmission
// counter the engine keeps. The registry key is the path the COMPILED filter
// carries (resolveList joins a bare name onto the lists directory), which is
// also the contract Engine.SetAutoList documents.
func TestAutoHostlistIsWired(t *testing.T) {
	al, err := lists.NewAutoList(filepath.Join(t.TempDir(), "auto.txt"))
	if err != nil {
		t.Fatalf("NewAutoList: %v", err)
	}
	s := loadInline(t, `
name = "auto"
[[profile]]
name = "p"
[profile.filter]
proto = "tcp"
ports = ["443"]
hostlist_auto = "auto.txt"
[[profile.ops]]
op = "multisplit"
pos = ["2"]
`)
	e := New(s, desync.FullCaps(), desync.FakeSet{})
	key := s.Profiles[0].Filter.AutoHostlist
	if key == "" {
		t.Fatal("the compiled filter carries no AutoHostlist path")
	}
	e.SetAutoList(key, al)

	cli, srv := mustAddr(t, "192.0.2.10"), mustAddr(t, "198.51.100.7")
	hello := tlsHello("a.example")
	if _, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 49000, dport: 443, seq: 1000, flags: proto.TCPSyn})); err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	// The host is not on the list yet, so nfqws desyncs nothing and merely
	// watches. The first data packet is not a retransmission, so packets 1..3
	// carry two retransmissions: below the default threshold of three.
	for i := 0; i < 3; i++ {
		plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 49000, dport: 443, seq: 1001, ack: 1, payload: hello}))
		if err != nil {
			t.Fatalf("OnTCP: %v", err)
		}
		if hasSegs(plan) {
			t.Fatalf("data packet %d was desynced although a.example is not on the learned list yet", i+1)
		}
	}
	if al.Set().Match("a.example") {
		t.Fatal("two retransmissions already put the host on the list; the threshold is three")
	}
	// The fourth data packet is the third retransmission: it crosses the
	// threshold, the host is learned, and the very same packet is desynced.
	plan, err := e.OnTCP(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 49000, dport: 443, seq: 1001, ack: 1, payload: hello}))
	if err != nil {
		t.Fatalf("OnTCP: %v", err)
	}
	if !al.Set().Match("a.example") {
		t.Fatal("three client retransmissions did not put the host on the self-learning list")
	}
	if !hasSegs(plan) {
		t.Fatal("the host was learned but the profile still did not fire")
	}
	if f := flowState(t, e, keyOf(mkPkt(t, pktSpec{src: cli, dst: srv, sport: 49000, dport: 443, seq: 1001, ack: 1, payload: hello}))); f.ProfileIdx != 0 {
		t.Fatalf("flow settled on profile %d, want 0 once the host was learned", f.ProfileIdx)
	}
}
