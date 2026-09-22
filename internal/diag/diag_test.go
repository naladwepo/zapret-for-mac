package diag

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// Every test in this file is hermetic: no root, no network, no pf. The two
// exceptions (TestDetectLive, TestDetectAsRoot) skip themselves with a reason
// unless explicitly enabled, because they touch the live network stack.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// findFinding returns the first finding whose title contains want, or fails.
func findFinding(t *testing.T, fs []Finding, want string) Finding {
	t.Helper()
	for _, f := range fs {
		if strings.Contains(f.Title, want) {
			return f
		}
	}
	var titles []string
	for _, f := range fs {
		titles = append(titles, fmt.Sprintf("[%s] %s", f.Severity, f.Title))
	}
	t.Fatalf("no finding with title containing %q; got:\n%s", want, strings.Join(titles, "\n"))
	return Finding{}
}

// hasFinding reports whether any finding's title contains want.
func hasFinding(fs []Finding, want string) bool {
	for _, f := range fs {
		if strings.Contains(f.Title, want) {
			return true
		}
	}
	return false
}

// mustAddr parses an address in a test.
func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

// goodCaps is a Capabilities value describing a fully working machine.
func goodCaps() Capabilities {
	return Capabilities{
		Root: true, PfOK: true, PfEnabled: true, AnchorReachable: true,
		UtunOK: true, UtunName: "utun9", SteerOK: true, SteerTested: true,
		BpfWriteOK: true, RawOK: true, NatlookOK: true,
		Iface: "en0", MTU: 1500,
		OSVersion: "26.5.1", Darwin: "25.5.0", Arch: "arm64", SIP: "enabled",
	}
}

// ---------------------------------------------------------------------------
// Capabilities: transport selection and caps mapping
// ---------------------------------------------------------------------------

func TestCapabilitiesTransport(t *testing.T) {
	full := goodCaps()

	steerFailed := full
	steerFailed.SteerOK = false

	steerUntested := full
	steerUntested.SteerOK = false
	steerUntested.SteerTested = false

	noBPF := full
	noBPF.BpfWriteOK = false

	noBPFNoNatlook := noBPF
	noBPFNoNatlook.NatlookOK = false

	cases := []struct {
		name string
		c    Capabilities
		want string
	}{
		{"everything works", full, TransportDivert},
		{"steering unproven only because the anchor is unwired", steerUntested, TransportDivert},
		{"steering actively failed", steerFailed, TransportProxy},
		{"no BPF write", noBPF, TransportProxy},
		{"no BPF and no natlook", noBPFNoNatlook, TransportNone},
		{"not root", Capabilities{PfOK: true, UtunOK: true, BpfWriteOK: true}, TransportNone},
		{"no pf", Capabilities{Root: true, UtunOK: true, BpfWriteOK: true}, TransportNone},
		{"zero value", Capabilities{}, TransportNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.Transport(); got != tc.want {
				t.Fatalf("Transport() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCapabilitiesDesyncCaps(t *testing.T) {
	if got := goodCaps().DesyncCaps(); got != desync.FullCaps() {
		t.Fatalf("divert should map to FullCaps, got %+v", got)
	}
	proxy := goodCaps()
	proxy.SteerOK = false
	if got := proxy.DesyncCaps(); got != desync.ProxyCaps() {
		t.Fatalf("proxy should map to ProxyCaps, got %+v", got)
	}
	if got := (Capabilities{}).DesyncCaps(); got != (desync.Caps{}) {
		t.Fatalf("none should map to the zero Caps, got %+v", got)
	}
	// The zero Caps must satisfy nothing, or a "none" machine would silently run
	// a strategy.
	if (desync.Caps{}).Segment {
		t.Fatal("the zero Caps must not claim Segment")
	}
}

func TestAnchorStatementLines(t *testing.T) {
	got := AnchorStatementLines("zapret-mac")
	for _, want := range []string{`rdr-anchor "zapret-mac"`, `anchor "zapret-mac"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("AnchorStatementLines missing %q:\n%s", want, got)
		}
	}
	// The two statements must be on separate lines: macOS pf rejects a single
	// block that mixes the translation and filter sections.
	if len(strings.Split(strings.TrimSpace(got), "\n")) != 2 {
		t.Fatalf("expected exactly two lines, got:\n%s", got)
	}
}

func TestRulesetReferencesAnchor(t *testing.T) {
	live := `scrub-anchor "com.apple/*" all fragment reassemble
anchor "zapret-mac" all
anchor "com.apple/*" all
pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port = 443 no state`
	if !rulesetReferencesAnchor(live, "zapret-mac") {
		t.Fatal("should find our anchor")
	}
	if rulesetReferencesAnchor(live, "zapret") {
		t.Fatal("must not match a prefix of another anchor's name")
	}
	if !rulesetReferencesAnchor(`anchor "zapret-mac/probe" all`, "zapret-mac") {
		t.Fatal("a nested anchor path should count as a reference to its parent")
	}
	if rulesetReferencesAnchor("pass out all\n", "zapret-mac") {
		t.Fatal("a ruleset with no anchor statement must not match")
	}
}

func TestPickTunnelPairIsInOurPool(t *testing.T) {
	local, peer, _ := pickTunnelPair()
	if !ourTunnelPool.Contains(local) || !ourTunnelPool.Contains(peer) {
		t.Fatalf("pair %s -> %s is outside %s", local, peer, ourTunnelPool)
	}
	if peer != local.Next() {
		t.Fatalf("peer %s should be local+1 (%s)", peer, local.Next())
	}
}

func TestIPv4Dst(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[16:20], []byte{198, 51, 100, 7})
	got, ok := ipv4Dst(pkt)
	if !ok || got != mustAddr(t, "198.51.100.7") {
		t.Fatalf("ipv4Dst = %v, %v", got, ok)
	}
	if _, ok := ipv4Dst(pkt[:19]); ok {
		t.Fatal("a truncated packet must not parse")
	}
	pkt[0] = 0x60 // IPv6
	if _, ok := ipv4Dst(pkt); ok {
		t.Fatal("an IPv6 packet must not parse as IPv4")
	}
}

func TestCleanupStackUnwindsInReverse(t *testing.T) {
	var order []string
	var cl cleanupStack
	cl.push("first", func() error { order = append(order, "first"); return nil })
	cl.push("second", func() error { order = append(order, "second"); return errors.New("boom") })
	cl.push("third", func() error { order = append(order, "third"); return nil })

	var c Capabilities
	cl.run(&c)

	want := []string{"third", "second", "first"}
	if len(order) != len(want) {
		t.Fatalf("ran %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("ran %v, want %v", order, want)
		}
	}
	// A failing step must not stop the others, and must be reported.
	if len(c.Notes) != 1 || !strings.Contains(c.Notes[0], "second") {
		t.Fatalf("expected one note naming the failing step, got %v", c.Notes)
	}
	// run must be idempotent: a deferred run after an explicit one is common.
	cl.run(&c)
	if len(order) != 3 {
		t.Fatalf("second run re-executed steps: %v", order)
	}
}

func TestErrnoName(t *testing.T) {
	if got := errnoName(nil); got != "OK" {
		t.Fatalf("errnoName(nil) = %q", got)
	}
	if got := errnoName(syscall.ENOENT); !strings.HasPrefix(got, "ENOENT") {
		t.Fatalf("errnoName(ENOENT) = %q, want an ENOENT prefix", got)
	}
	if got := errnoName(errors.New("plain")); got != "plain" {
		t.Fatalf("errnoName(plain) = %q", got)
	}
	// Wrapped errnos must still be recognised: every syscall wrapper in this
	// package wraps with fmt.Errorf("%w").
	wrapped := fmt.Errorf("ioctl failed: %w", syscall.ENOTTY)
	if got := errnoName(wrapped); !strings.Contains(got, "ENOTTY") {
		t.Fatalf("errnoName(wrapped ENOTTY) = %q", got)
	}
}

// ---------------------------------------------------------------------------
// error classification
// ---------------------------------------------------------------------------

// timeoutError is a synthetic net.Error that reports a timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "synthetic i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ClassOK},

		{"net.Error timeout",
			&net.OpError{Op: "dial", Net: "tcp", Err: timeoutError{}}, ClassTimeout},
		{"deadline exceeded", context.DeadlineExceeded, ClassTimeout},
		{"os deadline", os.ErrDeadlineExceeded, ClassTimeout},
		{"ETIMEDOUT", &net.OpError{Op: "dial", Err: syscall.ETIMEDOUT}, ClassTimeout},

		{"ECONNRESET",
			&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, ClassReset},
		{"EPIPE", &net.OpError{Op: "write", Err: syscall.EPIPE}, ClassReset},
		{"reset text only", errors.New("read: connection reset by peer"), ClassReset},

		{"ECONNREFUSED",
			&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, ClassRefused},
		{"EHOSTUNREACH",
			&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, ClassUnreachable},
		{"ENETDOWN", &net.OpError{Op: "dial", Err: syscall.ENETDOWN}, ClassUnreachable},

		{"tls.RecordHeaderError",
			tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
			ClassTLSHandshake},
		{"wrapped tls.RecordHeaderError",
			fmt.Errorf("Get %q: %w", "https://x/",
				tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}),
			ClassTLSHandshake},
		{"tls.AlertError", tls.AlertError(40), ClassTLSAlert},
		{"tls.CertificateVerificationError",
			&tls.CertificateVerificationError{Err: errors.New("x509: unknown authority")},
			ClassTLSCert},

		{"DNS not found",
			&net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true},
			ClassDNSNotFound},
		{"DNS other failure",
			&net.DNSError{Err: "server misbehaving", Name: "x"},
			ClassDNS},
		{"DNS timeout is a DNS problem, not a DPI timeout",
			&net.DNSError{Err: "i/o timeout", Name: "x", IsTimeout: true},
			ClassDNS},

		{"canceled", context.Canceled, ClassCanceled},
		{"EOF", io.EOF, ClassEOF},
		{"unexpected EOF", io.ErrUnexpectedEOF, ClassEOF},
		{"unknown", errors.New("something else entirely"), ClassOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyError(tc.err); got != tc.want {
				t.Fatalf("ClassifyError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestBlockedClasses(t *testing.T) {
	for _, c := range []string{ClassTimeout, ClassReset, ClassTLSHandshake, ClassTLSAlert, ClassEOF} {
		if !Blocked(c) {
			t.Errorf("%s should count as a DPI signature", c)
		}
	}
	for _, c := range []string{ClassOK, ClassRefused, ClassDNS, ClassDNSNotFound,
		ClassUnreachable, ClassCanceled, ClassHTTPStatus, ClassBadURL, ClassOther} {
		if Blocked(c) {
			t.Errorf("%s must not count as a DPI signature", c)
		}
	}
}

// ---------------------------------------------------------------------------
// scoring and ranking, with injected probe results
// ---------------------------------------------------------------------------

// result builds a probe result for the scoring tests.
func result(name string, ok bool, class string, ttfb time.Duration, control bool) Result {
	return Result{
		Name: name, URL: "https://" + name + "/", Kind: "https", Control: control,
		OK: ok, Class: class, FirstByteTime: ttfb,
	}
}

func TestScoreResults(t *testing.T) {
	res := []Result{
		result("control", true, ClassOK, 30*time.Millisecond, true),
		result("youtube", true, ClassOK, 100*time.Millisecond, false),
		result("googlevideo", true, ClassOK, 300*time.Millisecond, false),
		result("discord", false, ClassReset, 0, false),
		result("gateway", false, ClassRefused, 0, false),
	}
	s := ScoreResults(res)
	if s.Targets != 4 {
		t.Fatalf("Targets = %d, want 4 (control probes must not be counted as targets)", s.Targets)
	}
	if s.Passed != 2 {
		t.Fatalf("Passed = %d, want 2", s.Passed)
	}
	if s.Blocked != 1 {
		t.Fatalf("Blocked = %d, want 1 (only the RST carries a DPI signature)", s.Blocked)
	}
	if s.ControlTotal != 1 || s.ControlPassed != 1 {
		t.Fatalf("control accounting = %d/%d, want 1/1", s.ControlPassed, s.ControlTotal)
	}
	// Median of [100ms, 300ms] takes the lower middle.
	if s.MedianFirstByte != 100*time.Millisecond {
		t.Fatalf("MedianFirstByte = %s, want 100ms", s.MedianFirstByte)
	}
	if !s.Valid() {
		t.Fatal("a passing control probe makes the measurement valid")
	}
	if s.Perfect() {
		t.Fatal("2/4 is not perfect")
	}
}

func TestScoreTLSOnlyProbeCountsHandshakeAsLatency(t *testing.T) {
	r := Result{Name: "gateway", Kind: "tls", OK: true, Class: ClassOK, TLSTime: 250 * time.Millisecond}
	s := ScoreResults([]Result{r})
	if s.Passed != 1 || s.MedianFirstByte != 250*time.Millisecond {
		t.Fatalf("score = %+v, want the handshake time used as latency", s)
	}
}

func TestScoreInvalidWhenControlFails(t *testing.T) {
	s := ScoreResults([]Result{
		result("control", false, ClassTimeout, 0, true),
		result("youtube", false, ClassTimeout, 0, false),
	})
	if s.Valid() {
		t.Fatal("a measurement whose control probe failed must be invalid")
	}
	if s.Perfect() {
		t.Fatal("an invalid measurement can never be perfect")
	}
}

func TestScorePerfectRequiresTargets(t *testing.T) {
	// No target probes at all must not count as a perfect score, or a
	// misconfigured probe list would win instantly.
	s := ScoreResults([]Result{result("control", true, ClassOK, time.Millisecond, true)})
	if s.Perfect() {
		t.Fatal("a run with no target probes must not be perfect")
	}
}

func TestScoreBetter(t *testing.T) {
	base := Score{Targets: 4, Passed: 2, ControlTotal: 1, ControlPassed: 1, MedianFirstByte: 200 * time.Millisecond}

	morePassed := base
	morePassed.Passed = 3

	fewerBlocked := base
	fewerBlocked.Blocked = 0
	blocked := base
	blocked.Blocked = 2

	faster := base
	faster.MedianFirstByte = 100 * time.Millisecond

	invalid := morePassed
	invalid.ControlPassed = 0

	if !morePassed.Better(base) {
		t.Error("more passing targets must win")
	}
	if base.Better(morePassed) {
		t.Error("Better must be asymmetric")
	}
	if !fewerBlocked.Better(blocked) {
		t.Error("fewer DPI-signature failures must win at equal pass counts")
	}
	if !faster.Better(base) {
		t.Error("lower latency must win at equal pass and block counts")
	}
	if invalid.Better(base) {
		t.Error("an invalid measurement must never outrank a valid one, even with more passes")
	}
	if base.Better(base) {
		t.Error("a score must not be better than itself")
	}
	// A zero median (nothing passed) must not sort ahead of a measured one.
	zero := Score{Targets: 2, ControlTotal: 1, ControlPassed: 1}
	measured := Score{Targets: 2, ControlTotal: 1, ControlPassed: 1, MedianFirstByte: time.Second}
	if zero.Better(measured) {
		t.Error("a zero median must not outrank a real one")
	}
}

func TestRankCandidates(t *testing.T) {
	mk := func(name string, passed int, ttfb time.Duration) Candidate {
		return Candidate{
			Name:      name,
			Supported: true,
			Results:   []Result{result("x", passed > 0, ClassOK, ttfb, false)},
			Score: Score{Targets: 2, Passed: passed, ControlTotal: 1, ControlPassed: 1,
				MedianFirstByte: ttfb},
		}
	}
	list := []Candidate{
		mk("slow-good", 2, 400*time.Millisecond),
		{Name: "skipped", Skipped: "unsupported"},
		mk("bad", 0, 0),
		mk("fast-good", 2, 90*time.Millisecond),
		mk("middling", 1, 50*time.Millisecond),
	}
	got := rankCandidates(list)
	want := []string{"fast-good", "slow-good", "middling", "bad", "skipped"}
	for i, w := range want {
		if got[i].Name != w {
			names := make([]string, len(got))
			for j, c := range got {
				names[j] = c.Name
			}
			t.Fatalf("rank = %v, want %v", names, want)
		}
	}
}

func TestRankDryRunPutsSupportedFirst(t *testing.T) {
	list := []Candidate{
		{Name: "needs-three", Unsupported: []string{"a", "b", "c"}},
		{Name: "clean-b", Supported: true},
		{Name: "needs-one", Unsupported: []string{"a"}},
		{Name: "clean-a", Supported: true},
	}
	got := rankDryRun(list)
	want := []string{"clean-a", "clean-b", "needs-one", "needs-three"}
	for i, w := range want {
		if got[i].Name != w {
			t.Fatalf("position %d = %q, want %q", i, got[i].Name, w)
		}
	}
}

func TestMedian(t *testing.T) {
	if got := median(nil); got != 0 {
		t.Fatalf("median(nil) = %s, want 0", got)
	}
	if got := median([]time.Duration{5}); got != 5 {
		t.Fatalf("median([5]) = %s", got)
	}
	if got := median([]time.Duration{30, 10, 20}); got != 20 {
		t.Fatalf("median([30,10,20]) = %s, want 20", got)
	}
	// Even count: the lower middle, so one 10s outlier cannot drag it.
	if got := median([]time.Duration{10, 20, 30, 10 * time.Second}); got != 20 {
		t.Fatalf("median = %s, want 20", got)
	}
}

func TestSummariseAndVerdict(t *testing.T) {
	all := []Result{
		result("control", true, ClassOK, 20*time.Millisecond, true),
		result("a", true, ClassOK, 40*time.Millisecond, false),
	}
	s := Summarise(all)
	if s.Total != 2 || s.Passed != 2 || s.Failed != 0 {
		t.Fatalf("summary = %+v", s)
	}
	if !strings.Contains(s.Verdict(), "all 2 probes passed") {
		t.Fatalf("verdict = %q", s.Verdict())
	}

	outage := Summarise([]Result{
		result("control", false, ClassTimeout, 0, true),
		result("a", false, ClassTimeout, 0, false),
	})
	if !strings.Contains(outage.Verdict(), "no working internet") {
		t.Fatalf("an all-control failure must be reported as an outage, got %q", outage.Verdict())
	}

	censored := Summarise([]Result{
		result("control", true, ClassOK, 20*time.Millisecond, true),
		result("a", false, ClassReset, 0, false),
	})
	if !strings.Contains(censored.Verdict(), "DPI signature") {
		t.Fatalf("verdict = %q", censored.Verdict())
	}

	local := Summarise([]Result{
		result("control", true, ClassOK, 20*time.Millisecond, true),
		result("a", false, ClassRefused, 0, false),
	})
	if !strings.Contains(local.Verdict(), "local cause") {
		t.Fatalf("verdict = %q", local.Verdict())
	}

	if got := Summarise(nil).Verdict(); !strings.Contains(got, "no probes") {
		t.Fatalf("verdict = %q", got)
	}
}

func TestTableRendersEveryResult(t *testing.T) {
	out := Table([]Result{
		result("zzz-ok", true, ClassOK, 10*time.Millisecond, false),
		result("aaa-bad", false, ClassReset, 0, false),
	})
	if !strings.Contains(out, "aaa-bad") || !strings.Contains(out, "zzz-ok") {
		t.Fatalf("table missing rows:\n%s", out)
	}
	// Failures come first, whatever the name order.
	if strings.Index(out, "aaa-bad") > strings.Index(out, "zzz-ok") {
		t.Fatalf("failures must be listed first:\n%s", out)
	}
	if !strings.Contains(out, "classes:") {
		t.Fatalf("table should summarise classes:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// probes and target parsing
// ---------------------------------------------------------------------------

func TestDefaultProbesShape(t *testing.T) {
	probes := DefaultProbes()
	if len(probes) < 10 {
		t.Fatalf("only %d default probes", len(probes))
	}
	var controls, tlsOnly, downloads int
	seen := map[string]bool{}
	for _, p := range probes {
		if seen[p.Name] {
			t.Errorf("duplicate probe name %q", p.Name)
		}
		seen[p.Name] = true
		if p.URL == "" {
			t.Errorf("probe %q has no URL", p.Name)
		}
		if p.Control {
			controls++
		}
		if p.Kind() == "tls" {
			tlsOnly++
		}
		if p.Download > 0 {
			downloads++
		}
	}
	if controls == 0 {
		t.Error("there must be a control host, or an outage is indistinguishable from censorship")
	}
	if tlsOnly == 0 {
		t.Error("gateway.discord.gg must be probed with a handshake only")
	}
	if downloads == 0 {
		t.Error("at least one probe must download, or throughput is never measured")
	}

	// The endpoints the task and flowseal's targets.txt both require.
	want := []string{
		"youtube.com", "youtubei.googleapis.com", "googlevideo.com",
		"discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net",
		"example.com",
	}
	all := ""
	for _, p := range probes {
		all += p.URL + " "
	}
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Errorf("default probes do not cover %s", w)
		}
	}
}

func TestProbeKind(t *testing.T) {
	cases := map[string]string{
		"https://x/":      "https",
		"tls://x:443":     "tls",
		"wss://x/socket":  "wss",
		"stun://x:19302":  "stun",
		"ping://1.1.1.1":  "tcp",
		"http://x/":       "https",
		"nonsense-string": "https",
	}
	for url, want := range cases {
		if got := (Probe{URL: url}).Kind(); got != want {
			t.Errorf("Kind(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestDiscordProbesCoverAppAndVoicePaths(t *testing.T) {
	probes := DiscordProbes()
	kinds := map[string]bool{}
	all := ""
	for _, p := range probes {
		kinds[p.Kind()] = true
		all += p.URL + " "
	}
	for _, kind := range []string{"https", "wss", "stun"} {
		if !kinds[kind] {
			t.Errorf("DiscordProbes has no %s probe", kind)
		}
	}
	for _, host := range []string{"discord.com", "gateway.discord.gg", "cdn.discordapp.com", "updates.discord.com"} {
		if !strings.Contains(all, host) {
			t.Errorf("DiscordProbes does not cover %s", host)
		}
	}
}

func TestParseTargets(t *testing.T) {
	// Verbatim excerpt of flowseal's utils/targets.txt.
	const upstream = `# targets.txt - endpoint list for zapret.ps1 tests
#
# Format:
#   KeyName = "https://host..."   -> Runs HTTP/TLS checks + ping
#   KeyName = "PING:1.2.3.4"       -> Ping only

### Discord
DiscordMain           = "https://discord.com"
DiscordGateway        = "https://gateway.discord.gg"

### YouTube
YouTubeVideoRedirect  = "https://redirector.googlevideo.com"

### Public DNS (PING-only)
CloudflareDNS1111     = "PING:1.1.1.1"
GoogleDNS8888         = "PING:8.8.8.8"
`
	probes, err := ParseTargets(strings.NewReader(upstream))
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	if len(probes) != 5 {
		t.Fatalf("parsed %d probes, want 5: %+v", len(probes), probes)
	}
	if probes[0].Name != "DiscordMain" || probes[0].URL != "https://discord.com" {
		t.Fatalf("first probe = %+v", probes[0])
	}
	ping := probes[3]
	if ping.URL != "ping://1.1.1.1:443" {
		t.Fatalf("PING entry became %q, want ping://1.1.1.1:443", ping.URL)
	}
	if !ping.Control {
		t.Fatal("a PING entry is a reachability control, so it must be marked Control")
	}
	if ping.Kind() != "tcp" {
		t.Fatalf("PING entry kind = %q", ping.Kind())
	}

	if _, err := ParseTargets(strings.NewReader("# only comments\n")); err == nil {
		t.Fatal("a file with no targets must be an error, not an empty success")
	}
}

func TestLoadTargetsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte(`A = "https://a.example/"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probes, err := LoadTargetsFile(path)
	if err != nil || len(probes) != 1 {
		t.Fatalf("LoadTargetsFile = %v, %v", probes, err)
	}
	if _, err := LoadTargetsFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Fatal("a missing file must be reported so the caller can fall back")
	}
}

func TestRunProbeReportsDialFailureWithoutNetwork(t *testing.T) {
	// A stub dialer keeps this hermetic: no name resolution, no packets.
	o := RunOpts{
		Timeout: time.Second,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET}
		},
	}
	res, err := Run(context.Background(), []Probe{
		{Name: "https", URL: "https://blocked.example/"},
		{Name: "tls", URL: "tls://blocked.example:443"},
		{Name: "tcp", URL: "ping://198.51.100.7:443"},
		{Name: "broken", URL: "https://%zz/"},
	}, o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res) != 4 {
		t.Fatalf("got %d results", len(res))
	}
	for i, r := range res[:3] {
		if r.OK {
			t.Errorf("result %d should have failed", i)
		}
		if r.Class != ClassReset {
			t.Errorf("result %d class = %q, want %q", i, r.Class, ClassReset)
		}
	}
	if res[3].Class != ClassBadURL {
		t.Errorf("a malformed URL should be %q, got %q (%s)", ClassBadURL, res[3].Class, res[3].Err)
	}
	// Results must stay in input order so a caller can zip them with its probes.
	if res[0].Name != "https" || res[3].Name != "broken" {
		t.Fatal("Run must preserve the input order")
	}
}

func TestRunHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, DefaultProbes(), RunOpts{}); err == nil {
		t.Fatal("Run on a cancelled context must not start probing")
	}
}

// ---------------------------------------------------------------------------
// DNS: comparison logic and the wire codec
// ---------------------------------------------------------------------------

func TestClassifyDNS(t *testing.T) {
	a := func(t *testing.T, ss ...string) []netip.Addr {
		t.Helper()
		out := make([]netip.Addr, 0, len(ss))
		for _, s := range ss {
			out = append(out, mustAddr(t, s))
		}
		return out
	}
	t.Run("identical", func(t *testing.T) {
		if got := ClassifyDNS(a(t, "142.250.1.1"), a(t, "142.250.1.1")); got != DNSOk {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("same /24 counts as agreement", func(t *testing.T) {
		if got := ClassifyDNS(a(t, "142.250.1.5"), a(t, "142.250.1.99")); got != DNSOk {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("blackholed to loopback", func(t *testing.T) {
		if got := ClassifyDNS(a(t, "127.0.0.1"), a(t, "142.250.1.1")); got != DNSPoisoned {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("blackholed to 0.0.0.0", func(t *testing.T) {
		if got := ClassifyDNS(a(t, "0.0.0.0"), nil); got != DNSPoisoned {
			t.Fatalf("poisoning must be detectable even when DoH is unreachable, got %q", got)
		}
	})
	t.Run("redirected to a private address", func(t *testing.T) {
		if got := ClassifyDNS(a(t, "10.1.2.3"), a(t, "142.250.1.1")); got != DNSPoisoned {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("system has no answer", func(t *testing.T) {
		if got := ClassifyDNS(nil, a(t, "142.250.1.1")); got != DNSMissing {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("both empty", func(t *testing.T) {
		if got := ClassifyDNS(nil, nil); got != DNSUnknown {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("doh unreachable", func(t *testing.T) {
		if got := ClassifyDNS(a(t, "142.250.1.1"), nil); got != DNSUnknown {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("legitimate CDN divergence", func(t *testing.T) {
		if got := ClassifyDNS(a(t, "142.250.1.1"), a(t, "216.58.200.9")); got != DNSDiffers {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("IPv6 agreement at /48", func(t *testing.T) {
		if got := ClassifyDNS(a(t, "2a00:1450:4010:c07::5e"), a(t, "2a00:1450:4010:c07::71")); got != DNSOk {
			t.Fatalf("got %q", got)
		}
	})
}

func TestDNSFindingSeverities(t *testing.T) {
	cases := []struct {
		name    string
		obs     DNSObservation
		wantSev string
	}{
		{"poisoned", DNSObservation{Name: "youtube.com",
			System: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			DoH:    []netip.Addr{netip.MustParseAddr("142.250.1.1")}}, SeverityError},
		{"missing", DNSObservation{Name: "youtube.com",
			DoH: []netip.Addr{netip.MustParseAddr("142.250.1.1")}}, SeverityWarn},
		{"differs", DNSObservation{Name: "youtube.com",
			System: []netip.Addr{netip.MustParseAddr("142.250.1.1")},
			DoH:    []netip.Addr{netip.MustParseAddr("216.58.200.9")}}, SeverityInfo},
		{"clean", DNSObservation{Name: "youtube.com",
			System: []netip.Addr{netip.MustParseAddr("142.250.1.1")},
			DoH:    []netip.Addr{netip.MustParseAddr("142.250.1.1")}}, SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := dnsFinding(tc.obs)
			if f.Severity != tc.wantSev {
				t.Fatalf("severity = %q, want %q (%s)", f.Severity, tc.wantSev, f.Detail)
			}
			if tc.wantSev != SeverityInfo && !strings.Contains(f.Fix, "Secure DNS") {
				t.Fatalf("an actionable DNS finding must recommend Secure DNS/DoH, got %q", f.Fix)
			}
		})
	}
}

// stubResolver answers from a fixed table, which is how the DoH-versus-system
// comparison is tested without touching the network. The call counter is atomic
// because compareResolvers looks every name up concurrently, which is part of
// the Resolver contract.
type stubResolver struct {
	name    string
	answers map[string][]netip.Addr
	errs    map[string]error
	calls   atomic.Int64
}

func (s *stubResolver) Describe() string { return s.name }

func (s *stubResolver) LookupA(_ context.Context, name string) ([]netip.Addr, error) {
	s.calls.Add(1)
	if err, ok := s.errs[name]; ok {
		return nil, err
	}
	return s.answers[name], nil
}

func TestCompareResolversWithStubs(t *testing.T) {
	sys := &stubResolver{
		name: "system",
		answers: map[string][]netip.Addr{
			"clean.example":    {netip.MustParseAddr("142.250.1.1")},
			"poisoned.example": {netip.MustParseAddr("0.0.0.0")},
		},
		errs: map[string]error{
			"broken.example": &net.DNSError{Err: "no such host", Name: "broken.example", IsNotFound: true},
		},
	}
	doh := &stubResolver{
		name: "DoH 1.1.1.1",
		answers: map[string][]netip.Addr{
			"clean.example":    {netip.MustParseAddr("142.250.1.1")},
			"poisoned.example": {netip.MustParseAddr("142.250.1.1")},
			"broken.example":   {netip.MustParseAddr("142.250.1.1")},
		},
	}
	names := []string{"clean.example", "poisoned.example", "broken.example"}
	obs := compareResolvers(context.Background(), DoctorOpts{
		DNSNames:       names,
		SystemResolver: sys,
		DoHResolver:    doh,
	}.withDefaults())

	if len(obs) != 3 {
		t.Fatalf("got %d observations", len(obs))
	}
	// Order must follow DNSNames, not completion order.
	for i, n := range names {
		if obs[i].Name != n {
			t.Fatalf("observation %d is %q, want %q", i, obs[i].Name, n)
		}
		if obs[i].DoHServer != "DoH 1.1.1.1" {
			t.Fatalf("observation %d does not name the DoH server: %q", i, obs[i].DoHServer)
		}
	}
	if got := ClassifyDNS(obs[0].System, obs[0].DoH); got != DNSOk {
		t.Errorf("clean.example = %q", got)
	}
	if got := ClassifyDNS(obs[1].System, obs[1].DoH); got != DNSPoisoned {
		t.Errorf("poisoned.example = %q", got)
	}
	if obs[2].SystemErr == "" {
		t.Error("a system-resolver failure must be recorded")
	}
	if got := ClassifyDNS(obs[2].System, obs[2].DoH); got != DNSMissing {
		t.Errorf("broken.example = %q", got)
	}
	if sys.calls.Load() != 3 || doh.calls.Load() != 3 {
		t.Errorf("each resolver should be asked once per name, got %d/%d",
			sys.calls.Load(), doh.calls.Load())
	}
}

func TestDoctorUsesInjectedResolvers(t *testing.T) {
	// A whole Doctor run driven by injected state, then one driven by injected
	// resolvers through the collected-state path would need root; here we only
	// assert that Analyze surfaces the DNS observations it is handed.
	st := SystemState{
		Caps:   goodCaps(),
		Anchor: "zapret-mac",
		DNS: []DNSObservation{{
			Name:      "discord.com",
			System:    []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			DoH:       []netip.Addr{netip.MustParseAddr("162.159.128.233")},
			DoHServer: "DoH 1.1.1.1",
		}},
	}
	f := Analyze(st)
	dns := findFinding(t, f, "forged")
	if dns.Severity != SeverityError {
		t.Fatalf("a forged DNS answer must be an error, got %q", dns.Severity)
	}
}

func TestEncodeDNSName(t *testing.T) {
	got, err := encodeDNSName("www.youtube.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{3, 'w', 'w', 'w', 7, 'y', 'o', 'u', 't', 'u', 'b', 'e', 3, 'c', 'o', 'm', 0}
	if string(got) != string(want) {
		t.Fatalf("encodeDNSName = %v, want %v", got, want)
	}
	for _, bad := range []string{"", ".", "a..b", strings.Repeat("x", 64) + ".com",
		strings.Repeat("a.", 200) + "com"} {
		if _, err := encodeDNSName(bad); err == nil {
			t.Errorf("encodeDNSName(%q) should have failed", bad)
		}
	}
}

func TestBuildDNSQuery(t *testing.T) {
	q, err := buildDNSQuery("example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != dnsHeaderLen+13+4 {
		t.Fatalf("query is %d bytes, want %d", len(q), dnsHeaderLen+13+4)
	}
	if q[2]&0x80 != 0 {
		t.Fatal("QR bit must be 0 for a query")
	}
	if q[2]&0x01 == 0 {
		t.Fatal("RD (recursion desired) must be set")
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Fatal("QDCOUNT must be 1")
	}
	if binary.BigEndian.Uint16(q[len(q)-4:len(q)-2]) != dnsTypeA {
		t.Fatal("QTYPE must be A")
	}
	if binary.BigEndian.Uint16(q[len(q)-2:]) != dnsClassIN {
		t.Fatal("QCLASS must be IN")
	}
	// Two queries must not share a transaction id (they are random).
	q2, _ := buildDNSQuery("example.com", dnsTypeA)
	if string(q[:2]) == string(q2[:2]) && string(q[:2]) == "\x00\x00" {
		t.Fatal("transaction id must be random, not zero")
	}
}

// dnsResponse builds a wire-format DNS response with a CNAME (skipped), an A and
// an AAAA record, using a compression pointer for every owner name — the exact
// shape a real resolver returns.
func dnsResponse(t *testing.T, rcode byte, withRecords bool) []byte {
	t.Helper()
	q, err := encodeDNSName("www.youtube.com")
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, dnsHeaderLen)
	msg[0], msg[1] = 0xab, 0xcd
	msg[2] = 0x81 // QR=1, RD=1
	msg[3] = 0x80 | rcode
	binary.BigEndian.PutUint16(msg[4:6], 1)
	an := 0
	if withRecords {
		an = 3
	}
	binary.BigEndian.PutUint16(msg[6:8], uint16(an))
	msg = append(msg, q...)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeA)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	if !withRecords {
		return msg
	}

	appendRR := func(rtype uint16, rdata []byte) {
		// Owner name as a compression pointer to the question at offset 12.
		msg = append(msg, 0xc0, byte(dnsHeaderLen))
		msg = binary.BigEndian.AppendUint16(msg, rtype)
		msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
		msg = binary.BigEndian.AppendUint32(msg, 300)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
	}
	cname, err := encodeDNSName("youtube-ui.l.google.com")
	if err != nil {
		t.Fatal(err)
	}
	appendRR(5, cname) // CNAME: must be skipped, not mistaken for an address
	appendRR(dnsTypeA, []byte{142, 250, 179, 174})
	v6 := netip.MustParseAddr("2a00:1450:4010:c07::5e").As16()
	appendRR(dnsTypeAAAA, v6[:])
	return msg
}

func TestParseDNSAnswers(t *testing.T) {
	addrs, err := parseDNSAnswers(dnsResponse(t, 0, true))
	if err != nil {
		t.Fatalf("parseDNSAnswers: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("got %d addresses (%v), want 2 — the CNAME must be skipped", len(addrs), addrs)
	}
	if addrs[0].String() != "142.250.179.174" {
		t.Fatalf("A record = %s", addrs[0])
	}
	if addrs[1].String() != "2a00:1450:4010:c07::5e" {
		t.Fatalf("AAAA record = %s", addrs[1])
	}
}

func TestParseDNSAnswersNXDomain(t *testing.T) {
	addrs, err := parseDNSAnswers(dnsResponse(t, 3, false))
	if err != nil {
		t.Fatalf("NXDOMAIN is a valid answer, not a parse error: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("got %v", addrs)
	}
}

func TestParseDNSAnswersRejectsGarbageWithoutPanicking(t *testing.T) {
	full := dnsResponse(t, 0, true)
	// Every truncation of a valid message must produce an error or an empty
	// answer, never a panic and never an out-of-range read.
	for i := 0; i < len(full); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseDNSAnswers panicked on a %d-byte prefix: %v", i, r)
				}
			}()
			_, _ = parseDNSAnswers(full[:i])
		}()
	}
	if _, err := parseDNSAnswers([]byte{1, 2, 3}); err == nil {
		t.Fatal("a 3-byte message must be rejected")
	}
	// A response claiming a server failure must be reported.
	if _, err := parseDNSAnswers(dnsResponse(t, 2, false)); err == nil {
		t.Fatal("SERVFAIL must be reported")
	}
	// A name made of nothing but a self-referential pointer must terminate:
	// skipDNSName never follows a pointer, so this cannot loop.
	loop := []byte{0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}
	if _, err := parseDNSAnswers(loop); err != nil && !strings.Contains(err.Error(), "truncated") {
		t.Logf("self-referential pointer rejected as %v (acceptable)", err)
	}
}

func TestIsImpossibleAnswer(t *testing.T) {
	bad := []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.1.1", "224.0.0.1", "::1", "fe80::1"}
	for _, s := range bad {
		if !isImpossibleAnswer(netip.MustParseAddr(s)) {
			t.Errorf("%s should be impossible for a public name", s)
		}
	}
	good := []string{"1.1.1.1", "142.250.1.1", "2a00:1450:4010:c07::5e", "100.64.0.1"}
	for _, s := range good {
		if isImpossibleAnswer(netip.MustParseAddr(s)) {
			t.Errorf("%s is routable and must not be flagged", s)
		}
	}
	if isImpossibleAnswer(netip.Addr{}) {
		t.Error("the invalid address must not be flagged (it carries no information)")
	}
}

func TestFallbackResolver(t *testing.T) {
	blocked := &stubResolver{
		name: "DoH 1.1.1.1",
		errs: map[string]error{"x.example": errors.New("TLS handshake timeout")},
	}
	working := &stubResolver{
		name:    "DoH 8.8.8.8",
		answers: map[string][]netip.Addr{"x.example": {netip.MustParseAddr("1.2.3.4")}},
	}
	f := FallbackResolver(blocked, working)

	// Describe names the chain; it must not pretend to know who will answer.
	if got := f.Describe(); got != "DoH 1.1.1.1 then DoH 8.8.8.8" {
		t.Fatalf("Describe = %q", got)
	}
	addrs, err := f.LookupA(context.Background(), "x.example")
	if err != nil {
		t.Fatalf("LookupA: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "1.2.3.4" {
		t.Fatalf("addrs = %v", addrs)
	}
	// A censor blocking 1.1.1.1 is common; the report must cite the resolver
	// that actually answered, per name and without shared state.
	sr, ok := f.(sourcedResolver)
	if !ok {
		t.Fatal("FallbackResolver must implement sourcedResolver so the report can name the answering resolver")
	}
	_, source, err := sr.LookupAFrom(context.Background(), "x.example")
	if err != nil || source != "DoH 8.8.8.8" {
		t.Fatalf("LookupAFrom source = %q, %v", source, err)
	}
	if blocked.calls.Load() != 2 || working.calls.Load() != 2 {
		t.Fatalf("calls = %d/%d, want both tried on each of the two lookups", blocked.calls.Load(), working.calls.Load())
	}

	// Every member failing must surface every reason.
	allBad := FallbackResolver(blocked, &stubResolver{
		name: "DoH 8.8.8.8",
		errs: map[string]error{"x.example": errors.New("connection reset")},
	})
	_, err = allBad.LookupA(context.Background(), "x.example")
	if err == nil {
		t.Fatal("all resolvers failing must be an error")
	}
	for _, want := range []string{"1.1.1.1", "8.8.8.8", "handshake", "reset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error missing %q: %v", want, err)
		}
	}

	// An empty answer is an answer (NXDOMAIN), not a reason to fall through.
	empty := &stubResolver{name: "empty"}
	second := &stubResolver{name: "second",
		answers: map[string][]netip.Addr{"y.example": {netip.MustParseAddr("9.9.9.9")}}}
	got, err := FallbackResolver(empty, second).LookupA(context.Background(), "y.example")
	if err != nil || len(got) != 0 {
		t.Fatalf("LookupA = %v, %v — an empty answer must be accepted as final", got, err)
	}
	if second.calls.Load() != 0 {
		t.Fatal("the second resolver must not be consulted after a successful empty answer")
	}

	if _, err := FallbackResolver().LookupA(context.Background(), "x"); err == nil {
		t.Fatal("an empty chain must be an error")
	}
}

func TestDefaultDoHServersAreIPLiterals(t *testing.T) {
	// The whole point is to reach the resolver without a prior DNS lookup, so a
	// hostname here would defeat the check.
	for _, s := range DefaultDoHServers() {
		if _, err := netip.ParseAddr(s); err != nil {
			t.Fatalf("DoH server %q is not an IP literal", s)
		}
	}
	if got := NewDoHResolver("1.1.1.1", 0).Describe(); got != "DoH 1.1.1.1" {
		t.Fatalf("Describe = %q", got)
	}
	if got := NewSystemResolver().Describe(); got != "system" {
		t.Fatalf("Describe = %q", got)
	}
}

// ---------------------------------------------------------------------------
// pf rule drift
// ---------------------------------------------------------------------------

func TestRuleFeatures(t *testing.T) {
	// What netcfg.SteerRules emits.
	want := netcfg.SteerRules(netcfg.SteerOpts{
		Utun: "utun9", TunPeer: "198.18.0.2",
		TCPPorts:   []netcfg.PortRange{{80, 80}, {443, 443}},
		UDPPorts:   []netcfg.PortRange{{443, 443}, {19294, 19344}},
		ExemptRoot: true,
	})
	feats := RuleFeatures(want)
	if len(feats) == 0 {
		t.Fatalf("no features extracted from:\n%s", want)
	}
	var sawTCP, sawUDP bool
	for _, f := range feats {
		if f.Via != "utun9 198.18.0.2" {
			continue
		}
		switch f.Proto {
		case "tcp":
			sawTCP = true
			if len(f.Ports) != 2 {
				t.Errorf("tcp rule ports = %v, want two entries", f.Ports)
			}
		case "udp":
			sawUDP = true
			if len(f.Ports) != 2 {
				t.Errorf("udp rule ports = %v, want two entries", f.Ports)
			}
			found := false
			for _, p := range f.Ports {
				if p == "19294:19344" {
					found = true
				}
			}
			if !found {
				t.Errorf("a port range must survive as a range token, got %v", f.Ports)
			}
		}
	}
	if !sawTCP || !sawUDP {
		t.Fatalf("features missing a protocol: %+v", feats)
	}
	// The table declaration is not a rule.
	for _, f := range RuleFeatures("table <zmx> persist\n") {
		t.Fatalf("a table declaration must not become a feature: %+v", f)
	}
}

func TestRulesDriftNoDriftAgainstPfctlRendering(t *testing.T) {
	want := "pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port { 80 443 } no state\n"
	// pfctl expands the port list into one rule per port and adds `= ` before a
	// single port. Both must still compare equal.
	have := "pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port = 80 no state\n" +
		"pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port = 443 no state\n"
	missing, extra := RulesDrift(want, have)
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("expected no drift, got missing=%v extra=%v", missing, extra)
	}
}

func TestRulesDriftDetectsEmptiedAnchor(t *testing.T) {
	want := "pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port { 80 443 } no state\n"
	missing, extra := RulesDrift(want, "")
	if len(missing) != 1 {
		t.Fatalf("missing = %v, want one entry (this is the pfctl -f wipe we must catch)", missing)
	}
	if len(extra) != 0 {
		t.Fatalf("extra = %v", extra)
	}
	if !strings.Contains(missing[0].String(), "utun9") {
		t.Fatalf("the report should name the target: %s", missing[0])
	}
}

func TestRulesDriftDetectsPartialPortLoss(t *testing.T) {
	want := "pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port { 80 443 } no state\n"
	have := "pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port = 443 no state\n"
	missing, _ := RulesDrift(want, have)
	if len(missing) != 1 {
		t.Fatalf("losing port 80 must be reported, got %v", missing)
	}
}

func TestRulesDriftPortCoveredByRange(t *testing.T) {
	want := "pass out quick route-to (utun9 198.18.0.2) inet proto udp from any to any port { 19300 } no state\n"
	have := "pass out quick route-to (utun9 198.18.0.2) inet proto udp from any to any port 19294:19344 no state\n"
	missing, _ := RulesDrift(want, have)
	if len(missing) != 0 {
		t.Fatalf("a wanted single port inside a loaded range is not drift, got %v", missing)
	}
}

func TestRulesDriftDetectsChangedTarget(t *testing.T) {
	want := "pass out quick route-to (utun9 198.18.0.2) inet proto tcp from any to any port = 443 no state\n"
	have := "pass out quick route-to (utun4 10.8.0.1) inet proto tcp from any to any port = 443 no state\n"
	missing, extra := RulesDrift(want, have)
	if len(missing) != 1 || len(extra) != 1 {
		t.Fatalf("a changed route-to target must be both missing and extra: missing=%v extra=%v", missing, extra)
	}
}

func TestRuleFeaturesRdrRule(t *testing.T) {
	rules := netcfg.RedirectRules(netcfg.RedirOpts{
		ListenPort: 10800,
		TCPPorts:   []netcfg.PortRange{{80, 80}, {443, 443}},
		ExemptRoot: true,
	})
	feats := RuleFeatures(rules)
	var rdr *RuleFeature
	for i := range feats {
		if feats[i].Action == "rdr" {
			rdr = &feats[i]
		}
	}
	if rdr == nil {
		t.Fatalf("no rdr feature extracted from:\n%s", rules)
	}
	if !strings.Contains(rdr.Via, "127.0.0.1") || !strings.Contains(rdr.Via, "10800") {
		t.Fatalf("rdr target = %q, want the listener address and port", rdr.Via)
	}
	if len(rdr.Ports) != 2 {
		t.Fatalf("rdr ports = %v, want 80 and 443", rdr.Ports)
	}
}

func TestIsPortToken(t *testing.T) {
	for _, ok := range []string{"1", "443", "65535", "19294:19344"} {
		if !isPortToken(ok) {
			t.Errorf("%q should be a port token", ok)
		}
	}
	for _, bad := range []string{"", "no", "state", "65536", ":", "443:", "a:b", "-1"} {
		if isPortToken(bad) {
			t.Errorf("%q must not be a port token", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Analyze: findings from injected state
// ---------------------------------------------------------------------------

// healthyState is a SystemState describing a machine with nothing wrong.
func healthyState() SystemState {
	want := netcfg.SteerRules(netcfg.SteerOpts{
		Utun: "utun9", TunPeer: "198.18.0.2",
		TCPPorts: []netcfg.PortRange{{443, 443}},
	})
	return SystemState{
		Caps:                 goodCaps(),
		UID:                  0,
		Anchor:               "zapret-mac",
		PfConfPath:           "/etc/pf.conf",
		PfEnabled:            true,
		PfEnabledKnown:       true,
		AnchorInPfConf:       true,
		AnchorReferencedLive: true,
		WantRules:            want,
		AnchorRules:          want,
		Iface:                "en0",
		MTU:                  1500,
		Strategy:             "general",
		DaemonRunning:        true,
		DaemonRunningKnown:   true,
	}
}

func TestAnalyzeHealthyMachineHasNoErrors(t *testing.T) {
	f := Analyze(healthyState())
	for _, x := range f {
		if x.Severity == SeverityError {
			t.Errorf("unexpected error on a healthy machine: %s — %s", x.Title, x.Detail)
		}
		if x.Severity == SeverityWarn {
			t.Errorf("unexpected warning on a healthy machine: %s — %s", x.Title, x.Detail)
		}
	}
	if !hasFinding(f, "Transport: divert") {
		t.Error("a healthy machine should report the divert transport")
	}
	if !hasFinding(f, "Machine") {
		t.Error("the environment summary should always be present")
	}
}

func TestAnalyzeEveryActionableFindingHasAFix(t *testing.T) {
	// A warning or error without a Fix is a dead end for the user, so the
	// invariant is enforced across a state that trips as many checks as possible.
	st := healthyState()
	st.Caps.TunnelDefaultRoute = "utun4"
	st.Caps.BpfWriteOK = false
	st.PfEnabled = false
	st.AnchorInPfConf = false
	st.AnchorReferencedLive = false
	st.AnchorRules = ""
	st.ForeignAnchors = []string{"foreign-tool"}
	st.Competing = []ProcessInfo{{PID: 42, Path: "/Applications/LuLu.app/LuLu", Tool: "LuLu",
		Why: "why", Fix: "fix"}}
	st.BusyPorts = []int{1080}
	st.DaemonRunning = false
	st.Journal = []netcfg.Entry{{Seq: 1, Step: netcfg.StepPfToken}}
	st.JournalPath = "/var/db/zapret-mac/journal.jsonl"
	st.PfToken = "12"
	st.PfTokenPath = "/var/db/zapret-mac/pf.token"
	st.OrphanUtuns = []string{"utun9"}
	st.MTU = 1492
	st.IPSets = []IPSetInfo{{Name: "ipset-all.txt", Any: true}}
	st.StrategyUnsupported = []string{"fake (needs inject, per-packet-ttl)"}
	st.CollectErrors = []string{"pfctl -s info: permission denied"}
	st.Hosts = HostsState{Path: "/etc/hosts", UpstreamPath: "/x/hosts",
		Upstream: []netcfg.HostEntry{{IP: netip.MustParseAddr("1.2.3.4"), Names: []string{"a.example"}}}}
	st.DNS = []DNSObservation{{Name: "discord.com",
		System: []netip.Addr{netip.MustParseAddr("0.0.0.0")},
		DoH:    []netip.Addr{netip.MustParseAddr("162.159.128.233")}}}

	f := Analyze(st)
	if len(f) < 12 {
		t.Fatalf("expected many findings, got %d", len(f))
	}
	for _, x := range f {
		if x.Severity == SeverityInfo {
			continue
		}
		if strings.TrimSpace(x.Fix) == "" {
			t.Errorf("[%s] %q has no Fix", x.Severity, x.Title)
		}
		if strings.TrimSpace(x.Detail) == "" {
			t.Errorf("[%s] %q has no Detail", x.Severity, x.Title)
		}
	}
	// Errors must be listed before warnings, warnings before info.
	last := -1
	for _, x := range f {
		r := severityRank(x.Severity)
		if r < last {
			t.Fatalf("findings are not ordered by severity: %q (%s) after rank %d", x.Title, x.Severity, last)
		}
		last = r
	}
}

func TestAnalyzeTunnelDefaultRoute(t *testing.T) {
	st := healthyState()
	st.Caps.TunnelDefaultRoute = "utun4"
	f := findFinding(t, Analyze(st), "VPN holds the default route")
	if f.Severity != SeverityError {
		t.Fatalf("severity = %q, want error", f.Severity)
	}
	for _, want := range []string{"utun4", "en0"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail should name %s: %s", want, f.Detail)
		}
	}
	if !strings.Contains(strings.ToLower(f.Detail), "bpf") {
		t.Errorf("the detail must explain that the BPF write targets the wrong link: %s", f.Detail)
	}
	if !strings.Contains(strings.ToLower(f.Fix), "split") {
		t.Errorf("the fix should mention split tunnelling: %s", f.Fix)
	}
}

func TestAnalyzeAnchorStates(t *testing.T) {
	t.Run("nowhere", func(t *testing.T) {
		st := healthyState()
		st.AnchorInPfConf, st.AnchorReferencedLive = false, false
		f := findFinding(t, Analyze(st), "not referenced anywhere")
		if f.Severity != SeverityError {
			t.Fatalf("severity = %q", f.Severity)
		}
		if !strings.Contains(f.Fix, `rdr-anchor "zapret-mac"`) {
			t.Fatalf("the fix must contain the exact line to add: %s", f.Fix)
		}
	})
	t.Run("live but not persisted", func(t *testing.T) {
		st := healthyState()
		st.AnchorInPfConf = false
		f := findFinding(t, Analyze(st), "live but not persisted")
		if f.Severity != SeverityWarn {
			t.Fatalf("severity = %q", f.Severity)
		}
	})
	t.Run("persisted but not loaded", func(t *testing.T) {
		st := healthyState()
		st.AnchorReferencedLive = false
		f := findFinding(t, Analyze(st), "not loaded")
		if f.Severity != SeverityError {
			t.Fatalf("severity = %q", f.Severity)
		}
		if !strings.Contains(f.Fix, "pfctl -f") {
			t.Fatalf("fix should suggest a reload: %s", f.Fix)
		}
	})
}

func TestAnalyzeRuleDrift(t *testing.T) {
	st := healthyState()
	st.AnchorRules = "" // something ran `pfctl -f /etc/pf.conf`
	f := findFinding(t, Analyze(st), "do not match the running strategy")
	if f.Severity != SeverityError {
		t.Fatalf("severity = %q", f.Severity)
	}
	if !strings.Contains(f.Fix, "reload") {
		t.Fatalf("fix = %q", f.Fix)
	}
}

func TestAnalyzeUnexpectedRules(t *testing.T) {
	st := healthyState()
	st.AnchorRules += "pass out quick route-to (utun4 10.0.0.1) inet proto tcp from any to any port = 8080 no state\n"
	f := findFinding(t, Analyze(st), "Unexpected rules")
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %q", f.Severity)
	}
}

func TestAnalyzeEmptyAnchorWithActiveStrategy(t *testing.T) {
	st := healthyState()
	st.WantRules = ""
	st.AnchorRules = ""
	st.AnchorNat = ""
	f := findFinding(t, Analyze(st), "anchor is empty")
	if f.Severity != SeverityError {
		t.Fatalf("severity = %q", f.Severity)
	}
}

func TestAnalyzeJournalDependsOnDaemonState(t *testing.T) {
	st := healthyState()
	st.Journal = []netcfg.Entry{
		{Seq: 1, Step: netcfg.StepPfToken, Data: map[string]string{"token": "3"}},
		{Seq: 2, Step: netcfg.StepPfConf},
		{Seq: 3, Step: netcfg.StepPfConf},
	}
	st.JournalPath = "/var/db/zapret-mac/journal.jsonl"

	live := findFinding(t, Analyze(st), "Rollback journal is not empty")
	if live.Severity != SeverityInfo {
		t.Fatalf("with the daemon running this is informational, got %q", live.Severity)
	}

	st.DaemonRunning = false
	dead := findFinding(t, Analyze(st), "Rollback journal is not empty")
	if dead.Severity != SeverityError {
		t.Fatalf("leftovers from a crashed daemon must be an error, got %q", dead.Severity)
	}
	if !strings.Contains(dead.Detail, "pf.conf x2") {
		t.Fatalf("the detail should summarise the steps: %s", dead.Detail)
	}
	if !strings.Contains(dead.Fix, "--repair") {
		t.Fatalf("fix = %q", dead.Fix)
	}
}

func TestAnalyzeStalePfToken(t *testing.T) {
	st := healthyState()
	st.PfToken = "7"
	st.PfTokenPath = "/var/db/zapret-mac/pf.token"

	if got := findFinding(t, Analyze(st), "pf reference held").Severity; got != SeverityInfo {
		t.Fatalf("a token held by a live daemon is informational, got %q", got)
	}
	st.DaemonRunning = false
	f := findFinding(t, Analyze(st), "Stale pf enable reference")
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %q", f.Severity)
	}
	if !strings.Contains(f.Fix, "pfctl -X 7") {
		t.Fatalf("the fix must name the exact command: %s", f.Fix)
	}
}

func TestAnalyzeOrphanUtun(t *testing.T) {
	st := healthyState()
	st.OrphanUtuns = []string{"utun9"}
	// A running daemon owns its utun, so nothing should be reported.
	if hasFinding(Analyze(st), "Orphaned tunnel") {
		t.Fatal("a running daemon's utun must not be reported as orphaned")
	}
	st.DaemonRunning = false
	f := findFinding(t, Analyze(st), "Orphaned tunnel")
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %q", f.Severity)
	}
	if !strings.Contains(f.Fix, "lsof") {
		t.Fatalf("the fix must explain how to find the holder: %s", f.Fix)
	}
}

func TestAnalyzeIPSetTriState(t *testing.T) {
	st := healthyState()
	st.IPSets = []IPSetInfo{
		{Name: "any.txt", Any: true},
		{Name: "none.txt", None: true, Count: 1},
		{Name: "loaded.txt", Count: 31337},
	}
	f := Analyze(st)

	anyF := findFinding(t, f, `ipset any.txt is in the "any" state`)
	if anyF.Severity != SeverityWarn {
		t.Fatalf("severity = %q", anyF.Severity)
	}
	if !strings.Contains(anyF.Detail, "never blocked") {
		t.Fatalf("the detail must explain that unrelated sites break: %s", anyF.Detail)
	}
	if got := findFinding(t, f, `none.txt is in the "none" state`).Severity; got != SeverityInfo {
		t.Fatalf(`"none" should be informational, got %q`, got)
	}
	if got := findFinding(t, f, "loaded.txt loaded").Detail; !strings.Contains(got, "31337") {
		t.Fatalf("detail = %q", got)
	}
}

func TestAnalyzeMTUAndOffload(t *testing.T) {
	st := healthyState()
	st.MTU = 1492
	f := findFinding(t, Analyze(st), "Unusual uplink MTU")
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %q", f.Severity)
	}
	if !strings.Contains(f.Detail, "split") {
		t.Fatalf("the detail must connect the MTU to split positions: %s", f.Detail)
	}

	st.MTU = 9000
	if !strings.Contains(findFinding(t, Analyze(st), "Unusual uplink MTU").Detail, "jumbo") {
		t.Error("a jumbo MTU should be described as such")
	}

	st = healthyState()
	st.TSO, st.TSOKnown = 1, true
	tso := findFinding(t, Analyze(st), "segmentation offload")
	if tso.Severity != SeverityInfo {
		t.Fatalf("severity = %q", tso.Severity)
	}
	if !strings.Contains(tso.Detail, "checksum") {
		t.Fatalf("detail = %q", tso.Detail)
	}
}

func TestAnalyzeCompetingTools(t *testing.T) {
	st := healthyState()
	st.Competing = []ProcessInfo{
		{PID: 501, Path: "/Library/Little Snitch/littlesnitchd", Tool: "Little Snitch",
			Why: "it installs a NetworkExtension content filter", Fix: "allow the daemon"},
	}
	st.BusyPorts = []int{1080, 10800}
	f := Analyze(st)

	ls := findFinding(t, f, "Little Snitch")
	if ls.Severity != SeverityWarn || !strings.Contains(ls.Detail, "501") {
		t.Fatalf("finding = %+v", ls)
	}
	ports := findFinding(t, f, "Another local proxy is listening")
	if !strings.Contains(ports.Detail, "1080, 10800") {
		t.Fatalf("detail = %q", ports.Detail)
	}
	if !strings.Contains(ports.Fix, "lsof") {
		t.Fatalf("fix = %q", ports.Fix)
	}
}

func TestAnalyzeForeignAnchors(t *testing.T) {
	st := healthyState()
	st.ForeignAnchors = []string{"zapret", "com.something.vpn"}
	f := findFinding(t, Analyze(st), "Foreign pf anchors")
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %q", f.Severity)
	}
	if !strings.Contains(f.Detail, "zapret") || !strings.Contains(f.Detail, "com.something.vpn") {
		t.Fatalf("detail = %q", f.Detail)
	}
	if !strings.Contains(f.Fix, "never edits foreign rules") {
		t.Fatalf("the fix must make clear we do not touch them: %s", f.Fix)
	}
}

func TestAnalyzeTransportDegradations(t *testing.T) {
	st := healthyState()
	st.Caps.SteerOK = false // steering was tested and failed
	proxy := findFinding(t, Analyze(st), "Transport: proxy")
	if proxy.Severity != SeverityWarn {
		t.Fatalf("severity = %q", proxy.Severity)
	}

	st.Caps = Capabilities{}
	none := findFinding(t, Analyze(st), "No transport can run")
	if none.Severity != SeverityError {
		t.Fatalf("severity = %q", none.Severity)
	}
	if !strings.Contains(none.Fix, "sudo") {
		t.Fatalf("a non-root machine should be told to use sudo: %s", none.Fix)
	}

	st.Caps = Capabilities{Root: true}
	rootNone := findFinding(t, Analyze(st), "No transport can run")
	if strings.Contains(rootNone.Fix, "run as root") {
		t.Fatalf("a root machine must not be told to become root: %s", rootNone.Fix)
	}
}

func TestAnalyzeSkippedCapabilityProbeIsNotAVerdict(t *testing.T) {
	// A zero Capabilities with the probe skipped must NOT be reported as "no
	// transport can run": the daemon, which knows its own transport, calls Doctor
	// with SkipDetect and would otherwise be told its working setup is broken.
	st := healthyState()
	st.Caps = Capabilities{}
	st.CapsProbeSkipped = true
	f := Analyze(st)
	if hasFinding(f, "No transport can run") {
		t.Fatal("a skipped probe must not produce a transport verdict")
	}
	if got := findFinding(t, f, "Capability probe was not run").Severity; got != SeverityInfo {
		t.Fatalf("severity = %q", got)
	}
	// Without the flag, the same zero value IS a verdict.
	st.CapsProbeSkipped = false
	if !hasFinding(Analyze(st), "No transport can run") {
		t.Fatal("a measured zero Capabilities must still be reported as an error")
	}
}

func TestAnalyzeCapabilityNotesSurface(t *testing.T) {
	st := healthyState()
	st.Caps.Notes = []string{"pf is currently disabled"}
	if !hasFinding(Analyze(st), "Capability note") {
		t.Fatal("capability notes must reach the report; they are the only explanation of a degraded verdict")
	}
}

func TestAnalyzeCollectErrorsAreReported(t *testing.T) {
	st := healthyState()
	st.CollectErrors = []string{"pfctl -s info: exit status 1"}
	f := findFinding(t, Analyze(st), "could not be performed")
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %q", f.Severity)
	}
	if !strings.Contains(f.Fix, "missing finding is not a passing one") {
		t.Fatalf("fix = %q", f.Fix)
	}
}

// ---------------------------------------------------------------------------
// /etc/hosts findings
// ---------------------------------------------------------------------------

func hostEntry(t *testing.T, ip string, names ...string) netcfg.HostEntry {
	t.Helper()
	return netcfg.HostEntry{IP: mustAddr(t, ip), Names: names}
}

func TestHostsFindings(t *testing.T) {
	upstream := []netcfg.HostEntry{
		hostEntry(t, "162.159.135.232", "discord.gg"),
		hostEntry(t, "185.199.108.133", "raw.githubusercontent.com"),
	}

	t.Run("not applied with upstream available", func(t *testing.T) {
		f := hostsFindings(HostsState{Path: "/etc/hosts", UpstreamPath: "/x/hosts", Upstream: upstream})
		got := findFinding(t, f, "Host pinning not applied")
		if got.Severity != SeverityWarn {
			t.Fatalf("severity = %q", got.Severity)
		}
		if !strings.Contains(got.Fix, "--apply") {
			t.Fatalf("fix = %q", got.Fix)
		}
	})

	t.Run("not applied and nothing to compare", func(t *testing.T) {
		f := hostsFindings(HostsState{Path: "/etc/hosts"})
		if got := findFinding(t, f, "Host pinning not applied").Severity; got != SeverityInfo {
			t.Fatalf("severity = %q", got)
		}
	})

	t.Run("current", func(t *testing.T) {
		f := hostsFindings(HostsState{Path: "/etc/hosts", UpstreamPath: "/x/hosts",
			Upstream: upstream, Applied: upstream})
		if got := findFinding(t, f, "applied and current").Severity; got != SeverityInfo {
			t.Fatalf("severity = %q", got)
		}
	})

	t.Run("stale", func(t *testing.T) {
		applied := []netcfg.HostEntry{
			hostEntry(t, "162.159.135.111", "discord.gg"), // upstream moved the address
		}
		f := hostsFindings(HostsState{Path: "/etc/hosts", UpstreamPath: "/x/hosts",
			Upstream: upstream, Applied: applied})
		got := findFinding(t, f, "stale")
		if got.Severity != SeverityWarn {
			t.Fatalf("severity = %q", got.Severity)
		}
		if !strings.Contains(got.Detail, "2 entries upstream has") ||
			!strings.Contains(got.Detail, "1 entry we have") {
			t.Fatalf("detail should count both directions: %s", got.Detail)
		}
	})

	t.Run("parse error reported", func(t *testing.T) {
		f := hostsFindings(HostsState{Path: "/etc/hosts", Applied: upstream, Err: "line 7: bad"})
		if got := findFinding(t, f, "could not be fully parsed").Severity; got != SeverityWarn {
			t.Fatalf("severity = %q", got)
		}
	})
}

func TestDiffHostEntries(t *testing.T) {
	applied := []netcfg.HostEntry{hostEntry(t, "1.1.1.1", "a.example", "b.example")}
	upstream := []netcfg.HostEntry{hostEntry(t, "1.1.1.1", "a.example"), hostEntry(t, "2.2.2.2", "c.example")}
	added, removed := diffHostEntries(applied, upstream)
	if len(added) != 1 || added[0] != "2.2.2.2 c.example" {
		t.Fatalf("added = %v", added)
	}
	if len(removed) != 1 || removed[0] != "1.1.1.1 b.example" {
		t.Fatalf("removed = %v", removed)
	}
	// Case must not matter: hosts files are case-insensitive.
	up := []netcfg.HostEntry{hostEntry(t, "1.1.1.1", "A.Example")}
	added, removed = diffHostEntries([]netcfg.HostEntry{hostEntry(t, "1.1.1.1", "a.example")}, up)
	if len(added) != 0 || len(removed) != 0 {
		t.Fatalf("case difference reported as drift: %v / %v", added, removed)
	}
}

// ---------------------------------------------------------------------------
// state collection helpers that need no privileges
// ---------------------------------------------------------------------------

func TestReadJournalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, netcfg.JournalName)

	// Missing file: not an error, so a first run reports nothing rather than
	// failing.
	if e, err := readJournalFile(path); err != nil || e != nil {
		t.Fatalf("missing journal = %v, %v", e, err)
	}

	content := `{"time":"2026-01-01T00:00:00Z","seq":2,"step":"hosts","data":{"path":"/etc/hosts"}}
{"time":"2026-01-01T00:00:00Z","seq":1,"step":"pf.token","data":{"token":"9"}}
not json at all
{"time":"2026-01-01T00:00:00Z","seq":3,"step":""}
{"time":"2026-01-01T00:00:00Z","seq":4,"step":"pf.rules"` // torn final line
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := readJournalFile(path)
	if err != nil {
		t.Fatalf("readJournalFile: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (junk, empty steps and a torn tail are skipped): %+v", len(entries), entries)
	}
	if entries[0].Seq != 1 || entries[0].Step != netcfg.StepPfToken {
		t.Fatalf("entries are not sorted by sequence: %+v", entries)
	}
	// Reading must not modify the file: a doctor run is read-only.
	after, err := os.ReadFile(path)
	if err != nil || string(after) != content {
		t.Fatal("readJournalFile must not rewrite the journal")
	}
}

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte("4711\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, err := readTokenFile(good); err != nil || tok != "4711" {
		t.Fatalf("readTokenFile = %q, %v", tok, err)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not-a-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(bad); err == nil {
		t.Fatal("a non-numeric token must be rejected, not passed to pfctl -X")
	}
	if _, err := readTokenFile(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("a missing token file should report NotExist, got %v", err)
	}
}

func TestMatchProcesses(t *testing.T) {
	ps := `  501 /usr/libexec/UserEventAgent
  502 /Applications/Little Snitch.app/Contents/Components/littlesnitchd
  503 /Library/Objective-See/LuLu.app/Contents/MacOS/LuLu
  504 /usr/local/bin/tpws
  505 /Users/x/Downloads/ciadpi
  506 /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder
  507 /Applications/Little Snitch.app/Contents/MacOS/Little Snitch Agent
  508
garbage line
`
	got := matchProcesses(ps)
	tools := map[string]bool{}
	for _, p := range got {
		tools[p.Tool] = true
		if p.Fix == "" || p.Why == "" {
			t.Errorf("%s has no Why/Fix", p.Tool)
		}
		if p.PID == 0 {
			t.Errorf("%s has no pid", p.Tool)
		}
	}
	for _, want := range []string{"Little Snitch", "LuLu", "zapret tpws", "ByeDPI (ciadpi)"} {
		if !tools[want] {
			t.Errorf("did not recognise %s in:\n%s", want, ps)
		}
	}
	// One entry per product, even though Little Snitch has two processes.
	count := 0
	for _, p := range got {
		if p.Tool == "Little Snitch" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Little Snitch reported %d times, want 1", count)
	}
	if len(matchProcesses("")) != 0 {
		t.Error("empty ps output must yield nothing")
	}
}

func TestBusyLocalPortsDetectsAListener(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback listener here: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	busy := busyLocalPorts([]int{port})
	if len(busy) != 1 || busy[0] != port {
		t.Fatalf("busyLocalPorts(%d) = %v, want the port reported busy", port, busy)
	}
	l.Close()
	// After closing, the port must not be reported (a lingering TIME_WAIT does
	// not prevent a fresh bind).
	if got := busyLocalPorts([]int{port}); len(got) != 0 {
		t.Fatalf("port %d still reported busy after close: %v", port, got)
	}
}

func TestLiveAnchorNames(t *testing.T) {
	out := `scrub-anchor "com.apple/*" all fragment reassemble
anchor "zapret-mac" all
anchor "com.apple/*" all
rdr-anchor "other-tool" all
pass out all`
	got := liveAnchorNames(out)
	want := map[string]bool{"com.apple": true, "zapret-mac": true, "other-tool": true}
	if len(got) != len(want) {
		t.Fatalf("liveAnchorNames = %v, want %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected anchor %q", n)
		}
	}
}

func TestFindOrphanUtunsRequiresJournalEvidence(t *testing.T) {
	// This is the guard against a very real false positive: AmneziaVPN, running
	// on the development machine, addresses its own utun 198.18.0.1 — the exact
	// address our probe prefers. Claiming it because of its address would make
	// the doctor tell a user to go kill their VPN.
	if got := findOrphanUtuns(nil); got != nil {
		t.Fatalf("with no journal evidence nothing may be claimed, got %v", got)
	}
	if got := findOrphanUtuns([]netcfg.Entry{{Seq: 1, Step: netcfg.StepPfToken}}); got != nil {
		t.Fatalf("a journal with no utun entry claims nothing, got %v", got)
	}
	// An entry naming an interface that does not exist is not reported either:
	// the process holding it exited, which is the normal outcome.
	got := findOrphanUtuns([]netcfg.Entry{
		{Seq: 1, Step: netcfg.StepUtun, Data: map[string]string{"iface": "utun9999"}},
	})
	if got != nil {
		t.Fatalf("a vanished interface must not be reported, got %v", got)
	}
	// An entry with no iface field must not panic or claim anything.
	if got := findOrphanUtuns([]netcfg.Entry{{Seq: 1, Step: netcfg.StepUtun}}); got != nil {
		t.Fatalf("an entry with no iface claims nothing, got %v", got)
	}
	// Whatever it does return must at least be a utun.
	for _, name := range findOrphanUtuns([]netcfg.Entry{
		{Seq: 1, Step: netcfg.StepUtun, Data: map[string]string{"iface": "utun0"}},
		{Seq: 2, Step: netcfg.StepUtun, Data: map[string]string{"iface": "utun4"}},
	}) {
		if !strings.HasPrefix(name, "utun") {
			t.Fatalf("findOrphanUtuns returned a non-utun interface %q", name)
		}
	}
}

func TestSummariseJournalAndJoinInts(t *testing.T) {
	got := summariseJournal([]netcfg.Entry{
		{Seq: 1, Step: netcfg.StepPfToken},
		{Seq: 2, Step: netcfg.StepHosts},
		{Seq: 3, Step: netcfg.StepHosts},
	})
	if got != "pf.token x1, hosts x2" {
		t.Fatalf("summariseJournal = %q", got)
	}
	if got := joinInts([]int{1, 2, 3}); got != "1, 2, 3" {
		t.Fatalf("joinInts = %q", got)
	}
}

func TestIPSetInfoState(t *testing.T) {
	cases := []struct {
		in   IPSetInfo
		want string
	}{
		{IPSetInfo{Any: true}, "any"},
		{IPSetInfo{None: true}, "none"},
		{IPSetInfo{Count: 5}, "loaded"},
		{IPSetInfo{}, "loaded"},
	}
	for _, tc := range cases {
		if got := tc.in.State(); got != tc.want {
			t.Errorf("State(%+v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFindingString(t *testing.T) {
	f := Finding{Severity: SeverityError, Title: "T", Detail: "D", Fix: "F"}
	s := f.String()
	for _, want := range []string{"[ERROR]", "T", "D", "fix: F"} {
		if !strings.Contains(s, want) {
			t.Fatalf("Finding.String() = %q, missing %q", s, want)
		}
	}
	if strings.Contains(Finding{Severity: SeverityInfo, Title: "T", Detail: "D"}.String(), "fix:") {
		t.Fatal("a finding without a fix must not print an empty fix line")
	}
	if f.OK() {
		t.Fatal("an error finding must not report OK")
	}
	if !(Finding{Severity: SeverityInfo}).OK() {
		t.Fatal("an info finding must report OK")
	}
	if (Finding{Severity: SeverityWarn}).OK() {
		t.Fatal("a warning must not report OK")
	}
}

func TestClientFuncsAdapter(t *testing.T) {
	var activated string
	c := ClientFuncs{
		ActivateFn: func(_ context.Context, name string) error { activated = name; return nil },
		ActiveFn:   func(context.Context) (string, error) { return "general", nil },
	}
	if err := c.Activate(context.Background(), "general (ALT)"); err != nil || activated != "general (ALT)" {
		t.Fatalf("Activate = %v, activated %q", err, activated)
	}
	if got, err := c.Active(context.Background()); err != nil || got != "general" {
		t.Fatalf("Active = %q, %v", got, err)
	}
	// A nil ActiveFn means "nothing to restore", not a failure.
	if got, err := (ClientFuncs{}).Active(context.Background()); err != nil || got != "" {
		t.Fatalf("Active on a zero ClientFuncs = %q, %v", got, err)
	}
	if err := (ClientFuncs{}).Activate(context.Background(), "x"); err == nil {
		t.Fatal("a nil ActivateFn must be an error")
	}
	// It must satisfy the interface Pick takes.
	var _ Client = ClientFuncs{}
}

// ---------------------------------------------------------------------------
// Doctor / Repair, driven by injected state
// ---------------------------------------------------------------------------

func TestDoctorUsesInjectedState(t *testing.T) {
	st := healthyState()
	st.Caps.TunnelDefaultRoute = "utun4"
	f, err := Doctor(context.Background(), DoctorOpts{State: &st})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	// Injected state means no machine access at all, so this passes unprivileged
	// and offline. That is exactly why DoctorOpts carries a State field.
	if !hasFinding(f, "VPN holds the default route") {
		t.Fatal("Doctor must analyse the state it was given")
	}
}

func TestRepairRefusesWhileDaemonRunning(t *testing.T) {
	yes := true
	f, err := Repair(context.Background(), DoctorOpts{DaemonRunning: &yes, StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	got := findFinding(t, f, "Refusing to repair")
	if got.Severity != SeverityError {
		t.Fatalf("severity = %q", got.Severity)
	}
	if !strings.Contains(got.Fix, "stop the daemon") {
		t.Fatalf("fix = %q", got.Fix)
	}
}

func TestRepairNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the not-root branch cannot be exercised")
	}
	no := false
	f, err := Repair(context.Background(), DoctorOpts{DaemonRunning: &no, StateDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	got := findFinding(t, f, "needs root")
	if got.Severity != SeverityError || !strings.Contains(got.Fix, "sudo") {
		t.Fatalf("finding = %+v", got)
	}
	// Nothing may have been attempted beyond the refusal.
	if len(f) != 1 {
		t.Fatalf("expected exactly the refusal, got %d findings", len(f))
	}
}

func TestRevertJournalStepUnreversibleStepsAreDropped(t *testing.T) {
	// These two branches must neither touch pf/hosts (nil here proves it) nor
	// return an error, because an error would keep the entry in the journal
	// forever and make every future Repair fail.
	for _, step := range []string{netcfg.StepUtun, netcfg.StepRoute, "some.future.step"} {
		desc, err := revertJournalStep(nil, nil, step, map[string]string{"iface": "utun9", "dst": "1.2.3.4"})
		if err != nil {
			t.Errorf("revertJournalStep(%q) = %v, want no error", step, err)
		}
		if desc == "" {
			t.Errorf("revertJournalStep(%q) returned no description", step)
		}
	}
}

func TestDefaultDNSCheckNames(t *testing.T) {
	names := DefaultDNSCheckNames()
	if len(names) == 0 {
		t.Fatal("there must be names to check")
	}
	for _, n := range names {
		if _, err := encodeDNSName(n); err != nil {
			t.Errorf("default name %q cannot be encoded: %v", n, err)
		}
	}
}

func TestDoctorOptsDefaults(t *testing.T) {
	o := DoctorOpts{}.withDefaults()
	if o.Anchor != DefaultProbeAnchor {
		t.Errorf("Anchor = %q", o.Anchor)
	}
	if o.PfConfPath != netcfg.DefaultPfConfPath || o.HostsPath != netcfg.DefaultHostsPath {
		t.Errorf("paths = %q / %q", o.PfConfPath, o.HostsPath)
	}
	if o.PfctlPath != netcfg.DefaultPfctlPath {
		t.Errorf("PfctlPath = %q", o.PfctlPath)
	}
	if len(o.DNSNames) == 0 || o.Timeout <= 0 || o.Logf == nil || o.HostsMarker == "" {
		t.Errorf("unset defaults: %+v", o)
	}
}

func TestDetectOptsDefaults(t *testing.T) {
	o := DetectOpts{}.withDefaults()
	if o.Anchor != DefaultProbeAnchor || o.Port != defaultProbePort {
		t.Errorf("defaults = %+v", o)
	}
	if o.Target.String() != defaultProbeTarget {
		t.Errorf("Target = %s, want %s (TEST-NET-2, so nothing real is contacted)", o.Target, defaultProbeTarget)
	}
	if !netip.MustParsePrefix("198.51.100.0/24").Contains(o.Target) {
		t.Error("the probe target must stay inside RFC 5737 documentation space")
	}
	if o.Timeout <= 0 || o.Logf == nil {
		t.Errorf("defaults = %+v", o)
	}
}

func TestRunOptsDefaults(t *testing.T) {
	o := RunOpts{}.withDefaults()
	if o.Concurrency <= 0 || o.Timeout <= 0 || o.Download <= 0 || o.Logf == nil {
		t.Fatalf("defaults = %+v", o)
	}
}

// ---------------------------------------------------------------------------
// autopick
// ---------------------------------------------------------------------------

// stubClient records activations and can fail on demand.
type stubClient struct {
	active      string
	activations []string
	failOn      map[string]error
	activeErr   error
}

func (c *stubClient) Activate(_ context.Context, name string) error {
	if err := c.failOn[name]; err != nil {
		return err
	}
	c.activations = append(c.activations, name)
	c.active = name
	return nil
}

func (c *stubClient) Active(context.Context) (string, error) {
	if c.activeErr != nil {
		return "", c.activeErr
	}
	return c.active, nil
}

// stubStrategies builds compiled-looking strategies with no ops, so
// Strategy.Unsupported reports nothing and the picker's support logic is exercised
// without compiling real op chains.
func stubStrategies(names ...string) []*strategy.Strategy {
	out := make([]*strategy.Strategy, 0, len(names))
	for _, n := range names {
		out = append(out, &strategy.Strategy{Name: n})
	}
	return out
}

func TestPickDryRunActivatesNothing(t *testing.T) {
	client := &stubClient{active: "general"}
	res, err := Pick(context.Background(), PickOpts{
		Strategies: stubStrategies("general", "general (ALT)", "general (ALT2)"),
		Caps:       desync.ProxyCaps(),
		Client:     client,
		DryRun:     true,
	})
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if len(client.activations) != 0 {
		t.Fatalf("a dry run must not activate anything, got %v", client.activations)
	}
	if !res.DryRun {
		t.Error("result should be marked as a dry run")
	}
	if len(res.Ranked) != 3 {
		t.Fatalf("ranked %d candidates, want 3", len(res.Ranked))
	}
	for _, c := range res.Ranked {
		if !c.Supported {
			t.Errorf("%s should be reported supported (it has no ops): %v", c.Name, c.Unsupported)
		}
		if c.Results != nil {
			t.Errorf("%s has probe results in a dry run", c.Name)
		}
	}
	if res.Best == "" {
		t.Error("a dry run should still nominate the first fully supported strategy")
	}
	if !strings.Contains(res.Table(), "dry run") {
		t.Errorf("table should say it was a dry run:\n%s", res.Table())
	}
}

func TestPickDryRunNeedsNoClient(t *testing.T) {
	if _, err := Pick(context.Background(), PickOpts{
		Strategies: stubStrategies("a"), DryRun: true,
	}); err != nil {
		t.Fatalf("a dry run must work without a Client: %v", err)
	}
}

func TestPickRequiresClient(t *testing.T) {
	if _, err := Pick(context.Background(), PickOpts{Strategies: stubStrategies("a")}); err == nil {
		t.Fatal("Pick without a Client must fail")
	}
}

func TestPickRequiresStrategies(t *testing.T) {
	if _, err := Pick(context.Background(), PickOpts{DryRun: true}); err == nil {
		t.Fatal("Pick with neither Strategies nor StrategyDir must fail")
	}
}

// failingDial makes every probe fail without touching the network.
func failingDial(context.Context, string, string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET}
}

func TestPickRestoresOriginalWhenNothingWorks(t *testing.T) {
	client := &stubClient{active: "general"}
	res, err := Pick(context.Background(), PickOpts{
		Strategies: stubStrategies("general (ALT)", "general (ALT2)"),
		Client:     client,
		Caps:       desync.FullCaps(),
		Probes:     []Probe{{Name: "target", URL: "https://blocked.example/"}},
		Run:        RunOpts{Timeout: time.Second, DialContext: failingDial},
		Settle:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if res.Best != "" {
		t.Fatalf("nothing should have won, got %q", res.Best)
	}
	if !res.Restored || client.active != "general" {
		t.Fatalf("the original strategy must be restored: restored=%v active=%q", res.Restored, client.active)
	}
	if res.Tested != 2 {
		t.Fatalf("Tested = %d, want 2", res.Tested)
	}
	if !strings.Contains(res.Table(), "no strategy passed") {
		t.Errorf("table should say nothing worked:\n%s", res.Table())
	}
}

func TestPickContinuesWhenControlProbesFail(t *testing.T) {
	client := &stubClient{active: "general"}
	res, err := Pick(context.Background(), PickOpts{
		Strategies: stubStrategies("a", "b", "c"),
		Client:     client,
		Caps:       desync.FullCaps(),
		Probes: []Probe{
			{Name: "control", URL: "https://example.com/", Control: true},
			{Name: "target", URL: "https://blocked.example/"},
		},
		Run:    RunOpts{Timeout: time.Second, DialContext: failingDial},
		Settle: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	// One transient control failure must not leave every remaining candidate as
	// a misleading 0/0 row.
	if res.Tested != 3 {
		t.Fatalf("Tested = %d, want 3: invalid candidates must be excluded without aborting the sweep", res.Tested)
	}
	if !res.Restored {
		t.Fatal("the original strategy must be restored")
	}
}

func TestPickRestoresOnCancellation(t *testing.T) {
	client := &stubClient{active: "general"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Pick(ctx, PickOpts{
		Strategies: stubStrategies("a", "b"),
		Client:     client,
		Caps:       desync.FullCaps(),
		Probes:     []Probe{{Name: "t", URL: "https://blocked.example/"}},
		Run:        RunOpts{Timeout: time.Second, DialContext: failingDial},
		Settle:     time.Millisecond,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Pick error = %v, want context.Canceled", err)
	}
	if len(client.activations) != 1 || client.activations[0] != "general" {
		t.Fatalf("the restore must run on a context detached from the cancellation, got %v", client.activations)
	}
	if !res.Restored {
		t.Fatal("result should record the restore")
	}
}

func TestPickSkipsUnsupportedWhenAsked(t *testing.T) {
	// A strategy with no ops is always supported, so fake the unsupported state
	// through the candidate list instead: SkipUnsupported is exercised via
	// rankDryRun elsewhere. Here we check the opposite guarantee — that an
	// unsupported strategy is still TESTED by default, because its splits alone
	// may work.
	client := &stubClient{active: "general"}
	res, err := Pick(context.Background(), PickOpts{
		Strategies: stubStrategies("a"),
		Client:     client,
		Caps:       desync.Caps{}, // nothing supported
		Probes:     []Probe{{Name: "t", URL: "https://blocked.example/"}},
		Run:        RunOpts{Timeout: time.Second, DialContext: failingDial},
		Settle:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if res.Tested != 1 {
		t.Fatalf("an unsupported strategy should still be measured by default, Tested = %d", res.Tested)
	}
}

func TestPickMaxCandidates(t *testing.T) {
	client := &stubClient{active: "general"}
	res, err := Pick(context.Background(), PickOpts{
		Strategies:    stubStrategies("a", "b", "c", "d"),
		Client:        client,
		Caps:          desync.FullCaps(),
		Probes:        []Probe{{Name: "t", URL: "https://blocked.example/"}},
		Run:           RunOpts{Timeout: time.Second, DialContext: failingDial},
		Settle:        time.Millisecond,
		MaxCandidates: 2,
	})
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if len(res.Ranked) != 2 {
		t.Fatalf("MaxCandidates ignored: %d candidates", len(res.Ranked))
	}
}

func TestPickActivationFailureIsRecordedNotFatal(t *testing.T) {
	client := &stubClient{active: "general", failOn: map[string]error{"broken": errors.New("no such strategy")}}
	res, err := Pick(context.Background(), PickOpts{
		Strategies: stubStrategies("broken", "ok"),
		Client:     client,
		Caps:       desync.FullCaps(),
		Probes:     []Probe{{Name: "t", URL: "https://blocked.example/"}},
		Run:        RunOpts{Timeout: time.Second, DialContext: failingDial},
		Settle:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	var broken *Candidate
	for i := range res.Ranked {
		if res.Ranked[i].Name == "broken" {
			broken = &res.Ranked[i]
		}
	}
	if broken == nil || broken.Err == "" || broken.Skipped == "" {
		t.Fatalf("the failed activation must be recorded on its candidate: %+v", broken)
	}
	if res.Tested != 1 {
		t.Fatalf("Tested = %d, want 1 (only the strategy that activated)", res.Tested)
	}
}

func TestApplyOrder(t *testing.T) {
	list := stubStrategies("a", "b", "c", "d")
	got := applyOrder(list, []string{"c", "a"})
	want := []string{"c", "a", "b", "d"}
	for i, w := range want {
		if got[i].Name != w {
			names := make([]string, len(got))
			for j, s := range got {
				names[j] = s.Name
			}
			t.Fatalf("applyOrder = %v, want %v", names, want)
		}
	}
	// No order given: the input order (flowseal's menu order) must survive.
	got = applyOrder(list, nil)
	for i, s := range got {
		if s.Name != list[i].Name {
			t.Fatalf("applyOrder(nil) reordered the list")
		}
	}
}

func TestPickProbesHaveAControl(t *testing.T) {
	var control int
	for _, p := range PickProbes() {
		if p.Control {
			control++
		}
	}
	if control == 0 {
		t.Fatal("the picker's probe set needs a control host, or an outage looks like a bad strategy")
	}
	if len(PickProbes()) > 6 {
		t.Fatalf("the picker's probe set is %d probes; it runs once per strategy, so keep it short", len(PickProbes()))
	}
}

func TestPickResultDetailIncludesPerProbeEvidence(t *testing.T) {
	res := PickResult{
		Best: "winner",
		Ranked: []Candidate{{
			Name:  "winner",
			Score: Score{Targets: 1, Passed: 1, ControlTotal: 1, ControlPassed: 1, MedianFirstByte: 20 * time.Millisecond},
			Results: []Result{{
				Name: "youtube.com", OK: true, Class: ClassOK, Status: 200,
				ServerIP: "142.250.179.174:443", FirstByteTime: 20 * time.Millisecond,
			}},
		}},
	}
	detail := res.Detail()
	for _, want := range []string{"winner", "youtube.com", "142.250.179.174"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("Detail() missing %q:\n%s", want, detail)
		}
	}
}

func TestScoreString(t *testing.T) {
	s := Score{Targets: 4, Passed: 3, ControlTotal: 1, MedianFirstByte: 120 * time.Millisecond}
	if !strings.Contains(s.String(), "3/4") {
		t.Fatalf("Score.String() = %q", s.String())
	}
	if !strings.Contains(s.String(), "INVALID") {
		t.Fatalf("an invalid score must say so: %q", s.String())
	}
}

// ---------------------------------------------------------------------------
// live probes — skipped unless explicitly enabled
// ---------------------------------------------------------------------------

func TestDetectLive(t *testing.T) {
	if os.Getenv("ZAPRET_DIAG_LIVE") != "1" {
		t.Skip("Detect touches the live network stack (it reads the routing table and may send one " +
			"ARP-priming datagram to the gateway); set ZAPRET_DIAG_LIVE=1 to run it")
	}
	caps, err := Detect(context.Background(), DetectOpts{SkipSteer: true, SkipBPFWrite: true})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	t.Logf("%s", caps.Summary())
	for _, n := range caps.Notes {
		t.Logf("note: %s", n)
	}
	if caps.Root != (os.Geteuid() == 0) {
		t.Fatalf("Root = %v but euid is %d", caps.Root, os.Geteuid())
	}
	if os.Geteuid() != 0 {
		if caps.Transport() != TransportNone {
			t.Fatalf("an unprivileged Detect must conclude %q, got %q", TransportNone, caps.Transport())
		}
		if len(caps.Notes) == 0 {
			t.Fatal("an unprivileged Detect must explain itself through Notes")
		}
	}
}

func TestDetectAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the full capability probe needs root: /dev/pf, /dev/bpfN and utun creation are all privileged")
	}
	if os.Getenv("ZAPRET_DIAG_LIVE") != "1" {
		t.Skip("the full capability probe creates a utun and loads a pf rule (both unwound before returning); " +
			"set ZAPRET_DIAG_LIVE=1 to run it")
	}
	// Snapshot the tunnel interfaces so a leak is detectable. findOrphanUtuns
	// deliberately needs journal evidence, which a probe never writes, so count
	// the interfaces directly here.
	utunsBefore := countUtuns(t)
	caps, err := Detect(context.Background(), DetectOpts{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	t.Logf("%s", caps.Summary())
	for _, n := range caps.Notes {
		t.Logf("note: %s", n)
	}
	if !caps.UtunOK {
		t.Error("a root probe should have been able to create a utun")
	}
	// The probe must leave nothing behind: the utun disappears with its control
	// socket, and the anchor is flushed back to empty.
	if after := countUtuns(t); after != utunsBefore {
		t.Fatalf("Detect leaked a tunnel interface: %d before, %d after", utunsBefore, after)
	}
	if caps.UtunName != "" {
		if ifaces, ierr := netcfg.Interfaces(); ierr == nil {
			if _, still := ifaces[caps.UtunName]; still {
				t.Fatalf("probe utun %s still exists", caps.UtunName)
			}
		}
	}
}

// countUtuns counts the tunnel interfaces currently present.
func countUtuns(t *testing.T) int {
	t.Helper()
	ifaces, err := netcfg.Interfaces()
	if err != nil {
		t.Fatalf("netcfg.Interfaces: %v", err)
	}
	n := 0
	for name := range ifaces {
		if strings.HasPrefix(name, "utun") {
			n++
		}
	}
	return n
}

func TestDoHResolverLive(t *testing.T) {
	if os.Getenv("ZAPRET_DIAG_LIVE") != "1" {
		t.Skip("the DoH resolver needs the network; set ZAPRET_DIAG_LIVE=1 to run it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, server := range DefaultDoHServers() {
		r := NewDoHResolver(server, 8*time.Second)
		addrs, err := r.LookupA(ctx, "www.youtube.com")
		if err != nil {
			t.Errorf("%s: %v", r.Describe(), err)
			continue
		}
		if len(addrs) == 0 {
			t.Errorf("%s returned no addresses for www.youtube.com", r.Describe())
			continue
		}
		t.Logf("%s -> %v", r.Describe(), addrs)
	}
}

func TestCollectStateLive(t *testing.T) {
	if os.Getenv("ZAPRET_DIAG_LIVE") != "1" {
		t.Skip("state collection runs pfctl, scans processes and compares resolvers; " +
			"set ZAPRET_DIAG_LIVE=1 to run it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	st, err := CollectState(ctx, DoctorOpts{
		StateDir:          t.TempDir(),
		UpstreamHostsPath: "../../.upstream/service/hosts",
		Detect:            DetectOpts{SkipSteer: true, SkipBPFWrite: true},
	})
	if err != nil {
		t.Fatalf("CollectState: %v", err)
	}
	for _, f := range Analyze(st) {
		t.Logf("%s", f)
	}
	if st.Hosts.UpstreamPath != "" && len(st.Hosts.Upstream) == 0 {
		t.Error("flowseal's service/hosts should have parsed into entries")
	}
}

func TestRunLive(t *testing.T) {
	if os.Getenv("ZAPRET_DIAG_LIVE") != "1" {
		t.Skip("the connectivity probes need the network; set ZAPRET_DIAG_LIVE=1 to run them")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Run(ctx, DefaultProbes(), RunOpts{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Logf("\n%s", Table(res))
}
