package diag

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Probe is one connectivity test.
//
// The URL scheme selects what is measured:
//
//	https://host/path   full request: TLS handshake, request, response, body
//	tls://host[:port]   TLS handshake only
//	wss://host/path     TLS plus a real WebSocket HTTP Upgrade
//	stun://host:port    UDP STUN binding request/response
//	ping://host[:port]  TCP reachability only, no TLS
//
// "ping" is a TCP connect, not ICMP: an unprivileged process cannot send ICMP
// echo, and TCP reachability to port 443 is what actually matters for a browser
// anyway. flowseal's targets.txt uses "PING:1.2.3.4" for exactly these entries.
type Probe struct {
	// Name is the label shown in the report.
	Name string
	// URL is the endpoint, with one of the schemes above.
	URL string
	// Expect is the HTTP status the probe should return. 0 accepts any complete
	// HTTP response, which is the right default: a censored connection produces
	// no response at all, while a working one may legitimately answer 200, 302,
	// 403 or 404 depending on the endpoint.
	Expect int
	// Timeout bounds this probe. 0 takes RunOpts.Timeout.
	Timeout time.Duration

	// Download is how many body bytes to read for a throughput measurement. 0
	// takes RunOpts.Download. Reading part of the body matters beyond
	// throughput: DPI frequently lets the handshake through and kills the
	// connection mid-stream, which only a body read can observe.
	Download int64

	// Control marks an endpoint that is not expected to be blocked. Its failure
	// means the machine has no working internet, not that the bypass failed —
	// the single most common misdiagnosis when a strategy "stops working".
	Control bool
}

// Kind returns the probe's measurement mode.
func (p Probe) Kind() string {
	switch {
	case strings.HasPrefix(p.URL, "wss://"):
		return "wss"
	case strings.HasPrefix(p.URL, "stun://"):
		return "stun"
	case strings.HasPrefix(p.URL, "tls://"):
		return "tls"
	case strings.HasPrefix(p.URL, "ping://"):
		return "tcp"
	default:
		return "https"
	}
}

// Error classes. The class, not the error text, is what tells a user whether DPI
// or something else is in the way: a timeout on the TLS handshake and an RST
// right after the ClientHello are both "blocked", but a DNS failure or a refused
// connection is a different problem entirely.
const (
	// ClassOK means the probe completed.
	ClassOK = "ok"
	// ClassTimeout is a deadline expiry: the classic silent-drop DPI signature.
	ClassTimeout = "timeout"
	// ClassReset is ECONNRESET/EPIPE — an injected RST, the other classic DPI
	// signature.
	ClassReset = "rst"
	// ClassRefused is ECONNREFUSED: something answered, and it said no. Not DPI.
	ClassRefused = "refused"
	// ClassTLSHandshake is a malformed TLS record where a handshake was
	// expected, i.e. something injected bytes into the stream.
	ClassTLSHandshake = "tls-handshake"
	// ClassTLSAlert is a TLS alert from the peer.
	ClassTLSAlert = "tls-alert"
	// ClassTLSCert is certificate verification failure — a TLS interceptor.
	ClassTLSCert = "tls-cert"
	// ClassDNS is a resolver failure; ClassDNSNotFound is specifically NXDOMAIN,
	// which on a blocked name usually means DNS-level blocking.
	ClassDNS         = "dns"
	ClassDNSNotFound = "dns-nxdomain"
	// ClassUnreachable is EHOSTUNREACH/ENETUNREACH/ENETDOWN: no route.
	ClassUnreachable = "unreachable"
	// ClassEOF is a connection closed without an answer.
	ClassEOF = "eof"
	// ClassCanceled means the caller gave up, not the network.
	ClassCanceled = "canceled"
	// ClassHTTPStatus means the request completed but the status was not the
	// expected one.
	ClassHTTPStatus = "http-status"
	// ClassBadURL means the probe itself is malformed.
	ClassBadURL = "bad-url"
	// ClassOther is anything unrecognised.
	ClassOther = "other"
)

// Result is one probe's outcome.
type Result struct {
	// Name and URL identify the probe; Kind is its measurement mode and Control
	// mirrors Probe.Control.
	Name    string
	URL     string
	Kind    string
	Control bool

	// OK is the verdict: the endpoint answered as expected.
	OK bool
	// Status is the HTTP status code, 0 for a non-HTTP probe or a failure.
	Status int

	// ServerIP is the address actually connected to, which is the per-IP detail
	// that explains why one strategy wins on one CDN front end and not another.
	ServerIP string
	// SNI is the name sent in the TLS handshake — what the DPI matches on.
	SNI string
	// TLSVersion and ALPN describe the negotiated connection.
	TLSVersion string
	ALPN       string

	// DNSTime, ConnectTime, TLSTime, FirstByteTime and TotalTime are cumulative
	// from the start of the probe, except TLSTime which is the handshake's own
	// duration (that is the number a desync strategy changes).
	DNSTime       time.Duration
	ConnectTime   time.Duration
	TLSTime       time.Duration
	FirstByteTime time.Duration
	TotalTime     time.Duration

	// Bytes is how many body bytes were read and BytesPerSec the rate over the
	// interval they took. BytesPerSec is 0 when nothing was downloaded.
	Bytes       int64
	BytesPerSec float64

	// Class is one of the Class* constants, and Err the underlying error text.
	Class string
	Err   string
}

// String renders a result on one line.
func (r Result) String() string {
	status := "FAIL"
	if r.OK {
		status = "ok"
	}
	s := fmt.Sprintf("%-24s %-4s %-14s", r.Name, status, r.Class)
	if r.Status != 0 {
		s += fmt.Sprintf(" HTTP %d", r.Status)
	}
	if r.TLSTime > 0 {
		s += fmt.Sprintf(" tls %s", r.TLSTime.Round(time.Millisecond))
	}
	if r.FirstByteTime > 0 {
		s += fmt.Sprintf(" ttfb %s", r.FirstByteTime.Round(time.Millisecond))
	}
	if r.BytesPerSec > 0 {
		s += fmt.Sprintf(" %.0f KiB/s", r.BytesPerSec/1024)
	}
	if r.ServerIP != "" {
		s += " via " + r.ServerIP
	}
	if r.Err != "" {
		s += " — " + r.Err
	}
	return s
}

// RunOpts configures Run.
type RunOpts struct {
	// Concurrency bounds how many probes run at once. Defaults to 4: enough to
	// keep the wall-clock short, low enough that the probes do not compete for
	// the same uplink and distort each other's timings.
	Concurrency int
	// Timeout is the default per-probe deadline. Defaults to 10s.
	Timeout time.Duration
	// Download is the default number of body bytes to read. Defaults to 16 KiB.
	Download int64
	// DialContext overrides the dialer, which is how the tests avoid the
	// network entirely.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Logf receives one line per finished probe.
	Logf func(format string, args ...any)
}

// withDefaults fills in the unset fields.
func (o RunOpts) withDefaults() RunOpts {
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Download <= 0 {
		o.Download = 16 * 1024
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// DefaultProbes is the target list.
//
// The endpoints come from flowseal's own utils/targets.txt (fetched from
// Flowseal/zapret-discord-youtube at main while writing this), which is the list
// its zapret.ps1 checks after applying a strategy:
//
//	discord.com, gateway.discord.gg, cdn.discordapp.com, updates.discord.com,
//	www.youtube.com, youtu.be, i.ytimg.com, redirector.googlevideo.com,
//	www.google.com, www.gstatic.com, www.cloudflare.com, cdnjs.cloudflare.com,
//	plus PING-only entries for 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4 and 9.9.9.9.
//
// Three additions the upstream list does not have:
//
//   - media.discordapp.net and youtubei.googleapis.com, both of which are
//     separately blocked in practice and appear in flowseal's own hostlists;
//   - example.com as an explicit CONTROL host, so a total outage is
//     distinguishable from censorship. Without it every failure looks like the
//     strategy's fault.
//
// redirector.googlevideo.com stands in for a playback URL: a real
// googlevideo.com playback URL carries a signature that expires within hours, so
// it cannot live in a static list, and what the DPI actually matches on is the
// SNI — which is identical.
//
// ParseTargets reads the upstream format directly, so a caller that ships
// targets.txt can use it verbatim instead of this list.
func DefaultProbes() []Probe {
	const dl = 32 * 1024
	return []Probe{
		// Control first: if this fails, nothing below means anything.
		{Name: "control example.com", URL: "https://example.com/", Control: true, Expect: 200},

		{Name: "youtube.com", URL: "https://www.youtube.com/", Download: dl},
		{Name: "youtubei api", URL: "https://youtubei.googleapis.com/"},
		{Name: "googlevideo (playback)", URL: "https://redirector.googlevideo.com/", Download: dl},
		{Name: "i.ytimg.com", URL: "https://i.ytimg.com/", Download: dl},
		{Name: "youtu.be", URL: "https://youtu.be/"},

		{Name: "discord.com", URL: "https://discord.com/"},
		// A WebSocket endpoint: it never answers a plain GET, so only the
		// handshake is measured — which is the part DPI blocks anyway.
		{Name: "gateway.discord.gg", URL: "tls://gateway.discord.gg:443"},
		{Name: "cdn.discordapp.com", URL: "https://cdn.discordapp.com/", Download: dl},
		{Name: "media.discordapp.net", URL: "https://media.discordapp.net/", Download: dl},
		{Name: "updates.discord.com", URL: "https://updates.discord.com/"},

		{Name: "google.com", URL: "https://www.google.com/"},
		{Name: "gstatic.com", URL: "https://www.gstatic.com/", Download: dl},
		{Name: "cloudflare.com", URL: "https://www.cloudflare.com/"},
		{Name: "cdnjs.cloudflare.com", URL: "https://cdnjs.cloudflare.com/", Download: dl},

		// Reachability of the public resolvers, as flowseal's PING entries do.
		{Name: "dns 1.1.1.1", URL: "ping://1.1.1.1:443", Control: true},
		{Name: "dns 8.8.8.8", URL: "ping://8.8.8.8:443", Control: true},
	}
}

// DiscordProbes exercises the desktop client's network paths without launching
// it. The public STUN peer is intentionally on UDP/19302: this traverses the
// same Flowseal UDP port window and l7=stun profile used for Discord voice.
func DiscordProbes() []Probe {
	const dl = 32 * 1024
	return []Probe{
		{Name: "control example.com", URL: "https://example.com/", Control: true, Expect: 200},
		{Name: "discord API", URL: "https://discord.com/api/v10/gateway"},
		{Name: "discord Gateway WSS", URL: "wss://gateway.discord.gg/?v=10&encoding=json"},
		{Name: "discord invite", URL: "https://discord.gg/"},
		{Name: "discord CDN", URL: "https://cdn.discordapp.com/", Download: dl},
		{Name: "discord media", URL: "https://media.discordapp.net/", Download: dl},
		{Name: "discord updater", URL: "https://updates.discord.com/"},
		{Name: "discord stable updater", URL: "https://stable.dl2.discordapp.net/"},
		{Name: "UDP/STUN voice path", URL: "stun://stun.l.google.com:19302"},
	}
}

// reTargetsLine is deliberately not a regexp: the upstream format is
// `Key = "value"` with '#' comments, which Cut handles without a dependency.

// ParseTargets reads flowseal's utils/targets.txt format:
//
//	### section comment
//	DiscordMain  = "https://discord.com"
//	CloudflareDNS1111 = "PING:1.1.1.1"
//
// Unrecognised lines are skipped rather than rejected, because the upstream file
// is documentation as much as data. The returned probes carry the key as their
// name; PING entries become "ping://host:443" and everything else keeps its URL.
// A "PING:" entry is marked Control, since upstream only uses it for endpoints
// that are never blocked.
func ParseTargets(r io.Reader) ([]Probe, error) {
	var out []Probe
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"`)
		if key == "" || val == "" {
			continue
		}
		switch {
		case strings.HasPrefix(val, "PING:"):
			host := strings.TrimSpace(strings.TrimPrefix(val, "PING:"))
			if host == "" {
				continue
			}
			out = append(out, Probe{Name: key, URL: "ping://" + host + ":443", Control: true})
		case strings.HasPrefix(val, "https://"), strings.HasPrefix(val, "http://"),
			strings.HasPrefix(val, "tls://"), strings.HasPrefix(val, "ping://"):
			out = append(out, Probe{Name: key, URL: val})
		}
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("diag: reading targets: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("diag: no usable targets found")
	}
	return out, nil
}

// LoadTargetsFile reads a targets.txt from disk. A missing file is reported so
// the caller can fall back to DefaultProbes.
func LoadTargetsFile(path string) ([]Probe, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseTargets(f)
}

// Run executes probes concurrently, bounded by o.Concurrency, and returns one
// Result per probe in the order the probes were given.
//
// Every probe gets a brand-new connection with keep-alives disabled and HTTP/2
// switched off:
//
//   - a reused connection would skip the TLS handshake, and the handshake is the
//     only part of the exchange a desync strategy affects, so timings from a
//     pooled connection are meaningless;
//   - HTTP/2 is refused so that a result cannot depend on which protocol the
//     server negotiated, and QUIC never enters the picture at all (net/http
//     speaks only TCP) — otherwise a working QUIC path would silently rescue a
//     TCP strategy that does not work, which is exactly the illusion this test
//     exists to break;
//   - redirects are never followed: a 302 is a complete answer, and following it
//     would silently measure a different host than the one under test.
//
// The returned error is non-nil only when ctx was already done. A probe that
// fails is reported in its Result, never as an error.
func Run(ctx context.Context, probes []Probe, o RunOpts) ([]Result, error) {
	o = o.withDefaults()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := make([]Result, len(probes))
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p Probe) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = Result{
					Name: p.Name, URL: p.URL, Kind: p.Kind(), Control: p.Control,
					Class: ClassCanceled, Err: ctx.Err().Error(),
				}
				return
			}
			defer func() { <-sem }()
			results[i] = RunProbe(ctx, p, o)
			o.Logf("diag: %s", results[i])
		}(i, p)
	}
	wg.Wait()
	return results, nil
}

// RunProbe executes one probe. It is exported so a caller can retry a single
// endpoint without rebuilding a list.
func RunProbe(ctx context.Context, p Probe, o RunOpts) Result {
	o = o.withDefaults()
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = o.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := Result{Name: p.Name, URL: p.URL, Kind: p.Kind(), Control: p.Control}
	switch res.Kind {
	case "tcp":
		runTCPProbe(ctx, p, o, &res)
	case "tls":
		runTLSProbe(ctx, p, o, &res)
	case "wss":
		runWebSocketProbe(ctx, p, o, &res)
	case "stun":
		runSTUNProbe(ctx, p, &res)
	default:
		runHTTPProbe(ctx, p, o, &res)
	}
	return res
}

// runWebSocketProbe verifies the HTTP Upgrade after TLS; a TLS-only check can
// pass even when an intermediary kills the Gateway protocol transition.
func runWebSocketProbe(ctx context.Context, p Probe, o RunOpts, res *Result) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Hostname() == "" {
		res.Class, res.Err = ClassBadURL, "bad WebSocket URL: "+p.URL
		return
	}
	host, addr := u.Hostname(), u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(host, "443")
	}
	res.SNI = host
	start := time.Now()
	conn, err := o.dial(ctx, addr)
	res.ConnectTime = time.Since(start)
	if err != nil {
		res.Class, res.Err, res.TotalTime = ClassifyError(err), err.Error(), time.Since(start)
		return
	}
	defer conn.Close()
	if ra := conn.RemoteAddr(); ra != nil {
		res.ServerIP = ra.String()
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}})
	hsStart := time.Now()
	if err := tc.HandshakeContext(ctx); err != nil {
		res.TLSTime, res.TotalTime = time.Since(hsStart), time.Since(start)
		res.Class, res.Err = ClassifyError(err), err.Error()
		return
	}
	res.TLSTime = time.Since(hsStart)
	st := tc.ConnectionState()
	res.TLSVersion, res.ALPN = tlsVersionName(st.Version), st.NegotiatedProtocol
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"Origin: https://discord.com\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		res.Class, res.Err, res.TotalTime = ClassifyError(err), err.Error(), time.Since(start)
		return
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	res.FirstByteTime, res.TotalTime = time.Since(start), time.Since(start)
	if err != nil {
		res.Class, res.Err = ClassifyError(err), err.Error()
		return
	}
	var proto string
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%s %d", &proto, &res.Status); err != nil {
		res.Class, res.Err = ClassOther, "malformed WebSocket response: "+strings.TrimSpace(line)
		return
	}
	if res.Status != http.StatusSwitchingProtocols {
		res.Class, res.Err = ClassHTTPStatus, fmt.Sprintf("expected HTTP 101, got %d", res.Status)
		return
	}
	res.OK, res.Class = true, ClassOK
}

// runSTUNProbe sends a UDP binding request and validates the transaction ID.
func runSTUNProbe(ctx context.Context, p Probe, res *Result) {
	_, addr, err := hostPort(p.URL, "3478")
	if err != nil {
		res.Class, res.Err = ClassBadURL, err.Error()
		return
	}
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", addr)
	res.ConnectTime = time.Since(start)
	if err != nil {
		res.Class, res.Err, res.TotalTime = ClassifyError(err), err.Error(), time.Since(start)
		return
	}
	defer conn.Close()
	if ra := conn.RemoteAddr(); ra != nil {
		res.ServerIP = ra.String()
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tx := [12]byte{0x7a, 0x61, 0x70, 0x72, 0x65, 0x74, 0x2d, 0x6d, 0x61, 0x63, 0x01, 0x00}
	req := make([]byte, 20)
	req[0], req[1] = 0x00, 0x01
	copy(req[4:8], []byte{0x21, 0x12, 0xa4, 0x42})
	copy(req[8:20], tx[:])
	if _, err := conn.Write(req); err != nil {
		res.Class, res.Err, res.TotalTime = ClassifyError(err), err.Error(), time.Since(start)
		return
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	res.FirstByteTime, res.TotalTime = time.Since(start), time.Since(start)
	if err != nil {
		res.Class, res.Err = ClassifyError(err), err.Error()
		return
	}
	res.Bytes = int64(n)
	if n < 20 || buf[0] != 0x01 || buf[1] != 0x01 ||
		!bytes.Equal(buf[4:8], []byte{0x21, 0x12, 0xa4, 0x42}) || !bytes.Equal(buf[8:20], tx[:]) {
		res.Class, res.Err = ClassOther, "malformed or mismatched STUN binding response"
		return
	}
	res.OK, res.Class = true, ClassOK
}

// hostPort splits a probe URL of the form scheme://host[:port] and applies a
// default port.
func hostPort(raw, defaultPort string) (host, addr string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	host = u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("no host in %q", raw)
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	return host, net.JoinHostPort(host, port), nil
}

// dial performs the TCP connect, honouring RunOpts.DialContext when supplied.
func (o RunOpts) dial(ctx context.Context, addr string) (net.Conn, error) {
	if o.DialContext != nil {
		return o.DialContext(ctx, "tcp", addr)
	}
	d := net.Dialer{}
	return d.DialContext(ctx, "tcp", addr)
}

// runTCPProbe measures TCP reachability only.
func runTCPProbe(ctx context.Context, p Probe, o RunOpts, res *Result) {
	host, addr, err := hostPort(p.URL, "443")
	if err != nil {
		res.Class, res.Err = ClassBadURL, err.Error()
		return
	}
	res.SNI = host
	start := time.Now()
	conn, err := o.dial(ctx, addr)
	res.ConnectTime = time.Since(start)
	res.TotalTime = res.ConnectTime
	if err != nil {
		res.Class, res.Err = ClassifyError(err), err.Error()
		return
	}
	defer conn.Close()
	if ra := conn.RemoteAddr(); ra != nil {
		res.ServerIP = ra.String()
	}
	res.OK, res.Class = true, ClassOK
}

// runTLSProbe performs the TLS handshake and stops there. That is the only
// measurement possible for an endpoint that speaks a protocol we do not (a
// WebSocket gateway), and it is also the most sensitive one: DPI acts on the
// ClientHello, so a handshake that completes means the desync worked.
func runTLSProbe(ctx context.Context, p Probe, o RunOpts, res *Result) {
	host, addr, err := hostPort(p.URL, "443")
	if err != nil {
		res.Class, res.Err = ClassBadURL, err.Error()
		return
	}
	res.SNI = host
	start := time.Now()
	conn, err := o.dial(ctx, addr)
	res.ConnectTime = time.Since(start)
	if err != nil {
		res.Class, res.Err = ClassifyError(err), err.Error()
		res.TotalTime = time.Since(start)
		return
	}
	defer conn.Close()
	if ra := conn.RemoteAddr(); ra != nil {
		res.ServerIP = ra.String()
	}
	// http/1.1 only, for the same reason the HTTP probe refuses HTTP/2: the
	// result must not depend on protocol negotiation.
	tc := tls.Client(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	hsStart := time.Now()
	err = tc.HandshakeContext(ctx)
	res.TLSTime = time.Since(hsStart)
	res.TotalTime = time.Since(start)
	if err != nil {
		res.Class, res.Err = ClassifyError(err), err.Error()
		return
	}
	st := tc.ConnectionState()
	res.TLSVersion = tlsVersionName(st.Version)
	res.ALPN = st.NegotiatedProtocol
	res.OK, res.Class = true, ClassOK
	_ = tc.Close()
}

// runHTTPProbe performs a full request and reads part of the body.
func runHTTPProbe(ctx context.Context, p Probe, o RunOpts, res *Result) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Host == "" {
		res.Class = ClassBadURL
		if err != nil {
			res.Err = err.Error()
		} else {
			res.Err = "no host in " + p.URL
		}
		return
	}
	res.SNI = u.Hostname()

	var (
		start    = time.Now()
		dnsDone  time.Duration
		connDone time.Duration
		tlsStart time.Time
		tlsDur   time.Duration
	)
	trace := &httptrace.ClientTrace{
		DNSDone: func(httptrace.DNSDoneInfo) { dnsDone = time.Since(start) },
		ConnectDone: func(_, addr string, err error) {
			if err == nil {
				connDone = time.Since(start)
				res.ServerIP = addr
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(st tls.ConnectionState, err error) {
			if !tlsStart.IsZero() {
				tlsDur = time.Since(tlsStart)
			}
			if err == nil {
				res.TLSVersion = tlsVersionName(st.Version)
				res.ALPN = st.NegotiatedProtocol
			}
		},
		GotFirstResponseByte: func() { res.FirstByteTime = time.Since(start) },
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return o.dial(ctx, addr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Refusing h2 keeps every probe on the same protocol and keeps QUIC
			// out of the picture entirely.
			NextProtos: []string{"http/1.1"},
		},
		ForceAttemptHTTP2: false,
		// A pooled connection would skip the handshake the strategy affects.
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		// Never follow a redirect: a 3xx is a complete answer, and following it
		// would measure a host the caller did not ask about.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, p.URL, nil)
	if err != nil {
		res.Class, res.Err = ClassBadURL, err.Error()
		return
	}
	// A plausible browser UA: some of these endpoints answer 403 to an empty
	// one, which would look like a censorship failure.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "+
		"(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	res.DNSTime, res.ConnectTime, res.TLSTime = dnsDone, connDone, tlsDur
	if err != nil {
		res.TotalTime = time.Since(start)
		res.Class, res.Err = ClassifyError(err), err.Error()
		return
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode

	want := p.Download
	if want <= 0 {
		want = o.Download
	}
	readStart := time.Now()
	n, rerr := io.Copy(io.Discard, io.LimitReader(resp.Body, want))
	readDur := time.Since(readStart)
	res.Bytes = n
	res.TotalTime = time.Since(start)
	if n > 0 && readDur > 0 {
		res.BytesPerSec = float64(n) / readDur.Seconds()
	}
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		// A body that dies mid-stream is the signature of DPI that let the
		// handshake through, so this is a failure even though we have a status.
		res.Class, res.Err = ClassifyError(rerr), rerr.Error()
		return
	}
	if p.Expect != 0 && resp.StatusCode != p.Expect {
		res.Class = ClassHTTPStatus
		res.Err = fmt.Sprintf("expected HTTP %d, got %d", p.Expect, resp.StatusCode)
		return
	}
	res.OK, res.Class = true, ClassOK
}

// tlsVersionName renders a TLS version constant.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// ClassifyError maps a transport error onto one of the Class* constants.
//
// Order matters, because these errors nest. A DNS failure is checked first: it
// arrives wrapped in a *net.OpError that also reports Timeout(), and calling it
// a timeout would send the user looking for DPI when the resolver is the
// problem. TLS errors are checked before the generic syscall errors because a
// record-header error carries no errno at all, and a certificate failure must
// not be lumped in with a handshake failure — one means interception, the other
// means the handshake was disrupted.
func ClassifyError(err error) string {
	if err == nil {
		return ClassOK
	}

	// --- resolver -----------------------------------------------------------
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return ClassDNSNotFound
		}
		return ClassDNS
	}

	// --- TLS ----------------------------------------------------------------
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		// The peer sent something that is not a TLS record where a record was
		// required: either the server does not speak TLS on this port, or
		// something injected bytes into the stream.
		return ClassTLSHandshake
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return ClassTLSCert
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return ClassTLSAlert
	}

	// --- cancellation and deadlines ----------------------------------------
	if errors.Is(err, context.Canceled) {
		return ClassCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassTimeout
	}

	// --- errno --------------------------------------------------------------
	switch {
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return ClassReset
	case errors.Is(err, syscall.ECONNREFUSED):
		return ClassRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EHOSTDOWN):
		return ClassUnreachable
	case errors.Is(err, syscall.ETIMEDOUT):
		return ClassTimeout
	}

	// --- net.Error, after the specific cases above -------------------------
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ClassTimeout
	}

	// --- stream ended -------------------------------------------------------
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ClassEOF
	}
	// A TLS handshake killed by an RST that Go surfaced without an errno reads
	// as this text; classifying it as a reset is more useful than "other".
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection reset by peer"):
		return ClassReset
	case strings.Contains(msg, "handshake failure"), strings.Contains(msg, "tls: "):
		return ClassTLSHandshake
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "Client.Timeout"):
		return ClassTimeout
	case strings.Contains(msg, "no such host"):
		return ClassDNSNotFound
	}
	return ClassOther
}

// Blocked reports whether the class is one DPI produces. It is the question the
// report actually answers: a timeout, an injected RST, a broken handshake or a
// stream that died mid-body are all censorship signatures, while a refused
// connection, a DNS failure or a missing route are local problems.
func Blocked(class string) bool {
	switch class {
	case ClassTimeout, ClassReset, ClassTLSHandshake, ClassTLSAlert, ClassEOF:
		return true
	default:
		return false
	}
}

// Summary aggregates results for a one-line verdict.
type Summary struct {
	// Total, Passed and Failed count every probe.
	Total, Passed, Failed int
	// ControlTotal and ControlPassed count only the control probes.
	ControlTotal, ControlPassed int
	// Blocked counts failures whose class is a censorship signature.
	Blocked int
	// MedianFirstByte is the median first-byte time over the probes that
	// succeeded, and 0 when none did.
	MedianFirstByte time.Duration
	// Classes counts each error class seen.
	Classes map[string]int
}

// Verdict renders the human conclusion.
func (s Summary) Verdict() string {
	switch {
	case s.Total == 0:
		return "no probes ran"
	case s.ControlTotal > 0 && s.ControlPassed == 0:
		return "no working internet connection: even the control endpoints failed, so nothing here says anything " +
			"about the bypass"
	case s.Failed == 0:
		return fmt.Sprintf("all %d probes passed (median first byte %s)", s.Total,
			s.MedianFirstByte.Round(time.Millisecond))
	case s.Blocked > 0:
		return fmt.Sprintf("%d/%d probes failed, %d with a DPI signature (timeout, injected RST, broken handshake): "+
			"the strategy is not working for those endpoints", s.Failed, s.Total, s.Blocked)
	default:
		return fmt.Sprintf("%d/%d probes failed, none with a DPI signature: look for a local cause (DNS, routing, "+
			"a local firewall)", s.Failed, s.Total)
	}
}

// Summarise aggregates a result set. It is pure, so the ranking tests use it
// directly with injected results.
func Summarise(results []Result) Summary {
	s := Summary{Classes: map[string]int{}}
	var ttfb []time.Duration
	for _, r := range results {
		s.Total++
		s.Classes[r.Class]++
		if r.Control {
			s.ControlTotal++
		}
		if r.OK {
			s.Passed++
			if r.Control {
				s.ControlPassed++
			}
			if r.FirstByteTime > 0 {
				ttfb = append(ttfb, r.FirstByteTime)
			} else if r.TLSTime > 0 {
				// A TLS-only probe has no first byte; its handshake time is the
				// comparable latency.
				ttfb = append(ttfb, r.TLSTime)
			}
			continue
		}
		s.Failed++
		if Blocked(r.Class) {
			s.Blocked++
		}
	}
	s.MedianFirstByte = median(ttfb)
	return s
}

// median returns the middle value of a duration slice (the lower of the two
// middles for an even count), or 0 for an empty one. The median rather than the
// mean, because one endpoint timing out at the full 10s deadline would otherwise
// dominate the average and make two strategies indistinguishable.
func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	c := make([]time.Duration, len(d))
	copy(c, d)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[(len(c)-1)/2]
}

// Table renders results as an aligned, sorted report: failures first (they are
// what the user needs), then successes by name.
func Table(results []Result) string {
	sorted := make([]Result, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].OK != sorted[j].OK {
			return !sorted[i].OK
		}
		return sorted[i].Name < sorted[j].Name
	})
	var sb strings.Builder
	for _, r := range sorted {
		sb.WriteString(r.String())
		sb.WriteByte('\n')
	}
	s := Summarise(results)
	sb.WriteString("--\n")
	sb.WriteString(s.Verdict())
	sb.WriteByte('\n')
	if len(s.Classes) > 0 {
		keys := make([]string, 0, len(s.Classes))
		for k := range s.Classes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+strconv.Itoa(s.Classes[k]))
		}
		sb.WriteString("classes: " + strings.Join(parts, " ") + "\n")
	}
	return sb.String()
}
