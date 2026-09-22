//go:build darwin

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pfctlPath and pfConfPath are the stock locations on macOS. /etc/pf.conf is
// only ever read by this program, never written.
const (
	pfctlPath  = "/sbin/pfctl"
	pfConfPath = "/etc/pf.conf"
	pfDevice   = "/dev/pf"

	// probeAnchor is the anchor name the probe loads its rules into.
	probeAnchor = "zapret-mac-probe"

	// appleSubAnchor is a sub-anchor nested under the wildcard anchor point a
	// stock /etc/pf.conf already declares. Loading rules here makes them live
	// without editing /etc/pf.conf and without replacing the main ruleset.
	appleSubAnchor = "com.apple/zapret-mac-probe"
	// zapretMacAnchor is the anchor the DAEMON owns. The probe never writes it; it
	// only checks whether it holds rules, which is evidence that a daemon is live
	// and that replacing the main ruleset would wipe its steering.
	zapretMacAnchor = "zapret-mac"
)

// ---------------------------------------------------------------------------
// pfioc_natlook — hand-written because Apple stripped pfvar.h from the SDK
// ---------------------------------------------------------------------------

// _IOWR/_IOW encoding from <sys/ioccom.h>.
const (
	ioctlIn       = uint32(0x80000000)
	ioctlOut      = uint32(0x40000000)
	ioctlInOut    = ioctlIn | ioctlOut
	ioctlParmMask = uint32(0x1fff)
)

// pfDirOut is PF_OUT from the anonymous enum in xnu bsd/net/pfvar.h:
// { PF_INOUT, PF_IN, PF_OUT, PF_FWD }, i.e. PF_OUT == 2. A redirected inbound
// connection is looked up from the translator's point of view, which is why
// tpws (the upstream reference implementation) also passes PF_OUT here.
const pfDirOut = 2

// pfAddr mirrors "struct pf_addr" from xnu bsd/net/pfvar.h: a 16-byte union of
// in_addr / in6_addr / u_int8_t[16] / u_int16_t[8] / u_int32_t[4]. The widest
// member is u_int32_t, so the C alignment is 4; the zero-length [0]uint32 field
// reproduces that alignment in Go without adding any bytes.
type pfAddr struct {
	_   [0]uint32
	Raw [16]byte
}

// v4 returns the IPv4 address stored in the first 4 bytes of the union.
func (a pfAddr) v4() netip.Addr {
	return netip.AddrFrom4([4]byte{a.Raw[0], a.Raw[1], a.Raw[2], a.Raw[3]})
}

// setV4 stores an IPv4 address into the union.
func (a *pfAddr) setV4(ip netip.Addr) {
	b := ip.As4()
	copy(a.Raw[:4], b[:])
}

// pfStateXport mirrors "union pf_state_xport" from xnu bsd/net/pfvar.h:
//
//	union pf_state_xport { u_int16_t port; u_int16_t call_id; u_int32_t spi; };
//
// 4 bytes, 4-byte aligned. The u_int16_t port member overlays the first two
// bytes and holds the port in network byte order, so it is modelled as raw
// bytes with explicit big-endian access rather than relying on host endianness.
type pfStateXport struct {
	_   [0]uint32
	Raw [4]byte
}

// port returns the network-order port stored in the union, in host order.
func (x pfStateXport) port() uint16 { return binary.BigEndian.Uint16(x.Raw[:2]) }

// xportPort builds a pf_state_xport holding p (given in host order).
func xportPort(p uint16) pfStateXport {
	var x pfStateXport
	binary.BigEndian.PutUint16(x.Raw[:2], p)
	return x
}

// pfiocNatlook mirrors "struct pfioc_natlook" from xnu bsd/net/pfvar.h exactly:
//
//	struct pf_addr saddr, daddr, rsaddr, rdaddr;      // 4 x 16 bytes
//	union pf_state_xport sxport, dxport, rsxport, rdxport; // 4 x 4 bytes
//	sa_family_t af; u_int8_t proto, proto_variant, direction;
//
// sa_family_t is __uint8_t on Darwin, so the tail is four single bytes and the
// total size is 84 with 4-byte alignment. Note this is the Apple layout, not
// the OpenBSD/FreeBSD one: upstream pf has plain sport/dport u_int16_t fields
// instead of the pf_state_xport unions and no proto_variant.
type pfiocNatlook struct {
	Saddr        pfAddr
	Daddr        pfAddr
	Rsaddr       pfAddr
	Rdaddr       pfAddr
	Sxport       pfStateXport
	Dxport       pfStateXport
	Rsxport      pfStateXport
	Rdxport      pfStateXport
	Af           uint8
	Proto        uint8
	ProtoVariant uint8
	Direction    uint8
}

// sizeofPfiocNatlook is the size the DIOCNATLOOK request number encodes.
const sizeofPfiocNatlook = unsafe.Sizeof(pfiocNatlook{})

// diocNatlook is _IOWR('D', 23, struct pfioc_natlook), derived from the struct
// above so that any layout drift changes the request number and is caught by
// the assertions below rather than silently returning EINVAL at runtime.
const diocNatlook = ioctlInOut | ((uint32(sizeofPfiocNatlook) & ioctlParmMask) << 16) | (uint32('D') << 8) | 23

// Compile-time assertions. The expected values were produced by compiling a C
// program against xnu's pfvar.h on this machine:
//
//	sizeof(struct pfioc_natlook) = 84, alignment 4
//	offsets: saddr 0, daddr 16, rsaddr 32, rdaddr 48,
//	         sxport 64, dxport 68, rsxport 72, rdxport 76,
//	         af 80, proto 81, proto_variant 82, direction 83
//	DIOCNATLOOK = 0xc0544417
//
// Each pair of unsigned subtractions fails to compile unless the two sides are
// equal, since a negative constant cannot be converted to uint.
const (
	_ = uint(sizeofPfiocNatlook - 84)
	_ = uint(84 - sizeofPfiocNatlook)
	_ = uint(unsafe.Offsetof(pfiocNatlook{}.Daddr) - 16)
	_ = uint(16 - unsafe.Offsetof(pfiocNatlook{}.Daddr))
	_ = uint(unsafe.Offsetof(pfiocNatlook{}.Rdaddr) - 48)
	_ = uint(48 - unsafe.Offsetof(pfiocNatlook{}.Rdaddr))
	_ = uint(unsafe.Offsetof(pfiocNatlook{}.Sxport) - 64)
	_ = uint(64 - unsafe.Offsetof(pfiocNatlook{}.Sxport))
	_ = uint(unsafe.Offsetof(pfiocNatlook{}.Rdxport) - 76)
	_ = uint(76 - unsafe.Offsetof(pfiocNatlook{}.Rdxport))
	_ = uint(unsafe.Offsetof(pfiocNatlook{}.Af) - 80)
	_ = uint(80 - unsafe.Offsetof(pfiocNatlook{}.Af))
	_ = uint(unsafe.Offsetof(pfiocNatlook{}.Direction) - 83)
	_ = uint(83 - unsafe.Offsetof(pfiocNatlook{}.Direction))
	_ = uint(diocNatlook - 0xc0544417)
	_ = uint(0xc0544417 - diocNatlook)
)

// natlookLayout describes the assumed ABI, for the report.
func natlookLayout() string {
	return fmt.Sprintf("XNU/Apple pfvar.h layout: sizeof=%d align=4, "+
		"saddr@%d daddr@%d rsaddr@%d rdaddr@%d sxport@%d dxport@%d rsxport@%d rdxport@%d "+
		"af@%d proto@%d proto_variant@%d direction@%d; DIOCNATLOOK=_IOWR('D',23,84)=%#08x",
		sizeofPfiocNatlook,
		unsafe.Offsetof(pfiocNatlook{}.Saddr), unsafe.Offsetof(pfiocNatlook{}.Daddr),
		unsafe.Offsetof(pfiocNatlook{}.Rsaddr), unsafe.Offsetof(pfiocNatlook{}.Rdaddr),
		unsafe.Offsetof(pfiocNatlook{}.Sxport), unsafe.Offsetof(pfiocNatlook{}.Dxport),
		unsafe.Offsetof(pfiocNatlook{}.Rsxport), unsafe.Offsetof(pfiocNatlook{}.Rdxport),
		unsafe.Offsetof(pfiocNatlook{}.Af), unsafe.Offsetof(pfiocNatlook{}.Proto),
		unsafe.Offsetof(pfiocNatlook{}.ProtoVariant), unsafe.Offsetof(pfiocNatlook{}.Direction),
		diocNatlook)
}

// natlook asks pf for the pre-translation destination of a redirected TCP
// connection. client is the accepted socket's peer address and local is its own
// address (the rdr target); both ports are in host order.
func natlook(devFD int, client, local netip.AddrPort) (netip.AddrPort, error) {
	if devFD < 0 {
		return netip.AddrPort{}, fmt.Errorf("/dev/pf is not open")
	}
	if !client.Addr().Is4() || !local.Addr().Is4() {
		return netip.AddrPort{}, fmt.Errorf("DIOCNATLOOK probe only implements AF_INET")
	}
	var nl pfiocNatlook
	nl.Af = unix.AF_INET
	nl.Proto = unix.IPPROTO_TCP
	nl.Direction = pfDirOut
	nl.Saddr.setV4(client.Addr())
	nl.Daddr.setV4(local.Addr())
	nl.Sxport = xportPort(client.Port())
	nl.Dxport = xportPort(local.Port())
	if err := ioctlPtr(devFD, diocNatlook, unsafe.Pointer(&nl)); err != nil {
		return netip.AddrPort{}, syscallError("ioctl(DIOCNATLOOK)", err)
	}
	if nl.Af != unix.AF_INET {
		return netip.AddrPort{}, fmt.Errorf("DIOCNATLOOK returned unexpected af=%d", nl.Af)
	}
	return netip.AddrPortFrom(nl.Rdaddr.v4(), nl.Rdxport.port()), nil
}

// ---------------------------------------------------------------------------
// pfctl driving
// ---------------------------------------------------------------------------

// pfResult captures everything a pfctl invocation produced.
type pfResult struct {
	Args   []string
	Stdout string
	Stderr string
	Err    error
}

// combined returns stdout and stderr joined, which is what pfctl output must be
// scanned as: it writes rules to stdout but tokens and warnings to stderr.
func (r pfResult) combined() string {
	if r.Stderr == "" {
		return r.Stdout
	}
	if r.Stdout == "" {
		return r.Stderr
	}
	return r.Stdout + "\n" + r.Stderr
}

// runPfctl executes pfctl with the given arguments and optional stdin.
func runPfctl(stdin string, args ...string) pfResult {
	cmd := exec.Command(pfctlPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return pfResult{
		Args:   args,
		Stdout: strings.TrimRight(out.String(), "\n"),
		Stderr: strings.TrimRight(errb.String(), "\n"),
		Err:    err,
	}
}

var pfTokenRe = regexp.MustCompile(`(?m)^\s*Token\s*:\s*(\d+)\s*$`)

// pfEnable runs "pfctl -E", which enables pf with reference counting and prints
// a token that must later be handed to "pfctl -X". Reference counting is why
// the probe never calls "pfctl -d": releasing the token leaves pf enabled if
// another component (e.g. a system service) still holds a reference.
func pfEnable() (token string, res pfResult) {
	res = runPfctl("", "-E")
	if m := pfTokenRe.FindStringSubmatch(res.combined()); m != nil {
		token = m[1]
	}
	return token, res
}

// pfRelease drops one pf enable reference.
func pfRelease(token string) pfResult {
	return runPfctl("", "-X", token)
}

// pfStatusEnabled reports whether "pfctl -s info" says pf is currently enabled.
func pfStatusEnabled() (bool, pfResult) {
	res := runPfctl("", "-s", "info")
	return strings.Contains(res.combined(), "Status: Enabled"), res
}

// pfLoadAnchor loads rules into the named anchor. With dryRun it only parses
// them (-n), which is how the probe validates a ruleset before committing it.
func pfLoadAnchor(anchor, rules string, dryRun bool) pfResult {
	args := []string{"-a", anchor, "-f", "-"}
	if dryRun {
		args = []string{"-a", anchor, "-n", "-f", "-"}
	}
	return runPfctl(rules, args...)
}

// pfAnchorRules returns "pfctl -a <anchor> -s rules" output.
func pfAnchorRules(anchor string) pfResult {
	return runPfctl("", "-a", anchor, "-s", "rules")
}

// pfFlushAnchor removes everything from the anchor.
func pfFlushAnchor(anchor string) pfResult {
	return runPfctl("", "-a", anchor, "-F", "all")
}

// pfMainRules returns the main ruleset's filter rules.
func pfMainRules() pfResult { return runPfctl("", "-s", "rules") }

// pfMainNat returns the main ruleset's translation rules.
func pfMainNat() pfResult { return runPfctl("", "-s", "nat") }

// pfLoadMain replaces the main ruleset with the supplied text.
func pfLoadMain(ruleset string) pfResult { return runPfctl(ruleset, "-f", "-") }

// pfCheckMain parses a candidate main ruleset without loading it.
func pfCheckMain(ruleset string) pfResult { return runPfctl(ruleset, "-n", "-f", "-") }

// pfRestoreMain reloads the untouched /etc/pf.conf, undoing pfLoadMain.
func pfRestoreMain() pfResult { return runPfctl("", "-f", pfConfPath) }

// wildcardAnchorCovers reports whether the main ruleset contains a WILDCARD
// anchor statement whose path covers sub.
//
// This is the escape hatch from macOS's central pf problem. A stock
// /etc/pf.conf carries `anchor "com.apple/*"` (and the nat/rdr/scrub variants),
// and a trailing /* means "evaluate every sub-anchor nested at this point".
// Sub-anchors are created purely by loading rules into them, so
// `pfctl -a "com.apple/zapret-mac-probe" -f -` produces rules pf actually evaluates
// WITHOUT touching /etc/pf.conf and WITHOUT replacing the main ruleset — which
// is exactly how Apple's own services (Internet Sharing NAT, AirDrop) get their
// rules in at runtime.
//
// The cost is that we borrow Apple's namespace: anything that flushes
// com.apple/* wholesale would take our rules with it. Nothing observed does that
// (services flush their own leaf anchor), and the daemon watches for drift.
func wildcardAnchorCovers(mainRules, sub string) bool {
	for _, line := range strings.Split(mainRules, "\n") {
		l := strings.TrimSpace(line)
		if !anchorStatementRe.MatchString(l) {
			continue
		}
		q := strings.Index(l, `"`)
		if q < 0 {
			continue
		}
		rest := l[q+1:]
		e := strings.Index(rest, `"`)
		if e < 0 {
			continue
		}
		path := rest[:e]
		if !strings.HasSuffix(path, "/*") {
			continue
		}
		if strings.HasPrefix(sub, strings.TrimSuffix(path, "*")) {
			return true
		}
	}
	return false
}

// anchorStatementRe matches any anchor-declaring statement in "pfctl -s rules"
// or "pfctl -s nat" output.
var anchorStatementRe = regexp.MustCompile(`^(anchor|rdr-anchor|nat-anchor|scrub-anchor|dummynet-anchor)\s`)

// anchorReachableRe matches an anchor statement in "pfctl -s rules" output that
// names our anchor, e.g. `anchor "zapret-mac-probe" all`.
func anchorReachable(mainRules, anchor string) bool {
	for _, line := range strings.Split(mainRules, "\n") {
		l := strings.TrimSpace(line)
		if !strings.Contains(l, anchor) {
			continue
		}
		if strings.HasPrefix(l, "anchor") || strings.HasPrefix(l, "rdr-anchor") ||
			strings.HasPrefix(l, "nat-anchor") || strings.HasPrefix(l, "scrub-anchor") {
			return true
		}
	}
	return false
}

// filterSectionRe recognises the first line of the filter section in a pf.conf,
// which is where translation rules must stop and filter rules may begin.
var filterSectionRe = regexp.MustCompile(`^(anchor[\s"]|pass\b|block\b|match\b)`)

// spliceMainRuleset builds a replacement main ruleset from the text of
// /etc/pf.conf with extra rules inserted at the correct grammatical position.
//
// pf enforces a strict section order (options, normalization, queueing,
// translation, filtering), so translation rules go immediately before the first
// filter statement and the filter rules go right after them — ahead of
// `anchor "com.apple/*"` so a `quick` rule of ours is guaranteed to be reached.
// "load anchor" lines are moved to the end because they are not part of the
// ordered rule sequence.
func spliceMainRuleset(pfConf string, translation, filter []string) string {
	var head, loads []string
	inserted := false
	for _, line := range strings.Split(pfConf, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "load anchor") {
			loads = append(loads, line)
			continue
		}
		if !inserted && filterSectionRe.MatchString(t) {
			head = append(head, "# --- zapret-mac-probe (temporary) ---")
			head = append(head, translation...)
			head = append(head, filter...)
			head = append(head, "# --- end zapret-mac-probe ---")
			inserted = true
		}
		head = append(head, line)
	}
	if !inserted {
		head = append(head, "# --- zapret-mac-probe (temporary) ---")
		head = append(head, translation...)
		head = append(head, filter...)
		head = append(head, "# --- end zapret-mac-probe ---")
	}
	head = append(head, loads...)
	return strings.Join(head, "\n") + "\n"
}

// routeToRule is the rule that steers the port window into the utun: the exact
// text stage 5 loads and stage 6 depends on.
func routeToRule(utun string, peer netip.Addr, target netip.Addr, port int) string {
	return fmt.Sprintf("pass out quick route-to (%s %s) inet proto tcp from any to %s port %d no state",
		utun, peer, target, port)
}

// rdrRule is the loopback redirect the userspace proxy transport depends on.
func rdrRule(target netip.Addr, port, listenPort int) string {
	return fmt.Sprintf("rdr pass on lo0 inet proto tcp from ! 127.0.0.0/8 to %s port %d -> 127.0.0.1 port %d",
		target, port, listenPort)
}

// routeToLoopbackRule forces locally generated traffic onto lo0 so that the
// inbound rdr above can fire. macOS pf cannot redirect outbound packets, so
// this is the only way to hand a locally originated connection to a local
// listener; it is the same trick zapret's own pf.sh uses for tpws.
//
// The upstream rule additionally carries `user { >root }` so the proxy's own
// outbound connections are not redirected back into itself. The probe omits it
// because the probe runs as root and must have its own dial redirected.
func routeToLoopbackRule(target netip.Addr, port int) string {
	return fmt.Sprintf("pass out quick route-to (lo0 127.0.0.1) inet proto tcp from any to %s port %d",
		target, port)
}

// pfConfAddition is the single line an operator (or the daemon) must add to
// /etc/pf.conf for a top-level anchor to be evaluated at all.
func pfConfAddition(anchor string) string {
	return fmt.Sprintf("anchor %q   (and rdr-anchor %q for the proxy transport), inserted before the com.apple anchors",
		anchor, anchor)
}

// ---------------------------------------------------------------------------
// /etc/pf.conf integrity witness
// ---------------------------------------------------------------------------

// fileWitness records a file's identity so an unchanged file can be proven
// unchanged afterwards.
type fileWitness struct {
	Path    string
	Size    int64
	ModTime time.Time
	SHA256  string
	Err     string
}

// witnessFile hashes path and records its size and mtime.
func witnessFile(path string) fileWitness {
	w := fileWitness{Path: path}
	st, err := os.Stat(path)
	if err != nil {
		w.Err = err.Error()
		return w
	}
	w.Size = st.Size()
	w.ModTime = st.ModTime()
	data, err := os.ReadFile(path)
	if err != nil {
		w.Err = err.Error()
		return w
	}
	sum := sha256.Sum256(data)
	w.SHA256 = hex.EncodeToString(sum[:])
	return w
}

// same reports whether two witnesses describe identical file content and mtime.
func (w fileWitness) same(o fileWitness) bool {
	return w.Err == "" && o.Err == "" && w.Size == o.Size &&
		w.SHA256 == o.SHA256 && w.ModTime.Equal(o.ModTime)
}

// String renders the witness compactly for the report.
func (w fileWitness) String() string {
	if w.Err != "" {
		return "error: " + w.Err
	}
	short := w.SHA256
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("%d bytes, mtime %s, sha256 %s…", w.Size, w.ModTime.UTC().Format(time.RFC3339), short)
}

// openPFDevice opens /dev/pf read/write, the descriptor DIOCNATLOOK needs.
func openPFDevice() (int, error) {
	fd, err := unix.Open(pfDevice, unix.O_RDWR, 0)
	if err != nil {
		return -1, syscallError("open("+pfDevice+", O_RDWR)", err)
	}
	return fd, nil
}
