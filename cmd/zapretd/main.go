//go:build darwin

// Command zapretd is the root daemon: it owns the pf configuration, the packet
// datapath and the control socket. It is the macOS replacement for the winws
// service flowseal's service.bat installs on Windows.
//
// Normal operation is under launchd (see `zapretd install-daemon` and
// internal/launchd), which captures stderr into /var/log/zapretd.log. For
// development, `sudo zapretd --foreground --verbose` runs it in a terminal.
//
// Usage:
//
//	zapretd [flags]                       run the daemon
//	zapretd install-daemon [flags]        write the LaunchDaemon plist and bootstrap it
//	zapretd uninstall-daemon [flags]      bootout, remove the plist, revert pf and /etc/hosts
//	zapretd version                       print the build version
//
// Everything the daemon changes on the system is journalled by internal/netcfg
// before it happens, so a SIGKILLed daemon leaves nothing that
// `zaprctl doctor --repair` cannot undo.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/ctl"
	"github.com/naladwepo/zapret-for-mac/internal/launchd"
)

// version is stamped by the Makefile with -ldflags "-X main.version=...".
var version = "dev"

// DefaultDataDir is where the installed strategies, lists, fakes and the pf
// state directory live.
const DefaultDataDir = "/Library/Application Support/zapret-mac"

// DefaultAnchor is the pf anchor the daemon owns exclusively.
const DefaultAnchor = "zapret-mac"

// DefaultStrategy is the known-good combined Discord, YouTube and cloud-gaming
// profile. It is used only when neither --strategy nor persisted state names a
// strategy, so `zaprctl use` remains persistent across daemon restarts.
const DefaultStrategy = "cloud-gaming"

// Default point-to-point addresses of the steering utun. 198.18.0.0/15 is
// RFC 2544 benchmark space: it is not globally routed, so it cannot collide with
// a real destination, and it is not in the RFC 1918 ranges a VPN or a home
// router is likely to hand out.
const (
	DefaultTunLocal = "198.18.0.1"
	DefaultTunPeer  = "198.18.0.2"
)

// DefaultProxyPort is the loopback port the degraded (pf rdr) transport listens
// on.
const DefaultProxyPort = 19980

// options is the daemon's whole configuration.
type options struct {
	dataDir      string
	strategy     string
	transport    string
	proxyPort    int
	utunUnit     int
	iface        string
	blockQUIC    bool
	noExemptRoot bool
	allowVPN     bool
	verbose      int
	foreground   bool

	socketPath  string
	socketGroup string
	anchor      string
	tunLocal    string
	tunPeer     string
	logPath     string
	probeAddr   string
	pfConfPath  string
	hostsPath   string
	dryRun      bool
}

// defaultOptions returns the options a bare `zapretd` runs with.
func defaultOptions() options {
	return options{
		dataDir:     DefaultDataDir,
		transport:   "auto",
		proxyPort:   DefaultProxyPort,
		socketPath:  ctl.DefaultSocketPath,
		socketGroup: ctl.SocketGroup,
		anchor:      DefaultAnchor,
		tunLocal:    DefaultTunLocal,
		tunPeer:     DefaultTunPeer,
		logPath:     launchd.DefaultStdoutPath,
	}
}

// bind registers every flag on fs. It is shared by the run and install
// subcommands so `install-daemon` can bake exactly the flags the daemon accepts
// into the plist.
func (o *options) bind(fs *flag.FlagSet) {
	fs.StringVar(&o.dataDir, "data", o.dataDir, "data directory holding strategies/, lists/, fakes/ and state/")
	fs.StringVar(&o.strategy, "strategy", o.strategy, "strategy name or path to a .toml (default: the last one activated, else \"cloud-gaming\")")
	fs.StringVar(&o.transport, "transport", o.transport, "datapath: auto|divert|proxy")
	fs.IntVar(&o.proxyPort, "proxy-port", o.proxyPort, "loopback port for the proxy transport")
	fs.IntVar(&o.utunUnit, "utun-unit", o.utunUnit, "utun unit number for the divert transport (0 = first free)")
	fs.StringVar(&o.iface, "iface", o.iface, "physical uplink for packet re-emission (empty = from the default route)")
	fs.BoolVar(&o.blockQUIC, "block-quic", o.blockQUIC, "drop UDP/443 to the target set, forcing browsers back to TCP")
	fs.BoolVar(&o.noExemptRoot, "no-exempt-root", o.noExemptRoot, "also intercept root-owned direct sockets (required for VPN clients such as Happ; BPF injection remains loop-free)")
	fs.BoolVar(&o.allowVPN, "allow-vpn", o.allowVPN, "run beside a split-routing VPN (direct targets must leave through the physical uplink)")
	fs.IntVar(&o.verbose, "verbose", o.verbose, "log level: 0 quiet, 1 debug, 2 packet trace")
	fs.BoolVar(&o.foreground, "foreground", o.foreground, "run in this terminal instead of under launchd")
	fs.StringVar(&o.socketPath, "socket", o.socketPath, "control socket path")
	fs.StringVar(&o.socketGroup, "socket-group", o.socketGroup, "group allowed to use the control socket")
	fs.StringVar(&o.anchor, "anchor", o.anchor, "pf anchor name to own")
	fs.StringVar(&o.tunLocal, "tun-local", o.tunLocal, "local address of the steering utun")
	fs.StringVar(&o.tunPeer, "tun-peer", o.tunPeer, "peer address of the steering utun (the route-to target)")
	fs.StringVar(&o.logPath, "log", o.logPath, "path launchd writes our stdout to (reported by zaprctl, never written by us)")
	fs.StringVar(&o.probeAddr, "probe-addr", o.probeAddr, "IP[:port] the capability probe steers to (default 198.51.100.7:443, RFC 5737 TEST-NET-2)")
	fs.StringVar(&o.pfConfPath, "pf-conf", o.pfConfPath, "main pf ruleset to patch (default /etc/pf.conf)")
	fs.StringVar(&o.hostsPath, "hosts", o.hostsPath, "hosts file to pin entries in (default /etc/hosts)")
	fs.BoolVar(&o.dryRun, "dry-run", o.dryRun, "validate and log every privileged change without making it")
}

// validate rejects impossible combinations before anything is touched.
func (o *options) validate() error {
	switch o.transport {
	case "auto", "divert", "proxy":
	default:
		return fmt.Errorf("--transport %q is unknown; use auto, divert or proxy", o.transport)
	}
	if o.proxyPort < 1 || o.proxyPort > 65535 {
		return fmt.Errorf("--proxy-port %d is out of range 1..65535", o.proxyPort)
	}
	if o.utunUnit < 0 || o.utunUnit > 255 {
		return fmt.Errorf("--utun-unit %d is out of range 0..255", o.utunUnit)
	}
	if o.verbose < 0 || o.verbose > 2 {
		return fmt.Errorf("--verbose %d is out of range 0..2", o.verbose)
	}
	if o.dataDir == "" {
		return errors.New("--data must not be empty")
	}
	if o.socketPath == "" {
		return errors.New("--socket must not be empty")
	}
	if o.tunLocal == "" || o.tunPeer == "" {
		return errors.New("--tun-local and --tun-peer must both be set")
	}
	return nil
}

// exit codes: 0 ok, 1 error, 2 not root.
const (
	exitOK      = 0
	exitError   = 1
	exitNotRoot = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main with injectable streams so every path is testable.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub := args[0]
		rest := args[1:]
		switch sub {
		case "install-daemon":
			return runInstall(rest, stdout, stderr)
		case "uninstall-daemon":
			return runUninstall(rest, stdout, stderr)
		case "guard":
			return runGuard(rest, stdout, stderr)
		case "version", "--version":
			fmt.Fprintf(stdout, "zapretd %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return exitOK
		case "help":
			usage(stdout)
			return exitOK
		default:
			fmt.Fprintf(stderr, "zapretd: unknown subcommand %q\n", sub)
			usage(stderr)
			return exitError
		}
	}

	opts := defaultOptions()
	fs := flag.NewFlagSet("zapretd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the build version and exit")
	opts.bind(fs)
	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if *showVersion {
		fmt.Fprintf(stdout, "zapretd %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return exitOK
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "zapretd: unexpected argument %q\n", fs.Arg(0))
		return exitError
	}
	if err := opts.validate(); err != nil {
		fmt.Fprintf(stderr, "zapretd: %v\n", err)
		return exitError
	}

	// Root is the only gate this design has: pf, /dev/bpf and utun creation all
	// need euid 0, and there is no entitlement or helper that would substitute.
	//
	// --dry-run is the one exception, because it changes nothing: it exists so the
	// control plane, the strategy loader and the supervisor can be exercised
	// unprivileged. It cannot intercept a single packet, and says so.
	if os.Geteuid() != 0 && opts.dryRun {
		fmt.Fprintf(stderr, "zapretd: DRY RUN as uid %d: pf, the utun and /dev/bpf are all unavailable, "+
			"so NOTHING will be intercepted. This mode exists to exercise the control plane.\n", os.Geteuid())
	} else if os.Geteuid() != 0 {
		fmt.Fprintf(stderr, `zapretd: must run as root (euid is %d).

It needs root to load pf rules, to create the utun the packet window is steered
into and to open /dev/bpf for re-emission. There is no unprivileged fallback on
macOS: no divert socket, no NetworkExtension entitlement, no helper tool.

Run it as:   sudo %s %s
Or install the daemon once:   sudo make install
`, os.Geteuid(), exeName(), strings.Join(args, " "))
		return exitNotRoot
	}

	// Without --foreground the daemon expects to be a launchd job. Refusing an
	// orphaned run is deliberate: an unsupervised root packet interceptor whose
	// terminal is closed would keep pf rules loaded with nobody watching it.
	if !opts.foreground && os.Getppid() != 1 {
		fmt.Fprintf(stderr, `zapretd: refusing to run unsupervised (parent pid is %d, not launchd).

Either run it in this terminal:      sudo %s --foreground %s
or install it as a LaunchDaemon:     sudo make install
`, os.Getppid(), exeName(), strings.Join(args, " "))
		return exitError
	}

	log := newLogger(stderr, opts.verbose)
	d := newDaemon(opts, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP reloads the strategy in place: that is what an operator expects
	// from a daemon, and it costs nothing to keep flows alive across it.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				log.Printf("SIGHUP: reloading the strategy")
				if err := d.Reload(); err != nil {
					log.Printf("SIGHUP reload failed: %v", err)
				}
			}
		}
	}()

	if err := d.Run(ctx); err != nil {
		log.Printf("fatal: %v", err)
		return exitError
	}
	return exitOK
}

func exeName() string {
	exe, err := os.Executable()
	if err != nil {
		return "zapretd"
	}
	return exe
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `zapretd %s — DPI-desync daemon for macOS (Apple Silicon)

  zapretd [flags]                   run the daemon (root; --foreground outside launchd)
  zapretd install-daemon [flags]    write %s and bootstrap it
  zapretd uninstall-daemon [flags]  bootout, remove the plist, revert pf and /etc/hosts
  zapretd guard [flags]             flush the pf anchor if no daemon owns it (dead-man's switch)
  zapretd version                   print the build version

Flags:
`, version, launchd.DefaultPlistPath)
	fs := flag.NewFlagSet("zapretd", flag.ContinueOnError)
	fs.SetOutput(w)
	o := defaultOptions()
	o.bind(fs)
	fs.PrintDefaults()
	fmt.Fprintf(w, `
Control it with zaprctl:
  zaprctl status | list | use <strategy> | caps | doctor | test | logs
`)
}

// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------

// logRing is how many recent lines the daemon keeps for `zaprctl logs`. The
// launchd-captured file is the full record; this is the tail a user gets over
// the control socket without needing read access to /var/log.
const logRing = 2000

// logger writes plain text to stderr (launchd captures it) and keeps a ring
// buffer plus live subscribers so the logtail command can serve both history
// and a follow stream.
type logger struct {
	mu    sync.Mutex
	w     io.Writer
	level int
	ring  []string
	subs  map[int]chan string
	next  int
}

func newLogger(w io.Writer, level int) *logger {
	return &logger{w: w, level: level, subs: make(map[int]chan string)}
}

// Level reports the configured verbosity.
func (l *logger) Level() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetLevel changes verbosity at runtime.
func (l *logger) SetLevel(v int) {
	l.mu.Lock()
	l.level = v
	l.mu.Unlock()
}

// Printf logs unconditionally.
func (l *logger) Printf(format string, args ...any) { l.emit("", format, args...) }

// Debugf logs at --verbose 1.
func (l *logger) Debugf(format string, args ...any) {
	if l.Level() >= 1 {
		l.emit("debug: ", format, args...)
	}
}

// Tracef logs at --verbose 2.
func (l *logger) Tracef(format string, args ...any) {
	if l.Level() >= 2 {
		l.emit("trace: ", format, args...)
	}
}

func (l *logger) emit(prefix, format string, args ...any) {
	line := time.Now().Format("2006-01-02T15:04:05.000Z07:00") + " " + prefix + fmt.Sprintf(format, args...)
	line = strings.TrimRight(line, "\n")
	l.mu.Lock()
	if l.w != nil {
		fmt.Fprintln(l.w, line)
	}
	l.ring = append(l.ring, line)
	if len(l.ring) > logRing {
		// Drop the oldest quarter at once instead of shifting on every line.
		l.ring = append([]string(nil), l.ring[len(l.ring)-logRing*3/4:]...)
	}
	for _, ch := range l.subs {
		// Never block the datapath on a slow log reader: a full subscriber
		// channel silently loses lines, which is the right trade for a tail.
		select {
		case ch <- line:
		default:
		}
	}
	l.mu.Unlock()
}

// Lines returns up to n recent lines (all of them when n <= 0).
func (l *logger) Lines(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.ring) {
		n = len(l.ring)
	}
	out := make([]string, n)
	copy(out, l.ring[len(l.ring)-n:])
	return out
}

// Subscribe returns a channel of new lines and a function to release it.
func (l *logger) Subscribe() (<-chan string, func()) {
	ch := make(chan string, 256)
	l.mu.Lock()
	id := l.next
	l.next++
	l.subs[id] = ch
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		if c, ok := l.subs[id]; ok {
			delete(l.subs, id)
			close(c)
		}
		l.mu.Unlock()
	}
}

// netcfgLogf adapts the logger to netcfg.Logf, which is chatty enough to belong
// at debug level except for the lines that describe a change to a system file.
func (l *logger) netcfgLogf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	switch {
	case strings.Contains(msg, "patched"), strings.Contains(msg, "restored"),
		strings.Contains(msg, "warning"), strings.Contains(msg, "released"),
		strings.Contains(msg, "enabled"), strings.Contains(msg, "cannot"):
		l.Printf("%s", msg)
	default:
		l.Debugf("%s", msg)
	}
}

// filepathBase is used in messages where the full path would be noise.
func filepathBase(p string) string { return filepath.Base(p) }
