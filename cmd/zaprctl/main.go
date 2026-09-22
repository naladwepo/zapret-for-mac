//go:build darwin

// Command zaprctl is the user-facing control tool: the replacement for
// flowseal's service.bat menu. It talks to zapretd over the unix socket at
// /var/run/zapret-mac.sock, which is root:admin 0660 — so a machine
// administrator can read status, list strategies and switch them without sudo.
//
// Usage:
//
//	zaprctl status                     transport, strategy, counters, pf, warnings
//	zaprctl list                       installed strategies and what the transport can honour
//	zaprctl explain <name>             the compiled profiles, op by op, with real parameters
//	zaprctl use <name> [--force]       switch strategy
//	zaprctl start | stop | restart     control the datapath (and the daemon itself)
//	zaprctl caps                       capability matrix of a transport
//	zaprctl doctor [--repair]          diagnostics, and fix what can be fixed
//	zaprctl test [--strategy X] [t...] connectivity self-test
//	zaprctl hosts apply|remove         the /etc/hosts pinning block
//	zaprctl ipset [loaded|none|any]    flowseal's tri-state ipset switch
//	zaprctl vpn [status|stop|start]    the VPN that blocks the packet datapath
//	zaprctl logs [-n N] [-f]           tail the daemon log
//	zaprctl version
//
// Every command takes --json, and every command takes --transport
// auto|divert|proxy: "auto" reports the transport the daemon is actually
// running, while an explicit value answers "what would I get with that
// datapath" without needing a daemon at all — which is how a user finds out,
// before installing anything, that the socket-level fallback cannot honour the
// fake/seqovl half of nearly every flowseal strategy.
//
// Exit codes: 0 success, 1 error, 3 the daemon is not running, 4 permission
// denied (the message then contains the exact sudo command to retry with).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/ctl"
	"github.com/naladwepo/zapret-for-mac/internal/launchd"
)

// version is stamped by the Makefile with -ldflags "-X main.version=...".
var version = "dev"

// DefaultDataDir must match zapretd's --data default: it is where zaprctl looks
// for strategies, lists and the rollback journal when no daemon is running to
// ask.
const DefaultDataDir = "/Library/Application Support/zapret-mac"

// DefaultAnchor must match zapretd's --anchor default.
const DefaultAnchor = "zapret-mac"

// Exit codes. They are part of the interface: scripts branch on them.
const (
	exitOK         = 0
	exitError      = 1
	exitNotRunning = 3
	exitDenied     = 4
)

// parseContinue is returned by parseCmd when the flags were fine and the
// command should run. It is not an exit code.
const parseContinue = -1

// cli holds the global options and the output streams.
type cli struct {
	json    bool
	socket  string
	dataDir string
	anchor  string
	timeout time.Duration
	// transport is --transport: auto|divert|proxy. For list/caps/explain/use it
	// selects WHOSE capabilities to talk about; for start it selects the
	// datapath to actually bring up.
	transport string
	// transportSet distinguishes an explicit "--transport auto" from the
	// default, which is what lets `start` tell "leave the daemon's choice alone"
	// apart from "re-run the probe and choose".
	transportSet bool

	// argv0 and args are kept verbatim so a permission error can print the
	// exact command to retry under sudo.
	argv []string

	out io.Writer
	err io.Writer
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	c := &cli{
		socket:    ctl.DefaultSocketPath,
		dataDir:   DefaultDataDir,
		anchor:    DefaultAnchor,
		timeout:   ctl.DefaultTimeout,
		transport: transportAuto,
		argv:      append([]string(nil), args...),
		out:       stdout,
		err:       stderr,
	}

	// The top-level parse only has to find the command: every subcommand
	// registers the global flags again (see parseCmd), so they may also appear
	// after the command — which is where a user naturally types them.
	fs := flag.NewFlagSet("zaprctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c.globalFlags(fs)
	fs.Usage = func() { c.usage(stderr) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	rest := fs.Args()
	if len(rest) == 0 {
		c.usage(stderr)
		return exitError
	}

	cmd := strings.ToLower(rest[0])
	sub := rest[1:]

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "status":
		return c.cmdStatus(ctx, sub)
	case "stats":
		return c.cmdStats(ctx, sub)
	case "list", "ls":
		return c.cmdList(ctx, sub)
	case "explain", "show":
		return c.cmdExplain(ctx, sub)
	case "use":
		return c.cmdUse(ctx, sub)
	case "start":
		return c.cmdStart(ctx, sub)
	case "stop":
		return c.cmdStop(ctx, sub)
	case "restart":
		return c.cmdRestart(ctx, sub)
	case "reload":
		return c.cmdReload(ctx, sub)
	case "caps":
		return c.cmdCaps(ctx, sub)
	case "doctor":
		return c.cmdDoctor(ctx, sub)
	case "probe":
		return c.cmdProbe(sub)
	case "test", "selftest":
		return c.cmdTest(ctx, sub)
	case "hosts":
		return c.cmdHosts(ctx, sub)
	case "ipset":
		return c.cmdIPSet(ctx, sub)
	case "vpn":
		return c.cmdVPN(ctx, sub)
	case "router":
		return c.cmdRouter(ctx, sub)
	case "autostart":
		return c.cmdAutostart(ctx, sub)
	case "happ-agent":
		return c.cmdHappAgent(ctx)
	case "autopick", "pick":
		return c.cmdAutopick(ctx, sub)
	case "logs", "log":
		return c.cmdLogs(ctx, sub)
	case "version":
		return c.cmdVersion(ctx, sub)
	case "help", "-h", "--help":
		if _, code := c.parseCmd("help", "help [--json]", sub, nil); code != parseContinue {
			return code
		}
		if c.json {
			return c.printJSON(helpData(version))
		}
		c.usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "zaprctl: unknown command %q\n\n", cmd)
		c.usage(stderr)
		return exitError
	}
}

// globalFlags registers the options every command accepts. It is called once for
// the top-level parse and again for each subcommand's own flag set, always
// defaulting to the value already in c, so `zaprctl --json list --transport
// proxy` and `zaprctl list --json --transport proxy` are the same command.
func (c *cli) globalFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.json, "json", c.json, "print the JSON payload instead of a table")
	fs.StringVar(&c.socket, "socket", c.socket, "control socket path")
	fs.StringVar(&c.dataDir, "data", c.dataDir, "data directory (used when no daemon is running)")
	fs.StringVar(&c.anchor, "anchor", c.anchor, "pf anchor name (used when no daemon is running)")
	fs.DurationVar(&c.timeout, "timeout", c.timeout, "per-request timeout")
	fs.Func("transport", "for list/caps/explain: whose capabilities to report; for start: which datapath to bring up "+
		"(auto|divert|proxy)", func(v string) error {
		switch v {
		case "auto", "divert", "proxy":
			c.transport, c.transportSet = v, true
			return nil
		default:
			return fmt.Errorf("unknown transport %q; use auto, divert or proxy", v)
		}
	})
}

// parseCmd builds the flag set of one subcommand — the global flags plus
// whatever add registers — and parses args with it.
//
// Flags are accepted after positional arguments too (see reorderFlags), because
// `zaprctl use general --force` is what a user types, and Go's flag package
// stops at the first non-flag argument.
//
// The returned code is parseContinue when the command should run; otherwise it
// is the exit code to return (0 for --help, 1 for a bad flag).
func (c *cli) parseCmd(name, usage string, args []string, add func(*flag.FlagSet)) ([]string, int) {
	fs := flag.NewFlagSet("zaprctl "+name, flag.ContinueOnError)
	fs.SetOutput(c.err)
	c.globalFlags(fs)
	if add != nil {
		add(fs)
	}
	fs.Usage = func() {
		fmt.Fprintf(c.err, "usage: zaprctl %s\n\n", usage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderFlags(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, exitOK
		}
		return nil, exitError
	}
	if err := c.validateTransport(); err != nil {
		fmt.Fprintf(c.err, "zaprctl: %v\n", err)
		return nil, exitError
	}
	return fs.Args(), parseContinue
}

// reorderFlags moves flag tokens ahead of positional ones so a flag may follow
// an argument. A flag that takes a value keeps its value adjacent, and
// everything after a literal "--" is left alone.
func reorderFlags(fs *flag.FlagSet, args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			rest = append(rest, a)
			continue
		}
		flags = append(flags, a)
		if strings.Contains(a, "=") {
			continue
		}
		if flagTakesValue(fs, strings.TrimLeft(a, "-")) && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, rest...)
}

// flagTakesValue reports whether the named flag consumes the next argument. An
// unknown name is reported as valueless so flag.Parse gets to produce the error
// message instead of us swallowing the argument after it.
func flagTakesValue(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return false
	}
	return true
}

// noArgs rejects leftover positional arguments on a command that takes none.
func (c *cli) noArgs(name string, rest []string) int {
	if len(rest) == 0 {
		return parseContinue
	}
	fmt.Fprintf(c.err, "zaprctl %s: unexpected argument %q\n", name, rest[0])
	return exitError
}

// commandDoc is one line of the help screen.
type commandDoc struct {
	Use     string `json:"use"`
	Summary string `json:"summary"`
}

// commandDocs is the command list printed by --help and returned by
// `zaprctl help --json`.
func commandDocs() []commandDoc {
	return []commandDoc{
		{"status", "transport, strategy, uptime, counters, pf state and warnings"},
		{"stats", "the raw counters only"},
		{"list", "installed strategies, marking what the transport cannot honour"},
		{"explain <strategy>", "the compiled profiles: filters, ops with their real parameters, cutoff"},
		{"use <strategy> [--force]", "switch strategy; --force accepts one this transport degrades"},
		{"caps", "capability matrix of a transport, and what it costs the active strategy"},
		{"start", "bring the datapath up (loads the launchd job first if needed)"},
		{"stop", "take the datapath down and remove the pf rules; the daemon stays"},
		{"restart", "stop and start the datapath (or restart the daemon if it is wedged)"},
		{"reload", "re-read the active strategy and its lists from disk"},
		{"doctor [--repair]", "diagnostics; --repair fixes what it can (needs root)"},
		{"test [--suite all|discord]", "connectivity self-test; Discord includes WSS and UDP/STUN"},
		{"hosts apply | remove", "the /etc/hosts pinning block (Discord voice IPs)"},
		{"ipset [loaded|none|any]", "flowseal's tri-state ipset switch"},
		{"vpn [status|stop|start]", "VPN holding a tunnel default route: show it, stop it, put it back"},
		{"router happ [--install] [--output FILE]", "Happ-only split-routing policy; rejects other VPN clients"},
		{"autostart install|remove|status", "start Happ and refresh its routing profile at login"},
		{"probe [flags]", "run the reversible PF/BPF capability probe (needs root)"},
		{"autopick [--suite all|discord] [--rounds N]", "measure every strategy and leave the best one running"},
		{"logs [-n N] [-f] [--file P]", "tail the daemon log"},
		{"version", "the client and daemon builds, and whether they match"},
		{"help", "this text (`help --json` for the machine-readable form)"},
	}
}

// helpExamples are the copy-pasteable lines at the top of the help screen.
func helpExamples() []string {
	return []string{
		"zaprctl list --transport proxy",
		"sudo zaprctl use general-alt3 && zaprctl test",
		"zaprctl explain general --transport proxy",
	}
}

// helpPayload is the shape of `zaprctl help --json`.
type helpPayload struct {
	Version   string            `json:"version"`
	Commands  []commandDoc      `json:"commands"`
	Examples  []string          `json:"examples"`
	Transport []string          `json:"transport_values"`
	ExitCodes map[string]string `json:"exit_codes"`
}

// helpData builds the machine-readable help.
func helpData(ver string) helpPayload {
	return helpPayload{
		Version:   ver,
		Commands:  commandDocs(),
		Examples:  helpExamples(),
		Transport: []string{transportAuto, transportDivert, transportProxy},
		ExitCodes: map[string]string{
			"0": "ok",
			"1": "error: bad usage, a failed command, doctor/test found problems, or `use` refused without --force",
			"3": "the daemon is not running (any local answer was still printed)",
			"4": "permission denied on the control socket",
		},
	}
}

func (c *cli) usage(w io.Writer) {
	fmt.Fprintf(w, "zaprctl %s — control the zapret-mac daemon\n\nExamples\n", version)
	for _, e := range helpExamples() {
		fmt.Fprintf(w, "  %s\n", e)
	}
	fmt.Fprintf(w, "\nCommands\n")
	for _, d := range commandDocs() {
		fmt.Fprintf(w, "  %-32s %s\n", d.Use, d.Summary)
	}
	fmt.Fprintf(w, `
Global flags (before or after the command)
  --json                       print the JSON payload instead of a table
  --transport auto|%s|%s
                               whose capabilities list/caps/explain/use report.
                               auto asks the running daemon; an explicit value
                               answers "what would this datapath do" with no
                               daemon at all (default %s)
  --socket <path>              control socket (default %s)
  --data <dir>                 data directory used when no daemon is running (default %s)
  --anchor <name>              pf anchor name used when no daemon is running (default %s)
  --timeout <dur>              per-request timeout (default %s; start/stop/restart get %s)

Switching strategy needs root or membership of the %q group.

Exit codes
  0  ok
  1  error: bad usage, a failed command, doctor/test found problems,
     or "use" refused a degraded strategy without --force
  3  the daemon is not running; whatever could be answered locally was
     still printed ("doctor" reports it as a finding and exits 1 instead)
  4  permission denied on the control socket; the exact sudo command
     to retry with is printed
`, transportDivert, transportProxy, transportAuto, ctl.DefaultSocketPath, DefaultDataDir,
		DefaultAnchor, ctl.DefaultTimeout, lifecycleTimeout, ctl.SocketGroup)
}

// client returns a client bound to the configured socket and timeout.
func (c *cli) client() *ctl.Client {
	return ctl.NewClient(c.socket).WithTimeout(c.timeout)
}

// lifecycleTimeout is the deadline for start/stop/restart. Those commands block
// in the daemon until the supervisor has actually reached the requested state,
// which takes longer than any query.
const lifecycleTimeout = 45 * time.Second

// lifecycleClient returns a client with the longer lifecycle deadline, unless
// the user asked for an even longer one with --timeout.
func (c *cli) lifecycleClient() *ctl.Client {
	d := lifecycleTimeout
	if c.timeout > d {
		d = c.timeout
	}
	return ctl.NewClient(c.socket).WithTimeout(d)
}

// fail prints an error and maps it to an exit code, including the exact sudo
// command to retry with when the socket refused us.
func (c *cli) fail(err error) int {
	switch {
	case ctl.IsNotRunning(err):
		fmt.Fprintf(c.err, "zaprctl: the zapret-mac daemon is not running.\n")
		fmt.Fprintf(c.err, "  start it:      sudo zaprctl start\n")
		fmt.Fprintf(c.err, "  or load it:    sudo launchctl kickstart -k system/%s\n", launchd.DefaultLabel)
		fmt.Fprintf(c.err, "  install it:    sudo make install\n")
		fmt.Fprintf(c.err, "  its log:       %s\n", launchd.DefaultStdoutPath)
		return exitNotRunning
	case ctl.IsPermissionDenied(err):
		fmt.Fprintf(c.err, "zaprctl: permission denied on %s.\n", c.socket)
		fmt.Fprintf(c.err, "  the socket is root:%s 0%o — add yourself to that group, or retry with:\n", ctl.SocketGroup, ctl.SocketMode)
		fmt.Fprintf(c.err, "  sudo zaprctl %s\n", strings.Join(c.argv, " "))
		return exitDenied
	default:
		fmt.Fprintf(c.err, "zaprctl: %v\n", err)
		return exitError
	}
}

// printJSON writes v as indented JSON.
func (c *cli) printJSON(v any) int {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(c.err, "zaprctl: cannot encode JSON: %v\n", err)
		return exitError
	}
	return exitOK
}

// ---------------------------------------------------------------------------
// output helpers
// ---------------------------------------------------------------------------

// kv prints one aligned "key   value" line of a detail block.
func (c *cli) kv(key, format string, args ...any) {
	fmt.Fprintf(c.out, "  %-12s %s\n", key, fmt.Sprintf(format, args...))
}

// table is a minimal aligned text table. Columns are padded to the widest cell,
// which is all a terminal needs and keeps the output greppable.
type table struct {
	head []string
	rows [][]string
}

func newTable(head ...string) *table { return &table{head: head} }

func (t *table) add(cells ...string) { t.rows = append(t.rows, cells) }

func (t *table) render(w io.Writer) {
	cols := len(t.head)
	for _, r := range t.rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	width := make([]int, cols)
	measure := func(cells []string) {
		for i, s := range cells {
			if n := len([]rune(s)); n > width[i] {
				width[i] = n
			}
		}
	}
	if len(t.head) > 0 {
		measure(t.head)
	}
	for _, r := range t.rows {
		measure(r)
	}
	line := func(cells []string) {
		var b strings.Builder
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			if i == cols-1 {
				b.WriteString(cell)
				break
			}
			b.WriteString(cell)
			b.WriteString(strings.Repeat(" ", width[i]-len([]rune(cell))+2))
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
	if len(t.head) > 0 {
		line(t.head)
	}
	for _, r := range t.rows {
		line(r)
	}
}

// mark renders a boolean as the yes/no a capability matrix wants.
func mark(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// status tag for a check or a test row.
func tag(ok bool, sev string) string {
	if ok {
		return "[ok]  "
	}
	switch sev {
	case ctl.SevWarn:
		return "[warn]"
	case ctl.SevInfo:
		return "[info]"
	}
	return "[FAIL]"
}

// checkIndent is the left margin of a diagnostic's continuation lines: the width
// of the "[FAIL] " tag, so wrapped text lines up under the title.
const checkIndent = "       "

// wrapWidth is where diagnostic text is folded. 96 columns fits a default
// Terminal window without wrapping mid-word at an arbitrary place.
const wrapWidth = 96

// printCheck renders one diagnostic. Short findings stay on one line; anything
// longer becomes a title line plus wrapped detail, because internal/diag writes
// findings as full explanations (that is the point of them) and squeezing those
// into a column turns the report into unreadable ragged text.
func (c *cli) printCheck(ch ctl.Check) {
	t := tag(ch.OK, ch.Severity)
	if len([]rune(ch.Name)) <= 30 && len([]rune(ch.Detail)) <= 56 && !strings.Contains(ch.Detail, "\n") {
		fmt.Fprintf(c.out, "%s %-30s %s\n", t, ch.Name, ch.Detail)
	} else {
		fmt.Fprintf(c.out, "%s %s\n", t, ch.Name)
		for _, line := range wrapText(ch.Detail, wrapWidth-len(checkIndent)) {
			fmt.Fprintf(c.out, "%s%s\n", checkIndent, line)
		}
	}
	if ch.OK || ch.Fix == "" {
		return
	}
	// A fix is printed verbatim, never re-wrapped: it routinely contains a
	// command or a pf rule line, and folding those would produce something the
	// user cannot copy and paste.
	for i, line := range strings.Split(strings.TrimRight(ch.Fix, "\n"), "\n") {
		if i == 0 {
			fmt.Fprintf(c.out, "%sfix: %s\n", checkIndent, strings.TrimSpace(line))
			continue
		}
		fmt.Fprintf(c.out, "%s     %s\n", checkIndent, strings.TrimRight(line, " "))
	}
}

// wrapText folds s to width columns on word boundaries, preserving the line
// breaks already in it. An empty string yields no lines.
func wrapText(s string, width int) []string {
	if width < 20 {
		width = 20
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			continue
		}
		line := words[0]
		for _, w := range words[1:] {
			if len([]rune(line))+1+len([]rune(w)) > width {
				out = append(out, line)
				line = w
				continue
			}
			line += " " + w
		}
		out = append(out, line)
	}
	return out
}

// humanBytes renders a byte count the way a status line should read.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	i := -1
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// secs renders a float second count as a human duration.
func secs(v float64) string {
	return ctl.FormatDuration(time.Duration(v * float64(time.Second)))
}

// sortedStrings is a small helper for deterministic output.
func sortedStrings(v []string) []string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}

// goVersion is reported by `zaprctl version` so a mismatch between a freshly
// built CLI and an installed daemon is visible.
func goVersion() string { return runtime.Version() }
