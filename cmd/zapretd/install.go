//go:build darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/launchd"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
)

// runInstall implements `zapretd install-daemon`: write the LaunchDaemon plist
// and bootstrap it into the system domain.
//
// The plist bakes in only the flags that differ from the defaults, so the
// installed job stays readable and so `zaprctl use` — which persists its choice
// in the data directory — is not overridden by a --strategy frozen at install
// time.
func runInstall(args []string, stdout, stderr io.Writer) int {
	o := defaultOptions()
	fs := flag.NewFlagSet("install-daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	plistPath := fs.String("plist", launchd.DefaultPlistPath, "where to write the LaunchDaemon plist")
	program := fs.String("program", "", "daemon binary to run (default: this executable)")
	label := fs.String("label", launchd.DefaultLabel, "launchd label")
	noBootstrap := fs.Bool("no-bootstrap", false, "write the plist but do not load it")
	noGuard := fs.Bool("no-guard", false, "skip the anchor-guard job (see `zapretd guard`): only do this if you "+
		"accept that a SIGKILLed daemon leaves pf dropping the port window until the next daemon start")
	stdoutPath := fs.String("stdout", launchd.DefaultStdoutPath, "file launchd writes our stdout to")
	stderrPath := fs.String("stderr", launchd.DefaultStderrPath, "file launchd writes our stderr to")
	o.bind(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if err := o.validate(); err != nil {
		fmt.Fprintf(stderr, "install-daemon: %v\n", err)
		return exitError
	}
	if os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "install-daemon: must run as root to write %s and bootstrap the service.\nRetry with: sudo %s install-daemon %s\n",
			*plistPath, exeName(), strings.Join(args, " "))
		return exitNotRoot
	}

	prog := *program
	if prog == "" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(stderr, "install-daemon: cannot determine this executable's path: %v; pass --program\n", err)
			return exitError
		}
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		prog = exe
	}
	if !filepath.IsAbs(prog) {
		abs, err := filepath.Abs(prog)
		if err != nil {
			fmt.Fprintf(stderr, "install-daemon: %v\n", err)
			return exitError
		}
		prog = abs
	}
	if fi, err := os.Stat(prog); err != nil || fi.IsDir() {
		fmt.Fprintf(stderr, "install-daemon: %s is not an executable file (%v)\n", prog, err)
		return exitError
	}

	// launchd starts the job from a boot-time environment: the data directory
	// must exist before the first run, or the daemon fails and gets throttled.
	for _, dir := range []string{o.dataDir, filepath.Join(o.dataDir, "strategies"),
		filepath.Join(o.dataDir, "lists"), filepath.Join(o.dataDir, "fakes")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(stderr, "install-daemon: create %s: %v\n", dir, err)
			return exitError
		}
	}
	if err := os.MkdirAll(filepath.Join(o.dataDir, "state"), 0o700); err != nil {
		fmt.Fprintf(stderr, "install-daemon: create the state directory: %v\n", err)
		return exitError
	}

	p := launchd.Default(prog, plistArgs(o)...)
	p.Label = *label
	p.StandardOutPath = *stdoutPath
	p.StandardErrorPath = *stderrPath

	// Render once here so a bad option is reported before anything is booted
	// out; WritePlist renders it again for the file itself.
	if _, err := p.XML(); err != nil {
		fmt.Fprintf(stderr, "install-daemon: %v\n", err)
		return exitError
	}

	loaded, lerr := launchd.Loaded(p.Label)
	if lerr != nil {
		fmt.Fprintf(stderr, "install-daemon: cannot query system/%s: %v\n", p.Label, lerr)
		return exitError
	}
	if loaded {
		// Bootstrap refuses to replace a loaded job, and a stale plist would
		// keep running with the old arguments. Boot it out first.
		fmt.Fprintf(stdout, "system/%s is loaded; booting it out to install the new plist\n", p.Label)
		if err := launchd.Bootout(p.Label); err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
			fmt.Fprintf(stderr, "install-daemon: %v\n", err)
			return exitError
		}
		// launchd needs a moment to reap the job before the label is free.
		time.Sleep(500 * time.Millisecond)
	}

	if err := launchd.WritePlist(*plistPath, p); err != nil {
		fmt.Fprintf(stderr, "install-daemon: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "wrote %s (root:wheel 0644)\n", *plistPath)
	fmt.Fprintf(stdout, "  program   %s\n", p.Program)
	fmt.Fprintf(stdout, "  arguments %s\n", strings.Join(p.ProgramArguments[1:], " "))
	fmt.Fprintf(stdout, "  logs      %s / %s\n", p.StandardOutPath, p.StandardErrorPath)

	if *noBootstrap {
		fmt.Fprintf(stdout, "not loading it (--no-bootstrap); load it with:\n  sudo launchctl bootstrap system %s\n", *plistPath)
		return exitOK
	}
	if err := launchd.Bootstrap(*plistPath); err != nil {
		if errors.Is(err, launchd.ErrAlreadyLoaded) {
			fmt.Fprintf(stdout, "system/%s was already loaded; restarting it\n", p.Label)
			if kerr := launchd.Kickstart(p.Label, true); kerr != nil {
				fmt.Fprintf(stderr, "install-daemon: %v\n", kerr)
				return exitError
			}
		} else {
			fmt.Fprintf(stderr, "install-daemon: %v\n", err)
			return exitError
		}
	}
	fmt.Fprintf(stdout, "bootstrapped system/%s\n", p.Label)

	if !*noGuard {
		if code := installGuard(prog, o, stdout, stderr); code != exitOK {
			return code
		}
	} else {
		fmt.Fprintf(stdout, "\nNOT installing the anchor guard (--no-guard).\n")
	}

	fmt.Fprintf(stdout, `
It is now listed in System Settings > General > Login Items & Extensions, enabled.
That entry is disclosure, not an approval gate — but if you switch it off there,
the daemon will not start again until you switch it back on.

IF ANYTHING GOES WRONG and connections on the strategy ports stop working, this
command resolves and empties the exact pf anchor used on this Mac:

  sudo %s guard --data %q --anchor %s --verbose

Next:
  zaprctl status
  zaprctl list
  sudo zaprctl use cloud-gaming
`, prog, o.dataDir, o.anchor)
	return exitOK
}

// installGuard writes and bootstraps the periodic anchor-guard job.
//
// It is what makes the pflog interception rules survivable: originals stay
// blocked if the daemon dies before removing its anchor. See guard.go.
func installGuard(prog string, o options, stdout, stderr io.Writer) int {
	args := []string{"guard", "--data", o.dataDir}
	if o.anchor != defaultOptions().anchor {
		args = append(args, "--anchor", o.anchor)
	}
	if o.pfConfPath != "" {
		args = append(args, "--pf-conf", o.pfConfPath)
	}
	g := launchd.Guard(prog, args...)
	if _, err := g.XML(); err != nil {
		fmt.Fprintf(stderr, "install-daemon: the guard plist is invalid: %v\n", err)
		return exitError
	}
	if loaded, err := launchd.Loaded(g.Label); err == nil && loaded {
		if err := launchd.Bootout(g.Label); err != nil && !errors.Is(err, launchd.ErrNotLoaded) {
			fmt.Fprintf(stderr, "install-daemon: cannot boot out the old guard: %v\n", err)
			return exitError
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err := launchd.WritePlist(launchd.GuardPlistPath, g); err != nil {
		fmt.Fprintf(stderr, "install-daemon: %v\n", err)
		return exitError
	}
	if err := launchd.Bootstrap(launchd.GuardPlistPath); err != nil && !errors.Is(err, launchd.ErrAlreadyLoaded) {
		fmt.Fprintf(stderr, "install-daemon: cannot bootstrap the guard: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "wrote %s and bootstrapped system/%s\n", launchd.GuardPlistPath, g.Label)
	fmt.Fprintf(stdout, "  the guard runs every %ds and flushes the %q anchor whenever no daemon owns it,\n"+
		"  so a `kill -9` cannot leave pf dropping your traffic for longer than that\n",
		launchd.GuardInterval, o.anchor)
	return exitOK
}

// plistArgs renders the daemon flags worth freezing into the plist: only those
// that differ from the defaults.
func plistArgs(o options) []string {
	def := defaultOptions()
	var args []string
	add := func(flag, val string) { args = append(args, flag, val) }

	// --data is always written: it is the one path everything else hangs off.
	add("--data", o.dataDir)
	if o.transport != def.transport {
		add("--transport", o.transport)
	}
	if o.strategy != "" {
		// Deliberate opt-in: with this baked in, `zaprctl use` still switches
		// the running daemon but the flag wins again after a restart.
		add("--strategy", o.strategy)
	}
	if o.iface != "" {
		add("--iface", o.iface)
	}
	if o.proxyPort != def.proxyPort {
		add("--proxy-port", strconv.Itoa(o.proxyPort))
	}
	if o.utunUnit != def.utunUnit {
		add("--utun-unit", strconv.Itoa(o.utunUnit))
	}
	if o.socketPath != def.socketPath {
		add("--socket", o.socketPath)
	}
	if o.socketGroup != def.socketGroup {
		add("--socket-group", o.socketGroup)
	}
	if o.anchor != def.anchor {
		add("--anchor", o.anchor)
	}
	if o.tunLocal != def.tunLocal {
		add("--tun-local", o.tunLocal)
	}
	if o.tunPeer != def.tunPeer {
		add("--tun-peer", o.tunPeer)
	}
	if o.pfConfPath != "" {
		add("--pf-conf", o.pfConfPath)
	}
	if o.hostsPath != "" {
		add("--hosts", o.hostsPath)
	}
	if o.probeAddr != "" {
		add("--probe-addr", o.probeAddr)
	}
	if o.logPath != def.logPath {
		add("--log", o.logPath)
	}
	if o.verbose > 0 {
		add("--verbose", strconv.Itoa(o.verbose))
	}
	if o.blockQUIC {
		args = append(args, "--block-quic")
	}
	if o.noExemptRoot {
		args = append(args, "--no-exempt-root")
	}
	if o.allowVPN {
		args = append(args, "--allow-vpn")
	}
	if o.dryRun {
		args = append(args, "--dry-run")
	}
	// --foreground is never written: under launchd the parent IS launchd, which
	// is exactly the supervised case the flag exists to bypass.
	return args
}

// runUninstall implements `zapretd uninstall-daemon`: stop the service, remove
// the plist and revert every system change that could outlive the process.
//
// It is deliberately tolerant: each step reports what it did and the command
// keeps going, because a half-uninstalled packet interceptor is the one state
// nobody should be left in.
func runUninstall(args []string, stdout, stderr io.Writer) int {
	o := defaultOptions()
	fs := flag.NewFlagSet("uninstall-daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	plistPath := fs.String("plist", launchd.DefaultPlistPath, "plist to remove")
	label := fs.String("label", launchd.DefaultLabel, "launchd label to boot out")
	keepHosts := fs.Bool("keep-hosts", false, "leave the /etc/hosts pinning block in place")
	keepPf := fs.Bool("keep-pf", false, "leave our anchor statements in /etc/pf.conf")
	o.bind(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "uninstall-daemon: must run as root.\nRetry with: sudo %s uninstall-daemon %s\n",
			exeName(), strings.Join(args, " "))
		return exitNotRoot
	}

	failed := false
	step := func(what string, err error) {
		if err != nil {
			failed = true
			fmt.Fprintf(stderr, "  %-28s FAILED: %v\n", what, err)
			return
		}
		fmt.Fprintf(stdout, "  %-28s ok\n", what)
	}

	fmt.Fprintf(stdout, "uninstalling zapret-mac:\n")

	// Booting the job out sends SIGTERM, which makes the daemon run its own
	// rollback. Everything after this is belt and braces for the case where it
	// had already been killed.
	err := launchd.Bootout(*label)
	switch {
	case err == nil:
		step("bootout system/"+*label, nil)
		time.Sleep(700 * time.Millisecond)
	case errors.Is(err, launchd.ErrNotLoaded):
		fmt.Fprintf(stdout, "  %-28s not loaded\n", "bootout system/"+*label)
	default:
		step("bootout system/"+*label, err)
	}

	step("remove "+*plistPath, launchd.RemovePlist(*plistPath))

	// The guard job goes with it: it exists only to clean up after this daemon,
	// and a guard left behind would keep waking up every few seconds for ever.
	gerr := launchd.Bootout(launchd.GuardLabel)
	switch {
	case gerr == nil:
		step("bootout system/"+launchd.GuardLabel, nil)
	case errors.Is(gerr, launchd.ErrNotLoaded):
		fmt.Fprintf(stdout, "  %-28s not loaded\n", "bootout the anchor guard")
	default:
		step("bootout system/"+launchd.GuardLabel, gerr)
	}
	step("remove "+launchd.GuardPlistPath, launchd.RemovePlist(launchd.GuardPlistPath))

	stateDir := filepath.Join(o.dataDir, "state")
	pf := netcfg.NewPF(o.anchor, netcfg.PFOpts{
		PfConfPath: o.pfConfPath,
		StateDir:   stateDir,
		Logf:       func(f string, a ...any) { fmt.Fprintf(stdout, "    "+f+"\n", a...) },
	})
	if _, err := pf.ResolveAnchor(); err != nil {
		step("resolve the "+o.anchor+" anchor", err)
	}
	step("flush the "+o.anchor+" anchor", pf.FlushRules())
	if !*keepPf {
		perr := pf.RemoveAnchorStatements()
		if perr != nil && errors.Is(perr, netcfg.ErrPfConfDrift) {
			fmt.Fprintf(stdout, "  %-28s ok (the file had been edited since we patched it; only our block was removed)\n",
				"unpatch "+pf.PfConfPath())
		} else {
			step("unpatch "+pf.PfConfPath(), perr)
		}
	}
	step("release the pf reference", pf.Release())

	if !*keepHosts {
		h := netcfg.NewHosts(o.hostsPath, stateDir)
		h.SetLogf(func(f string, a ...any) { fmt.Fprintf(stdout, "    "+f+"\n", a...) })
		if err := h.Remove(); err != nil {
			step("remove the hosts block", err)
		} else {
			step("remove the hosts block", nil)
			if err := netcfg.FlushDNSCache(); err != nil {
				fmt.Fprintf(stdout, "    DNS cache flush failed: %v\n", err)
			}
		}
		_ = h.Close()
	}

	if j := pf.Journal(); j != nil {
		step("clear the rollback journal", j.Clear())
	}
	_ = pf.Close()

	// A socket file left behind by a killed daemon would make the next install
	// think another daemon is running.
	if fi, err := os.Lstat(o.socketPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
		step("remove "+o.socketPath, os.Remove(o.socketPath))
	}

	fmt.Fprintf(stdout, `
Removed the service and every system change. Left in place:
  %s   (strategies, lists, fakes, backups — delete it yourself if you want to)
  %s   (log, rotated by newsyslog)
`, o.dataDir, launchd.DefaultStdoutPath)
	if failed {
		fmt.Fprintf(stderr, "\nsome steps failed; run `sudo zaprctl doctor --repair` (exit code 1)\n")
		return exitError
	}
	return exitOK
}
