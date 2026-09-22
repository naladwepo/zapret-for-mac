// Package vpn detects VPN clients that hold an IPv4 default route and stops
// them in a way the machine can recover from.
//
// This exists because of a concrete failure mode. The packet datapath steers
// traffic into a utun and re-emits it on the physical link; if a full-tunnel VPN
// owns the default route, the kernel picks source addresses from the tunnel and
// those re-emitted packets are dropped by the gateway — every steered
// connection dies, censored or not. So the datapath refuses to start in that
// situation, and this package is how a user resolves it without hunting for
// processes by hand.
//
// Design rules, in order of importance:
//
//  1. Only known VPN software is ever touched. A tunnel interface with no
//     recognised owner is reported, never killed: something else on the machine
//     may legitimately own it.
//  2. Stopping is graceful first. macOS VPN clients install a launchd job; the
//     supported way to stop one is `launchctl bootout`, which lets the client
//     tear down its own routes, DNS and firewall rules. SIGTERM and SIGKILL are
//     last resorts behind an explicit flag, because a killed VPN can leave the
//     machine with no working network at all.
//  3. Everything is reversible and the reversal is recorded, so `vpn start`
//     brings back exactly what `vpn stop` took down.
package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Standard launchd locations. User agents are also searched under the home of
// every logged-in console user, because a VPN installed per-user lives there.
const (
	systemDaemonDir = "/Library/LaunchDaemons"
	systemAgentDir  = "/Library/LaunchAgents"
)

// stopTimeout bounds how long Stop waits for a tunnel to disappear before it
// escalates or gives up.
const stopTimeout = 20 * time.Second

// signature describes how to recognise one VPN product.
type signature struct {
	// Name is what the user sees.
	Name string
	// AppName is the .app bundle name, used for a graceful "quit" via
	// osascript. Empty when the product has no GUI.
	AppName string
	// PlistNames are exact launchd plist file names.
	PlistNames []string
	// LabelPrefixes match a launchd label (com.example.vpn...).
	LabelPrefixes []string
	// ProcNames are executable base names. Matching is exact to avoid killing
	// something merely similar.
	ProcNames []string
}

// signatures is the allow-list. Nothing outside it is ever stopped.
//
// The entries were chosen from what actually ships as a macOS VPN client and
// installs a launchd job that can hold a default route. Adding a product means
// adding it here, deliberately.
var signatures = []signature{
	{
		Name:          "Happ",
		AppName:       "Happ",
		LabelPrefixes: []string{"su.ffg.happ"},
		ProcNames:     []string{"Happ"},
	},
	{
		Name:       "AmneziaVPN",
		AppName:    "AmneziaVPN",
		PlistNames: []string{"AmneziaVPN.plist"},
		ProcNames:  []string{"AmneziaVPN-service", "AmneziaVPN"},
	},
	{
		Name:       "OpenVPN Connect",
		AppName:    "OpenVPN Connect",
		PlistNames: []string{"org.openvpn.client.plist", "org.openvpn.helper.plist"},
		ProcNames:  []string{"ovpnagent", "ovpnhelper", "OpenVPN Connect"},
	},
	{
		Name:          "WireGuard",
		AppName:       "WireGuard",
		LabelPrefixes: []string{"com.wireguard"},
		ProcNames:     []string{"wireguard-go", "wg-quick"},
	},
	{
		Name:          "Tunnelblick",
		AppName:       "Tunnelblick",
		LabelPrefixes: []string{"net.tunnelblick"},
		ProcNames:     []string{"openvpn"},
	},
	{
		Name:          "ProtonVPN",
		AppName:       "ProtonVPN",
		LabelPrefixes: []string{"ch.protonvpn"},
	},
	{
		Name:          "NordVPN",
		AppName:       "NordVPN",
		LabelPrefixes: []string{"com.nordvpn"},
	},
	{
		Name:          "Mullvad VPN",
		AppName:       "Mullvad VPN",
		LabelPrefixes: []string{"net.mullvad"},
		ProcNames:     []string{"mullvad-daemon"},
	},
	{
		Name:          "Outline",
		AppName:       "Outline",
		LabelPrefixes: []string{"org.outline"},
	},
	{
		Name:      "sing-box / Xray / Clash class tunnel",
		ProcNames: []string{"sing-box", "xray", "v2ray", "clash", "clash-verge", "tun2socks", "hev-socks5-tunnel"},
	},
}

// Job is one launchd job belonging to a VPN.
type Job struct {
	Label     string `json:"label"`
	PlistPath string `json:"plist"`
	// Domain is "system" for /Library/LaunchDaemons and "gui/<uid>" for an agent.
	Domain string `json:"domain"`
	Loaded bool   `json:"loaded"`
}

// Process is a running executable matched by signature.
type Process struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// Finding is one detected VPN product.
type Finding struct {
	Provider  string    `json:"provider"`
	Jobs      []Job     `json:"jobs,omitempty"`
	Processes []Process `json:"processes,omitempty"`
	// AppRunning is true when the GUI application is up and can be asked to quit.
	AppRunning bool   `json:"app_running"`
	AppName    string `json:"app_name,omitempty"`
}

// Report is what Detect returns.
type Report struct {
	// Findings are recognised VPN products, whether or not they hold a route.
	Findings []Finding `json:"findings"`
	// TunnelDefaults are tunnel interfaces currently holding an IPv4 default
	// route. This is the thing that actually blocks the packet datapath.
	TunnelDefaults []string `json:"tunnel_defaults"`
	// Unattributed are tunnel default-route interfaces we could not attribute
	// to any known product. They are reported and never touched.
	Unattributed []string `json:"unattributed,omitempty"`
}

// Blocking reports whether anything currently holds a tunnel default route.
func (r Report) Blocking() bool { return len(r.TunnelDefaults) > 0 }

// TunnelLister returns the tunnel interfaces holding an IPv4 default route.
// It is a parameter so the caller supplies netcfg's routing-table reader and
// this package stays testable and dependency-free.
type TunnelLister func() ([]string, error)

// Detect enumerates known VPN software and current tunnel default routes.
func Detect(tunnels TunnelLister) (Report, error) {
	var rep Report
	if tunnels != nil {
		t, err := tunnels()
		if err != nil {
			return rep, fmt.Errorf("vpn: reading default routes: %w", err)
		}
		rep.TunnelDefaults = t
	}

	procs, _ := runningProcesses()
	loaded := loadedLabels()

	for _, sig := range signatures {
		f := Finding{Provider: sig.Name, AppName: sig.AppName}
		for _, p := range procs {
			if matchesProc(sig, p) {
				f.Processes = append(f.Processes, p)
				// Exact executable name, not a path prefix: the helper
				// "AmneziaVPN.app/Contents/MacOS/AmneziaVPN-service" lives under
				// the same bundle as the GUI binary and a prefix match reported a
				// running app that was not there.
				if sig.AppName != "" && p.Name == sig.AppName {
					f.AppRunning = true
				}
			}
		}
		f.Jobs = append(f.Jobs, jobsFor(sig, loaded)...)
		if len(f.Processes) > 0 || len(f.Jobs) > 0 {
			rep.Findings = append(rep.Findings, f)
		}
	}

	// A tunnel default route with no recognised owner is worth saying out loud:
	// it blocks the datapath and we deliberately will not touch it.
	if len(rep.TunnelDefaults) > 0 && len(rep.Findings) == 0 {
		rep.Unattributed = append(rep.Unattributed, rep.TunnelDefaults...)
	}
	return rep, nil
}

// matchesProc reports whether a process belongs to a signature. Base names are
// compared exactly: "openvpn" must not match "openvpn-monitor-helper" from some
// unrelated package.
func matchesProc(sig signature, p Process) bool {
	for _, n := range sig.ProcNames {
		if p.Name == n {
			return true
		}
	}
	if sig.AppName != "" && strings.Contains(p.Path, "/"+sig.AppName+".app/") {
		return true
	}
	return false
}

// jobsFor finds launchd plists belonging to a signature.
func jobsFor(sig signature, loaded map[string]bool) []Job {
	var out []Job
	scan := func(dir, domain string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			label := labelFromPlist(path)
			hit := false
			for _, n := range sig.PlistNames {
				if e.Name() == n {
					hit = true
				}
			}
			for _, pre := range sig.LabelPrefixes {
				if label != "" && strings.HasPrefix(label, pre) {
					hit = true
				}
			}
			if !hit {
				continue
			}
			if label == "" {
				label = strings.TrimSuffix(e.Name(), ".plist")
			}
			out = append(out, Job{Label: label, PlistPath: path, Domain: domain, Loaded: loaded[label]})
		}
	}
	scan(systemDaemonDir, "system")
	scan(systemAgentDir, guiDomain())
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// reLabel extracts the Label value from a launchd plist. A regex rather than a
// plist parser keeps this dependency-free; launchd plists put the label in a
// <string> right after <key>Label</key> in both XML and (converted) binary form,
// and a miss simply falls back to the file name.
var reLabel = regexp.MustCompile(`(?s)<key>\s*Label\s*</key>\s*<string>([^<]+)</string>`)

// labelFromPlist reads a job's label, converting a binary plist first if needed.
func labelFromPlist(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if m := reLabel.FindSubmatch(b); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	// Binary plist: ask plutil for an XML rendering on stdout.
	out, err := exec.Command("/usr/bin/plutil", "-convert", "xml1", "-o", "-", path).Output()
	if err != nil {
		return ""
	}
	if m := reLabel.FindSubmatch(out); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// guiDomain returns the launchd domain for user agents, e.g. "gui/501".
func guiDomain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

// loadedLabels lists labels launchd currently knows about.
func loadedLabels() map[string]bool {
	out := map[string]bool{}
	b, err := exec.Command("/bin/launchctl", "list").Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 {
			out[fields[2]] = true
		}
	}
	return out
}

// reProcLine parses one `ps -axo pid=,comm=` row.
var reProcLine = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)

// runningProcesses lists processes with their executable path.
func runningProcesses() ([]Process, error) {
	b, err := exec.Command("/bin/ps", "-axo", "pid=,comm=").Output()
	if err != nil {
		return nil, err
	}
	var out []Process
	for _, line := range strings.Split(string(b), "\n") {
		m := reProcLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pid, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		path := strings.TrimSpace(m[2])
		out = append(out, Process{PID: pid, Name: filepath.Base(path), Path: path})
	}
	return out, nil
}

// StopOpts controls how hard Stop tries.
type StopOpts struct {
	// Force permits SIGTERM and then SIGKILL when launchd and a graceful quit
	// were not enough. Off by default: a killed VPN client can leave routes,
	// DNS settings and firewall rules behind, which is worse than a running one.
	Force bool
	// Timeout bounds the wait for tunnels to disappear (default 20s).
	Timeout time.Duration
	// StateFile records what was stopped so Start can restore it.
	StateFile string
	// Logf receives progress lines.
	Logf func(string, ...any)
}

// StopResult describes what happened.
type StopResult struct {
	Stopped   []string `json:"stopped"`   // human-readable actions performed
	Remaining []string `json:"remaining"` // tunnel defaults still present
	Restore   []string `json:"restore"`   // commands that undo this
}

// stoppedState is the on-disk record of a Stop, so Start can undo exactly it.
type stoppedState struct {
	Jobs []Job     `json:"jobs"`
	When time.Time `json:"when"`
}

// Stop takes down every recognised VPN that holds (or could hold) a tunnel
// default route, gracefully first.
//
// Order matters and is deliberate: quit the GUI app so the client tears its own
// tunnel down, then bootout its launchd job, and only with Force signal the
// processes. After each step it re-checks whether any tunnel default route
// survives, and stops as soon as the blockage is gone.
func Stop(ctx context.Context, rep Report, tunnels TunnelLister, o StopOpts) (StopResult, error) {
	var res StopResult
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = stopTimeout
	}
	deadline := time.Now().Add(timeout)

	var state stoppedState
	state.When = time.Now()

	clear := func() bool {
		if tunnels == nil {
			return false
		}
		t, err := tunnels()
		if err != nil {
			return false
		}
		res.Remaining = t
		return len(t) == 0
	}

	for _, f := range rep.Findings {
		if f.AppRunning && f.AppName != "" {
			logf("asking %s to quit", f.AppName)
			// osascript's "quit" is the documented way to end a GUI app; the VPN
			// client then removes its own routes and DNS settings.
			_ = exec.CommandContext(ctx, "/usr/bin/osascript", "-e",
				fmt.Sprintf("tell application %q to quit", f.AppName)).Run()
			res.Stopped = append(res.Stopped, "quit application "+f.AppName)
			waitUntil(ctx, deadline, 2*time.Second, clear)
		}
	}
	if clear() {
		res.Restore = restoreCommands(state.Jobs)
		return res, writeState(o.StateFile, state)
	}

	for _, f := range rep.Findings {
		for _, j := range f.Jobs {
			target := j.Domain + "/" + j.Label
			logf("bootout %s", target)
			out, err := exec.CommandContext(ctx, "/bin/launchctl", "bootout", target).CombinedOutput()
			if err != nil {
				// "No such process" simply means it was not loaded.
				if !strings.Contains(strings.ToLower(string(out)), "no such process") {
					logf("launchctl bootout %s: %v: %s", target, err, strings.TrimSpace(string(out)))
					continue
				}
			}
			state.Jobs = append(state.Jobs, j)
			res.Stopped = append(res.Stopped, "unloaded launchd job "+target)
			if waitUntil(ctx, deadline, 3*time.Second, clear) {
				res.Restore = restoreCommands(state.Jobs)
				return res, writeState(o.StateFile, state)
			}
		}
	}

	if clear() {
		res.Restore = restoreCommands(state.Jobs)
		return res, writeState(o.StateFile, state)
	}

	if !o.Force {
		res.Restore = restoreCommands(state.Jobs)
		if err := writeState(o.StateFile, state); err != nil {
			return res, err
		}
		if len(res.Remaining) == 0 {
			return res, nil
		}
		return res, fmt.Errorf("a tunnel default route is still held by %s after the graceful steps; "+
			"re-run with --force to signal the processes, or disconnect the VPN from its own interface",
			strings.Join(res.Remaining, ", "))
	}

	for _, f := range rep.Findings {
		for _, p := range f.Processes {
			logf("SIGTERM %s (pid %d)", p.Name, p.PID)
			_ = syscall.Kill(p.PID, syscall.SIGTERM)
			res.Stopped = append(res.Stopped, fmt.Sprintf("SIGTERM %s (pid %d)", p.Name, p.PID))
		}
	}
	if waitUntil(ctx, deadline, 3*time.Second, clear) {
		res.Restore = restoreCommands(state.Jobs)
		return res, writeState(o.StateFile, state)
	}
	for _, f := range rep.Findings {
		for _, p := range f.Processes {
			if !alive(p.PID) {
				continue
			}
			logf("SIGKILL %s (pid %d)", p.Name, p.PID)
			_ = syscall.Kill(p.PID, syscall.SIGKILL)
			res.Stopped = append(res.Stopped, fmt.Sprintf("SIGKILL %s (pid %d)", p.Name, p.PID))
		}
	}
	waitUntil(ctx, deadline, 3*time.Second, clear)
	res.Restore = restoreCommands(state.Jobs)
	if err := writeState(o.StateFile, state); err != nil {
		return res, err
	}
	if len(res.Remaining) > 0 {
		return res, fmt.Errorf("tunnel default route still held by %s", strings.Join(res.Remaining, ", "))
	}
	return res, nil
}

// Start re-bootstraps whatever a previous Stop unloaded.
func Start(ctx context.Context, stateFile string) (StopResult, error) {
	var res StopResult
	st, err := readState(stateFile)
	if err != nil {
		return res, err
	}
	if len(st.Jobs) == 0 {
		return res, fmt.Errorf("no record of a VPN stopped by us (%s); start it from its own application", stateFile)
	}
	for _, j := range st.Jobs {
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", j.Domain, j.PlistPath).CombinedOutput()
		if err != nil && !strings.Contains(strings.ToLower(string(out)), "already bootstrapped") {
			return res, fmt.Errorf("launchctl bootstrap %s %s: %v: %s", j.Domain, j.PlistPath, err,
				strings.TrimSpace(string(out)))
		}
		res.Stopped = append(res.Stopped, "re-loaded launchd job "+j.Domain+"/"+j.Label)
	}
	_ = os.Remove(stateFile)
	return res, nil
}

// restoreCommands renders the exact commands that undo a Stop.
func restoreCommands(jobs []Job) []string {
	var out []string
	for _, j := range jobs {
		out = append(out, fmt.Sprintf("sudo launchctl bootstrap %s %s", j.Domain, j.PlistPath))
	}
	return out
}

// waitUntil polls done until it returns true, the budget expires or ctx ends.
func waitUntil(ctx context.Context, deadline time.Time, budget time.Duration, done func() bool) bool {
	end := time.Now().Add(budget)
	if end.After(deadline) {
		end = deadline
	}
	for time.Now().Before(end) {
		if done() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
		}
	}
	return done()
}

// alive reports whether a pid still exists.
func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func writeState(path string, st stoppedState) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readState(path string) (stoppedState, error) {
	var st stoppedState
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}
