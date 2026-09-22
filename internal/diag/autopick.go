package diag

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// Client is the slice of the control-socket client that the auto-picker needs:
// activate a strategy by name, and ask which one is active. internal/ctl's
// client satisfies it; declaring the interface here rather than importing that
// package keeps diag usable from a test with a stub and keeps the dependency
// pointing one way.
type Client interface {
	// Activate makes the named strategy the running one, returning only once the
	// daemon has applied it.
	Activate(ctx context.Context, name string) error
	// Active reports the name of the currently running strategy, "" when none
	// is.
	Active(ctx context.Context) (string, error)
}

// ClientFuncs adapts a pair of closures to Client, so a caller holding an
// internal/ctl client does not need a named wrapper type. The two operations map
// onto ctl.Client.Use and ctl.Client.Status:
//
//	diag.ClientFuncs{
//	    ActivateFn: func(ctx context.Context, name string) error {
//	        _, err := c.Use(ctx, name)
//	        return err
//	    },
//	    ActiveFn: func(ctx context.Context) (string, error) {
//	        st, err := c.Status(ctx)
//	        return st.Strategy, err
//	    },
//	}
//
// A nil ActiveFn reports no active strategy, which disables the restore step; a
// nil ActivateFn is an error, since activation is the whole point.
type ClientFuncs struct {
	ActivateFn func(ctx context.Context, name string) error
	ActiveFn   func(ctx context.Context) (string, error)
}

// Activate implements Client.
func (c ClientFuncs) Activate(ctx context.Context, name string) error {
	if c.ActivateFn == nil {
		return errors.New("diag: ClientFuncs.ActivateFn is nil")
	}
	return c.ActivateFn(ctx, name)
}

// Active implements Client.
func (c ClientFuncs) Active(ctx context.Context) (string, error) {
	if c.ActiveFn == nil {
		return "", nil
	}
	return c.ActiveFn(ctx)
}

// PickOpts configures Pick.
type PickOpts struct {
	// Strategies is the ordered candidate list. When empty, StrategyDir is
	// compiled with LoadOpts (strategy.LoadDir already returns flowseal's
	// strategy-menu order, so "general (ALT2)" precedes "general (ALT10)").
	Strategies  []*strategy.Strategy
	StrategyDir string
	LoadOpts    strategy.LoadOpts

	// Caps is the active transport's capabilities. It decides which strategies
	// are worth testing at all: a fake-based strategy under the proxy transport
	// exercises nothing the proxy can do, so its score would be noise.
	Caps desync.Caps

	// Client activates each candidate. Required unless DryRun is set.
	Client Client

	// Probes is the probe subset each candidate is measured with. Defaults to
	// PickProbes(), which is deliberately short: the picker runs it once per
	// strategy, so a full DefaultProbes sweep over twenty strategies would take
	// minutes.
	Probes []Probe
	// Run configures the probe runner.
	Run RunOpts

	// Settle is how long to wait after activation before probing, so the daemon
	// has reloaded its anchor and the previous strategy's flows have expired.
	// Defaults to 1.5s.
	Settle time.Duration

	// Order optionally overrides the candidate order by name; names not listed
	// keep their original relative order after the listed ones.
	Order []string
	// MaxCandidates caps how many strategies are tried. 0 means all of them.
	MaxCandidates int
	// NoEarlyStop keeps testing after a candidate scores perfectly. By default
	// the first perfect score wins, because that is what the user asked for and
	// every further candidate costs another round of probes.
	NoEarlyStop bool
	// Rounds repeats the probe set for each candidate. A candidate must keep its
	// controls alive in every round; all target results are included in the
	// score, so a one-off success cannot win a stability run. Defaults to 1.
	Rounds int
	// SkipUnsupported drops candidates the transport cannot fully honour instead
	// of testing them anyway. Off by default: a strategy whose fake ops are
	// skipped can still work through its splits alone, and that is worth
	// knowing.
	SkipUnsupported bool

	// DryRun reports which strategies the active transport fully supports and
	// activates nothing.
	DryRun bool

	// Logf receives progress lines.
	Logf func(format string, args ...any)
}

// withDefaults fills in the unset fields.
func (o PickOpts) withDefaults() PickOpts {
	if len(o.Probes) == 0 {
		o.Probes = PickProbes()
	}
	if o.Settle <= 0 {
		o.Settle = 1500 * time.Millisecond
	}
	if o.Rounds <= 0 {
		o.Rounds = 1
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// PickProbes is the short probe set the auto-picker uses per candidate: one
// control endpoint plus the four target families flowseal's strategies exist for
// (YouTube web, googlevideo playback, the Discord API and the Discord gateway
// handshake). Keeping it to five keeps a twenty-strategy sweep inside a minute.
func PickProbes() []Probe {
	return []Probe{
		{Name: "control example.com", URL: "https://example.com/", Control: true, Expect: 200},
		{Name: "youtube.com", URL: "https://www.youtube.com/", Download: 16 * 1024},
		{Name: "googlevideo (playback)", URL: "https://redirector.googlevideo.com/", Download: 16 * 1024},
		{Name: "discord.com", URL: "https://discord.com/"},
		{Name: "gateway.discord.gg", URL: "tls://gateway.discord.gg:443"},
	}
}

// DiscordPickProbes is the short but protocol-complete set used by
// `autopick --suite discord`. Unlike the generic picker it verifies the API
// request, the real WebSocket upgrade and the UDP/STUN voice path.
func DiscordPickProbes() []Probe {
	return []Probe{
		{Name: "control example.com", URL: "https://example.com/", Control: true, Expect: 200},
		{Name: "discord API", URL: "https://discord.com/api/v10/gateway"},
		{Name: "discord Gateway WSS", URL: "wss://gateway.discord.gg/?v=10&encoding=json"},
		{Name: "UDP/STUN voice path", URL: "stun://stun.l.google.com:19302"},
	}
}

// Score is a candidate's measured quality.
//
// Control probes are counted separately and never contribute to Passed: they
// always succeed on a healthy machine, so including them would flatten the
// difference between strategies. Their only job is to invalidate a measurement
// taken while the machine had no internet at all.
type Score struct {
	// Targets is the number of non-control probes, Passed how many succeeded.
	Targets int
	Passed  int
	// Blocked counts failures carrying a DPI signature.
	Blocked int
	// ControlTotal and ControlPassed count the control probes.
	ControlTotal  int
	ControlPassed int
	// MedianFirstByte is the median latency across the probes that passed.
	MedianFirstByte time.Duration
}

// Valid reports whether the measurement means anything: at least one control
// probe passed, or there were no control probes to begin with.
func (s Score) Valid() bool {
	return s.ControlTotal == 0 || s.ControlPassed > 0
}

// Perfect reports whether every target probe passed on a valid measurement.
func (s Score) Perfect() bool {
	return s.Valid() && s.Targets > 0 && s.Passed == s.Targets
}

// String renders the score compactly.
func (s Score) String() string {
	v := ""
	if !s.Valid() {
		v = " (INVALID: control probes failed)"
	}
	return fmt.Sprintf("%d/%d targets, median first byte %s%s",
		s.Passed, s.Targets, s.MedianFirstByte.Round(time.Millisecond), v)
}

// Better reports whether s should outrank other.
//
// The ordering is: a valid measurement beats an invalid one; more targets passed
// wins; then fewer DPI-signature failures; then the lower median first-byte time.
// Latency is the tie-break rather than a weighted term because the difference
// between two strategies that both work is small and noisy, while the difference
// between working and not working is the entire question.
func (s Score) Better(other Score) bool {
	if s.Valid() != other.Valid() {
		return s.Valid()
	}
	if s.Passed != other.Passed {
		return s.Passed > other.Passed
	}
	if s.Blocked != other.Blocked {
		return s.Blocked < other.Blocked
	}
	if s.MedianFirstByte != other.MedianFirstByte {
		// A zero median means nothing passed, which must not sort first.
		if s.MedianFirstByte == 0 {
			return false
		}
		if other.MedianFirstByte == 0 {
			return true
		}
		return s.MedianFirstByte < other.MedianFirstByte
	}
	return false
}

// ScoreResults reduces one candidate's probe results to a Score. Pure.
func ScoreResults(results []Result) Score {
	var (
		s    Score
		ttfb []time.Duration
	)
	for _, r := range results {
		if r.Control {
			s.ControlTotal++
			if r.OK {
				s.ControlPassed++
			}
			continue
		}
		s.Targets++
		switch {
		case r.OK:
			s.Passed++
			switch {
			case r.FirstByteTime > 0:
				ttfb = append(ttfb, r.FirstByteTime)
			case r.TLSTime > 0:
				// A TLS-only probe has no first byte; its handshake is the
				// comparable latency.
				ttfb = append(ttfb, r.TLSTime)
			}
		case Blocked(r.Class):
			s.Blocked++
		}
	}
	s.MedianFirstByte = median(ttfb)
	return s
}

// Candidate is one strategy's entry in the ranked table.
type Candidate struct {
	// Name is the strategy's name.
	Name string
	// Strategy is the compiled strategy, nil when it was supplied by name only.
	Strategy *strategy.Strategy
	// Supported is false when the active transport cannot honour every op;
	// Unsupported then lists them in strategy.Strategy.Unsupported's format.
	Supported   bool
	Unsupported []string
	// Score is the measurement, zero when the candidate was skipped.
	Score Score
	// BreaksTraffic marks a candidate that made even the control endpoints fail
	// while it was active, with connectivity returning once it was deactivated.
	// That is a property of the strategy, not of the network.
	BreaksTraffic bool
	// Results are the per-probe details — the per-host and per-IP evidence for
	// why this candidate scored what it did.
	Results []Result
	// Skipped explains why no measurement was taken, "" when one was.
	Skipped string
	// Err records an activation or probe failure.
	Err string
}

// PickResult is Pick's report.
type PickResult struct {
	// Best is the winning strategy's name, "" when nothing worked.
	Best string
	// BestScore is the winner's score.
	BestScore Score
	// Ranked is every candidate, best first.
	Ranked []Candidate
	// Original is the strategy that was active before Pick started, and
	// Restored whether Pick put it back (it does on cancellation, and when no
	// candidate managed to pass a single target probe).
	Original string
	Restored bool
	// Activated is the strategy left running when Pick returned.
	Activated string
	// Tested counts the candidates that were actually measured.
	Tested int
	// StoppedEarly is true when a perfect score ended the sweep.
	StoppedEarly bool
	// DryRun mirrors PickOpts.DryRun.
	DryRun bool
}

// Pick is the answer to "try strategies until one works", which is the actual UX
// of the Windows original — except mechanised: activate, wait, probe, score,
// keep the best.
//
// Order is the candidate list's own order, which for strategy.LoadDir is
// flowseal's strategy-menu order, so the strategies its README recommends trying
// first are tried first.
//
// Two safety properties matter more than the ranking:
//
//   - the strategy that was active before Pick started is captured up front and
//     restored on context cancellation (through a context that is deliberately
//     immune to that cancellation, or the restore could not run) and when no
//     candidate managed a single passing target probe. Leaving the machine on a
//     random half-tested strategy after Ctrl-C would be worse than not running
//     at all;
//   - with DryRun nothing is activated at all. It reports which strategies the
//     active transport fully supports, using strategy.Strategy.Unsupported,
//     because measuring a fake-based strategy under the proxy transport is
//     meaningless: the fake ops never run, so the score describes the splits
//     alone and attributes their result to the wrong strategy.
func Pick(ctx context.Context, o PickOpts) (PickResult, error) {
	o = o.withDefaults()

	candidates, err := resolveStrategies(o)
	if err != nil {
		return PickResult{}, err
	}
	if len(candidates) == 0 {
		return PickResult{}, errors.New("diag: no strategies to pick from")
	}
	if o.MaxCandidates > 0 && len(candidates) > o.MaxCandidates {
		candidates = candidates[:o.MaxCandidates]
	}

	res := PickResult{DryRun: o.DryRun}

	// Classify support first: it is pure, needs nothing from the daemon, and is
	// the entire answer in dry-run mode.
	list := make([]Candidate, 0, len(candidates))
	for _, s := range candidates {
		c := Candidate{Name: s.Name, Strategy: s}
		c.Unsupported = s.Unsupported(o.Caps)
		c.Supported = len(c.Unsupported) == 0
		list = append(list, c)
	}

	if o.DryRun {
		for i := range list {
			if !list[i].Supported {
				list[i].Skipped = "the active transport cannot honour: " + strings.Join(list[i].Unsupported, "; ")
			}
		}
		res.Ranked = rankDryRun(list)
		for _, c := range res.Ranked {
			if c.Supported {
				res.Best = c.Name
				break
			}
		}
		return res, nil
	}

	if o.Client == nil {
		return PickResult{}, errors.New("diag: Pick needs a Client to activate strategies (or DryRun)")
	}

	if name, err := o.Client.Active(ctx); err == nil {
		res.Original = name
	} else {
		o.Logf("diag: cannot read the active strategy, so none can be restored afterwards: %v", err)
	}

	// The restore must survive the cancellation that triggers it, so it runs on
	// a context detached from ctx's cancellation but still bounded by a deadline.
	restore := func(reason string) {
		if res.Original == "" || res.Original == res.Activated {
			return
		}
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if err := o.Client.Activate(rctx, res.Original); err != nil {
			o.Logf("diag: could not restore strategy %q (%s): %v", res.Original, reason, err)
			return
		}
		res.Restored = true
		res.Activated = res.Original
		o.Logf("diag: restored strategy %q (%s)", res.Original, reason)
	}

	var best *Candidate
	for i := range list {
		c := &list[i]
		if err := ctx.Err(); err != nil {
			c.Skipped = "cancelled before this candidate was tried"
			restore("cancelled")
			res.Ranked = rankCandidates(list)
			finishPick(&res, best)
			return res, err
		}
		if !c.Supported && o.SkipUnsupported {
			c.Skipped = "the active transport cannot honour: " + strings.Join(c.Unsupported, "; ")
			continue
		}

		o.Logf("diag: trying strategy %q (%d/%d)", c.Name, i+1, len(list))
		if err := o.Client.Activate(ctx, c.Name); err != nil {
			c.Err = err.Error()
			c.Skipped = "activation failed"
			continue
		}
		res.Activated = c.Name

		// Let the daemon reload its anchor and let the previous strategy's flow
		// state expire before measuring; otherwise the first probe is measured
		// against a half-applied configuration.
		if !sleepCtx(ctx, o.Settle) {
			c.Skipped = "cancelled while waiting for the strategy to settle"
			restore("cancelled")
			res.Ranked = rankCandidates(list)
			finishPick(&res, best)
			return res, ctx.Err()
		}

		controlsOKEveryRound := true
		for round := 1; round <= o.Rounds; round++ {
			results, err := Run(ctx, o.Probes, o.Run)
			if err != nil {
				c.Err = err.Error()
				c.Skipped = "probes could not run"
				restore("cancelled")
				res.Ranked = rankCandidates(list)
				finishPick(&res, best)
				return res, err
			}
			c.Results = append(c.Results, results...)
			if !ScoreResults(results).Valid() {
				controlsOKEveryRound = false
			}
			if o.Rounds > 1 {
				o.Logf("diag: strategy %q round %d/%d scored %s", c.Name, round, o.Rounds,
					ScoreResults(results))
			}
		}
		c.Score = ScoreResults(c.Results)
		if !controlsOKEveryRound {
			c.Score.ControlPassed = 0
		}
		res.Tested++
		o.Logf("diag: strategy %q scored %s", c.Name, c.Score)

		if !c.Score.Valid() {
			// The control probes failed. That has two very different causes and
			// telling them apart is what makes this sweep usable:
			//
			//   * the uplink is down — every further measurement is meaningless;
			//   * THIS strategy breaks traffic — a desync that a middlebox or the
			//     server rejects can kill even uncensored connections, which is
			//     exactly what a fake whose decoy reaches the server does.
			//
			// So deactivate the candidate and re-measure the controls. If they
			// come back, the strategy was the culprit. If they do not, keep
			// sweeping anyway: a transient control failure or stale flow state must
			// not turn the remaining candidates into misleading 0/0 rows.
			c.Skipped = "control probes failed, so this measurement says nothing about the strategy"
			if o.Client != nil && res.Original != "" && res.Original != c.Name {
				if aerr := o.Client.Activate(ctx, res.Original); aerr == nil {
					// The original is back on, whatever the re-check says; record
					// that now so the "restored" contract holds on both paths
					// (restore() below is a no-op once Activated == Original).
					res.Activated, res.Restored = res.Original, true
					sleepCtx(ctx, o.Settle)
					if recheck := controlsPass(ctx, o); recheck {
						c.Skipped = "this strategy breaks traffic: the control endpoints failed with it active " +
							"and recovered as soon as it was deactivated"
						c.BreaksTraffic = true
						o.Logf("diag: strategy %q breaks traffic (controls recovered without it); continuing", c.Name)
						continue
					}
				}
			}
			c.Skipped = "control probes failed and did not recover during the immediate re-check; " +
				"candidate excluded, sweep continued"
			o.Logf("diag: controls still fail after strategy %q; excluding it and continuing", c.Name)
			continue
		}
		if best == nil || c.Score.Better(best.Score) {
			best = c
		}
		if c.Score.Perfect() && !o.NoEarlyStop {
			res.StoppedEarly = true
			break
		}
	}

	res.Ranked = rankCandidates(list)
	finishPick(&res, best)

	switch {
	case best == nil || best.Score.Passed == 0:
		// Nothing worked. Putting the machine back where it started is the only
		// honest outcome.
		restore("no candidate passed a single target probe")
	case res.Activated != best.Name:
		if err := o.Client.Activate(ctx, best.Name); err != nil {
			o.Logf("diag: could not activate the winning strategy %q: %v", best.Name, err)
		} else {
			res.Activated = best.Name
		}
	}
	return res, nil
}

// finishPick copies the winner into the result.
func finishPick(res *PickResult, best *Candidate) {
	if best == nil || best.Score.Passed == 0 {
		return
	}
	res.Best = best.Name
	res.BestScore = best.Score
}

// resolveStrategies produces the candidate list, loading it from disk when it
// was not supplied.
func resolveStrategies(o PickOpts) ([]*strategy.Strategy, error) {
	list := o.Strategies
	if len(list) == 0 {
		if o.StrategyDir == "" {
			return nil, errors.New("diag: Pick needs either Strategies or StrategyDir")
		}
		loaded, err := strategy.LoadDir(o.StrategyDir, o.LoadOpts)
		if err != nil {
			return nil, err
		}
		list = loaded
	}
	out := make([]*strategy.Strategy, 0, len(list))
	for _, s := range list {
		if s != nil {
			out = append(out, s)
		}
	}
	return applyOrder(out, o.Order), nil
}

// applyOrder moves the strategies named in order to the front, in that order,
// leaving the rest in their original relative order.
func applyOrder(list []*strategy.Strategy, order []string) []*strategy.Strategy {
	if len(order) == 0 {
		return list
	}
	rank := make(map[string]int, len(order))
	for i, n := range order {
		if _, dup := rank[n]; !dup {
			rank[n] = i
		}
	}
	out := make([]*strategy.Strategy, len(list))
	copy(out, list)
	sort.SliceStable(out, func(i, j int) bool {
		ri, oki := rank[out[i].Name]
		rj, okj := rank[out[j].Name]
		switch {
		case oki && okj:
			return ri < rj
		case oki:
			return true
		default:
			return false
		}
	})
	return out
}

// rankCandidates sorts measured candidates best first: measured ones (by score)
// before skipped ones, and skipped ones by name so the table is stable.
func rankCandidates(list []Candidate) []Candidate {
	out := make([]Candidate, len(list))
	copy(out, list)
	sort.SliceStable(out, func(i, j int) bool {
		mi := out[i].Skipped == "" && out[i].Results != nil
		mj := out[j].Skipped == "" && out[j].Results != nil
		if mi != mj {
			return mi
		}
		if mi {
			if out[i].Score.Better(out[j].Score) {
				return true
			}
			if out[j].Score.Better(out[i].Score) {
				return false
			}
			return out[i].Name < out[j].Name
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// rankDryRun sorts a dry-run listing: fully supported strategies first, then by
// how few capabilities they are missing, then by name.
func rankDryRun(list []Candidate) []Candidate {
	out := make([]Candidate, len(list))
	copy(out, list)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Supported != out[j].Supported {
			return out[i].Supported
		}
		if len(out[i].Unsupported) != len(out[j].Unsupported) {
			return len(out[i].Unsupported) < len(out[j].Unsupported)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// sleepCtx waits for d, returning false when ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Table renders the ranked summary: one line per candidate, best first.
func (r PickResult) Table() string {
	var sb strings.Builder
	if r.DryRun {
		sb.WriteString("dry run: no strategy was activated; support is judged from the active transport's Caps\n")
	}
	for i, c := range r.Ranked {
		mark := " "
		if c.Name == r.Best {
			mark = "*"
		}
		fmt.Fprintf(&sb, "%s %2d. %-34s ", mark, i+1, c.Name)
		switch {
		case c.Skipped != "" && c.Results == nil:
			sb.WriteString("skipped: " + c.Skipped)
		case c.Results == nil:
			sb.WriteString("not tested")
		default:
			sb.WriteString(c.Score.String())
			if c.Score.Blocked > 0 {
				fmt.Fprintf(&sb, ", %d with a DPI signature", c.Score.Blocked)
			}
		}
		if !c.Supported {
			fmt.Fprintf(&sb, "  [unsupported ops: %s]", strings.Join(c.Unsupported, "; "))
		}
		if c.Err != "" {
			sb.WriteString("  error: " + c.Err)
		}
		sb.WriteByte('\n')
	}
	switch {
	case r.DryRun:
	case r.Best == "":
		sb.WriteString("\nno strategy passed a single target probe")
		if r.Restored {
			sb.WriteString("; restored " + r.Original)
		}
		sb.WriteByte('\n')
	default:
		fmt.Fprintf(&sb, "\nwinner: %s (%s)\n", r.Best, r.BestScore)
		if r.StoppedEarly {
			sb.WriteString("stopped early: it passed every target probe\n")
		}
	}
	return sb.String()
}

// Detail renders the per-probe evidence for every measured candidate: which host
// worked, over which server address, and with what latency or error class. This
// is what answers "why did that strategy win" — usually because one CDN front end
// answers and another does not.
func (r PickResult) Detail() string {
	var sb strings.Builder
	for _, c := range r.Ranked {
		if len(c.Results) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "%s — %s\n", c.Name, c.Score)
		for _, res := range c.Results {
			fmt.Fprintf(&sb, "    %s\n", res)
		}
	}
	return sb.String()
}

// controlsPass re-runs only the control probes and reports whether they succeed.
// It is how the picker distinguishes "the uplink died" from "the strategy under
// test was killing traffic".
func controlsPass(ctx context.Context, o PickOpts) bool {
	var controls []Probe
	for _, p := range o.Probes {
		if p.Control {
			controls = append(controls, p)
		}
	}
	if len(controls) == 0 {
		return false
	}
	results, err := Run(ctx, controls, o.Run)
	if err != nil {
		return false
	}
	for _, r := range results {
		if !r.OK {
			return false
		}
	}
	return true
}
