//go:build darwin

package divert

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
)

// TestLivePFLogIntercept is opt-in because it temporarily installs one PF rule.
// It targets RFC 5737 TEST-NET-2, cleans up every object with defers, and proves
// the complete replacement for route-to/utun: block+log capture followed by a
// raw BPF write on the physical uplink.
func TestLivePFLogIntercept(t *testing.T) {
	if os.Getenv("ZAPRET_LIVE_PFLOG") != "1" {
		t.Skip("set ZAPRET_LIVE_PFLOG=1 and run as root")
	}
	requireRoot(t)
	iface := os.Getenv("ZAPRET_TEST_IFACE")
	if iface == "" {
		iface = "en0"
	}

	plog, err := createPFLog()
	if err != nil {
		t.Fatal(err)
	}
	defer plog.Close()

	state := filepath.Join(t.TempDir(), "state")
	// NewPF accepts the logical anchor name. It resolves that name beneath
	// com.apple/* itself when the system wildcard anchor is available.
	pf := netcfg.NewPF("zapret-pflog-live-test", netcfg.PFOpts{StateDir: state})
	defer pf.Close()
	defer pf.Release()
	defer pf.FlushRules()
	if _, err := pf.EnsureAnchorStatements(); err != nil {
		t.Fatal(err)
	}
	if err := pf.Enable(); err != nil {
		t.Fatal(err)
	}
	rules := netcfg.LogDropRules(netcfg.LogDropOpts{
		PFLog: plog.Name(), TCPPorts: []netcfg.PortRange{{443, 443}},
		TargetTable: "zlive",
	})
	if err := pf.LoadRules(rules); err != nil {
		t.Fatal(err)
	}
	if err := pf.TableReplace("zlive", []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}); err != nil {
		t.Fatal(err)
	}
	if n, err := pf.TableCount("zlive"); err != nil || n != 1 {
		t.Fatalf("live target table count = %d, err = %v; want 1", n, err)
	}

	route, err := netcfg.RouteForIface(iface)
	if err != nil {
		t.Fatal(err)
	}
	inj, err := newBPFInjector(route, route.MTU)
	if err != nil {
		t.Fatal(err)
	}
	defer inj.Close()

	go func() {
		c, _ := net.DialTimeout("tcp4", "198.51.100.7:443", time.Second)
		if c != nil {
			_ = c.Close()
		}
	}()
	buf := make([]byte, pflogBufLen)
	ver, pkt, ok, err := plog.Read(buf, 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("PF did not deliver the blocked packet to pflog")
	}
	if err := inj.Inject(ver, pkt); err != nil {
		t.Fatalf("BPF re-injection failed: %v", err)
	}
	t.Logf("captured and re-injected IPv%d packet (%d bytes) through %s", ver, len(pkt), iface)
}
