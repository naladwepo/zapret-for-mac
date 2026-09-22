// Package transport defines the datapath contract. Two implementations exist:
//
//   - transport/divert — pf logs and blocks matching originals on a dedicated
//     pflog interface; the daemon re-emits packets with a BPF Ethernet write on
//     the physical interface (bypassing pf, so no loop).
//     Inbound traffic is never steered, so no userspace TCP stack is needed and
//     the application's real 4-tuple is preserved. Full winws-class Caps.
//
//   - transport/proxy — pf `rdr pass` redirects TCP to a local listener whose
//     original destination is recovered with ioctl(DIOCNATLOOK) on /dev/pf, the
//     way zapret's tpws does it on macOS. Socket-level Caps only.
//
// CONTRACT FILE — types only.
package transport

import (
	"context"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/engine"
	"github.com/naladwepo/zapret-for-mac/internal/strategy"
)

// Stats is what `zaprctl status` reports.
type Stats struct {
	Transport string

	FlowsActive int64
	FlowsTotal  int64

	PktsIn      int64 // packets taken from the interception queue
	PktsOut     int64 // packets re-emitted
	PktsInject  int64 // synthetic packets injected
	PktsDropped int64 // originals suppressed on purpose
	BytesIn     int64
	BytesOut    int64

	Desyncs   int64 // flows a profile fired on
	Matched   int64 // flows that matched a profile
	Errors    int64
	QueueDrop int64 // kernel-side drops (BPF bs_drop / utun read backlog)
}

// Transport is the lifecycle contract; the datapath itself lives inside each
// implementation.
type Transport interface {
	Name() string
	Caps() desync.Caps
	// Start blocks until ctx is cancelled or a fatal error occurs.
	Start(ctx context.Context) error
	// Reload swaps the active strategy without dropping established flows.
	Reload(s *strategy.Strategy) error
	Stats() Stats
	Close() error
}

// Config is what both transports need from the daemon.
type Config struct {
	Strategy *strategy.Strategy
	Engine   *engine.Engine

	// Iface is the physical uplink (e.g. "en0"); empty means autodetect from
	// the default route.
	Iface string

	// UtunUnit is the requested utun unit number for the divert transport;
	// 0 means "first free".
	UtunUnit int
	// TunLocal/TunPeer is the point-to-point /30-free pair used by route-to.
	TunLocal string
	TunPeer  string

	// ProxyPort is the local listener port for the proxy transport.
	ProxyPort int

	// BlockQUIC installs the pf rule that drops UDP/443 to the target set,
	// forcing browsers back to TCP.
	BlockQUIC bool

	// ExemptRoot keeps root-owned traffic out of the window (loop breaker).
	ExemptRoot bool

	// AllowTunnelDefault permits the packet datapath to run while a tunnel
	// interface holds an IPv4 default route (a full-tunnel VPN).
	//
	// This is safe only when the VPN has already classified the target as Direct:
	// its outbound socket then carries the physical source address. A blind
	// full-tunnel flow still carries a tunnel source and cannot be re-emitted.
	AllowTunnelDefault bool

	Verbose int
}
