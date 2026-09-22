//go:build darwin

package divert

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/naladwepo/zapret-for-mac/internal/desync"
	"github.com/naladwepo/zapret-for-mac/internal/netcfg"
)

// BPF ioctl request numbers. Verified against <net/bpf.h> and cross-checked
// against golang.org/x/sys/unix's generated darwin/arm64 constants:
//
//	BIOCSBLEN     _IOWR('B', 102, u_int)       == 0xc0044266
//	BIOCSETF      _IOW ('B', 103, bpf_program) == 0x80104267 (sizeof 16)
//	BIOCSETIF     _IOW ('B', 108, struct ifreq)== 0x8020426c
//	BIOCGDLT      _IOR ('B', 106, u_int)       == 0x4004426a
//	BIOCGSTATS    _IOR ('B', 111, bpf_stat)    == 0x4008426f
//	BIOCIMMEDIATE _IOW ('B', 112, u_int)       == 0x80044270
//	BIOCSHDRCMPLT _IOW ('B', 117, u_int)       == 0x80044275
//	BIOCSSEESENT  _IOW ('B', 119, u_int)       == 0x80044277
const (
	biocSBlen     = 0xc0044266
	biocSetF      = 0x80104267
	biocSetIf     = 0x8020426c
	biocGDLT      = 0x4004426a
	biocGStats    = 0x4008426f
	biocImmediate = 0x80044270
	biocSHdrCmplt = 0x80044275
	biocSSeeSent  = 0x80044277
)

// dltEN10MB is DLT_EN10MB, the Ethernet link type: frames written to the
// descriptor must start with a 14-byte Ethernet header.
const dltEN10MB = 1

// ethHdrLen is the length of an Ethernet II header, and the two ethertypes we
// ever emit.
const (
	ethHdrLen   = 14
	ethTypeIPv4 = 0x0800
	ethTypeIPv6 = 0x86dd
	ethAddrLen  = 6
	ethMinFrame = 60 // Ethernet minimum frame minus the 4-byte FCS
)

// bpfInjectBufLen is the kernel buffer requested via BIOCSBLEN on the injector
// handle. The injector never reads, so this only has to be large enough for the
// ioctl to succeed; the read path (observe.go) asks for much more.
const bpfInjectBufLen = 32 * 1024

// bpfProgram mirrors "struct bpf_program" from <net/bpf.h>: an instruction count
// plus a pointer, 16 bytes on arm64.
type bpfProgram struct {
	Len   uint32
	_     uint32
	Insns *unix.BpfInsn
}

// Compile-time guards for the sizes the ioctl numbers above encode.
const (
	_ = uint(unsafe.Sizeof(bpfProgram{}) - 16)
	_ = uint(16 - unsafe.Sizeof(bpfProgram{}))
	_ = uint(unsafe.Sizeof(unix.BpfHdr{}) - 20)
	_ = uint(20 - unsafe.Sizeof(unix.BpfHdr{}))
)

// bpfWordAlign implements BPF_WORDALIGN: records inside the read buffer are
// padded to a 4-byte boundary (BPF_ALIGNMENT == sizeof(int32_t)).
func bpfWordAlign(n int) int { return (n + 3) &^ 3 }

// bpfHandle is an open /dev/bpfN descriptor bound to one interface.
type bpfHandle struct {
	fd       int
	Device   string
	Iface    string
	BufLen   int
	Datalink int
}

// openBPF finds the first usable /dev/bpfN, binds it to iface and configures it.
//
// hdrComplete selects BIOCSHDRCMPLT, which makes the kernel transmit a written
// frame verbatim instead of filling in the source address — and, crucially,
// transmit it below the IP layer, bypassing pf. That is what keeps the re-emit
// step from looping back into our own route-to rule. seeSent controls whether
// locally transmitted frames are also captured; the observer sets it to false so
// it never sees its own injections.
func openBPF(iface string, bufLen int, hdrComplete, seeSent bool, filter []unix.BpfInsn) (*bpfHandle, error) {
	return openBPFWithDLT(iface, bufLen, hdrComplete, seeSent, filter, dltEN10MB)
}

// openBPFWithDLT is openBPF with an explicit link type.  The packet injector
// and observer use Ethernet; the pflog interceptor uses DLT_PFLOG.
func openBPFWithDLT(iface string, bufLen int, hdrComplete, seeSent bool, filter []unix.BpfInsn, wantDLT int) (*bpfHandle, error) {
	if iface == "" {
		return nil, fmt.Errorf("divert: openBPF needs an interface name")
	}
	var lastErr error
scan:
	for i := 0; i < 256; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(dev, unix.O_RDWR, 0)
		if err != nil {
			lastErr = syscallError("open("+dev+")", err)
			switch err {
			case unix.EBUSY:
				continue // taken by another process; try the next clone
			case unix.ENOENT:
				break scan // no more cloned nodes exist
			case unix.EACCES, unix.EPERM:
				break scan // not root: no point walking 256 nodes
			}
			continue
		}
		h := &bpfHandle{fd: fd, Device: dev, Iface: iface, BufLen: bufLen}
		if err := h.setup(hdrComplete, seeSent, filter, wantDLT); err != nil {
			unix.Close(fd)
			h.fd = -1
			return nil, err
		}
		return h, nil
	}
	if lastErr == nil {
		lastErr = syscallError("open(/dev/bpfN)", unix.ENOENT)
	}
	return nil, fmt.Errorf("divert: no usable BPF device: %w", lastErr)
}

// setup applies the descriptor options in the order the kernel requires: the
// buffer length must be set before the interface is attached.
func (h *bpfHandle) setup(hdrComplete, seeSent bool, filter []unix.BpfInsn, wantDLT int) error {
	blen := int32(h.BufLen)
	if err := ioctlPtr(h.fd, biocSBlen, unsafe.Pointer(&blen)); err != nil {
		return syscallError("ioctl(BIOCSBLEN)", err)
	}
	h.BufLen = int(blen) // the kernel may clamp the request

	var req ifReqInt
	copy(req.Name[:], h.Iface)
	if err := ioctlPtr(h.fd, biocSetIf, unsafe.Pointer(&req)); err != nil {
		return syscallError(fmt.Sprintf("ioctl(BIOCSETIF, %s)", h.Iface), err)
	}

	one, zero := int32(1), int32(0)
	if hdrComplete {
		if err := ioctlPtr(h.fd, biocSHdrCmplt, unsafe.Pointer(&one)); err != nil {
			return syscallError("ioctl(BIOCSHDRCMPLT, 1)", err)
		}
	}
	if err := ioctlPtr(h.fd, biocImmediate, unsafe.Pointer(&one)); err != nil {
		return syscallError("ioctl(BIOCIMMEDIATE, 1)", err)
	}
	seen := &zero
	if seeSent {
		seen = &one
	}
	if err := ioctlPtr(h.fd, biocSSeeSent, unsafe.Pointer(seen)); err != nil {
		return syscallError("ioctl(BIOCSSEESENT)", err)
	}
	if len(filter) > 0 {
		prog := bpfProgram{Len: uint32(len(filter)), Insns: &filter[0]}
		if err := ioctlPtr(h.fd, biocSetF, unsafe.Pointer(&prog)); err != nil {
			return syscallError("ioctl(BIOCSETF)", err)
		}
	}
	var dlt int32
	if err := ioctlPtr(h.fd, biocGDLT, unsafe.Pointer(&dlt)); err != nil {
		return syscallError("ioctl(BIOCGDLT)", err)
	}
	h.Datalink = int(dlt)
	if h.Datalink != wantDLT {
		return fmt.Errorf("divert: %s has link type %d, want %d", h.Iface, h.Datalink, wantDLT)
	}
	if err := unix.SetNonblock(h.fd, true); err != nil {
		return syscallError("SetNonblock(bpf)", err)
	}
	return nil
}

// write writes one complete link-layer frame.
func (h *bpfHandle) write(frame []byte) error {
	if h == nil || h.fd < 0 {
		return unix.EBADF
	}
	for {
		_, err := unix.Write(h.fd, frame)
		if err == nil {
			return nil
		}
		if err == unix.EINTR {
			continue
		}
		return syscallError("write(bpf)", err)
	}
}

// stats returns the BIOCGSTATS counters: frames the descriptor received and
// frames the kernel had to drop because the buffer was full.
func (h *bpfHandle) stats() (recv, drop uint32, err error) {
	if h == nil || h.fd < 0 {
		return 0, 0, unix.EBADF
	}
	var st unix.BpfStat
	if err := ioctlPtr(h.fd, biocGStats, unsafe.Pointer(&st)); err != nil {
		return 0, 0, syscallError("ioctl(BIOCGSTATS)", err)
	}
	return st.Recv, st.Drop, nil
}

// Close releases the BPF descriptor.
func (h *bpfHandle) Close() error {
	if h == nil || h.fd < 0 {
		return nil
	}
	err := unix.Close(h.fd)
	h.fd = -1
	if err != nil {
		return syscallError("close(bpf)", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Ethernet framing
// ---------------------------------------------------------------------------

// ethTypeFor maps an IP version to its ethertype.
func ethTypeFor(ver uint8) uint16 {
	if ver == 6 {
		return ethTypeIPv6
	}
	return ethTypeIPv4
}

// ipVersionOf reads the version nibble of an IP packet, 0 for a buffer too short
// to have one.
func ipVersionOf(pkt []byte) uint8 {
	if len(pkt) == 0 {
		return 0
	}
	return pkt[0] >> 4
}

// ipDestOf extracts the destination address of an IP packet. ok is false when the
// buffer is too short or the version is neither 4 nor 6.
func ipDestOf(pkt []byte) (netip.Addr, bool) {
	switch ipVersionOf(pkt) {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	default:
		return netip.Addr{}, false
	}
}

// buildEthFrame writes an Ethernet II header plus payload into dst, returning the
// frame. dst is reused across calls to keep the datapath allocation-free; it
// grows only when a packet needs more room than it currently has.
//
// The frame is padded to the 60-byte Ethernet minimum: a shorter frame is legal
// to hand to BPF (the driver pads it) but padding here makes the produced bytes
// deterministic, which is what the framing test asserts against.
func buildEthFrame(dst []byte, dstMAC, srcMAC net.HardwareAddr, etherType uint16, payload []byte) ([]byte, error) {
	if len(dstMAC) != ethAddrLen || len(srcMAC) != ethAddrLen {
		return nil, fmt.Errorf("divert: need %d-byte MACs, got dst=%d src=%d",
			ethAddrLen, len(dstMAC), len(srcMAC))
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("divert: refusing to write an empty Ethernet payload")
	}
	n := ethHdrLen + len(payload)
	pad := 0
	if n < ethMinFrame {
		pad = ethMinFrame - n
	}
	if cap(dst) < n+pad {
		dst = make([]byte, n+pad)
	}
	frame := dst[:n+pad]
	copy(frame[0:ethAddrLen], dstMAC)
	copy(frame[ethAddrLen:2*ethAddrLen], srcMAC)
	binary.BigEndian.PutUint16(frame[2*ethAddrLen:ethHdrLen], etherType)
	copy(frame[ethHdrLen:], payload)
	for i := n; i < n+pad; i++ {
		frame[i] = 0
	}
	return frame, nil
}

// ---------------------------------------------------------------------------
// injector
// ---------------------------------------------------------------------------

// injector is the datapath's write side: one complete IP packet in, one packet on
// the wire out. Both implementations bypass the routing table, which is the whole
// point — the packet must not be handed back to pf.
type injector interface {
	// Inject puts one complete IP packet (network byte order) on the wire. ver is
	// the address family the interception path reported (4, 6, or 0 for "derive
	// it from the packet"); it is what lets a packet we could not parse still be
	// forwarded verbatim instead of dropped.
	Inject(ver uint8, pkt []byte) error
	// Name identifies the injector in logs and Stats.
	Name() string
	// Caps reports what the desync engine can rely on with this injector.
	Caps() desync.Caps
	// Limits describes, in one line, what this injector cannot do. Empty for the
	// BPF injector, non-empty for the raw fallback.
	Limits() string
	Close() error
}

// gwMACRefresh is how often the neighbour cache is re-read. A gateway MAC almost
// never changes, but a DHCP lease renewal or a router failover can move it, and
// one sysctl every 30s is free compared to the packet rate we handle.
const gwMACRefresh = 30 * time.Second

// bpfInjector writes complete Ethernet frames on the physical uplink.
//
// This is the injector that gives the transport desync.FullCaps: the kernel
// transmits the frame verbatim (BIOCSHDRCMPLT) without consulting the routing
// table or pf, so every byte of the IP and TCP headers is ours — ip_id including
// zero, a deliberately wrong L4 checksum, per-packet TTL, sub-window sequence
// numbers and IPv6 extension headers.
type bpfInjector struct {
	h      *bpfHandle
	srcMAC net.HardwareAddr
	gw     netip.Addr
	mtu    int

	mu        sync.Mutex
	gwMAC     net.HardwareAddr
	neigh     map[netip.Addr]net.HardwareAddr
	refreshed time.Time
	frame     []byte
}

// newBPFInjector opens the injector on the uplink described by r and resolves the
// next hop's link-layer address.
//
// r.GatewayMAC is preferred when the routing table already handed us one (a
// directly attached next hop); otherwise the ARP cache is consulted and, if the
// neighbour is unknown, netcfg pokes it with a single UDP datagram and retries.
func newBPFInjector(r netcfg.Route, mtu int) (*bpfInjector, error) {
	if len(r.MAC) != ethAddrLen {
		return nil, fmt.Errorf("divert: uplink %s has no %d-byte link-layer address (got %d bytes); "+
			"a raw Ethernet write needs one", r.Iface, ethAddrLen, len(r.MAC))
	}
	h, err := openBPF(r.Iface, bpfInjectBufLen, true, false, nil)
	if err != nil {
		return nil, err
	}
	inj := &bpfInjector{
		h:      h,
		srcMAC: r.MAC,
		gw:     r.Gateway,
		mtu:    mtu,
		frame:  make([]byte, 0, ethHdrLen+2048),
	}
	switch {
	case len(r.GatewayMAC) == ethAddrLen:
		inj.gwMAC = r.GatewayMAC
	case r.Gateway.IsValid():
		mac, err := netcfg.ResolveGatewayMAC(r.Gateway)
		if err != nil {
			h.Close()
			return nil, fmt.Errorf("divert: cannot resolve the link-layer address of gateway %s on %s: %w",
				r.Gateway, r.Iface, err)
		}
		inj.gwMAC = mac
	default:
		h.Close()
		return nil, fmt.Errorf("divert: default route on %s has no next hop to address frames to", r.Iface)
	}
	inj.mu.Lock()
	inj.refreshNeighboursLocked()
	inj.mu.Unlock()
	return inj, nil
}

// Name implements injector.
func (i *bpfInjector) Name() string { return "bpf" }

// Caps implements injector: the BPF path imposes no reduction.
func (i *bpfInjector) Caps() desync.Caps { return desync.FullCaps() }

// Limits implements injector.
func (i *bpfInjector) Limits() string { return "" }

// Device reports which /dev/bpfN is in use, for the status report.
func (i *bpfInjector) Device() string { return i.h.Device }

// GatewayMAC reports the Ethernet destination currently in use.
func (i *bpfInjector) GatewayMAC() net.HardwareAddr {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.gwMAC
}

// Inject implements injector.
func (i *bpfInjector) Inject(ver uint8, pkt []byte) error {
	if ver != 4 && ver != 6 {
		// Trust the packet only when the caller had nothing better: the utun's
		// own 4-byte framing header is written by the kernel and is therefore the
		// more authoritative of the two.
		ver = ipVersionOf(pkt)
	}
	if ver != 4 && ver != 6 {
		return fmt.Errorf("divert: refusing to inject a buffer that is neither IPv4 nor IPv6 (first nibble %d)",
			ipVersionOf(pkt))
	}
	dstMAC := i.dstMACFor(pkt)

	i.mu.Lock()
	defer i.mu.Unlock()
	// Oversize packets are split here rather than dropped by the driver: we
	// author the packets ourselves and therefore do not get the kernel's own
	// fragmentation, and a seqovl prefix or an inserted extension header can push
	// a full-size segment past the MTU.
	for _, part := range fragmentForMTU(pkt, i.mtu) {
		frame, err := buildEthFrame(i.frame, dstMAC, i.srcMAC, ethTypeFor(ver), part)
		if err != nil {
			return err
		}
		i.frame = frame[:0]
		if err := i.h.write(frame); err != nil {
			return err
		}
	}
	return nil
}

// dstMACFor picks the Ethernet destination for a packet: the neighbour's own
// address when the destination is on-link, the next hop's otherwise.
//
// Consulting the neighbour cache first matters for a LAN destination inside the
// steered port window: sending it to the router would still deliver it, but only
// after an ICMP redirect and an extra hop.
func (i *bpfInjector) dstMACFor(pkt []byte) net.HardwareAddr {
	dst, ok := ipDestOf(pkt)
	i.mu.Lock()
	defer i.mu.Unlock()
	if time.Since(i.refreshed) > gwMACRefresh {
		i.refreshNeighboursLocked()
	}
	if ok {
		if mac, found := i.neigh[dst]; found && len(mac) == ethAddrLen {
			return mac
		}
	}
	return i.gwMAC
}

// refreshNeighboursLocked re-reads the IPv4 neighbour cache and, with it, the
// gateway's link-layer address.
//
// APPROXIMATION: netcfg.ARPTable only dumps the IPv4 cache, so an IPv6
// destination always goes to the IPv4 next hop's MAC. That is correct on every
// network where the router is one box with one NIC per link (its MAC is per
// interface, not per address family), which covers home and office LANs; a
// network with distinct IPv4 and IPv6 first hops would need an NDP dump
// (net.route.0.inet6.flags RTF_LLINFO) that netcfg does not expose.
func (i *bpfInjector) refreshNeighboursLocked() {
	i.refreshed = time.Now()
	tbl, err := netcfg.ARPTable()
	if err != nil {
		return // keep the previous cache; a stale MAC beats no MAC
	}
	i.neigh = tbl
	if mac, ok := tbl[i.gw]; ok && len(mac) == ethAddrLen {
		i.gwMAC = mac
	}
}

// Close implements injector.
func (i *bpfInjector) Close() error { return i.h.Close() }
