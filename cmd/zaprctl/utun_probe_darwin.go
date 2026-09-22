//go:build darwin

package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctl request numbers used to configure an interface. Values verified by
// compiling <sys/sockio.h> from this machine's SDK, and cross-checked against
// golang.org/x/sys/unix's generated constants for darwin/arm64:
//
//	SIOCAIFADDR   _IOW ('i', 26, struct ifaliasreq) == 0x8040691a  (sizeof 64)
//	SIOCSIFMTU    _IOW ('i', 52, struct ifreq)      == 0x80206934  (sizeof 32)
//	SIOCSIFFLAGS  _IOW ('i', 16, struct ifreq)      == 0x80206910
//	SIOCGIFFLAGS  _IOWR('i', 17, struct ifreq)      == 0xc0206911
const (
	siocAIfAddr  = 0x8040691a
	siocSIfMTU   = 0x80206934
	siocSIfFlags = 0x80206910
	siocGIfFlags = 0xc0206911
)

// utunAFPrefixLen is the length of the 4-byte framing header on every read from
// and write to a utun control socket. The header is the address family in
// network byte order, i.e. {0,0,0,AF_INET} == {0,0,0,2} for IPv4.
const utunAFPrefixLen = 4

// ifAliasReq mirrors "struct ifaliasreq" from <net/if.h>: a 16-byte interface
// name followed by three sockaddrs (addr, broadaddr, mask), total 64 bytes.
// For a point-to-point interface the kernel treats ifra_broadaddr as the
// destination (peer) address, which is how "ifconfig utunN A B" works.
type ifAliasReq struct {
	Name      [unix.IFNAMSIZ]byte
	Addr      unix.RawSockaddrInet4
	Broadaddr unix.RawSockaddrInet4
	Mask      unix.RawSockaddrInet4
}

// ifReqInt mirrors "struct ifreq" when the union member in use is the int
// ifr_mtu: 16-byte name plus a 16-byte union, 32 bytes total.
type ifReqInt struct {
	Name [unix.IFNAMSIZ]byte
	Val  int32
	_    [12]byte
}

// ifReqFlags mirrors "struct ifreq" when the union member in use is the
// "short ifru_flags".
type ifReqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

// Compile-time guards on the struct sizes the ioctl request numbers encode.
// A mismatch would make the kernel reject the call with ENOTTY, so catch it
// at build time instead.
const (
	_ = uint(unsafe.Sizeof(ifAliasReq{}) - 64)
	_ = uint(64 - unsafe.Sizeof(ifAliasReq{}))
	_ = uint(unsafe.Sizeof(ifReqInt{}) - 32)
	_ = uint(32 - unsafe.Sizeof(ifReqInt{}))
	_ = uint(unsafe.Sizeof(ifReqFlags{}) - 32)
	_ = uint(32 - unsafe.Sizeof(ifReqFlags{}))
)

// sockaddrInet4Raw builds a filled-in sockaddr_in for the ifaliasreq slots.
func sockaddrInet4Raw(ip netip.Addr) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   ip.As4(),
	}
}

// utunHandle owns a utun control socket and therefore the interface itself:
// closing the socket destroys the utunN device, which is what makes cleanup
// trivially complete.
type utunHandle struct {
	fd            int
	Name          string
	Unit          int
	RequestedUnit int
	FellBack      bool
	Local         netip.Addr
	Peer          netip.Addr
	MTU           int
	Configured    bool
	ConfigErrors  []string
}

// createUTUN opens a utun control socket, attaches it to a unit, reads back the
// kernel-assigned interface name, and configures addresses, MTU and flags with
// ioctls only (never ifconfig).
//
// The kernel's sc_unit numbering is 1-based: sc_unit == unit+1 selects utun<unit>
// and sc_unit == 0 asks the kernel for the lowest free unit.
func createUTUN(unit int, local, peer netip.Addr, mtu int) (*utunHandle, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, syscallError("socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)", err)
	}
	h := &utunHandle{fd: fd, RequestedUnit: unit, Local: local, Peer: peer, MTU: mtu}

	var ci unix.CtlInfo
	copy(ci.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &ci); err != nil {
		unix.Close(fd)
		return nil, syscallError(`ioctl(CTLIOCGINFO, "com.apple.net.utun_control")`, err)
	}

	connectErr := unix.Connect(fd, &unix.SockaddrCtl{ID: ci.Id, Unit: uint32(unit) + 1})
	if connectErr != nil {
		// The requested unit is taken (EBUSY) or otherwise unusable; ask the
		// kernel to pick one by passing sc_unit == 0.
		if err2 := unix.Connect(fd, &unix.SockaddrCtl{ID: ci.Id, Unit: 0}); err2 != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("%v; fallback to auto unit also failed: %s",
				syscallError(fmt.Sprintf("connect(utun unit %d)", unit), connectErr),
				errnoName(err2))
		}
		h.FellBack = true
	}

	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, syscallError("getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)", err)
	}
	h.Name = name
	h.Unit = unit
	if n, perr := fmt.Sscanf(name, "utun%d", &h.Unit); perr != nil || n != 1 {
		h.Unit = -1
	}

	if err := h.configure(); err != nil {
		unix.Close(fd)
		h.fd = -1
		return h, err
	}
	h.Configured = true
	return h, nil
}

// configure assigns the point-to-point addresses, sets the MTU and brings the
// interface up, all through ioctls on a scratch AF_INET datagram socket.
func (h *utunHandle) configure() error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return syscallError("socket(AF_INET, SOCK_DGRAM) for ioctl", err)
	}
	defer unix.Close(s)

	var aif ifAliasReq
	copy(aif.Name[:], h.Name)
	aif.Addr = sockaddrInet4Raw(h.Local)
	// On a point-to-point interface ifra_broadaddr carries the peer address.
	aif.Broadaddr = sockaddrInet4Raw(h.Peer)
	aif.Mask = sockaddrInet4Raw(netip.AddrFrom4([4]byte{255, 255, 255, 255}))
	if err := ioctlPtr(s, siocAIfAddr, unsafe.Pointer(&aif)); err != nil {
		return syscallError(fmt.Sprintf("ioctl(SIOCAIFADDR, %s %s->%s/32)", h.Name, h.Local, h.Peer), err)
	}

	var mtu ifReqInt
	copy(mtu.Name[:], h.Name)
	mtu.Val = int32(h.MTU)
	if err := ioctlPtr(s, siocSIfMTU, unsafe.Pointer(&mtu)); err != nil {
		// A wrong MTU is not fatal to the experiment; record and continue.
		h.ConfigErrors = append(h.ConfigErrors,
			syscallError(fmt.Sprintf("ioctl(SIOCSIFMTU, %s, %d)", h.Name, h.MTU), err).Error())
	}

	var fl ifReqFlags
	copy(fl.Name[:], h.Name)
	if err := ioctlPtr(s, siocGIfFlags, unsafe.Pointer(&fl)); err != nil {
		return syscallError(fmt.Sprintf("ioctl(SIOCGIFFLAGS, %s)", h.Name), err)
	}
	// IFF_RUNNING is driver-owned on most interfaces but utun honours it; the
	// bit that matters for pf's route-to is IFF_UP.
	fl.Flags |= int16(unix.IFF_UP | unix.IFF_RUNNING)
	if err := ioctlPtr(s, siocSIfFlags, unsafe.Pointer(&fl)); err != nil {
		return syscallError(fmt.Sprintf("ioctl(SIOCSIFFLAGS, %s, UP)", h.Name), err)
	}
	return nil
}

// read waits up to timeout for one datagram and returns the IP packet with the
// 4-byte address-family framing stripped, plus the raw prefix that was present.
func (h *utunHandle) read(timeout time.Duration) (prefix []byte, pkt []byte, err error) {
	if h == nil || h.fd < 0 {
		return nil, nil, unix.EBADF
	}
	ready, err := waitReadable(h.fd, timeout)
	if err != nil {
		return nil, nil, err
	}
	if !ready {
		return nil, nil, nil
	}
	buf := make([]byte, h.MTU+utunAFPrefixLen+512)
	n, err := unix.Read(h.fd, buf)
	if err != nil {
		return nil, nil, syscallError("read(utun)", err)
	}
	if n < utunAFPrefixLen {
		return buf[:n], nil, fmt.Errorf("short utun read: %d bytes", n)
	}
	return buf[:utunAFPrefixLen], buf[utunAFPrefixLen:n], nil
}

// write sends an IPv4 packet into the utun, prepending the {0,0,0,AF_INET}
// framing header the control socket requires.
func (h *utunHandle) write(pkt []byte) (int, error) {
	if h == nil || h.fd < 0 {
		return 0, unix.EBADF
	}
	buf := make([]byte, utunAFPrefixLen+len(pkt))
	binary.BigEndian.PutUint32(buf[:utunAFPrefixLen], uint32(unix.AF_INET))
	copy(buf[utunAFPrefixLen:], pkt)
	n, err := unix.Write(h.fd, buf)
	if err != nil {
		return n, syscallError("write(utun)", err)
	}
	return n, nil
}

// FramingNote describes the utun wire framing for the report.
func (h *utunHandle) FramingNote() string {
	return fmt.Sprintf("reads/writes carry a 4-byte prefix {0,0,0,%d} = htonl(AF_INET) before the IP header",
		unix.AF_INET)
}

// Close destroys the interface by closing its control socket.
func (h *utunHandle) Close() error {
	if h == nil || h.fd < 0 {
		return nil
	}
	err := unix.Close(h.fd)
	h.fd = -1
	return err
}
