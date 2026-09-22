//go:build darwin

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// syscall plumbing
// ---------------------------------------------------------------------------

// sysprotoControl is SYSPROTO_CONTROL from <sys/sys_domain.h>.
// golang.org/x/sys/unix does not export it; the value was read from
// $(xcrun --show-sdk-path)/usr/include/sys/sys_domain.h on this machine.
const sysprotoControl = 2

// utunOptIfname is UTUN_OPT_IFNAME from <net/if_utun.h> (getsockopt at level
// SYSPROTO_CONTROL returns the kernel-assigned "utunN" name).
const utunOptIfname = 2

// sysCsrctl is the csrctl(2) syscall number (SYS_CSRCTL == 483 on Darwin).
// op 1 is CSR_SYSCALL_GET_ACTIVE_CONFIG in xnu bsd/kern/kern_csr.c; it copies
// out a single uint32_t csr_config_t, and the kernel rejects any other size.
const (
	sysCsrctl                 = unix.SYS_CSRCTL
	csrSyscallGetActiveConfig = 1
	csrConfigSize             = 4
)

// ioctlPtr issues ioctl(fd, req, arg). It mirrors the internal helper in
// golang.org/x/sys/unix, which that package does not export for arbitrary
// struct arguments. Callers must pass a pointer obtained via
// unsafe.Pointer(&x) so that escape analysis heap-allocates x: heap objects do
// not move, so handing the kernel a uintptr of it is safe.
func ioctlPtr(fd int, req uint32, arg unsafe.Pointer) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// sysctlMIB performs sysctl(3) with a numeric MIB, sizing the buffer with a
// probe call first. unix.SysctlRaw only accepts symbolic names, and the routing
// table has none, so the MIB must be passed numerically.
func sysctlMIB(mib []int32) ([]byte, error) {
	if len(mib) == 0 {
		return nil, unix.EINVAL
	}
	n := uintptr(0)
	if _, _, e := unix.Syscall6(unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		0, uintptr(unsafe.Pointer(&n)), 0, 0); e != 0 {
		return nil, e
	}
	if n == 0 {
		return nil, nil
	}
	// The table can grow between the sizing call and the read, so retry a few
	// times on ENOMEM with the size the kernel reports.
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, n)
		got := n
		_, _, e := unix.Syscall6(unix.SYS___SYSCTL,
			uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&got)), 0, 0)
		if e == 0 {
			if got > uintptr(len(buf)) {
				got = uintptr(len(buf))
			}
			return buf[:got], nil
		}
		if e != unix.ENOMEM {
			return nil, e
		}
		n = n + n/4 + 1024
	}
	return nil, unix.ENOMEM
}

// errnoNames maps every errno this probe can plausibly observe to its symbolic
// name. It is a slice rather than a map literal because Darwin aliases some
// values (EWOULDBLOCK == EAGAIN), and duplicate constant keys in a map literal
// do not compile.
var errnoNames = []struct {
	e    unix.Errno
	name string
}{
	{unix.EPERM, "EPERM"}, {unix.ENOENT, "ENOENT"}, {unix.ESRCH, "ESRCH"},
	{unix.EINTR, "EINTR"}, {unix.EIO, "EIO"}, {unix.ENXIO, "ENXIO"},
	{unix.E2BIG, "E2BIG"}, {unix.EBADF, "EBADF"}, {unix.ECHILD, "ECHILD"},
	{unix.EDEADLK, "EDEADLK"}, {unix.ENOMEM, "ENOMEM"}, {unix.EACCES, "EACCES"},
	{unix.EFAULT, "EFAULT"}, {unix.EBUSY, "EBUSY"}, {unix.EEXIST, "EEXIST"},
	{unix.EXDEV, "EXDEV"}, {unix.ENODEV, "ENODEV"}, {unix.ENOTDIR, "ENOTDIR"},
	{unix.EISDIR, "EISDIR"}, {unix.EINVAL, "EINVAL"}, {unix.ENFILE, "ENFILE"},
	{unix.EMFILE, "EMFILE"}, {unix.ENOTTY, "ENOTTY"}, {unix.EFBIG, "EFBIG"},
	{unix.ENOSPC, "ENOSPC"}, {unix.ESPIPE, "ESPIPE"}, {unix.EROFS, "EROFS"},
	{unix.EPIPE, "EPIPE"}, {unix.EAGAIN, "EAGAIN"}, {unix.EINPROGRESS, "EINPROGRESS"},
	{unix.EALREADY, "EALREADY"}, {unix.ENOTSOCK, "ENOTSOCK"},
	{unix.EDESTADDRREQ, "EDESTADDRREQ"}, {unix.EMSGSIZE, "EMSGSIZE"},
	{unix.EPROTOTYPE, "EPROTOTYPE"}, {unix.ENOPROTOOPT, "ENOPROTOOPT"},
	{unix.EPROTONOSUPPORT, "EPROTONOSUPPORT"}, {unix.ESOCKTNOSUPPORT, "ESOCKTNOSUPPORT"},
	{unix.ENOTSUP, "ENOTSUP"}, {unix.EPFNOSUPPORT, "EPFNOSUPPORT"},
	{unix.EAFNOSUPPORT, "EAFNOSUPPORT"}, {unix.EADDRINUSE, "EADDRINUSE"},
	{unix.EADDRNOTAVAIL, "EADDRNOTAVAIL"}, {unix.ENETDOWN, "ENETDOWN"},
	{unix.ENETUNREACH, "ENETUNREACH"}, {unix.ENETRESET, "ENETRESET"},
	{unix.ECONNABORTED, "ECONNABORTED"}, {unix.ECONNRESET, "ECONNRESET"},
	{unix.ENOBUFS, "ENOBUFS"}, {unix.EISCONN, "EISCONN"}, {unix.ENOTCONN, "ENOTCONN"},
	{unix.ESHUTDOWN, "ESHUTDOWN"}, {unix.ETIMEDOUT, "ETIMEDOUT"},
	{unix.ECONNREFUSED, "ECONNREFUSED"}, {unix.ELOOP, "ELOOP"},
	{unix.ENAMETOOLONG, "ENAMETOOLONG"}, {unix.EHOSTDOWN, "EHOSTDOWN"},
	{unix.EHOSTUNREACH, "EHOSTUNREACH"}, {unix.ENOTEMPTY, "ENOTEMPTY"},
	{unix.ENOSYS, "ENOSYS"}, {unix.ECANCELED, "ECANCELED"},
	{unix.EOPNOTSUPP, "EOPNOTSUPP"}, {unix.EDEVERR, "EDEVERR"},
	{unix.ERANGE, "ERANGE"}, {unix.EOVERFLOW, "EOVERFLOW"},
	{unix.EDOM, "EDOM"}, {unix.EMLINK, "EMLINK"}, {unix.ENOLCK, "ENOLCK"},
	{unix.EPROCLIM, "EPROCLIM"}, {unix.EUSERS, "EUSERS"},
}

var errnoNameByValue = func() map[unix.Errno]string {
	m := make(map[unix.Errno]string, len(errnoNames))
	for _, en := range errnoNames {
		if _, dup := m[en.e]; !dup {
			m[en.e] = en.name
		}
	}
	return m
}()

// errnoName renders err as "ENAME (message)" when it carries an errno, and as
// the plain message otherwise. Every syscall failure the probe reports goes
// through this so the operator always sees the symbolic errno.
func errnoName(err error) string {
	if err == nil {
		return "OK"
	}
	var e unix.Errno
	if errors.As(err, &e) {
		if name, ok := errnoNameByValue[e]; ok {
			return fmt.Sprintf("%s (%v)", name, e)
		}
		return fmt.Sprintf("errno %d (%v)", int(e), e)
	}
	return err.Error()
}

// syscallError annotates a failing syscall with its name and symbolic errno.
func syscallError(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %s", op, errnoName(err))
}

// ---------------------------------------------------------------------------
// stage 1: environment
// ---------------------------------------------------------------------------

// csrAllowNames maps csr_config_t bits (xnu bsd/sys/csr.h) to their symbolic
// names so a partially disabled SIP can be described precisely.
var csrAllowNames = []struct {
	bit  uint32
	name string
}{
	{1 << 0, "ALLOW_UNTRUSTED_KEXTS"},
	{1 << 1, "ALLOW_UNRESTRICTED_FS"},
	{1 << 2, "ALLOW_TASK_FOR_PID"},
	{1 << 3, "ALLOW_KERNEL_DEBUGGER"},
	{1 << 4, "ALLOW_APPLE_INTERNAL"},
	{1 << 5, "ALLOW_UNRESTRICTED_DTRACE"},
	{1 << 6, "ALLOW_UNRESTRICTED_NVRAM"},
	{1 << 7, "ALLOW_DEVICE_CONFIGURATION"},
	{1 << 8, "ALLOW_ANY_RECOVERY_OS"},
	{1 << 9, "ALLOW_UNAPPROVED_KEXTS"},
	{1 << 10, "ALLOW_EXECUTABLE_POLICY_OVERRIDE"},
	{1 << 11, "ALLOW_UNAUTHENTICATED_ROOT"},
}

// envInfo is the machine description gathered by stage 1.
type envInfo struct {
	UID            int
	EUID           int
	OSRelease      string
	ProductVersion string
	OSVersion      string
	Machine        string
	CSRConfig      uint32
	CSRConfigKnown bool
	SIP            string
	SIPDetail      string
	Errors         []string
}

// gatherEnv collects uid, kernel/product version, arch and SIP state. SIP is
// read through csrctl(2) op CSR_SYSCALL_GET_ACTIVE_CONFIG, falling back to
// csrutil(1) if the syscall is unavailable.
func gatherEnv() envInfo {
	e := envInfo{UID: os.Getuid(), EUID: os.Geteuid()}
	get := func(name string) string {
		v, err := unix.Sysctl(name)
		if err != nil {
			e.Errors = append(e.Errors, syscallError("sysctl "+name, err).Error())
			return "?"
		}
		return v
	}
	e.OSRelease = get("kern.osrelease")
	e.ProductVersion = get("kern.osproductversion")
	e.OSVersion = get("kern.osversion")
	e.Machine = get("hw.machine")

	var cfg uint32
	_, _, errno := unix.Syscall(sysCsrctl, csrSyscallGetActiveConfig,
		uintptr(unsafe.Pointer(&cfg)), csrConfigSize)
	if errno == 0 {
		e.CSRConfig = cfg
		e.CSRConfigKnown = true
		if cfg == 0 {
			e.SIP = "enabled"
			e.SIPDetail = "csr_active_config=0x0 (all protections on)"
		} else {
			var allowed []string
			for _, a := range csrAllowNames {
				if cfg&a.bit != 0 {
					allowed = append(allowed, a.name)
				}
			}
			if len(allowed) == 0 {
				allowed = []string{"unknown bits"}
			}
			e.SIP = "partially-disabled"
			e.SIPDetail = fmt.Sprintf("csr_active_config=%#x: %s", cfg, strings.Join(allowed, ","))
		}
		return e
	}
	e.Errors = append(e.Errors, syscallError("csrctl(GET_ACTIVE_CONFIG)", errno).Error())
	out, err := exec.Command("/usr/bin/csrutil", "status").CombinedOutput()
	if err != nil {
		e.SIP = "unknown"
		e.SIPDetail = "csrctl failed and csrutil status failed: " + err.Error()
		return e
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	e.SIPDetail = line
	switch {
	case strings.Contains(line, "enabled"):
		e.SIP = "enabled"
	case strings.Contains(line, "disabled"):
		e.SIP = "disabled"
	default:
		e.SIP = "unknown"
	}
	return e
}

// sysctlInt reads an integer sysctl by name, returning ok=false if it does not
// exist on this kernel.
func sysctlInt(name string) (int, bool) {
	v, err := unix.SysctlUint32(name)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// ---------------------------------------------------------------------------
// routing table (stage 2 and 3)
// ---------------------------------------------------------------------------

// Offsets inside the Darwin routing-socket message headers. All of these were
// verified by compiling a C program against <net/route.h> and <net/if.h> from
// the SDK on this machine:
//
//	struct rt_msghdr  size 92: rtm_index @4, rtm_flags @8, rtm_addrs @12
//	struct if_msghdr  size 112: ifm_addrs @4, ifm_flags @8, ifm_index @12
//	struct ifa_msghdr size 20: ifam_addrs @4, ifam_flags @8, ifam_index @12
const (
	sizeofRtMsghdr  = 92
	sizeofIfMsghdr  = 112
	sizeofIfaMsghdr = 20

	offRtIndex = 4
	offRtFlags = 8
	offRtAddrs = 12

	offIfAddrs = 4
	offIfFlags = 8
	offIfIndex = 12

	offIfaAddrs = 4
	offIfaIndex = 12

	rtaxMax = 8 // RTAX_MAX
)

// roundup4 implements the ROUNDUP() macro the Darwin routing code uses to step
// between sockaddrs: lengths are rounded up to 4 bytes, and a zero length still
// consumes one 4-byte slot.
func roundup4(n int) int {
	if n == 0 {
		return 4
	}
	return (n + 3) &^ 3
}

// splitSockaddrs slices the sockaddr array that follows a routing message
// header into one entry per RTAX_* slot present in addrs. Absent slots are nil.
// It never reads past the end of b.
func splitSockaddrs(b []byte, addrs uint32) [][]byte {
	out := make([][]byte, rtaxMax)
	for i := 0; i < rtaxMax; i++ {
		if addrs&(1<<uint(i)) == 0 {
			continue
		}
		if len(b) < 2 {
			return out
		}
		salen := int(b[0])
		step := roundup4(salen)
		if salen == 0 || salen > len(b) {
			salen = min(step, len(b))
		}
		out[i] = b[:salen]
		if step >= len(b) {
			return out
		}
		b = b[step:]
	}
	return out
}

// sockaddrInet4 extracts the IPv4 address and port from a sockaddr_in that the
// routing socket produced. Netmask slots are frequently truncated (sa_len < 16),
// so missing trailing bytes are treated as zero, exactly as the kernel intends.
func sockaddrInet4(b []byte) (netip.Addr, uint16, bool) {
	if len(b) < 2 || b[1] != unix.AF_INET {
		return netip.Addr{}, 0, false
	}
	var a [4]byte
	if len(b) > 4 {
		copy(a[:], b[4:min(len(b), 8)])
	}
	var port uint16
	if len(b) >= 4 {
		port = binary.BigEndian.Uint16(b[2:4])
	}
	return netip.AddrFrom4(a), port, true
}

// sockaddrMaskIsZero reports whether a RTA_NETMASK slot denotes /0. The kernel
// encodes a default route's mask either by omitting the slot or by emitting a
// truncated sockaddr whose address bytes are all zero.
func sockaddrMaskIsZero(b []byte) bool {
	if len(b) <= 4 {
		return true
	}
	for _, c := range b[4:] {
		if c != 0 {
			return false
		}
	}
	return true
}

// parseLinkAddr decodes a sockaddr_dl. Layout verified against <net/if_dl.h>:
// sdl_len@0 sdl_family@1 sdl_index@2 sdl_type@4 sdl_nlen@5 sdl_alen@6
// sdl_slen@7 sdl_data@8.
func parseLinkAddr(b []byte) (index int, name string, mac net.HardwareAddr, ok bool) {
	if len(b) < 8 || b[1] != unix.AF_LINK {
		return 0, "", nil, false
	}
	index = int(binary.LittleEndian.Uint16(b[2:4]))
	nlen := int(b[5])
	alen := int(b[6])
	if 8+nlen > len(b) {
		return index, "", nil, false
	}
	name = string(b[8 : 8+nlen])
	if alen > 0 && 8+nlen+alen <= len(b) {
		mac = net.HardwareAddr(append([]byte(nil), b[8+nlen:8+nlen+alen]...))
	}
	return index, name, mac, true
}

// ifaceInfo describes one network interface as reported by NET_RT_IFLIST.
type ifaceInfo struct {
	Index int
	Name  string
	Flags uint32
	MAC   net.HardwareAddr
	IPv4  []netip.Addr
}

// interfaceTable dumps NET_RT_IFLIST and returns interfaces keyed by ifindex,
// including link-layer address and every configured IPv4 address.
func interfaceTable() (map[int]*ifaceInfo, error) {
	buf, err := sysctlMIB([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, 0, unix.NET_RT_IFLIST, 0})
	if err != nil {
		return nil, syscallError("sysctl net.route.0.0.iflist", err)
	}
	out := make(map[int]*ifaceInfo)
	for b := buf; len(b) >= 4; {
		msglen := int(binary.LittleEndian.Uint16(b[0:2]))
		if msglen < 4 || msglen > len(b) {
			break
		}
		msg := b[:msglen]
		b = b[msglen:]
		if msg[2] != unix.RTM_VERSION {
			continue
		}
		switch msg[3] {
		case unix.RTM_IFINFO:
			if msglen <= sizeofIfMsghdr {
				continue
			}
			idx := int(binary.LittleEndian.Uint16(msg[offIfIndex : offIfIndex+2]))
			flags := binary.LittleEndian.Uint32(msg[offIfFlags : offIfFlags+4])
			addrs := binary.LittleEndian.Uint32(msg[offIfAddrs : offIfAddrs+4])
			sas := splitSockaddrs(msg[sizeofIfMsghdr:], addrs)
			info := out[idx]
			if info == nil {
				info = &ifaceInfo{Index: idx}
				out[idx] = info
			}
			info.Flags = flags
			if sa := sas[unix.RTAX_IFP]; sa != nil {
				if _, name, mac, ok := parseLinkAddr(sa); ok {
					if name != "" {
						info.Name = name
					}
					if len(mac) > 0 {
						info.MAC = mac
					}
				}
			}
		case unix.RTM_NEWADDR:
			if msglen <= sizeofIfaMsghdr {
				continue
			}
			idx := int(binary.LittleEndian.Uint16(msg[offIfaIndex : offIfaIndex+2]))
			addrs := binary.LittleEndian.Uint32(msg[offIfaAddrs : offIfaAddrs+4])
			sas := splitSockaddrs(msg[sizeofIfaMsghdr:], addrs)
			if sa := sas[unix.RTAX_IFA]; sa != nil {
				if ip, _, ok := sockaddrInet4(sa); ok {
					info := out[idx]
					if info == nil {
						info = &ifaceInfo{Index: idx}
						out[idx] = info
					}
					info.IPv4 = append(info.IPv4, ip)
				}
			}
		}
	}
	return out, nil
}

// routeInfo is one IPv4 default route as read from the kernel routing table.
type routeInfo struct {
	IfIndex    int
	IfName     string
	Flags      uint32
	Gateway    netip.Addr       // invalid when the gateway is link-layer only
	GatewayMAC net.HardwareAddr // set when RTAX_GATEWAY was a sockaddr_dl
	LocalIPv4  netip.Addr
	MAC        net.HardwareAddr
	IsTunnel   bool
}

// routeMessageTypes are the RTM_* types whose payload is a struct rt_msghdr.
// A NET_RT_DUMP always reports RTM_GET, but accept the whole family so the
// parser is not brittle across releases.
var routeMessageTypes = map[byte]bool{
	unix.RTM_ADD: true, unix.RTM_DELETE: true, unix.RTM_CHANGE: true,
	unix.RTM_GET: true, unix.RTM_LOSING: true, unix.RTM_REDIRECT: true,
	unix.RTM_MISS: true, unix.RTM_LOCK: true, unix.RTM_RESOLVE: true,
}

// isTunnelName reports whether an interface name belongs to a VPN-style
// point-to-point device. A default route on one of these means the probe is
// measuring the VPN path rather than the physical link.
func isTunnelName(name string) bool {
	for _, p := range []string{"utun", "ipsec", "ppp", "gif", "stf", "tun", "tap"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// defaultRoutes returns every usable IPv4 default route (dst 0.0.0.0/0),
// enriched with the outgoing interface's name, MAC and local address.
func defaultRoutes(ifaces map[int]*ifaceInfo) ([]routeInfo, error) {
	buf, err := sysctlMIB([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_INET, unix.NET_RT_DUMP, 0})
	if err != nil {
		return nil, syscallError("sysctl net.route.0.inet.dump", err)
	}
	var out []routeInfo
	for b := buf; len(b) >= 4; {
		msglen := int(binary.LittleEndian.Uint16(b[0:2]))
		if msglen < 4 || msglen > len(b) {
			break
		}
		msg := b[:msglen]
		b = b[msglen:]
		if msg[2] != unix.RTM_VERSION || !routeMessageTypes[msg[3]] || msglen <= sizeofRtMsghdr {
			continue
		}
		flags := binary.LittleEndian.Uint32(msg[offRtFlags : offRtFlags+4])
		if flags&unix.RTF_UP == 0 {
			continue
		}
		addrs := binary.LittleEndian.Uint32(msg[offRtAddrs : offRtAddrs+4])
		sas := splitSockaddrs(msg[sizeofRtMsghdr:], addrs)
		dst, _, ok := sockaddrInet4(sas[unix.RTAX_DST])
		if !ok || dst != netip.AddrFrom4([4]byte{}) {
			continue
		}
		if !sockaddrMaskIsZero(sas[unix.RTAX_NETMASK]) {
			continue
		}
		ri := routeInfo{
			IfIndex: int(binary.LittleEndian.Uint16(msg[offRtIndex : offRtIndex+2])),
			Flags:   flags,
		}
		if gw := sas[unix.RTAX_GATEWAY]; gw != nil {
			if ip, _, ok := sockaddrInet4(gw); ok {
				ri.Gateway = ip
			} else if _, _, mac, ok := parseLinkAddr(gw); ok {
				ri.GatewayMAC = mac
			}
		}
		if ifa := sas[unix.RTAX_IFA]; ifa != nil {
			if ip, _, ok := sockaddrInet4(ifa); ok {
				ri.LocalIPv4 = ip
			}
		}
		if inf := ifaces[ri.IfIndex]; inf != nil {
			ri.IfName = inf.Name
			ri.MAC = inf.MAC
			if !ri.LocalIPv4.IsValid() && len(inf.IPv4) > 0 {
				ri.LocalIPv4 = inf.IPv4[0]
			}
		}
		ri.IsTunnel = isTunnelName(ri.IfName)
		out = append(out, ri)
	}
	// Deterministic order: non-tunnel routes first, then by ifindex.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsTunnel != out[j].IsTunnel {
			return !out[i].IsTunnel
		}
		return out[i].IfIndex < out[j].IfIndex
	})
	return out, nil
}

// gatewayRouteForIface finds a usable gateway on the named interface when the
// operator pinned --iface to something that is not currently the default route.
func gatewayRouteForIface(ifaces map[int]*ifaceInfo, name string) (routeInfo, bool) {
	buf, err := sysctlMIB([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_INET, unix.NET_RT_DUMP, 0})
	if err != nil {
		return routeInfo{}, false
	}
	want := -1
	for idx, inf := range ifaces {
		if inf.Name == name {
			want = idx
			break
		}
	}
	if want < 0 {
		return routeInfo{}, false
	}
	for b := buf; len(b) >= 4; {
		msglen := int(binary.LittleEndian.Uint16(b[0:2]))
		if msglen < 4 || msglen > len(b) {
			break
		}
		msg := b[:msglen]
		b = b[msglen:]
		if msg[2] != unix.RTM_VERSION || !routeMessageTypes[msg[3]] || msglen <= sizeofRtMsghdr {
			continue
		}
		flags := binary.LittleEndian.Uint32(msg[offRtFlags : offRtFlags+4])
		if flags&unix.RTF_UP == 0 || flags&unix.RTF_GATEWAY == 0 {
			continue
		}
		if int(binary.LittleEndian.Uint16(msg[offRtIndex:offRtIndex+2])) != want {
			continue
		}
		addrs := binary.LittleEndian.Uint32(msg[offRtAddrs : offRtAddrs+4])
		sas := splitSockaddrs(msg[sizeofRtMsghdr:], addrs)
		gw, _, ok := sockaddrInet4(sas[unix.RTAX_GATEWAY])
		if !ok {
			continue
		}
		ri := routeInfo{IfIndex: want, IfName: name, Flags: flags, Gateway: gw}
		if inf := ifaces[want]; inf != nil {
			ri.MAC = inf.MAC
			if len(inf.IPv4) > 0 {
				ri.LocalIPv4 = inf.IPv4[0]
			}
		}
		if ifa := sas[unix.RTAX_IFA]; ifa != nil {
			if ip, _, ok := sockaddrInet4(ifa); ok {
				ri.LocalIPv4 = ip
			}
		}
		ri.IsTunnel = isTunnelName(name)
		return ri, true
	}
	return routeInfo{}, false
}

// arpTable dumps the IPv4 ARP cache (NET_RT_FLAGS filtered by RTF_LLINFO) and
// returns the resolved link-layer address for each neighbour.
func arpTable() (map[netip.Addr]net.HardwareAddr, error) {
	buf, err := sysctlMIB([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_INET, unix.NET_RT_FLAGS, unix.RTF_LLINFO})
	if err != nil {
		return nil, syscallError("sysctl net.route.0.inet.flags(RTF_LLINFO)", err)
	}
	out := make(map[netip.Addr]net.HardwareAddr)
	for b := buf; len(b) >= 4; {
		msglen := int(binary.LittleEndian.Uint16(b[0:2]))
		if msglen < 4 || msglen > len(b) {
			break
		}
		msg := b[:msglen]
		b = b[msglen:]
		if msg[2] != unix.RTM_VERSION || !routeMessageTypes[msg[3]] || msglen <= sizeofRtMsghdr {
			continue
		}
		addrs := binary.LittleEndian.Uint32(msg[offRtAddrs : offRtAddrs+4])
		sas := splitSockaddrs(msg[sizeofRtMsghdr:], addrs)
		ip, _, ok := sockaddrInet4(sas[unix.RTAX_DST])
		if !ok {
			continue
		}
		gw := sas[unix.RTAX_GATEWAY]
		if gw == nil {
			continue
		}
		if _, _, mac, ok := parseLinkAddr(gw); ok && len(mac) == 6 {
			out[ip] = mac
		}
	}
	return out, nil
}

// primeARP forces the kernel to resolve gw's link-layer address by sending a
// single UDP datagram to the discard port. Nothing is expected in return; the
// point is only the ARP request the send triggers.
func primeARP(gw netip.Addr) error {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gw.AsSlice(), Port: 9})
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = c.Write([]byte{0})
	return err
}

// resolveGatewayMAC looks gw up in the ARP cache and, if it is missing, sends
// one UDP probe to populate the cache and retries once.
func resolveGatewayMAC(gw netip.Addr) (net.HardwareAddr, bool, error) {
	tbl, err := arpTable()
	if err != nil {
		return nil, false, err
	}
	if mac, ok := tbl[gw]; ok && len(mac) == 6 {
		return mac, false, nil
	}
	if err := primeARP(gw); err != nil {
		return nil, true, fmt.Errorf("ARP prime via UDP to %s:9 failed: %v", gw, err)
	}
	// Give the ARP exchange a moment; a LAN round trip is sub-millisecond but
	// the cache entry is installed asynchronously from the reply.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		tbl, err = arpTable()
		if err != nil {
			return nil, true, err
		}
		if mac, ok := tbl[gw]; ok && len(mac) == 6 {
			return mac, true, nil
		}
	}
	return nil, true, fmt.Errorf("no ARP entry for %s after one UDP probe", gw)
}

// ---------------------------------------------------------------------------
// IPv4/TCP parsing, checksums, synthesis
// ---------------------------------------------------------------------------

// onesComplementSum accumulates the 16-bit one's-complement sum used by both
// the IPv4 header and TCP checksums, folding the carries at the end.
func onesComplementSum(b []byte, initial uint32) uint32 {
	sum := initial
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		// Odd trailing byte is treated as the high half of a 16-bit word.
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum
}

// ipv4HeaderChecksum computes the header checksum over hdr with the checksum
// field itself treated as zero.
func ipv4HeaderChecksum(hdr []byte) uint16 {
	if len(hdr) < 20 {
		return 0
	}
	tmp := make([]byte, len(hdr))
	copy(tmp, hdr)
	tmp[10], tmp[11] = 0, 0
	return ^uint16(onesComplementSum(tmp, 0))
}

// tcpChecksum computes the TCP checksum over an IPv4 packet, with the checksum
// field treated as zero. src/dst come from the IP header, forming the
// pseudo-header together with the protocol number and the TCP segment length.
func tcpChecksum(ip []byte, ihl int) uint16 {
	if len(ip) < ihl+20 {
		return 0
	}
	seg := ip[ihl:]
	tmp := make([]byte, len(seg))
	copy(tmp, seg)
	tmp[16], tmp[17] = 0, 0
	var pseudo [12]byte
	copy(pseudo[0:4], ip[12:16])
	copy(pseudo[4:8], ip[16:20])
	pseudo[8] = 0
	pseudo[9] = 6 // IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	sum := onesComplementSum(pseudo[:], 0)
	return ^uint16(onesComplementSum(tmp, sum))
}

// ipv4Info is the decoded view of a captured IPv4 packet used in the reports.
type ipv4Info struct {
	Version     int
	IHL         int
	TotalLen    int
	ID          uint16
	FragField   uint16
	TTL         uint8
	Proto       uint8
	HdrCsum     uint16
	HdrCsumCalc uint16
	HdrCsumOK   bool
	Src         netip.Addr
	Dst         netip.Addr

	HasTCP       bool
	SrcPort      uint16
	DstPort      uint16
	Seq          uint32
	Ack          uint32
	TCPFlags     uint8
	TCPFlagsText string
	Window       uint16
	TCPCsum      uint16
	TCPCsumCalc  uint16
	TCPCsumOK    bool
	PayloadLen   int
}

// tcpFlagNames renders a TCP flag byte, e.g. 0x12 -> "SYN,ACK".
func tcpFlagNames(f uint8) string {
	names := []struct {
		bit  uint8
		name string
	}{
		{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"}, {0x08, "PSH"},
		{0x10, "ACK"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"},
	}
	var set []string
	for _, n := range names {
		if f&n.bit != 0 {
			set = append(set, n.name)
		}
	}
	if len(set) == 0 {
		return "none"
	}
	return strings.Join(set, ",")
}

// parseIPv4 decodes an IPv4 packet defensively: every field access is bounds
// checked, so a truncated or hostile buffer yields ok=false rather than a panic.
func parseIPv4(pkt []byte) (ipv4Info, bool) {
	var info ipv4Info
	if len(pkt) < 20 {
		return info, false
	}
	info.Version = int(pkt[0] >> 4)
	info.IHL = int(pkt[0]&0x0f) * 4
	if info.Version != 4 || info.IHL < 20 || info.IHL > len(pkt) {
		return info, false
	}
	info.TotalLen = int(binary.BigEndian.Uint16(pkt[2:4]))
	info.ID = binary.BigEndian.Uint16(pkt[4:6])
	info.FragField = binary.BigEndian.Uint16(pkt[6:8])
	info.TTL = pkt[8]
	info.Proto = pkt[9]
	info.HdrCsum = binary.BigEndian.Uint16(pkt[10:12])
	info.HdrCsumCalc = ipv4HeaderChecksum(pkt[:info.IHL])
	info.HdrCsumOK = info.HdrCsum == info.HdrCsumCalc
	info.Src = netip.AddrFrom4([4]byte(pkt[12:16]))
	info.Dst = netip.AddrFrom4([4]byte(pkt[16:20]))

	if info.Proto != 6 {
		return info, true
	}
	// Trust the shorter of total_len and the buffer so a padded frame does not
	// poison the TCP checksum.
	end := len(pkt)
	if info.TotalLen >= info.IHL && info.TotalLen <= len(pkt) {
		end = info.TotalLen
	}
	if end < info.IHL+20 {
		return info, true
	}
	tcp := pkt[info.IHL:end]
	info.HasTCP = true
	info.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
	info.DstPort = binary.BigEndian.Uint16(tcp[2:4])
	info.Seq = binary.BigEndian.Uint32(tcp[4:8])
	info.Ack = binary.BigEndian.Uint32(tcp[8:12])
	info.TCPFlags = tcp[13]
	info.TCPFlagsText = tcpFlagNames(info.TCPFlags)
	info.Window = binary.BigEndian.Uint16(tcp[14:16])
	info.TCPCsum = binary.BigEndian.Uint16(tcp[16:18])
	info.TCPCsumCalc = tcpChecksum(pkt[:end], info.IHL)
	info.TCPCsumOK = info.TCPCsum == info.TCPCsumCalc
	dataOff := int(tcp[12]>>4) * 4
	if dataOff >= 20 && dataOff <= len(tcp) {
		info.PayloadLen = len(tcp) - dataOff
	}
	return info, true
}

// hexdump renders up to max bytes of b in the classic offset/hex/ASCII layout.
func hexdump(b []byte, max int) string {
	if max > 0 && len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for off := 0; off < len(b); off += 16 {
		end := min(off+16, len(b))
		fmt.Fprintf(&sb, "%04x  ", off)
		for i := off; i < off+16; i++ {
			if i < end {
				fmt.Fprintf(&sb, "%02x ", b[i])
			} else {
				sb.WriteString("   ")
			}
			if i-off == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for i := off; i < end; i++ {
			if b[i] >= 0x20 && b[i] < 0x7f {
				sb.WriteByte(b[i])
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|")
		if end < len(b) {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// buildSYN synthesises a minimal 40-byte IPv4/TCP SYN with both checksums
// filled in. It is the stand-in packet for stages 7 and 8 when route-to never
// delivered a real one.
func buildSYN(src, dst netip.Addr, sport, dport uint16, id uint16, seq uint32) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, IHL 5 (no options)
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF, no fragment offset
	pkt[8] = 64                                  // TTL
	pkt[9] = 6                                   // IPPROTO_TCP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4 // data offset 5 words, no options
	tcp[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(pkt, 20))
	return pkt
}

// ---------------------------------------------------------------------------
// stage 8: SOCK_RAW / IP_HDRINCL
// ---------------------------------------------------------------------------

// rawSender owns an AF_INET/SOCK_RAW socket with IP_HDRINCL enabled, the
// classic BSD path for injecting a fully formed IPv4 packet.
type rawSender struct {
	fd int
}

// newRawSender creates the raw socket and turns on IP_HDRINCL.
func newRawSender() (*rawSender, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, syscallError("socket(AF_INET, SOCK_RAW, IPPROTO_RAW)", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, syscallError("setsockopt(IP_HDRINCL)", err)
	}
	return &rawSender{fd: fd}, nil
}

// hostOrderIPv4 returns a copy of pkt with ip_len and ip_off byte-swapped into
// host order and ip_sum zeroed. Darwin's rip_output() is the historical BSD
// code path: with IP_HDRINCL it expects exactly those two fields in host byte
// order (every other field stays network order) and computes the header
// checksum itself when it is zero.
func hostOrderIPv4(pkt []byte) []byte {
	out := make([]byte, len(pkt))
	copy(out, pkt)
	if len(out) < 20 {
		return out
	}
	l := binary.BigEndian.Uint16(out[2:4])
	binary.NativeEndian.PutUint16(out[2:4], l)
	off := binary.BigEndian.Uint16(out[6:8])
	binary.NativeEndian.PutUint16(out[6:8], off)
	out[10], out[11] = 0, 0
	return out
}

// send transmits pkt (a network-order IPv4 packet) and returns the exact bytes
// handed to sendto(2), i.e. after the host-order fixup.
func (r *rawSender) send(pkt []byte, dst netip.Addr) ([]byte, error) {
	wire := hostOrderIPv4(pkt)
	sa := &unix.SockaddrInet4{Addr: dst.As4()}
	if err := unix.Sendto(r.fd, wire, 0, sa); err != nil {
		return wire, syscallError(fmt.Sprintf("sendto(%s)", dst), err)
	}
	return wire, nil
}

// Close releases the raw socket.
func (r *rawSender) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	err := unix.Close(r.fd)
	r.fd = -1
	return err
}

// waitReadable blocks until fd is readable or the timeout expires, retrying on
// EINTR. It is used instead of SO_RCVTIMEO because the utun control socket is
// an AF_SYSTEM socket and BPF descriptors are character devices.
func waitReadable(fd int, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return false, nil
		}
		ms := int(remain / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, ms)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return false, syscallError("poll", err)
		}
		if n == 0 {
			return false, nil
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return true, nil
		}
	}
}
