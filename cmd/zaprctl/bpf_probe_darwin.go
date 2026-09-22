//go:build darwin

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF ioctl request numbers. Verified by compiling <net/bpf.h> from this
// machine's SDK and cross-checked against golang.org/x/sys/unix's generated
// darwin/arm64 constants:
//
//	BIOCSBLEN     _IOWR('B', 102, u_int)          == 0xc0044266
//	BIOCSETF      _IOW ('B', 103, bpf_program)    == 0x80104267 (sizeof 16)
//	BIOCFLUSH     _IO  ('B', 104)                 == 0x20004268
//	BIOCSETIF     _IOW ('B', 108, struct ifreq)   == 0x8020426c
//	BIOCGDLT      _IOR ('B', 106, u_int)          == 0x4004426a
//	BIOCGSTATS    _IOR ('B', 111, bpf_stat)       == 0x4008426f
//	BIOCIMMEDIATE _IOW ('B', 112, u_int)          == 0x80044270
//	BIOCSHDRCMPLT _IOW ('B', 117, u_int)          == 0x80044275
//	BIOCSSEESENT  _IOW ('B', 119, u_int)          == 0x80044277
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

// bpfBufLen is the kernel read buffer size requested via BIOCSBLEN. 256 KiB is
// comfortably inside BPF_MAXBUFSIZE (512 KiB on this kernel) and large enough
// that a busy Wi-Fi link does not drop the frames we are looking for.
const bpfBufLen = 256 * 1024

// bpfProgram mirrors "struct bpf_program" from <net/bpf.h>: an instruction
// count plus a pointer, 16 bytes on arm64.
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

// BPF instruction opcodes, from <net/bpf.h>. Composed from the class/size/mode
// bit fields: BPF_LD|BPF_H|BPF_ABS == 0x28 and so on.
const (
	bpfLDH = 0x28 // load 16 bits absolute
	bpfLDW = 0x20 // load 32 bits absolute
	bpfLDB = 0x30 // load 8 bits absolute
	bpfJEQ = 0x15 // jump if A == k
	bpfRET = 0x06 // return k
)

// tcpToHostFilter builds a BPF program matching Ethernet/IPv4/TCP frames whose
// IPv4 destination is dst. Offsets are fixed regardless of IP options because
// the destination address always sits at IP offset 16 and the protocol at 9.
func tcpToHostFilter(dst netip.Addr) []unix.BpfInsn {
	d := dst.As4()
	key := binary.BigEndian.Uint32(d[:])
	// Jump displacements are relative to the instruction after the jump, so
	// every "no match" branch targets the final "ret 0" at index 7.
	return []unix.BpfInsn{
		/* 0 */ {Code: bpfLDH, K: 12}, // ethertype
		/* 1 */ {Code: bpfJEQ, Jt: 0, Jf: 5, K: 0x0800}, // IPv4?
		/* 2 */ {Code: bpfLDW, K: 14 + 16}, // IPv4 dst address
		/* 3 */ {Code: bpfJEQ, Jt: 0, Jf: 3, K: key}, // == target?
		/* 4 */ {Code: bpfLDB, K: 14 + 9}, // IPv4 protocol
		/* 5 */ {Code: bpfJEQ, Jt: 0, Jf: 1, K: 6}, // IPPROTO_TCP?
		/* 6 */ {Code: bpfRET, K: 65535}, // accept
		/* 7 */ {Code: bpfRET, K: 0}, // drop
	}
}

// bpfHandle is an open /dev/bpfN descriptor bound to one interface.
type bpfHandle struct {
	fd       int
	Device   string
	Iface    string
	BufLen   int
	Datalink int
}

// openBPF finds the first usable /dev/bpfN, binds it to iface and configures it
// for immediate delivery. hdrComplete selects BIOCSHDRCMPLT (the caller supplies
// the whole link-layer header on write); seeSent controls whether locally
// transmitted frames are also captured. filter may be nil.
func openBPF(iface string, hdrComplete, seeSent bool, filter []unix.BpfInsn) (*bpfHandle, error) {
	var lastErr error
	for i := 0; i < 256; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(dev, unix.O_RDWR, 0)
		if err != nil {
			lastErr = syscallError("open("+dev+")", err)
			if err == unix.EBUSY {
				continue
			}
			if err == unix.ENOENT {
				// No more cloned nodes exist; stop scanning.
				break
			}
			if err == unix.EACCES || err == unix.EPERM {
				break
			}
			continue
		}
		h := &bpfHandle{fd: fd, Device: dev, Iface: iface, BufLen: bpfBufLen}
		if err := h.setup(hdrComplete, seeSent, filter); err != nil {
			unix.Close(fd)
			h.fd = -1
			return nil, err
		}
		return h, nil
	}
	if lastErr == nil {
		lastErr = syscallError("open(/dev/bpfN)", unix.ENOENT)
	}
	return nil, fmt.Errorf("no usable BPF device: %v", lastErr)
}

// setup applies the descriptor options in the order the kernel requires: the
// buffer length must be set before the interface is attached.
func (h *bpfHandle) setup(hdrComplete, seeSent bool, filter []unix.BpfInsn) error {
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
	one := int32(1)
	zero := int32(0)
	if hdrComplete {
		if err := ioctlPtr(h.fd, biocSHdrCmplt, unsafe.Pointer(&one)); err != nil {
			return syscallError("ioctl(BIOCSHDRCMPLT, 1)", err)
		}
	}
	if err := ioctlPtr(h.fd, biocImmediate, unsafe.Pointer(&one)); err != nil {
		return syscallError("ioctl(BIOCIMMEDIATE, 1)", err)
	}
	seen := &one
	if !seeSent {
		seen = &zero
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
	if err := unix.SetNonblock(h.fd, true); err != nil {
		return syscallError("SetNonblock(bpf)", err)
	}
	return nil
}

// writeFrame writes one complete link-layer frame. With BIOCSHDRCMPLT set the
// kernel transmits it verbatim, bypassing pf entirely — which is what keeps the
// re-emit step from looping back into our own route-to rule.
func (h *bpfHandle) writeFrame(frame []byte) (int, error) {
	if h == nil || h.fd < 0 {
		return 0, unix.EBADF
	}
	n, err := unix.Write(h.fd, frame)
	if err != nil {
		return n, syscallError("write(bpf)", err)
	}
	return n, nil
}

// readFrames drains the descriptor until deadline, returning the captured
// link-layer frames. Records are laid out as bpf_hdr + data, each padded to a
// BPF_WORDALIGN boundary.
func (h *bpfHandle) readFrames(deadline time.Time, maxFrames int) ([][]byte, error) {
	if h == nil || h.fd < 0 {
		return nil, unix.EBADF
	}
	buf := make([]byte, h.BufLen)
	var out [][]byte
	for time.Now().Before(deadline) && (maxFrames <= 0 || len(out) < maxFrames) {
		ready, err := waitReadable(h.fd, time.Until(deadline))
		if err != nil {
			return out, err
		}
		if !ready {
			break
		}
		n, err := unix.Read(h.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return out, syscallError("read(bpf)", err)
		}
		for off := 0; off+int(unsafe.Sizeof(unix.BpfHdr{})) <= n; {
			hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
			hdrLen := int(hdr.Hdrlen)
			capLen := int(hdr.Caplen)
			if hdrLen <= 0 || capLen < 0 || off+hdrLen+capLen > n {
				break
			}
			frame := make([]byte, capLen)
			copy(frame, buf[off+hdrLen:off+hdrLen+capLen])
			out = append(out, frame)
			step := bpfWordAlign(hdrLen + capLen)
			if step <= 0 {
				break
			}
			off += step
			if maxFrames > 0 && len(out) >= maxFrames {
				break
			}
		}
	}
	return out, nil
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
	return err
}

// ethFrame prepends a 14-byte Ethernet II header to payload.
func ethFrame(dstMAC, srcMAC net.HardwareAddr, etherType uint16, payload []byte) ([]byte, error) {
	if len(dstMAC) != 6 || len(srcMAC) != 6 {
		return nil, fmt.Errorf("need 6-byte MACs, got dst=%d src=%d bytes", len(dstMAC), len(srcMAC))
	}
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame, nil
}

// ethPayload strips the Ethernet header from a captured frame, returning the
// network-layer bytes for an IPv4 frame.
func ethPayload(frame []byte) ([]byte, bool) {
	if len(frame) < 14 {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return nil, false
	}
	return frame[14:], true
}
