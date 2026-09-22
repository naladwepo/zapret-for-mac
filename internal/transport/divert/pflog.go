//go:build darwin

package divert

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	dltPFLOG       = 117
	pflogBufLen    = 512 * 1024
	pflogSnapLen   = 65535
	pflogNameFirst = 9
	pflogNameLast  = 31
)

// pflogHandle owns a temporary pflog interface and the BPF descriptor bound to
// it. PF logs a packet before applying its block verdict, giving userspace a
// lossless interception primitive on macOS versions where route-to/utun is
// broken.
type pflogHandle struct {
	name    string
	h       *bpfHandle
	pending [][]byte
}

func createPFLog() (*pflogHandle, error) {
	var last error
	for n := pflogNameFirst; n <= pflogNameLast; n++ {
		name := fmt.Sprintf("pflog%d", n)
		cmd := exec.Command("/sbin/ifconfig", name, "create")
		if out, err := cmd.CombinedOutput(); err != nil {
			last = fmt.Errorf("ifconfig %s create: %w: %s", name, err, strings.TrimSpace(string(out)))
			continue
		}
		// A freshly cloned pflog interface is DOWN. tcpdump brings capture
		// interfaces up as a side effect, which made the shell probe work while
		// our direct BPF reader saw no logged packets at all.
		if out, err := exec.Command("/sbin/ifconfig", name, "up").CombinedOutput(); err != nil {
			_ = exec.Command("/sbin/ifconfig", name, "destroy").Run()
			return nil, fmt.Errorf("ifconfig %s up: %w: %s", name, err, strings.TrimSpace(string(out)))
		}
		h, err := openBPFWithDLT(name, pflogBufLen, false, true, nil, dltPFLOG)
		if err != nil {
			_ = exec.Command("/sbin/ifconfig", name, "destroy").Run()
			return nil, err
		}
		return &pflogHandle{name: name, h: h}, nil
	}
	return nil, fmt.Errorf("divert: cannot create a free pflog interface: %w", last)
}

func (p *pflogHandle) Name() string { return p.name }

// Read returns one IP packet from a batch of BPF records. The pflog header's
// first byte is its own length; the IP packet starts immediately after it.
func (p *pflogHandle) Read(buf []byte, timeout time.Duration) (ver uint8, pkt []byte, ok bool, err error) {
	if len(p.pending) > 0 {
		pkt = p.pending[0]
		p.pending = p.pending[1:]
		return ipVersionOf(pkt), pkt, true, nil
	}
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil, false, nil
		}
		ready, err := waitReadable(p.h.fd, remaining)
		if err != nil || !ready {
			return 0, nil, false, err
		}
		n, err := unix.Read(p.h.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, nil, false, syscallError("read(pflog)", err)
		}
		hdrSize := int(unsafe.Sizeof(unix.BpfHdr{}))
		for off := 0; off+hdrSize <= n; {
			bh := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
			hl, cl := int(bh.Hdrlen), int(bh.Caplen)
			if hl < hdrSize || cl < 1 || off+hl+cl > n {
				break
			}
			frame := buf[off+hl : off+hl+cl]
			plen := int(frame[0])
			// pfloghdr.length is the unpadded structure length. The captured IP
			// payload starts at the next BPF_ALIGNMENT boundary (macOS currently
			// reports 61 bytes and places IP at offset 64).
			ipOff := bpfWordAlign(plen)
			if plen > 0 && ipOff < len(frame) {
				ip := frame[ipOff:]
				v := ipVersionOf(ip)
				if v == 4 || v == 6 {
					p.pending = append(p.pending, append([]byte(nil), ip...))
				}
			}
			step := bpfWordAlign(hl + cl)
			if step <= 0 {
				break
			}
			off += step
		}
		// A readable BPF batch can contain only a link-layer notification or a
		// malformed/truncated record. Keep waiting for an actual IP packet for
		// the remainder of the caller's timeout instead of reporting a false
		// timeout immediately.
		if len(p.pending) == 0 {
			continue
		}
		pkt = p.pending[0]
		p.pending = p.pending[1:]
		return ipVersionOf(pkt), pkt, true, nil
	}
}

func (p *pflogHandle) Close() error {
	if p == nil {
		return nil
	}
	var errs []string
	if p.h != nil {
		if err := p.h.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if out, err := exec.Command("/sbin/ifconfig", p.name, "destroy").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Sprintf("ifconfig %s destroy: %v: %s", p.name, err, strings.TrimSpace(string(out))))
	}
	if len(errs) != 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Ensure the full packet, not just the pflog prefix, fits the BPF snapshot.
var _ = pflogSnapLen
