package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Errors returned by Parse. They are wrapped with context, so use errors.Is.
var (
	// ErrTruncated means the buffer is shorter than the headers claim.
	ErrTruncated = errors.New("proto: truncated packet")
	// ErrIPVersion means the first nibble was neither 4 nor 6.
	ErrIPVersion = errors.New("proto: unsupported IP version")
	// ErrIPFragment means the packet is a non-initial IP fragment: it carries no
	// L4 header, so ports/flags cannot be parsed. Callers must forward such
	// packets untouched instead of trying to desync them.
	ErrIPFragment = errors.New("proto: non-initial IP fragment")
	// ErrMalformedHeader means a header field is self-inconsistent (bad IHL,
	// bad TCP data offset, an endless IPv6 extension-header chain, ...).
	ErrMalformedHeader = errors.New("proto: malformed header")
)

// Header geometry. Unexported so they cannot clash with other files of the
// package.
const (
	ipv4MinHdrLen   = 20
	ipv6FixedHdrLen = 40
	tcpMinHdrLen    = 20
	tcpMaxHdrLen    = 60
	udpHdrLen       = 8

	tcpChecksumOff = 16 // offset of the checksum inside the TCP header
	udpChecksumOff = 6  // offset of the checksum inside the UDP header

	// ipProtoRouting is the IPv6 routing header; types.go already names the
	// hop-by-hop (0), fragment (44) and destination-options (60) headers.
	ipProtoRouting = 43
	// ipProtoNoNext is IPv6 "no next header": the chain simply ends.
	ipProtoNoNext = 59

	// maxV6ExtHdrs bounds the extension-header walk so a crafted packet with a
	// zero-length loop cannot spin forever.
	maxV6ExtHdrs = 32

	// TCP option kinds we build or read.
	tcpOptKindEOL = 0
	tcpOptKindNOP = 1
	tcpOptKindTS  = 8
	tcpOptKindMD5 = 19
	tcpOptLenTS   = 10
	tcpOptLenMD5  = 18

	pktDefaultTTL = 64
	// pktDefaultWindow is used when Tmpl.Window is zero. Emitting a real zero
	// window would tell the peer to stop sending, which would break the very
	// connection we are trying to help.
	pktDefaultWindow = 64240

	// badSumXor is flipped into the L4 checksum for
	// --dpi-desync-fooling=badsum. A fixed XOR keeps injected packets
	// reproducible while guaranteeing the sum is wrong.
	badSumXor = 0xbeaf
)

// md5SigFiller is the 16-byte body of the bogus TCP-MD5 signature option
// (--dpi-desync-fooling=md5sig). Middleboxes only look at the option kind while
// the peer's TCP drops the segment for a bad signature, so the bytes just have
// to be present; a constant keeps output reproducible.
var md5SigFiller = [16]byte{
	0x9e, 0x4b, 0x1c, 0x2f, 0x7a, 0xd0, 0x33, 0x86,
	0x51, 0xe8, 0x0c, 0xb7, 0x45, 0x92, 0x6d, 0x1a,
}

// Parse decodes one complete IP packet (IPv4 or IPv6, TCP/UDP inside) into a
// Pkt. Every slice in the result aliases raw — do not retain the Pkt past the
// lifetime of raw.
//
// Raw is trimmed to the length the IP header declares, which removes the
// Ethernet minimum-frame padding a BPF read hands us; without that trim
// Payload() would report padding as L7 bytes.
//
// A protocol other than TCP/UDP (ICMP, ESP, ...) is not an error: Proto is set,
// L4Len is 0 and the port/TCP fields stay zero.
func Parse(raw []byte) (*Pkt, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty buffer", ErrTruncated)
	}
	switch raw[0] >> 4 {
	case 4:
		return parseV4(raw)
	case 6:
		return parseV6(raw)
	default:
		return nil, fmt.Errorf("%w: %d", ErrIPVersion, raw[0]>>4)
	}
}

func parseV4(raw []byte) (*Pkt, error) {
	if len(raw) < ipv4MinHdrLen {
		return nil, fmt.Errorf("%w: ipv4 header wants %d bytes, have %d", ErrTruncated, ipv4MinHdrLen, len(raw))
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < ipv4MinHdrLen {
		return nil, fmt.Errorf("%w: ipv4 ihl %d < %d", ErrMalformedHeader, ihl, ipv4MinHdrLen)
	}
	if len(raw) < ihl {
		return nil, fmt.Errorf("%w: ipv4 options want %d bytes, have %d", ErrTruncated, ihl, len(raw))
	}
	total := int(binary.BigEndian.Uint16(raw[2:4]))
	switch {
	case total == 0:
		// TCP segmentation offload leaves ip_len zero on locally generated
		// packets; the buffer length is then the only truth we have. Fill the
		// header too: the divert transport writes this packet below the IP
		// stack, where no driver will supply the missing length for us.
		if len(raw) > 0xffff {
			return nil, fmt.Errorf("%w: ipv4 offload packet length %d exceeds 65535", ErrMalformedHeader, len(raw))
		}
		total = len(raw)
		binary.BigEndian.PutUint16(raw[2:4], uint16(total))
	case total < ihl:
		return nil, fmt.Errorf("%w: ipv4 total length %d < ihl %d", ErrMalformedHeader, total, ihl)
	case total > len(raw):
		return nil, fmt.Errorf("%w: ipv4 total length %d, have %d", ErrTruncated, total, len(raw))
	}
	raw = raw[:total]

	fragField := binary.BigEndian.Uint16(raw[6:8])
	p := &Pkt{
		Raw:          raw,
		Ver:          4,
		Proto:        raw[9],
		TTL:          raw[8],
		IPID:         binary.BigEndian.Uint16(raw[4:6]),
		TrafficClass: raw[1],
		DF:           fragField&0x4000 != 0,
		Src:          netip.AddrFrom4([4]byte(raw[12:16])),
		Dst:          netip.AddrFrom4([4]byte(raw[16:20])),
		L3Len:        ihl,
	}
	if off := fragField & 0x1fff; off != 0 {
		return nil, fmt.Errorf("%w: ipv4 offset %d bytes", ErrIPFragment, int(off)*8)
	}
	if err := parseL4(p); err != nil {
		return nil, err
	}
	return p, nil
}

func parseV6(raw []byte) (*Pkt, error) {
	if len(raw) < ipv6FixedHdrLen {
		return nil, fmt.Errorf("%w: ipv6 header wants %d bytes, have %d", ErrTruncated, ipv6FixedHdrLen, len(raw))
	}
	plen := int(binary.BigEndian.Uint16(raw[4:6]))
	total := ipv6FixedHdrLen + plen
	switch {
	case plen == 0:
		// A zero length can mean a jumbogram (hop-by-hop option) or local
		// offload. Only a bare TCP/UDP packet is safe to normalise here;
		// jumbograms must retain their zero payload-length field.
		total = len(raw)
		if len(raw) <= ipv6FixedHdrLen+0xffff &&
			(raw[6] == IPProtoTCP || raw[6] == IPProtoUDP) {
			binary.BigEndian.PutUint16(raw[4:6], uint16(len(raw)-ipv6FixedHdrLen))
		}
	case total > len(raw):
		return nil, fmt.Errorf("%w: ipv6 payload length %d, have %d", ErrTruncated, plen, len(raw)-ipv6FixedHdrLen)
	}
	raw = raw[:total]

	// Addresses are kept in their true 16-byte form (no Unmap): an IPv6 header
	// must always yield Is6 addresses so Ver and the address family agree, even
	// for the pathological ::ffff:a.b.c.d source.
	p := &Pkt{
		Raw: raw,
		Ver: 6,
		TTL: raw[7],
		// Traffic class straddles the first two bytes: the low nibble of byte 0
		// is its top half, the high nibble of byte 1 its bottom half.
		TrafficClass: (raw[0]&0x0f)<<4 | raw[1]>>4,
		FlowLabel:    binary.BigEndian.Uint32(raw[0:4]) & 0x000fffff,
		// IPv6 routers never fragment in flight, so the IPv4 "don't fragment"
		// semantics are permanently in effect.
		DF:    true,
		Src:   netip.AddrFrom16([16]byte(raw[8:24])),
		Dst:   netip.AddrFrom16([16]byte(raw[24:40])),
		L3Len: ipv6FixedHdrLen,
	}

	next := raw[6]
	off := ipv6FixedHdrLen
	fragmented := false
	for hdrs := 0; ; hdrs++ {
		if hdrs > maxV6ExtHdrs {
			return nil, fmt.Errorf("%w: more than %d ipv6 extension headers", ErrMalformedHeader, maxV6ExtHdrs)
		}
		switch next {
		case IPProtoHopOpt, ipProtoRouting, IPProtoDstOpt:
			if off+2 > len(raw) {
				return nil, fmt.Errorf("%w: ipv6 ext header %d at %d", ErrTruncated, next, off)
			}
			// Hdr Ext Len counts 8-octet units *not* including the first one.
			hlen := (int(raw[off+1]) + 1) * 8
			if off+hlen > len(raw) {
				return nil, fmt.Errorf("%w: ipv6 ext header %d wants %d bytes at %d", ErrTruncated, next, hlen, off)
			}
			next = raw[off]
			off += hlen
		case IPProtoFrag:
			if off+8 > len(raw) {
				return nil, fmt.Errorf("%w: ipv6 fragment header at %d", ErrTruncated, off)
			}
			// Fragment offset lives in the top 13 bits of the second word.
			if binary.BigEndian.Uint16(raw[off+2:off+4])>>3 != 0 {
				fragmented = true
			}
			next = raw[off]
			off += 8
		default:
			p.Proto = next
			p.L3Len = off
			if fragmented {
				return nil, fmt.Errorf("%w: ipv6 fragment header with non-zero offset", ErrIPFragment)
			}
			if next == ipProtoNoNext {
				return p, nil
			}
			if err := parseL4(p); err != nil {
				return nil, err
			}
			return p, nil
		}
	}
}

// parseL4 fills the transport-layer fields of p, whose L3Len/Proto are already
// known.
func parseL4(p *Pkt) error {
	switch p.Proto {
	case IPProtoTCP:
		if len(p.Raw) < p.L3Len+tcpMinHdrLen {
			return fmt.Errorf("%w: tcp header wants %d bytes, have %d", ErrTruncated, tcpMinHdrLen, len(p.Raw)-p.L3Len)
		}
		h := p.Raw[p.L3Len:]
		dataOff := int(h[12]>>4) * 4
		if dataOff < tcpMinHdrLen {
			return fmt.Errorf("%w: tcp data offset %d < %d", ErrMalformedHeader, dataOff, tcpMinHdrLen)
		}
		if len(h) < dataOff {
			return fmt.Errorf("%w: tcp options want %d bytes, have %d", ErrTruncated, dataOff, len(h))
		}
		p.SrcPort = binary.BigEndian.Uint16(h[0:2])
		p.DstPort = binary.BigEndian.Uint16(h[2:4])
		p.Seq = binary.BigEndian.Uint32(h[4:8])
		p.Ack = binary.BigEndian.Uint32(h[8:12])
		p.Flags = h[13]
		p.Window = binary.BigEndian.Uint16(h[14:16])
		p.L4Len = dataOff
		p.TCPOpts = h[tcpMinHdrLen:dataOff]
		return nil

	case IPProtoUDP:
		if len(p.Raw) < p.L3Len+udpHdrLen {
			return fmt.Errorf("%w: udp header wants %d bytes, have %d", ErrTruncated, udpHdrLen, len(p.Raw)-p.L3Len)
		}
		h := p.Raw[p.L3Len:]
		p.SrcPort = binary.BigEndian.Uint16(h[0:2])
		p.DstPort = binary.BigEndian.Uint16(h[2:4])
		p.L4Len = udpHdrLen
		// A sane UDP length trims trailing padding the IP layer did not catch.
		if ulen := int(binary.BigEndian.Uint16(h[4:6])); ulen >= udpHdrLen && p.L3Len+ulen <= len(p.Raw) {
			p.Raw = p.Raw[:p.L3Len+ulen]
		}
		return nil

	default:
		// ICMP/ESP/... : no L4 view, Payload() is the whole rest of the packet.
		p.L4Len = 0
		return nil
	}
}

// Marshal builds a complete IP packet in network byte order, ready for a BPF
// Ethernet write (the buffer is the wire image, no host-order fields).
//
// Src/Dst decide the family and must agree. TCP is built unless UDP is set;
// TCP flags default to PSH|ACK, TTL to 64 and the window to 64240. The fooling
// knobs (BadSum, MD5Sig, NoAck) are applied here, at the end, so the checksum
// they corrupt is the one that would otherwise have been correct.
func (t *Tmpl) Marshal() ([]byte, error) {
	if !t.Src.IsValid() || !t.Dst.IsValid() {
		return nil, errors.New("proto: Tmpl needs a valid Src and Dst")
	}
	src, dst := t.Src.Unmap(), t.Dst.Unmap()
	if src.Is4() != dst.Is4() {
		return nil, fmt.Errorf("proto: mixed address families %s -> %s", src, dst)
	}

	var (
		l4     []byte
		ipprot uint8
		sumOff int
		err    error
	)
	if t.UDP {
		ipprot, sumOff = IPProtoUDP, udpChecksumOff
		l4 = t.marshalUDP()
	} else {
		ipprot, sumOff = IPProtoTCP, tcpChecksumOff
		if l4, err = t.marshalTCP(); err != nil {
			return nil, err
		}
	}

	// The checksum field is still zero inside l4, which is what the ones'
	// complement sum requires.
	sum := L4Checksum(src, dst, ipprot, l4)
	if t.BadSum {
		sum = corruptSum(sum)
	}
	binary.BigEndian.PutUint16(l4[sumOff:sumOff+2], sum)

	ttl := t.TTL
	if ttl == 0 {
		ttl = pktDefaultTTL
	}

	if src.Is4() {
		total := ipv4MinHdrLen + len(l4)
		if total > 0xffff {
			return nil, fmt.Errorf("proto: ipv4 packet too long: %d bytes", total)
		}
		out := make([]byte, total)
		out[0] = 0x45           // version 4, 20-byte header, no options
		out[1] = t.TrafficClass // DSCP + ECN, copied from the intercepted packet
		binary.BigEndian.PutUint16(out[2:4], uint16(total))
		binary.BigEndian.PutUint16(out[4:6], t.IPID)
		var frag uint16
		if t.DF {
			frag |= 0x4000
		}
		binary.BigEndian.PutUint16(out[6:8], frag)
		out[8] = ttl
		out[9] = ipprot
		// out[10:12] checksum stays zero while it is computed.
		s4, d4 := src.As4(), dst.As4()
		copy(out[12:16], s4[:])
		copy(out[16:20], d4[:])
		binary.BigEndian.PutUint16(out[10:12], Checksum16(out[:ipv4MinHdrLen]))
		copy(out[ipv4MinHdrLen:], l4)
		return out, nil
	}

	if len(l4) > 0xffff {
		return nil, fmt.Errorf("proto: ipv6 payload too long: %d bytes", len(l4))
	}
	out := make([]byte, ipv6FixedHdrLen+len(l4))
	// Version 6, then traffic class and flow label exactly as configured.
	binary.BigEndian.PutUint32(out[0:4], 0x60000000|
		uint32(t.TrafficClass)<<20|
		(t.FlowLabel&0x000fffff))
	binary.BigEndian.PutUint16(out[4:6], uint16(len(l4)))
	out[6] = ipprot
	out[7] = ttl // hop limit
	s16, d16 := src.As16(), dst.As16()
	copy(out[8:24], s16[:])
	copy(out[24:40], d16[:])
	copy(out[ipv6FixedHdrLen:], l4)
	return out, nil
}

// marshalTCP builds the TCP header, options and payload with a zero checksum.
func (t *Tmpl) marshalTCP() ([]byte, error) {
	flags := t.Flags
	if flags == 0 {
		flags = TCPPsh | TCPAck
	}
	if t.NoAck {
		// --dpi-desync-fooling=datanoack: the ack number stays put, only the
		// flag goes, so the peer's TCP discards the segment while a stateless
		// DPI still parses its payload.
		flags &^= TCPAck
	}

	opts := make([]byte, 0, tcpMaxHdrLen-tcpMinHdrLen)
	opts = append(opts, t.TCPOpts...)
	if t.MD5Sig {
		opts = append(opts, tcpOptKindMD5, tcpOptLenMD5)
		opts = append(opts, md5SigFiller[:]...)
	}
	if rem := len(opts) % 4; rem != 0 {
		// The data offset counts 32-bit words, so pad with NOPs and close the
		// list with a single End-of-Option-List byte (RFC 9293 3.1).
		for i := 0; i < 4-rem-1; i++ {
			opts = append(opts, tcpOptKindNOP)
		}
		opts = append(opts, tcpOptKindEOL)
	}
	if len(opts) > tcpMaxHdrLen-tcpMinHdrLen {
		return nil, fmt.Errorf("proto: tcp options too long: %d bytes (max %d)", len(opts), tcpMaxHdrLen-tcpMinHdrLen)
	}

	hlen := tcpMinHdrLen + len(opts)
	b := make([]byte, hlen+len(t.Payload))
	binary.BigEndian.PutUint16(b[0:2], t.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], t.DstPort)
	binary.BigEndian.PutUint32(b[4:8], t.Seq)
	binary.BigEndian.PutUint32(b[8:12], t.Ack)
	b[12] = byte(hlen/4) << 4
	b[13] = flags
	window := t.Window
	if window == 0 {
		window = pktDefaultWindow
	}
	binary.BigEndian.PutUint16(b[14:16], window)
	// b[16:18] checksum, b[18:20] urgent pointer: left zero.
	copy(b[tcpMinHdrLen:], opts)
	copy(b[hlen:], t.Payload)
	return b, nil
}

// marshalUDP builds the UDP header and payload with a zero checksum.
func (t *Tmpl) marshalUDP() []byte {
	b := make([]byte, udpHdrLen+len(t.Payload))
	binary.BigEndian.PutUint16(b[0:2], t.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], t.DstPort)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)))
	// b[6:8] checksum: left zero.
	copy(b[udpHdrLen:], t.Payload)
	return b
}

// corruptSum turns a correct L4 checksum into a deliberately wrong one.
func corruptSum(good uint16) uint16 {
	bad := good ^ badSumXor
	if bad == 0 {
		// Zero means "no checksum" for UDP, which a receiver would happily
		// accept; pick any other value that is still wrong.
		bad = 0xffff
	}
	return bad
}

// HostOrderIPHeaderInPlace converts an IPv4 header's total-length and
// flags/fragment-offset fields from network to host byte order.
//
// This is only for the SOCK_RAW + IP_HDRINCL fallback: Darwin's rip_output()
// does ip_len = htons(ip_len) and ip_off = htons(ip_off) on the buffer it gets,
// so userspace must hand it those two fields in host order. Everything else,
// including the header checksum, stays in wire order — the kernel swaps the two
// fields back before transmitting, so a checksum computed over the network-order
// header is exactly right on the wire.
//
// No-op for IPv6 (no such quirk) and for buffers too short to be an IPv4 header.
func HostOrderIPHeaderInPlace(pkt []byte) {
	if len(pkt) < ipv4MinHdrLen || pkt[0]>>4 != 4 {
		return
	}
	binary.NativeEndian.PutUint16(pkt[2:4], binary.BigEndian.Uint16(pkt[2:4]))
	binary.NativeEndian.PutUint16(pkt[6:8], binary.BigEndian.Uint16(pkt[6:8]))
}

// tcpOptFind walks a TCP option block and returns the offset of the first
// option with the given kind and length, or -1. The walk stops at the first
// End-of-Option-List and at the first malformed length, so hostile input can
// never make it read out of range.
func tcpOptFind(opts []byte, kind, length byte) int {
	for i := 0; i < len(opts); {
		switch opts[i] {
		case tcpOptKindEOL:
			return -1
		case tcpOptKindNOP:
			i++
			continue
		}
		if i+1 >= len(opts) {
			return -1
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			return -1
		}
		if opts[i] == kind && l == int(length) {
			return i
		}
		i += l
	}
	return -1
}

// TCPTimestamps extracts the RFC 7323 timestamp option (kind 8, len 10) from a
// TCP option block. ok is false when the option is absent or the block is
// malformed.
func TCPTimestamps(opts []byte) (tsval, tsecho uint32, ok bool) {
	i := tcpOptFind(opts, tcpOptKindTS, tcpOptLenTS)
	if i < 0 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(opts[i+2 : i+6]), binary.BigEndian.Uint32(opts[i+6 : i+10]), true
}

// SetTCPTimestamps returns a copy of opts with the timestamp option's TSval and
// TSecr replaced (--dpi-desync-fooling=ts). opts is never modified; when there
// is no timestamp option to patch, opts itself is returned unchanged.
func SetTCPTimestamps(opts []byte, tsval, tsecho uint32) []byte {
	i := tcpOptFind(opts, tcpOptKindTS, tcpOptLenTS)
	if i < 0 {
		return opts
	}
	out := make([]byte, len(opts))
	copy(out, opts)
	binary.BigEndian.PutUint32(out[i+2:i+6], tsval)
	binary.BigEndian.PutUint32(out[i+6:i+10], tsecho)
	return out
}
