package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// mustAddr parses an address or fails the test.
func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

// fakeBlob loads one of the real payload vectors from fakes/.
func fakeBlob(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fakes", name))
	if err != nil {
		t.Skipf("test vector %s unavailable: %v", name, err)
	}
	if len(b) == 0 {
		t.Fatalf("test vector %s is empty", name)
	}
	return b
}

// checkV4HeaderChecksum verifies that summing the header (checksum included)
// yields zero, the standard receiver-side check.
func checkV4HeaderChecksum(t *testing.T, pkt []byte) {
	t.Helper()
	ihl := int(pkt[0]&0x0f) * 4
	if got := Checksum16(pkt[:ihl]); got != 0 {
		t.Errorf("ipv4 header checksum verification = %#04x, want 0", got)
	}
}

// checkL4Checksum recomputes the stored L4 checksum and compares it.
func checkL4Checksum(t *testing.T, p *Pkt) {
	t.Helper()
	l4 := make([]byte, len(p.Raw)-p.L3Len)
	copy(l4, p.Raw[p.L3Len:])
	off := tcpChecksumOff
	if p.IsUDP() {
		off = udpChecksumOff
	}
	stored := binary.BigEndian.Uint16(l4[off : off+2])
	binary.BigEndian.PutUint16(l4[off:off+2], 0)
	want := L4Checksum(p.Src, p.Dst, p.Proto, l4)
	if stored != want {
		t.Errorf("L4 checksum = %#04x, want %#04x", stored, want)
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	hello := fakeBlob(t, "tls_clienthello_www_google_com.bin")
	quic := fakeBlob(t, "quic_initial_www_google_com.bin")

	tests := []struct {
		name string
		tmpl Tmpl
		// expectations after Marshal defaults are applied
		wantVer   uint8
		wantProto uint8
		wantFlags uint8
		wantTTL   uint8
		wantWin   uint16
		wantL4Len int
	}{
		{
			name: "tcp v4 defaults",
			tmpl: Tmpl{
				Src: mustAddr(t, "192.168.0.1"), Dst: mustAddr(t, "142.250.185.100"),
				SrcPort: 51000, DstPort: 443,
				Seq: 0x11223344, Ack: 0x55667788,
				Payload: hello,
			},
			wantVer: 4, wantProto: IPProtoTCP, wantFlags: TCPPsh | TCPAck,
			wantTTL: pktDefaultTTL, wantWin: pktDefaultWindow, wantL4Len: 20,
		},
		{
			name: "tcp v4 explicit flags ttl ipid df window",
			tmpl: Tmpl{
				Src: mustAddr(t, "10.0.0.2"), Dst: mustAddr(t, "1.1.1.1"),
				SrcPort: 1234, DstPort: 80,
				Seq: 1, Ack: 2, Flags: TCPSyn, TTL: 3, IPID: 0xbeef, DF: true, Window: 1000,
				Payload: []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"),
			},
			wantVer: 4, wantProto: IPProtoTCP, wantFlags: TCPSyn,
			wantTTL: 3, wantWin: 1000, wantL4Len: 20,
		},
		{
			name: "tcp v6 with verbatim options",
			tmpl: Tmpl{
				Src: mustAddr(t, "2a00:1450:4010:c0e::64"), Dst: mustAddr(t, "2606:4700:4700::1111"),
				SrcPort: 40000, DstPort: 443,
				Seq: 0xdeadbeef, Ack: 0x0badf00d,
				// NOP,NOP,TS(10) -> 12 bytes, already 4-byte aligned.
				TCPOpts: []byte{
					tcpOptKindNOP, tcpOptKindNOP, tcpOptKindTS, tcpOptLenTS,
					0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				},
				TTL:     55,
				Payload: hello,
			},
			wantVer: 6, wantProto: IPProtoTCP, wantFlags: TCPPsh | TCPAck,
			wantTTL: 55, wantWin: pktDefaultWindow, wantL4Len: 32,
		},
		{
			name: "udp v4 quic initial",
			tmpl: Tmpl{
				Src: mustAddr(t, "192.168.1.77"), Dst: mustAddr(t, "142.250.185.100"),
				SrcPort: 55555, DstPort: 443,
				UDP: true, TTL: 8, IPID: 0,
				Payload: quic,
			},
			wantVer: 4, wantProto: IPProtoUDP, wantTTL: 8, wantL4Len: udpHdrLen,
		},
		{
			name: "udp v6 empty payload",
			tmpl: Tmpl{
				Src: mustAddr(t, "fd00::1"), Dst: mustAddr(t, "fd00::2"),
				SrcPort: 1, DstPort: 65535, UDP: true,
			},
			wantVer: 6, wantProto: IPProtoUDP, wantTTL: pktDefaultTTL, wantL4Len: udpHdrLen,
		},
		{
			name: "tcp v4 noack clears ack bit",
			tmpl: Tmpl{
				Src: mustAddr(t, "172.16.0.5"), Dst: mustAddr(t, "93.184.216.34"),
				SrcPort: 9999, DstPort: 443, Seq: 7, Ack: 9, NoAck: true,
				Payload: []byte("x"),
			},
			wantVer: 4, wantProto: IPProtoTCP, wantFlags: TCPPsh,
			wantTTL: pktDefaultTTL, wantWin: pktDefaultWindow, wantL4Len: 20,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.tmpl.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			p, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if p.Ver != tc.wantVer {
				t.Errorf("Ver = %d, want %d", p.Ver, tc.wantVer)
			}
			if p.Proto != tc.wantProto {
				t.Errorf("Proto = %d, want %d", p.Proto, tc.wantProto)
			}
			if p.TTL != tc.wantTTL {
				t.Errorf("TTL = %d, want %d", p.TTL, tc.wantTTL)
			}
			if p.Src != tc.tmpl.Src.Unmap() || p.Dst != tc.tmpl.Dst.Unmap() {
				t.Errorf("addresses = %s -> %s, want %s -> %s", p.Src, p.Dst, tc.tmpl.Src, tc.tmpl.Dst)
			}
			if p.SrcPort != tc.tmpl.SrcPort || p.DstPort != tc.tmpl.DstPort {
				t.Errorf("ports = %d -> %d, want %d -> %d", p.SrcPort, p.DstPort, tc.tmpl.SrcPort, tc.tmpl.DstPort)
			}
			if p.L4Len != tc.wantL4Len {
				t.Errorf("L4Len = %d, want %d", p.L4Len, tc.wantL4Len)
			}
			wantL3 := ipv4MinHdrLen
			if tc.wantVer == 6 {
				wantL3 = ipv6FixedHdrLen
			}
			if p.L3Len != wantL3 {
				t.Errorf("L3Len = %d, want %d", p.L3Len, wantL3)
			}
			if !bytes.Equal(p.Payload(), tc.tmpl.Payload) {
				t.Errorf("payload round trip mismatch: %d bytes vs %d", len(p.Payload()), len(tc.tmpl.Payload))
			}
			if p.IsTCP() {
				if p.Flags != tc.wantFlags {
					t.Errorf("Flags = %#02x, want %#02x", p.Flags, tc.wantFlags)
				}
				if p.Seq != tc.tmpl.Seq || p.Ack != tc.tmpl.Ack {
					t.Errorf("seq/ack = %d/%d, want %d/%d", p.Seq, p.Ack, tc.tmpl.Seq, tc.tmpl.Ack)
				}
				if p.Window != tc.wantWin {
					t.Errorf("Window = %d, want %d", p.Window, tc.wantWin)
				}
				if len(tc.tmpl.TCPOpts) > 0 && !bytes.Equal(p.TCPOpts, tc.tmpl.TCPOpts) {
					t.Errorf("TCPOpts = %x, want %x", p.TCPOpts, tc.tmpl.TCPOpts)
				}
			}
			if tc.wantVer == 4 {
				checkV4HeaderChecksum(t, raw)
				if p.IPID != tc.tmpl.IPID {
					t.Errorf("IPID = %#04x, want %#04x", p.IPID, tc.tmpl.IPID)
				}
				if p.DF != tc.tmpl.DF {
					t.Errorf("DF = %v, want %v", p.DF, tc.tmpl.DF)
				}
			}
			checkL4Checksum(t, p)
		})
	}
}

func TestParseRestoresOffloadedIPLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		dst  string
		off  int
		base int
	}{
		{"ipv4", "192.0.2.1", "198.51.100.1", 2, 0},
		{"ipv6", "2001:db8::1", "2001:db8::2", 4, ipv6FixedHdrLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tm := &Tmpl{
				Src: mustAddr(t, tc.src), Dst: mustAddr(t, tc.dst),
				SrcPort: 12345, DstPort: 443, Flags: TCPSyn,
			}
			raw, err := tm.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			binary.BigEndian.PutUint16(raw[tc.off:tc.off+2], 0)
			if _, err := Parse(raw); err != nil {
				t.Fatal(err)
			}
			if got, want := int(binary.BigEndian.Uint16(raw[tc.off:tc.off+2])), len(raw)-tc.base; got != want {
				t.Fatalf("restored IP length = %d, want %d", got, want)
			}
		})
	}
}

func TestMarshalErrors(t *testing.T) {
	tests := []struct {
		name string
		tmpl Tmpl
	}{
		{"no addresses", Tmpl{SrcPort: 1, DstPort: 2}},
		{"mixed families", Tmpl{Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "fd00::1")}},
		{"options too long", Tmpl{
			Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"),
			TCPOpts: bytes.Repeat([]byte{tcpOptKindNOP}, 44),
		}},
		{"md5sig pushes options over 40 bytes", Tmpl{
			Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"),
			TCPOpts: bytes.Repeat([]byte{tcpOptKindNOP}, 24), MD5Sig: true,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.tmpl.Marshal(); err == nil {
				t.Fatal("Marshal succeeded, want error")
			}
		})
	}
}

func TestChecksum16Vectors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		{
			// RFC 1071 section 3 worked example.
			name: "rfc1071",
			data: []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7},
			want: 0x220d,
		},
		{
			// Textbook IPv4 header, checksum field zeroed. Hand sum:
			// 4500+0073+0000+4000+4011+0000+c0a8+0001+c0a8+00c7 = 0x479e -> ^ = 0xb861
			name: "ipv4 header",
			data: []byte{
				0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
				0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
				0xc0, 0xa8, 0x00, 0xc7,
			},
			want: 0xb861,
		},
		{
			// Odd length: the trailing byte counts as the high half of a word.
			// 0x0102 + 0x0300 = 0x0402 -> ^ = 0xfbfd
			name: "odd length",
			data: []byte{0x01, 0x02, 0x03},
			want: 0xfbfd,
		},
		{
			name: "empty",
			data: nil,
			want: 0xffff,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Checksum16(tc.data); got != tc.want {
				t.Errorf("Checksum16 = %#04x, want %#04x", got, tc.want)
			}
		})
	}
}

func TestL4ChecksumVectors(t *testing.T) {
	// Hand-computed UDP checksum, 192.168.0.1 -> 192.168.0.199, ports
	// 0x1234 -> 0x5678, payload "abcd":
	//   pseudo: c0a8+0001+c0a8+00c7+0011+000c = 0x8236
	//   udp:    1234+5678+000c+0000+6162+6364
	//   total folded = 0xafb5 -> ^ = 0x504a
	udp := []byte{0x12, 0x34, 0x56, 0x78, 0x00, 0x0c, 0x00, 0x00, 'a', 'b', 'c', 'd'}
	got := L4Checksum(mustAddr(t, "192.168.0.1"), mustAddr(t, "192.168.0.199"), IPProtoUDP, udp)
	if got != 0x504a {
		t.Errorf("v4 udp L4Checksum = %#04x, want %#04x", got, 0x504a)
	}

	// Inserting the checksum must make the whole thing verify to zero.
	withSum := append([]byte(nil), udp...)
	binary.BigEndian.PutUint16(withSum[6:8], got)
	var acc uint32
	s, d := mustAddr(t, "192.168.0.1").As4(), mustAddr(t, "192.168.0.199").As4()
	acc = sum16(acc, s[:])
	acc = sum16(acc, d[:])
	acc += uint32(IPProtoUDP) + uint32(len(withSum))
	acc = sum16(acc, withSum)
	if v := ^fold32(acc); v != 0 {
		t.Errorf("verification sum = %#04x, want 0", v)
	}

	// A computed zero must be reported as 0xffff so UDP never claims "no
	// checksum". With a 0.0.0.0 -> 0.0.0.0 pseudo-header the sum is
	// proto(0x11) + length(0x08) = 0x19, so the L4 words have to add up to
	// 0xffff - 0x19 = 0xffe6: 0xffde (ports) + 0x0008 (length field).
	zeroAddr := netip.AddrFrom4([4]byte{0, 0, 0, 0})
	l4 := []byte{0xff, 0xde, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00}
	if v := L4Checksum(zeroAddr, zeroAddr, IPProtoUDP, l4); v != 0xffff {
		t.Errorf("computed-zero UDP checksum = %#04x, want 0xffff", v)
	}

	// IPv6 pseudo-header: the value must differ from the v4 one for the same
	// L4 bytes, and inserting it must verify to zero.
	v6a, v6b := mustAddr(t, "fd00::1"), mustAddr(t, "fd00::2")
	sum6 := L4Checksum(v6a, v6b, IPProtoUDP, udp)
	if sum6 == got {
		t.Errorf("v6 checksum %#04x equals the v4 one, pseudo-header ignored?", sum6)
	}
	with6 := append([]byte(nil), udp...)
	binary.BigEndian.PutUint16(with6[6:8], sum6)
	if v := L4Checksum(v6a, v6b, IPProtoUDP, with6); v != 0xffff {
		// Re-checksumming a buffer that already carries its checksum yields
		// the ones'-complement zero, reported as 0xffff for UDP.
		t.Errorf("v6 re-checksum = %#04x, want 0xffff", v)
	}
}

func TestMarshalMD5Sig(t *testing.T) {
	tests := []struct {
		name        string
		opts        []byte
		wantHdrLen  int // TCP header length including options
		wantOptsLen int
	}{
		{"no extra options", nil, 40, 20},
		{"4 aligned option bytes", []byte{tcpOptKindNOP, tcpOptKindNOP, tcpOptKindNOP, tcpOptKindNOP}, 44, 24},
		{"2 option bytes need no padding", []byte{tcpOptKindNOP, tcpOptKindNOP}, 40, 20},
		{"3 option bytes need 3 pad bytes", []byte{tcpOptKindNOP, tcpOptKindNOP, tcpOptKindNOP}, 44, 24},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tm := Tmpl{
				Src: mustAddr(t, "10.1.2.3"), Dst: mustAddr(t, "10.4.5.6"),
				SrcPort: 1111, DstPort: 443, Seq: 5, Ack: 6,
				TCPOpts: tc.opts, MD5Sig: true, Payload: []byte("hello"),
			}
			raw, err := tm.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			p, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if p.L4Len != tc.wantHdrLen {
				t.Fatalf("tcp header length = %d, want %d", p.L4Len, tc.wantHdrLen)
			}
			if len(p.TCPOpts) != tc.wantOptsLen {
				t.Fatalf("option block = %d bytes, want %d", len(p.TCPOpts), tc.wantOptsLen)
			}
			if len(p.TCPOpts)%4 != 0 {
				t.Errorf("option block %d bytes is not 4-byte aligned", len(p.TCPOpts))
			}
			// The verbatim options come first, then kind 19 len 18.
			if !bytes.Equal(p.TCPOpts[:len(tc.opts)], tc.opts) {
				t.Errorf("verbatim options = %x, want %x", p.TCPOpts[:len(tc.opts)], tc.opts)
			}
			md5 := p.TCPOpts[len(tc.opts):]
			if md5[0] != tcpOptKindMD5 || md5[1] != tcpOptLenMD5 {
				t.Fatalf("md5 option header = %x, want %02x%02x", md5[:2], tcpOptKindMD5, tcpOptLenMD5)
			}
			if !bytes.Equal(md5[2:tcpOptLenMD5], md5SigFiller[:]) {
				t.Errorf("md5 signature = %x, want %x", md5[2:tcpOptLenMD5], md5SigFiller)
			}
			// Padding: NOPs then a single EOL, filling to the 4-byte boundary.
			pad := md5[tcpOptLenMD5:]
			for i, b := range pad {
				want := byte(tcpOptKindNOP)
				if i == len(pad)-1 {
					want = tcpOptKindEOL
				}
				if b != want {
					t.Errorf("pad[%d] = %d, want %d", i, b, want)
				}
			}
			// A walker must still find the timestamp option absent without
			// tripping over the appended md5 option.
			if _, _, ok := TCPTimestamps(p.TCPOpts); ok {
				t.Error("TCPTimestamps found a timestamp option that was never added")
			}
			if !bytes.Equal(p.Payload(), []byte("hello")) {
				t.Errorf("payload = %q, want %q", p.Payload(), "hello")
			}
			checkL4Checksum(t, p)
		})
	}
}

func TestMarshalBadSum(t *testing.T) {
	base := Tmpl{
		Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"),
		SrcPort: 1000, DstPort: 443, Seq: 1, Ack: 1, Payload: []byte("payload bytes"),
	}
	v6 := base
	v6.Src, v6.Dst = mustAddr(t, "fd00::1"), mustAddr(t, "fd00::2")
	udp := base
	udp.UDP = true
	udp6 := v6
	udp6.UDP = true

	for _, tc := range []struct {
		name string
		tmpl Tmpl
	}{
		{"tcp v4", base}, {"tcp v6", v6}, {"udp v4", udp}, {"udp v6", udp6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			good := tc.tmpl
			bad := tc.tmpl
			bad.BadSum = true

			gr, err := good.Marshal()
			if err != nil {
				t.Fatalf("Marshal good: %v", err)
			}
			br, err := bad.Marshal()
			if err != nil {
				t.Fatalf("Marshal bad: %v", err)
			}
			gp, err := Parse(gr)
			if err != nil {
				t.Fatalf("Parse good: %v", err)
			}
			bp, err := Parse(br)
			if err != nil {
				t.Fatalf("Parse bad: %v", err)
			}
			off := tcpChecksumOff
			if tc.tmpl.UDP {
				off = udpChecksumOff
			}
			gsum := binary.BigEndian.Uint16(gp.Raw[gp.L3Len+off : gp.L3Len+off+2])
			bsum := binary.BigEndian.Uint16(bp.Raw[bp.L3Len+off : bp.L3Len+off+2])
			if gsum == bsum {
				t.Errorf("BadSum produced the correct checksum %#04x", bsum)
			}
			if bsum == 0 {
				t.Error("BadSum produced a zero checksum, which UDP reads as 'no checksum'")
			}
			// Everything except the checksum must be byte-identical.
			gclean := append([]byte(nil), gr...)
			bclean := append([]byte(nil), br...)
			binary.BigEndian.PutUint16(gclean[gp.L3Len+off:], 0)
			binary.BigEndian.PutUint16(bclean[bp.L3Len+off:], 0)
			if !bytes.Equal(gclean, bclean) {
				t.Error("BadSum changed more than the checksum")
			}
			// And the good one must actually be right.
			checkL4Checksum(t, gp)
		})
	}
}

func TestCorruptSumNeverZero(t *testing.T) {
	for v := 0; v <= 0xffff; v++ {
		bad := corruptSum(uint16(v))
		if bad == 0 {
			t.Fatalf("corruptSum(%#04x) = 0", v)
		}
		if bad == uint16(v) {
			t.Fatalf("corruptSum(%#04x) returned the input unchanged", v)
		}
	}
}

func TestIPFragment(t *testing.T) {
	tm := Tmpl{
		Src: mustAddr(t, "192.0.2.10"), Dst: mustAddr(t, "198.51.100.20"),
		SrcPort: 12345, DstPort: 443, Seq: 100, Ack: 200,
		IPID: 0x4d2, DF: true, Payload: bytes.Repeat([]byte("0123456789"), 10),
	}
	raw, err := tm.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	l4len := len(raw) - ipv4MinHdrLen

	for _, pos := range []int{8, 24, 25, 31, l4len - 1} {
		t.Run(fmt.Sprintf("pos%d", pos), func(t *testing.T) {
			frags, err := IPFragment(raw, pos)
			if err != nil {
				t.Fatalf("IPFragment(%d): %v", pos, err)
			}
			if len(frags) != 2 {
				t.Fatalf("got %d fragments, want 2", len(frags))
			}
			want := pos &^ 7
			f1, f2 := frags[0], frags[1]

			if got := int(binary.BigEndian.Uint16(f1[2:4])); got != len(f1) || got != ipv4MinHdrLen+want {
				t.Errorf("fragment 1 total length = %d, buffer %d, want %d", got, len(f1), ipv4MinHdrLen+want)
			}
			if got := int(binary.BigEndian.Uint16(f2[2:4])); got != len(f2) || got != ipv4MinHdrLen+l4len-want {
				t.Errorf("fragment 2 total length = %d, buffer %d, want %d", got, len(f2), ipv4MinHdrLen+l4len-want)
			}
			ff1 := binary.BigEndian.Uint16(f1[6:8])
			ff2 := binary.BigEndian.Uint16(f2[6:8])
			if ff1&0x2000 == 0 {
				t.Error("fragment 1 has no MF bit")
			}
			if ff1&0x1fff != 0 {
				t.Errorf("fragment 1 offset = %d, want 0", ff1&0x1fff)
			}
			if ff2&0x2000 != 0 {
				t.Error("fragment 2 has the MF bit set")
			}
			if got := int(ff2&0x1fff) * 8; got != want {
				t.Errorf("fragment 2 offset = %d bytes, want %d", got, want)
			}
			if ff1&0x4000 != 0 || ff2&0x4000 != 0 {
				t.Error("DF survived fragmentation")
			}
			if id1, id2 := binary.BigEndian.Uint16(f1[4:6]), binary.BigEndian.Uint16(f2[4:6]); id1 != id2 || id1 != tm.IPID {
				t.Errorf("ip ids = %#04x/%#04x, want both %#04x", id1, id2, tm.IPID)
			}
			checkV4HeaderChecksum(t, f1)
			checkV4HeaderChecksum(t, f2)
			// Reassembly must reproduce the original L4 bytes exactly.
			joined := append(append([]byte(nil), f1[ipv4MinHdrLen:]...), f2[ipv4MinHdrLen:]...)
			if !bytes.Equal(joined, raw[ipv4MinHdrLen:]) {
				t.Error("reassembled L4 content differs from the original")
			}
		})
	}

	// Fragmenting an existing fragment keeps the base offset and the MF bit.
	frags, err := IPFragment(raw, 32)
	if err != nil {
		t.Fatalf("IPFragment: %v", err)
	}
	sub, err := IPFragment(frags[1], 16)
	if err != nil {
		t.Fatalf("IPFragment of a fragment: %v", err)
	}
	base := int(binary.BigEndian.Uint16(frags[1][6:8]) & 0x1fff)
	if got := int(binary.BigEndian.Uint16(sub[0][6:8]) & 0x1fff); got != base {
		t.Errorf("sub-fragment 1 offset = %d, want %d", got, base)
	}
	if got := int(binary.BigEndian.Uint16(sub[1][6:8]) & 0x1fff); got != base+2 {
		t.Errorf("sub-fragment 2 offset = %d, want %d", got, base+2)
	}
	if binary.BigEndian.Uint16(sub[1][6:8])&0x2000 != 0 {
		t.Error("last sub-fragment must not set MF")
	}
	if binary.BigEndian.Uint16(sub[0][6:8])&0x2000 == 0 {
		t.Error("first sub-fragment must set MF")
	}
}

func TestIPFragmentErrors(t *testing.T) {
	v4 := Tmpl{Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"), SrcPort: 1, DstPort: 2}
	small, err := v4.Marshal() // 20 byte TCP header, no payload
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	v6 := Tmpl{Src: mustAddr(t, "fd00::1"), Dst: mustAddr(t, "fd00::2"), SrcPort: 1, DstPort: 2, Payload: bytes.Repeat([]byte{7}, 64)}
	raw6, err := v6.Marshal()
	if err != nil {
		t.Fatalf("Marshal v6: %v", err)
	}
	// A bare UDP datagram has 8 L4 bytes, so no legal split position exists.
	tinyTmpl := Tmpl{Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"), SrcPort: 1, DstPort: 2, UDP: true}
	tiny, err := tinyTmpl.Marshal()
	if err != nil {
		t.Fatalf("Marshal tiny: %v", err)
	}

	tests := []struct {
		name string
		pkt  []byte
		pos  int
	}{
		{"ipv6 rejected", raw6, 16},
		{"empty", nil, 8},
		{"pos zero", small, 0},
		{"pos negative", small, -16},
		{"pos below 8 rounds to 0", small, 7},
		{"pos beyond payload", small, 64},
		{"pos at payload end", small, 24},
		{"nothing to split", tiny, 8},
		{"nothing to split high pos", tiny, 64},
		{"truncated header", small[:12], 8},
		{"total length lies", func() []byte {
			b := append([]byte(nil), small...)
			binary.BigEndian.PutUint16(b[2:4], 4000)
			return b
		}(), 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := IPFragment(tc.pkt, tc.pos); err == nil {
				t.Fatal("IPFragment succeeded, want error")
			}
		})
	}
}

func TestAddIPv6ExtHdr(t *testing.T) {
	tm := Tmpl{
		Src: mustAddr(t, "2001:db8::1"), Dst: mustAddr(t, "2001:db8::2"),
		SrcPort: 30000, DstPort: 443, Seq: 42, Ack: 43,
		Payload: []byte("hello ipv6 extension headers"),
	}
	raw, err := tm.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	origPayloadLen := int(binary.BigEndian.Uint16(raw[4:6]))

	tests := []struct {
		name  string
		count int
		kind  uint8
	}{
		{"hopbyhop", 1, IPProtoHopOpt},
		{"hopbyhop2", 2, IPProtoHopOpt},
		{"dstopts", 1, IPProtoDstOpt},
		{"dstopts x3", 3, IPProtoDstOpt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := AddIPv6ExtHdr(raw, tc.count, tc.kind)
			if err != nil {
				t.Fatalf("AddIPv6ExtHdr: %v", err)
			}
			if len(out) != len(raw)+8*tc.count {
				t.Fatalf("length = %d, want %d", len(out), len(raw)+8*tc.count)
			}
			if got := int(binary.BigEndian.Uint16(out[4:6])); got != origPayloadLen+8*tc.count {
				t.Errorf("payload length = %d, want %d", got, origPayloadLen+8*tc.count)
			}
			if out[6] != tc.kind {
				t.Errorf("fixed header next = %d, want %d", out[6], tc.kind)
			}
			for i := 0; i < tc.count; i++ {
				off := ipv6FixedHdrLen + i*8
				wantNext := tc.kind
				if i == tc.count-1 {
					wantNext = IPProtoTCP
				}
				if out[off] != wantNext {
					t.Errorf("ext header %d next = %d, want %d", i, out[off], wantNext)
				}
				if out[off+1] != 0 {
					t.Errorf("ext header %d HdrExtLen = %d, want 0", i, out[off+1])
				}
				if !bytes.Equal(out[off+2:off+8], ipv6EmptyExtHdr[:]) {
					t.Errorf("ext header %d body = %x, want %x", i, out[off+2:off+8], ipv6EmptyExtHdr)
				}
			}
			// The input must be untouched.
			if binary.BigEndian.Uint16(raw[4:6]) != uint16(origPayloadLen) || raw[6] != IPProtoTCP {
				t.Error("AddIPv6ExtHdr modified its input")
			}

			// Parse must walk the whole chain and still see the TCP header.
			p, err := Parse(out)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if p.Proto != IPProtoTCP {
				t.Errorf("Proto = %d, want TCP", p.Proto)
			}
			if p.L3Len != ipv6FixedHdrLen+8*tc.count {
				t.Errorf("L3Len = %d, want %d", p.L3Len, ipv6FixedHdrLen+8*tc.count)
			}
			if p.DstPort != tm.DstPort || p.Seq != tm.Seq {
				t.Errorf("L4 fields after ext headers: port %d seq %d, want %d %d", p.DstPort, p.Seq, tm.DstPort, tm.Seq)
			}
			if !bytes.Equal(p.Payload(), tm.Payload) {
				t.Errorf("payload = %q, want %q", p.Payload(), tm.Payload)
			}
			// Extension headers do not change the pseudo-header, so the L4
			// checksum stays valid.
			checkL4Checksum(t, p)
		})
	}

	t.Run("count zero copies", func(t *testing.T) {
		out, err := AddIPv6ExtHdr(raw, 0, IPProtoHopOpt)
		if err != nil {
			t.Fatalf("AddIPv6ExtHdr: %v", err)
		}
		if !bytes.Equal(out, raw) {
			t.Error("count 0 must return an unchanged copy")
		}
		if &out[0] == &raw[0] {
			t.Error("count 0 must return a copy, not the input buffer")
		}
	})

	t.Run("errors", func(t *testing.T) {
		v4 := Tmpl{Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"), SrcPort: 1, DstPort: 2}
		raw4, err := v4.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		for _, tc := range []struct {
			name  string
			pkt   []byte
			count int
			kind  uint8
		}{
			{"ipv4 input", raw4, 1, IPProtoHopOpt},
			{"short input", raw[:20], 1, IPProtoHopOpt},
			{"bad kind", raw, 1, IPProtoTCP},
			{"routing kind", raw, 1, ipProtoRouting},
			{"negative count", raw, -1, IPProtoHopOpt},
		} {
			if _, err := AddIPv6ExtHdr(tc.pkt, tc.count, tc.kind); err == nil {
				t.Errorf("%s: AddIPv6ExtHdr succeeded, want error", tc.name)
			}
		}
	})
}

func TestParseIPv6ExtHdrChainAndFragments(t *testing.T) {
	// Hand-built chain: fixed header -> hop-by-hop -> routing -> dst opts -> UDP.
	body := []byte{0x00, 0x35, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 'd', 'n', 's', '!'}
	chain := []struct {
		kind uint8
		next uint8
	}{
		{IPProtoHopOpt, ipProtoRouting},
		{ipProtoRouting, IPProtoDstOpt},
		{IPProtoDstOpt, IPProtoUDP},
	}
	pkt := make([]byte, ipv6FixedHdrLen)
	pkt[0] = 0x60
	pkt[6] = IPProtoHopOpt
	pkt[7] = 64
	copy(pkt[8:24], netip.MustParseAddr("fd00::1").AsSlice())
	copy(pkt[24:40], netip.MustParseAddr("fd00::2").AsSlice())
	for _, c := range chain {
		hdr := make([]byte, 8)
		hdr[0] = c.next
		hdr[1] = 0
		copy(hdr[2:], ipv6EmptyExtHdr[:])
		pkt = append(pkt, hdr...)
	}
	pkt = append(pkt, body...)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-ipv6FixedHdrLen))

	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Proto != IPProtoUDP {
		t.Errorf("Proto = %d, want UDP", p.Proto)
	}
	if p.L3Len != ipv6FixedHdrLen+3*8 {
		t.Errorf("L3Len = %d, want %d", p.L3Len, ipv6FixedHdrLen+24)
	}
	if p.SrcPort != 53 || p.DstPort != 53 {
		t.Errorf("ports = %d/%d, want 53/53", p.SrcPort, p.DstPort)
	}
	if !bytes.Equal(p.Payload(), []byte("dns!")) {
		t.Errorf("payload = %q, want %q", p.Payload(), "dns!")
	}
	if p.TTL != 64 || !p.DF {
		t.Errorf("TTL = %d, DF = %v, want 64/true", p.TTL, p.DF)
	}

	// A fragment header with offset 0 is the first fragment and still parses.
	first := make([]byte, ipv6FixedHdrLen)
	copy(first, pkt[:ipv6FixedHdrLen])
	first[6] = IPProtoFrag
	fragHdr := []byte{IPProtoUDP, 0, 0x00, 0x01 /* offset 0, M=1 */, 0xaa, 0xbb, 0xcc, 0xdd}
	first = append(first, fragHdr...)
	first = append(first, body...)
	binary.BigEndian.PutUint16(first[4:6], uint16(len(first)-ipv6FixedHdrLen))
	fp, err := Parse(first)
	if err != nil {
		t.Fatalf("Parse first fragment: %v", err)
	}
	if fp.L3Len != ipv6FixedHdrLen+8 || fp.Proto != IPProtoUDP || fp.SrcPort != 53 {
		t.Errorf("first fragment: L3Len %d proto %d sport %d", fp.L3Len, fp.Proto, fp.SrcPort)
	}

	// A non-initial fragment has no L4 header and must be rejected.
	later := append([]byte(nil), first...)
	binary.BigEndian.PutUint16(later[ipv6FixedHdrLen+2:], 0x0008) // offset 1 unit
	if _, err := Parse(later); !errors.Is(err, ErrIPFragment) {
		t.Errorf("non-initial v6 fragment: err = %v, want ErrIPFragment", err)
	}

	// An endless chain of zero-progress headers must be bounded, not hang.
	loop := make([]byte, ipv6FixedHdrLen)
	copy(loop, pkt[:ipv6FixedHdrLen])
	loop[6] = IPProtoDstOpt
	for i := 0; i < maxV6ExtHdrs+4; i++ {
		hdr := make([]byte, 8)
		hdr[0] = IPProtoDstOpt
		copy(hdr[2:], ipv6EmptyExtHdr[:])
		loop = append(loop, hdr...)
	}
	binary.BigEndian.PutUint16(loop[4:6], uint16(len(loop)-ipv6FixedHdrLen))
	if _, err := Parse(loop); err == nil {
		t.Error("an over-long extension header chain must be rejected")
	}
}

func TestParseIPv4Fragments(t *testing.T) {
	tm := Tmpl{
		Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"),
		SrcPort: 1, DstPort: 443, Payload: bytes.Repeat([]byte{9}, 64),
	}
	raw, err := tm.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	frags, err := IPFragment(raw, 24)
	if err != nil {
		t.Fatalf("IPFragment: %v", err)
	}
	// The first fragment carries the L4 header, so it parses.
	if p, err := Parse(frags[0]); err != nil {
		t.Errorf("Parse first fragment: %v", err)
	} else if p.DstPort != 443 {
		t.Errorf("first fragment dst port = %d, want 443", p.DstPort)
	}
	// The second has no L4 header at all.
	if _, err := Parse(frags[1]); !errors.Is(err, ErrIPFragment) {
		t.Errorf("Parse second fragment: err = %v, want ErrIPFragment", err)
	}
}

func TestParseTruncatedAndHostile(t *testing.T) {
	hello := fakeBlob(t, "tls_clienthello_max_ru.bin")
	tmpls := []Tmpl{
		{Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"), SrcPort: 1, DstPort: 443,
			TCPOpts: []byte{tcpOptKindNOP, tcpOptKindNOP, tcpOptKindTS, tcpOptLenTS, 1, 2, 3, 4, 5, 6, 7, 8},
			Payload: hello},
		{Src: mustAddr(t, "fd00::1"), Dst: mustAddr(t, "fd00::2"), SrcPort: 2, DstPort: 443, Payload: hello},
		{Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"), SrcPort: 3, DstPort: 443, UDP: true, Payload: hello},
		{Src: mustAddr(t, "fd00::1"), Dst: mustAddr(t, "fd00::2"), SrcPort: 4, DstPort: 443, UDP: true, Payload: hello},
	}
	for i, tm := range tmpls {
		raw, err := tm.Marshal()
		if err != nil {
			t.Fatalf("Marshal %d: %v", i, err)
		}
		// Every strict prefix is truncated: the declared length no longer fits.
		for n := 0; n < len(raw); n++ {
			p, err := Parse(raw[:n])
			if err == nil {
				t.Fatalf("template %d prefix %d: Parse succeeded (L3Len %d), want error", i, n, p.L3Len)
			}
		}
		if _, err := Parse(raw); err != nil {
			t.Fatalf("template %d: full packet failed to parse: %v", i, err)
		}
	}

	// Random and mutated buffers must never panic.
	rnd := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		b := make([]byte, rnd.IntN(80))
		for j := range b {
			b[j] = byte(rnd.UintN(256))
		}
		Parse(b) //nolint:errcheck // only checking that it cannot panic
	}
	base, err := tmpls[0].Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), base...)
		for k := 0; k < 4; k++ {
			b[rnd.IntN(len(b))] = byte(rnd.UintN(256))
		}
		if rnd.IntN(2) == 0 {
			b = b[:rnd.IntN(len(b)+1)]
		}
		if p, err := Parse(b); err == nil {
			_ = p.Payload()
			_, _, _ = TCPTimestamps(p.TCPOpts)
			_ = SetTCPTimestamps(p.TCPOpts, 1, 2)
			_, _ = IPFragment(p.Raw, 16)
			_, _ = AddIPv6ExtHdr(p.Raw, 2, IPProtoHopOpt)
		}
	}
}

func TestParseMalformedHeaders(t *testing.T) {
	good := Tmpl{Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"), SrcPort: 1, DstPort: 443, Payload: []byte("abc")}
	raw, err := good.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	mutate := func(f func([]byte)) []byte {
		b := append([]byte(nil), raw...)
		f(b)
		return b
	}

	tests := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"version 5", mutate(func(b []byte) { b[0] = 0x54 }), ErrIPVersion},
		{"ihl 4", mutate(func(b []byte) { b[0] = 0x41 }), ErrMalformedHeader},
		{"total length below ihl", mutate(func(b []byte) { binary.BigEndian.PutUint16(b[2:4], 8) }), ErrMalformedHeader},
		{"total length past buffer", mutate(func(b []byte) { binary.BigEndian.PutUint16(b[2:4], 9000) }), ErrTruncated},
		{"fragment offset set", mutate(func(b []byte) { binary.BigEndian.PutUint16(b[6:8], 0x0001) }), ErrIPFragment},
		{"tcp data offset 4", mutate(func(b []byte) { b[ipv4MinHdrLen+12] = 0x10 }), ErrMalformedHeader},
		{"tcp data offset past packet", mutate(func(b []byte) { b[ipv4MinHdrLen+12] = 0xf0 }), ErrTruncated},
		{"empty", nil, ErrTruncated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.pkt)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// Ethernet padding beyond the declared total length must be trimmed away.
	padded := append(append([]byte(nil), raw...), bytes.Repeat([]byte{0xff}, 24)...)
	p, err := Parse(padded)
	if err != nil {
		t.Fatalf("Parse padded: %v", err)
	}
	if !bytes.Equal(p.Payload(), []byte("abc")) {
		t.Errorf("padded payload = %q, want %q", p.Payload(), "abc")
	}

	// UDP length shorter than the buffer also trims (the IP layer may lie in
	// the other direction on offloaded paths).
	udp := Tmpl{Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"), SrcPort: 1, DstPort: 443, UDP: true, Payload: []byte("12345678")}
	uraw, err := udp.Marshal()
	if err != nil {
		t.Fatalf("Marshal udp: %v", err)
	}
	binary.BigEndian.PutUint16(uraw[ipv4MinHdrLen+4:], udpHdrLen+4)
	up, err := Parse(uraw)
	if err != nil {
		t.Fatalf("Parse udp: %v", err)
	}
	if !bytes.Equal(up.Payload(), []byte("1234")) {
		t.Errorf("udp payload = %q, want %q", up.Payload(), "1234")
	}

	// A non-TCP/UDP protocol parses as L3 only.
	icmp := mutate(func(b []byte) {
		b[9] = IPProtoICMP
		binary.BigEndian.PutUint16(b[10:12], 0)
		binary.BigEndian.PutUint16(b[10:12], Checksum16(b[:ipv4MinHdrLen]))
	})
	ip, err := Parse(icmp)
	if err != nil {
		t.Fatalf("Parse icmp: %v", err)
	}
	if ip.Proto != IPProtoICMP || ip.L4Len != 0 || ip.SrcPort != 0 {
		t.Errorf("icmp: proto %d L4Len %d sport %d", ip.Proto, ip.L4Len, ip.SrcPort)
	}
	if len(ip.Payload()) != len(icmp)-ipv4MinHdrLen {
		t.Errorf("icmp payload = %d bytes, want %d", len(ip.Payload()), len(icmp)-ipv4MinHdrLen)
	}
}

func TestTCPTimestamps(t *testing.T) {
	tests := []struct {
		name       string
		opts       []byte
		wantOK     bool
		wantVal    uint32
		wantEcho   uint32
		setChanges bool
	}{
		{
			name: "nop nop ts",
			opts: []byte{tcpOptKindNOP, tcpOptKindNOP, tcpOptKindTS, tcpOptLenTS,
				0x00, 0x00, 0x10, 0x00, 0xde, 0xad, 0xbe, 0xef},
			wantOK: true, wantVal: 0x1000, wantEcho: 0xdeadbeef, setChanges: true,
		},
		{
			name: "mss sackok ts wscale",
			opts: []byte{
				2, 4, 0x05, 0xb4, // MSS 1460
				4, 2, // SACK permitted
				tcpOptKindTS, tcpOptLenTS, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				tcpOptKindNOP, 3, 3, 7, // window scale
			},
			wantOK: true, wantVal: 0x01020304, wantEcho: 0x05060708, setChanges: true,
		},
		{"empty", nil, false, 0, 0, false},
		{"no ts", []byte{2, 4, 0x05, 0xb4, tcpOptKindEOL, 0, 0, 0}, false, 0, 0, false},
		{"ts after eol is invisible", []byte{tcpOptKindEOL, tcpOptKindTS, tcpOptLenTS, 1, 2, 3, 4, 5, 6, 7, 8, 9}, false, 0, 0, false},
		{"ts with wrong length", []byte{tcpOptKindTS, 6, 1, 2, 3, 4}, false, 0, 0, false},
		{"truncated ts", []byte{tcpOptKindNOP, tcpOptKindTS, tcpOptLenTS, 1, 2, 3}, false, 0, 0, false},
		{"zero length option", []byte{5, 0, 1, 2}, false, 0, 0, false},
		{"length past end", []byte{2, 40, 1, 2}, false, 0, 0, false},
		{"kind without length", []byte{tcpOptKindTS}, false, 0, 0, false},
		{"all nops", bytes.Repeat([]byte{tcpOptKindNOP}, 40), false, 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := append([]byte(nil), tc.opts...)
			val, echo, ok := TCPTimestamps(tc.opts)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && (val != tc.wantVal || echo != tc.wantEcho) {
				t.Fatalf("tsval/tsecho = %#08x/%#08x, want %#08x/%#08x", val, echo, tc.wantVal, tc.wantEcho)
			}

			out := SetTCPTimestamps(tc.opts, 0xcafebabe, 0x8badf00d)
			if !bytes.Equal(tc.opts, orig) {
				t.Error("SetTCPTimestamps modified its input")
			}
			if !tc.setChanges {
				if len(tc.opts) == 0 {
					if len(out) != 0 {
						t.Errorf("out = %x, want empty", out)
					}
				} else if &out[0] != &tc.opts[0] {
					t.Error("with no timestamp option, opts must be returned unchanged")
				}
				return
			}
			if len(out) != len(tc.opts) {
				t.Fatalf("length changed: %d -> %d", len(tc.opts), len(out))
			}
			nval, necho, nok := TCPTimestamps(out)
			if !nok || nval != 0xcafebabe || necho != 0x8badf00d {
				t.Fatalf("after Set: %#08x/%#08x ok=%v", nval, necho, nok)
			}
			// Everything but the eight timestamp bytes must be identical.
			diff := 0
			for i := range out {
				if out[i] != tc.opts[i] {
					diff++
				}
			}
			if diff > 8 {
				t.Errorf("%d bytes changed, want at most 8", diff)
			}
		})
	}
}

func TestHostOrderIPHeaderInPlace(t *testing.T) {
	tm := Tmpl{
		Src: mustAddr(t, "10.0.0.1"), Dst: mustAddr(t, "10.0.0.2"),
		SrcPort: 1, DstPort: 443, DF: true, IPID: 0x1234, Payload: []byte("0123456789"),
	}
	raw, err := tm.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wantTotal := binary.BigEndian.Uint16(raw[2:4])
	wantFrag := binary.BigEndian.Uint16(raw[6:8])
	sum := binary.BigEndian.Uint16(raw[10:12])

	host := append([]byte(nil), raw...)
	HostOrderIPHeaderInPlace(host)
	if got := binary.NativeEndian.Uint16(host[2:4]); got != wantTotal {
		t.Errorf("host-order total length = %d, want %d", got, wantTotal)
	}
	if got := binary.NativeEndian.Uint16(host[6:8]); got != wantFrag {
		t.Errorf("host-order frag field = %#04x, want %#04x", got, wantFrag)
	}
	if got := binary.BigEndian.Uint16(host[10:12]); got != sum {
		t.Error("the header checksum must stay in wire order")
	}
	if !bytes.Equal(host[12:], raw[12:]) || !bytes.Equal(host[0:2], raw[0:2]) {
		t.Error("HostOrderIPHeaderInPlace touched fields outside ip_len/ip_off")
	}
	// The conversion is its own inverse, so applying it twice restores the wire
	// form on any endianness.
	HostOrderIPHeaderInPlace(host)
	if !bytes.Equal(host, raw) {
		t.Error("applying the conversion twice did not restore the original")
	}

	// IPv6 and short buffers are no-ops.
	v6 := Tmpl{Src: mustAddr(t, "fd00::1"), Dst: mustAddr(t, "fd00::2"), SrcPort: 1, DstPort: 2}
	raw6, err := v6.Marshal()
	if err != nil {
		t.Fatalf("Marshal v6: %v", err)
	}
	copy6 := append([]byte(nil), raw6...)
	HostOrderIPHeaderInPlace(copy6)
	if !bytes.Equal(copy6, raw6) {
		t.Error("HostOrderIPHeaderInPlace modified an IPv6 packet")
	}
	short := []byte{0x45, 0, 0, 20}
	HostOrderIPHeaderInPlace(short)
	if !bytes.Equal(short, []byte{0x45, 0, 0, 20}) {
		t.Error("HostOrderIPHeaderInPlace modified a too-short buffer")
	}
	HostOrderIPHeaderInPlace(nil)
}

func TestMarshalRealFakePayloads(t *testing.T) {
	for _, name := range []string{
		"tls_clienthello_www_google_com.bin",
		"tls_clienthello_4pda_to.bin",
		"tls_clienthello_max_ru.bin",
		"quic_initial_www_google_com.bin",
		"quic_initial_tencent_com.bin",
		"ACTIVE_DISCORD_UDP.bin",
		"ACTIVE_GAME_UDP.bin",
		"stun.bin",
		"stun2.bin",
	} {
		t.Run(name, func(t *testing.T) {
			blob := fakeBlob(t, name)
			for _, udp := range []bool{false, true} {
				tm := Tmpl{
					Src: mustAddr(t, "192.168.3.4"), Dst: mustAddr(t, "203.0.113.9"),
					SrcPort: 44444, DstPort: 443, Seq: 1000, Ack: 2000,
					TTL: 5, UDP: udp, Payload: blob,
				}
				raw, err := tm.Marshal()
				if err != nil {
					t.Fatalf("Marshal(udp=%v): %v", udp, err)
				}
				p, err := Parse(raw)
				if err != nil {
					t.Fatalf("Parse(udp=%v): %v", udp, err)
				}
				if !bytes.Equal(p.Payload(), blob) {
					t.Fatalf("payload round trip failed for udp=%v", udp)
				}
				checkV4HeaderChecksum(t, raw)
				checkL4Checksum(t, p)
				if !udp {
					// Splitting a real ClientHello mid-record is the fragment
					// case the desync ops actually use.
					frags, err := IPFragment(raw, tcpMinHdrLen+64)
					if err != nil {
						t.Fatalf("IPFragment: %v", err)
					}
					joined := append(append([]byte(nil), frags[0][ipv4MinHdrLen:]...), frags[1][ipv4MinHdrLen:]...)
					if !bytes.Equal(joined, raw[ipv4MinHdrLen:]) {
						t.Error("fragment reassembly mismatch")
					}
				}
			}
		})
	}
}
