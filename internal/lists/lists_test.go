package lists

import (
	"bufio"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------- helpers ----------

// repoList returns the path of one of the shipped list files and fails the test
// if it is missing: these are the real parity vectors.
func repoList(tb testing.TB, name string) string {
	tb.Helper()
	p := filepath.Join("..", "..", "lists", name)
	if _, err := os.Stat(p); err != nil {
		tb.Fatalf("missing test vector %s: %v", p, err)
	}
	return p
}

// writeFileAtomic writes content to path via a temp file and a rename, so a
// concurrent reader never observes a partial file.
func writeFileAtomic(tb testing.TB, path, content string) {
	tb.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		tb.Fatalf("write %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		tb.Fatalf("rename %s: %v", tmp, err)
	}
}

func tempList(tb testing.TB, name, content string) string {
	tb.Helper()
	p := filepath.Join(tb.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		tb.Fatalf("write %s: %v", p, err)
	}
	return p
}

func mustAddr(tb testing.TB, s string) netip.Addr {
	tb.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		tb.Fatalf("bad test address %q: %v", s, err)
	}
	return a
}

// ---------- HostSet ----------

func TestHostSetSuffixMatch(t *testing.T) {
	s := NewHostSet()
	for _, e := range []string{"discord.com", "cdn.example.net", "gd", "7tv.app"} {
		s.Add(e)
	}
	if got := s.Len(); got != 4 {
		t.Fatalf("Len = %d, want 4", got)
	}
	if s.Any {
		t.Fatal("Any set on a non-empty list")
	}

	tests := []struct {
		host string
		want bool
	}{
		{"discord.com", true},
		{"cdn.discord.com", true},
		{"a.b.c.discord.com", true},
		{"DISCORD.COM", true},
		{"Cdn.Discord.Com", true},
		{"discord.com.", true},   // trailing root dot
		{"discord.com...", true}, // several of them
		{" discord.com ", true},  // stray whitespace
		{"notdiscord.com", false},
		{"xdiscord.com", false},
		{"discord.com.evil.net", false}, // suffix rule, not substring
		{"discord.co", false},
		{"discord.comm", false},
		{"com", false},
		{"", false},
		{".", false},
		{"cdn.example.net", true},
		{"a.cdn.example.net", true},
		{"example.net", false}, // only the deeper entry was listed
		{"notcdn.example.net", false},
		{"dis.gd", true}, // bare TLD entry
		{"gd", true},
		{"disgd", false},
		{"7tv.app", true},
		{"static.7tv.app", true},
		{"n7tv.app", false},
	}
	for _, tc := range tests {
		if got := s.Match(tc.host); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestHostSetEntryNormalisation(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		matches []string
		misses  []string
		counted bool
	}{
		{"plain", "example.com", []string{"example.com", "a.example.com"}, []string{"notexample.com"}, true},
		{"wildcard", "*.example.org", []string{"example.org", "a.example.org"}, []string{"badexample.org"}, true},
		{"leading dot", ".example.io", []string{"example.io", "a.example.io"}, nil, true},
		{"trailing dot", "example.dev.", []string{"example.dev"}, nil, true},
		{"upper case", "ExAmPle.Net", []string{"example.net", "X.EXAMPLE.NET"}, nil, true},
		{"padded", "\texample.co \r", []string{"example.co"}, nil, true},
		{"inline comment", "example.gg # why not", []string{"example.gg"}, nil, true},
		{"comment line", "# example.zz", nil, []string{"example.zz"}, false},
		{"blank", "   ", nil, nil, false},
		{"junk with space", "two words.com", nil, []string{"two words.com"}, false},
		{"junk with slash", "http://example.ru/x", nil, []string{"example.ru"}, false},
		{"double dot", "a..b.com", nil, []string{"a..b.com", "b.com"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewHostSet()
			s.Add(tc.entry)
			want := 0
			if tc.counted {
				want = 1
			}
			if got := s.Len(); got != want {
				t.Fatalf("Len after Add(%q) = %d, want %d", tc.entry, got, want)
			}
			for _, h := range tc.matches {
				if !s.Match(h) {
					t.Errorf("Match(%q) = false, want true", h)
				}
			}
			for _, h := range tc.misses {
				if s.Match(h) {
					t.Errorf("Match(%q) = true, want false", h)
				}
			}
		})
	}
}

func TestHostSetDuplicateEntries(t *testing.T) {
	s := NewHostSet()
	s.Add("discord.com")
	s.Add("DISCORD.COM.")
	s.Add("*.discord.com")
	if got := s.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1 (duplicates collapse)", got)
	}
}

func TestHostSetLoadRealLists(t *testing.T) {
	general := repoList(t, "list-general.txt")
	exclude := repoList(t, "list-exclude.txt")

	gs := NewHostSet()
	if err := gs.LoadFile(general); err != nil {
		t.Fatalf("LoadFile(list-general.txt): %v", err)
	}
	if got := gs.Len(); got != 50 {
		t.Errorf("list-general.txt Len = %d, want 50", got)
	}
	if gs.Any {
		t.Error("list-general.txt must not be Any")
	}
	if len(gs.Files) != 1 || gs.Files[0] != general {
		t.Errorf("Files = %v, want [%s]", gs.Files, general)
	}
	for _, h := range []string{"discord.com", "cdn.discordapp.com", "media.discordapp.net", "7tv.io", "dis.gd", "CLOUDFRONT.NET"} {
		if !gs.Match(h) {
			t.Errorf("list-general: Match(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"notdiscord.com", "discord.com.evil.net", "example.com", "youtube.com"} {
		if gs.Match(h) {
			t.Errorf("list-general: Match(%q) = true, want false", h)
		}
	}

	es := NewHostSet()
	if err := es.LoadFile(exclude); err != nil {
		t.Fatalf("LoadFile(list-exclude.txt): %v", err)
	}
	if got := es.Len(); got != 126 {
		t.Errorf("list-exclude.txt Len = %d, want 126", got)
	}
	for _, h := range []string{"mail.ru", "www.yandex.ru", "twitch.tv", "ya.ru", "vkplay.ru", "vkplay.live", "userapi.com"} {
		if !es.Match(h) {
			t.Errorf("list-exclude: Match(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"discord.com", "notmail.ru"} {
		if es.Match(h) {
			t.Errorf("list-exclude: Match(%q) = true, want false", h)
		}
	}
}

func TestHostSetMergeFiles(t *testing.T) {
	s := NewHostSet()
	if err := s.LoadFile(repoList(t, "list-general.txt")); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadFile(repoList(t, "list-google.txt")); err != nil {
		t.Fatal(err)
	}
	if got := s.Len(); got != 50+20 {
		t.Errorf("merged Len = %d, want 70", got)
	}
	if !s.Match("discord.com") || !s.Match("youtube.com") || !s.Match("rr1.googlevideo.com") {
		t.Error("merged set lost entries from one of the files")
	}
	if len(s.Files) != 2 {
		t.Errorf("Files = %v, want 2 entries", s.Files)
	}
}

func TestHostSetEmptyFileMeansAny(t *testing.T) {
	for name, content := range map[string]string{
		"empty":         "",
		"only newlines": "\n\n\r\n",
		"only comments": "# nothing here\n#  either\n",
	} {
		t.Run(name, func(t *testing.T) {
			s := NewHostSet()
			if err := s.LoadFile(tempList(t, "list.txt", content)); err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			if !s.Any {
				t.Fatal("Any = false, want true for a list with no usable entries")
			}
			if got := s.Len(); got != 0 {
				t.Errorf("Len = %d, want 0", got)
			}
			for _, h := range []string{"discord.com", "anything.at.all", ""} {
				if !s.Match(h) {
					t.Errorf("Match(%q) = false, want true (Any)", h)
				}
			}
		})
	}
}

func TestHostSetLoadFileErrors(t *testing.T) {
	s := NewHostSet()
	if err := s.LoadFile(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("LoadFile of a missing file returned nil error")
	}
	if len(s.Files) != 0 {
		t.Errorf("failed load recorded Files = %v", s.Files)
	}
	if s.Any {
		t.Error("failed load set Any")
	}
}

func TestHostSetOversizedLineSkipped(t *testing.T) {
	huge := strings.Repeat("a", readBufSize+10) + ".com"
	s := NewHostSet()
	if err := s.LoadFile(tempList(t, "list.txt", huge+"\nexample.com\n")); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got := s.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1 (oversized line dropped)", got)
	}
	if !s.Match("example.com") {
		t.Error("entry after the oversized line was lost")
	}
	if s.Match(huge) {
		t.Error("oversized entry was kept")
	}
}

func TestHostSetReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	writeFileAtomic(t, path, "discord.com\nexample.com\n")

	s := NewHostSet()
	if err := s.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if got := s.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}

	writeFileAtomic(t, path, "# now different\nyoutube.com\n")
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := s.Len(); got != 1 {
		t.Errorf("Len after Reload = %d, want 1", got)
	}
	if !s.Match("www.youtube.com") {
		t.Error("Reload did not pick up the new entry")
	}
	if s.Match("discord.com") {
		t.Error("Reload kept a removed entry")
	}
	if len(s.Files) != 1 {
		t.Errorf("Files = %v, want 1 entry", s.Files)
	}

	// An unreadable file leaves the previous contents in place.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Error("Reload of a removed file returned nil error")
	}
	if !s.Match("youtube.com") {
		t.Error("failed Reload discarded the previous contents")
	}

	// A user override may vanish without breaking the reload.
	upath := filepath.Join(dir, "list-user.txt")
	writeFileAtomic(t, upath, "user.example\n")
	us := NewHostSet()
	if err := us.LoadFile(upath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(upath); err != nil {
		t.Fatal(err)
	}
	if err := us.Reload(); err != nil {
		t.Errorf("Reload of a missing -user.txt: %v", err)
	}
	if us.Len() != 0 || us.Match("user.example") {
		t.Error("missing -user.txt should reload to an empty set")
	}

	// A set with no files is left untouched.
	manual := NewHostSet()
	manual.Add("kept.example")
	if err := manual.Reload(); err != nil {
		t.Fatalf("Reload of a fileless set: %v", err)
	}
	if !manual.Match("kept.example") {
		t.Error("Reload of a fileless set dropped its entries")
	}
}

func TestHostSetMatchDoesNotAllocate(t *testing.T) {
	s := NewHostSet()
	if err := s.LoadFile(repoList(t, "list-general.txt")); err != nil {
		t.Fatal(err)
	}
	cases := []string{"cdn.discord.com", "CDN.DISCORD.COM", "some.unlisted.example.org"}
	for _, h := range cases {
		host := h
		allocs := testing.AllocsPerRun(200, func() {
			s.Match(host)
		})
		if allocs != 0 {
			t.Errorf("Match(%q) allocated %.1f objects per call, want 0", host, allocs)
		}
	}
}

// ---------- CIDRSet ----------

func TestCIDRSetAddMatch(t *testing.T) {
	s := NewCIDRSet()
	for _, p := range []string{"10.0.0.0/8", "192.168.1.0/24", "1.2.3.4/32", "2001:db8::/32", "2001:db8:1:2::5/128"} {
		s.Add(netip.MustParsePrefix(p))
	}
	if got := s.Len(); got != 5 {
		t.Fatalf("Len = %d, want 5", got)
	}
	if s.Any {
		t.Error("Any set on a non-empty set")
	}
	if s.IsNone() {
		t.Error("IsNone true for a normal set")
	}

	tests := []struct {
		addr string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"9.255.255.255", false},
		{"192.168.1.0", true},
		{"192.168.1.255", true},
		{"192.168.2.1", false},
		{"1.2.3.4", true},
		{"1.2.3.5", false},
		{"::ffff:10.0.0.7", true}, // 4-in-6 is unmapped before matching
		{"::ffff:11.0.0.7", false},
		{"2001:db8::1", true},
		{"2001:db8:ffff::1", true},
		{"2001:db9::1", false},
		{"2001:db8:1:2::5", true},
		{"2001:db8:1:2::6", true}, // covered by the enclosing /32
	}
	for _, tc := range tests {
		if got := s.Match(mustAddr(t, tc.addr)); got != tc.want {
			t.Errorf("Match(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	if s.Match(netip.Addr{}) {
		t.Error("Match(invalid addr) = true, want false")
	}
}

func TestCIDRSetHostBitsAndDuplicates(t *testing.T) {
	s := NewCIDRSet()
	s.Add(netip.MustParsePrefix("1.2.3.4/24")) // host bits set
	s.Add(netip.MustParsePrefix("1.2.3.0/24"))
	s.Add(netip.MustParsePrefix("1.2.3.99/24"))
	if got := s.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1 (host bits zeroed, duplicates collapsed)", got)
	}
	if !s.Match(mustAddr(t, "1.2.3.200")) {
		t.Error("Match inside the canonicalised prefix = false")
	}
	// A 4-in-6 prefix folds onto its IPv4 equivalent.
	s.Add(netip.MustParsePrefix("::ffff:5.6.7.0/120"))
	if !s.Match(mustAddr(t, "5.6.7.9")) {
		t.Error("4-in-6 prefix did not match the unmapped address")
	}
	if !s.Match(mustAddr(t, "::ffff:5.6.7.9")) {
		t.Error("4-in-6 prefix did not match the mapped address")
	}
}

func TestCIDRSetLoadFileForms(t *testing.T) {
	content := strings.Join([]string{
		"# comment",
		"",
		"1.2.3.0/24",
		"  9.9.9.9  ", // bare v4 host
		"2001:db8::/32",
		"2606:4700:4700::1111", // bare v6 host
		"3.4.5.0/24 # trailing comment",
		"not-an-address",
		"1.2.3.4/99",
		"10.0.0.0-10.0.0.255",
		"\r",
	}, "\n")
	s := NewCIDRSet()
	if err := s.LoadFile(tempList(t, "ipset.txt", content)); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got := s.Len(); got != 5 {
		t.Fatalf("Len = %d, want 5", got)
	}
	if s.Any {
		t.Error("Any set although the file had entries")
	}
	for _, a := range []string{"1.2.3.77", "9.9.9.9", "2001:db8:1::1", "2606:4700:4700::1111", "3.4.5.6"} {
		if !s.Match(mustAddr(t, a)) {
			t.Errorf("Match(%s) = false, want true", a)
		}
	}
	for _, a := range []string{"9.9.9.10", "2606:4700:4700::1112", "4.4.5.6"} {
		if s.Match(mustAddr(t, a)) {
			t.Errorf("Match(%s) = true, want false", a)
		}
	}
}

func TestCIDRSetEmptyFileMeansAny(t *testing.T) {
	s := NewCIDRSet()
	if err := s.LoadFile(tempList(t, "ipset.txt", "# nothing\n\n")); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !s.Any {
		t.Fatal("Any = false, want true for an ipset with no usable entries")
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len = %d, want 0", got)
	}
	if s.IsNone() {
		t.Error("IsNone true for an Any set")
	}
	for _, a := range []string{"1.2.3.4", "2001:db8::1"} {
		if !s.Match(mustAddr(t, a)) {
			t.Errorf("Match(%s) = false, want true (Any)", a)
		}
	}
}

func TestCIDRSetSentinelIsNone(t *testing.T) {
	// flowseal writes exactly this into ipset-exclude-user.txt for "none".
	s := NewCIDRSet()
	if err := s.LoadFile(repoList(t, "ipset-exclude-user.txt")); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !s.IsNone() {
		t.Fatalf("IsNone = false for the sentinel-only set (Len=%d, Any=%v)", s.Len(), s.Any)
	}
	if s.Any {
		t.Error("sentinel-only set must not be Any")
	}
	if got := s.Len(); got != 1 {
		t.Errorf("Len = %d, want 1", got)
	}
	// The sentinel stays a normal entry: it matches itself and nothing else.
	if !s.Match(mustAddr(t, "203.0.113.113")) {
		t.Error("sentinel address does not match its own entry")
	}
	for _, a := range []string{"203.0.113.112", "1.2.3.4", "2001:db8::1"} {
		if s.Match(mustAddr(t, a)) {
			t.Errorf("Match(%s) = true, want false", a)
		}
	}

	// Merged with a real list it is no longer the "none" state.
	m := NewCIDRSet()
	if err := m.LoadFile(repoList(t, "ipset-exclude.txt")); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadFile(repoList(t, "ipset-exclude-user.txt")); err != nil {
		t.Fatal(err)
	}
	if got := m.Len(); got != 12 {
		t.Errorf("merged Len = %d, want 12", got)
	}
	if m.IsNone() {
		t.Error("IsNone true for a merged set with real entries")
	}
	if !m.Match(mustAddr(t, "192.168.7.1")) || !m.Match(mustAddr(t, "fe80::1")) {
		t.Error("merged exclude set lost entries")
	}
}

// refIPSet is an independent membership oracle: a prefix contains a iff masking
// a to that prefix length yields the prefix itself.
type refIPSet struct {
	m     map[netip.Prefix]bool
	lens4 []int
	lens6 []int
}

func loadRefIPSet(tb testing.TB, path string) *refIPSet {
	tb.Helper()
	f, err := os.Open(path)
	if err != nil {
		tb.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	r := &refIPSet{m: make(map[netip.Prefix]bool, 40000)}
	seen4 := make(map[int]bool)
	seen6 := make(map[int]bool)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			tb.Fatalf("reference parse %q: %v", line, err)
		}
		p = p.Masked()
		r.m[p] = true
		if p.Addr().Is4() {
			seen4[p.Bits()] = true
		} else {
			seen6[p.Bits()] = true
		}
	}
	if err := sc.Err(); err != nil {
		tb.Fatalf("scan %s: %v", path, err)
	}
	for b := range seen4 {
		r.lens4 = append(r.lens4, b)
	}
	for b := range seen6 {
		r.lens6 = append(r.lens6, b)
	}
	return r
}

func (r *refIPSet) has(a netip.Addr) bool {
	a = a.Unmap()
	lens := r.lens6
	if a.Is4() {
		lens = r.lens4
	}
	for _, b := range lens {
		if r.m[netip.PrefixFrom(a, b).Masked()] {
			return true
		}
	}
	return false
}

func (r *refIPSet) prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(r.m))
	for p := range r.m {
		out = append(out, p)
	}
	return out
}

func TestCIDRSetRealIPSet(t *testing.T) {
	path := repoList(t, "ipset-all.txt")
	s := NewCIDRSet()
	if err := s.LoadFile(path); err != nil {
		t.Fatalf("LoadFile(ipset-all.txt): %v", err)
	}
	if got := s.Len(); got != 32132 {
		t.Errorf("ipset-all.txt Len = %d, want 32132", got)
	}
	if s.Any || s.IsNone() {
		t.Errorf("Any = %v, IsNone = %v, want both false", s.Any, s.IsNone())
	}

	inside := []string{"1.0.0.1", "1.0.0.254", "8.8.8.8", "2c0f:f7f8::1", "2c0f:f7f8:abcd::9"}
	for _, a := range inside {
		if !s.Match(mustAddr(t, a)) {
			t.Errorf("Match(%s) = false, want true (inside a known prefix)", a)
		}
	}
	// Reserved documentation / private space: covered by no prefix in the file.
	outside := []string{"192.0.2.1", "203.0.113.113", "198.51.100.7", "10.1.2.3", "127.0.0.1", "2001:db8::1", "fe80::1"}
	for _, a := range outside {
		if s.Match(mustAddr(t, a)) {
			t.Errorf("Match(%s) = true, want false (outside every prefix)", a)
		}
	}

	// Cross-check the binary search against an independent oracle, using
	// addresses picked to sit inside, just below and just above real prefixes.
	ref := loadRefIPSet(t, path)
	ps := ref.prefixes()
	if len(ps) != 32132 {
		t.Fatalf("reference holds %d prefixes, want 32132", len(ps))
	}
	rng := rand.New(rand.NewPCG(0x5eed, 0xf00d))
	check := func(a netip.Addr) {
		if got, want := s.Match(a), ref.has(a); got != want {
			t.Fatalf("Match(%s) = %v, oracle says %v", a, got, want)
		}
	}
	for i := 0; i < 1500; i++ {
		p := ps[rng.IntN(len(ps))]
		check(randomInPrefix(p, rng))
		check(p.Addr().Prev())
		check(lastInPrefix(p).Next())
	}
	for i := 0; i < 2000; i++ {
		check(randomAddr(rng, i%2 == 0))
	}
}

func TestCIDRSetReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipset.txt")
	writeFileAtomic(t, path, "1.2.3.0/24\n2001:db8::/32\n")
	s := NewCIDRSet()
	if err := s.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if got := s.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}

	writeFileAtomic(t, path, "5.6.7.0/24\n")
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := s.Len(); got != 1 {
		t.Errorf("Len after Reload = %d, want 1", got)
	}
	if !s.Match(mustAddr(t, "5.6.7.8")) {
		t.Error("Reload did not pick up the new prefix")
	}
	if s.Match(mustAddr(t, "1.2.3.4")) || s.Match(mustAddr(t, "2001:db8::1")) {
		t.Error("Reload kept removed prefixes")
	}

	// Empty file after reload flips the set into Any.
	writeFileAtomic(t, path, "\n")
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !s.Any || !s.Match(mustAddr(t, "1.2.3.4")) {
		t.Error("reload of an emptied file did not produce the Any state")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Error("Reload of a removed non-user file returned nil error")
	}

	manual := NewCIDRSet()
	manual.Add(netip.MustParsePrefix("9.9.9.0/24"))
	if err := manual.Reload(); err != nil {
		t.Fatalf("Reload of a fileless set: %v", err)
	}
	if !manual.Match(mustAddr(t, "9.9.9.1")) {
		t.Error("Reload of a fileless set dropped its prefixes")
	}
}

func randomInPrefix(p netip.Prefix, rng *rand.Rand) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		net := binary.BigEndian.Uint32(b[:])
		// Randomise only the host bits; a shift of 32 yields 0 in Go.
		host := rng.Uint32() >> uint(p.Bits())
		binary.BigEndian.PutUint32(b[:], net|host)
		return netip.AddrFrom4(b)
	}
	b := p.Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		if rng.Uint32()&1 == 1 {
			b[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	return netip.AddrFrom16(b)
}

func lastInPrefix(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		net := binary.BigEndian.Uint32(b[:])
		var mask uint32 = 0xffffffff >> uint(p.Bits())
		binary.BigEndian.PutUint32(b[:], net|mask)
		return netip.AddrFrom4(b)
	}
	b := p.Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom16(b)
}

func randomAddr(rng *rand.Rand, v4 bool) netip.Addr {
	if v4 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], rng.Uint32())
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], rng.Uint64())
	binary.BigEndian.PutUint64(b[8:16], rng.Uint64())
	a := netip.AddrFrom16(b)
	if a.Is4In6() {
		return a.Unmap()
	}
	return a
}

// ---------- Set ----------

func TestSetResolveCacheAndMerge(t *testing.T) {
	dir := t.TempDir()
	writeFileAtomic(t, filepath.Join(dir, "list-a.txt"), "a.example\n")
	writeFileAtomic(t, filepath.Join(dir, "list-b.txt"), "b.example\n")
	writeFileAtomic(t, filepath.Join(dir, "ipset-a.txt"), "1.2.3.0/24\n")
	writeFileAtomic(t, filepath.Join(dir, "ipset-b.txt"), "2001:db8::/32\n")
	s := NewSet(dir)

	if hs, err := s.Hosts(); hs != nil || err != nil {
		t.Errorf("Hosts() = (%v, %v), want (nil, nil)", hs, err)
	}
	if cs, err := s.CIDRs(); cs != nil || err != nil {
		t.Errorf("CIDRs() = (%v, %v), want (nil, nil)", cs, err)
	}

	h1, err := s.Hosts("list-a.txt")
	if err != nil {
		t.Fatalf("Hosts(list-a.txt): %v", err)
	}
	h2, err := s.Hosts("list-a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("Hosts returned two different sets for the same name; the parse is not shared")
	}
	if !h1.Match("x.a.example") || h1.Match("b.example") {
		t.Error("list-a.txt content is wrong")
	}

	m, err := s.Hosts("list-a.txt", "list-b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if m == h1 {
		t.Error("merged set aliases the single-file set")
	}
	if got := m.Len(); got != 2 {
		t.Errorf("merged Len = %d, want 2", got)
	}
	if !m.Match("a.example") || !m.Match("b.example") {
		t.Error("merged hostlist lost entries")
	}
	if m2, err := s.Hosts("list-a.txt", "list-b.txt"); err != nil || m2 != m {
		t.Error("merged sets are not cached by name tuple")
	}

	c1, err := s.CIDRs("ipset-a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !c1.Match(mustAddr(t, "1.2.3.4")) {
		t.Error("ipset-a.txt content is wrong")
	}
	cm, err := s.CIDRs("ipset-a.txt", "ipset-b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := cm.Len(); got != 2 {
		t.Errorf("merged ipset Len = %d, want 2", got)
	}
	if !cm.Match(mustAddr(t, "1.2.3.4")) || !cm.Match(mustAddr(t, "2001:db8::5")) {
		t.Error("merged ipset lost prefixes")
	}

	// Absolute names bypass dir.
	abs, err := filepath.Abs(filepath.Join(dir, "list-b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	ah, err := s.Hosts(abs)
	if err != nil {
		t.Fatalf("Hosts(abs): %v", err)
	}
	if !ah.Match("b.example") {
		t.Error("absolute path did not load")
	}

	// Real shipped lists resolve through the same code path.
	shipped := NewSet(filepath.Join("..", "..", "lists"))
	rh, err := shipped.Hosts("list-general.txt", "list-general-user.txt")
	if err != nil {
		t.Fatalf("Hosts(real lists): %v", err)
	}
	if got := rh.Len(); got != 51 {
		t.Errorf("list-general + user Len = %d, want 51", got)
	}
	if !rh.Match("discord.com") || !rh.Match("domain.example.abc") {
		t.Error("merged real hostlists lost entries")
	}
	ri, err := shipped.CIDRs("ipset-all.txt")
	if err != nil {
		t.Fatalf("CIDRs(ipset-all.txt): %v", err)
	}
	if got := ri.Len(); got != 32132 {
		t.Errorf("ipset-all.txt Len = %d, want 32132", got)
	}
}

func TestSetMissingFiles(t *testing.T) {
	dir := t.TempDir()
	writeFileAtomic(t, filepath.Join(dir, "list-a.txt"), "a.example\n")
	s := NewSet(dir)

	hs, err := s.Hosts("list-a.txt", "list-a-user.txt")
	if err != nil {
		t.Fatalf("missing -user.txt must be skipped, got %v", err)
	}
	if got := hs.Len(); got != 1 {
		t.Errorf("Len = %d, want 1", got)
	}
	if hs.Any {
		t.Error("skipping a missing user file must not set Any")
	}

	cs, err := s.CIDRs("ipset-nope-user.txt")
	if err != nil {
		t.Fatalf("missing -user.txt ipset must be skipped, got %v", err)
	}
	if cs.Len() != 0 || cs.Any || cs.Match(mustAddr(t, "1.2.3.4")) {
		t.Error("an all-skipped ipset must be empty and match nothing")
	}

	if _, err := s.Hosts("list-missing.txt"); err == nil {
		t.Error("Hosts of a missing non-user file returned nil error")
	}
	if _, err := s.CIDRs("ipset-missing.txt"); err == nil {
		t.Error("CIDRs of a missing non-user file returned nil error")
	}
}

func TestSetReloadAllAndStats(t *testing.T) {
	dir := t.TempDir()
	hpath := filepath.Join(dir, "list-a.txt")
	ipath := filepath.Join(dir, "ipset-a.txt")
	writeFileAtomic(t, hpath, "a.example\n")
	writeFileAtomic(t, ipath, "1.2.3.0/24\n")
	s := NewSet(dir)

	hs, err := s.Hosts("list-a.txt")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := s.CIDRs("ipset-a.txt")
	if err != nil {
		t.Fatal(err)
	}

	stats := s.Stats()
	if stats["list-a.txt"] != 1 || stats["ipset-a.txt"] != 1 {
		t.Errorf("Stats = %v, want both counts 1", stats)
	}

	writeFileAtomic(t, hpath, "a.example\nc.example\n")
	writeFileAtomic(t, ipath, "1.2.3.0/24\n4.5.6.0/24\n")
	if err := s.ReloadAll(); err != nil {
		t.Fatalf("ReloadAll: %v", err)
	}
	if got := hs.Len(); got != 2 {
		t.Errorf("hostlist Len after ReloadAll = %d, want 2", got)
	}
	if !hs.Match("c.example") {
		t.Error("ReloadAll did not update the shared hostlist")
	}
	if got := cs.Len(); got != 2 {
		t.Errorf("ipset Len after ReloadAll = %d, want 2", got)
	}
	if !cs.Match(mustAddr(t, "4.5.6.7")) {
		t.Error("ReloadAll did not update the shared ipset")
	}
	stats = s.Stats()
	if stats["list-a.txt"] != 2 || stats["ipset-a.txt"] != 2 {
		t.Errorf("Stats after ReloadAll = %v, want both counts 2", stats)
	}

	if err := os.Remove(hpath); err != nil {
		t.Fatal(err)
	}
	if err := s.ReloadAll(); err == nil {
		t.Error("ReloadAll with a removed non-user file returned nil error")
	}
	if got := cs.Len(); got != 2 {
		t.Errorf("a failing hostlist reload must not stop the ipset reload (Len = %d)", got)
	}
}

// ---------- AutoList ----------

// withFakeClock swaps the package clock for a deterministic one and returns a
// pointer used to advance it.
func withFakeClock(t *testing.T) *int64 {
	t.Helper()
	ns := int64(1_000_000_000)
	autoClock = func() int64 { return ns }
	t.Cleanup(func() { autoClock = monotonicNowNs })
	return &ns
}

const nsPerSec = int64(1_000_000_000)

func TestAutoListFailThreshold(t *testing.T) {
	clock := withFakeClock(t)
	path := filepath.Join(t.TempDir(), "auto.txt")
	a, err := NewAutoList(path)
	if err != nil {
		t.Fatalf("NewAutoList: %v", err)
	}
	if a.FailThreshold != 3 || a.FailTimeSeconds != 60 || a.RetransThreshold != 3 {
		t.Fatalf("defaults = %d/%d/%d, want 3/60/3", a.FailThreshold, a.FailTimeSeconds, a.RetransThreshold)
	}

	if a.Fail("Bad.Example.COM") {
		t.Error("first failure added the host")
	}
	*clock += 10 * nsPerSec
	if a.Fail("bad.example.com") {
		t.Error("second failure added the host")
	}
	*clock += 10 * nsPerSec
	if !a.Fail("bad.example.com") {
		t.Fatal("third failure inside the window did not add the host")
	}
	if a.Fail("bad.example.com") {
		t.Error("a host already on the list was reported as newly added")
	}
	if !a.Set().Match("bad.example.com") || !a.Set().Match("cdn.bad.example.com") {
		t.Error("learned host is not matched by the set")
	}
	if a.Fail("cdn.bad.example.com") {
		t.Error("a host covered by a learned suffix was added again")
	}
	if got := a.Set().Len(); got != 1 {
		t.Errorf("Set().Len() = %d, want 1", got)
	}

	// Failures spread wider than FailTimeSeconds restart the window.
	for i := 0; i < 5; i++ {
		if a.Fail("slow.example.net") {
			t.Fatalf("failure %d outside the window added the host", i+1)
		}
		*clock += 61 * nsPerSec
	}
	if a.Set().Match("slow.example.net") {
		t.Error("slow trickle of failures should not learn a host")
	}
	// Two quick ones after the trickle still need a third.
	if a.Fail("slow.example.net") || a.Fail("slow.example.net") {
		t.Fatal("host added before reaching the threshold")
	}
	if !a.Fail("slow.example.net") {
		t.Error("third failure inside a fresh window did not add the host")
	}

	// Custom threshold.
	a.FailThreshold = 2
	if a.Fail("two.example.org") {
		t.Error("first failure added the host with threshold 2")
	}
	if !a.Fail("two.example.org") {
		t.Error("second failure did not add the host with threshold 2")
	}

	if a.Fail("") || a.Fail("   ") || a.Fail("# nope") {
		t.Error("junk host names must be ignored")
	}
}

func TestAutoListRetransThreshold(t *testing.T) {
	withFakeClock(t)
	a, err := NewAutoList(filepath.Join(t.TempDir(), "auto.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Retrans("r.example.com") || a.Retrans("r.example.com") {
		t.Fatal("host added before the retransmission threshold")
	}
	if !a.Retrans("r.example.com") {
		t.Fatal("third retransmission did not add the host")
	}
	if a.Retrans("r.example.com") {
		t.Error("already-listed host reported as newly added")
	}
	a.RetransThreshold = 1
	if !a.Retrans("once.example.com") {
		t.Error("threshold 1 did not add on the first retransmission")
	}
	if got := a.Set().Len(); got != 2 {
		t.Errorf("Set().Len() = %d, want 2", got)
	}
}

func TestAutoListPersistence(t *testing.T) {
	withFakeClock(t)
	dir := t.TempDir()
	// A nested directory is created on demand.
	path := filepath.Join(dir, "state", "auto.txt")
	a, err := NewAutoList(path)
	if err != nil {
		t.Fatalf("NewAutoList: %v", err)
	}
	// Nothing learned yet: Flush must be a no-op, not an empty file.
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("Flush with nothing learned created a file")
	}

	for _, h := range []string{"b.example.com", "a.example.org"} {
		for i := 0; i < 3; i++ {
			a.Fail(h)
		}
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	got := string(data)
	want := autoHeader + "\na.example.org\nb.example.com\n"
	if got != want {
		t.Errorf("file =\n%q\nwant\n%q", got, want)
	}
	if entries, err := filepath.Glob(filepath.Join(dir, "state", "*.tmp")); err != nil || len(entries) != 0 {
		t.Errorf("temp files left behind: %v (err %v)", entries, err)
	}

	// Idempotent: a second Flush with nothing new must not touch the file. Proof:
	// clobber the file behind its back and check the bytes survive.
	writeFileAtomic(t, path, "clobbered\n")
	if err := a.Flush(); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "clobbered\n" {
		t.Error("second Flush rewrote the file although nothing changed")
	}

	// Reopening an existing list keeps the learned hosts and adds to them.
	writeFileAtomic(t, path, want)
	b, err := NewAutoList(path)
	if err != nil {
		t.Fatalf("NewAutoList (reopen): %v", err)
	}
	if got := b.Set().Len(); got != 2 {
		t.Fatalf("reopened Len = %d, want 2", got)
	}
	if !b.Set().Match("cdn.a.example.org") {
		t.Error("reopened list does not match a learned host")
	}
	if b.Fail("a.example.org") {
		t.Error("host from the file was reported as newly added")
	}
	for i := 0; i < 3; i++ {
		b.Fail("c.example.net")
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush after reopen: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != autoHeader+"\na.example.org\nb.example.com\nc.example.net\n" {
		t.Errorf("appended file =\n%q", data)
	}
}

func TestAutoListEmptyFileMatchesNothing(t *testing.T) {
	withFakeClock(t)
	path := tempList(t, "auto.txt", "")
	a, err := NewAutoList(path)
	if err != nil {
		t.Fatalf("NewAutoList: %v", err)
	}
	if a.Set().Any {
		t.Fatal("an empty auto-list must not become the Any set")
	}
	if a.Set().Match("anything.example") {
		t.Error("empty auto-list matched a host")
	}
	if _, err := NewAutoList("  "); err == nil {
		t.Error("NewAutoList with an empty path returned nil error")
	}
}

// ---------- concurrency ----------

func TestConcurrentMatchReload(t *testing.T) {
	dir := t.TempDir()
	hpath := filepath.Join(dir, "list.txt")
	ipath := filepath.Join(dir, "ipset.txt")
	writeFileAtomic(t, hpath, "discord.com\nexample.com\n")
	writeFileAtomic(t, ipath, "1.2.3.0/24\n2001:db8::/32\n")

	hs := NewHostSet()
	if err := hs.LoadFile(hpath); err != nil {
		t.Fatal(err)
	}
	cs := NewCIDRSet()
	if err := cs.LoadFile(ipath); err != nil {
		t.Fatal(err)
	}

	v4 := mustAddr(t, "1.2.3.4")
	v6 := mustAddr(t, "2001:db8::1")
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = hs.Match("cdn.discord.com")
				_ = hs.Match("CDN.EXAMPLE.COM")
				_ = hs.Len()
				_ = cs.Match(v4)
				_ = cs.Match(v6)
				_ = cs.Len()
				_ = cs.IsNone()
			}
		}()
	}
	// A writer that also mutates through Add, to exercise the lazy-sort path.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			cs.Add(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := 0; i < 60; i++ {
			writeFileAtomic(t, hpath, "discord.com\nexample.com\nround.example\n")
			writeFileAtomic(t, ipath, "1.2.3.0/24\n2001:db8::/32\n9.9.9.0/24\n")
			if err := hs.Reload(); err != nil {
				t.Errorf("hostlist Reload: %v", err)
				return
			}
			if err := cs.Reload(); err != nil {
				t.Errorf("ipset Reload: %v", err)
				return
			}
		}
	}()

	wg.Wait()
	if !hs.Match("cdn.discord.com") || !cs.Match(v4) {
		t.Error("set contents lost after concurrent reloads")
	}
}

// ---------- benchmarks ----------

func BenchmarkCIDRSetMatch(b *testing.B) {
	s := NewCIDRSet()
	if err := s.LoadFile(repoList(b, "ipset-all.txt")); err != nil {
		b.Fatal(err)
	}
	if s.Len() != 32132 {
		b.Fatalf("Len = %d, want 32132", s.Len())
	}
	addrs := []netip.Addr{
		netip.MustParseAddr("1.0.0.1"),        // hit, /24
		netip.MustParseAddr("8.8.8.8"),        // hit, /9
		netip.MustParseAddr("192.0.2.1"),      // miss
		netip.MustParseAddr("203.0.113.113"),  // miss
		netip.MustParseAddr("2c0f:f7f8::1"),   // hit, v6 /32
		netip.MustParseAddr("2001:db8::1"),    // miss, v6
		netip.MustParseAddr("::ffff:1.0.0.9"), // hit through 4-in-6 unmapping
	}
	want := []bool{true, true, false, false, true, false, true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % len(addrs)
		if s.Match(addrs[j]) != want[j] {
			b.Fatalf("Match(%s) = %v, want %v", addrs[j], !want[j], want[j])
		}
	}
}

func BenchmarkHostSetMatch(b *testing.B) {
	s := NewHostSet()
	if err := s.LoadFile(repoList(b, "list-general.txt")); err != nil {
		b.Fatal(err)
	}
	if err := s.LoadFile(repoList(b, "list-google.txt")); err != nil {
		b.Fatal(err)
	}
	hosts := []string{
		"cdn.discord.com",
		"rr3---sn-abc.googlevideo.com",
		"www.example.org",
		"NOTDISCORD.COM",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Match(hosts[i%len(hosts)])
	}
}
