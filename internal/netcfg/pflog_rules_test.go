package netcfg

import (
	"strings"
	"testing"
)

func TestLogDropRules(t *testing.T) {
	r := LogDropRules(LogDropOpts{
		PFLog: "pflog9", TCPPorts: []PortRange{{80, 80}, {443, 443}},
		UDPPorts:     []PortRange{{443, 443}, {50000, 50100}},
		ExcludeTable: "zmx", ExemptRoot: true,
	})
	for _, want := range []string{
		"table <zmx> persist",
		"block out log (all, to pflog9) quick inet proto tcp",
		"port { 80 443 } user { > root } no state",
		"block out log (all, to pflog9) quick inet proto udp",
		"port { 443 50000:50100 } user { > root } no state",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("rules missing %q:\n%s", want, r)
		}
	}
}

func TestLogDropRulesPhysicalUplinkOnly(t *testing.T) {
	r := LogDropRules(LogDropOpts{PFLog: "pflog9", Iface: "en0", TCPPorts: []PortRange{{443, 443}}, ExcludeTable: "zmx", ExemptRoot: true})
	if !strings.Contains(r, "block out log (all, to pflog9) quick on en0") {
		t.Fatalf("missing physical-uplink restriction:\n%s", r)
	}
	if strings.Contains(r, "block out log (all, to pflog9) quick inet") {
		t.Fatalf("rule still matches every outbound interface:\n%s", r)
	}
}
