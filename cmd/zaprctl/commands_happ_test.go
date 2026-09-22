//go:build darwin

package main

import "testing"

func TestHappServiceConnected(t *testing.T) {
	for _, tc := range []struct {
		name string
		list string
		want bool
	}{
		{"connected", `* (Connected)  6764094B VPN (su.ffg.happ) "Happ"`, true},
		{"connecting", `* (Connecting) 6764094B VPN (su.ffg.happ) "Happ"`, true},
		{"disconnected", `* (Disconnected) 6764094B VPN (su.ffg.happ) "Happ"`, false},
		{"other VPN", `* (Connected) 6764094B VPN (com.example.other) "Other"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := happServiceConnected(tc.list); got != tc.want {
				t.Fatalf("happServiceConnected(%q) = %t, want %t", tc.list, got, tc.want)
			}
		})
	}
}

func TestHappServiceName(t *testing.T) {
	line := `* (Disconnected) 6764094B VPN (su.ffg.happ) "Happ" [VPN:su.ffg.happ]`
	if got := happServiceName(line); got != "Happ" {
		t.Fatalf("happServiceName(%q) = %q, want Happ", line, got)
	}
	if got := happServiceName(`* (Connected) UUID VPN (com.example.other) "Happ"`); got != "" {
		t.Fatalf("unrelated service was selected: %q", got)
	}
}
