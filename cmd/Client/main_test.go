package main

import (
	"net/netip"
	"testing"
)

func TestParseFlagsRequiresDiscoveryAndVPNIP(t *testing.T) {
	if _, err := parseFlags([]string{"-vpn-ip", "10.77.0.2/24"}); err == nil {
		t.Error("expected missing -discovery to fail")
	}
	if _, err := parseFlags([]string{"-discovery", "https://localhost:8081"}); err == nil {
		t.Error("expected missing -vpn-ip to fail")
	}
	if _, err := parseFlags([]string{"-discovery", "https://localhost:8081", "-vpn-ip", "10.77.0.2"}); err == nil {
		t.Error("expected -vpn-ip without a prefix length to fail")
	}
	cfg, err := parseFlags([]string{"-discovery", "https://localhost:8081", "-vpn-ip", "10.77.0.2/24"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.vpnPrefix != netip.MustParsePrefix("10.77.0.2/24") {
		t.Fatalf("unexpected prefix %s", cfg.vpnPrefix)
	}
}

func TestAdvertisedEndpoint(t *testing.T) {
	cases := []struct {
		listen, advertise string
		want              string
		wantErr           bool
	}{
		{listen: ":7777", want: "0.0.0.0:7777"},
		{listen: "0.0.0.0:7000", want: "0.0.0.0:7000"},
		{listen: ":7777", advertise: "203.0.113.5:9000", want: "203.0.113.5:9000"},
		{listen: ":0", wantErr: true},
		{listen: ":7777", advertise: "not-an-endpoint", wantErr: true},
	}
	for _, tc := range cases {
		got, err := advertisedEndpoint(config{listen: tc.listen, advertise: tc.advertise})
		if tc.wantErr {
			if err == nil {
				t.Errorf("listen %q advertise %q: expected error, got %s", tc.listen, tc.advertise, got)
			}
			continue
		}
		if err != nil || got != netip.MustParseAddrPort(tc.want) {
			t.Errorf("listen %q advertise %q: got %s, %v; want %s", tc.listen, tc.advertise, got, err, tc.want)
		}
	}
}
