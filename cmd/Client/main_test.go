package main

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	discovery "github.com/JacobSartin/SMESH-VPN/pkg/Discovery"
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

func TestRegisterWithRetry(t *testing.T) {
	ok := discovery.Registration{PeerRecord: discovery.PeerRecord{VPNIP: netip.MustParseAddr("10.77.0.2")}, TTLMillis: 120000}
	noLog := func(string, ...any) {}

	t.Run("retries until the server is reachable", func(t *testing.T) {
		calls := 0
		record, err := registerWithRetry(context.Background(), func(context.Context) (discovery.Registration, error) {
			calls++
			switch calls {
			case 1:
				return discovery.Registration{}, errors.New("connection refused")
			case 2:
				return discovery.Registration{}, &discovery.StatusError{StatusCode: http.StatusServiceUnavailable}
			}
			return ok, nil
		}, time.Millisecond, time.Millisecond, noLog)
		if err != nil || record != ok || calls != 3 {
			t.Fatalf("got %+v, %v after %d calls", record, err, calls)
		}
	})

	t.Run("client errors are not retried", func(t *testing.T) {
		calls := 0
		_, err := registerWithRetry(context.Background(), func(context.Context) (discovery.Registration, error) {
			calls++
			return discovery.Registration{}, &discovery.StatusError{StatusCode: http.StatusConflict}
		}, time.Millisecond, time.Millisecond, noLog)
		if err == nil || calls != 1 {
			t.Fatalf("expected one failed call, got %v after %d calls", err, calls)
		}
	})

	t.Run("stops when cancelled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := registerWithRetry(ctx, func(context.Context) (discovery.Registration, error) {
			return discovery.Registration{}, errors.New("connection refused")
		}, time.Millisecond, 5*time.Millisecond, noLog)
		if err == nil {
			t.Fatal("expected an error once the context is done")
		}
	})
}
