// Command smesh-client joins the mesh: it brings up a TUN interface, registers
// with the discovery server, and tunnels overlay traffic to other peers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	discovery "github.com/JacobSartin/SMESH-VPN/pkg/Discovery"
	mesh "github.com/JacobSartin/SMESH-VPN/pkg/Mesh"
	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
	tun "github.com/JacobSartin/SMESH-VPN/pkg/Tun"
)

const (
	heartbeatInterval = 30 * time.Second // the server's default TTL is 2m
	keepaliveInterval = 10 * time.Second
	maxSessionIdle    = 3 * keepaliveInterval
	maxKeyAge         = time.Hour
)

type config struct {
	discoveryURL string
	identityDir  string
	listen       string
	advertise    string
	vpnPrefix    netip.Prefix
	tunName      string
	mtu          int
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("smesh-client", flag.ContinueOnError)
	cfg := config{}
	fs.StringVar(&cfg.discoveryURL, "discovery", "", "discovery server URL, for example https://discovery.example:8081 (required)")
	fs.StringVar(&cfg.identityDir, "dir", ".", "directory containing client.crt, client.key, and ca.crt from issue-client")
	fs.StringVar(&cfg.listen, "listen", ":7777", "TCP address to accept peer sessions on")
	fs.StringVar(&cfg.advertise, "advertise", "", "endpoint peers should dial (default: the discovery server's view of this host, at the -listen port)")
	vpnIP := fs.String("vpn-ip", "", "this peer's overlay address and prefix, for example 10.77.0.2/24 (required)")
	fs.StringVar(&cfg.tunName, "tun", "smesh0", "TUN interface name")
	fs.IntVar(&cfg.mtu, "mtu", tun.DefaultMTU, "TUN interface MTU")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	if cfg.discoveryURL == "" {
		return config{}, errors.New("-discovery is required")
	}
	if *vpnIP == "" {
		return config{}, errors.New("-vpn-ip is required")
	}
	prefix, err := netip.ParsePrefix(*vpnIP)
	if err != nil || !prefix.Addr().Is4() {
		return config{}, fmt.Errorf("-vpn-ip must be an IPv4 address with prefix length, for example 10.77.0.2/24: %q", *vpnIP)
	}
	cfg.vpnPrefix = prefix
	return cfg, nil
}

// advertisedEndpoint returns the endpoint to register. Without -advertise it
// uses an unspecified host so the discovery server fills in the source IP.
func advertisedEndpoint(cfg config) (netip.AddrPort, error) {
	if cfg.advertise != "" {
		endpoint, err := netip.ParseAddrPort(cfg.advertise)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid -advertise %q: %w", cfg.advertise, err)
		}
		return endpoint, nil
	}
	_, rawPort, err := net.SplitHostPort(cfg.listen)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid -listen %q: %w", cfg.listen, err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("-listen %q needs an explicit port when -advertise is not set", cfg.listen)
	}
	return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)), nil
}

func run(ctx context.Context, cfg config) error {
	identity, err := session.LoadClientIdentity(
		filepath.Join(cfg.identityDir, "client.crt"),
		filepath.Join(cfg.identityDir, "client.key"),
		filepath.Join(cfg.identityDir, certs.CACertificateFile),
	)
	if err != nil {
		return err
	}
	log.Printf("Client ID %s", identity.ID)

	endpoint, err := advertisedEndpoint(cfg)
	if err != nil {
		return err
	}
	vpnIP := cfg.vpnPrefix.Addr()

	device, err := tun.Open(cfg.tunName, cfg.vpnPrefix, cfg.mtu)
	if err != nil {
		return fmt.Errorf("open TUN device: %w", err)
	}
	log.Printf("Interface %s up with %s (MTU %d)", device.Name(), cfg.vpnPrefix, cfg.mtu)

	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		device.Close()
		return fmt.Errorf("listen for peers: %w", err)
	}

	discoveryClient, err := discovery.NewClient(cfg.discoveryURL, identity)
	if err != nil {
		listener.Close()
		device.Close()
		return err
	}
	record, err := registerWithRetry(ctx, func(ctx context.Context) (discovery.PeerRecord, error) {
		return discoveryClient.Register(ctx, endpoint, vpnIP)
	}, time.Second, 10*time.Second, log.Printf)
	if err != nil {
		listener.Close()
		device.Close()
		return fmt.Errorf("register with discovery server: %w", err)
	}
	log.Printf("Registered with discovery as %s (overlay %s)", record.Address, record.VPNIP)

	sessions := session.NewSessionManager(time.Second*5, maxSessionIdle, maxKeyAge, identity)
	defer sessions.Shutdown()

	node, err := mesh.New(mesh.Config{
		Sessions:          sessions,
		Peers:             discoveryClient,
		Listener:          listener,
		Device:            device,
		KeepaliveInterval: keepaliveInterval,
	})
	if err != nil {
		listener.Close()
		device.Close()
		return err
	}

	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	go discoveryClient.Heartbeat(heartbeatCtx, heartbeatInterval, endpoint, vpnIP, func(err error) {
		log.Printf("Discovery heartbeat failed: %v", err)
	})

	runErr := node.Run(ctx)
	stopHeartbeat()

	deregisterCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := discoveryClient.Deregister(deregisterCtx); err != nil {
		log.Printf("Deregister failed: %v", err)
	}
	log.Print("Stopped")
	return runErr
}

// registerWithRetry performs the initial registration. The discovery server
// may not be reachable yet (it may still be starting), so transport errors and
// server errors are retried with backoff until ctx is done. Client errors such
// as a rejected certificate or an overlay IP conflict are returned at once.
func registerWithRetry(ctx context.Context, register func(context.Context) (discovery.PeerRecord, error), minDelay, maxDelay time.Duration, logf func(string, ...any)) (discovery.PeerRecord, error) {
	delay := minDelay
	for {
		record, err := register(ctx)
		if err == nil {
			return record, nil
		}
		var statusErr *discovery.StatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode < 500 {
			return discovery.PeerRecord{}, err
		}
		if ctx.Err() != nil {
			return discovery.PeerRecord{}, err
		}

		logf("Registration failed, retrying in %s: %v", delay, err)
		select {
		case <-ctx.Done():
			return discovery.PeerRecord{}, err
		case <-time.After(delay):
		}
		delay = min(2*delay, maxDelay)
	}
}
