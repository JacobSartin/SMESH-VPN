// Command smesh-server manages the network CA and runs the discovery server.
package main

import (
	"context"
	"crypto/mldsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
	discovery "github.com/JacobSartin/SMESH-VPN/pkg/Discovery"
)

// Files written by issue-client, in the layout the client expects.
const (
	clientCertificateFile = "client.crt"
	clientPrivateKeyFile  = "client.key"
)

const usage = `usage: smesh-server <command> [flags]

commands:
  init-ca       create a new network CA
  issue-client  issue a client certificate and key from the CA
  serve         run the discovery server

Run "smesh-server <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init-ca":
		err = runInitCA(os.Args[2:], os.Stdout)
	case "issue-client":
		err = runIssueClient(os.Args[2:], os.Stdout)
	case "serve":
		err = runServe(os.Args[2:])
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		log.Fatal(err)
	}
}

func runInitCA(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init-ca", flag.ContinueOnError)
	dir := fs.String("dir", "ca", "directory to write ca.crt and ca.key into")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		return err
	}
	if err := ca.Save(*dir); err != nil {
		return fmt.Errorf("save CA: %w", err)
	}
	fmt.Fprintf(out, "Created CA in %s. Keep %s private.\n", *dir, filepath.Join(*dir, certs.CAPrivateKeyFile))
	return nil
}

func runIssueClient(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("issue-client", flag.ContinueOnError)
	caDir := fs.String("ca-dir", "ca", "directory containing ca.crt and ca.key")
	outDir := fs.String("out", "", "directory to write client.crt, client.key, and ca.crt into (required)")
	rawID := fs.String("id", "", "client ID (UUID); generated if empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outDir == "" {
		return errors.New("issue-client: -out is required")
	}

	id := uuid.NewV7()
	if *rawID != "" {
		parsed, err := uuid.Parse(*rawID)
		if err != nil || parsed == uuid.Nil() {
			return fmt.Errorf("issue-client: invalid -id %q", *rawID)
		}
		id = parsed
	}

	ca, err := certs.LoadCertificateAuthority(*caDir)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return err
	}
	der, err := ca.IssueClientCertificate(key.PublicKey(), id.String())
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return err
	}
	if err := certs.WritePrivateKeyFile(filepath.Join(*outDir, clientPrivateKeyFile), key); err != nil {
		return err
	}
	if err := certs.WriteCertificateFile(filepath.Join(*outDir, clientCertificateFile), der); err != nil {
		return err
	}
	if err := certs.WriteCertificateFile(filepath.Join(*outDir, certs.CACertificateFile), ca.Certificate.Raw); err != nil {
		return err
	}
	fmt.Fprintf(out, "Issued client %s into %s\n", id, *outDir)
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	caDir := fs.String("ca-dir", "ca", "directory containing ca.crt and ca.key")
	listen := fs.String("listen", ":8081", "address to listen on")
	ttl := fs.Duration("ttl", 2*time.Minute, "drop peers that have not re-registered within this long")
	var hostnames, ips listFlag
	fs.Var(&hostnames, "hostname", "DNS name clients use to reach this server (repeatable; default localhost)")
	fs.Var(&ips, "ip", "IP address clients use to reach this server (repeatable; default 127.0.0.1 and ::1)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	serverIPs, err := parseIPs(ips)
	if err != nil {
		return err
	}
	if len(hostnames) == 0 && len(serverIPs) == 0 {
		hostnames = listFlag{"localhost"}
		serverIPs = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}

	ca, err := certs.LoadCertificateAuthority(*caDir)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	tlsConfig, err := discovery.NewServerTLSConfig(ca, hostnames, serverIPs)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           discovery.NewServer(ca, *ttl).Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("Discovery server listening on %s (names: %s; IPs: %s)", *listen, strings.Join(hostnames, ", "), joinIPs(serverIPs))
		errCh <- httpServer.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Print("Shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func parseIPs(values []string) ([]net.IP, error) {
	ips := make([]net.IP, 0, len(values))
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid -ip %q", value)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func joinIPs(ips []net.IP) string {
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ", ")
}
