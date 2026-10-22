package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	session "github.com/JacobSartin/SMESH-VPN/pkg/Session"
)

// Client talks to a discovery server using the peer's certificate for mutual TLS.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient creates a client for the server at baseURL (for example
// https://discovery.example:8081). The server certificate is verified against
// the identity's CA certificate.
func NewClient(baseURL string, identity *session.ClientIdentity) (*Client, error) {
	if identity == nil || identity.CACertificate == nil {
		return nil, errors.New("discovery client requires an identity with a CA certificate")
	}
	clientCert, err := identity.TLSCertificate()
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(identity.CACertificate)

	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:   tls.VersionTLS13,
					RootCAs:      roots,
					Certificates: []tls.Certificate{clientCert},
				},
			},
		},
	}, nil
}

// Register registers or refreshes this peer. Pass an unspecified host in
// address (for example 0.0.0.0:7777) to have the server use the source IP it sees.
func (c *Client) Register(ctx context.Context, address netip.AddrPort, vpnIP netip.Addr) (PeerRecord, error) {
	body, err := json.Marshal(RegistrationRequest{Address: address, VPNIP: vpnIP})
	if err != nil {
		return PeerRecord{}, err
	}
	var record PeerRecord
	err = c.do(ctx, http.MethodPost, "/peers", body, http.StatusOK, &record)
	return record, err
}

// ListPeers returns the live peers other than this one.
func (c *Client) ListPeers(ctx context.Context) ([]PeerRecord, error) {
	var peers []PeerRecord
	err := c.do(ctx, http.MethodGet, "/peers", nil, http.StatusOK, &peers)
	return peers, err
}

// Deregister removes this peer from the server.
func (c *Client) Deregister(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/peers", nil, http.StatusNoContent, nil)
}

// Heartbeat re-registers every interval until ctx is done. The first
// registration happens immediately. onError, if set, is called for failed attempts.
func (c *Client) Heartbeat(ctx context.Context, interval time.Duration, address netip.AddrPort, vpnIP netip.Addr, onError func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := c.Register(ctx, address, vpnIP); err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// StatusError is returned when the server answers with an unexpected status.
type StatusError struct {
	StatusCode int
	Message    string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("discovery server returned %d: %s", e.StatusCode, e.Message)
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, wantStatus int, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != wantStatus {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return &StatusError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(message))}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
