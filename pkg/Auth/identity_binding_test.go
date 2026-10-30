package auth

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
)

func newBindingFixture(t *testing.T) (*certs.CertificateAuthority, *certs.ClientCertificateVerifier) {
	t.Helper()
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	verifier, err := certs.NewClientCertificateVerifier(*ca.Certificate)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	return ca, verifier
}

func TestHandshakeReturnsCertificateIdentities(t *testing.T) {
	ca, verifier := newBindingFixture(t)
	clientCert, clientKey, err := createTestClientCertificate(ca)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey, err := createTestServerCertificate(ca)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewAuthenticatedPQXDHClient(clientCert, clientKey, verifier)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewAuthenticatedPQXDHServer(serverCert, serverKey, verifier)
	if err != nil {
		t.Fatal(err)
	}

	hello, err := client.CreateClientHello()
	if err != nil {
		t.Fatal(err)
	}
	response, _, clientID, err := server.ProcessClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	wantClientID, _ := certs.ClientIDFromCertificate(clientCert)
	if clientID != wantClientID {
		t.Fatalf("client ID %s, want certificate ID %s", clientID, wantClientID)
	}
	_, peerID, err := client.ProcessServerResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	wantServerID, _ := certs.ClientIDFromCertificate(serverCert)
	if peerID != wantServerID {
		t.Fatalf("peer ID %s, want certificate ID %s", peerID, wantServerID)
	}
}

func TestHandshakeRejectsResponseForDifferentHello(t *testing.T) {
	ca, verifier := newBindingFixture(t)
	clientCert, clientKey, _ := createTestClientCertificate(ca)
	serverCert, serverKey, _ := createTestServerCertificate(ca)
	server, _ := NewAuthenticatedPQXDHServer(serverCert, serverKey, verifier)

	first, _ := NewAuthenticatedPQXDHClient(clientCert, clientKey, verifier)
	firstHello, err := first.CreateClientHello()
	if err != nil {
		t.Fatal(err)
	}
	response, _, _, err := server.ProcessClientHello(firstHello)
	if err != nil {
		t.Fatal(err)
	}

	second, _ := NewAuthenticatedPQXDHClient(clientCert, clientKey, verifier)
	if _, err := second.CreateClientHello(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := second.ProcessServerResponse(response); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for replayed response, got %v", err)
	}
}

func TestHandshakeRejectsDiscoveryServerCertificateAsPeer(t *testing.T) {
	ca, verifier := newBindingFixture(t)
	clientCert, clientKey, _ := createTestClientCertificate(ca)
	client, _ := NewAuthenticatedPQXDHClient(clientCert, clientKey, verifier)

	serverKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.IssueServerCertificate(serverKey.PublicKey(), "discovery", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	discoveryCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	impostor, _ := NewAuthenticatedPQXDHServer(discoveryCert, serverKey, verifier)

	hello, err := client.CreateClientHello()
	if err != nil {
		t.Fatal(err)
	}
	response, _, _, err := impostor.ProcessClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ProcessServerResponse(response); err == nil {
		t.Fatal("expected discovery server certificate to be rejected as a peer certificate")
	}
}

// Signatures must survive the JSON round trip regardless of the sender's time
// zone. A zone named like UTC but distinct from time.UTC used to change the
// signed timestamp bytes once decoded on the other side.
func TestHandshakeSignaturesSurviveJSONInAnyTimeZone(t *testing.T) {
	ca, verifier := newBindingFixture(t)
	clientCert, clientKey, _ := createTestClientCertificate(ca)
	serverCert, serverKey, _ := createTestServerCertificate(ca)
	client, _ := NewAuthenticatedPQXDHClient(clientCert, clientKey, verifier)
	server, _ := NewAuthenticatedPQXDHServer(serverCert, serverKey, verifier)

	for _, zone := range []*time.Location{time.FixedZone("UTC", 0), time.FixedZone("", 0), time.FixedZone("CET", 3600), time.UTC} {
		hello, err := client.CreateClientHello()
		if err != nil {
			t.Fatal(err)
		}
		hello.Timestamp = hello.Timestamp.In(zone)
		if err := hello.Sign(clientKey); err != nil {
			t.Fatal(err)
		}
		var decodedHello AuthenticatedHandshakeHello
		roundTrip(t, hello, &decodedHello)

		response, _, _, err := server.ProcessClientHello(&decodedHello)
		if err != nil {
			t.Fatalf("zone %q: hello rejected after JSON round trip: %v", zone, err)
		}
		var decodedResponse AuthenticatedHandshakeResponse
		roundTrip(t, response, &decodedResponse)
		if _, _, err := client.ProcessServerResponse(&decodedResponse); err != nil {
			t.Fatalf("zone %q: response rejected after JSON round trip: %v", zone, err)
		}
	}
}

func roundTrip(t *testing.T, in, out any) {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}
