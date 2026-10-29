package auth

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"testing"
	"uuid"

	certs "github.com/JacobSartin/SMESH-VPN/pkg/Certs"
)

// Tests added during code review. Each one targets a specific weakness in the
// authenticated handshake; a failing test here means the weakness is present.

type reviewPeer struct {
	id   uuid.UUID
	cert *x509.Certificate
	key  *mldsa.PrivateKey
}

func issueReviewPeer(t *testing.T, ca *certs.CertificateAuthority) reviewPeer {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id := uuid.NewV7()
	der, err := ca.IssueClientCertificate(key.PublicKey(), id.String())
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return reviewPeer{id: id, cert: cert, key: key}
}

func reviewCA(t *testing.T) (*certs.CertificateAuthority, *certs.ClientCertificateVerifier) {
	t.Helper()
	ca, err := certs.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	verifier, err := certs.NewClientCertificateVerifier(*ca.Certificate)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return ca, verifier
}

// The hello carries a self-asserted ID. The server never checks that it
// matches the identity bound into the certificate, so a peer holding a valid
// certificate for A can introduce itself as B. The session manager then
// indexes the session under B.
func TestHelloIDMustMatchCertificateIdentity(t *testing.T) {
	ca, verifier := reviewCA(t)
	victim := issueReviewPeer(t, ca)
	attacker := issueReviewPeer(t, ca)
	serverPeer := issueReviewPeer(t, ca)

	// Attacker signs a hello with their own certificate but claims victim's ID.
	client, err := NewAuthenticatedPQXDHClient(attacker.cert, attacker.key, verifier)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := client.CreateClientHello()
	if err != nil {
		t.Fatal(err)
	}
	hello.ID = victim.id
	if err := hello.Sign(attacker.key); err != nil {
		t.Fatal(err)
	}

	server, err := NewAuthenticatedPQXDHServer(serverPeer.cert, serverPeer.key, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.ProcessClientHello(hello); err == nil {
		t.Fatalf("server accepted a hello whose ID %s does not match the certificate identity %s", victim.id, attacker.id)
	}
}

// Unknown key share / identity misbinding. The server's response is not bound
// to the hello it answers, and the KDF does not include either party's
// identity. A malicious insider M can take A's ephemeral public keys, wrap them
// in a hello signed with M's own certificate, and forward B's response back to
// A. A and B end up with the same session key, but B believes it is talking to
// M while A believes it is talking to B.
func TestResponseIsBoundToTheHelloItAnswers(t *testing.T) {
	ca, verifier := reviewCA(t)
	alice := issueReviewPeer(t, ca)
	bob := issueReviewPeer(t, ca)
	mallory := issueReviewPeer(t, ca)

	aliceClient, err := NewAuthenticatedPQXDHClient(alice.cert, alice.key, verifier)
	if err != nil {
		t.Fatal(err)
	}
	aliceHello, err := aliceClient.CreateClientHello()
	if err != nil {
		t.Fatal(err)
	}

	// Mallory re-wraps Alice's ephemeral keys under Mallory's identity.
	malloryHello := &AuthenticatedHandshakeHello{
		PQPublicKey: aliceHello.PQPublicKey,
		ECPublicKey: aliceHello.ECPublicKey,
		Certificate: mallory.cert.Raw,
		Timestamp:   aliceHello.Timestamp,
		ID:          mallory.id,
	}
	if err := malloryHello.Sign(mallory.key); err != nil {
		t.Fatal(err)
	}

	bobServer, err := NewAuthenticatedPQXDHServer(bob.cert, bob.key, verifier)
	if err != nil {
		t.Fatal(err)
	}
	response, bobKey, err := bobServer.ProcessClientHello(malloryHello)
	if err != nil {
		t.Fatalf("bob rejected mallory's (validly signed) hello: %v", err)
	}

	// Mallory forwards Bob's response to Alice unchanged.
	aliceKey, _, err := aliceClient.ProcessServerResponse(response)
	if err == nil && bytes.Equal(aliceKey, bobKey) {
		t.Fatalf("identity misbinding: alice and bob share a key, but bob attributes the session to mallory (%s)", mallory.id)
	}
}

// The peer verifier does not require client-auth usage or a client identity in
// the certificate, so any certificate the CA has ever signed (here, the
// discovery server's TLS certificate) can authenticate as a mesh peer.
func TestPeerVerifierRejectsNonClientCertificates(t *testing.T) {
	ca, verifier := reviewCA(t)
	serverPeer := issueReviewPeer(t, ca)

	tlsKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	tlsDER, err := ca.IssueServerCertificate(tlsKey.PublicKey(), "discovery", []string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := x509.ParseCertificate(tlsDER)
	if err != nil {
		t.Fatal(err)
	}

	// The client constructor already refuses a certificate without a client
	// identity, so build the hello by hand to exercise the server's check.
	keySource, err := NewAuthenticatedPQXDHClient(serverPeer.cert, serverPeer.key, verifier)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := keySource.CreateClientHello()
	if err != nil {
		t.Fatal(err)
	}
	hello.Certificate = tlsCert.Raw
	hello.ID = uuid.NewV7()
	if err := hello.Sign(tlsKey); err != nil {
		t.Fatal(err)
	}
	server, err := NewAuthenticatedPQXDHServer(serverPeer.cert, serverPeer.key, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.ProcessClientHello(hello); err == nil {
		t.Fatal("a server-auth-only TLS certificate was accepted as a mesh peer identity")
	}
}
