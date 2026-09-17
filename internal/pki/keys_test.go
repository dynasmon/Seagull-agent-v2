package pki_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
)

func TestAKeyIsNamedAsTheRequestAndTheCertificateForItNameIt(t *testing.T) {
	created := create(t, openKeys(t, keysDirectory(t)))
	asked := request(t, created, "web-01")
	if err := asked.CheckSignature(); err != nil {
		t.Fatalf("the request is not signed by the key it carries: %v", err)
	}
	issued := newAuthority(t).issue(t, "web-01", asked.PublicKey, x509.ExtKeyUsageClientAuth)
	named, err := pki.KeyID(issued.PublicKey)
	if err != nil {
		t.Fatalf("name the certified key: %v", err)
	}
	if digest(asked.RawSubjectPublicKeyInfo) != created.ID() || digest(issued.RawSubjectPublicKeyInfo) != created.ID() || named != created.ID() {
		t.Fatalf("the key is %s, the request names %s and the certificate %s",
			created.ID(), digest(asked.RawSubjectPublicKeyInfo), digest(issued.RawSubjectPublicKeyInfo))
	}
}

func TestAKeyAuthenticatesATLSClientOnlyWithItsOwnCertificate(t *testing.T) {
	keys := openKeys(t, keysDirectory(t))
	agent, other := create(t, keys), create(t, keys)
	authority := newAuthority(t)
	gatewayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the gateway key: %v", err)
	}
	gateway := authority.issue(t, "gateway", gatewayKey.Public(), x509.ExtKeyUsageServerAuth)
	trusted := x509.NewCertPool()
	trusted.AddCert(authority.certificate)
	server := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{gateway.Raw}, PrivateKey: gatewayKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    trusted,
	}
	client := func(certificate *x509.Certificate) *tls.Config {
		return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ServerName:   "gateway",
			RootCAs:      trusted,
			Certificates: []tls.Certificate{{Certificate: [][]byte{certificate.Raw}, PrivateKey: agent}},
		}
	}

	own := authority.issue(t, "web-01", agent.Public(), x509.ExtKeyUsageClientAuth)
	state, err := handshake(t, server, client(own))
	if err != nil {
		t.Fatalf("the handshake with the agent's own certificate failed: %v", err)
	}
	if peer := state.PeerCertificates[0]; peer.Subject.CommonName != "web-01" || digest(peer.RawSubjectPublicKeyInfo) != agent.ID() {
		t.Fatalf("the gateway authenticated %s with key %s", peer.Subject.CommonName, digest(peer.RawSubjectPublicKeyInfo))
	}

	copied := authority.issue(t, "db-07", other.Public(), x509.ExtKeyUsageClientAuth)
	if _, err := handshake(t, server, client(copied)); err == nil {
		t.Fatal("the key authenticated with a certificate issued for another key")
	}
}

func TestAKeyCannotBeReadOutOfWhatItOffers(t *testing.T) {
	directory := keysDirectory(t)
	created := create(t, openKeys(t, directory))
	content := readKey(t, directory, created.ID())
	scalar, err := decodeKey(t, content).Bytes()
	if err != nil {
		t.Fatalf("read the private scalar: %v", err)
	}

	if _, err := x509.MarshalPKCS8PrivateKey(created); err == nil {
		t.Error("the key encodes as PKCS #8")
	}
	switch exported := any(created).(type) {
	case *ecdsa.PrivateKey, interface{ Bytes() ([]byte, error) }:
		t.Errorf("the key is a %T, which hands out its private half", exported)
	}
	var shown bytes.Buffer
	fmt.Fprintf(&shown, "%v %+v %#v %s\n", created, created, created, created)
	slog.New(slog.NewJSONHandler(&shown, nil)).Info("key", slog.Any("key", created))
	slog.New(slog.NewTextHandler(&shown, nil)).Info("key", slog.Any("key", created))
	for _, secret := range []string{hex.EncodeToString(scalar), new(big.Int).SetBytes(scalar).String()} {
		if strings.Contains(shown.String(), secret) {
			t.Fatalf("formatting the key shows its private scalar:\n%s", shown.String())
		}
	}
	if exposes(shown.String(), content) {
		t.Fatalf("formatting the key shows its file:\n%s", shown.String())
	}
}

type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the authority key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agents"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("sign the authority: %v", err)
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatalf("parse the authority: %v", err)
	}
	return authority{certificate: certificate, key: key}
}

func (a authority) issue(t *testing.T, name string, public crypto.PublicKey, usage x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, a.certificate, public, a.key)
	if err != nil {
		t.Fatalf("issue a certificate for %s: %v", name, err)
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatalf("parse the certificate for %s: %v", name, err)
	}
	return certificate
}

func request(t *testing.T, key pki.Key, name string) *x509.CertificateRequest {
	t.Helper()
	signed, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	if err != nil {
		t.Fatalf("sign a certificate request with the key: %v", err)
	}
	asked, err := x509.ParseCertificateRequest(signed)
	if err != nil {
		t.Fatalf("parse the certificate request: %v", err)
	}
	return asked
}

func handshake(t *testing.T, server, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	near, far := net.Pipe()
	defer near.Close()
	accepted := tls.Server(far, server)
	defer accepted.Close()
	served := make(chan error, 1)
	go func() { served <- accepted.HandshakeContext(ctx) }()
	connecting := tls.Client(near, client)
	err := connecting.HandshakeContext(ctx)
	drained := make(chan error, 1)
	go func() {
		_, read := io.Copy(io.Discard, connecting)
		drained <- read
	}()
	err = errors.Join(err, <-served)
	near.Close()
	if read := <-drained; err == nil && read != nil && !errors.Is(read, io.ErrClosedPipe) {
		err = read
	}
	return accepted.ConnectionState(), err
}

func digest(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
