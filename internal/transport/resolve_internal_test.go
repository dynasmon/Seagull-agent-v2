package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A name server that reads every question and answers none, as one that is
// down or dropped behind a firewall looks to the agent.
func TestResolvingTheListenerTakesNoLongerThanConnectingToIt(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { silent.Close() })
	var asked atomic.Int32
	go func() {
		question := make([]byte, 512)
		for {
			if _, _, err := silent.ReadFrom(question); err != nil {
				return
			}
			asked.Add(1)
		}
	}()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", silent.LocalAddr().String())
	}}
	authority, credential := enrolled(t)
	client, err := compose(Options{
		Authorities:      []*x509.Certificate{authority},
		Credentials:      credential,
		ConnectTimeout:   time.Second,
		RequestTimeout:   30 * time.Second,
		MaxResponseBytes: 1 << 10,
		MaxConnections:   1,
	}, resolver)
	if err != nil {
		t.Fatalf("compose the transport: %v", err)
	}
	t.Cleanup(client.Close)

	for name, reach := range map[string]func() error{
		"a request": func() error {
			_, err := client.Post(t.Context(), Request{URL: "https://gateway.seagull.test:8443/v1/events", ContentType: "application/x-protobuf", Body: bytes.NewReader([]byte("batch")), Length: 5})
			return err
		},
		"a check": func() error {
			_, err := client.Check(t.Context(), "https://gateway.seagull.test:8443")
			return err
		},
	} {
		began := time.Now()
		err := reach()
		if took := time.Since(began); !errors.Is(err, ErrUnreachable) || took > 3*time.Second {
			t.Fatalf("%s to a name nobody resolves returned %v after %s, with a connect timeout of 1s", name, err, took)
		}
	}
	if asked.Load() == 0 {
		t.Fatal("nothing asked the name server for the listener's name")
	}
}

type credential struct{ held Credential }

func (c credential) Credential() (Credential, error) { return c.held, nil }

func enrolled(t *testing.T) (*x509.Certificate, credential) {
	t.Helper()
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Seagull platform"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signing.Public(), signing)
	if err != nil {
		t.Fatalf("sign the authority: %v", err)
	}
	authority, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the authority: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	leaf, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "web-01"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, authority, key.Public(), signing)
	if err != nil {
		t.Fatalf("issue the agent's certificate: %v", err)
	}
	return authority, credential{held: Credential{Chain: [][]byte{leaf}, Signer: key}}
}
