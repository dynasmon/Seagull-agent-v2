package architecture_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Each parser reads one form a credential or an identity takes once it is
// encoded: a certificate, which would be an identity or an authority the build
// brought with it, and a private key in each encoding x509 reads.
var credentialForms = []struct {
	name  string
	reads func([]byte) error
}{
	{"a certificate", func(der []byte) error { _, err := x509.ParseCertificate(der); return err }},
	{"a PKCS #8 private key", func(der []byte) error { _, err := x509.ParsePKCS8PrivateKey(der); return err }},
	{"an EC private key", func(der []byte) error { _, err := x509.ParseECPrivateKey(der); return err }},
	{"a PKCS #1 private key", func(der []byte) error { _, err := x509.ParsePKCS1PrivateKey(der); return err }},
}

// Every PEM block, and every DER structure one of the forms above reads, found
// anywhere in the bytes of a build. pem.Decode only finds a block that starts
// a line, and one embedded in a binary follows whatever the linker put before
// it, so each block is decoded from its own first byte, up to the next.
func credentialsIn(content []byte) []string {
	var found []string
	begins := []byte("-----BEGIN ")
	for start := bytes.Index(content, begins); start >= 0; {
		end, next := len(content), -1
		if after := bytes.Index(content[start+len(begins):], begins); after >= 0 {
			end, next = start+len(begins)+after, start+len(begins)+after
		}
		if block, _ := pem.Decode(content[start:end]); block != nil {
			found = append(found, fmt.Sprintf("a PEM %s block at byte %d", block.Type, start))
		}
		start = next
	}
	for offset := range content {
		der, ok := sequenceAt(content[offset:])
		if !ok {
			continue
		}
		for _, form := range credentialForms {
			if form.reads(der) == nil {
				found = append(found, fmt.Sprintf("%s at byte %d", form.name, offset))
			}
		}
	}
	return found
}

// The DER SEQUENCE starting the bytes, when its length fits within them and is
// long enough to hold a key or a certificate.
func sequenceAt(content []byte) ([]byte, bool) {
	if len(content) < 2 || content[0] != 0x30 {
		return nil, false
	}
	size, header := int(content[1]), 2
	if content[1] >= 0x80 {
		octets := int(content[1] & 0x7f)
		if octets == 0 || octets > 3 || len(content) < 2+octets {
			return nil, false
		}
		size = 0
		for _, octet := range content[2 : 2+octets] {
			size = size<<8 | int(octet)
		}
		header += octets
	}
	if size < 32 || header+size > len(content) {
		return nil, false
	}
	return content[:header+size], true
}

func TestACredentialInABuildIsRecognised(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encode the key: %v", err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("encode the key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "web-01"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("sign a certificate: %v", err)
	}
	filler := bytes.Repeat([]byte("\x00\x30\x82\xff\xff-----BEGIN \x30\x81"), 64)
	cases := map[string]struct {
		content []byte
		want    []string
	}{
		"nothing but code": {content: filler},
		"a key written as PEM": {
			content: slices.Concat(filler, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), filler),
			want:    []string{fmt.Sprintf("a PEM PRIVATE KEY block at byte %d", len(filler))},
		},
		"an authority written as PEM": {
			content: slices.Concat(filler, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("anything")})),
			want:    []string{fmt.Sprintf("a PEM CERTIFICATE block at byte %d", len(filler))},
		},
		"a key and a certificate embedded as DER": {
			content: slices.Concat(filler, sec1, filler, certificate),
			want: []string{
				fmt.Sprintf("an EC private key at byte %d", len(filler)),
				fmt.Sprintf("a certificate at byte %d", 2*len(filler)+len(sec1)),
			},
		},
	}
	for name, c := range cases {
		if found := credentialsIn(c.content); !slices.Equal(found, c.want) {
			t.Errorf("%s: found %q, want %q", name, found, c.want)
		}
	}
}

// An installation draws its own key and is issued its certificate on the host
// it runs on, and the platform's authority reaches it through its settings. So
// no build carries a key, a certificate or an authority: a copy of the binary
// authenticates as no agent and trusts no platform of its own.
func TestNoBuildOfTheAgentCarriesACredential(t *testing.T) {
	root := moduleRoot(t)
	for _, goos := range platforms {
		built := filepath.Join(t.TempDir(), "seagull-agent")
		runWith(t, root, []string{"GOOS=" + goos, "GOARCH=amd64", "CGO_ENABLED=0"},
			"go", "build", "-trimpath", "-o", built, "./cmd/seagull-agent")
		content, err := os.ReadFile(built)
		if err != nil {
			t.Fatalf("read the agent built for %s: %v", goos, err)
		}
		for _, credential := range credentialsIn(content) {
			t.Errorf("the agent built for %s carries %s: a build holds no identity, key or authority, which each installation is given on its host",
				goos, credential)
		}
	}
}
