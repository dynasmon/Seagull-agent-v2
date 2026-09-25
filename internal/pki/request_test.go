package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
)

func TestARequestNamesTheAgentAndProvesTheKeyAndNothingElse(t *testing.T) {
	directory := keysDirectory(t)
	key := create(t, openKeys(t, directory))
	written, err := pki.Request(key, "web-01")
	if err != nil {
		t.Fatalf("make the request: %v", err)
	}
	block, rest := pem.Decode(written)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) > 0 || len(rest) > 0 {
		t.Fatalf("the request is not one PEM certificate request:\n%s", written)
	}
	asked, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse the request: %v", err)
	}
	if err := asked.CheckSignature(); err != nil {
		t.Fatalf("the request is not signed by the key it carries: %v", err)
	}
	switch {
	case asked.Subject.String() != "CN=web-01":
		t.Errorf("the request asks to be %s", asked.Subject)
	case digest(asked.RawSubjectPublicKeyInfo) != key.ID():
		t.Errorf("the request carries key %s, it was made with %s", digest(asked.RawSubjectPublicKeyInfo), key.ID())
	case asked.SignatureAlgorithm != x509.ECDSAWithSHA256:
		t.Errorf("the request is signed with %s", asked.SignatureAlgorithm)
	case len(asked.Extensions) > 0 || len(asked.DNSNames) > 0 || len(asked.IPAddresses) > 0 || len(asked.EmailAddresses) > 0 || len(asked.URIs) > 0:
		t.Errorf("the request asks for more than the agent: %v", asked.Extensions)
	}
	if exposes(string(written), readKey(t, directory, key.ID())) {
		t.Fatal("the request carries the key")
	}
}
