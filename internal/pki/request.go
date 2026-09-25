package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// Request is what the platform issues a certificate from: the agent the key
// asks to be, and the public half of the key, signed by the key to prove that
// the installation holds it. It carries nothing else, and no private key.
func Request(key Key, agentID string) ([]byte, error) {
	signed, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}, key)
	if err != nil {
		return nil, fmt.Errorf("sign a certificate request with key %s: %w", key.ID(), err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: signed}), nil
}
