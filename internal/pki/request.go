package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
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

// MadeBy says whether a request is one key made to be agentID, so that a request
// kept while it waits for its certificate is sent again byte for byte, and a
// request that is anything else is made anew.
func MadeBy(request []byte, key Key, agentID string) error {
	block, rest := pem.Decode(request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) > 0 || len(rest) > 0 {
		return errors.New("it is not one PEM certificate request")
	}
	asked, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("it is not a certificate request: %s", secrets.Bounded(err.Error()))
	}
	if err := asked.CheckSignature(); err != nil {
		return fmt.Errorf("it is not signed by the key it carries: %s", secrets.Bounded(err.Error()))
	}
	carried, err := KeyID(asked.PublicKey)
	switch {
	case err != nil:
		return err
	case carried != key.ID():
		return fmt.Errorf("it carries key %s, not %s", carried, key.ID())
	case asked.Subject.String() != "CN="+agentID:
		return fmt.Errorf("it asks to be %s, not agent %s", secrets.Shown(asked.Subject.String()), secrets.Shown(agentID))
	}
	return nil
}
