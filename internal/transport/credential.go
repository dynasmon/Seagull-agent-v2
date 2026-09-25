package transport

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

// A Credential is what the agent authenticates with: the certificate chain the
// platform issued, leaf first, and the key it was issued for, which signs the
// handshake through crypto.Signer alone and is never handed over whole.
type Credential struct {
	Chain  [][]byte
	Signer crypto.Signer
}

type Credentials interface {
	Credential() (Credential, error)
}

func (c *Client) present() error {
	if c.options.Credentials == nil {
		c.current.Load().transport.CloseIdleConnections()
		return fmt.Errorf("%w: the installation is not enrolled", ErrUnauthenticated)
	}
	held, err := c.options.Credentials.Credential()
	var certificate tls.Certificate
	if err == nil {
		certificate, err = usable(held, time.Now())
	}
	if err != nil {
		c.current.Load().transport.CloseIdleConnections()
		return fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if previous := c.presented.Swap(&certificate); previous != nil && !bytes.Equal(previous.Certificate[0], certificate.Certificate[0]) {
		c.current.Load().transport.CloseIdleConnections()
	}
	return nil
}

func (c *Client) certificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if held := c.presented.Load(); held != nil {
		return held, nil
	}
	return &tls.Certificate{}, nil
}

func usable(held Credential, now time.Time) (tls.Certificate, error) {
	if len(held.Chain) == 0 || held.Signer == nil {
		return tls.Certificate{}, errors.New("the credential holds no certificate or no key")
	}
	leaf, err := x509.ParseCertificate(held.Chain[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("the credential holds no certificate: %s", secrets.Bounded(err.Error()))
	}
	for _, issuer := range held.Chain[1:] {
		if _, err := x509.ParseCertificate(issuer); err != nil {
			return tls.Certificate{}, fmt.Errorf("the credential's chain holds a block that is not a certificate: %s", secrets.Bounded(err.Error()))
		}
	}
	public, comparable := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	switch {
	case !comparable || !public.Equal(held.Signer.Public()):
		return tls.Certificate{}, errors.New("the certificate was not issued for the agent's key")
	case now.Before(leaf.NotBefore):
		return tls.Certificate{}, fmt.Errorf("the certificate is valid from %s, and the clock says %s", leaf.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	case !now.Before(leaf.NotAfter):
		return tls.Certificate{}, fmt.Errorf("the certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	case len(leaf.ExtKeyUsage) > 0 && !slices.ContainsFunc(leaf.ExtKeyUsage, func(usage x509.ExtKeyUsage) bool {
		return usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny
	}):
		return tls.Certificate{}, errors.New("the certificate does not authenticate a client")
	case leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0:
		return tls.Certificate{}, errors.New("the certificate does not let its key sign")
	}
	return tls.Certificate{Certificate: held.Chain, PrivateKey: held.Signer, Leaf: leaf}, nil
}
