package enrollment

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const (
	MaxIssuedBytes = 256 << 10
	maxPublished   = 64
	maxSerialBytes = 32
)

type Expected struct {
	AgentID string
	KeyID   string
}

type Issued struct {
	Chain       [][]byte
	Certificate identity.Certificate
	Issuer      string
	Published   []*x509.Certificate
}

type answer struct {
	leaf      *x509.Certificate
	chain     []*x509.Certificate
	published []*x509.Certificate
	recorded  *agentv1.Identity
}

// Verify reads what the platform answered a certificate request with, a
// seagull.agent.v1.IssuedCertificate, and returns the chain it issued only when
// its certificate names the agent and the key expected, authenticates a client,
// is valid at now and chains to one of authorities, and when what the platform
// recorded of it is that certificate. The authorities the answer publishes are
// returned as read, and never trusted for it.
func Verify(issued []byte, expected Expected, authorities []*x509.Certificate, now time.Time) (Issued, error) {
	answered, err := read(issued)
	if err != nil {
		return Issued{}, err
	}
	return answered.verify(expected, authorities, now)
}

func read(issued []byte) (answer, error) {
	if len(issued) > MaxIssuedBytes {
		return answer{}, fmt.Errorf("%w: it is larger than %d bytes", ErrUnreadable, MaxIssuedBytes)
	}
	var message agentv1.IssuedCertificate
	if err := proto.Unmarshal(issued, &message); err != nil {
		return answer{}, fmt.Errorf("%w: it is not a %s: %s", ErrUnreadable, message.ProtoReflect().Descriptor().FullName(), secrets.Bounded(err.Error()))
	}
	leaves, err := certificates("certificate_pem", message.GetCertificatePem(), 1, false)
	if err == nil && len(leaves) == 0 {
		err = errors.New("certificate_pem holds no certificate")
	}
	if err != nil {
		return answer{}, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	chain, err := certificates("chain_pem", message.GetChainPem(), pki.MaxChain-1, true)
	if err != nil {
		return answer{}, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	published, err := certificates("trust_bundle_pem", message.GetTrustBundlePem(), maxPublished, true)
	if err == nil && len(published) == 0 {
		err = errors.New("trust_bundle_pem holds no authority")
	}
	if err != nil {
		return answer{}, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	if message.GetIdentity() == nil {
		return answer{}, fmt.Errorf("%w: it carries no identity, which is what the platform recorded of the certificate", ErrUnreadable)
	}
	return answer{leaf: leaves[0], chain: chain, published: published, recorded: message.GetIdentity()}, nil
}

func (a answer) verify(expected Expected, authorities []*x509.Certificate, now time.Time) (Issued, error) {
	leaf := a.leaf
	certified, err := pki.KeyID(leaf.PublicKey)
	switch {
	case err != nil:
		return Issued{}, fmt.Errorf("%w: it was issued for a key the agent does not draw, and the installation asked with key %s", ErrMismatched, expected.KeyID)
	case certified != expected.KeyID:
		return Issued{}, fmt.Errorf("%w: it was issued for key %s, and the installation asked with key %s", ErrMismatched, certified, expected.KeyID)
	case leaf.Subject.CommonName != expected.AgentID:
		return Issued{}, fmt.Errorf("%w: it was issued for agent %s, and the installation asked to be %s",
			ErrMismatched, secrets.Shown(leaf.Subject.CommonName), secrets.Shown(expected.AgentID))
	}
	serial := leaf.SerialNumber.Bytes()
	switch {
	case leaf.IsCA:
		return Issued{}, fmt.Errorf("%w: it is the certificate of an authority, not of an agent", ErrUntrusted)
	case len(leaf.ExtKeyUsage) > 0 && !slices.ContainsFunc(leaf.ExtKeyUsage, func(usage x509.ExtKeyUsage) bool {
		return usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny
	}):
		return Issued{}, fmt.Errorf("%w: it does not authenticate a client", ErrUntrusted)
	case leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0:
		return Issued{}, fmt.Errorf("%w: it does not let its key sign", ErrUntrusted)
	case leaf.SerialNumber.Sign() <= 0 || len(serial) > maxSerialBytes:
		return Issued{}, fmt.Errorf("%w: its serial is not one a certificate authority issues", ErrUntrusted)
	case now.Before(leaf.NotBefore):
		return Issued{}, fmt.Errorf("%w: it is valid from %s, and the clock says %s",
			ErrNotCurrent, leaf.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	case !now.Before(leaf.NotAfter):
		return Issued{}, fmt.Errorf("%w: it expired at %s, and the clock says %s",
			ErrNotCurrent, leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, authority := range authorities {
		roots.AddCert(authority)
	}
	for _, authority := range a.chain {
		intermediates.AddCert(authority)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return Issued{}, fmt.Errorf("%w: %s", ErrUntrusted, secrets.Bounded(err.Error()))
	}
	held := identity.Certificate{
		Subject:           leaf.Subject.CommonName,
		Serial:            hex.EncodeToString(serial),
		FingerprintSHA256: pki.Fingerprint(leaf.Raw),
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
	}
	if err := agrees(a.recorded, held); err != nil {
		return Issued{}, fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	chain := [][]byte{leaf.Raw}
	for _, authority := range a.chain {
		chain = append(chain, authority.Raw)
	}
	return Issued{Chain: chain, Certificate: held, Issuer: leaf.Issuer.CommonName, Published: a.published}, nil
}

func agrees(recorded *agentv1.Identity, held identity.Certificate) error {
	switch {
	case recorded.GetSubject() != held.Subject:
		return fmt.Errorf("the platform recorded it for %s, and it names %s", secrets.Shown(recorded.GetSubject()), secrets.Shown(held.Subject))
	case recorded.GetSerial() != held.Serial:
		return fmt.Errorf("the platform recorded serial %s, and it carries %s", secrets.Shown(recorded.GetSerial()), held.Serial)
	case recorded.GetFingerprintSha256() != held.FingerprintSHA256:
		return fmt.Errorf("the platform recorded fingerprint %s, and it is %s", secrets.Shown(recorded.GetFingerprintSha256()), held.FingerprintSHA256)
	case !recorded.GetIssuedAt().AsTime().Equal(held.NotBefore) || !recorded.GetExpiresAt().AsTime().Equal(held.NotAfter):
		return fmt.Errorf("the platform recorded it valid from %s to %s, and it is valid from %s to %s",
			recorded.GetIssuedAt().AsTime().UTC().Format(time.RFC3339), recorded.GetExpiresAt().AsTime().UTC().Format(time.RFC3339),
			held.NotBefore.Format(time.RFC3339), held.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func certificates(field string, content []byte, most int, authorities bool) ([]*x509.Certificate, error) {
	var held []*x509.Certificate
	for rest := content; len(bytes.TrimSpace(rest)) > 0; {
		if len(held) == most && most == 1 {
			return nil, fmt.Errorf("%s holds more than one certificate", field)
		}
		if len(held) == most {
			return nil, fmt.Errorf("%s holds more than %d certificates", field, most)
		}
		block, remainder := pem.Decode(rest)
		switch {
		case block == nil:
			return nil, fmt.Errorf("%s holds something that is not PEM", field)
		case block.Type != "CERTIFICATE" || len(block.Headers) > 0:
			return nil, fmt.Errorf("%s holds a %s block, not a certificate", field, secrets.Shown(block.Type))
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s holds a block that is not a certificate: %s", field, secrets.Bounded(err.Error()))
		}
		if authorities && (!parsed.BasicConstraintsValid || !parsed.IsCA) {
			return nil, fmt.Errorf("%s holds %s, which is not a certificate authority", field, secrets.Shown(parsed.Subject.CommonName))
		}
		held = append(held, parsed)
		rest = remainder
	}
	return held, nil
}
