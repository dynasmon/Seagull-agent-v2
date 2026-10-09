// Package enrollment gives an installation the identity an operator has the
// platform issue it. The installation asks for a certificate with a key it
// drew itself, and activates only the certificate issued for that request once
// it verifies against the authorities the agent already trusts. It reaches no
// host: the request and the certificate travel through the operator, whose
// credentials never reach the endpoint.
package enrollment

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
)

var (
	ErrNotAsked   = errors.New("the installation asked for no certificate")
	ErrUnreadable = errors.New("what was imported is not a certificate the platform issued")
	ErrMismatched = errors.New("the certificate was not issued for the request the installation made")
	ErrUntrusted  = errors.New("the certificate does not verify against the authorities the agent trusts")
	ErrNotCurrent = errors.New("the certificate is not valid at this moment")
)

type Asked struct {
	AgentID   string
	KeyID     string
	Request   []byte
	Again     bool
	Abandoned string
}

type Imported struct {
	Enrollment identity.Enrollment
	Issuer     string
	Already    bool
	Unheld     []*x509.Certificate
}

// Request asks for a certificate as agentID with a key drawn for it, and
// records the request before it returns it. Asking again for the same agent
// makes the same request, byte for byte, so a request lost on its way to the
// platform costs nothing; asking for another agent draws another key, as
// does asking again once the key of the request is gone, since a key nothing
// was issued for yet is no identity.
func Request(installation *identity.Installation, keys pki.KeyProvider, agentID string, now time.Time) (Asked, error) {
	if err := installation.MayAsk(agentID); err != nil {
		return Asked{}, err
	}
	var abandoned string
	if pending, ok := installation.Pending(); ok && pending.AgentID == agentID {
		key, err := keys.Open(pending.KeyID)
		switch {
		case err == nil:
			signed, err := Kept(installation, pending, key)
			if err != nil {
				return Asked{}, err
			}
			return Asked{AgentID: agentID, KeyID: key.ID(), Request: signed, Again: true}, nil
		case !errors.Is(err, pki.ErrKeyMissing) && !errors.Is(err, pki.ErrKeyDamaged):
			return Asked{}, err
		}
		abandoned = pending.KeyID
	}
	key, err := keys.Create()
	if err != nil {
		return Asked{}, err
	}
	signed, err := pki.Request(key, agentID)
	if err != nil {
		return Asked{}, err
	}
	if err := installation.Ask(identity.Request{AgentID: agentID, KeyID: key.ID(), CSR: string(signed), RequestedAt: now.UTC()}); err != nil {
		return Asked{}, err
	}
	return Asked{AgentID: agentID, KeyID: key.ID(), Request: signed, Abandoned: abandoned}, nil
}

// Kept is the request to send for a pending request whose key the installation
// holds: the bytes it kept, when that key made them to be the agent, since the
// same bytes tell a request asked again from anybody else holding the key; and
// otherwise a request made anew, kept before it is returned.
func Kept(installation *identity.Installation, pending identity.Request, key pki.Key) ([]byte, error) {
	if pki.MadeBy([]byte(pending.CSR), key, pending.AgentID) == nil {
		return []byte(pending.CSR), nil
	}
	signed, err := pki.Request(key, pending.AgentID)
	if err != nil {
		return nil, err
	}
	pending.CSR = string(signed)
	if err := installation.Ask(pending); err != nil {
		return nil, err
	}
	return signed, nil
}

// Import activates the certificate the platform issued for the pending
// request as the installation's next credential generation, once it is kept
// beside its key. Importing the certificate of the active generation again
// changes nothing but restoring its file, so an import interrupted anywhere
// is completed by running it again.
func Import(installation *identity.Installation, keys pki.KeyProvider, certificates *pki.CertificateFiles, authorities []*x509.Certificate, issued []byte, now time.Time) (Imported, error) {
	answered, err := read(issued)
	if err != nil {
		return Imported{}, err
	}
	active, enrolled := installation.Enrollment()
	if enrolled && pki.Fingerprint(answered.leaf.Raw) == active.Certificate.FingerprintSHA256 {
		verified, err := answered.verify(Expected{AgentID: active.AgentID, KeyID: active.KeyID}, authorities, now)
		if err != nil {
			return Imported{}, err
		}
		if _, err := certificates.Store(verified.Chain); err != nil {
			return Imported{}, err
		}
		return Imported{Enrollment: active, Issuer: verified.Issuer, Already: true, Unheld: unheld(verified.Published, authorities)}, nil
	}
	pending, asked := installation.Pending()
	switch {
	case !asked && enrolled:
		return Imported{}, fmt.Errorf("%w: credential generation %d is active, and nothing was asked for since", ErrNotAsked, active.Generation)
	case !asked:
		return Imported{}, fmt.Errorf("%w: it is not enrolled and holds no request", ErrNotAsked)
	}
	verified, err := answered.verify(Expected{AgentID: pending.AgentID, KeyID: pending.KeyID}, authorities, now)
	if err != nil {
		return Imported{}, err
	}
	if _, err := keys.Open(pending.KeyID); err != nil {
		return Imported{}, err
	}
	if _, err := certificates.Store(verified.Chain); err != nil {
		return Imported{}, err
	}
	next := identity.Enrollment{AgentID: pending.AgentID, Generation: 1, KeyID: pending.KeyID, KeyDrawnAt: pending.RequestedAt, Certificate: verified.Certificate}
	if enrolled {
		next.Generation = active.Generation + 1
	}
	if enrolled && pending.KeyID == active.KeyID {
		next.KeyDrawnAt = active.KeyDrawnAt
	}
	if err := installation.Activate(next); err != nil {
		return Imported{}, err
	}
	return Imported{Enrollment: next, Issuer: verified.Issuer, Unheld: unheld(verified.Published, authorities)}, nil
}

func unheld(published, authorities []*x509.Certificate) []*x509.Certificate {
	var missing []*x509.Certificate
	for _, authority := range published {
		if !slices.ContainsFunc(authorities, authority.Equal) {
			missing = append(missing, authority)
		}
	}
	return missing
}
