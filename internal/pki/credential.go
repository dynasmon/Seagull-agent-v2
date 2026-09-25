package pki

import (
	"crypto/x509"
	"fmt"
)

// A Credential is what an installation authenticates with: one of its keys,
// and the chain the platform issued for that key, leaf first.
type Credential struct {
	Key   Key
	Chain [][]byte
}

// OpenCredential opens the key keyID names and the chain fingerprint names,
// and returns them only when that chain was issued for that key.
func OpenCredential(keys KeyProvider, certificates *CertificateFiles, keyID, fingerprint string) (Credential, error) {
	key, err := keys.Open(keyID)
	if err != nil {
		return Credential{}, err
	}
	chain, err := certificates.Open(fingerprint)
	if err != nil {
		return Credential{}, err
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return Credential{}, fmt.Errorf("%w: %s holds no certificate", ErrCertificateDamaged, certificates.path(fingerprint+keySuffix))
	}
	if certified, err := KeyID(leaf.PublicKey); err != nil || certified != keyID {
		return Credential{}, fmt.Errorf("%w: %s was not issued for key %s", ErrCertificateDamaged, certificates.path(fingerprint+keySuffix), keyID)
	}
	return Credential{Key: key, Chain: chain}, nil
}
