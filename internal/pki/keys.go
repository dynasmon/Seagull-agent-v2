package pki

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var (
	ErrKeyMissing  = errors.New("the key does not exist")
	ErrKeyDamaged  = errors.New("the key is damaged")
	ErrKeyInsecure = errors.New("the key is not private to the account the agent runs as")
)

// A Key proves the agent's identity by signing: a certificate request, or a
// TLS handshake. It is used through crypto.Signer alone, so what holds its
// private half never has to hand that half to a caller.
type Key interface {
	crypto.Signer
	ID() string
}

// A KeyProvider holds the keys of one installation. Create returns a key only
// once it is durable, and Open refuses a key that is damaged, reachable by
// another account or not the key its identifier names.
type KeyProvider interface {
	Create() (Key, error)
	Open(id string) (Key, error)
	Posture() Posture
}

type Posture struct {
	Provider   string
	Exportable bool
}

// KeyID names a public key by the SHA-256 digest of its DER-encoded
// SubjectPublicKeyInfo, the bytes a certificate request or a certificate for
// the key carries, in lower-case hexadecimal.
func KeyID(public crypto.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", fmt.Errorf("name the key: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

type key struct {
	id     string
	signer crypto.Signer
}

func (k *key) ID() string { return k.id }

func (k *key) Public() crypto.PublicKey { return k.signer.Public() }

func (k *key) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.signer.Sign(random, digest, opts)
}
