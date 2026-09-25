package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const MaxAuthorities = 64

// AuthorityFiles keeps the sets of authorities the platform published to the
// agent to authenticate it with, each in a file named after its digest, so that
// the set an installation adopted names exactly one file.
type AuthorityFiles struct {
	files pemFiles
}

func OpenAuthorityFiles(directory *os.Root) (*AuthorityFiles, error) {
	if err := settle(directory, ErrCertificateInsecure); err != nil {
		return nil, err
	}
	return &AuthorityFiles{files: pemFiles{directory: directory, most: MaxAuthorities}}, nil
}

// ReadAuthorities opens the set digest names in directory and changes nothing,
// so it reads beside an agent that holds the directory without waiting for it.
func ReadAuthorities(directory *os.Root, digest string) ([]*x509.Certificate, error) {
	return (&AuthorityFiles{files: pemFiles{directory: directory, most: MaxAuthorities}}).Open(digest)
}

func (a *AuthorityFiles) Store(authorities []*x509.Certificate) (string, error) {
	held := make([][]byte, 0, len(authorities))
	for _, authority := range authorities {
		if !authority.BasicConstraintsValid || !authority.IsCA {
			return "", fmt.Errorf("%s is not a certificate authority", secrets.Shown(authority.Subject.CommonName))
		}
		held = append(held, authority.Raw)
	}
	digest := Digest(authorities)
	return digest, a.files.store(digest, held)
}

func (a *AuthorityFiles) Open(digest string) ([]*x509.Certificate, error) {
	if !keyIDPattern.MatchString(digest) {
		return nil, fmt.Errorf("%s is not the digest of a set of authorities", secrets.Shown(digest))
	}
	var authorities []*x509.Certificate
	_, err := a.files.open(digest, func(held [][]byte) error {
		for _, certificate := range held {
			parsed, err := x509.ParseCertificate(certificate)
			if err != nil {
				return errors.New("holds a block that is not a certificate")
			}
			if !parsed.BasicConstraintsValid || !parsed.IsCA {
				return fmt.Errorf("holds %s, which is not a certificate authority", secrets.Shown(parsed.Subject.CommonName))
			}
			authorities = append(authorities, parsed)
		}
		if held := Digest(authorities); held != digest {
			return fmt.Errorf("holds the authorities %s", held)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return authorities, nil
}

// Digest names a set of authorities by the SHA-256 digest of their DER
// encodings, in the order given, in lower-case hexadecimal.
func Digest(authorities []*x509.Certificate) string {
	digest := sha256.New()
	for _, authority := range authorities {
		digest.Write(authority.Raw)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
