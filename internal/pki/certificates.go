package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxChain         = 8
	certificateBlock = "CERTIFICATE"
	maxChainBytes    = 64 << 10
)

var (
	ErrCertificateMissing  = errors.New("the certificate does not exist")
	ErrCertificateDamaged  = errors.New("the certificate is damaged")
	ErrCertificateInsecure = errors.New("the certificate is not private to the account the agent runs as")
)

// CertificateFiles keeps the chains the platform issued for the installation's
// keys, each as the PEM certificates of one chain, leaf first, in a file named
// after the fingerprint of its leaf. A certificate is public: the directory is
// private so that no other account decides what the agent presents.
type CertificateFiles struct {
	directory *os.Root
}

func OpenCertificateFiles(directory *os.Root) (*CertificateFiles, error) {
	if err := settle(directory, ErrCertificateInsecure); err != nil {
		return nil, err
	}
	return &CertificateFiles{directory: directory}, nil
}

// Store keeps chain, leaf first, under the fingerprint of its leaf and returns
// that fingerprint once the chain is durable. A chain already kept is left as
// it is; whatever else a file of that name holds is replaced.
func (c *CertificateFiles) Store(chain [][]byte) (string, error) {
	written, err := encodeChain(chain)
	if err != nil {
		return "", err
	}
	fingerprint := Fingerprint(chain[0])
	name := fingerprint + keySuffix
	if held, err := c.read(name); err == nil && bytes.Equal(held, written) {
		return fingerprint, nil
	}
	temporary := "." + name + ".tmp"
	file, err := c.directory.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("write %s: %w", c.path(name), err)
	}
	_, err = file.Write(written)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = c.directory.Rename(temporary, name)
	}
	if err != nil {
		return "", errors.Join(fmt.Errorf("write %s: %w", c.path(name), err), ignoreMissing(c.directory.Remove(temporary)))
	}
	if err := syncDirectory(c.directory); err != nil {
		return "", err
	}
	return fingerprint, nil
}

// Open returns the chain whose leaf fingerprint names, leaf first, and refuses
// a file that holds anything but the chain Store kept under that name.
func (c *CertificateFiles) Open(fingerprint string) ([][]byte, error) {
	if !keyIDPattern.MatchString(fingerprint) {
		return nil, fmt.Errorf("%s is not a certificate fingerprint", secrets.Shown(fingerprint))
	}
	name := fingerprint + keySuffix
	content, err := c.read(name)
	if err != nil {
		return nil, err
	}
	chain, err := decodeChain(content)
	if err == nil && Fingerprint(chain[0]) != fingerprint {
		err = fmt.Errorf("holds certificate %s", Fingerprint(chain[0]))
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s %v", ErrCertificateDamaged, c.path(name), err)
	}
	return chain, nil
}

// Fingerprint names a certificate by the SHA-256 digest of its DER encoding, in
// lower-case hexadecimal, as the platform records the certificates it issues.
func Fingerprint(certificate []byte) string {
	digest := sha256.Sum256(certificate)
	return hex.EncodeToString(digest[:])
}

func (c *CertificateFiles) read(name string) ([]byte, error) {
	path := c.path(name)
	described, err := c.directory.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%w: there is no %s", ErrCertificateMissing, path)
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrCertificateDamaged, path)
	}
	if err := private(path, described, ErrCertificateInsecure); err != nil {
		return nil, err
	}
	file, err := c.directory.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return nil, fmt.Errorf("%w: %s changed while it was being opened", ErrCertificateInsecure, path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxChainBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxChainBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrCertificateDamaged, path, maxChainBytes)
	}
	return content, nil
}

func (c *CertificateFiles) path(name string) string { return filepath.Join(c.directory.Name(), name) }

func encodeChain(chain [][]byte) ([]byte, error) {
	if len(chain) == 0 || len(chain) > MaxChain {
		return nil, fmt.Errorf("a chain of %d certificates is not one the agent keeps, which holds 1 to %d", len(chain), MaxChain)
	}
	var written []byte
	for _, certificate := range chain {
		if _, err := x509.ParseCertificate(certificate); err != nil {
			return nil, fmt.Errorf("the chain holds a block that is not a certificate: %s", secrets.Bounded(err.Error()))
		}
		written = append(written, pem.EncodeToMemory(&pem.Block{Type: certificateBlock, Bytes: certificate})...)
	}
	return written, nil
}

func decodeChain(content []byte) ([][]byte, error) {
	var chain [][]byte
	for rest := content; len(rest) > 0; {
		if len(chain) == MaxChain {
			return nil, fmt.Errorf("holds more than %d certificates", MaxChain)
		}
		block, remainder := pem.Decode(rest)
		switch {
		case block == nil:
			return nil, errors.New("holds something that is not a PEM certificate")
		case block.Type != certificateBlock || len(block.Headers) > 0:
			return nil, fmt.Errorf("holds a %s block, not a certificate", secrets.Shown(block.Type))
		}
		chain = append(chain, block.Bytes)
		rest = remainder
	}
	written, err := encodeChain(chain)
	switch {
	case err != nil:
		return nil, err
	case !bytes.Equal(written, content):
		return nil, errors.New("holds more than the chain")
	}
	return chain, nil
}

func ignoreMissing(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
