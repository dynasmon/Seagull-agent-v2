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
	files pemFiles
}

type pemFiles struct {
	directory *os.Root
	most      int
}

func OpenCertificateFiles(directory *os.Root) (*CertificateFiles, error) {
	if err := settle(directory, ErrCertificateInsecure); err != nil {
		return nil, err
	}
	return &CertificateFiles{files: pemFiles{directory: directory, most: MaxChain}}, nil
}

// Store keeps chain, leaf first, under the fingerprint of its leaf and returns
// that fingerprint once the chain is durable. A chain already kept is left as
// it is; whatever else a file of that name holds is replaced.
func (c *CertificateFiles) Store(chain [][]byte) (string, error) {
	if len(chain) == 0 {
		return "", errors.New("a chain of no certificate is not one the agent keeps")
	}
	fingerprint := Fingerprint(chain[0])
	return fingerprint, c.files.store(fingerprint, chain)
}

// Open returns the chain whose leaf fingerprint names, leaf first, and refuses
// a file that holds anything but the chain Store kept under that name.
func (c *CertificateFiles) Open(fingerprint string) ([][]byte, error) {
	if !keyIDPattern.MatchString(fingerprint) {
		return nil, fmt.Errorf("%s is not a certificate fingerprint", secrets.Shown(fingerprint))
	}
	return c.files.open(fingerprint, func(chain [][]byte) error {
		if Fingerprint(chain[0]) != fingerprint {
			return fmt.Errorf("holds certificate %s", Fingerprint(chain[0]))
		}
		return nil
	})
}

// Fingerprint names a certificate by the SHA-256 digest of its DER encoding, in
// lower-case hexadecimal, as the platform records the certificates it issues.
func Fingerprint(certificate []byte) string {
	digest := sha256.Sum256(certificate)
	return hex.EncodeToString(digest[:])
}

func (c *CertificateFiles) path(name string) string { return c.files.path(name) }

func (f pemFiles) store(digest string, certificates [][]byte) error {
	written, err := encodeChain(certificates, f.most)
	if err != nil {
		return err
	}
	name := digest + keySuffix
	if held, err := f.read(name); err == nil && bytes.Equal(held, written) {
		return nil
	}
	temporary := "." + name + ".tmp"
	file, err := f.directory.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", f.path(name), err)
	}
	_, err = file.Write(written)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = f.directory.Rename(temporary, name)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", f.path(name), err), ignoreMissing(f.directory.Remove(temporary)))
	}
	return syncDirectory(f.directory)
}

func (f pemFiles) open(digest string, named func([][]byte) error) ([][]byte, error) {
	name := digest + keySuffix
	content, err := f.read(name)
	if err != nil {
		return nil, err
	}
	certificates, err := decodeChain(content, f.most)
	if err == nil {
		err = named(certificates)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s %v", ErrCertificateDamaged, f.path(name), err)
	}
	return certificates, nil
}

func (f pemFiles) read(name string) ([]byte, error) {
	path := f.path(name)
	described, err := f.directory.Lstat(name)
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
	file, err := f.directory.Open(name)
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

func (f pemFiles) path(name string) string { return filepath.Join(f.directory.Name(), name) }

func encodeChain(chain [][]byte, most int) ([]byte, error) {
	if len(chain) == 0 || len(chain) > most {
		return nil, fmt.Errorf("%d certificates are not what the agent keeps together, which is 1 to %d", len(chain), most)
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

func decodeChain(content []byte, most int) ([][]byte, error) {
	var chain [][]byte
	for rest := content; len(rest) > 0; {
		if len(chain) == most {
			return nil, fmt.Errorf("holds more than %d certificates", most)
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
	written, err := encodeChain(chain, most)
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
