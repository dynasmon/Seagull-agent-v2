package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

const (
	keyBlock    = "PRIVATE KEY"
	keySuffix   = ".pem"
	maxKeyBytes = 4 << 10
)

var (
	keyIDPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	interruptedPattern = regexp.MustCompile(`^\.[0-9a-f]{64}\.pem\.tmp$`)
)

var _ KeyProvider = (*KeyFiles)(nil)

// KeyFiles keeps each key as an unencrypted PKCS #8 ECDSA P-256 key in a file
// named after its identifier, in a directory private to the account the agent
// runs as. That account, and any account that can act as it, can read a key
// out of its file: the protection is the file's, not the key's.
type KeyFiles struct {
	directory *os.Root
}

func OpenKeyFiles(directory *os.Root) (*KeyFiles, error) {
	described, err := directory.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", directory.Name(), err)
	}
	if err := private(directory.Name(), described); err != nil {
		return nil, err
	}
	keys := &KeyFiles{directory: directory}
	names, err := keys.names()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if interruptedPattern.MatchString(name) {
			if err := directory.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("discard the interrupted write %s: %w", keys.path(name), err)
			}
			continue
		}
		described, err := directory.Lstat(name)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", keys.path(name), err)
		}
		if described.Mode().IsRegular() {
			if err := private(keys.path(name), described); err != nil {
				return nil, err
			}
		}
	}
	return keys, nil
}

func (k *KeyFiles) Create() (Key, error) {
	drawn, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate a key: %w", err)
	}
	id, err := KeyID(drawn.Public())
	if err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(drawn)
	if err != nil {
		return nil, fmt.Errorf("encode key %s: %w", id, err)
	}
	name := id + keySuffix
	temporary := "." + name + ".tmp"
	file, err := k.directory.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("write %s: %w", k.path(name), err)
	}
	_, err = file.Write(pem.EncodeToMemory(&pem.Block{Type: keyBlock, Bytes: encoded}))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = k.directory.Link(temporary, name)
	}
	if err = errors.Join(err, k.directory.Remove(temporary)); err == nil {
		err = k.sync()
	}
	if err != nil {
		return nil, fmt.Errorf("write %s: %w", k.path(name), err)
	}
	return &key{id: id, signer: drawn}, nil
}

func (k *KeyFiles) Open(id string) (Key, error) {
	if !keyIDPattern.MatchString(id) {
		return nil, fmt.Errorf("%q is not a key identifier", id)
	}
	name := id + keySuffix
	path := k.path(name)
	described, err := k.directory.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%w: there is no %s", ErrKeyMissing, path)
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrKeyDamaged, path)
	}
	if err := private(path, described); err != nil {
		return nil, err
	}
	file, err := k.directory.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return nil, fmt.Errorf("%w: %s changed while it was being opened", ErrKeyInsecure, path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	signer, err := decode(content, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %v", ErrKeyDamaged, path, err)
	}
	return &key{id: id, signer: signer}, nil
}

func (k *KeyFiles) Posture() Posture {
	return Posture{Provider: "filesystem", Exportable: true}
}

func decode(content []byte, id string) (*ecdsa.PrivateKey, error) {
	if len(content) > maxKeyBytes {
		return nil, fmt.Errorf("is larger than %d bytes", maxKeyBytes)
	}
	block, rest := pem.Decode(content)
	switch {
	case block == nil:
		return nil, errors.New("holds no PEM block")
	case block.Type != keyBlock || len(block.Headers) > 0:
		return nil, fmt.Errorf("holds a %q block, not an unencrypted PKCS #8 key", block.Type)
	case len(rest) > 0:
		return nil, errors.New("holds more than the key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("holds no PKCS #8 key: %v", err)
	}
	decoded, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || decoded.Curve != elliptic.P256() {
		return nil, errors.New("holds a key that is not ECDSA P-256")
	}
	held, err := KeyID(decoded.Public())
	if err != nil {
		return nil, err
	}
	if held != id {
		return nil, fmt.Errorf("holds key %s", held)
	}
	return decoded, nil
}

func (k *KeyFiles) names() ([]string, error) {
	directory, err := k.directory.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", k.directory.Name(), err)
	}
	defer directory.Close()
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", k.directory.Name(), err)
	}
	return names, nil
}

func (k *KeyFiles) sync() error {
	directory, err := k.directory.Open(".")
	if err != nil {
		return fmt.Errorf("open %s: %w", k.directory.Name(), err)
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return fmt.Errorf("sync %s: %w", k.directory.Name(), err)
	}
	return nil
}

func (k *KeyFiles) path(name string) string { return filepath.Join(k.directory.Name(), name) }

func private(path string, described fs.FileInfo) error {
	if err := files.Private(described); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return fmt.Errorf("keep keys in %s: %w", path, err)
		}
		return fmt.Errorf("%w: %s %v", ErrKeyInsecure, path, err)
	}
	return nil
}
