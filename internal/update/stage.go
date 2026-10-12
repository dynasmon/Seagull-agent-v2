package update

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	offerFile     = "offer.pb"
	readyFile     = "ready"
	packageSuffix = ".deb"
)

var ErrUnverified = errors.New("the package is not the one the release names")

// Where the agent leaves a release for the installer: the offer it judged, the
// packages it fetched, each under its digest, and a mark written last, which is
// what starts the installer.
type Staging struct {
	root *os.Root
}

func OpenStaging(root *os.Root) *Staging { return &Staging{root: root} }

func PackageName(digest []byte) string { return hex.EncodeToString(digest) + packageSuffix }

func (s *Staging) Ready() bool {
	_, err := s.root.Lstat(readyFile)
	return err == nil
}

func (s *Staging) Clear() error {
	directory, err := s.root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s: %w", s.root.Name(), err)
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		return fmt.Errorf("list %s: %w", s.root.Name(), err)
	}
	for _, name := range names {
		if err := s.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("clear %s: %w", filepath.Join(s.root.Name(), name), err)
		}
	}
	return synced(s.root)
}

// Fetch keeps the package a release names once what fetch wrote is exactly the
// size and the digest the release gives, and fetches nothing it already keeps.
func (s *Staging) Fetch(release *updatev1.Release, fetch func(io.Writer) error) error {
	payload := release.GetPayload()
	name := PackageName(payload.GetSha256())
	if held, err := verified(s.root, name, payload); err == nil && held {
		return nil
	}
	return written(s.root, name, payload, fetch)
}

func (s *Staging) Hand(offer []byte) error {
	if err := keep(s.root, offerFile, offer); err != nil {
		return err
	}
	return keep(s.root, readyFile, nil)
}

func (s *Staging) Offer() ([]byte, error) {
	content, found, err := read(s.root, offerFile, MaxOfferBytes)
	if err == nil && !found {
		err = fmt.Errorf("%w: nothing was staged in %s", ErrDamaged, s.root.Name())
	}
	return content, err
}

// Take copies the package a release names into another directory, verifying
// the copy, so what is installed is a copy the account that staged it cannot
// change.
func (s *Staging) Take(release *updatev1.Release, into *os.Root) error {
	payload := release.GetPayload()
	name := PackageName(payload.GetSha256())
	source, err := s.root.OpenFile(name, os.O_RDONLY|files.NoFollow, 0)
	if err != nil {
		return fmt.Errorf("%w: %s was not staged: %v", ErrUnverified, name, err)
	}
	defer source.Close()
	described, err := source.Stat()
	if err != nil || !described.Mode().IsRegular() || described.Size() != int64(payload.GetSize()) {
		return fmt.Errorf("%w: %s is not a regular file of %d bytes", ErrUnverified, name, payload.GetSize())
	}
	return written(into, name, payload, func(destination io.Writer) error {
		_, err := io.Copy(destination, io.LimitReader(source, int64(payload.GetSize())+1))
		return err
	})
}

func verified(root *os.Root, name string, payload *updatev1.Payload) (bool, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|files.NoFollow, 0)
	if err != nil {
		return false, err
	}
	defer file.Close()
	described, err := file.Stat()
	if err != nil || !described.Mode().IsRegular() || described.Size() != int64(payload.GetSize()) {
		return false, err
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, int64(payload.GetSize())+1)); err != nil {
		return false, err
	}
	return bytes.Equal(digest.Sum(nil), payload.GetSha256()), nil
}

func written(root *os.Root, name string, payload *updatev1.Payload, fill func(io.Writer) error) error {
	random := make([]byte, 8)
	rand.Read(random)
	temporary := "." + name + "." + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("keep %s: %w", filepath.Join(root.Name(), name), err)
	}
	digest := sha256.New()
	counted := &counting{most: int64(payload.GetSize())}
	err = fill(io.MultiWriter(file, digest, counted))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	switch {
	case err != nil:
	case counted.written != int64(payload.GetSize()) || !bytes.Equal(digest.Sum(nil), payload.GetSha256()):
		err = fmt.Errorf("%w: what arrived is %d bytes of another digest than the %d the release names", ErrUnverified, counted.written, payload.GetSize())
	default:
		err = root.Rename(temporary, name)
	}
	if err == nil {
		err = synced(root)
	}
	if err != nil {
		if removed := root.Remove(temporary); removed != nil && !errors.Is(removed, fs.ErrNotExist) {
			err = errors.Join(err, removed)
		}
		return err
	}
	return nil
}

type counting struct {
	most    int64
	written int64
}

func (c *counting) Write(written []byte) (int, error) {
	c.written += int64(len(written))
	if c.written > c.most {
		return 0, fmt.Errorf("%w: it runs on past the %d bytes the release names", ErrUnverified, c.most)
	}
	return len(written), nil
}
