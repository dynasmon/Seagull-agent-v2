package update

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	Format       = 1
	heldFile     = "held.json"
	maxHeldBytes = 2 << 20
)

var (
	ErrDamaged = errors.New("what was verified of updates cannot be read back")
	ErrNewer   = errors.New("what was verified of updates was kept by a newer agent")
)

type keptHeld struct {
	Format  int    `json:"format"`
	Root    []byte `json:"root"`
	Catalog uint64 `json:"catalog"`
}

// A Store keeps the newest root and the highest catalog verified, so a restart
// goes below neither. A write is whole or absent, and outlives a crash once it
// returns.
type Store struct {
	root *os.Root
}

func OpenStore(root *os.Root) (*Store, error) {
	if err := discard(root); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

// A root kept earlier is taken again only when its own keys signed it and it is
// no older than the one the agent is provisioned with now, so provisioning a
// newer root moves past whatever was kept.
func (s *Store) Held(anchor *Root, now time.Time) (Held, error) {
	content, found, err := read(s.root, heldFile, maxHeldBytes)
	if err != nil || !found {
		return Held{Root: anchor}, err
	}
	var declared struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return Held{Root: anchor}, fmt.Errorf("%w: it is not what the agent writes", ErrDamaged)
	}
	if declared.Format > Format {
		return Held{Root: anchor}, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, declared.Format, Format)
	}
	var stored keptHeld
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil || stored.Format != Format {
		return Held{Root: anchor}, fmt.Errorf("%w: it is not what the agent writes", ErrDamaged)
	}
	root, err := Anchor(stored.Root, now)
	if err != nil {
		return Held{Root: anchor}, fmt.Errorf("%w: %v", ErrDamaged, err)
	}
	if root.Version() < anchor.Version() {
		root = anchor
	}
	return Held{Root: root, Catalog: stored.Catalog}, nil
}

func (s *Store) Keep(held Held) error {
	content, err := json.Marshal(keptHeld{Format: Format, Root: held.Root.Served(), Catalog: held.Catalog})
	if err != nil {
		return fmt.Errorf("encode what was verified of updates: %w", err)
	}
	return keep(s.root, heldFile, append(content, '\n'))
}

func read(root *os.Root, name string, most int64) ([]byte, bool, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|files.NoFollow, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	defer file.Close()
	described, err := file.Stat()
	if err != nil || !described.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%w: %s is not a regular file", ErrDamaged, filepath.Join(root.Name(), name))
	}
	content, err := io.ReadAll(io.LimitReader(file, most+1))
	if err != nil || int64(len(content)) > most {
		return nil, false, fmt.Errorf("%w: %s is unreadable or longer than %d bytes", ErrDamaged, filepath.Join(root.Name(), name), most)
	}
	return content, true, nil
}

func keep(root *os.Root, name string, content []byte) error {
	random := make([]byte, 8)
	rand.Read(random)
	temporary := "." + name + "." + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("keep %s: %w", filepath.Join(root.Name(), name), err)
	}
	_, err = file.Write(content)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = root.Rename(temporary, name)
	}
	if err == nil {
		err = synced(root)
	}
	if err != nil {
		if removed := root.Remove(temporary); removed != nil && !errors.Is(removed, fs.ErrNotExist) {
			err = errors.Join(err, removed)
		}
		return fmt.Errorf("keep %s: %w", filepath.Join(root.Name(), name), err)
	}
	return nil
}

func synced(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func discard(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s: %w", root.Name(), err)
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		return fmt.Errorf("list %s: %w", root.Name(), err)
	}
	for _, name := range names {
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") {
			if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("discard the interrupted write %s: %w", filepath.Join(root.Name(), name), err)
			}
		}
	}
	return nil
}
