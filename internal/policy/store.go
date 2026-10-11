package policy

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
	"regexp"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	Format       = 1
	heldFile     = "policy.json"
	maxHeldBytes = 2 << 20
)

var (
	ErrDamaged = errors.New("the policy the agent applied cannot be read back")
	ErrNewer   = errors.New("the policy the agent applied was kept by a newer agent")
)

var interrupted = regexp.MustCompile(`^\.` + regexp.QuoteMeta(heldFile) + `\.[0-9a-f]{16}\.tmp$`)

type Held struct {
	Holding
	AppliedAt time.Time
	Envelope  []byte
}

type kept struct {
	Format    int       `json:"format"`
	Revision  uint64    `json:"revision"`
	Digest    string    `json:"digest_sha256"`
	AppliedAt time.Time `json:"applied_at"`
	Envelope  []byte    `json:"envelope"`
}

// Where the agent keeps the policy it applied: the envelope exactly as it was
// handed, so it is verified again at every start under the keys the agent then
// holds, and the revision it applied, which no policy it is handed later may go
// below. A write is whole or absent, and outlives a crash once it returns.
type Store struct {
	root *os.Root
}

func Open(root *os.Root) (*Store, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", root.Name(), err)
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", root.Name(), err)
	}
	for _, name := range names {
		if interrupted.MatchString(name) {
			if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("discard the interrupted write %s: %w", filepath.Join(root.Name(), name), err)
			}
		}
	}
	return &Store{root: root}, nil
}

func (s *Store) Read() (Held, bool, error) {
	file, err := s.root.Open(heldFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Held{}, false, nil
	case err != nil:
		return Held{}, false, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxHeldBytes+1))
	if err != nil || len(content) > maxHeldBytes {
		return Held{}, false, fmt.Errorf("%w: it is unreadable or longer than %d bytes", ErrDamaged, maxHeldBytes)
	}
	var declared struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return Held{}, false, fmt.Errorf("%w: it is not what the agent writes", ErrDamaged)
	}
	if declared.Format > Format {
		return Held{}, false, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, declared.Format, Format)
	}
	var stored kept
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil || stored.Format != Format || stored.Revision == 0 || len(stored.Envelope) == 0 || stored.Digest == "" {
		return Held{}, false, fmt.Errorf("%w: it is not what the agent writes", ErrDamaged)
	}
	return Held{
		Holding:   Holding{Revision: stored.Revision, Digest: stored.Digest},
		AppliedAt: stored.AppliedAt,
		Envelope:  stored.Envelope,
	}, true, nil
}

func (s *Store) Keep(verified Verified, at time.Time) (Held, error) {
	held := Held{
		Holding:   Holding{Revision: verified.Policy.GetRevision(), Digest: verified.Digest},
		AppliedAt: at.UTC(),
		Envelope:  verified.Envelope,
	}
	content, err := json.Marshal(kept{
		Format:    Format,
		Revision:  held.Revision,
		Digest:    held.Digest,
		AppliedAt: held.AppliedAt,
		Envelope:  held.Envelope,
	})
	if err != nil {
		return Held{}, fmt.Errorf("encode the policy the agent applied: %w", err)
	}
	random := make([]byte, 8)
	rand.Read(random)
	temporary := "." + heldFile + "." + hex.EncodeToString(random) + ".tmp"
	file, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Held{}, fmt.Errorf("keep the policy the agent applied: %w", err)
	}
	_, err = file.Write(append(content, '\n'))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = s.root.Rename(temporary, heldFile)
	}
	if err == nil {
		err = s.synced()
	}
	if err != nil {
		if removed := s.root.Remove(temporary); removed != nil && !errors.Is(removed, fs.ErrNotExist) {
			err = errors.Join(err, removed)
		}
		return Held{}, fmt.Errorf("keep the policy the agent applied in %s: %w", s.root.Name(), err)
	}
	return held, nil
}

func (s *Store) synced() error {
	directory, err := s.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
