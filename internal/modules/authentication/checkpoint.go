package authentication

import (
	"bytes"
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
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	positionFile = Name + ".json"
	format       = 1
	maxPosition  = 4 << 10
)

var (
	ErrDamaged   = errors.New("the place the collector reached in the journal cannot be read")
	ErrNewer     = errors.New("the place the collector reached in the journal was written by a newer agent")
	ErrInsecure  = errors.New("the place the collector reached in the journal is not private to the account the agent runs as")
	errUnwritten = errors.New("the collector has not read the journal yet")
	interrupted  = regexp.MustCompile(`^\.` + regexp.QuoteMeta(positionFile) + `\.[0-9a-f]{16}\.tmp$`)
)

// Where the collector is in the journal: the last entry it handled, and when
// journald wrote it down, or, before it handled any, the moment it reads from.
// It is written once what the entries before it gave is durable in the spool.
type position struct {
	Format int       `json:"format"`
	Cursor string    `json:"cursor,omitempty"`
	Read   time.Time `json:"read,omitzero"`
	Since  time.Time `json:"since,omitzero"`
}

func (p position) journal() journal.Position {
	if p.Cursor != "" {
		return journal.Position{Cursor: p.Cursor}
	}
	return journal.Position{Since: p.Since}
}

func load(root *os.Root) (position, error) {
	path := filepath.Join(root.Name(), positionFile)
	described, err := root.Lstat(positionFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return position{}, errUnwritten
	case err != nil:
		return position{}, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return position{}, fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	if err := files.Private(described); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return position{}, fmt.Errorf("read %s: %w", path, err)
		}
		return position{}, fmt.Errorf("%w: %s %v", ErrInsecure, path, err)
	}
	file, err := root.Open(positionFile)
	if err != nil {
		return position{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return position{}, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxPosition+1))
	if err != nil {
		return position{}, fmt.Errorf("read %s: %w", path, err)
	}
	held, err := decode(content)
	if err != nil {
		return position{}, fmt.Errorf("%s: %w", path, err)
	}
	return held, nil
}

func decode(content []byte) (position, error) {
	if len(content) > maxPosition {
		return position{}, fmt.Errorf("%w: it is larger than %d bytes", ErrDamaged, maxPosition)
	}
	var declared struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return position{}, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if declared.Format > format {
		return position{}, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, declared.Format, format)
	}
	var held position
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&held); err != nil {
		return position{}, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return position{}, fmt.Errorf("%w: it holds more than one place", ErrDamaged)
	}
	switch {
	case held.Format != format:
		return position{}, fmt.Errorf("%w: format %d is not one this agent reads", ErrDamaged, held.Format)
	case held.Cursor != "" && (!journal.Cursor(held.Cursor) || held.Read.IsZero() || !held.Since.IsZero()):
		return position{}, fmt.Errorf("%w: it names no entry of the journal", ErrDamaged)
	case held.Cursor == "" && (held.Since.IsZero() || !held.Read.IsZero()):
		return position{}, fmt.Errorf("%w: it names neither an entry of the journal nor a moment", ErrDamaged)
	}
	return held, nil
}

// A place lost in a crash only makes the collector read again entries whose
// events it already admitted, which it admits again under the same names, so
// the file is synced before it replaces the last one and the directory is not.
func save(root *os.Root, held position) error {
	path := filepath.Join(root.Name(), positionFile)
	content, err := json.Marshal(held)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	random := make([]byte, 8)
	rand.Read(random)
	temporary := "." + positionFile + "." + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, err = file.Write(append(content, '\n'))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = root.Rename(temporary, positionFile)
	}
	if err != nil {
		if removed := root.Remove(temporary); removed != nil && !errors.Is(removed, fs.ErrNotExist) {
			err = errors.Join(err, removed)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
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
		if !interrupted.MatchString(name) {
			continue
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("discard the interrupted write %s: %w", filepath.Join(root.Name(), name), err)
		}
	}
	return nil
}
