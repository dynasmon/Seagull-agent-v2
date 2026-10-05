package inventory

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
	"slices"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	baselineFile = Name + ".json"
	format       = 1
	maxBaseline  = 64 << 10
	maxRecordID  = 64
	leastNeeds   = 64 << 10
)

var (
	ErrDamaged   = errors.New("what the collector last admitted of the host cannot be read")
	ErrNewer     = errors.New("what the collector last admitted of the host was written down by a newer agent")
	ErrInsecure  = errors.New("what the collector last admitted of the host is not private to the account the agent runs as")
	errUnwritten = errors.New("the collector has admitted nothing of the host yet")
	interrupted  = regexp.MustCompile(`^\.` + regexp.QuoteMeta(baselineFile) + `\.[0-9a-f]{16}\.tmp$`)
	digested     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// The baseline is what the collector last admitted of each kind: when it took
// the snapshot, under which identifier, how large it was and the digest of
// what it said. It is written once the spool made that snapshot durable.
type baseline struct {
	Format int              `json:"format"`
	Kinds  map[string]entry `json:"kinds"`
}

type entry struct {
	CollectedAt time.Time `json:"collected_at"`
	RecordID    string    `json:"record_id"`
	Items       int       `json:"items"`
	Bytes       int       `json:"bytes"`
	Digest      string    `json:"digest"`
}

func (b baseline) needs() int64 {
	var held int64
	for _, sent := range b.Kinds {
		held += int64(sent.Bytes)
	}
	return max(held, leastNeeds)
}

func load(root *os.Root) (baseline, error) {
	path := filepath.Join(root.Name(), baselineFile)
	described, err := root.Lstat(baselineFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return baseline{}, errUnwritten
	case err != nil:
		return baseline{}, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return baseline{}, fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	if err := files.Private(described); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return baseline{}, fmt.Errorf("read %s: %w", path, err)
		}
		return baseline{}, fmt.Errorf("%w: %s %v", ErrInsecure, path, err)
	}
	file, err := root.Open(baselineFile)
	if err != nil {
		return baseline{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return baseline{}, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBaseline+1))
	if err != nil {
		return baseline{}, fmt.Errorf("read %s: %w", path, err)
	}
	held, err := decode(content)
	if err != nil {
		return baseline{}, fmt.Errorf("%s: %w", path, err)
	}
	return held, nil
}

func decode(content []byte) (baseline, error) {
	if len(content) > maxBaseline {
		return baseline{}, fmt.Errorf("%w: it is larger than %d bytes", ErrDamaged, maxBaseline)
	}
	var declared struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return baseline{}, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if declared.Format > format {
		return baseline{}, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, declared.Format, format)
	}
	var held baseline
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&held); err != nil {
		return baseline{}, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return baseline{}, fmt.Errorf("%w: it holds more than one baseline", ErrDamaged)
	}
	if held.Format != format {
		return baseline{}, fmt.Errorf("%w: format %d is not one this agent reads", ErrDamaged, held.Format)
	}
	for name, sent := range held.Kinds {
		known := slices.ContainsFunc(kinds, func(held taker) bool { return KindName(held.kind) == name })
		if !known || sent.CollectedAt.IsZero() || sent.RecordID == "" || len(sent.RecordID) > maxRecordID || sent.Items < 0 || sent.Bytes < 0 || !digested.MatchString(sent.Digest) {
			return baseline{}, fmt.Errorf("%w: what it says of %s does not read", ErrDamaged, secrets.Shown(name))
		}
	}
	if held.Kinds == nil {
		held.Kinds = map[string]entry{}
	}
	return held, nil
}

// A baseline lost in a crash only has the collector admit again snapshots
// the platform already took, which leave what it holds as it was, so the file
// is synced before it replaces the last one and the directory is not.
func save(root *os.Root, held baseline) error {
	path := filepath.Join(root.Name(), baselineFile)
	held.Format = format
	content, err := json.Marshal(held)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	random := make([]byte, 8)
	rand.Read(random)
	temporary := "." + baselineFile + "." + hex.EncodeToString(random) + ".tmp"
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
		err = root.Rename(temporary, baselineFile)
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
