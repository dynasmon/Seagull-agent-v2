package reporting

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
)

const (
	Format          = 1
	sequenceFile    = "sequence.json"
	maxSequenceSize = 4 << 10
)

var (
	ErrSequenceLost = errors.New("the sequence of the reports cannot be read back")
	leftover        = regexp.MustCompile(`^\.` + regexp.QuoteMeta(sequenceFile) + `\.[0-9a-f]{16}\.tmp$`)
)

type counted struct {
	Format   int    `json:"format"`
	Sequence uint64 `json:"sequence"`
}

// The count of the reports an installation wrote, kept so that no sequence is
// ever written twice: a sequence is durable before the report carrying it is
// sent. A count that cannot be read back is taken up again from the clock, in
// seconds, which no installation reporting every ten seconds reaches.
type sequence struct {
	root *os.Root
	last uint64
	lost error
}

func openSequence(root *os.Root, now time.Time) (*sequence, error) {
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
		if leftover.MatchString(name) {
			if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("discard the interrupted write %s: %w", filepath.Join(root.Name(), name), err)
			}
		}
	}
	held := &sequence{root: root}
	last, err := held.read()
	switch {
	case err == nil:
		held.last = last
	case !errors.Is(err, fs.ErrNotExist):
		held.last, held.lost = uint64(max(now.Unix(), 0)), fmt.Errorf("%w: %w", ErrSequenceLost, err)
	}
	return held, nil
}

func (s *sequence) read() (uint64, error) {
	file, err := s.root.Open(sequenceFile)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxSequenceSize+1))
	if err != nil {
		return 0, err
	}
	if len(content) > maxSequenceSize {
		return 0, fmt.Errorf("%s holds more than %d bytes", sequenceFile, maxSequenceSize)
	}
	var held counted
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&held); err != nil || held.Format != Format {
		return 0, fmt.Errorf("%s is not what this agent writes", sequenceFile)
	}
	return held.Sequence, nil
}

// next makes the following sequence durable and returns it, so a crash at any
// moment loses at most a sequence that was never sent.
func (s *sequence) next() (uint64, error) {
	following := s.last + 1
	content, err := json.Marshal(counted{Format: Format, Sequence: following})
	if err != nil {
		return 0, err
	}
	random := make([]byte, 8)
	rand.Read(random)
	temporary := "." + sequenceFile + "." + hex.EncodeToString(random) + ".tmp"
	file, err := s.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("keep the sequence of the reports: %w", err)
	}
	_, err = file.Write(append(content, '\n'))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = s.root.Rename(temporary, sequenceFile)
	}
	if err == nil {
		var directory *os.File
		if directory, err = s.root.Open("."); err == nil {
			err = errors.Join(directory.Sync(), directory.Close())
		}
	}
	if err != nil {
		if removed := s.root.Remove(temporary); removed != nil && !errors.Is(removed, fs.ErrNotExist) {
			err = errors.Join(err, removed)
		}
		return 0, fmt.Errorf("keep the sequence of the reports in %s: %w", s.root.Name(), err)
	}
	s.last = following
	return following, nil
}
