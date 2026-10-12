package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

const (
	journalFile     = "journal.json"
	pendingFile     = "pending"
	maxJournalBytes = 64 << 10
)

type Stage string

const (
	Downloading Stage = "downloading"
	Staged      Stage = "staged"
	Installing  Stage = "installing"
	Checking    Stage = "checking"
	Reverting   Stage = "reverting"
	Installed   Stage = "installed"
	RolledBack  Stage = "rolled_back"
	Failed      Stage = "failed"
)

type Failure string

const (
	Unreachable  Failure = "unreachable"
	Unverified   Failure = "unverified"
	Refused      Failure = "refused"
	Installation Failure = "installation"
	Unhealthy    Failure = "unhealthy"
)

// What the installer did with the newest release it was handed, written before
// each step it takes, so a step a crash or a reboot interrupted is taken again
// from where it stood.
type Journal struct {
	Format        int       `json:"format"`
	Stage         Stage     `json:"stage"`
	Version       string    `json:"version"`
	Previous      string    `json:"previous,omitempty"`
	PreviousState uint32    `json:"previous_state,omitempty"`
	Catalog       uint64    `json:"catalog"`
	Root          uint64    `json:"root"`
	Target        string    `json:"target,omitempty"`
	Fallback      string    `json:"fallback,omitempty"`
	Started       time.Time `json:"started"`
	Since         time.Time `json:"since"`
	Failure       Failure   `json:"failure,omitempty"`
	Reason        string    `json:"reason,omitempty"`
}

func (j Journal) Done() bool {
	return j.Stage == Installed || j.Stage == RolledBack || j.Stage == Failed
}

func ReadJournal(root *os.Root) (Journal, bool, error) {
	content, found, err := read(root, journalFile, maxJournalBytes)
	if err != nil || !found {
		return Journal{}, false, err
	}
	var journal Journal
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return Journal{}, false, fmt.Errorf("%w: the installer's journal is not what it writes", ErrDamaged)
	}
	if journal.Format > Format {
		return Journal{}, false, fmt.Errorf("%w: the installer's journal is of format %d, and this agent reads format %d", ErrNewer, journal.Format, Format)
	}
	return journal, true, nil
}

func KeepJournal(root *os.Root, journal Journal) error {
	journal.Format = Format
	content, err := json.Marshal(journal)
	if err != nil {
		return fmt.Errorf("encode the installer's journal: %w", err)
	}
	if !journal.Done() {
		marked, err := root.OpenFile(pendingFile, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return fmt.Errorf("mark an installation as pending in %s: %w", root.Name(), err)
		}
		if err := marked.Close(); err != nil {
			return err
		}
	}
	if err := keep(root, journalFile, append(content, '\n')); err != nil {
		return err
	}
	if journal.Done() {
		if err := root.Remove(pendingFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("unmark the installation in %s: %w", root.Name(), err)
		}
	}
	return nil
}
