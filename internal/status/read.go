package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

// Read returns the snapshot the agent last wrote in directory, without the lock
// of the installation, so it reads while the agent runs. It takes the snapshot
// only from a directory and a file private to the account that reads them.
func Read(directory string) (Snapshot, error) {
	described, err := os.Lstat(directory)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Snapshot{}, fmt.Errorf("%w in %s", ErrUnwritten, directory)
	case err != nil:
		return Snapshot{}, fmt.Errorf("inspect %s: %w", directory, err)
	case !described.IsDir():
		return Snapshot{}, fmt.Errorf("%w: %s is not a directory", ErrDamaged, directory)
	}
	if err := private(directory, described); err != nil {
		return Snapshot{}, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open %s: %w", directory, err)
	}
	defer root.Close()
	path := filepath.Join(directory, name)
	described, err = root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Snapshot{}, fmt.Errorf("%w in %s", ErrUnwritten, directory)
	case err != nil:
		return Snapshot{}, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return Snapshot{}, fmt.Errorf("%w: %s is not a regular file", ErrDamaged, path)
	}
	if err := private(path, described); err != nil {
		return Snapshot{}, err
	}
	file, err := root.Open(name)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return Snapshot{}, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxBytes {
		return Snapshot{}, fmt.Errorf("%w: %s is larger than %d bytes", ErrDamaged, path, maxBytes)
	}
	snapshot, err := decode(content)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: %s", err, path)
	}
	return snapshot, nil
}

func decode(content []byte) (Snapshot, error) {
	var declared struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	switch {
	case declared.Format > Format:
		return Snapshot{}, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, declared.Format, Format)
	case declared.Format != Format:
		return Snapshot{}, fmt.Errorf("%w: format %d is not one this agent reads", ErrDamaged, declared.Format)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if snapshot.WrittenAt.IsZero() || !slices.Contains([]State{Running, Degraded, Failed, Stopped}, snapshot.State) {
		return Snapshot{}, fmt.Errorf("%w: it says neither when it was written nor what state the agent was in", ErrDamaged)
	}
	return snapshot, nil
}

func private(path string, described fs.FileInfo) error {
	if err := files.Private(described); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return fmt.Errorf("read the status in %s: %w", path, err)
		}
		return fmt.Errorf("%w: %s %v", ErrInsecure, path, err)
	}
	return nil
}
