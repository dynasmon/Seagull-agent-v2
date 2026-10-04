package diagnostics

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

var (
	ErrExists       = errors.New("the bundle names a file that is already there")
	ErrInstallation = errors.New("the bundle names a directory the agent keeps as its own")
)

// Write puts bundle in a new file at destination, which the account the agent
// runs as alone may read, and returns how many bytes it holds. The bundle is
// written whole under another name and only then linked into place, so the
// destination holds all of it or nothing, whatever stops the write: it never
// replaces what is there, follows no link, and never lands in a directory the
// bundle lists or in one only that account may enter, which is where the agent
// keeps its own even when nobody could tell which installation it is.
func Write(destination string, bundle Bundle) (int, error) {
	bundle.Format, bundle.WrittenAt, bundle.Limits = Format, time.Now().UTC(), limits()
	content, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("encode the bundle: %w", err)
	}
	if len(content) >= MaxBytes {
		return 0, fmt.Errorf("the bundle would hold %d bytes, and one holds less than %d", len(content), MaxBytes)
	}
	content = append(content, '\n')
	named := secrets.Shown(destination)
	directory, name := filepath.Split(destination)
	if name == "" || name == "." || name == ".." {
		return 0, fmt.Errorf("%s names no file to write the bundle to", named)
	}
	if directory == "" {
		directory = "."
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return 0, fmt.Errorf("write %s: %w", named, plain(err))
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		return 0, fmt.Errorf("write %s: %w", named, plain(err))
	}
	switch {
	case inside(directory, string(bundle.Files.Directory)) || slices.ContainsFunc(bundle.Files.directories, func(held fs.FileInfo) bool { return os.SameFile(held, opened) }):
		return 0, fmt.Errorf("%w: %s is in the installation, %s", ErrInstallation, named, secrets.Shown(string(bundle.Files.Directory)))
	case files.Private(opened) == nil:
		return 0, fmt.Errorf("%w: %s is in a directory only the account that writes it may enter", ErrInstallation, named)
	}
	switch _, err := root.Lstat(name); {
	case err == nil:
		return 0, fmt.Errorf("%w: %s", ErrExists, named)
	case !errors.Is(err, fs.ErrNotExist):
		return 0, fmt.Errorf("write %s: %w", named, plain(err))
	}
	if err := place(root, name, content); err != nil {
		return 0, fmt.Errorf("write %s: %w", named, plain(err))
	}
	return len(content), nil
}

func place(root *os.Root, name string, content []byte) error {
	temporary := "." + name + "." + rand.Text() + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = file.Chmod(0o600)
	if err == nil {
		_, err = file.Write(content)
	}
	if err == nil {
		err = file.Sync()
	}
	var written fs.FileInfo
	if err == nil {
		written, err = file.Stat()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = root.Link(temporary, name)
		if errors.Is(err, fs.ErrExist) {
			err = fmt.Errorf("%w: it appeared while the bundle was written", ErrExists)
		}
	}
	if err == nil {
		if linked, held := root.Lstat(name); held != nil || !os.SameFile(linked, written) {
			err = errors.Join(errors.New("what was linked into place is not what the agent wrote"), held, missing(root.Remove(name)))
		}
	}
	if removed := missing(root.Remove(temporary)); removed != nil {
		if err == nil {
			err = errors.Join(removed, missing(root.Remove(name)))
		} else {
			err = errors.Join(err, removed)
		}
	}
	return err
}

// Whether directory resolves to the installation's directory or to one inside
// it, however links lead there: what a listing reached is also compared by
// identity, and what it did not reach, too deep or past its bound, by path.
func inside(directory, installation string) bool {
	if installation == "" {
		return false
	}
	resolved, err := resolve(directory)
	if err != nil {
		return false
	}
	held, err := resolve(installation)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(held, resolved)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func resolve(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}

// What went wrong with a path the operator named, without the path again: the
// message names it once, bounded, whatever was typed.
func plain(err error) error {
	switch held := err.(type) {
	case *fs.PathError:
		return held.Err
	case *os.LinkError:
		return held.Err
	}
	return err
}

func missing(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func limits() Limits {
	return Limits{
		Bytes:        MaxBytes,
		Files:        MaxFiles,
		Depth:        maxDepth,
		LogEntries:   MaxEntries,
		LogBytes:     maxLogBytes,
		MessageBytes: maxMessage,
		TextBytes:    maxText,
		Seconds:      int(MaxTime / time.Second),
	}
}
