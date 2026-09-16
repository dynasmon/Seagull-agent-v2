//go:build linux || darwin

package files_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

func TestALockHoldsUntilTheFileThatTookItIsClosed(t *testing.T) {
	directory := t.TempDir()
	holder := open(t, directory)
	if err := files.Lock(holder); err != nil {
		t.Fatalf("lock %s: %v", directory, err)
	}
	contender := open(t, directory)
	if err := files.Lock(contender); !errors.Is(err, files.ErrLocked) {
		t.Fatalf("a second lock on %s returned %v while the first was held", directory, err)
	}
	if err := holder.Close(); err != nil {
		t.Fatalf("close the holder: %v", err)
	}
	if err := files.Lock(contender); err != nil {
		t.Fatalf("the lock outlived the file that took it: %v", err)
	}
}

func TestOnlyWhatNoGroupOrOtherAccountReachesIsPrivate(t *testing.T) {
	directory := t.TempDir()
	cases := map[fs.FileMode]bool{
		0o600: true,
		0o400: true,
		0o700: true,
		0o640: false,
		0o610: false,
		0o604: false,
		0o602: false,
		0o666: false,
	}
	for mode, private := range cases {
		path := filepath.Join(directory, mode.String())
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod %s: %v", path, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("describe %s: %v", path, err)
		}
		if err := files.Private(info); (err == nil) != private {
			t.Errorf("a file with mode %s is private: %v, want %t", mode, err, private)
		}
	}
}

type ownedBy struct {
	fs.FileInfo
	described any
}

func (o ownedBy) Sys() any { return o.described }

func TestWhatAnotherAccountOwnsIsNotPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installation.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("describe %s: %v", path, err)
	}
	for name, described := range map[string]any{
		"another account": &syscall.Stat_t{Uid: uint32(os.Geteuid() + 1)},
		"no owner at all": nil,
	} {
		if err := files.Private(ownedBy{FileInfo: info, described: described}); err == nil {
			t.Errorf("a file owned by %s is private", name)
		}
	}
}

func open(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}
