//go:build linux || darwin

package files_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

func TestAFileIsReadWholeUpToTheBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	content, err := files.Read(path, 32)
	if err != nil || string(content) != "root:x:0:0:root:/root:/bin/bash\n" {
		t.Errorf("a file of the bound was read as %q and %v", content, err)
	}
	if content, err := files.Read(path, 31); !errors.Is(err, files.ErrTooLarge) || content != nil {
		t.Errorf("a file one byte over the bound was read as %q and %v", content, err)
	}
	if _, err := files.Read(filepath.Join(t.TempDir(), "absent"), 32); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a file that is not there was read as %v", err)
	}
}

func TestAFifoInPlaceOfAFileHoldsNothingUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := files.Read(path, 1<<10)
		read <- err
	}()
	select {
	case err := <-read:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("a FIFO was read as %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reading a FIFO no process writes to waited for a writer")
	}
	if _, err := files.Read(t.TempDir(), 1<<10); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory was read as %v", err)
	}
}
