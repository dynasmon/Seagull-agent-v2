//go:build linux || darwin

package files

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type entry struct {
	uid  uint32
	mode fs.FileMode
	link string
}

type described struct {
	name string
	held entry
}

func (d described) Name() string       { return d.name }
func (d described) Size() int64        { return 0 }
func (d described) Mode() fs.FileMode  { return d.held.mode }
func (d described) ModTime() time.Time { return time.Time{} }
func (d described) IsDir() bool        { return d.held.mode.IsDir() }
func (d described) Sys() any           { return &syscall.Stat_t{Uid: d.held.uid} }

func tree(entries map[string]entry) (func(string) (fs.FileInfo, error), func(string) (string, error)) {
	describe := func(path string) (fs.FileInfo, error) {
		held, found := entries[path]
		if !found {
			return nil, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrNotExist}
		}
		return described{name: filepath.Base(path), held: held}, nil
	}
	resolve := func(path string) (string, error) { return entries[path].link, nil }
	return describe, resolve
}

func host(extra map[string]entry) map[string]entry {
	entries := map[string]entry{
		"/":                         {mode: fs.ModeDir | 0o755},
		"/usr":                      {mode: fs.ModeDir | 0o755},
		"/usr/bin":                  {mode: fs.ModeDir | 0o755},
		"/usr/bin/seagull-agent":    {mode: 0o755},
		"/etc":                      {mode: fs.ModeDir | 0o755},
		"/etc/seagull-agent":        {mode: fs.ModeDir | 0o755},
		"/etc/seagull-agent/a.json": {mode: 0o644},
		"/tmp":                      {mode: fs.ModeDir | fs.ModeSticky | 0o777},
		"/tmp/root-owned":           {mode: 0o644},
		"/tmp/somebody-else":        {uid: 1000, mode: 0o644},
		"/var":                      {mode: fs.ModeDir | 0o755},
		"/var/opt":                  {mode: fs.ModeDir | 0o775},
		"/var/opt/agent.json":       {mode: 0o644},
		"/etc/linked":               {mode: fs.ModeSymlink | 0o777, link: "seagull-agent/a.json"},
		"/etc/through-tmp":          {mode: fs.ModeSymlink | 0o777, link: "/tmp/somebody-else"},
		"/etc/loop":                 {mode: fs.ModeSymlink | 0o777, link: "/etc/loop"},
		"/etc/seagull-agent/b.json": {uid: 997, mode: 0o644},
		"/etc/seagull-agent/c.json": {mode: 0o664},
	}
	for path, held := range extra {
		entries[path] = held
	}
	return entries
}

func TestWhatRootAloneCanChangeIsProtectedAndAnythingElseIsNamed(t *testing.T) {
	describe, resolve := tree(host(nil))
	for path, refused := range map[string]string{
		"/usr/bin/seagull-agent":    "",
		"/etc/seagull-agent/a.json": "",
		"/tmp/root-owned":           "",
		"/etc/linked":               "",
		"/etc/seagull-agent/b.json": "/etc/seagull-agent/b.json belongs to uid 997",
		"/etc/seagull-agent/c.json": "/etc/seagull-agent/c.json grants -rw-rw-r--",
		"/tmp/somebody-else":        "/tmp/somebody-else belongs to uid 1000",
		"/var/opt/agent.json":       "/var/opt grants -rwxrwxr-x",
		"/etc/through-tmp":          "/tmp/somebody-else belongs to uid 1000",
	} {
		err := guarded(path, describe, resolve)
		switch {
		case refused == "" && err != nil:
			t.Errorf("%s was refused: %v", path, err)
		case refused != "" && (!errors.Is(err, ErrUnprotected) || !strings.Contains(err.Error(), refused)):
			t.Errorf("%s was answered %v, and %q was expected", path, err, refused)
		}
	}
}

func TestAPathThatCannotBeFollowedIsNeverProtected(t *testing.T) {
	describe, resolve := tree(host(map[string]entry{"/": {uid: 1000, mode: fs.ModeDir | 0o755}}))
	if err := guarded("/usr/bin/seagull-agent", describe, resolve); !errors.Is(err, ErrUnprotected) {
		t.Errorf("a root directory somebody else owns was answered %v", err)
	}
	describe, resolve = tree(host(nil))
	for _, path := range []string{"/etc/loop", "/etc/missing", "relative/agent.json"} {
		if err := guarded(path, describe, resolve); err == nil {
			t.Errorf("%s was protected", path)
		}
	}
}

func TestTheHostsOwnFilesAreProtectedAndATemporaryOneIsNot(t *testing.T) {
	if err := Protected("/usr/bin/env"); err != nil {
		t.Skipf("this host lets another account than root change /usr/bin/env: %v", err)
	}
	mine := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(mine, nil, 0o600); err != nil {
		t.Fatalf("write %s: %v", mine, err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root owns whatever this test writes")
	}
	if err := Protected(mine); !errors.Is(err, ErrUnprotected) {
		t.Errorf("a file the test's own account wrote was answered %v", err)
	}
}
