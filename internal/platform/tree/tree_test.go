//go:build linux

package tree_test

import (
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/tree"
)

func write(t *testing.T, path, content string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chmod(path, uint32(mode)); err != nil {
		t.Fatal(err)
	}
}

func open(t *testing.T, path string) *tree.Dir {
	t.Helper()
	held, err := tree.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { held.Close() })
	return held
}

func TestOpenRefusesAPathThatALinkStandsIn(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "real", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(base, "file"), "x", 0o644)
	for path, want := range map[string]error{
		filepath.Join(base, "link"):               tree.ErrLink,
		filepath.Join(base, "link", "sub"):        tree.ErrLink,
		filepath.Join(base, "file"):               tree.ErrNotDirectory,
		filepath.Join(base, "file", "sub"):        tree.ErrNotDirectory,
		filepath.Join(base, "missing"):            fs.ErrNotExist,
		filepath.Join(base, "real", "..", "file"): nil,
		"relative": nil,
	} {
		held, err := tree.Open(path)
		if err == nil {
			held.Close()
			t.Errorf("%s opened", path)
			continue
		}
		if want != nil && !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", path, err, want)
		}
	}
	held := open(t, filepath.Join(base, "real", "sub"))
	if held.Path() != filepath.Join(base, "real", "sub") || held.Node().Kind != tree.Directory {
		t.Errorf("opened %s as %v", held.Path(), held.Node())
	}
	root := open(t, "/")
	if root.Path() != "/" || root.Node().Kind != tree.Directory {
		t.Errorf("opened / as %s, %v", root.Path(), root.Node())
	}
}

func TestStatDescribesWhatEachNameStandsFor(t *testing.T) {
	base := t.TempDir()
	write(t, filepath.Join(base, "regular"), "seven b", 0o4750)
	if err := os.Mkdir(filepath.Join(base, "directory"), 0o1700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chmod(filepath.Join(base, "directory"), 0o1700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("regular", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(base, "regular"), filepath.Join(base, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(base, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(base, "socket"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	held := open(t, base)
	want := map[string]tree.Kind{"regular": tree.Regular, "hard": tree.Regular, "directory": tree.Directory, "link": tree.Link, "pipe": tree.Pipe, "socket": tree.Socket}
	for name, kind := range want {
		node, err := held.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		described, err := os.Lstat(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		system := described.Sys().(*syscall.Stat_t)
		if node.Kind != kind || node.Inode != system.Ino || node.Device != system.Dev || node.Links != uint64(system.Nlink) ||
			node.User != system.Uid || node.Group != system.Gid || node.Mode != system.Mode&0o7777 || node.Size != system.Size ||
			!node.Modified.Equal(described.ModTime()) || !node.Changed.Equal(time.Unix(system.Ctim.Unix())) {
			t.Errorf("%s is described as %+v, and lstat says %+v", name, node, system)
		}
	}
	regular, _ := held.Stat("regular")
	hard, _ := held.Stat("hard")
	if !regular.Same(hard) || regular.Links != 2 || regular.Mode != 0o4750 || regular.Size != 7 {
		t.Errorf("a file with two names is described as %+v and %+v", regular, hard)
	}
	if directory, _ := held.Stat("directory"); directory.Mode != 0o1700 {
		t.Errorf("a sticky directory is described with mode %#o", directory.Mode)
	}
	for _, name := range []string{"", ".", "..", "a/b", "regular/"} {
		if _, err := held.Stat(name); err == nil {
			t.Errorf("stat %q succeeded", name)
		}
	}
	if _, err := held.Stat("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stat of a missing name: %v", err)
	}
}

func TestNamesListsWhatADirectoryHoldsAndRefusesMoreThanItIsToRead(t *testing.T) {
	base := t.TempDir()
	var want []string
	for _, name := range []string{"b", "a", "c\nd", ".hidden", "z"} {
		write(t, filepath.Join(base, name), name, 0o644)
		want = append(want, name)
	}
	slices.Sort(want)
	names, err := open(t, base).Names(5)
	if err != nil || !slices.Equal(names, want) {
		t.Fatalf("listed %q, %v, want %q", names, err, want)
	}
	if names, err := open(t, base).Names(4); !errors.Is(err, tree.ErrTooMany) {
		t.Fatalf("a directory of five names read as at most four: %q, %v", names, err)
	}
	many := t.TempDir()
	for i := range 600 {
		write(t, filepath.Join(many, strings.Repeat("n", 1+i%200)+string(rune('a'+i/200))), "", 0o644)
	}
	if names, err := open(t, many).Names(600); err != nil || len(names) != 600 || !slices.IsSorted(names) {
		t.Fatalf("listed %d names, %v", len(names), err)
	}
}

func TestReadReadsTheFileSeenAndNothingPutInItsPlace(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "watched")
	write(t, path, "what was seen", 0o644)
	held := open(t, base)
	seen, err := held.Stat("watched")
	if err != nil {
		t.Fatal(err)
	}
	file, err := held.Read("watched", seen)
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(content) != "what was seen" {
		t.Fatalf("read %q, %v", content, err)
	}

	write(t, filepath.Join(base, "other"), "something else", 0o644)
	if err := os.Rename(filepath.Join(base, "other"), path); err != nil {
		t.Fatal(err)
	}
	if file, err := held.Read("watched", seen); !errors.Is(err, tree.ErrChanged) {
		if file != nil {
			file.Close()
		}
		t.Errorf("a file renamed over the one seen was read: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", path); err != nil {
		t.Fatal(err)
	}
	if file, err := held.Read("watched", seen); !errors.Is(err, tree.ErrChanged) {
		if file != nil {
			file.Close()
		}
		t.Errorf("a link put in place of the file seen was followed: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		file, err := held.Read("watched", seen)
		if file != nil {
			file.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, tree.ErrChanged) {
			t.Errorf("a pipe put in place of the file seen was read: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a pipe put in place of the file seen waits for a writer")
	}

	pipe, err := held.Stat("watched")
	if err != nil {
		t.Fatal(err)
	}
	if file, err := held.Read("watched", pipe); !errors.Is(err, tree.ErrChanged) {
		if file != nil {
			file.Close()
		}
		t.Errorf("a pipe seen as a pipe was opened to be read: %v", err)
	}
}

func TestEnterOpensTheDirectorySeenAndNothingPutInItsPlace(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"sub", "other"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(base, "sub", "inside"), "", 0o644)
	held := open(t, base)
	seen, err := held.Stat("sub")
	if err != nil {
		t.Fatal(err)
	}
	entered, err := held.Enter("sub", seen)
	if err != nil {
		t.Fatal(err)
	}
	if names, err := entered.Names(10); err != nil || !slices.Equal(names, []string{"inside"}) {
		t.Errorf("entered sub and listed %q, %v", names, err)
	}

	if err := os.Rename(filepath.Join(base, "sub"), filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if _, err := entered.Stat("inside"); err != nil {
		t.Errorf("a directory moved after it was entered no longer reads what it holds: %v", err)
	}
	entered.Close()

	if err := os.Symlink("other", filepath.Join(base, "sub")); err != nil {
		t.Fatal(err)
	}
	if entered, err := held.Enter("sub", seen); !errors.Is(err, tree.ErrChanged) {
		if entered != nil {
			entered.Close()
		}
		t.Errorf("a link put in place of the directory seen was entered: %v", err)
	}
	if err := os.Remove(filepath.Join(base, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(base, "sub")); err != nil {
		t.Fatal(err)
	}
	if entered, err := held.Enter("sub", seen); err == nil {
		entered.Close()
		t.Error("a link out of the directory was entered")
	}
	if err := os.Remove(filepath.Join(base, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if entered, err := held.Enter("sub", seen); !errors.Is(err, tree.ErrChanged) {
		if entered != nil {
			entered.Close()
		}
		t.Errorf("another directory put in place of the one seen was entered: %v", err)
	}
	file, _ := held.Stat("moved")
	file.Kind = tree.Regular
	if entered, err := held.Enter("moved", file); !errors.Is(err, tree.ErrNotDirectory) {
		if entered != nil {
			entered.Close()
		}
		t.Errorf("a name seen as a file was entered: %v", err)
	}
}

func TestTargetIsWhatALinkNamesWithinItsBound(t *testing.T) {
	base := t.TempDir()
	long := strings.Repeat("x", 300)
	if err := os.Symlink(long, filepath.Join(base, "long")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../escape", filepath.Join(base, "short")); err != nil {
		t.Fatal(err)
	}
	held := open(t, base)
	if target, err := held.Target("short", 300); err != nil || target != "../escape" {
		t.Errorf("read %q, %v", target, err)
	}
	if target, err := held.Target("long", 300); err != nil || target != long {
		t.Errorf("read %d bytes, %v", len(target), err)
	}
	if _, err := held.Target("long", 299); !errors.Is(err, tree.ErrLonger) {
		t.Errorf("a target past the bound was read: %v", err)
	}
}

func TestChangedFollowsWhatHappensToTheInode(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "file")
	write(t, path, "content", 0o644)
	held := open(t, base)
	before, err := held.Stat("file")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := held.Stat("file")
	if err != nil {
		t.Fatal(err)
	}
	if !after.Changed.After(before.Changed) || !after.Modified.Equal(before.Modified) || after.Mode != 0o600 || !after.Same(before) {
		t.Errorf("a chmod changed %+v into %+v", before, after)
	}
	file, err := held.Read("file", after)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || opened != after {
		t.Errorf("the opened file is described as %+v, %v, and was seen as %+v", opened, err, after)
	}
}
