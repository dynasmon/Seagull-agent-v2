//go:build linux

package tree_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/tree"
)

var (
	planted = []string{"etc", "a", "b", "\xff\xfe", "a b", "a\nb", "-rf", "x.conf", "x.conf~", string(bytes.Repeat([]byte("n"), 255))}
	aimed   = []string{"..", "../..", "/", "/etc/passwd", "a", "a/b", ".", "missing", "/proc/self/root", "../outside"}
)

// built plants in a directory what the fuzzer's bytes describe, two bytes at a
// time: what to plant, and under which name or towards which target.
func built(t *testing.T, root string, plan []byte) {
	t.Helper()
	directories := []string{root}
	var regular []string
	for i := 0; i+1 < len(plan) && i < 96; i += 2 {
		within := directories[int(plan[i]>>4)%len(directories)]
		name := filepath.Join(within, planted[int(plan[i+1])%len(planted)])
		switch plan[i] % 6 {
		case 0:
			if os.Mkdir(name, 0o755) == nil && len(directories) < 16 {
				directories = append(directories, name)
			}
		case 1:
			if file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); err == nil {
				_, err = file.Write(bytes.Repeat(plan[i:i+2], int(plan[i+1])))
				if errors.Join(err, file.Close()) == nil {
					regular = append(regular, name)
				}
			}
		case 2:
			os.Symlink(aimed[int(plan[i+1])%len(aimed)], name)
		case 3:
			syscall.Mkfifo(name, 0o644)
		case 4:
			if len(regular) > 0 {
				os.Link(regular[int(plan[i+1])%len(regular)], name)
			}
		case 5:
			os.Symlink(filepath.Join(root, "..", "outside"), name)
		}
	}
}

// Whatever a directory holds, links that lead anywhere, pipes no one writes,
// names of any bytes and files with several names among it, walking it reads
// what lstat says each name stands for, never follows a link and is never held.
func FuzzWalk(f *testing.F) {
	f.Add([]byte{0, 0, 0x11, 1, 2, 3, 3, 4, 0x14, 5, 0x15, 6, 4, 7, 0x22, 2, 5, 8})
	f.Add(bytes.Repeat([]byte{0, 1, 0x12, 0, 0x23, 9}, 8))
	f.Fuzz(func(t *testing.T, plan []byte) {
		top := t.TempDir()
		root := filepath.Join(top, "watched")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(top, "outside"), []byte("outside"), 0o644); err != nil {
			t.Fatal(err)
		}
		built(t, root, plan)
		walked := make(chan error, 1)
		go func() { walked <- walk(root) }()
		select {
		case err := <-walked:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("walking the directory was held")
		}
	})
}

func walk(path string) error {
	held, err := tree.Open(path)
	if err != nil {
		return err
	}
	defer held.Close()
	return walkWithin(held, path)
}

func walkWithin(held *tree.Dir, path string) error {
	names, err := held.Names(1024)
	if err != nil {
		return err
	}
	for _, name := range names {
		named := filepath.Join(path, name)
		node, err := held.Stat(name)
		if err != nil {
			return err
		}
		described, err := os.Lstat(named)
		if err != nil {
			return err
		}
		system := described.Sys().(*syscall.Stat_t)
		if node.Inode != system.Ino || node.Size != described.Size() || node.Links != uint64(system.Nlink) {
			return errors.New(named + " was described as another file than lstat describes")
		}
		switch node.Kind {
		case tree.Directory:
			entered, err := held.Enter(name, node)
			if err != nil {
				return err
			}
			err = walkWithin(entered, named)
			entered.Close()
			if err != nil {
				return err
			}
		case tree.Regular:
			file, err := held.Read(name, node)
			if err != nil {
				return err
			}
			content, err := io.ReadAll(file)
			file.Close()
			if want, read := os.ReadFile(named); read != nil || err != nil || !bytes.Equal(content, want) {
				return errors.New(named + " was read as other bytes than it holds")
			}
		case tree.Link:
			target, err := held.Target(name, 4096)
			if want, read := os.Readlink(named); read != nil || err != nil || target != want {
				return errors.New(named + " was read as another target than it names")
			}
			if _, err := held.Enter(name, node); err == nil {
				return errors.New("the link " + named + " was entered as a directory")
			}
			if file, err := held.Read(name, node); err == nil {
				file.Close()
				return errors.New("the link " + named + " was read as a file")
			}
		default:
			if file, err := held.Read(name, node); err == nil {
				file.Close()
				return errors.New(named + ", which is no regular file, was read as one")
			}
		}
	}
	return nil
}
