//go:build linux || darwin

package metadata

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAPathIsDescribedAsTheKernelShowsItWithoutFollowingItself(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "shadow")
	if err := os.WriteFile(file, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o640|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	through := filepath.Join(root, "through")
	if err := os.Symlink(root, through); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]Node{
		file:                             {Kind: Regular, User: uint32(os.Getuid()), Group: uint32(os.Getgid()), Permissions: 0o2640},
		link:                             {Kind: Symlink, User: uint32(os.Getuid()), Group: uint32(os.Getgid()), Permissions: 0o777},
		filepath.Join(through, "shadow"): {Kind: Regular, User: uint32(os.Getuid()), Group: uint32(os.Getgid()), Permissions: 0o2640},
		root:                             {Kind: Directory, User: uint32(os.Getuid()), Group: uint32(os.Getgid()), Permissions: 0o700},
	} {
		got, err := Describe(path)
		if err != nil || got != want {
			t.Errorf("%s is described as %+v: %v, want %+v", path, got, err, want)
		}
	}
	for _, path := range []string{filepath.Join(root, "absent"), filepath.Join(file, "below")} {
		if _, err := Describe(path); !errors.Is(err, ErrAbsent) {
			t.Errorf("%s was answered %v", path, err)
		}
	}
	for _, path := range []string{"relative", root + "/../x", root + "/"} {
		if _, err := Describe(path); err == nil || errors.Is(err, ErrAbsent) {
			t.Errorf("%q was answered %v", path, err)
		}
	}
}

func TestAPathTheServiceMountsAnInaccessibleNodeOverIsHidden(t *testing.T) {
	root := t.TempDir()
	nodes := filepath.Join(root, "inaccessible")
	if err := os.MkdirAll(filepath.Join(nodes, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	saved := inaccessible
	inaccessible = nodes
	t.Cleanup(func() { inaccessible = saved })
	over := filepath.Join(root, "home")
	if err := os.Symlink(filepath.Join(nodes, "dir"), over); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(over, "alice", ".ssh"), filepath.Join(nodes, "dir")} {
		if _, err := Describe(path); !errors.Is(err, ErrHidden) {
			t.Errorf("%s, reached through an inaccessible node, was answered %v", path, err)
		}
	}
	if _, err := Describe(root); err != nil {
		t.Errorf("a path the service does not hide was answered %v", err)
	}
}

func TestADirectoryTheAccountCannotSearchDeniesWhatIsBelowIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser searches whatever the mode says")
	}
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, "key"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
	if _, err := Describe(filepath.Join(private, "key")); !errors.Is(err, ErrDenied) {
		t.Fatalf("a file below a directory the account cannot search was answered %v", err)
	}
	var held syscall.Stat_t
	if err := syscall.Stat(private, &held); err != nil || held.Mode&0o777 != 0 {
		t.Fatalf("the directory reads as mode %o: %v", held.Mode&0o777, err)
	}
}
