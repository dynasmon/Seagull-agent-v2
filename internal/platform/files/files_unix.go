//go:build linux || darwin

package files

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// The lock belongs to the open file, so the kernel releases it when the file is
// closed or the process ends, however it ends.
func Lock(file *os.File) error {
	connection, err := file.SyscallConn()
	if err != nil {
		return fmt.Errorf("lock %s: %w", file.Name(), err)
	}
	var locked error
	if err := connection.Control(func(descriptor uintptr) {
		locked = syscall.Flock(int(descriptor), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil {
		return fmt.Errorf("lock %s: %w", file.Name(), err)
	}
	if errors.Is(locked, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	if locked != nil {
		return fmt.Errorf("lock %s: %w", file.Name(), locked)
	}
	return nil
}

// Available is what the filesystem holding file still lets an account that is
// not the superuser write, which is the room the agent can count on.
func Available(file *os.File) (int64, error) {
	connection, err := file.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("measure the room left beside %s: %w", file.Name(), err)
	}
	var described syscall.Statfs_t
	var measured error
	if err := connection.Control(func(descriptor uintptr) {
		measured = syscall.Fstatfs(int(descriptor), &described)
	}); err != nil {
		return 0, fmt.Errorf("measure the room left beside %s: %w", file.Name(), err)
	}
	if measured != nil {
		return 0, fmt.Errorf("measure the room left beside %s: %w", file.Name(), measured)
	}
	return int64(described.Bavail) * int64(described.Bsize), nil
}

func Private(info fs.FileInfo) error {
	described, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("does not say who owns it")
	}
	if owner, agent := int(described.Uid), os.Geteuid(); owner != agent {
		return fmt.Errorf("belongs to uid %d and the agent runs as uid %d", owner, agent)
	}
	if permissions := info.Mode().Perm(); permissions&0o077 != 0 {
		return fmt.Errorf("grants %s, which opens it to its group or to others", permissions)
	}
	return nil
}

// Trusted reports what the file says about who may change it. The agent's
// settings are public, and deciding them belongs to the account the agent runs
// as and to the superuser alone.
func Trusted(info fs.FileInfo) error {
	described, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("does not say who owns it")
	}
	if owner, agent := int(described.Uid), os.Geteuid(); owner != agent && owner != 0 {
		return fmt.Errorf("belongs to uid %d, and the agent runs as uid %d", owner, agent)
	}
	if permissions := info.Mode().Perm(); permissions&0o022 != 0 {
		return fmt.Errorf("grants %s, which lets its group or others change it", permissions)
	}
	return nil
}

func Owner(info fs.FileInfo) (int, error) {
	described, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("does not say who owns it")
	}
	return int(described.Uid), nil
}
