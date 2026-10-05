package files

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

var (
	ErrLocked   = errors.New("another process holds the lock")
	ErrTooLarge = errors.New("the file holds more than the agent reads of it")
)

// Read returns what the regular file at path holds, when that is at most most
// bytes. It opens the file without waiting for a writer, so a FIFO put in its
// place cannot hold the agent, and it reads nothing but a regular file.
func Read(path string, most int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	described, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !described.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	content, err := io.ReadAll(io.LimitReader(file, most+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > most {
		return nil, fmt.Errorf("%w: %s holds more than %d bytes", ErrTooLarge, path, most)
	}
	return content, nil
}
