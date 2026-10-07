//go:build !linux

package tree

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

var errLooped = errors.New("the name is a link")

func describe(fs.FileInfo) (Node, error) {
	return Node{}, fmt.Errorf("describe the files of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}

func openFile(*os.File, string) (*os.File, error) {
	return nil, fmt.Errorf("read the files of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
