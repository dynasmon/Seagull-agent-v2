// Package logindefs reads /etc/login.defs as the shadow utilities read it: a
// name, white space and a value up to a double quote, the last line naming an
// item being the one they apply.
package logindefs

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

const MaxBytes = 256 << 10

var path = "/etc/login.defs"

var (
	ErrAbsent     = errors.New("the host has no login.defs")
	ErrUnreadable = errors.New("login.defs cannot be read by the agent")
)

type Setting struct {
	Value string
	File  string
	Line  int
}

// Read returns the value each item is set to, by the line that sets it last.
func Read() (map[string]Setting, error) {
	content, err := files.Read(path, MaxBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%w: %s is not there", ErrAbsent, path)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	held := map[string]Setting{}
	for index, line := range strings.Split(string(content), "\n") {
		line = strings.TrimRight(line, " \t\r\n")
		name := strings.TrimLeft(line, " \t")
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		end := strings.IndexAny(name, " \t")
		if end < 0 {
			held[name] = Setting{File: path, Line: index + 1}
			continue
		}
		value := strings.TrimLeft(name[end:], " \t\"")
		if quote := strings.IndexByte(value, '"'); quote >= 0 {
			value = value[:quote]
		}
		held[name[:end]] = Setting{Value: value, File: path, Line: index + 1}
	}
	return held, nil
}
