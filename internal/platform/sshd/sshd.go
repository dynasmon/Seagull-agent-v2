// Package sshd reads the configuration the OpenSSH server reads at start:
// /etc/ssh/sshd_config and every file its Include directives name, split into
// keywords and arguments as sshd splits them. It says which value each line
// sets and whether a Match block holds the line, and decides nothing of what
// sshd makes of a keyword.
package sshd

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxDepth     = 16
	MaxFiles     = 256
	MaxFileBytes = 1 << 20
)

var (
	configuration = "/etc/ssh/sshd_config"
	directory     = "/etc/ssh"
)

var (
	ErrAbsent     = errors.New("the host has no configuration of the OpenSSH server")
	ErrUnreadable = errors.New("a file the OpenSSH server reads cannot be read by the agent")
	ErrMalformed  = errors.New("the OpenSSH server would not read its configuration")
)

// A Setting is one line naming a keyword: its arguments joined by one space,
// where it is, and the criteria of the Match block it is in, empty for a line
// that holds for every connection. Settings returns every line naming the
// keyword, without regard to case, in the order sshd reads them.
type Setting struct {
	Value string
	File  string
	Line  int
	Match string
}

type Configuration struct {
	settings map[string][]Setting
}

func (c Configuration) Settings(keyword string) []Setting {
	return c.settings[strings.ToLower(keyword)]
}

type reading struct {
	held  Configuration
	files int
}

func Read() (Configuration, error) {
	reader := &reading{held: Configuration{settings: map[string][]Setting{}}}
	if err := reader.file(configuration, "", 0); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Configuration{}, fmt.Errorf("%w: %s is not there", ErrAbsent, configuration)
		}
		return Configuration{}, err
	}
	return reader.held, nil
}

// Within an included file a Match block ends where the file does, and every
// line of a file included from within a Match block is held by that block.
func (r *reading) file(path, held string, depth int) error {
	r.files++
	if r.files > MaxFiles {
		return fmt.Errorf("%w: it names more than %d files", ErrMalformed, MaxFiles)
	}
	content, err := files.Read(path, MaxFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist) && depth == 0:
		return err
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%w: %s", ErrUnreadable, path)
	case err != nil:
		return fmt.Errorf("%w: %s: %s", ErrUnreadable, path, secrets.Bounded(err.Error()))
	}
	match := held
	for index, line := range strings.Split(string(content), "\n") {
		keyword, arguments, err := split(line)
		switch {
		case err != nil:
			return fmt.Errorf("%w: %s line %d: %v", ErrMalformed, path, index+1, err)
		case keyword == "":
			continue
		}
		switch strings.ToLower(keyword) {
		case "match":
			if held == "" {
				match = strings.Join(arguments, " ")
				if strings.EqualFold(match, "all") {
					match = ""
				}
			}
		case "include":
			if depth >= MaxDepth {
				return fmt.Errorf("%w: %s line %d includes deeper than %d files", ErrMalformed, path, index+1, MaxDepth)
			}
			for _, pattern := range arguments {
				if !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "~") {
					pattern = filepath.Join(directory, pattern)
				}
				named, err := filepath.Glob(pattern)
				if err != nil {
					return fmt.Errorf("%w: %s line %d: %s", ErrMalformed, path, index+1, secrets.Shown(pattern))
				}
				for _, included := range named {
					if err := r.file(included, match, depth+1); err != nil {
						return err
					}
				}
			}
		default:
			setting := Setting{Value: strings.Join(arguments, " "), File: path, Line: index + 1, Match: match}
			r.held.settings[strings.ToLower(keyword)] = append(r.held.settings[strings.ToLower(keyword)], setting)
		}
	}
	return nil
}

// split reads a line as sshd does: the keyword up to white space or one
// equals sign, then arguments split on white space, quoted with double or
// single quotes, escaped with a backslash, and ended by a # that starts one.
func split(line string) (string, []string, error) {
	line = strings.TrimRight(line, " \t\r\f")
	rest := strings.TrimLeft(line, " \t")
	if rest == "" || strings.HasPrefix(rest, "#") {
		return "", nil, nil
	}
	end := strings.IndexAny(rest, " \t=")
	if end < 0 {
		return "", nil, fmt.Errorf("no argument after keyword %s", secrets.Shown(rest))
	}
	keyword := rest[:end]
	rest = strings.TrimLeft(rest[end:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	arguments, err := arguments(rest)
	if err != nil {
		return "", nil, err
	}
	if len(arguments) == 0 {
		return "", nil, fmt.Errorf("no argument after keyword %s", secrets.Shown(keyword))
	}
	return keyword, arguments, nil
}

func arguments(text string) ([]string, error) {
	var found []string
	for i := 0; i < len(text); i++ {
		if text[i] == ' ' || text[i] == '\t' {
			continue
		}
		if text[i] == '#' {
			break
		}
		var argument strings.Builder
		quote := byte(0)
		for ; i < len(text); i++ {
			c := text[i]
			switch {
			case c == '\\' && i+1 < len(text) && (text[i+1] == '\'' || text[i+1] == '"' || text[i+1] == '\\' || (quote == 0 && text[i+1] == ' ')):
				i++
				argument.WriteByte(text[i])
				continue
			case quote == 0 && (c == ' ' || c == '\t'):
			case quote == 0 && (c == '"' || c == '\''):
				quote = c
				continue
			case quote != 0 && c == quote:
				quote = 0
				continue
			default:
				argument.WriteByte(c)
				continue
			}
			break
		}
		if quote != 0 {
			return nil, errors.New("a quote is never closed")
		}
		found = append(found, argument.String())
	}
	return found, nil
}
