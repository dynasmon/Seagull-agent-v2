package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
)

const syslogIdentifier = "seagull-agent"

// What a command that changes the installation did, written to the system
// journal as the running agent writes its log, where journald writes down
// beside it who ran the command as the kernel tells: the account, the process
// and, on a host that keeps login sessions, the login it was run from, through
// however many accounts it went. A platform with no journal keeps no record.
var noted = journal.Send

func audit(stderr io.Writer, level slog.Level, event string, attributes ...slog.Attr) {
	var written bytes.Buffer
	slog.New(slog.NewJSONHandler(&written, nil)).LogAttrs(context.Background(), level, event, attributes...)
	err := noted(journal.Note{
		Identifier: syslogIdentifier,
		Priority:   priority(level),
		Message:    strings.TrimSuffix(written.String(), "\n"),
		Fields:     map[string]string{"SEAGULL_EVENT": event},
	})
	if err != nil && !errors.Is(err, errors.ErrUnsupported) {
		fmt.Fprintf(stderr, "seagull-agent: the system journal holds no record of what this command did: %v\n", err)
	}
}

func priority(level slog.Level) int {
	switch {
	case level >= slog.LevelError:
		return 3
	case level >= slog.LevelWarn:
		return 4
	}
	return 6
}
