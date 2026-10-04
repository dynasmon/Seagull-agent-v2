// Package journal reads the system journal through journalctl, whose export
// format systemd documents: the entries a query matches, in the order the
// journal holds them, each named by its cursor and carrying the moment
// journald wrote it down and the fields asked for.
package journal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxLine      = 64 << 10
	MaxLast      = 10000
	maxComplaint = 1 << 10
	maxFields    = 32
	stopping     = time.Second
	denied       = "insufficient permissions"
)

var program = "/usr/bin/journalctl"

var (
	ErrUnreadable = errors.New("journalctl wrote an entry that cannot be read")
	ErrDenied     = errors.New("the account the agent runs as may not read the system journal")
	cursorPattern = regexp.MustCompile(`^s=[0-9a-f]{32};i=[0-9a-f]{1,16};b=[0-9a-f]{32};m=[0-9a-f]{1,16};t=[0-9a-f]{1,16};x=[0-9a-f]{1,16}$`)
	fieldPattern  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	unitPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,240}\.service$`)
)

type Match struct {
	Field string
	Value string
}

// A Query reads the entries that hold, for every field it matches on, one of
// the values it names for that field, and of each entry the fields it names.
// Naming a unit reads what journalctl reads for one: what the processes of the
// service wrote and what the service manager wrote about it.
type Query struct {
	Unit    string
	Matches []Match
	Fields  []string
}

type Position struct {
	Cursor string
	Since  time.Time
	Last   int
}

type Entry struct {
	Cursor   string
	Realtime time.Time
	Fields   map[string]string
}

type Journal struct {
	query Query
}

func New(query Query) (*Journal, error) {
	var problems []error
	if len(query.Matches) == 0 && query.Unit == "" {
		problems = append(problems, errors.New("a query matches on a unit or on at least one field"))
	}
	if query.Unit != "" && !unitPattern.MatchString(query.Unit) {
		problems = append(problems, fmt.Errorf("%s is not a service of the system", secrets.Bounded(query.Unit)))
	}
	for _, match := range query.Matches {
		if !fieldPattern.MatchString(match.Field) || match.Value == "" || strings.ContainsAny(match.Value, "\x00\n") {
			problems = append(problems, fmt.Errorf("%s=%s is not a match on a field of the journal", secrets.Bounded(match.Field), secrets.Bounded(match.Value)))
		}
	}
	if len(query.Fields) == 0 || len(query.Fields) > maxFields {
		problems = append(problems, fmt.Errorf("a query reads between 1 and %d fields of each entry", maxFields))
	}
	for _, field := range query.Fields {
		if !fieldPattern.MatchString(field) {
			problems = append(problems, fmt.Errorf("%s is not a field of the journal", secrets.Bounded(field)))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the query of the journal: %w", errors.Join(problems...))
	}
	return &Journal{query: Query{Unit: query.Unit, Matches: slices.Clone(query.Matches), Fields: slices.Clone(query.Fields)}}, nil
}

func Cursor(cursor string) bool { return cursorPattern.MatchString(cursor) }

// Open starts journalctl at from: at the entry its cursor names while the
// journal holds it, and otherwise where that entry was, at the first entry
// written at or after Since, or at the last entries the query matches. Without
// following it stops at the end of the journal; following, it goes on as
// journald writes until ctx ends or the reader is closed, and journalctl
// follows the boot that is running alone.
func (j *Journal) Open(ctx context.Context, from Position, follow bool) (*Reader, error) {
	start, err := from.argument()
	if err != nil {
		return nil, err
	}
	arguments := []string{"--system", "--no-pager", "--output=json", "--output-fields=" + strings.Join(j.query.Fields, ","), start}
	if follow {
		arguments = append(arguments, "--follow")
	}
	if j.query.Unit != "" {
		arguments = append(arguments, "--unit="+j.query.Unit)
	}
	for _, match := range j.query.Matches {
		arguments = append(arguments, match.Field+"="+match.Value)
	}
	ctx, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(ctx, program, arguments...)
	command.Env = []string{}
	command.WaitDelay = stopping
	said := &complaint{}
	command.Stderr = said
	if err := supervise(command); err != nil {
		cancel()
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err == nil {
		err = command.Start()
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("read the system journal: %w", err)
	}
	return &Reader{ctx: ctx, cancel: cancel, command: command, output: bufio.NewReaderSize(output, MaxLine), said: said, wanted: j.query.Fields}, nil
}

func (p Position) argument() (string, error) {
	switch starts := len(slices.DeleteFunc([]bool{p.Cursor != "", !p.Since.IsZero(), p.Last != 0}, func(set bool) bool { return !set })); {
	case starts > 1:
		return "", errors.New("a reading of the journal starts at a cursor, at a moment or at its last entries, and at one of them alone")
	case p.Last < 0 || p.Last > MaxLast:
		return "", fmt.Errorf("a reading of the journal starts at its last 1 to %d entries, not %d", MaxLast, p.Last)
	case p.Last > 0:
		return "--lines=" + strconv.Itoa(p.Last), nil
	case p.Cursor != "":
		if !cursorPattern.MatchString(p.Cursor) {
			return "", fmt.Errorf("%s is not a cursor of the journal", secrets.Bounded(p.Cursor))
		}
		return "--cursor=" + p.Cursor, nil
	case !p.Since.IsZero():
		micros := p.Since.UnixMicro()
		if micros < 0 {
			return "", fmt.Errorf("the journal holds nothing written before %s", time.Unix(0, 0).UTC().Format(time.RFC3339))
		}
		return fmt.Sprintf("--since=@%d.%06d", micros/1_000_000, micros%1_000_000), nil
	}
	return "", errors.New("a reading of the journal starts at a cursor, at a moment or at its last entries")
}

type Reader struct {
	ctx     context.Context
	cancel  context.CancelFunc
	command *exec.Cmd
	output  *bufio.Reader
	said    *complaint
	wanted  []string
	once    sync.Once
	stopped error
	ended   error
}

// Next returns the next entry. An entry it cannot read is reported as
// ErrUnreadable, and the ones after it are read all the same; once journalctl
// stops, Next reports io.EOF when it read to the end of the journal, and why
// it stopped otherwise.
func (r *Reader) Next() (Entry, error) {
	if r.ended != nil {
		return Entry{}, r.ended
	}
	line, err := r.output.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = r.output.ReadSlice('\n')
		}
		if err == nil {
			return Entry{}, fmt.Errorf("%w: it is longer than %d bytes", ErrUnreadable, MaxLine)
		}
	}
	if err != nil {
		r.ended = r.end(err)
		return Entry{}, r.ended
	}
	return r.decode(line)
}

func (r *Reader) Pending() bool { return r.output.Buffered() > 0 }

func (r *Reader) Close() error {
	r.cancel()
	r.wait()
	return nil
}

func (r *Reader) wait() error {
	r.once.Do(func() { r.stopped = r.command.Wait() })
	return r.stopped
}

func (r *Reader) end(read error) error {
	stopped := r.wait()
	switch {
	case r.ctx.Err() != nil:
		return r.ctx.Err()
	case stopped != nil:
		return r.said.explain(stopped)
	case errors.Is(read, io.EOF):
		return io.EOF
	}
	return fmt.Errorf("read what journalctl writes: %w", read)
}

func (r *Reader) decode(line []byte) (Entry, error) {
	var held map[string]json.RawMessage
	if err := json.Unmarshal(line, &held); err != nil {
		return Entry{}, fmt.Errorf("%w: %s", ErrUnreadable, secrets.Bounded(err.Error()))
	}
	cursor, named := text(held["__CURSOR"])
	if !named || !cursorPattern.MatchString(cursor) {
		return Entry{}, fmt.Errorf("%w: it names no cursor", ErrUnreadable)
	}
	written, dated := text(held["__REALTIME_TIMESTAMP"])
	micros, err := strconv.ParseInt(written, 10, 64)
	if !dated || err != nil || micros <= 0 {
		return Entry{}, fmt.Errorf("%w: it says no moment journald wrote it down", ErrUnreadable)
	}
	entry := Entry{Cursor: cursor, Realtime: time.UnixMicro(micros).UTC(), Fields: make(map[string]string, len(r.wanted))}
	for _, field := range r.wanted {
		if found, ok := value(held[field]); ok {
			entry.Fields[field] = found
		}
	}
	return entry, nil
}

func text(raw json.RawMessage) (string, bool) {
	var held string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &held) != nil {
		return "", false
	}
	return held, true
}

func value(raw json.RawMessage) (string, bool) {
	if held, ok := text(raw); ok {
		return held, true
	}
	var octets []int
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &octets) != nil {
		return "", false
	}
	held := make([]byte, len(octets))
	for i, octet := range octets {
		if octet < 0 || octet > 255 {
			return "", false
		}
		held[i] = byte(octet)
	}
	return string(held), true
}

type complaint struct {
	mu   sync.Mutex
	held []byte
}

func (c *complaint) Write(written []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := append(c.held, written[max(len(written)-maxComplaint, 0):]...)
	c.held = append([]byte(nil), kept[max(len(kept)-maxComplaint, 0):]...)
	return len(written), nil
}

func (c *complaint) explain(stopped error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	last := ""
	for line := range strings.SplitSeq(string(bytes.TrimSpace(c.held)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			last = line
		}
	}
	if last == "" {
		return fmt.Errorf("journalctl stopped: %w", stopped)
	}
	failure := fmt.Errorf("journalctl stopped, %v: %s", stopped, secrets.Bounded(last))
	if bytes.Contains(c.held, []byte(denied)) {
		return fmt.Errorf("%w: %w", ErrDenied, failure)
	}
	return failure
}
