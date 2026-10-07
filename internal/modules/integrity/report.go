package integrity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/inotify"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/tree"
)

const (
	loggedPerMinute = 1000
	examples        = 4
	cut             = "..."
)

var (
	ErrUnobserved   = errors.New("the module cannot look at a path it was given")
	ErrTruncated    = errors.New("the paths the module was given hold more than it keeps")
	ErrUnwatched    = errors.New("the kernel tells the module nothing of some directories it watches")
	errLinked       = errors.New("the path is a symbolic link, which the module never follows")
	errWatchesSpent = errors.New("the module watches as many directories as it may")
)

const dropIn = "have the service show the agent what it hides and let it read what only root reads: a drop-in for seagull-agent.service that sets ProtectHome=read-only, CapabilityBoundingSet=CAP_DAC_READ_SEARCH and AmbientCapabilities=CAP_DAC_READ_SEARCH, then systemctl daemon-reload and systemctl restart seagull-agent; or leave what the agent cannot read out of modules.files.paths"

func Recovery(failed error) string {
	switch {
	case errors.Is(failed, fs.ErrPermission):
		return dropIn
	case errors.Is(failed, errLinked), errors.Is(failed, tree.ErrLink):
		return "name in modules.files.paths the path the link leads to: the module never follows a link"
	case errors.Is(failed, ErrTruncated):
		return "narrow modules.files.paths, or leave out of it with modules.files.exclude what changes by design"
	case errors.Is(failed, inotify.ErrLimit), errors.Is(failed, errWatchesSpent):
		return "raise fs.inotify.max_user_watches with sysctl, or narrow modules.files.paths: meanwhile the module finds what changes in the directories it does not watch every modules.files.interval"
	case errors.Is(failed, ErrUnwatched):
		return "none: the module finds what changes every modules.files.interval"
	}
	return "none: the module looks again as it next walks the paths it watches"
}

// report writes down one change the module found. A minute writes down at
// most a thousand, so a package upgrade or a directory that changes by design
// cannot crowd the rest of the agent out of the journal, and what it holds
// back is counted and said once the pass ends.
func (c *Collector) report(found change, origin string) {
	now := time.Now()
	c.mu.Lock()
	c.changes++
	c.changed = now
	if now.Sub(c.window) >= time.Minute {
		c.window, c.logged = now, 0
	}
	allowed := c.logged < loggedPerMinute
	if allowed {
		c.logged++
	} else {
		c.unlogged++
		c.withheld[found.operation]++
	}
	c.mu.Unlock()
	if origin == fromRealtime {
		c.retain(found.path, now)
	}
	if !allowed {
		return
	}
	attributes := []any{slog.String("path", told(found.path)), slog.String("operation", found.operation), slog.String("origin", origin)}
	if found.previous != "" {
		attributes = append(attributes, slog.String("previous", told(found.previous)))
	}
	if len(found.changes) > 0 {
		attributes = append(attributes, slog.Any("changes", found.changes))
	}
	if found.hint != nil {
		attributes = append(attributes, slog.Any("seen", found.hint.seen.Names()), slog.Int("coalesced", found.hint.count))
	}
	if found.before != nil {
		attributes = append(attributes, slog.Group("before", described(found.before)...))
	}
	if found.after != nil {
		attributes = append(attributes, slog.Group("after", described(found.after)...))
	}
	c.logger.Info("file_changed", attributes...)
}

func (c *Collector) withholding() {
	c.mu.Lock()
	withheld := maps.Clone(c.withheld)
	clear(c.withheld)
	c.mu.Unlock()
	if len(withheld) == 0 {
		return
	}
	counted := make([]any, 0, len(withheld))
	for _, operation := range slices.Sorted(maps.Keys(withheld)) {
		counted = append(counted, slog.Int(operation, withheld[operation]))
	}
	c.logger.Warn("files_changes_not_logged", slog.Group("withheld", counted...),
		slog.String("reason", fmt.Sprintf("the module writes down at most %d changes a minute, and found more", loggedPerMinute)),
		slog.String("recovery", "leave what changes by design out of modules.files.paths, or out of what it watches with modules.files.exclude"))
}

func described(held *entry) []any {
	node := held.node
	attributes := []any{
		slog.String("kind", node.Kind.String()),
		slog.Uint64("device", node.Device),
		slog.Uint64("inode", node.Inode),
		slog.Uint64("links", node.Links),
		slog.Uint64("user", uint64(node.User)),
		slog.Uint64("group", uint64(node.Group)),
		slog.String("mode", fmt.Sprintf("%04o", node.Mode)),
		slog.Int64("size", node.Size),
		slog.Time("modified", node.Modified.UTC()),
		slog.Time("changed", node.Changed.UTC()),
	}
	switch node.Kind {
	case tree.Regular:
		if held.content.state == hashed {
			attributes = append(attributes, slog.String("sha256", hex.EncodeToString(held.content.digest[:])))
		} else {
			state := knowns[held.content.state]
			if state == "" {
				state = "unread"
			}
			attributes = append(attributes, slog.String("content", state))
		}
	case tree.Link:
		attributes = append(attributes, slog.String("target", told(held.target)))
	case tree.Block, tree.Character:
		attributes = append(attributes, slog.Uint64("special", node.Special))
	}
	return attributes
}

// told is a name the host keeps as a message may carry it: one that is not
// printable text is quoted as Go quotes a string, and every name is cut at
// what a path holds at most.
func told(text string) string {
	if !utf8.ValidString(text) || strings.IndexFunc(text, func(held rune) bool { return !unicode.IsPrint(held) }) >= 0 {
		text = strconv.Quote(text)
	}
	if len(text) <= maxPathBytes {
		return text
	}
	held := text[:maxPathBytes-len(cut)]
	for !utf8.ValidString(held) {
		held = held[:len(held)-1]
	}
	return held + cut
}

type Gap struct {
	Count    int
	Examples []string
}

func (g *Gap) add(path string) {
	g.Count++
	if len(g.Examples) < examples {
		g.Examples = append(g.Examples, told(path))
	}
}

func (g Gap) String() string {
	if g.Count == 0 {
		return ""
	}
	return fmt.Sprintf("%d, such as %s", g.Count, strings.Join(g.Examples, ", "))
}

type Stats struct {
	Paths       int
	Entries     int
	Directories int
	Watched     int
	Changes     uint64
	Unlogged    uint64
	Changed     time.Time
	Walked      time.Time
	Missing     []string
	Unlisted    Gap
	Unread      Gap
	Large       Gap
	Unstable    Gap
	Mounts      Gap
	Deep        Gap
	Failure     error
}

func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	held := c.stats
	held.Missing = slices.Clone(held.Missing)
	held.Watched, held.Changes, held.Unlogged, held.Changed = 0, c.changes, c.unlogged, c.changed
	for _, watching := range c.byWatch {
		if watching.listing {
			held.Watched++
		}
	}
	if held.Failure == nil && c.unwatched != nil {
		held.Failure = fmt.Errorf("%w: %w", ErrUnwatched, c.unwatched)
	}
	return held
}

// survey counts what the baseline holds and what the module could not see of
// the paths it watches, as of the last time it looked at each.
func (c *Collector) survey(walked time.Time) {
	held := Stats{Paths: len(c.scope.given.Paths), Walked: walked}
	var failures []error
	for _, path := range c.scope.given.Paths {
		kept := c.held.roots[path]
		switch {
		case kept == nil:
		case kept.problem != nil:
			failures = append(failures, fmt.Errorf("%w: %s: %w", ErrUnobserved, told(path), kept.problem))
		case kept.observed && kept.entry == nil:
			held.Missing = append(held.Missing, told(path))
		}
		if kept == nil || kept.entry == nil {
			continue
		}
		kept.entry.each(path, func(path string, saw *entry) {
			held.Entries++
			switch saw.node.Kind {
			case tree.Directory:
				held.Directories++
				switch saw.gap {
				case unlisted:
					held.Unlisted.add(path)
				case mounted:
					held.Mounts.add(path)
				case deep:
					held.Deep.add(path)
				case truncated:
					failures = append(failures, fmt.Errorf("%w: %s holds more than the %d entries the module keeps", ErrTruncated, told(path), maxEntries))
				}
			case tree.Regular:
				switch saw.content.state {
				case unreadable:
					held.Unread.add(path)
				case large:
					held.Large.add(path)
				case unstable:
					held.Unstable.add(path)
				}
			}
		})
	}
	if len(failures) > 0 {
		held.Failure = failures[0]
	}
	c.mu.Lock()
	if c.stats.Walked.After(walked) {
		held.Walked = c.stats.Walked
	}
	c.stats = held
	c.mu.Unlock()
	said := held.Coverage()
	if said == c.covered {
		return
	}
	c.covered = said
	if said == "" {
		c.logger.Info("files_covered", slog.Int("entries", held.Entries))
		return
	}
	reported := []any{slog.String("reason", said)}
	if held.Failure != nil {
		reported = append(reported, slog.Any("error", held.Failure), slog.String("recovery", Recovery(held.Failure)))
	} else if held.Unlisted.Count > 0 || held.Unread.Count > 0 {
		reported = append(reported, slog.String("recovery", dropIn))
	}
	c.logger.Warn("files_not_covered", reported...)
}

func (s Stats) Coverage() string {
	var said []string
	for _, gap := range []struct {
		what string
		held Gap
	}{
		{"directories it cannot list", s.Unlisted},
		{"files whose content it cannot read", s.Unread},
		{"files larger than it hashes", s.Large},
		{"files that changed whenever it read them", s.Unstable},
		{"directories on another filesystem, which it does not walk", s.Mounts},
		{"directories deeper than it walks", s.Deep},
	} {
		if gap.held.Count > 0 {
			said = append(said, fmt.Sprintf("%s: %s", gap.what, gap.held))
		}
	}
	if len(s.Missing) > 0 {
		said = append(said, fmt.Sprintf("paths that name nothing on this host: %s", strings.Join(s.Missing, ", ")))
	}
	if s.Failure != nil {
		said = append(said, s.Failure.Error())
	}
	return strings.Join(said, "; ")
}
