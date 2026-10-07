package integrity

import (
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/inotify"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/tree"
)

const (
	settle     = time.Second
	firstHold  = 2 * time.Second
	longest    = 5 * time.Minute
	maxDirty   = 1 << 16
	maxWatches = 1 << 14
)

// What a Watcher tells is what the kernel said happened in the directories
// it was given; the module looks at those names again before it believes any
// of it.
type Watcher interface {
	Add(directory *os.File) (int, error)
	Remove(watch int) error
	Read() ([]inotify.Event, error)
	Close() error
}

type hint struct {
	first   time.Time
	count   int
	seen    inotify.What
	cookies []uint32
}

const (
	maxCookies = 8
	structural = inotify.Created | inotify.Deleted | inotify.MovedFrom | inotify.MovedTo | inotify.SelfDeleted | inotify.SelfMoved | inotify.Unmounted
)

type watched struct {
	path    string
	listing bool
}

type hold struct {
	until  time.Time
	length time.Duration
}

// watch has the kernel tell what happens in a directory the module holds
// open, unless it watches as many directories as it may already.
func (c *Collector) watch(dir *tree.Dir, path string, listing bool) {
	if c.watcher == nil {
		return
	}
	c.mu.Lock()
	_, found := c.byPath[path]
	full := len(c.byWatch) >= maxWatches
	c.mu.Unlock()
	if full && !found {
		c.limited(errWatchesSpent)
		return
	}
	watch, err := c.watcher.Add(dir.File())
	if err != nil {
		if errors.Is(err, inotify.ErrLimit) {
			c.limited(err)
		}
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if earlier, found := c.byWatch[watch]; found && c.byPath[earlier.path] == watch {
		delete(c.byPath, earlier.path)
	}
	c.byWatch[watch] = watched{path: path, listing: listing}
	c.byPath[path] = watch
}

func (c *Collector) limited(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.unwatched == nil {
		c.unwatched = err
	}
}

// unwatch stops watching what the scope no longer covers.
func (c *Collector) unwatch() {
	if c.watcher == nil {
		return
	}
	c.mu.Lock()
	var dropped []int
	for watch, held := range c.byWatch {
		if !c.scope.covers(held.path) && !slices.ContainsFunc(c.scope.given.Paths, func(root string) bool { return filepath.Dir(root) == held.path }) {
			dropped = append(dropped, watch)
			delete(c.byWatch, watch)
			delete(c.byPath, held.path)
		}
	}
	c.mu.Unlock()
	for _, watch := range dropped {
		c.watcher.Remove(watch)
	}
}

func (c *Collector) listen(watcher Watcher) {
	for {
		events, err := watcher.Read()
		c.heard(events, time.Now())
		if err != nil {
			if !errors.Is(err, inotify.ErrClosed) {
				c.ended <- err
			}
			return
		}
	}
}

func (c *Collector) heard(events []inotify.Event, now time.Time) {
	if len(events) == 0 {
		return
	}
	c.mu.Lock()
	for _, event := range events {
		if event.What&inotify.Overflowed != 0 {
			c.lost++
			continue
		}
		held, found := c.byWatch[event.Watch]
		if !found {
			continue
		}
		if event.What&inotify.Ignored != 0 {
			delete(c.byWatch, event.Watch)
			if c.byPath[held.path] == event.Watch {
				delete(c.byPath, held.path)
			}
		}
		path := held.path
		if event.Name != "" {
			if strings.ContainsRune(event.Name, '/') || event.Name == "." || event.Name == ".." {
				continue
			}
			path = filepath.Join(held.path, event.Name)
		}
		root, covered := c.scope.root(path)
		if !covered || c.scope.excludes(path) {
			continue
		}
		if event.What&inotify.SelfMoved != 0 || event.What&inotify.OfDirectory != 0 && event.What&(inotify.MovedFrom|inotify.MovedTo) != 0 {
			c.moved[root] = true
		}
		noted := c.dirty[path]
		if noted == nil {
			if len(c.dirty) >= maxDirty {
				c.lost++
				clear(c.dirty)
				clear(c.cookies)
				continue
			}
			noted = &hint{first: now}
			c.dirty[path] = noted
		}
		noted.count++
		noted.seen |= event.What
		if event.Cookie != 0 && event.What&(inotify.MovedFrom|inotify.MovedTo) != 0 && len(noted.cookies) < maxCookies && !slices.Contains(noted.cookies, event.Cookie) {
			noted.cookies = append(noted.cookies, event.Cookie)
			c.cookies[event.Cookie] = append(c.cookies[event.Cookie], path)
		}
	}
	c.mu.Unlock()
	select {
	case c.hinted <- struct{}{}:
	default:
	}
}

// due takes the hints that settled: a name the kernel spoke of a while ago,
// which is not held back for having been written shortly before. A name keeps
// being held back for twice as long each time it is written again within the
// time it was held, up to five minutes, so a file that keeps changing is
// reported a few times an hour rather than on every write, with every hint
// it folded into the report counted. A name created, deleted or moved is
// never held back, and the two names of a move settle together.
func (c *Collector) due(now time.Time) (map[string]*hint, []string, uint64, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ready := map[string]*hint{}
	for path, noted := range c.dirty {
		at := noted.first.Add(settle)
		if held, found := c.holds[path]; found && held.until.After(at) && noted.seen&structural == 0 {
			at = held.until
		}
		if !at.After(now) {
			ready[path] = noted
		}
	}
	for pending := slices.Collect(maps.Keys(ready)); len(pending) > 0; {
		path := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, cookie := range ready[path].cookies {
			for _, partner := range c.cookies[cookie] {
				if noted, found := c.dirty[partner]; found && ready[partner] == nil {
					ready[partner] = noted
					pending = append(pending, partner)
				}
			}
			delete(c.cookies, cookie)
		}
	}
	var next time.Time
	for path, noted := range c.dirty {
		if ready[path] != nil {
			delete(c.dirty, path)
			continue
		}
		at := noted.first.Add(settle)
		if held, found := c.holds[path]; found && held.until.After(at) && noted.seen&structural == 0 {
			at = held.until
		}
		if next.IsZero() || at.Before(next) {
			next = at
		}
	}
	for path, held := range c.holds {
		if now.After(held.until.Add(held.length)) {
			delete(c.holds, path)
		}
	}
	moved := slices.Sorted(maps.Keys(c.moved))
	clear(c.moved)
	lost := c.lost
	c.lost = 0
	return ready, moved, lost, next
}

func (c *Collector) retain(path string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	length := firstHold
	if held, found := c.holds[path]; found && !now.After(held.until.Add(held.length)) {
		length = min(2*held.length, longest)
	}
	c.holds[path] = hold{until: now.Add(length), length: length}
}

func (c *Collector) hintsLost() {
	c.mu.Lock()
	c.losses++
	losses := c.losses
	c.mu.Unlock()
	if losses&(losses-1) == 0 {
		c.logger.Warn("files_hints_lost", slog.Uint64("times", losses),
			slog.String("reason", "the kernel dropped what it had to say of the directories the module watches, or said more than the module keeps, so the module walks every path it watches again"),
			slog.String("recovery", "none: the walk finds whatever changed meanwhile"))
	}
}
