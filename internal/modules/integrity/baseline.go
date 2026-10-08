package integrity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/tree"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	format        = 1
	baselineFile  = "files.json"
	maxBaseline   = 64 << 20
	maxPathBytes  = 4 << 10
	maxTarget     = 4 << 10
	digestPrefix  = "sha256:"
	maxWatchPaths = 64
)

var maxEntries = 100_000

var (
	ErrDamaged   = errors.New("what the module last saw of the files it watches cannot be read")
	ErrNewer     = errors.New("what the module last saw of the files it watches was written down by a newer agent")
	ErrInsecure  = errors.New("what the module last saw of the files it watches is not private to the account the agent runs as")
	errUnwritten = errors.New("the module has seen nothing of the files it watches yet")
	interrupted  = regexp.MustCompile(`^\.` + regexp.QuoteMeta(baselineFile) + `\.[0-9a-f]{16}\.tmp$`)
)

type known uint8

const (
	unread known = iota
	hashed
	unreadable
	large
	unstable
)

var knowns = map[known]string{unreadable: "unreadable", large: "large", unstable: "unstable"}

type content struct {
	state  known
	digest [sha256.Size]byte
}

func (c content) String() string {
	if c.state == hashed {
		return digestPrefix + hex.EncodeToString(c.digest[:])
	}
	return knowns[c.state]
}

type gap uint8

const (
	covered gap = iota
	unlisted
	mounted
	deep
	truncated
)

// An entry is what the module last saw of a name: the node the filesystem
// described, what it knows of the content of a regular file, the target of a
// link and, for a directory it listed, the entries it holds. A directory it
// has not listed has entries it knows of, and none it knows to be missing.
type entry struct {
	node     tree.Node
	content  content
	target   string
	listed   bool
	gap      gap
	children map[string]*entry
}

func (e *entry) child(name string) *entry {
	if e == nil {
		return nil
	}
	return e.children[name]
}

func (e *entry) adopt(name string, held *entry) {
	if e.children == nil {
		e.children = map[string]*entry{}
	}
	e.children[name] = held
}

func (e *entry) count() int {
	counted := 1
	for _, held := range e.children {
		counted += held.count()
	}
	return counted
}

func (e *entry) each(path string, visit func(string, *entry)) {
	visit(path, e)
	for _, name := range slices.Sorted(maps.Keys(e.children)) {
		e.children[name].each(filepath.Join(path, name), visit)
	}
}

type rooted struct {
	observed bool
	entry    *entry
	problem  error
}

// The baseline is everything the module last saw of the paths it watches, the
// scope it saw it within, and what that scope watches that an earlier one left
// out, until a walk over every path has seen it whole.
type baseline struct {
	scope   Scope
	fresh   fresh
	roots   map[string]*rooted
	entries int
}

func empty(given Scope) *baseline {
	held := &baseline{scope: given.clone(), roots: map[string]*rooted{}}
	for _, path := range given.Paths {
		held.roots[path] = &rooted{}
	}
	return held
}

func (b *baseline) count() int {
	counted := 0
	for _, kept := range b.roots {
		if kept.entry != nil {
			counted += kept.entry.count()
		}
	}
	return counted
}

func (b *baseline) find(within scope, path string) (*entry, *rooted) {
	root, found := within.root(path)
	if !found {
		return nil, nil
	}
	held := b.roots[root]
	if held == nil {
		return nil, nil
	}
	current := held.entry
	for _, name := range elements(root, path) {
		current = current.child(name)
	}
	return current, held
}

func elements(root, path string) []string {
	rest := strings.TrimPrefix(strings.TrimPrefix(path, root), "/")
	if rest == "" {
		return nil
	}
	return strings.Split(rest, "/")
}

type record struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	Links    uint64 `json:"links"`
	User     uint32 `json:"user"`
	Group    uint32 `json:"group"`
	Mode     uint32 `json:"mode"`
	Special  uint64 `json:"special,omitzero"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
	Changed  int64  `json:"changed"`
	Content  string `json:"content,omitempty"`
	Target   string `json:"target,omitempty"`
	Listed   bool   `json:"listed,omitzero"`
}

type stored struct {
	Format   int      `json:"format"`
	Paths    []string `json:"paths"`
	Exclude  []string `json:"exclude"`
	Fresh    unseen   `json:"fresh"`
	Observed []string `json:"observed"`
	Entries  []record `json:"entries"`
}

type unseen struct {
	Paths    []string `json:"paths"`
	Patterns []string `json:"patterns"`
}

var kinds = map[string]tree.Kind{}

func init() {
	for kind := tree.Regular; kind <= tree.Character; kind++ {
		kinds[kind.String()] = kind
	}
}

func (b *baseline) records() ([]string, []record) {
	var observed []string
	var held []record
	for _, root := range slices.Sorted(maps.Keys(b.roots)) {
		kept := b.roots[root]
		if kept.observed {
			observed = append(observed, root)
		}
		if kept.entry == nil {
			continue
		}
		kept.entry.each(root, func(path string, saw *entry) {
			held = append(held, record{
				Path: path, Kind: saw.node.Kind.String(), Device: saw.node.Device, Inode: saw.node.Inode, Links: saw.node.Links,
				User: saw.node.User, Group: saw.node.Group, Mode: saw.node.Mode, Special: saw.node.Special, Size: saw.node.Size,
				Modified: saw.node.Modified.UnixNano(), Changed: saw.node.Changed.UnixNano(),
				Content: saw.content.String(), Target: saw.target, Listed: saw.listed,
			})
		})
	}
	return observed, held
}

// rebuild holds what was seen of the records within the scope, under the
// paths of that scope: a path the scope names that was seen within another
// one is known as it was seen there, and seen whole when the directory that
// holds it was listed, and a record whose directory is not held is left out
// with it.
func rebuild(given Scope, own []string, observed []string, records []record) (*baseline, error) {
	within := scoped(given, own)
	held := empty(given)
	for _, path := range observed {
		if kept := held.roots[path]; kept != nil {
			kept.observed = true
		}
	}
	for _, written := range records {
		saw, err := decoded(written)
		if err != nil {
			return nil, err
		}
		if !within.covers(written.Path) {
			continue
		}
		root, _ := within.root(written.Path)
		kept := held.roots[root]
		if written.Path == root {
			if kept.entry != nil {
				return nil, fmt.Errorf("%w: it holds %s twice", ErrDamaged, secrets.Shown(written.Path))
			}
			kept.entry, kept.observed = saw, true
			held.entries++
			continue
		}
		parent, _ := held.find(within, filepath.Dir(written.Path))
		name := filepath.Base(written.Path)
		switch {
		case parent == nil:
			continue
		case parent.node.Kind != tree.Directory:
			return nil, fmt.Errorf("%w: it holds %s within something that is not a directory", ErrDamaged, secrets.Shown(written.Path))
		case parent.child(name) != nil:
			return nil, fmt.Errorf("%w: it holds %s twice", ErrDamaged, secrets.Shown(written.Path))
		}
		parent.adopt(name, saw)
		held.entries++
	}
	return held, nil
}

func decoded(written record) (*entry, error) {
	kind, known := kinds[written.Kind]
	shown := secrets.Shown(written.Path)
	switch {
	case len(written.Path) > maxPathBytes || !filepath.IsAbs(written.Path) || filepath.Clean(written.Path) != written.Path:
		return nil, fmt.Errorf("%w: it holds an entry at %s", ErrDamaged, shown)
	case !known:
		return nil, fmt.Errorf("%w: it says %s is a %s", ErrDamaged, shown, secrets.Shown(written.Kind))
	case written.Mode > 0o7777:
		return nil, fmt.Errorf("%w: it says %s has mode %#o", ErrDamaged, shown, written.Mode)
	case written.Listed && kind != tree.Directory:
		return nil, fmt.Errorf("%w: it says it listed %s, which is a %s", ErrDamaged, shown, kind)
	case written.Target != "" && kind != tree.Link, len(written.Target) > maxTarget:
		return nil, fmt.Errorf("%w: it says what %s links to", ErrDamaged, shown)
	case written.Content != "" && kind != tree.Regular:
		return nil, fmt.Errorf("%w: it says what %s holds, which is a %s", ErrDamaged, shown, kind)
	}
	saw := &entry{
		node: tree.Node{
			Kind: kind, Device: written.Device, Inode: written.Inode, Links: written.Links, User: written.User, Group: written.Group,
			Mode: written.Mode, Special: written.Special, Size: written.Size,
			Modified: time.Unix(0, written.Modified), Changed: time.Unix(0, written.Changed),
		},
		target: written.Target,
		listed: written.Listed,
	}
	switch held, isDigest := strings.CutPrefix(written.Content, digestPrefix); {
	case written.Content == "":
	case isDigest:
		digest, err := hex.DecodeString(held)
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("%w: it says %s holds what digests to %s", ErrDamaged, shown, secrets.Shown(written.Content))
		}
		saw.content.state = hashed
		copy(saw.content.digest[:], digest)
	default:
		for state, name := range knowns {
			if name == written.Content {
				saw.content.state = state
			}
		}
		if saw.content.state == unread {
			return nil, fmt.Errorf("%w: it says the content of %s is %s", ErrDamaged, shown, secrets.Shown(written.Content))
		}
	}
	return saw, nil
}

func encode(held *baseline) ([]byte, error) {
	observed, records := held.records()
	written := stored{
		Format:   format,
		Paths:    listed(held.scope.Paths),
		Exclude:  listed(held.scope.Exclude),
		Fresh:    unseen{Paths: listed(held.fresh.paths), Patterns: listed(held.fresh.patterns)},
		Observed: listed(observed),
		Entries:  records,
	}
	if written.Entries == nil {
		written.Entries = []record{}
	}
	return json.Marshal(written)
}

func listed(held []string) []string {
	if held == nil {
		return []string{}
	}
	return held
}

func decode(content []byte, given Scope, own []string) (*baseline, error) {
	if len(content) > maxBaseline {
		return nil, fmt.Errorf("%w: it is larger than %d bytes", ErrDamaged, maxBaseline)
	}
	var declared struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if declared.Format > format {
		return nil, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, declared.Format, format)
	}
	var written stored
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&written); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: it holds more than one baseline", ErrDamaged)
	}
	switch {
	case written.Format != format:
		return nil, fmt.Errorf("%w: format %d is not one this agent reads", ErrDamaged, written.Format)
	case len(written.Paths) > maxWatchPaths || len(written.Entries) > 2*maxEntries:
		return nil, fmt.Errorf("%w: it holds %d paths and %d entries", ErrDamaged, len(written.Paths), len(written.Entries))
	}
	for _, path := range slices.Concat(written.Paths, written.Observed, written.Fresh.Paths) {
		if len(path) > maxPathBytes || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("%w: it names the path %s", ErrDamaged, secrets.Shown(path))
		}
	}
	for _, pattern := range slices.Concat(written.Exclude, written.Fresh.Patterns) {
		if _, err := filepath.Match(pattern, ""); err != nil || len(pattern) > maxPathBytes {
			return nil, fmt.Errorf("%w: it leaves out %s", ErrDamaged, secrets.Shown(pattern))
		}
	}
	for _, path := range written.Observed {
		if !slices.Contains(written.Paths, path) {
			return nil, fmt.Errorf("%w: it says it saw %s, which it does not watch", ErrDamaged, secrets.Shown(path))
		}
	}
	slices.SortStableFunc(written.Entries, func(a, b record) int { return strings.Compare(a.Path, b.Path) })
	earlier := Scope{Paths: written.Paths, Exclude: written.Exclude}
	held, err := rebuild(earlier, own, written.Observed, written.Entries)
	if err != nil {
		return nil, err
	}
	held.fresh = fresh{paths: written.Fresh.Paths, patterns: written.Fresh.Patterns}
	return held.rescope(given, own)
}

func rescopedObserved(held *baseline, given Scope) []string {
	within := scoped(held.scope, nil)
	var observed []string
	for _, path := range given.Paths {
		if kept := held.roots[path]; kept != nil {
			if kept.observed {
				observed = append(observed, path)
			}
			continue
		}
		if parent, _ := held.find(within, filepath.Dir(path)); parent != nil && parent.listed && within.covers(path) {
			observed = append(observed, path)
		}
	}
	return observed
}

func (b *baseline) rescope(given Scope, own []string) (*baseline, error) {
	if given.Equal(b.scope) {
		return b, nil
	}
	_, records := b.records()
	rescoped, err := rebuild(given, own, rescopedObserved(b, given), records)
	if err != nil {
		return nil, err
	}
	rescoped.fresh = b.fresh.join(scoped(given, own).since(b.scope))
	return rescoped, nil
}

func load(root *os.Root, given Scope, own []string) (*baseline, error) {
	path := filepath.Join(root.Name(), baselineFile)
	described, err := root.Lstat(baselineFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, errUnwritten
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	if err := files.Private(described); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return nil, fmt.Errorf("%w: %s %v", ErrInsecure, path, err)
	}
	file, err := root.Open(baselineFile)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return nil, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBaseline+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	held, err := decode(content, given, own)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return held, nil
}

// A baseline lost in a crash only has the module report again changes it
// reported before, so the file is synced before it replaces the last one and
// the directory is not.
func save(root *os.Root, held *baseline) error {
	path := filepath.Join(root.Name(), baselineFile)
	content, err := encode(held)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	random := make([]byte, 8)
	rand.Read(random)
	temporary := "." + baselineFile + "." + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, err = file.Write(append(content, '\n'))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = root.Rename(temporary, baselineFile)
	}
	if err != nil {
		if removed := root.Remove(temporary); removed != nil && !errors.Is(removed, fs.ErrNotExist) {
			err = errors.Join(err, removed)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func discard(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s: %w", root.Name(), err)
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		return fmt.Errorf("list %s: %w", root.Name(), err)
	}
	for _, name := range names {
		if !interrupted.MatchString(name) {
			continue
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("discard the interrupted write %s: %w", filepath.Join(root.Name(), name), err)
		}
	}
	return nil
}
