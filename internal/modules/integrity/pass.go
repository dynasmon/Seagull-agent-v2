package integrity

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/inotify"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/tree"
)

const (
	maxHashBytes = 256 << 20
	hashAttempts = 3
	entryCharge  = 1 << 10
	maxDepth     = 64
)

const (
	fromRealtime       = "realtime"
	fromReconciliation = "reconciliation"
)

type change struct {
	operation string
	path      string
	previous  string
	changes   []string
	before    *entry
	after     *entry
	hint      *hint
}

type placed struct {
	path   string
	parent *entry
	root   *rooted
	entry  *entry
	hint   *hint
}

// A pass looks at part of what the module watches, the paths it walks whole or
// the names the kernel spoke of, each through the directory that holds it,
// and compares it with the baseline. A directory that is not the one the
// baseline holds at its path moved or was replaced, and the path that holds it
// is walked whole instead. What changed in place is written into the baseline
// as it is found; what vanished and what appeared waits for the end of the
// pass, which pairs a name that went with one that came as the one file moved.
type pass struct {
	c        *Collector
	ctx      context.Context
	meter    *governor.Meter
	origin   string
	fresh    fresh
	vanished []placed
	appeared []placed
	added    int
	changed  bool
	saved    time.Time
}

func (p *pass) charge(bytes int64) error { return p.meter.Charge(p.ctx, bytes) }

func (p *pass) room(held *entry) int {
	return max(0, maxEntries-p.c.held.entries-p.added+len(held.children))
}

func (p *pass) root(path string) error {
	kept := p.c.held.roots[path]
	if kept == nil {
		kept = &rooted{}
		p.c.held.roots[path] = kept
	}
	parent, err := tree.Open(filepath.Dir(path))
	var node tree.Node
	if err == nil {
		defer parent.Close()
		p.c.watch(parent, filepath.Dir(path), false)
		node, err = parent.Stat(filepath.Base(path))
	}
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, tree.ErrNotDirectory):
		kept.problem = nil
		if kept.entry != nil && kept.observed {
			p.vanished = append(p.vanished, placed{path: path, root: kept, entry: kept.entry})
		} else if kept.entry != nil {
			kept.entry, p.changed = nil, true
		}
		if !kept.observed {
			kept.observed, p.changed = true, true
		}
		return nil
	case err != nil:
		kept.problem = err
		return p.ctx.Err()
	}
	kept.problem = nil
	if node.Kind == tree.Link {
		kept.problem = errLinked
	}
	if err := p.charge(entryCharge); err != nil {
		return err
	}
	return p.observe(parent, placed{path: path, root: kept, entry: kept.entry}, !kept.observed, node, 0)
}

// observe compares what a name stands for now with what the baseline held of
// it, which the module may never have seen. A name new to the baseline is new
// to the host only when the module had listed the directory that holds it.
func (p *pass) observe(dir *tree.Dir, at placed, unseen bool, node tree.Node, depth int) error {
	prior := at.entry
	now := &entry{node: node}
	name := filepath.Base(at.path)
	switch node.Kind {
	case tree.Regular:
		if err := p.content(dir, name, prior, now); err != nil {
			return err
		}
	case tree.Link:
		now.target, _ = dir.Target(name, maxTarget)
	}
	switch {
	case prior == nil && (unseen || p.fresh.holds(at.path)):
		p.added++
		p.place(at, now)
		return p.descend(dir, at.path, now, depth)
	case prior == nil:
		p.added++
		if err := p.descend(dir, at.path, now, depth); err != nil {
			return err
		}
		at.entry = now
		p.appeared = append(p.appeared, at)
		return nil
	}
	changes := compare(prior, now, false)
	before := snapshot(prior)
	p.update(prior, now)
	if len(changes) > 0 {
		p.c.report(change{operation: "modified", path: at.path, changes: changes, before: before, after: snapshot(prior), hint: at.hint}, p.origin)
	}
	switch {
	case before.node.Kind == tree.Directory && now.node.Kind != tree.Directory:
		for _, name := range slices.Sorted(maps.Keys(prior.children)) {
			prior.children[name].each(filepath.Join(at.path, name), func(path string, saw *entry) {
				p.c.report(change{operation: "deleted", path: path, before: snapshot(saw)}, p.origin)
			})
		}
		prior.children, prior.listed = nil, false
	case before.node.Kind != tree.Directory && now.node.Kind == tree.Directory:
		prior.listed = true
	}
	return p.descend(dir, at.path, prior, depth)
}

func (p *pass) update(prior, now *entry) {
	if prior.node != now.node || prior.content != now.content || prior.target != now.target {
		p.changed = true
	}
	prior.node, prior.content, prior.target = now.node, now.content, now.target
}

func (p *pass) place(at placed, held *entry) {
	if at.parent != nil {
		at.parent.adopt(filepath.Base(at.path), held)
	} else {
		at.root.entry, at.root.observed = held, true
	}
	p.changed = true
}

func (p *pass) descend(dir *tree.Dir, path string, held *entry, depth int) error {
	if held.node.Kind != tree.Directory {
		return nil
	}
	switch {
	case depth > 0 && held.node.Device != dir.Node().Device:
		held.gap = mounted
		return nil
	case depth >= maxDepth:
		held.gap = deep
		return nil
	}
	entered, err := dir.Enter(filepath.Base(path), held.node)
	if err != nil {
		held.gap = unlisted
		return p.ctx.Err()
	}
	defer entered.Close()
	return p.visit(entered, path, held, depth+1)
}

func (p *pass) visit(dir *tree.Dir, path string, held *entry, depth int) error {
	root, _ := p.c.scope.root(path)
	p.c.watch(dir, path, true)
	names, err := dir.Names(p.room(held))
	if err != nil {
		held.gap = unlisted
		if errors.Is(err, tree.ErrTooMany) {
			held.gap = truncated
		}
		return p.ctx.Err()
	}
	listed := held.listed
	present := map[string]bool{}
	for _, name := range names {
		if err := p.ctx.Err(); err != nil {
			return err
		}
		child := filepath.Join(path, name)
		if len(child) > maxPathBytes || !p.c.scope.walks(root, child) {
			continue
		}
		node, err := dir.Stat(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		present[name] = true
		if err != nil {
			continue
		}
		if err := p.charge(entryCharge); err != nil {
			return err
		}
		if err := p.observe(dir, placed{path: child, parent: held, entry: held.child(name)}, !listed, node, depth); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(held.children)) {
		child := filepath.Join(path, name)
		if present[name] || !p.c.scope.walks(root, child) {
			continue
		}
		if listed {
			p.vanished = append(p.vanished, placed{path: child, parent: held, entry: held.children[name]})
			continue
		}
		delete(held.children, name)
		p.changed = true
	}
	if !held.listed {
		p.changed = true
	}
	held.listed, held.gap = true, covered
	return p.keep()
}

func (p *pass) keep() error {
	if !p.changed || time.Since(p.saved) < saveEvery {
		return nil
	}
	p.saved = time.Now()
	return p.c.persist()
}

func (p *pass) content(dir *tree.Dir, name string, prior, now *entry) error {
	if prior != nil && prior.node.Kind == tree.Regular && prior.content.state == hashed && unchanged(prior.node, now.node) {
		now.content = prior.content
		return nil
	}
	if now.node.Size > maxHashBytes {
		now.content.state = large
		return nil
	}
	for range hashAttempts {
		state, err := p.hash(dir, name, now)
		if err != nil {
			return err
		}
		if now.content.state = state; state != unstable {
			return nil
		}
	}
	return nil
}

func (p *pass) hash(dir *tree.Dir, name string, now *entry) (known, error) {
	file, err := dir.Read(name, now.node)
	switch {
	case errors.Is(err, tree.ErrChanged):
		return unstable, nil
	case err != nil:
		return unreadable, nil
	}
	defer file.Close()
	digest := sha256.New()
	read, err := io.Copy(digest, p.meter.Reader(p.ctx, io.LimitReader(file, maxHashBytes+1)))
	if err != nil {
		if p.ctx.Err() != nil {
			return unread, p.ctx.Err()
		}
		return unreadable, nil
	}
	after, err := file.Stat()
	if err != nil || read != now.node.Size || !unchanged(now.node, after) {
		return unstable, nil
	}
	digest.Sum(now.content.digest[:0])
	return hashed, nil
}

func unchanged(before, after tree.Node) bool {
	return before.Same(after) && before.Size == after.Size && before.Modified.Equal(after.Modified) && before.Changed.Equal(after.Changed)
}

// compare names what changed between two looks at a name. The time an inode
// last changed moves with anything done to it, so it is reported only when
// nothing else that changed is visible, and never for a name that moved,
// since moving it is what changed it.
func compare(before, after *entry, moved bool) []string {
	b, a := before.node, after.node
	if b.Kind != a.Kind {
		return []string{"kind"}
	}
	var changes []string
	if !b.Same(a) {
		changes = append(changes, "identity")
	}
	if b.User != a.User {
		changes = append(changes, "owner")
	}
	if b.Group != a.Group {
		changes = append(changes, "group")
	}
	if b.Mode != a.Mode && a.Kind != tree.Link {
		changes = append(changes, "mode")
	}
	switch a.Kind {
	case tree.Regular:
		if contentChanged(before, after) {
			changes = append(changes, "content")
		}
		if b.Links != a.Links {
			changes = append(changes, "links")
		}
	case tree.Link:
		if before.target != after.target {
			changes = append(changes, "target")
		}
	case tree.Block, tree.Character:
		if b.Special != a.Special {
			changes = append(changes, "device")
		}
	}
	if len(changes) == 0 && !moved && a.Kind != tree.Directory && a.Kind != tree.Link && !b.Changed.Equal(a.Changed) {
		changes = append(changes, "attributes")
	}
	return changes
}

func contentChanged(before, after *entry) bool {
	if before.content.state == hashed && after.content.state == hashed {
		return before.content.digest != after.content.digest
	}
	return before.node.Size != after.node.Size || !before.node.Modified.Equal(after.node.Modified)
}

func (p *pass) hinted(hints map[string]*hint, moved []string) error {
	opened := map[string]*tree.Dir{}
	defer func() {
		for _, dir := range opened {
			dir.Close()
		}
	}()
	relocated := slices.Clone(moved)
	var ready []string
	for _, path := range slices.Sorted(maps.Keys(hints)) {
		root, held := p.c.scope.root(path)
		if !held || !p.c.scope.covers(path) {
			continue
		}
		if path == root {
			relocated = append(relocated, root)
			continue
		}
		parentPath := filepath.Dir(path)
		parent, _ := p.c.held.find(p.c.scope, parentPath)
		if parent == nil || parent.node.Kind != tree.Directory {
			relocated = append(relocated, root)
			continue
		}
		if opened[parentPath] == nil {
			dir, err := tree.Open(parentPath)
			if err != nil {
				relocated = append(relocated, root)
				continue
			}
			opened[parentPath] = dir
			if !dir.Node().Same(parent.node) {
				relocated = append(relocated, root)
				continue
			}
		}
		ready = append(ready, path)
	}
	slices.Sort(relocated)
	relocated = slices.Compact(relocated)
	for _, path := range ready {
		if err := p.ctx.Err(); err != nil {
			return err
		}
		root, _ := p.c.scope.root(path)
		if slices.Contains(relocated, root) {
			continue
		}
		dir := opened[filepath.Dir(path)]
		parent, _ := p.c.held.find(p.c.scope, filepath.Dir(path))
		if parent == nil || !dir.Node().Same(parent.node) {
			continue
		}
		at := placed{path: path, parent: parent, entry: parent.child(filepath.Base(path)), hint: hints[path]}
		node, err := dir.Stat(filepath.Base(path))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			p.missing(at, parent.listed)
		case err == nil:
			if err := p.charge(entryCharge); err != nil {
				return err
			}
			if err := p.observe(dir, at, !parent.listed, node, len(elements(root, path))); err != nil {
				return err
			}
		}
	}
	for _, root := range relocated {
		if err := p.root(root); err != nil {
			return err
		}
	}
	return nil
}

func (p *pass) missing(at placed, listed bool) {
	switch {
	case at.entry != nil && listed:
		p.vanished = append(p.vanished, at)
	case at.entry != nil:
		delete(at.parent.children, filepath.Base(at.path))
		p.changed = true
	case listed && at.hint != nil && at.hint.seen&(inotify.Created|inotify.MovedTo) != 0 && at.hint.seen&inotify.MovedFrom == 0:
		p.c.report(change{operation: "transient", path: at.path, hint: at.hint}, p.origin)
	}
}

type identity struct{ device, inode uint64 }

// finish settles what vanished and what appeared in the pass. A name that
// went and one that came are the one file moved when no other name that went
// or came in the pass is that file, and it is alike in both looks, so an inode
// a new file reuses is not taken for the one that was deleted.
func (p *pass) finish() {
	gone, came := map[identity][]int{}, map[identity][]int{}
	for i, held := range p.vanished {
		gone[identify(held.entry.node)] = append(gone[identify(held.entry.node)], i)
	}
	for i, held := range p.appeared {
		came[identify(held.entry.node)] = append(came[identify(held.entry.node)], i)
	}
	moved := map[int]int{}
	for key, arrived := range came {
		if left := gone[key]; len(arrived) == 1 && len(left) == 1 && alike(p.vanished[left[0]].entry, p.appeared[arrived[0]].entry) {
			moved[arrived[0]] = left[0]
		}
	}
	paired := map[int]bool{}
	for _, left := range moved {
		paired[left] = true
	}
	for i, held := range p.vanished {
		if !paired[i] {
			p.remove(held)
			held.entry.each(held.path, func(path string, saw *entry) {
				p.c.report(change{operation: "deleted", path: path, before: snapshot(saw), hint: hinted(held, path)}, p.origin)
			})
		}
	}
	for i, held := range p.appeared {
		left, renamed := moved[i]
		if !renamed {
			p.place(held, held.entry)
			held.entry.each(held.path, func(path string, saw *entry) {
				p.c.report(change{operation: "created", path: path, after: snapshot(saw), hint: hinted(held, path)}, p.origin)
			})
			continue
		}
		before := p.vanished[left]
		p.remove(before)
		p.place(held, held.entry)
		p.c.report(change{operation: "renamed", path: held.path, previous: before.path, changes: compare(before.entry, held.entry, true),
			before: snapshot(before.entry), after: snapshot(held.entry), hint: held.hint}, p.origin)
		p.within(held.path, before.entry, held.entry)
	}
	p.vanished, p.appeared, p.added = nil, nil, 0
	p.c.held.entries = p.c.held.count()
}

func hinted(held placed, path string) *hint {
	if path == held.path {
		return held.hint
	}
	return nil
}

func (p *pass) within(path string, before, after *entry) {
	if before.node.Kind != tree.Directory || after.node.Kind != tree.Directory || !after.listed {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(before.children)) {
		if after.child(name) == nil {
			before.children[name].each(filepath.Join(path, name), func(path string, saw *entry) {
				p.c.report(change{operation: "deleted", path: path, before: snapshot(saw)}, p.origin)
			})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(after.children)) {
		child := filepath.Join(path, name)
		was, now := before.child(name), after.children[name]
		if was == nil {
			now.each(child, func(path string, saw *entry) {
				p.c.report(change{operation: "created", path: path, after: snapshot(saw)}, p.origin)
			})
			continue
		}
		if changes := compare(was, now, true); len(changes) > 0 {
			p.c.report(change{operation: "modified", path: child, changes: changes, before: snapshot(was), after: snapshot(now)}, p.origin)
		}
		p.within(child, was, now)
	}
}

func (p *pass) remove(held placed) {
	if held.parent != nil {
		if held.parent.children[filepath.Base(held.path)] == held.entry {
			delete(held.parent.children, filepath.Base(held.path))
		}
	} else if held.root.entry == held.entry {
		held.root.entry = nil
	}
	p.changed = true
}

func identify(node tree.Node) identity { return identity{device: node.Device, inode: node.Inode} }

func alike(before, after *entry) bool {
	b, a := before.node, after.node
	switch {
	case b.Kind != a.Kind:
		return false
	case a.Kind == tree.Regular:
		return b.Size == a.Size && b.Modified.Equal(a.Modified)
	case a.Kind == tree.Link:
		return before.target == after.target
	}
	return b.Modified.Equal(a.Modified) || a.Kind == tree.Directory
}

func snapshot(held *entry) *entry {
	if held == nil {
		return nil
	}
	return &entry{node: held.node, content: held.content, target: held.target}
}
