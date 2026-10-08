package integrity

import (
	"path/filepath"
	"slices"
	"strings"
)

// A Scope is what the module watches: the paths it is given, each a file or a
// directory it descends, and what it leaves out of them, by absolute path or
// by a pattern the name of an entry matches.
type Scope struct {
	Paths   []string
	Exclude []string
}

func (s Scope) Equal(other Scope) bool {
	return slices.Equal(s.Paths, other.Paths) && slices.Equal(s.Exclude, other.Exclude)
}

func (s Scope) clone() Scope {
	return Scope{Paths: slices.Clone(s.Paths), Exclude: slices.Clone(s.Exclude)}
}

type scope struct {
	given    Scope
	own      []string
	absolute []string
	patterns []string
}

func scoped(given Scope, own []string) scope {
	held := scope{given: given.clone(), own: slices.Clone(own)}
	for _, excluded := range given.Exclude {
		if strings.HasPrefix(excluded, "/") {
			held.absolute = append(held.absolute, excluded)
		} else {
			held.patterns = append(held.patterns, excluded)
		}
	}
	return held
}

func within(path, root string) bool {
	return path == root || root == "/" || strings.HasPrefix(path, root+"/")
}

func (s scope) root(path string) (string, bool) {
	found := ""
	for _, root := range s.given.Paths {
		if within(path, root) && len(root) > len(found) {
			found = root
		}
	}
	return found, found != ""
}

func (s scope) isRoot(path string) bool { return slices.Contains(s.given.Paths, path) }

func (s scope) excludes(path string) bool {
	beneath := func(held string) bool { return within(path, held) }
	if slices.ContainsFunc(s.own, beneath) || slices.ContainsFunc(s.absolute, beneath) {
		return true
	}
	if s.isRoot(path) {
		return false
	}
	return matches(s.patterns, filepath.Base(path))
}

func matches(patterns []string, name string) bool {
	return slices.ContainsFunc(patterns, func(pattern string) bool {
		matched, _ := filepath.Match(pattern, name)
		return matched
	})
}

func (s scope) covers(path string) bool {
	_, held := s.root(path)
	return held && !s.excludes(path)
}

// Within a walk of one path, an entry another path names is that path's to
// watch, and one the scope leaves out is nobody's.
func (s scope) walks(root, path string) bool {
	owner, held := s.root(path)
	return held && owner == root && !s.excludes(path)
}

// What a scope watches that the one before it left out: an entry found there
// is new to the baseline rather than new to the host.
type fresh struct {
	paths    []string
	patterns []string
}

func (s scope) since(before Scope) fresh {
	earlier := scoped(before, nil)
	var held fresh
	for _, excluded := range earlier.absolute {
		if !slices.Contains(s.absolute, excluded) {
			held.paths = append(held.paths, excluded)
		}
	}
	for _, pattern := range earlier.patterns {
		if !slices.Contains(s.patterns, pattern) {
			held.patterns = append(held.patterns, pattern)
		}
	}
	return held
}

func (f fresh) join(other fresh) fresh {
	held := fresh{paths: slices.Clone(f.paths), patterns: slices.Clone(f.patterns)}
	for _, path := range other.paths {
		if !slices.Contains(held.paths, path) {
			held.paths = append(held.paths, path)
		}
	}
	for _, pattern := range other.patterns {
		if !slices.Contains(held.patterns, pattern) {
			held.patterns = append(held.patterns, pattern)
		}
	}
	return held
}

func (f fresh) holds(path string) bool {
	return slices.ContainsFunc(f.paths, func(held string) bool { return within(path, held) }) || matches(f.patterns, filepath.Base(path))
}
